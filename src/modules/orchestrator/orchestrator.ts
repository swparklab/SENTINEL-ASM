/**
 * 점검 오케스트레이터 (설계 §2.1 오케스트레이션 / §2.2 데이터 흐름).
 * 승인된 작업을 큐잉·스케줄링하고 동시성 제한 하에 워커로 분산 실행한다.
 * 운영에서는 Kafka/Temporal + K8s 워커로 수평 확장되지만(설계 §7/§8.1),
 * 본 구현은 단일 노드 인메모리 큐 + 동시성 풀로 동일한 제어 흐름을 제공한다.
 *
 * 모든 작업은 enqueue 시점에 소유권 검증 게이트(설계 §3)를 통과해야 하며,
 * 실행 직전·실행 중에도 kill-switch(동의 철회/만료)를 재확인한다.
 */
import { config } from '../../config.js';
import { repos } from '../../db/store.js';
import { audit } from '../../db/audit.js';
import { id, now } from '../../util.js';
import type { Asset, Consent, ScanIntensity, ScanJob, ScanModule, Finding } from '../../types.js';
import { evaluateGate, currentConsentStatus, computeEgressAllowlist } from '../authorizationGate/gate.js';
import { SCANNERS, EgressGuard } from '../scanners/index.js';
import { prioritize } from '../risk/scoring.js';
import { mapCompliance } from '../compliance/mapping.js';

export interface EnqueueParams {
  tenantId: string;
  asset: Asset;
  consent: Consent | undefined;
  modules: ScanModule[];
  intensity: ScanIntensity;
  deep?: boolean;
  actor: string;
}

class Orchestrator {
  private queue: string[] = [];
  private running = 0;

  /** 게이트 평가 후 작업을 큐에 넣는다. 거부 시 rejected 작업으로 기록(감사 추적 보존). */
  enqueue(p: EnqueueParams): ScanJob {
    const targets = [p.asset.value]; // 능동 발신 대상 (서브도메인은 범위 내 자동 포함)
    const decision = evaluateGate({
      tenantId: p.tenantId, asset: p.asset, consent: p.consent,
      intensity: p.intensity, modules: p.modules, targets, actor: p.actor,
    });

    const job: ScanJob = {
      id: id('job'),
      tenantId: p.tenantId,
      assetId: p.asset.id,
      consentId: p.consent?.id ?? '',
      modules: p.modules,
      intensity: p.intensity,
      depth: p.deep ? 'deep' : 'simple',
      status: decision.allowed ? 'queued' : 'rejected',
      gateDecision: { allowed: decision.allowed, reason: decision.reason, checkedAt: decision.checkedAt },
      requestedBy: p.actor,
      queuedAt: now(),
      findings: [],
      egressAllowlist: decision.egressAllowlist,
      finishedAt: decision.allowed ? undefined : now(),
    };
    repos.scanJobs.insert(job);

    audit({
      tenantId: p.tenantId, actor: p.actor,
      action: decision.allowed ? 'scan.enqueue' : 'scan.reject',
      target: p.asset.value, outcome: decision.allowed ? 'allow' : 'deny',
      reason: decision.reason, meta: { jobId: job.id, intensity: p.intensity, modules: p.modules },
    });

    if (decision.allowed) {
      this.queue.push(job.id);
      queueMicrotask(() => this.pump());
    }
    return job;
  }

  private pump(): void {
    while (this.running < config.scan.concurrency && this.queue.length > 0) {
      const jobId = this.queue.shift()!;
      this.running++;
      this.runJob(jobId)
        .catch((e) => {
          repos.scanJobs.update(jobId, { status: 'failed', error: String(e), finishedAt: now() });
        })
        .finally(() => {
          this.running--;
          this.pump();
        });
    }
  }

  private async runJob(jobId: string): Promise<void> {
    const job = repos.scanJobs.get(jobId);
    if (!job || job.status !== 'queued') return;

    const asset = repos.assets.get(job.assetId);
    if (!asset) {
      repos.scanJobs.update(jobId, { status: 'failed', error: '자산을 찾을 수 없음', finishedAt: now() });
      return;
    }

    // 실행 직전 kill-switch 재확인 (설계 §3.2): 동의 철회/만료 시 중단
    if (job.consentId) {
      const consent = repos.consents.get(job.consentId);
      if (!consent || currentConsentStatus(consent) !== 'active') {
        repos.scanJobs.update(jobId, { status: 'aborted', error: '동의 비활성(kill-switch)', finishedAt: now() });
        audit({ tenantId: job.tenantId, action: 'scan.killswitch', target: asset.value, outcome: 'deny', reason: '실행 직전 동의 비활성', meta: { jobId } });
        return;
      }
    }

    repos.scanJobs.update(jobId, { status: 'running', startedAt: now() });
    audit({ tenantId: job.tenantId, actor: job.requestedBy, action: 'scan.start', target: asset.value, outcome: 'info', meta: { jobId, modules: job.modules } });

    const consent = job.consentId ? repos.consents.get(job.consentId) : undefined;
    const allowedPorts = consent?.scope.allowedPorts ?? [];
    const guard = new EgressGuard(job.egressAllowlist, { tenantId: job.tenantId, jobId });
    const logs: string[] = [];
    const ctx = {
      asset, guard, intensity: job.intensity, allowedPorts,
      tenantId: job.tenantId, jobId, deep: job.depth === 'deep', targets: [asset.value],
      log: (m: string) => logs.push(m),
    };

    const MODULE_LABEL: Record<ScanModule, string> = { asm: 'ASM(공격표면)', config: '구성·헤더', cve: 'CVE·SBOM', dast: '동적(DAST)' };
    type MS = NonNullable<ScanJob['moduleStatus']>[number];
    const moduleStatus: MS[] = job.modules.map((m) => ({ module: m, status: 'pending', findings: 0 }));
    repos.scanJobs.update(jobId, { progress: 3, stage: '점검 초기화', moduleStatus });

    let findings: Finding[] = [];
    const total = job.modules.length;
    for (let mi = 0; mi < job.modules.length; mi++) {
      const mod = job.modules[mi]!;
      const scanner = SCANNERS[mod];
      const ms = moduleStatus[mi]!;
      // 강도 정책 (설계 §4.5): 모듈의 최소 강도를 충족하지 못하면 건너뜀
      if (rank(job.intensity) < rank(scanner.minIntensity)) {
        logs.push(`${mod}: 강도 부족(${job.intensity} < ${scanner.minIntensity}) — 생략`);
        ms.status = 'skipped';
        repos.scanJobs.update(jobId, { moduleStatus: [...moduleStatus] });
        continue;
      }
      // 실행 중 kill-switch 재확인
      const fresh = repos.scanJobs.get(jobId);
      if (fresh?.status === 'aborted') { logs.push('kill-switch 로 중단됨'); break; }
      ms.status = 'running';
      repos.scanJobs.update(jobId, {
        progress: Math.round(5 + (mi / total) * 88),
        stage: `${MODULE_LABEL[mod]} 점검 중 (${mi + 1}/${total})`,
        moduleStatus: [...moduleStatus],
      });
      try {
        const result = await scanner.run(ctx as any);
        findings.push(...result);
        ms.status = 'done'; ms.findings = result.length;
      } catch (e) {
        logs.push(`${mod} 실행 오류: ${String(e)}`);
        ms.status = 'error';
        audit({ tenantId: job.tenantId, action: 'scan.module.error', target: asset.value, outcome: 'error', reason: String(e), meta: { jobId, module: mod } });
      }
      repos.scanJobs.update(jobId, { moduleStatus: [...moduleStatus] });
    }

    // 위험 산정 + 컴플라이언스 매핑 (설계 §5)
    repos.scanJobs.update(jobId, { progress: 95, stage: '위험 산정·컴플라이언스 매핑' });
    findings = mapCompliance(prioritize(findings, asset));

    const current = repos.scanJobs.get(jobId);
    if (current?.status === 'aborted') return; // kill-switch 도중 발생 시 결과 폐기

    repos.scanJobs.update(jobId, {
      status: 'completed', findings, finishedAt: now(), progress: 100, stage: '완료',
      error: logs.length ? logs.join(' | ') : undefined,
    });
    audit({
      tenantId: job.tenantId, actor: job.requestedBy, action: 'scan.complete',
      target: asset.value, outcome: 'info',
      reason: `${findings.length}건 발견`, meta: { jobId, findings: findings.length },
    });
  }
}

function rank(i: ScanIntensity): number {
  return { passive: 0, standard: 1, aggressive: 2 }[i];
}

export const orchestrator = new Orchestrator();

/** 미완료 동의/작업 만료 점검 — 주기적 kill-switch (설계 §3.2). */
export function sweepExpiredConsents(): void {
  for (const consent of repos.consents.list()) {
    if (consent.status === 'active' && currentConsentStatus(consent) === 'expired') {
      repos.consents.update(consent.id, { status: 'expired' });
      const running = repos.scanJobs.list(consent.tenantId)
        .filter((j) => j.consentId === consent.id && (j.status === 'queued' || j.status === 'running'));
      for (const job of running) {
        repos.scanJobs.update(job.id, { status: 'aborted', finishedAt: now(), error: '동의 만료(kill-switch)' });
        audit({ tenantId: consent.tenantId, action: 'scan.killswitch', target: job.assetId, outcome: 'deny', reason: '동의 만료', meta: { jobId: job.id } });
      }
    }
  }
}

export { computeEgressAllowlist };
