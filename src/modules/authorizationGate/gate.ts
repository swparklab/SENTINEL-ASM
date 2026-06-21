/**
 * 소유권 검증 게이트 — 핵심 모듈 (설계 §3).
 * 시스템의 법적·기술적 안전장치. 검증되지 않은 대상은 어떤 경로로도 능동 스캔
 * 큐에 진입할 수 없다. 본 모듈을 우회하는 구현은 설계 범위에서 명시적으로 제외된다.
 */
import { repos } from '../../db/store.js';
import { audit } from '../../db/audit.js';
import { now } from '../../util.js';
import type {
  Asset, Consent, ScanIntensity, ScanModule,
} from '../../types.js';

const INTENSITY_RANK: Record<ScanIntensity, number> = { passive: 0, standard: 1, aggressive: 2 };

export interface GateRequest {
  tenantId: string;
  asset: Asset;
  consent: Consent | undefined;
  intensity: ScanIntensity;
  modules: ScanModule[];
  /** 능동 발신이 필요한 실제 점검 대상들 (서브도메인/호스트 등) */
  targets: string[];
  /** 활성(침투) 검증 모드 — 취약점을 실제 트리거해 확정(비파괴 한정). aggressive + 4-eyes 필수. */
  active?: boolean;
  actor: string;
}

export interface GateDecision {
  allowed: boolean;
  reason: string;
  checkedAt: string;
  /** 통과 시 워커에 적용될 egress allowlist (설계 §3.2 하드 차단 근거) */
  egressAllowlist: string[];
}

/**
 * 게이트 통과 로직 (설계 §3.3 의사코드의 구현).
 *   if (ownershipVerified && consent.active && target ∈ approvedScope && now ∈ window)
 *      → ENQUEUE  else → REJECT + audit.log(reason)
 */
export function evaluateGate(req: GateRequest): GateDecision {
  const checkedAt = now();
  const reject = (reason: string): GateDecision => {
    audit({
      tenantId: req.tenantId, actor: req.actor, action: 'gate.decision',
      target: req.asset.value, outcome: 'deny', reason,
      meta: { assetId: req.asset.id, intensity: req.intensity, modules: req.modules },
    });
    return { allowed: false, reason, checkedAt, egressAllowlist: [] };
  };

  // 1) 소유권 검증 (설계 §3.1) — passive 를 포함한 모든 능동 행위의 최소 전제
  if (req.asset.ownership?.status !== 'verified') {
    return reject('소유권이 검증되지 않은 자산입니다 (ownership != verified).');
  }

  // 활성(침투) 검증은 강도와 무관하게 aggressive 가 아니면 즉시 거부한다.
  // passive 조기허용(아래)보다 먼저 평가해야 {intensity:'passive', active:true} 우회를 차단한다.
  if (req.active && req.intensity !== 'aggressive') {
    return reject('활성(침투) 검증 모드는 aggressive 강도(+ 4-eyes 서면승인)에서만 허용됩니다.');
  }

  // passive 프로파일은 소유권 검증만으로 허용 (설계 §4.5: 대상에 트래픽 미발생)
  if (req.intensity === 'passive') {
    const egress = computeEgressAllowlist(req.asset, req.consent);
    audit({
      tenantId: req.tenantId, actor: req.actor, action: 'gate.decision',
      target: req.asset.value, outcome: 'allow', reason: 'passive: 소유권 검증 충족',
      meta: { assetId: req.asset.id, intensity: 'passive' },
    });
    return { allowed: true, reason: 'passive 프로파일: 소유권 검증 충족', checkedAt, egressAllowlist: egress };
  }

  // 2) 동의 존재·활성 (설계 §3.2)
  const consent = req.consent;
  if (!consent) return reject('등록된 동의(consent)가 없습니다.');
  const status = currentConsentStatus(consent);
  if (status !== 'active') return reject(`동의 상태가 active 가 아닙니다 (status=${status}).`);

  // 3) 점검 윈도우 (설계 §3.2 start–end)
  const t = Date.now();
  if (t < Date.parse(consent.windowStart) || t > Date.parse(consent.windowEnd)) {
    return reject(`현재 시각이 점검 윈도우 밖입니다 (${consent.windowStart} ~ ${consent.windowEnd}).`);
  }

  // 4) 강도 한도 (설계 §4.5)
  if (INTENSITY_RANK[req.intensity] > INTENSITY_RANK[consent.scope.maxIntensity]) {
    return reject(`요청 강도(${req.intensity})가 동의 한도(${consent.scope.maxIntensity})를 초과합니다.`);
  }
  // Aggressive 는 추가 서면 승인 필요 (설계 §4.5 / §9 4-eyes)
  // active 는 위에서 이미 aggressive 를 강제했으므로, 이 검사로 4-eyes 서면승인이 자동 강제된다.
  if (req.intensity === 'aggressive' && !consent.aggressiveApprovedBy) {
    return reject('Aggressive 프로파일은 추가 서면 승인(4-eyes)이 필요합니다.');
  }

  // 5) 범위(scope) 검증 — 모든 점검 대상이 승인 범위에 속해야 함 (설계 §3.2)
  const allow = computeEgressAllowlist(req.asset, consent);
  const out = req.targets.filter((tgt) => !isInScope(tgt, allow));
  if (out.length) {
    return reject(`승인 범위를 벗어난 대상 포함: ${out.join(', ')}`);
  }

  audit({
    tenantId: req.tenantId, actor: req.actor, action: 'gate.decision',
    target: req.asset.value, outcome: 'allow',
    reason: `통과: ownership+consent+window+scope 충족 (intensity=${req.intensity})`,
    meta: { assetId: req.asset.id, consentId: consent.id, modules: req.modules },
  });
  return {
    allowed: true,
    reason: `게이트 통과 (intensity=${req.intensity})`,
    checkedAt,
    egressAllowlist: allow,
  };
}

/** 동의 범위 + 자산값으로 egress allowlist 를 산출 (설계 §3.2 하드 차단 근거). */
export function computeEgressAllowlist(asset: Asset, consent?: Consent): string[] {
  const set = new Set<string>([asset.value.toLowerCase()]);
  for (const t of consent?.scope.allowedTargets ?? []) set.add(t.toLowerCase());
  return [...set];
}

/** target 이 allowlist 범위에 속하는지 — 정확 일치 또는 서브도메인 매칭. */
export function isInScope(target: string, allowlist: string[]): boolean {
  const t = stripScheme(target).toLowerCase();
  return allowlist.some((a) => {
    const base = stripScheme(a).toLowerCase();
    return t === base || t.endsWith('.' + base);
  });
}

function stripScheme(s: string): string {
  return s.replace(/^https?:\/\//, '').replace(/[:/].*$/, '');
}

/** 동의의 현재 유효 상태를 계산 (만료 자동 반영). */
export function currentConsentStatus(consent: Consent): Consent['status'] {
  if (consent.status === 'revoked') return 'revoked';
  if (Date.now() > Date.parse(consent.windowEnd)) return 'expired';
  return consent.status;
}

/**
 * Kill-switch (설계 §3.2): 동의 철회/만료 시 진행 중인 작업을 즉시 중단 처리.
 * 오케스트레이터가 워커 루프에서 이 상태를 확인해 실제 실행을 멈춘다.
 */
export function revokeConsent(consent: Consent, actor: string): void {
  repos.consents.update(consent.id, { status: 'revoked', revokedAt: now() });
  const running = repos.scanJobs.list(consent.tenantId)
    .filter((j) => j.consentId === consent.id && (j.status === 'queued' || j.status === 'running'));
  for (const job of running) {
    repos.scanJobs.update(job.id, { status: 'aborted', finishedAt: now(), error: '동의 철회로 중단(kill-switch)' });
    audit({
      tenantId: consent.tenantId, actor, action: 'scan.killswitch', target: job.assetId,
      outcome: 'deny', reason: '동의 철회', meta: { jobId: job.id, consentId: consent.id },
    });
  }
  audit({
    tenantId: consent.tenantId, actor, action: 'consent.revoke', target: consent.assetId,
    outcome: 'info', reason: `진행 중 작업 ${running.length}건 중단`, meta: { consentId: consent.id },
  });
}
