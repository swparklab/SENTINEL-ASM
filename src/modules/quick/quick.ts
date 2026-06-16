/**
 * 빠른 점검 (Quick Scan) — 저마찰 진입점.
 * 1) 소프트웨어 파일(SBOM) 정적 분석: 원격 트래픽 없음 → 권한 절차 불필요, 즉시 실행.
 * 2) 도메인/URL 점검: 권한 보유 전자 확인(attestation)을 받아 자산·동의를 자동 생성하고
 *    게이트(§3)를 통과시켜 점검을 큐잉한다. 게이트·egress·감사 등 안전장치는 그대로 유지된다.
 */
import { repos } from '../../db/store.js';
import { audit } from '../../db/audit.js';
import { id, now } from '../../util.js';
import type { Asset, Consent, ScanIntensity, ScanJob } from '../../types.js';
import { parseManifest, matchSbom, staticFileAudit } from '../scanners/sbom.js';
import { id as genId } from '../../util.js';
import { prioritize } from '../risk/scoring.js';
import { mapCompliance } from '../compliance/mapping.js';
import { orchestrator } from '../orchestrator/orchestrator.js';
import { STANDARD_PORTS } from '../scanners/types.js';

/** 소프트웨어 파일을 정적 분석하여 완료된 점검 작업으로 기록하고 반환. */
export function scanSoftware(tenantId: string, actor: string, filename: string, content: string): {
  job: ScanJob; format: string; componentCount: number;
} {
  const { components, format } = parseManifest(filename, content);
  let findings = [...matchSbom(components), ...staticFileAudit(filename, content)];
  // 매니페스트 미인식/0건 가시화 (커버리지 공백 투명 고지)
  if (format === '미인식' && !findings.length) {
    findings.push({ id: genId('fnd'), module: 'cve', severity: 'info', title: '매니페스트 형식 미인식', target: filename || 'file', description: '지원되는 의존성 매니페스트로 인식되지 않아 구성요소 CVE 대조를 수행하지 못했습니다.', evidence: `format=미인식`, remediation: 'package.json·requirements.txt·pom.xml·*.lock·SBOM(CycloneDX) 형식으로 제출하십시오.', confidence: 'firm' });
  } else if (components.length === 0 && format !== '미인식') {
    findings.push({ id: genId('fnd'), module: 'cve', severity: 'info', title: `${format} 파싱 결과 구성요소 0건`, target: filename || 'file', description: '형식은 인식되었으나 추출된 구성요소가 없습니다(형식 이상 또는 빈 파일).', evidence: `format=${format}`, remediation: '파일 내용을 확인하십시오.', confidence: 'firm' });
  }

  const asset: Asset = {
    id: id('ast'), tenantId, type: 'software', value: filename || 'software-artifact',
    label: `SBOM 정적분석 (${format}, ${components.length}개 구성요소)`,
    businessCriticality: 'high', ownership: null, createdAt: now(), createdBy: actor,
  };
  repos.assets.insert(asset);

  findings = mapCompliance(prioritize(findings, asset));

  const job: ScanJob = {
    id: id('job'), tenantId, assetId: asset.id, consentId: '',
    modules: ['cve'], intensity: 'passive', status: 'completed',
    gateDecision: { allowed: true, reason: 'SBOM 정적 분석 — 원격 대상 없음(게이트 비대상)', checkedAt: now() },
    requestedBy: actor, queuedAt: now(), startedAt: now(), finishedAt: now(),
    findings, egressAllowlist: [],
  };
  repos.scanJobs.insert(job);
  audit({
    tenantId, actor, action: 'quick.sbom', target: asset.value, outcome: 'info',
    reason: `${format}: 구성요소 ${components.length}개, 취약 ${findings.length}건`,
    meta: { jobId: job.id, format },
  });
  return { job, format, componentCount: components.length };
}

/** 정규화: scheme/path/port 제거하여 호스트만 추출. */
function hostOf(target: string): string {
  return target.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '').replace(/:.*/, '');
}

export interface QuickDomainResult { job: ScanJob; asset: Asset; }

/**
 * 도메인/URL 빠른 점검. attestation(권한 보유 확인)을 전제로 자산·동의를 자동 생성한다.
 * attestation 은 설계 §3 의 '사전 동의'를 전자적으로 충족하는 최소 단위이며, 생략할 수 없다.
 */
export function scanDomainQuick(
  tenantId: string, actor: string, target: string, attested: boolean,
  modules: ScanJob['modules'] = ['asm', 'config', 'cve', 'dast'],
  deep = false,
): QuickDomainResult {
  if (!attested) throw new Error('점검 권한 보유 확인(attestation)이 필요합니다.');
  const host = hostOf(target);
  if (!host) throw new Error('유효한 도메인/URL 이 아닙니다.');

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const type: Asset['type'] = isIp ? 'host' : 'domain';

  // 기존 자산 재사용 또는 생성
  let asset = repos.assets.list(tenantId).find((a) => a.value === host);
  if (!asset) {
    asset = {
      id: id('ast'), tenantId, type, value: host, label: '빠른 점검 대상',
      businessCriticality: 'high', ownership: null, createdAt: now(), createdBy: actor,
    };
    repos.assets.insert(asset);
  }

  // 권한 보유 전자 확인 → 소유권 verified(self-attested)
  repos.assets.update(asset.id, {
    ownership: {
      method: 'self-attested', token: '', status: 'verified',
      issuedAt: now(), verifiedAt: now(),
      detail: `점검 권한 보유 전자 확인 (attested by ${actor})`,
    },
  });
  asset = repos.assets.get(asset.id)!;

  // 점검 윈도우 1시간짜리 자동 동의 생성 (범위 = 해당 호스트, 표준 강도)
  const consent: Consent = {
    id: id('cns'), tenantId, assetId: asset.id,
    scope: { allowedTargets: [host], allowedPorts: STANDARD_PORTS, maxIntensity: 'standard' },
    windowStart: new Date(Date.now() - 5 * 60_000).toISOString(),
    windowEnd: new Date(Date.now() + 60 * 60_000).toISOString(),
    status: 'active', signedBy: actor, signedAt: now(),
  };
  repos.consents.insert(consent);
  audit({
    tenantId, actor, action: 'quick.attest', target: host, outcome: 'allow',
    reason: '권한 보유 전자 확인 → 자산/동의 자동 생성', meta: { assetId: asset.id, consentId: consent.id },
  });

  const intensity: ScanIntensity = 'standard';
  const job = orchestrator.enqueue({ tenantId, asset, consent, modules, intensity, deep, actor });
  return { job, asset };
}
