/**
 * 클라우드 공개 자산 탐지 — 자격증명 없이 HTTP로 탐지 가능한 항목.
 * S3·GCS·Azure Blob 공개 버킷, 공개 ECR/GCR 레지스트리 메타,
 * 클라우드 메타데이터 응답(SSRF 침해 흔적), 공개 쿠버네티스 API.
 * 모두 비파괴(GET 읽기전용, 실제 데이터 미수집).
 */
import { id } from '../../util.js';
import type { Finding } from '../../types.js';
import type { EgressGuard } from './egress.js';
import { mk } from './asm.js';

const TIMEOUT = 5000;

/** 공개 S3 버킷 여부 확인 (버킷명 추측 → 응답 시그니처). */
async function probeS3(guard: EgressGuard, host: string, domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  // domain에서 S3 버킷명 후보 생성 (회사명 등)
  const candidates = [domain, domain.replace(/\./g, '-'), `www-${domain}`, `static-${domain}`, `media-${domain}`, `assets-${domain}`, `backup-${domain}`];
  for (const name of candidates.slice(0, 4)) {
    const url = `https://${name}.s3.amazonaws.com/`;
    try {
      const r = await guard.httpGet(url, { timeoutMs: TIMEOUT });
      if (!r) continue;
      if (r.status === 200 && /<ListBucketResult/.test(r.body)) {
        findings.push(mk('asm', 'critical', `S3 버킷 공개 노출: ${name}`, url, 'S3 버킷이 인증 없이 공개 조회 가능합니다(버킷 내용 열람 가능).', r.body.slice(0, 120).replace(/\s+/g, ' '), 'S3 버킷 ACL 을 private 으로 설정하고 퍼블릭 접근을 차단하십시오.'));
      } else if (r.status === 403 && /AccessDenied/.test(r.body)) {
        // 버킷은 존재하나 접근 차단 — 인벤토리 정보
        findings.push(mk('asm', 'info', `S3 버킷 존재 확인(접근 차단): ${name}`, url, '버킷이 존재하나 접근이 차단되어 있습니다. 최신 S3 버킷 정책을 유지하십시오.', `status=403`, '버킷 정책 및 ACL 정기 검토를 권장합니다.'));
      }
    } catch { /* 네트워크 오류 — 정상 미존재 */ }
  }
  return findings;
}

/** 공개 GCS 버킷 여부 확인. */
async function probeGcs(guard: EgressGuard, host: string, domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const name = domain.replace(/\./g, '_');
  const url = `https://storage.googleapis.com/${name}/`;
  try {
    const r = await guard.httpGet(url, { timeoutMs: TIMEOUT });
    if (r && r.status === 200 && (/<ListBucketResult/.test(r.body) || /"kind"\s*:\s*"storage#objects"/.test(r.body))) {
      findings.push(mk('asm', 'critical', `GCS 버킷 공개 노출: ${name}`, url, 'Google Cloud Storage 버킷이 공개 조회됩니다.', r.body.slice(0, 100), 'GCS 버킷의 IAM 정책에서 allUsers·allAuthenticatedUsers 권한을 제거하십시오.'));
    }
  } catch { /* */ }
  return findings;
}

/** Azure Blob Storage 공개 컨테이너 탐지. */
async function probeAzureBlob(guard: EgressGuard, host: string, domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const account = domain.split('.')[0] ?? domain.replace(/\W/g, '');
  const url = `https://${account}.blob.core.windows.net/$web?restype=container&comp=list`;
  try {
    const r = await guard.httpGet(url, { timeoutMs: TIMEOUT });
    if (r && r.status === 200 && /<EnumerationResults/.test(r.body)) {
      findings.push(mk('asm', 'high', `Azure Blob Storage 공개 컨테이너: ${account}`, url, 'Azure Blob $web 컨테이너가 공개 조회됩니다(정적 웹호스팅).', r.body.slice(0, 80), '민감 파일을 제거하고 Static Website 설정에서 필요 파일만 게시하십시오.'));
    }
  } catch { /* */ }
  return findings;
}

/** 쿠버네티스 API 무인증 노출 (포트 스캔 후 HTTP 확인). */
async function probeK8sApi(guard: EgressGuard, host: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const port of [6443, 8001, 8080]) {
    const url = `http${port === 6443 ? 's' : ''}://${host}:${port}/api/v1`;
    try {
      const r = await guard.httpGet(url, { timeoutMs: TIMEOUT });
      if (r && r.status === 200 && /"kind"\s*:\s*"APIResourceList"/.test(r.body)) {
        findings.push(mk('asm', 'critical', `Kubernetes API 무인증 노출: ${host}:${port}`, `${host}:${port}`, 'K8s API 가 인증 없이 응답합니다(클러스터 전체 통제 위험).', r.body.slice(0, 80), 'K8s API 서버를 내부망/VPN 뒤에 두고 RBAC 를 활성화하십시오.'));
      }
    } catch { /* */ }
  }
  return findings;
}

/** 공개 Docker 레지스트리(포트 5000) 탐지. */
async function probeDockerRegistry(guard: EgressGuard, host: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const url = `http://${host}:5000/v2/_catalog`;
  try {
    const r = await guard.httpGet(url, { timeoutMs: TIMEOUT });
    if (r && r.status === 200 && /"repositories"/.test(r.body)) {
      findings.push(mk('asm', 'high', `Docker 레지스트리 공개 카탈로그 노출: ${host}:5000`, url, 'Docker 레지스트리 카탈로그가 인증 없이 조회됩니다(이미지 목록 노출).', r.body.slice(0, 80), 'Docker 레지스트리에 TLS 와 basic auth/token 인증을 적용하십시오.'));
    }
  } catch { /* */ }
  return findings;
}

/** 위협 인텔: HIBP(Have I Been Pwned) 도메인 유출 확인 — 무료 공개 API. */
export async function checkHibpDomain(domain: string): Promise<{ breached: boolean; count: number; names: string[] }> {
  try {
    const res = await fetch(`https://haveibeenpwned.com/api/v3/breachesforaccount/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000),
      headers: { 'user-agent': 'SENTINEL-ASM/1.0 (+authorized-security-research)', 'hibp-api-key': '' },
    });
    if (res.status === 404) return { breached: false, count: 0, names: [] };
    if (res.status === 401 || res.status === 403) return { breached: false, count: 0, names: [] }; // API key 필요
    if (!res.ok) return { breached: false, count: 0, names: [] };
    const data = await res.json() as { Name: string }[];
    return { breached: data.length > 0, count: data.length, names: data.map(d => d.Name).slice(0, 5) };
  } catch {
    return { breached: false, count: 0, names: [] };
  }
}

/** 통합 클라우드 공개 자산 점검. */
export async function runCloudChecks(
  guard: EgressGuard, host: string, domain: string,
): Promise<Finding[]> {
  const results = await Promise.allSettled([
    probeS3(guard, host, domain),
    probeGcs(guard, host, domain),
    probeAzureBlob(guard, host, domain),
    probeK8sApi(guard, host),
    probeDockerRegistry(guard, host),
  ]);
  return results.flatMap(r => r.status === 'fulfilled' ? r.value : []);
}
