/**
 * 인증서 투명성(CT) 로그 마이닝 — crt.sh 무료 공개 API.
 * 대상 도메인에 과거/현재 발급된 모든 공인 TLS 인증서의 SAN 필드를 수집하여
 * 워드리스트 열거가 놓치는 서브도메인·내부 호스트명을 발굴한다.
 *
 * crt.sh 는 외부 공개 서비스이므로 EgressGuard 대상(대상 호스트 패킷 발신)이 아니다.
 * 이는 DNS 리졸버 질의가 EgressGuard를 우회하는 것과 동일한 원칙 — 외부 정보 수집 API 조회.
 */

const TIMEOUT_MS = 12_000;

export interface CtEntry {
  hostname: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}

/** crt.sh JSON API 로 도메인의 CT 로그 항목 수집. */
export async function queryCrtSh(domain: string): Promise<CtEntry[]> {
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'user-agent': 'SENTINEL-ASM/1.0 (+ct-log-research; non-destructive)' },
    });
    if (!res.ok) return [];
    const data = await res.json() as Record<string, string>[];
    const seen = new Set<string>();
    const out: CtEntry[] = [];
    for (const entry of data) {
      const nameVal = (entry['name_value'] || entry['common_name'] || '').toLowerCase();
      for (const raw of nameVal.split(/\n|\s+/)) {
        const name = raw.trim().replace(/^\*\./, '');
        if (!name || seen.has(name)) continue;
        seen.add(name);
        // SAN 에서 대상 도메인의 서브도메인만 수집
        if (name.endsWith('.' + domain) && name !== domain) {
          out.push({
            hostname: name,
            issuer: (entry['issuer_name'] || '').replace(/^.*CN=/, '').slice(0, 60),
            notBefore: entry['not_before'] || '',
            notAfter: entry['not_after'] || '',
          });
        }
      }
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}

/** CT 로그에서 발견된 내부 명명 규칙 탐지 (staging-/internal-/vpn- 등). */
export function detectInternalNaming(entries: CtEntry[]): string[] {
  const internal = /\b(internal|staging|dev|test|uat|preprod|admin|corp|intranet|vpn|bastion|jump|mgmt|management|backup|old|legacy|ci|cd|jenkins|gitlab|jira|confluence|wiki|harbor|rancher|k8s|kube)/i;
  return entries.filter((e) => internal.test(e.hostname)).map((e) => e.hostname);
}
