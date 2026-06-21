/**
 * 위협 인텔(CTI / IoC) 소비·대조 — 설계 §4.3.
 * STIX2.1/TAXII2.1 또는 단순 줄단위 IoC 피드를 비파괴로 consume 하고(외부 CTI 인프라 호출, 점검 대상 미발신),
 * asm 이 해석한 발견 지표(IP/도메인/CNAME)를 known-bad 인덱스와 대조해 Finding 으로 enrich 한다.
 *
 * 안전: 외부로의 행위는 GET 소비만(STIX 게시·공격성 없음). 점검 대상에는 단 한 패킷도 보내지 않는다
 * (이미 asm 이 수행한 DNS 해석 결과를 읽어 대조만). 모든 외부 fetch 는 try/catch + 타임아웃(피드 단위 graceful).
 * 미설정 시 데모 지표(RFC5737/RFC2606 예약대역)로만 동작 — 실제 대상은 이 대역에 들지 않으므로 오탐 0.
 *
 * 순환참조 회피: asm.ts 가 본 모듈을 import 하므로, 여기서는 asm 의 mk()를 import 하지 않고 Finding 을 직접 생성한다.
 */
import { id } from '../../util.js';
import { config } from '../../config.js';
import type { Finding } from '../../types.js';
import type { ScanContext } from '../scanners/types.js';

export interface Indicator { type: 'ip' | 'domain' | 'cname' | 'url' | 'sha256'; value: string }
export interface IocMeta { source: string; label: string; demo: boolean }
export interface IocMatch { value: string; type: Indicator['type']; source: string; label: string; demo: boolean }

const REF_CTI = ['https://attack.mitre.org/', 'https://oasis-open.github.io/cti-documentation/'];

/** 데모 지표 — 모두 문서화/예약 대역이라 실제 대상엔 매칭되지 않는다(파이프라인 시연·테스트용). */
const DEMO_DOMAINS: Record<string, string> = {
  'malware.example': 'DEMO: 악성 배포 도메인(예약 TLD)',
  'c2.test': 'DEMO: C2 도메인(예약 TLD)',
  'phish.invalid': 'DEMO: 피싱 도메인(예약 TLD)',
};
/** RFC5737 문서화용 IPv4 대역 — 실제 호스트는 절대 이 대역으로 해석되지 않음. */
const DEMO_IP_CIDRS: { cidr: string; lo: number; hi: number; label: string }[] = [
  cidr('192.0.2.0/24', 'DEMO: 악성 IP(RFC5737 TEST-NET-1)'),
  cidr('198.51.100.0/24', 'DEMO: 악성 IP(RFC5737 TEST-NET-2)'),
  cidr('203.0.113.0/24', 'DEMO: 악성 IP(RFC5737 TEST-NET-3)'),
];
const DEMO_SHA256: Record<string, string> = {
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855: 'DEMO: 알려진 해시(빈 파일 SHA-256)',
};

export function isCtiConfigured(): boolean {
  return !!config.cti.taxiiUrl || config.cti.feedUrls.length > 0;
}
export function ctiStatus(): { configured: boolean; feeds: number; taxii: boolean; demo: boolean } {
  return { configured: isCtiConfigured(), feeds: config.cti.feedUrls.length, taxii: !!config.cti.taxiiUrl, demo: config.cti.enableDemoIndicators };
}

type IndicatorSet = { exact: Map<string, IocMeta>; ipRanges: typeof DEMO_IP_CIDRS };
let cachedSet: IndicatorSet | null = null;
let cachedAt = 0;

/** known-bad 인덱스 구성: 데모 + 줄단위 피드 + TAXII/STIX. 외부 실패는 해당 피드만 스킵(graceful).
 * 외부 피드 재다운로드를 막기 위해 10분 TTL 로 메모이즈(프로세스 단위). */
export async function loadIndicatorSet(): Promise<IndicatorSet> {
  if (cachedSet && Date.now() - cachedAt < 600_000) return cachedSet;
  const exact = new Map<string, IocMeta>();
  const ipRanges = [...(config.cti.enableDemoIndicators ? DEMO_IP_CIDRS : [])];
  if (config.cti.enableDemoIndicators) {
    for (const [d, label] of Object.entries(DEMO_DOMAINS)) exact.set(d, { source: 'demo', label, demo: true });
    for (const [h, label] of Object.entries(DEMO_SHA256)) exact.set(h, { source: 'demo', label, demo: true });
  }
  // 줄단위 IoC 피드
  for (const url of config.cti.feedUrls) {
    try {
      const txt = await fetchText(url);
      if (!txt) continue;
      for (const raw of txt.split(/\r?\n/)) {
        const line = raw.split(/[#;]/)[0]!.trim().toLowerCase();
        if (!line) continue;
        if (isIp(line) || isDomain(line) || isSha256(line)) exact.set(line, { source: 'feed', label: 'feed IoC', demo: false });
      }
    } catch { /* 해당 피드만 스킵 */ }
  }
  // TAXII 2.1 / STIX 2.1
  if (config.cti.taxiiUrl) {
    try {
      const url = `${config.cti.taxiiUrl.replace(/\/$/, '')}/${config.cti.apiRoot}/collections/${config.cti.collection}/objects/`;
      const json = await fetchJson(url, {
        accept: 'application/taxii+json;version=2.1',
        ...(config.cti.token ? { authorization: `Bearer ${config.cti.token}` } : {}),
      });
      const objs = (json as { objects?: { type?: string; pattern?: string; labels?: string[] }[] })?.objects ?? [];
      for (const o of objs) {
        if (o.type !== 'indicator' || !o.pattern) continue;
        const label = (o.labels && o.labels[0]) || 'taxii indicator';
        for (const m of o.pattern.matchAll(/(ipv4-addr|ipv6-addr|domain-name|url|file:hashes\.'SHA-256')[^=]*=\s*'([^']+)'/gi)) {
          const v = m[2]!.toLowerCase();
          if (v) exact.set(v, { source: 'taxii', label, demo: false });
        }
      }
    } catch { /* TAXII 실패 graceful */ }
  }
  cachedSet = { exact, ipRanges };
  cachedAt = Date.now();
  return cachedSet;
}

/** 지표 배열을 known-bad 인덱스와 대조. */
export function checkIndicators(indicators: Indicator[], set: { exact: Map<string, IocMeta>; ipRanges: typeof DEMO_IP_CIDRS }): IocMatch[] {
  const out: IocMatch[] = [];
  const seen = new Set<string>();
  for (const ind of indicators) {
    const v = normalize(ind);
    if (!v || seen.has(ind.type + ':' + v)) continue;
    seen.add(ind.type + ':' + v);
    // 정확 매칭 + (도메인) 접미사 매칭
    let meta = set.exact.get(v);
    if (!meta && (ind.type === 'domain' || ind.type === 'cname')) {
      for (const [ioc, m] of set.exact) { if (v.endsWith('.' + ioc)) { meta = m; break; } }
    }
    // IP 대역 멤버십 — IPv4 만(ip2int 는 IPv4 전용; IPv6 는 정확매칭만).
    if (!meta && ind.type === 'ip' && /^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
      const n = ip2int(v);
      const range = set.ipRanges.find((r) => n >= r.lo && n <= r.hi);
      if (range) meta = { source: 'demo', label: range.label, demo: true };
    }
    if (meta) out.push({ value: v, type: ind.type, source: meta.source, label: meta.label, demo: meta.demo });
  }
  return out;
}

/** asm 이 호출: 발견 지표를 받아 known-bad 매칭을 Finding 으로 생성. ctx 는 로깅용. */
export async function checkIndicatorsAndEnrich(ctx: ScanContext, indicators: Indicator[]): Promise<Finding[]> {
  try {
    const set = await loadIndicatorSet();
    const matches = checkIndicators(indicators, set);
    if (matches.length) ctx.log(`cti: 위협 인텔 매칭 ${matches.length}건(${matches.filter((m) => m.demo).length} 데모)`);
    return matches.map((m) => ctiFinding(m, ctx.asset.value));
  } catch (e) {
    ctx.log(`cti: 위협 인텔 대조 오류 — ${(e as Error).message}`);
    return [];
  }
}

function ctiFinding(m: IocMatch, host: string): Finding {
  const sev: Finding['severity'] = m.demo ? 'info' : (m.type === 'cname' ? 'medium' : 'high');
  const owasp = m.type === 'cname' ? 'A05:2021' : 'A06:2021';
  const kindKo = { ip: '악성 IP', domain: '악성 도메인', cname: 'CNAME known-bad 대상', url: '악성 URL', sha256: '악성 파일 해시' }[m.type];
  return {
    id: id('fnd'), module: 'asm', severity: sev,
    title: `위협 인텔/IoC 매칭${m.demo ? '[데모 지표]' : ''}: ${kindKo}`,
    target: host,
    description: m.demo
      ? `발견 지표가 데모 위협 인텔 지표와 매칭되었습니다(파이프라인 시연용 — 실제 위협 아님). 실 피드/TAXII 연동 시 동일 방식으로 known-bad 와 대조합니다.`
      : `발견된 ${kindKo}(${m.value})가 위협 인텔 피드의 알려진 악성 지표(IoC)와 매칭되었습니다. 침해 연관 가능성을 즉시 조사하십시오.`,
    evidence: `지표=${m.value} · 유형=${m.type} · 출처=${m.source} · 라벨=${m.label}`,
    remediation: m.demo
      ? 'SENTINEL_CTI_TAXII_URL 또는 SENTINEL_CTI_FEED_URLS 로 실제 위협 인텔 피드를 연동하면 운영 지표로 대조합니다.'
      : '매칭 자산을 격리·조사하고, 관련 통신 로그·접속 이력을 분석하십시오. IoC 출처의 캠페인/위협 행위자 정보를 확인해 대응하십시오.',
    owasp, cwe: 'CWE-506', confidence: m.demo ? 'tentative' : 'firm', references: REF_CTI,
  };
}

// ── 외부 fetch (인프라 호출, EgressGuard 우회 — ai/provider.ts 선례) ──
async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(config.cti.timeoutMs), redirect: 'manual' });
    if (!res.ok) return null;
    return (await res.text()).slice(0, 1_000_000);
  } catch { return null; }
}
async function fetchJson(url: string, headers: Record<string, string>): Promise<unknown> {
  const res = await fetch(url, { signal: AbortSignal.timeout(config.cti.timeoutMs), headers, redirect: 'manual' });
  if (!res.ok) return null;
  return res.json();
}

// ── 정규화/판정 ──
function normalize(ind: Indicator): string {
  let v = (ind.value || '').trim().toLowerCase();
  if (!v) return '';
  if (ind.type === 'ip') return v.replace(/^::ffff:/, '');
  if (ind.type === 'url') { try { v = new URL(v).hostname; } catch { /* */ } }
  return v.replace(/\.$/, ''); // trailing dot 제거(도메인/cname)
}
function isIp(s: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true;                                  // IPv4
  if (!/^[0-9a-f:]+$/i.test(s) || !/[0-9a-f]/i.test(s)) return false;                   // IPv6 후보(hex+콜론)
  return s.includes('::') || (s.match(/:/g) || []).length >= 2;                         // 'cafe:'/'a:b' 등 과대매칭 배제
}
function isDomain(s: string): boolean { return /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i.test(s); }
function isSha256(s: string): boolean { return /^[a-f0-9]{64}$/i.test(s); }
function ip2int(ip: string): number { return ip.split('.').reduce((a, o) => (a << 8) + (Number(o) & 255), 0) >>> 0; }
function cidr(c: string, label: string): { cidr: string; lo: number; hi: number; label: string } {
  const [net, bitsStr] = c.split('/');
  const bits = Number(bitsStr);
  const base = ip2int(net!);
  const size = bits === 0 ? 0xffffffff : (2 ** (32 - bits)) - 1;
  return { cidr: c, lo: base, hi: (base + size) >>> 0, label };
}
