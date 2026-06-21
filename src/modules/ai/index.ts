/**
 * AI 보안 분석 엔진 (설계 §5.3) — 사이트 맞춤 적응형 점검.
 *
 * 흐름: 핑거프린트(PII 마스킹) → LLM 이 사이트 특화 점검 후보 제안(계획) →
 *       기존 비파괴 엔진이 EgressGuard 로 GET/HEAD/OPTIONS 만 실행(검증) → 구체 신호 관측 시에만 발견 생성.
 *
 * 안전 불변식:
 *  - LLM 은 절대 패킷을 보내지 않는다. 제안 경로는 동일 출처·읽기전용 메서드로 필터된 뒤 가드를 통과한다.
 *  - "AI 가 제안했다"는 사실만으로는 발견이 아니다. 응답에서 PII·인가누락·정보노출 등 구체 신호가
 *    실제로 관측될 때만 Finding 을 만들고, 휴리스틱은 confidence='tentative' 로 표기한다.
 *  - 키 미설정 시 즉시 빈 결과(점검 무중단).
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from '../scanners/types.js';
import { mk } from '../scanners/asm.js';
import { analyzePii, parseJson, recordCount } from '../scanners/apiexposure.js';
import { isAiConfigured, aiStatus } from './provider.js';
import { buildFingerprint } from './fingerprint.js';
import { proposeProbes, type AiProbe } from './planner.js';
import { config } from '../../config.js';

export { aiStatus, isAiConfigured } from './provider.js';
export { analyzeFindings, type AiAnalysis } from './analyst.js';
export { buildFingerprint } from './fingerprint.js';
export { proposeProbes } from './planner.js';

type HttpResp = { ok: boolean; status: number; headers: Record<string, string>; body: string };

const REF = ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/', 'https://cwe.mitre.org/data/definitions/284.html'];

export const aiScanner: Scanner = {
  module: 'ai',
  minIntensity: 'standard',
  async run(ctx: ScanContext): Promise<Finding[]> {
    if (!isAiConfigured()) {
      ctx.log('ai: 미구성 — SENTINEL_AI_API_KEY(또는 ANTHROPIC_API_KEY) 설정 시 적응형 AI 점검 활성화');
      return [];
    }
    const findings: Finding[] = [];
    const scheme = ctx.asset.type === 'host' ? 'http' : 'https';
    const base = `${scheme}://${ctx.asset.value}`;
    const host = ctx.asset.value;
    const root = await ctx.guard.httpGet(base + '/');
    if (!root) { ctx.log('ai: 대상 응답 없음 — 점검 생략'); return findings; }

    const rndPath = `/sentinel-ai-${Math.random().toString(36).slice(2)}`;
    const baseline = await ctx.guard.httpGet(base + rndPath);
    const baseStatus = baseline?.status ?? 404;
    const baseBody = baseline?.body ?? '';

    // robots/sitemap 로 추가 경로 힌트(비파괴 GET)
    const extraPaths: string[] = [];
    const robots = await ctx.guard.httpGet(base + '/robots.txt');
    if (robots && robots.status === 200 && /(allow|disallow|sitemap)/i.test(robots.body)) {
      for (const m of robots.body.matchAll(/(?:allow|disallow)\s*:\s*(\/[^\s#]{1,60})/gi)) extraPaths.push(m[1]!);
    }

    const fp = buildFingerprint({ host, scheme, status: root.status, headers: root.headers, body: root.body, extraPaths: extraPaths.slice(0, 20) });
    ctx.log(`ai: 핑거프린트 — 용도힌트=[${fp.purposeHints.join(',')}] 기술=[${fp.tech.join(',')}] API힌트=${fp.apiHints.length}`);

    const probes = await proposeProbes(fp, config.ai.maxProbes);
    if (!probes.length) { ctx.log('ai: 제안 없음(모델 무응답 또는 후보 없음)'); return findings; }
    ctx.log(`ai: 모델이 사이트 특화 점검 ${probes.length}건 제안 — 비파괴 검증 시작`);

    const seenPath = new Set<string>();
    let verified = 0;
    for (const probe of probes) {
      if (seenPath.has(probe.path)) continue;
      seenPath.add(probe.path);
      const f = await verifyProbe(ctx, base, host, probe, { baseStatus, baseBody, rootBody: root.body });
      if (f) { findings.push(f); verified++; }
    }
    ctx.log(`ai: 제안 ${probes.length}건 중 구체 신호 확인 ${verified}건`);
    return findings;
  },
};

interface VBase { baseStatus: number; baseBody: string; rootBody: string }

/** AI 제안 경로를 비파괴로 호출하고, 응답에서 구체 신호가 관측될 때만 Finding 을 만든다. */
async function verifyProbe(ctx: ScanContext, base: string, host: string, probe: AiProbe, vb: VBase): Promise<Finding | null> {
  const r = await ctx.guard.httpGet(base + probe.path, { method: probe.method, headers: { accept: 'application/json,text/html,*/*' } });
  if (!r) return null;
  const why = `AI 가설(${probe.category}): ${probe.rationale}${probe.expect ? ` | 확인기준: ${probe.expect}` : ''}`;

  // OPTIONS — 위험 메서드 노출만 관측
  if (probe.method === 'OPTIONS') {
    const allow = (r.headers['allow'] || r.headers['access-control-allow-methods'] || '').toUpperCase();
    const risky = ['PUT', 'DELETE', 'PATCH', 'TRACE'].filter((m) => allow.includes(m));
    if (risky.length) return build('low', `[AI] 위험 HTTP 메서드 허용: ${probe.path} (${risky.join(',')})`, host + probe.path,
      `AI 가 점검 제안한 경로에서 위험 메서드(${risky.join(',')})가 허용됩니다.`, `Allow: ${allow} | ${why}`,
      '불필요한 쓰기/추적 메서드를 비활성화하십시오.', 'A05:2021', 'CWE-650', 'tentative');
    return null;
  }
  if (probe.method === 'HEAD') {
    if (r.status === 200 && /admin|internal|backup|\.env|config|export|dump/i.test(probe.path)) {
      return build('info', `[AI] 민감 추정 경로 존재(HEAD 200): ${probe.path}`, host + probe.path,
        `AI 가 민감 추정으로 제안한 경로가 200 으로 존재합니다(본문 미확인).`, `HEAD 200 | ${why}`,
        '해당 경로의 인가·노출 여부를 확인하십시오.', 'A05:2021', 'CWE-200', 'tentative');
    }
    return null;
  }

  // GET
  if (r.status === 401 || r.status === 403) return null;             // 정상 보호
  if (r.status !== 200 || !r.body) return null;
  if (isShell(r, vb) || looksLikeLogin(r.body)) return null;          // 셸/로그인 게이트 = 신호 아님

  // JSON → PII / 과다 노출
  if (looksJson(r)) {
    const parsed = parseJson(r.body);
    if (parsed !== undefined) {
      const a = analyzePii(r.body, parsed);
      const records = recordCount(parsed);
      const ct = (r.headers['content-type'] || '').split(';')[0] || 'json';
      const strong = a.rrn || a.card || a.emails.size >= 2 || a.phones.size >= 2 || (records >= 2 && (a.emails.size >= 1 || a.phones.size >= 1));
      if (strong) return build('critical', `[AI] 인증 없이 개인정보 노출 — 사이트 특화 API: ${probe.path}`, host + probe.path,
        `AI 가 이 사이트의 데이터 모델을 추론해 제안한 엔드포인트가 인증 없이 개인정보를 반환합니다(레코드 ${records}건, ${piiDetail(a)}).`,
        `status=200 ${ct}, records≈${records}, ${piiDetail(a)}; sample=${a.sample} | ${why}`,
        '데이터 API 에 인증·객체/필드 수준 인가를 강제하고 응답을 최소 필드로 제한하십시오. 노출된 개인정보는 즉시 차단·통지하십시오.',
        'A01:2021', 'CWE-359', (a.rrn || a.card) ? 'confirmed' : 'firm');
      if (records >= 5 || a.sensitiveKeys.size >= 2) return build('medium', `[AI] 인증 없이 데이터 노출(과다 노출) — 사이트 특화 API: ${probe.path}`, host + probe.path,
        `AI 가 제안한 엔드포인트가 인증 없이 데이터를 반환합니다(레코드 ${records}건${a.sensitiveKeys.size ? `, 민감필드 ${[...a.sensitiveKeys].slice(0, 5).join('/')}` : ''}).`,
        `status=200 ${ct}, records≈${records} | ${why}`,
        '비공개 데이터라면 인증·인가를 강제하고 응답 스키마를 최소화하십시오.', 'A01:2021', 'CWE-213', 'tentative');
    }
    return null;
  }

  // HTML → 관리/내부 영역, 정보 노출
  const body = r.body;
  if (/logout|로그아웃|sign\s?out|admin panel|관리자 패널|관리자 메뉴|관리자 대시보드|admin dashboard|회원 관리|user list|사용자 목록/i.test(body)) {
    return build('high', `[AI] 비인가 관리/내부 영역 접근 가능: ${probe.path}`, host + probe.path,
      `AI 가 관리/내부로 추정해 제안한 경로가 인증 없이 관리/세션 콘텐츠를 200 으로 반환합니다.`,
      `status=200, 관리/세션 시그니처 일치 | ${why}`,
      '민감 경로에 서버측 인증·역할기반 인가를 강제하십시오(화면 숨김만으로는 통제 불가).', 'A01:2021', 'CWE-862', 'tentative');
  }
  const leak = matchLeak(body);
  if (leak) return build('medium', `[AI] 민감 정보/설정 노출: ${probe.path} (${leak})`, host + probe.path,
    `AI 가 제안한 경로에서 ${leak} 시그니처가 관측됩니다.`, `${leak} | ${why}`,
    '민감 파일/디버그/설정 노출을 차단하고 운영에서 상세 정보를 숨기십시오.', 'A05:2021', 'CWE-200', 'tentative');
  if (/<title>Index of|Directory listing for/i.test(body)) return build('medium', `[AI] 디렉터리 인덱싱 노출: ${probe.path}`, host + probe.path,
    `AI 가 제안한 경로에서 디렉터리 자동 목록이 노출됩니다.`, `directory listing | ${why}`,
    '웹서버 디렉터리 인덱싱을 비활성화하십시오.', 'A05:2021', 'CWE-548', 'firm');
  return null;

  function build(sev: Finding['severity'], title: string, target: string, desc: string, evidence: string, remediation: string, owasp: string, cwe: string, confidence: Finding['confidence']): Finding {
    return { ...mk('ai', sev, title, target, desc, evidence, remediation), owasp, cwe, confidence, references: REF };
  }
}

function isShell(r: HttpResp, vb: VBase): boolean {
  return (vb.baseStatus === 200 && r.status === 200 && similar(r.body, vb.baseBody)) || similar(r.body, vb.rootBody);
}
function looksJson(r: HttpResp): boolean {
  const ct = (r.headers['content-type'] || '').toLowerCase();
  if (ct.includes('json')) return true;
  const t = r.body.trim();
  return (t[0] === '{' || t[0] === '[') && !/^<(!doctype|html)/i.test(t);
}
function looksLikeLogin(body: string): boolean {
  if (/type\s*=\s*["']password["']/i.test(body)) return true;
  const b = body.slice(0, 30_000).toLowerCase();
  return /(로그인|sign\s?in|log\s?in|authentication required|unauthorized|권한이 없|접근 권한)/i.test(b) && body.length < 24_000;
}
function matchLeak(b: string): string | null {
  if (/^[A-Z0-9_]+\s*=|APP_KEY|DB_PASSWORD|SECRET|API_KEY/m.test(b.slice(0, 4000))) return '환경설정(.env류)';
  if (/Traceback \(most recent call last\)|Exception in thread|at [\w.$]+\([\w]+\.java:\d+\)|Stack trace:\s*#0|Werkzeug Debugger/.test(b)) return '스택트레이스';
  if (/\[core\]|repositoryformatversion/.test(b)) return 'Git 설정';
  if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(b)) return '개인키';
  if (/phpinfo\(\)|PHP Version/.test(b)) return 'phpinfo';
  return null;
}
function piiDetail(a: { emails: Set<string>; phones: Set<string>; rrn: boolean; card: boolean; sensitiveKeys: Set<string> }): string {
  const bits: string[] = [];
  if (a.emails.size) bits.push(`이메일 ${a.emails.size}건`);
  if (a.phones.size) bits.push(`휴대전화 ${a.phones.size}건`);
  if (a.rrn) bits.push('주민등록번호(검증)');
  if (a.card) bits.push('신용카드(검증)');
  if (a.sensitiveKeys.size) bits.push(`민감필드 ${[...a.sensitiveKeys].slice(0, 4).join('/')}`);
  return bits.join(', ') || '데이터';
}
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (Math.abs(a.length - b.length) > Math.max(48, Math.min(a.length, b.length) * 0.15)) return false;
  const n = Math.min(a.length, b.length, 600);
  if (n === 0) return false;
  let same = 0;
  for (let i = 0; i < n; i++) if (a[i] === b[i]) same++;
  return same / n > 0.9;
}
