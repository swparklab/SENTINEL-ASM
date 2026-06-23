/**
 * 대역외(Out-of-Band) 능동 확정 — Active OOB Confirmation (설계 §4.5 active).
 *
 * 응답 본문에 신호가 안 보이는 blind 취약점(blind SSRF 등)을, 페이로드에 콜라보레이터 URL 을 심어
 * 대상이 **대역외로 우리 콜백 엔드포인트를 호출**하면 확정한다(Burp Collaborator 방식).
 *
 * 비파괴 엄수: 스캐너는 GET 만 발신(EgressGuard 강제), 콜백 신호(토큰 일치)만 확인한다. 대상 상태를
 * 변경·삭제하지 않고, 콜백에는 어떤 대상 데이터도 실어 나르지 않는다(토큰=상관관계 식별자일 뿐).
 * 게이트: ctx.active(=aggressive + 4-eyes 서면승인)인 경우에만 실행한다.
 * collaboratorBase 미설정 시 콜백 수신이 불가하므로 OOB 확정을 건너뛴다.
 */
import type { Finding } from '../../types.js';
import type { ScanContext } from './types.js';
import { mk } from './asm.js';
import { config } from '../../config.js';

export interface OobHit { token: string; ts: number; path: string; method: string; ua: string; remote: string }

// 프로세스 내 콜라보레이터 저장소(토큰 → 상호작용). 라우트(/collab/:token)가 기록하고 스캐너가 조회한다.
const HITS = new Map<string, OobHit[]>();
const TOKEN_JOB = new Map<string, string>();   // token → jobId (감사/정리용)

/** 점검 작업용 OOB 토큰 발급(상관관계 식별자). */
export function mintOobToken(jobId: string): string {
  const tok = 'oob' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
  TOKEN_JOB.set(tok, jobId);
  if (!HITS.has(tok)) HITS.set(tok, []);
  return tok;
}

/** 콜라보레이터 라우트가 호출 — 대역외 상호작용 1건 기록. */
export function recordOobHit(token: string, meta: { path?: string; method?: string; ua?: string; remote?: string }): boolean {
  const arr = HITS.get(token);
  if (!arr) return false;   // 미발급 토큰은 무시(노이즈/스캐닝 차단)
  if (arr.length < 50) arr.push({ token, ts: Date.now(), path: meta.path ?? '/', method: meta.method ?? 'GET', ua: (meta.ua ?? '').slice(0, 120), remote: (meta.remote ?? '').slice(0, 64) });
  return true;
}

export function oobHits(token: string): OobHit[] { return HITS.get(token) ?? []; }

/** 콜라보레이터 베이스 URL(대상이 도달 가능한 공개 도메인/IP). 미설정 시 빈 문자열. */
export function collaboratorBase(): string { return config.oob.collaboratorBase; }

/** 작업 종료 시 토큰/상호작용 정리(메모리 누수 방지). */
export function purgeOobJob(jobId: string): void {
  for (const [tok, jid] of TOKEN_JOB) if (jid === jobId) { TOKEN_JOB.delete(tok); HITS.delete(tok); }
}

// SSRF 가 발생하기 쉬운 파라미터/헤더(서버측 URL fetch 표면).
const SSRF_PARAMS = /^(url|uri|link|href|redirect|redirect_uri|next|return|return_url|callback|image|img|src|source|path|dest|destination|feed|rss|webhook|host|domain|target|proxy|fetch|load|file|page|site|u|q)$/i;

type ParamLite = { path: string; param: string; value: string; url: (encVal: string) => string };

const REF_SSRF = ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/', 'https://cwe.mitre.org/data/definitions/918.html'];

/**
 * blind SSRF 대역외 확정 — SSRF 의심 파라미터/헤더에 콜라보레이터 URL 을 주입하고, 대상이 콜백하면 확정.
 * (응답 본문 신호가 없어도 OOB 콜백으로 확정 — 단순 관찰을 넘어선 능동 확정, 비파괴.)
 */
export async function runOobConfirmation(ctx: ScanContext, base: string, host: string, params: ParamLite[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (!ctx.active || ctx.intensity !== 'aggressive') return findings;   // 방어심도: active(=aggressive+4-eyes)에서만
  const collab = collaboratorBase();
  if (!collab) { ctx.log('oob: collaboratorBase 미설정 — 대역외 확정 생략(콜백 수신 불가)'); return findings; }

  const candidates = params.filter((p) => SSRF_PARAMS.test(p.param)).slice(0, 6);
  if (!candidates.length) { ctx.log('oob: SSRF 의심 파라미터 없음 — 대역외 SSRF 확정 생략'); return findings; }
  ctx.log(`oob: SSRF 의심 파라미터 ${candidates.length}개로 대역외 콜백 확정 시도(비파괴: 콜백 신호만)`);

  const probes: { token: string; how: string }[] = [];
  for (const p of candidates) {
    const token = mintOobToken(ctx.jobId);
    // http/https 두 스킴으로 콜라보레이터 경로 콜백 유도(데이터 미적재 — 토큰만).
    const payloadUrl = `${collab}/${token}`;
    await ctx.guard.httpGet(p.url(encodeURIComponent(payloadUrl)), { timeoutMs: 7000 }).catch(() => null);
    probes.push({ token, how: `파라미터 ${p.param}` });
  }
  // 헤더 기반 SSRF(서버측 URL 빌드/프록시) — 소수 표준 헤더만.
  {
    const token = mintOobToken(ctx.jobId);
    const payloadUrl = `${collab}/${token}`;
    const dom = collab.replace(/^https?:\/\//, '');
    await ctx.guard.httpGet(base + '/', { timeoutMs: 7000, headers: { 'x-forwarded-host': `${token}.${dom}`, 'forwarded': `host=${token}.${dom}` } }).catch(() => null);
    probes.push({ token, how: '헤더(X-Forwarded-Host/Forwarded)' });
  }

  // 콜백 수신 대기(비동기 대역외) 후 토큰별 상호작용 확인.
  await sleep(config.oob.waitMs);
  for (const pr of probes) {
    const hits = oobHits(pr.token);
    if (hits.length) {
      const h = hits[0]!;
      findings.push({ ...mk('dast', 'high', `[활성 확정·대역외] Blind SSRF 확정 — ${pr.how}`, host,
        `${pr.how} 에 심은 콜라보레이터 URL 로 대상 서버가 대역외 콜백을 보냈습니다. 응답 본문 신호 없이도 서버측 요청 위조(SSRF)가 확정됩니다 — 내부 서비스·클라우드 메타데이터 접근으로 확장될 수 있습니다(콜백 신호만 확인, 대상 데이터 미수집).`,
        `OOB 콜백 수신: token=${pr.token}, ${h.method} ${h.path}, src=${h.remote || 'n/a'} (대역외 상호작용 ${hits.length}회)`,
        '서버측 URL fetch 를 허용목록(스킴/호스트)으로 제한하고, 내부망·링크로컬(169.254.169.254)·메타데이터 IP 로의 요청을 차단하며, 리다이렉트 추적을 비활성화하십시오.',
        ), owasp: 'A10:2021', cwe: 'CWE-918', confidence: 'confirmed', references: REF_SSRF });
    }
  }
  ctx.log(`oob: 대역외 확정 ${findings.length}건`);
  return findings;
}

function sleep(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, Math.max(0, Math.min(ms, 15_000)))); }
