/**
 * 활성(침투) 검증 — Active Vulnerability Confirmation (설계 §4.5 aggressive 프로파일).
 *
 * "마커만 관측"하던 비파괴 점검을 한 단계 끌어올려, 취약점을 **실제로 트리거해 확정**한다.
 * 단, 비파괴 한계는 그대로다 — 데이터 변경·삭제, DoS/플러딩, 무차별 대입, 실 악성 페이로드는 수행하지 않는다.
 * 확정 방식은 모두 "읽기전용 차분/반사/소량 열거"이며 요청 수는 기법당 소수로 제한한다(브루트포스 아님).
 *
 * 게이트: ctx.active 는 evaluateGate 에서 aggressive 강도 + 4-eyes 서면승인을 통과한 경우에만 true 다.
 *
 * 확정 기법:
 *  (1) Boolean 기반 SQL 인젝션 — `AND 1=1`(참) vs `AND 1=2`(거짓) 응답 차분으로 주입을 확정.
 *      데이터 추출/변경 없이 참/거짓 분기만 관측한다(UNION/스택트/시간폭주/DROP 미사용).
 *  (2) 반사형 XSS 컨텍스트 확정 — HTML/속성 컨텍스트 이스케이프 마커가 인코딩 없이 실행 위치에 반사되는지.
 *      실제 스크립트 실행을 유도하지 않고 안전 토큰의 미인코딩 반사만 확인한다.
 *  (3) IDOR/BOLA 확정 — 인접 식별자 소량(≤4) 읽기전용 열람으로 타 객체 무인증 접근을 확정한다.
 */
import type { Finding } from '../../types.js';
import type { ScanContext } from './types.js';
import { mk } from './asm.js';
import { analyzePii } from './apiexposure.js';
import { buildParamUrl, type ParamTarget as CrawlParam } from './crawl.js';

type HttpResp = { ok: boolean; status: number; headers: Record<string, string>; body: string };

const REF_SQLI = ['https://owasp.org/Top10/A03_2021-Injection/', 'https://cwe.mitre.org/data/definitions/89.html'];
const REF_XSS = ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', 'https://cwe.mitre.org/data/definitions/79.html'];
const REF_IDOR = ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/', 'https://cwe.mitre.org/data/definitions/639.html'];

export async function runActiveConfirmation(
  ctx: ScanContext, base: string, host: string, root: HttpResp, baseStatus: number, baseBody: string,
  extraParams?: CrawlParam[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  // 방어심도: 게이트/오케스트레이터가 active⟹aggressive+4-eyes 를 보장하지만, 소비자 단에서도 강도를 재확인한다.
  // (어떤 모듈이 ctx.active 를 읽든 aggressive 가 아니면 활성 침투를 절대 실행하지 않는다.)
  if (ctx.intensity !== 'aggressive') { ctx.log('active: aggressive 강도가 아니어서 활성 검증 생략(방어심도)'); return findings; }
  const get = (url: string) => ctx.guard.httpGet(url, { timeoutMs: 7000 });
  const isSoft404 = (r: HttpResp | null): boolean =>
    !!r && baseStatus === 200 && r.status === 200 && similar(r.body, baseBody);
  const ok = (r: HttpResp | null): r is HttpResp => !!r && r.status === 200 && !!r.body && !isSoft404(r);

  const targets = collectParamTargets(root.body, base);
  // 전수 크롤로 발견한 파라미터까지 확정 점검 대상에 병합(중복 제거) — 홈페이지뿐 아니라 앱 전체 표면을 능동 확정.
  if (extraParams?.length) {
    const seen = new Set(targets.map((t) => t.path + '?' + t.param));
    for (const e of extraParams) {
      const key = e.path + '?' + e.param;
      if (seen.has(key) || targets.length >= 25) continue;
      seen.add(key);
      // 형제 파라미터를 보존하는 URL 빌더(buildParamUrl)로 능동 확정 표적 추가.
      targets.push({ path: e.path, param: e.param, orig: e.value || '1', url: (encVal) => buildParamUrl(base, e, encVal) });
    }
  }
  ctx.log(`active: 파라미터 표적 ${targets.length}개로 침투 확정 시작(비파괴: 데이터 변경·DoS·brute-force 없음)`);

  // ── (1) Boolean 기반 SQLi 확정 ──
  let sqliDone = 0;
  for (const t of targets) {
    if (sqliDone >= 3) break;
    const orig = await get(t.url(enc(t.orig)));
    if (!ok(orig)) { sqliDone++; continue; }   // 표적당 1회 카운트 — 비-200 표적이 많아도 cap(3)을 실제로 강제.
    // 베이스라인 안정성 게이트: 동일 입력을 2회 호출해 자기차분이 작을 때만(결정적 페이지) 차분을 신뢰한다.
    // 타임스탬프·랜덤배너·CSRF 토큰 등 비결정적 본문에서의 boolean 오탐을 차단한다.
    const orig2 = await get(t.url(enc(t.orig)));
    if (!ok(orig2) || !similar(orig.body, orig2.body)) { sqliDone++; continue; }
    // 숫자 컨텍스트: AND 1=1 / AND 1=2
    const variants: { t: string; f: string; kind: string }[] = [
      { t: `${enc(t.orig)}%20AND%201%3D1`, f: `${enc(t.orig)}%20AND%201%3D2`, kind: '숫자' },
      { t: `${enc(t.orig)}%27%20AND%20%271%27%3D%271`, f: `${enc(t.orig)}%27%20AND%20%271%27%3D%272`, kind: '문자열' },
    ];
    let confirmed = false;
    for (const v of variants) {
      const rt = await get(t.url(v.t));
      const rf = await get(t.url(v.f));
      if (!ok(rt) || !rf) continue;
      // 참 응답은 원본과 동일, 거짓 응답은 유의미하게 다름(소프트404 아님) → boolean SQLi 확정.
      const trueLikeOrig = similar(orig.body, rt.body);
      const falseDiffers = !similar(rt.body, rf.body) && !isSoft404(rf);
      if (trueLikeOrig && falseDiffers) {
        findings.push(mkActive('high', `[활성 확정] SQL 인젝션 확정 — Boolean 차분(${v.kind}): ${t.param}`, host + t.path,
          `파라미터 '${t.param}' 에서 \`AND 1=1\`(참)은 원본과 동일한 응답을, \`AND 1=2\`(거짓)은 다른 응답을 반환합니다. 입력이 SQL 질의에 그대로 합쳐져 참/거짓이 결과를 바꾸는 SQL 인젝션이 확정되었습니다(데이터 추출·변경 없이 차분만 관측).`,
          `${t.param}: AND 1=1 ≈ 원본 / AND 1=2 ≠ (Boolean 분기 확인, ${v.kind} 컨텍스트)`,
          '모든 DB 질의를 파라미터화(Prepared Statement)하고 입력을 화이트리스트 검증하십시오. ORM/바인딩을 사용하고 동적 문자열 결합을 제거하십시오.',
          'A03:2021', 'CWE-89', 'firm', REF_SQLI));
        confirmed = true; break;
      }
    }
    sqliDone++;
    if (confirmed) continue;
  }

  // ── (2) 반사형 XSS 컨텍스트 확정 ──
  let xssDone = 0;
  for (const t of targets) {
    if (xssDone >= 2) break;
    xssDone++;
    const tok = 'sx' + rnd();
    // HTML 컨텍스트 이스케이프 + 속성 컨텍스트 이스케이프 마커(안전 토큰, 실제 실행 유도 없음)
    const payload = `"'></x><${tok} q="${tok}"`;
    const r = await get(t.url(enc(payload)));
    if (!ok(r)) continue;
    const rawTag = r.body.includes(`<${tok}`);            // 주입 토큰 태그가 인코딩 없이 생성됨 = HTML 탈출
    const rawAttr = r.body.includes(`'></x><${tok}`);     // 토큰 앵커링 — 우연한 "'> 존재가 아닌 실제 미인코딩 반사만
    if (rawTag || rawAttr) {
      findings.push(mkActive('high', `[활성 확정] 반사형 XSS 확정 — 컨텍스트 이스케이프: ${t.param}`, host + t.path,
        `파라미터 '${t.param}' 의 특수문자(< > " ')가 인코딩 없이 응답에 반사되어 ${rawTag ? '새 HTML 태그가 생성' : 'HTML/속성 경계가 탈출'}됩니다. 반사형 XSS 가 확정되었습니다(안전 토큰만 사용, 실제 스크립트 실행 유도는 하지 않음).`,
        `reflected raw: ${rawTag ? `<${tok}…>` : `"'>`} (미인코딩)`,
        '컨텍스트별 출력 인코딩(HTML/속성/JS/URL)을 적용하고 CSP(nonce/해시 기반)를 강화하십시오.',
        'A03:2021', 'CWE-79', 'firm', REF_XSS));
    }
  }

  // ── (3) IDOR/BOLA 확정 — 인접 식별자 소량 읽기전용 열람 ──
  const idTargets = collectIdTargets(root.body, base).slice(0, 3);
  for (const t of idTargets) {
    // 식별자 표본 중복 제거(val===1 일 때 Math.max(1,val-1)=1 충돌로 중복 요청·distinct 손실 방지).
    const seq = [...new Set([t.val, t.val + 1, t.val + 2, t.val + 3, Math.max(1, t.val - 1)])].slice(0, 4);
    const resps: { v: number; body: string }[] = [];
    for (const v of seq) {
      const r = await get(t.url(v));
      if (ok(r)) resps.push({ v, body: r.body });
    }
    // 서로 다른 식별자가 모두 같은 템플릿·다른 데이터로 200 → 객체 수준 인가 부재 확정.
    const distinct = new Set(resps.map((x) => x.body)).size;
    // "동일 템플릿·다른 데이터" — 식별자만 바뀐 응답은 길이가 비슷하고(같은 셸) 내용은 다르다.
    const lens = resps.map((x) => x.body.length);
    const sameTpl = resps.length >= 3 && Math.min(...lens) / Math.max(...lens) > 0.6;
    if (resps.length >= 3 && distinct >= 3 && sameTpl) {
      // PII 가 실제 포함될 때만 'firm/high'(타인 개인정보 열람 확정). 그 외(공개 콘텐츠 가능)는 'tentative/medium' 단서.
      const piiHit = resps.some((x) => analyzePii(x.body, undefined).total > 0);
      findings.push(mkActive(piiHit ? 'high' : 'medium',
        `[활성 확정] IDOR/BOLA ${piiHit ? '확정 — 타 객체 무인증 개인정보 열람' : '단서 — 객체 분기 관측'}: ${t.label}`, host,
        piiHit
          ? `식별자 '${t.param}' 를 ${seq.join(', ')} 로 바꾸면 인증 없이 서로 다른 객체가 개인정보를 포함해 반환됩니다. 주소창 번호만 바꿔 타인의 개인정보를 열람할 수 있는 객체 수준 인가 부재가 확정되었습니다(읽기전용 열람으로만 확인).`
          : `식별자 '${t.param}' 를 ${seq.join(', ')} 로 바꾸면 인증 없이 서로 다른 객체(${distinct}건)가 같은 형식으로 반환됩니다. 객체 수준 인가 부재 단서이나 PII 미검출이라 공개 콘텐츠일 수 있어 검증이 필요합니다.`,
        `${t.param}=${seq.join('/')} → ${distinct}개 상이한 200(동일 템플릿)${piiHit ? ', PII 포함' : ''}`,
        '객체 접근마다 요청자의 소유/권한을 서버측에서 검증하고, 추측 가능한 순번 대신 비순차 식별자(UUID)/간접참조를 사용하십시오.',
        'A01:2021', 'CWE-639', piiHit ? 'firm' : 'tentative', REF_IDOR));
    }
  }

  ctx.log(`active: 침투 확정 ${findings.length}건`);
  return findings;
}

function mkActive(sev: Finding['severity'], title: string, target: string, desc: string, evidence: string, remediation: string,
  owasp: string, cwe: string, confidence: Finding['confidence'], references: string[]): Finding {
  return { ...mk('dast', sev, title, target, desc, evidence, remediation), owasp, cwe, confidence, references };
}

interface ParamTarget { path: string; param: string; orig: string; url: (encVal: string) => string }

/** 쿼리 파라미터 표적 수집 — 본문 내 링크의 쿼리 + 흔한 기본 파라미터 폴백. */
function collectParamTargets(body: string, base: string): ParamTarget[] {
  const out: ParamTarget[] = [];
  const seen = new Set<string>();
  const add = (path: string, query: Record<string, string>, param: string) => {
    const key = path + '?' + param;
    if (seen.has(key) || !(param in query)) return;
    seen.add(key);
    const orig = query[param] ?? '';
    out.push({
      path, param, orig,
      url: (encVal: string) => base.replace(/\/$/, '') + path + '?' +
        Object.entries(query).map(([k, v]) => `${encodeURIComponent(k)}=${k === param ? encVal : encodeURIComponent(v)}`).join('&'),
    });
  };
  for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"']*\?[^"'#]+)["']/gi)) {
    let raw = m[1]!;
    if (/^https?:\/\//i.test(raw) && !raw.startsWith(base)) continue;     // 외부 출처 제외
    raw = raw.replace(/^https?:\/\/[^/]+/i, '');
    const qi = raw.indexOf('?');
    if (qi < 0) continue;
    const path = raw.slice(0, qi) || '/';
    const query: Record<string, string> = {};
    for (const kv of raw.slice(qi + 1).split('&')) {
      const eq = kv.indexOf('=');
      if (eq <= 0) continue;
      const k = decodeURIComponent(kv.slice(0, eq));
      const v = kv.slice(eq + 1);
      if (k && v && v.length <= 40) query[k] = decodeURIComponent(v);
    }
    for (const param of Object.keys(query)) {
      if (out.length >= 8) break;
      add(path, query, param);
    }
  }
  // 폴백 기본 파라미터(발견된 표적이 적을 때)
  if (out.length < 2) {
    add('/', { id: '1' }, 'id');
    add('/', { q: '1' }, 'q');
    add('/', { search: '1' }, 'search');
  }
  return out.slice(0, 6);
}

/** 순차 숫자 식별자 IDOR 표적(경로형/쿼리형). */
function collectIdTargets(body: string, base: string): { param: string; val: number; label: string; url: (v: number) => string }[] {
  const out: { param: string; val: number; label: string; url: (v: number) => string }[] = [];
  const seen = new Set<string>();
  for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
    const raw = m[1]!;
    // 객체 귀속성이 강한 식별자 파라미터만(no/seq/num/idx/page 류 공개 게시판·페이지네이션 순번 제외 — 오탐 억제).
    const pm = /[?&](id|uid|userid|user_id|user|account|account_id|accountid|order|orderid|order_id|member|member_id|profile|customer)=(\d{1,9})\b/i.exec(raw);
    if (!pm) continue;
    const param = pm[1]!; const val = Number(pm[2]!);
    if (seen.has(param) || !(val >= 1 && val < 1e9)) continue;
    seen.add(param);
    let abs = raw; if (/^https?:\/\//i.test(raw)) { if (!raw.startsWith(base)) continue; } else abs = base.replace(/\/$/, '') + (raw.startsWith('/') ? raw : '/' + raw);
    out.push({ param, val, label: `${param}=${val}`, url: (v: number) => abs.replace(new RegExp(`([?&]${param}=)\\d+`, 'i'), `$1${v}`) });
  }
  for (const m of body.matchAll(/["'\s(](\/[a-z][a-z0-9_\-]{1,24})\/(\d{1,9})(?=["'/?#)\s]|$)/gi)) {
    const resource = m[1]!; const val = Number(m[2]!);
    if (seen.has('p:' + resource) || !(val >= 1 && val < 1e9)) continue;
    // 객체 참조성 자원만(공개 목록 /page/N·/item/N 등 정상 페이지네이션 오탐 억제).
    if (!/\/(users?|accounts?|orders?|members?|profiles?|invoices?|customers?|applicants?|submissions?|tickets?|messages?|documents?|posts?|comments?|records?|reservations?|payments?)$/i.test(resource)) continue;
    seen.add('p:' + resource);
    out.push({ param: resource.replace(/^\//, '') + '/{id}', val, label: `${resource}/${val}`, url: (v: number) => `${base}${resource}/${v}` });
  }
  return out;
}

function enc(s: string): string { return encodeURIComponent(s); }
function rnd(): string { return Math.random().toString(36).slice(2, 8); }
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (Math.abs(a.length - b.length) > Math.max(48, Math.min(a.length, b.length) * 0.15)) return false;
  const n = Math.min(a.length, b.length, 800);
  if (n === 0) return false;
  let same = 0;
  for (let i = 0; i < n; i++) if (a[i] === b[i]) same++;
  return same / n > 0.9;
}
