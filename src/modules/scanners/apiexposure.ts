/**
 * 비인가 API 개인정보·과다 노출 점검 (Unauthenticated API PII / Excessive Data Exposure / BOLA)
 * — OWASP API Security Top 10: API1(BOLA)·API2(Broken Auth)·API3(Object Property/Excessive Data) /
 *   OWASP 2021 A01(취약한 접근통제)·A02(개인정보 노출).
 *
 * 배경: 실제 유출 사고("API 요청 시 개인정보를 무분별하게 제공하는 구조")는 관리자 페이지가 아니라
 * 인증 없이 호출 가능한 데이터 API 가 이메일·이름·평가/심사 정보 등을 응답으로 그대로 돌려주는 데서 났다.
 * 기존 경로/관리자 점검은 이 클래스를 구조적으로 놓친다(엔드포인트 미발견 + 응답 본문 PII 미검사).
 * 본 모듈은 그 공백을 메운다:
 *   (A) API 엔드포인트 발견 — 컬렉션 워드리스트 + OpenAPI/Swagger 명세 파싱 + 홈/번들 JS 내 `/api/..` 마이닝.
 *   (B) 응답 본문(JSON) PII 워킹 — 이메일·휴대전화·주민번호(체크섬)·카드(Luhn) + 한국형 민감 필드명
 *       (이메일·연락처·이름·주소·생년월일·점수·평가·심사평·등급·합격·선정·지원자/신청자/회원…).
 *   (C) 과다 노출(Excessive Data Exposure) — 인증 없이 레코드 배열/대량 데이터를 그대로 반환하는 표면.
 *   (D) 객체 수준 인가(BOLA) — {id} 를 인접값으로만 바꿔 타인 레코드(특히 PII)가 열리는지(소량 표본).
 *   (E) 인증 미강제 차분 — 익명 vs 무효 토큰이 동일 PII 를 반환하면 인증이 강제되지 않음을 확증.
 *
 * 모든 동작은 비파괴 — GET/HEAD/OPTIONS 만 사용하고, 식별자 표본은 2~3개로 제한하며(브루트포스 금지),
 * 쓰기/상태변경/익스플로잇을 수행하지 않는다. 발견은 "안전 지표(indicator)"이며, PII 가 실제 본문에서
 * 검증된 경우에만 'firm'/'confirmed' 로 승격한다.
 */
import type { Finding } from '../../types.js';
import type { ScanContext } from './types.js';
import { mk } from './asm.js';

type HttpResp = { ok: boolean; status: number; headers: Record<string, string>; body: string };
type Sev = Finding['severity'];
type Conf = Finding['confidence'];

const REF_API = [
  'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
  'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/',
];
const REF_PII = ['https://cwe.mitre.org/data/definitions/359.html', 'https://www.pipc.go.kr'];

/** 인증 없이 호출되는 데이터/컬렉션 API 후보. 사고(지원자·심사·회원 데이터) 맥락을 포함해 광범위하게 둔다. */
const API_COLLECTIONS: string[] = [
  '/api/users', '/api/user', '/api/members', '/api/member', '/api/customers', '/api/customer',
  '/api/accounts', '/api/account', '/api/profiles', '/api/profile', '/api/contacts', '/api/contact',
  '/api/applicants', '/api/applicant', '/api/applications', '/api/application', '/api/apply',
  '/api/submissions', '/api/submission', '/api/submit', '/api/entries', '/api/registrations',
  '/api/participants', '/api/candidates', '/api/selected', '/api/winners',
  '/api/evaluations', '/api/evaluation', '/api/reviews', '/api/review', '/api/scores', '/api/results',
  '/api/orders', '/api/order', '/api/payments', '/api/transactions', '/api/list', '/api/data',
  '/api/export', '/api/download', '/api/all', '/api/search',
  '/api/admin/users', '/api/admin/members', '/api/internal/users',
  '/api/v1/users', '/api/v1/members', '/api/v1/applicants', '/api/v1/applications',
  '/api/v1/submissions', '/api/v1/evaluations', '/api/v1/profiles', '/api/v1/customers', '/api/v1/orders',
  '/api/v2/users', '/api/v2/members',
  '/users.json', '/members.json', '/applicants.json', '/data.json', '/list.json',
  '/rest/users', '/rest/members', '/graphql',
];

/** OpenAPI/Swagger 등 API 명세 후보(공개 시 그 자체로 정보 노출 + 실제 엔드포인트 인벤토리 확보). */
const SPEC_PATHS: string[] = [
  '/swagger.json', '/swagger/v1/swagger.json', '/openapi.json', '/api/openapi.json',
  '/api-docs', '/api-docs/swagger.json', '/v2/api-docs', '/v3/api-docs', '/api/swagger.json',
  '/swagger-ui/index.html', '/swagger/index.html', '/.well-known/openapi.json', '/api/docs',
];

export interface ApiExposureInput {
  ctx: ScanContext;
  base: string;
  host: string;
  root: HttpResp;
  baseStatus: number;
  baseBody: string;
}

export async function scanApiExposure(p: ApiExposureInput): Promise<Finding[]> {
  const { ctx, base, host, root, baseStatus, baseBody } = p;
  const findings: Finding[] = [];
  const get = (url: string, headers?: Record<string, string>) =>
    ctx.guard.httpGet(url, { headers: { accept: 'application/json,text/plain,*/*', ...(headers ?? {}) } });

  // SPA/포괄-200 셸을 실데이터로 오인하지 않도록 베이스라인 셸을 억제 기준으로 둔다.
  const isShell = (r: HttpResp): boolean =>
    (baseStatus === 200 && r.status === 200 && similar(r.body, baseBody)) || similar(r.body, root.body);

  // ── (A) 엔드포인트 발견 ────────────────────────────────────────────────
  const candidates = new Set<string>();
  for (const c of API_COLLECTIONS) candidates.add(c);

  // A-1) OpenAPI/Swagger 명세 — 공개 시 finding + 실제 경로 인벤토리 추출
  const specEndpoints = new Set<string>();
  for (const sp of SPEC_PATHS) {                          // SPEC_PATHS 자체가 경계(고정 13개) — 별도 캡 불필요.
    const r = await get(base + sp);
    if (!r || r.status !== 200 || !r.body) continue;
    const spec = parseJson(r.body);
    const isSpec = !!spec && typeof spec === 'object' &&
      ('swagger' in (spec as object) || 'openapi' in (spec as object) || 'paths' in (spec as object));
    if (!isSpec) continue;
    const paths = (spec as { paths?: Record<string, unknown> }).paths ?? {};
    const names = Object.keys(paths).filter((k) => k.startsWith('/'));
    findings.push(make('low', `공개된 OpenAPI/Swagger API 명세 노출: ${sp}`, host + sp,
      `API 명세(${sp})가 인증 없이 공개되어 전체 엔드포인트(${names.length}개)·파라미터·스키마가 드러납니다. 공격자에게 비인가 데이터 API 의 정확한 지도를 제공합니다.`,
      `status=200, paths=${names.length} (${names.slice(0, 6).join(', ')}${names.length > 6 ? ' …' : ''})`,
      '운영에서 API 명세 공개를 차단하거나 인증 뒤로 옮기고, 노출이 필요하면 내부망/IP 허용목록으로 제한하십시오.',
      'A05:2021', 'CWE-200', 'firm', ['https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html']));
    for (const n of names) {
      if (!/[{}:]/.test(n)) candidates.add(n);          // 파라미터 없는 컬렉션형 → 직접 호출 후보
      else specEndpoints.add(n);                         // {id} 형 → BOLA 후보
    }
  }

  // A-2) 홈 본문(+심층: 동일출처 번들 JS) 에서 `/api/..` 문자열 마이닝
  let inlineText = root.body;
  if (ctx.deep) {
    const scripts = [...root.body.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)]
      .map((m) => m[1]!).filter((s) => /\.js(\?|$)/i.test(s)).slice(0, 5);
    for (const s of scripts) {
      const abs = toAbsolute(s, base);
      if (!abs) continue;
      const r = await ctx.guard.httpGet(abs);
      if (r && r.body) inlineText += '\n' + r.body;
    }
  }
  for (const pth of extractApiPaths(inlineText)) candidates.add(pth);

  // ── (B/C) 후보 GET → 본문 PII / 과다 노출 분석 ─────────────────────────
  const cap = ctx.deep ? 60 : 28;
  let probed = 0;
  let protectedCount = 0;
  const reportedEndpoints = new Set<string>();
  for (const path of candidates) {
    if (probed >= cap) break;
    probed++;
    const r = await get(base + path);
    if (!r) continue;
    if (r.status === 401 || r.status === 403) { protectedCount++; continue; } // 정상 보호
    if (r.status !== 200 || !r.body) continue;
    if (!looksJson(r)) continue;
    if (isShell(r)) continue;
    const parsed = parseJson(r.body);
    if (parsed === undefined) continue;

    const a = analyzePii(r.body, parsed);
    const records = recordCount(parsed);
    const ct = (r.headers['content-type'] || '').split(';')[0] || '?';

    // 강한 PII 신호(critical 승격): 검증된 주민/카드, 또는 "레코드 배열(≥2건)에 PII 가 다수(≥2 distinct) 귀속"될 때만.
    // (레코드 다수 + 이메일/전화 1건은 푸터 연락처 1개일 수 있어 critical 로 단정하지 않는다.)
    const strong = a.rrn || a.card || (records >= 2 && (a.emails.size >= 2 || a.phones.size >= 2));
    const multi = a.emails.size >= 2 || a.phones.size >= 2;   // 레코드 배열 아닌 단일 응답의 PII 다수(records<2)
    const single = a.emails.size === 1 || a.phones.size === 1;

    if (strong) {
      reportedEndpoints.add(path);
      // 인증 미강제 차분 — 무효 토큰으로도 동일 분량 PII 가 나오면 인증이 강제되지 않음을 확증.
      const diff = await get(base + path, { authorization: `Bearer sentinel-invalid-${rnd()}` });
      const authNotEnforced = !!diff && diff.status === 200 && !!diff.body && analyzePii(diff.body, parseJson(diff.body)).total >= a.total;
      const conf: Conf = (a.rrn || a.card) ? 'confirmed' : 'firm';
      const detail = piiDetail(a);
      findings.push(make('critical',
        `인증 없이 개인정보(PII) 대량 노출 — 비인가 API 응답: ${path}`, host + path,
        `데이터 API(${path})가 인증·인가 없이 개인정보를 그대로 반환합니다(레코드 ${records}건, ${detail}). ` +
        `주소창/스크립트로 호출만 하면 비공개 개인정보가 외부로 유출되는 구조입니다(API 요청 시 개인정보 무분별 제공). ` +
        (authNotEnforced ? '익명 요청과 무효 토큰 요청이 동일한 개인정보를 반환해 인증이 강제되지 않음을 확인했습니다.' : ''),
        `status=200, content-type=${ct}, records≈${records}, ${detail}; sample=${a.sample}` +
        (authNotEnforced ? ' | 익명+무효토큰 동일 PII 반환(인증 미강제)' : ''),
        '데이터 API 전 구간에 인증·객체/필드 수준 인가를 서버측에서 강제하고, 응답은 요청자가 권한을 가진 필드만(최소수집·최소노출) 직렬화하십시오. 대량 조회는 레이트리밋·페이지네이션·감사로깅으로 통제하고, 노출된 개인정보는 즉시 차단·통지·재발급 절차를 가동하십시오.',
        'A01:2021', 'CWE-359', conf, REF_PII));
    } else if (multi) {
      reportedEndpoints.add(path);
      findings.push(make('high',
        `비인가 API 개인정보 노출 가능성(다수): ${path}`, host + path,
        `데이터 API(${path})가 인증 없이 개인정보로 보이는 값 다수(${piiDetail(a)})를 단일 응답으로 반환합니다. 레코드 배열이 아니어서 대량 유출로 단정하긴 어려우나 공개 의도인지 인가 누락인지 확인이 필요합니다.`,
        `status=200, content-type=${ct}, records≈${records}, ${piiDetail(a)}; sample=${a.sample}`,
        '엔드포인트가 비공개 데이터를 다룬다면 인증·인가를 강제하고 개인정보 필드를 응답에서 제거/마스킹하십시오.',
        'A01:2021', 'CWE-359', 'tentative', REF_PII));
    } else if (single && records >= 1) {
      reportedEndpoints.add(path);
      findings.push(make('medium',
        `비인가 API 개인정보 값 노출 가능성: ${path}`, host + path,
        `데이터 API(${path})가 인증 없이 개인정보로 보이는 값 1건(${piiDetail(a)})을 반환합니다. 공개 연락처(support 등)일 수 있어, 비공개 데이터인지 인가 누락인지 확인이 필요합니다.`,
        `status=200, content-type=${ct}, records≈${records}, ${piiDetail(a)}; sample=${a.sample}`,
        '엔드포인트가 비공개 데이터를 다룬다면 인증·인가를 강제하고 개인정보 필드를 응답에서 제거/마스킹하십시오.',
        'A01:2021', 'CWE-359', 'tentative', REF_PII));
    } else if (a.sensitiveKeys.size >= 2 && records >= 3) {
      reportedEndpoints.add(path);
      findings.push(make('medium',
        `인증 없이 민감 필드 데이터 노출(과다 노출 표면): ${path}`, host + path,
        `데이터 API(${path})가 인증 없이 민감해 보이는 필드(${[...a.sensitiveKeys].slice(0, 6).join(', ')})를 ${records}건 반환합니다. PII 패턴은 미검증이나 과다 노출(Excessive Data Exposure) 표면입니다.`,
        `status=200, content-type=${ct}, records≈${records}, sensitive-keys=${[...a.sensitiveKeys].slice(0, 8).join(', ')}`,
        '응답 스키마를 최소 필드로 제한(허용목록 직렬화)하고, 민감 데이터 조회에 인증·인가를 강제하십시오.',
        'A01:2021', 'CWE-213', 'tentative', REF_API));
    } else if (records >= 25) {
      reportedEndpoints.add(path);
      findings.push(make('low',
        `인증 없이 대량 데이터 반환(대량 수집 표면): ${path}`, host + path,
        `데이터 API(${path})가 인증 없이 ${records}건의 레코드를 한 번에 반환합니다. 개인정보가 아니더라도 대량 자동수집(스크레이핑)·열거에 악용될 표면입니다.`,
        `status=200, content-type=${ct}, records≈${records}`,
        '대량 조회에 인증·페이지네이션·레이트리밋을 적용하고, 불필요한 전체 덤프 엔드포인트를 제거하십시오.',
        'A01:2021', 'CWE-213', 'tentative', REF_API));
    }
  }
  if (protectedCount > 0) ctx.log(`apiexposure: 데이터 API ${protectedCount}건 인증 보호(401/403) 확인`);

  // ── (D) BOLA — {id} 인접값 표본으로 타인 레코드(특히 PII) 열람 ──────────
  if (ctx.deep) {
    // inlineText = 홈 본문 + (심층) 번들 JS — {id} 엔드포인트가 스크립트에만 등장하는 경우까지 포착.
    const idTemplates = collectIdTemplates(base, inlineText, specEndpoints).slice(0, 8);
    let bolaProbes = 0;
    for (const t of idTemplates) {
      if (bolaProbes >= 8) break;
      bolaProbes++;
      const r1 = await get(t.url(1));
      if (!r1 || r1.status !== 200 || !r1.body || !looksJson(r1) || isShell(r1)) continue;
      const p1 = parseJson(r1.body);
      if (p1 === undefined) continue;
      const r2 = await get(t.url(2));
      if (!r2 || r2.status !== 200 || !r2.body || !looksJson(r2) || isShell(r2)) continue;
      const p2 = parseJson(r2.body);
      if (p2 === undefined) continue;
      if (r1.body === r2.body) continue;                // 완전 동일 응답 → id 무시(객체 분기 아님). PII 레코드는
                                                         // 구조가 ~동일해 fuzzy similar 로는 오판되므로 정확 일치로만 제외.
      const a1 = analyzePii(r1.body, p1);
      const a2 = analyzePii(r2.body, p2);
      // critical 은 양쪽 객체 모두 PII 를 보유할 때만(서로 다른 소유자 귀속이 드러남). 한쪽만 PII 면 아래 tentative 단서로.
      const pii = a1.total > 0 && a2.total > 0;
      if (pii) {
        findings.push(make('critical',
          `객체 수준 인가 누락(BOLA)로 타인 개인정보 열람: ${t.label}`, host + t.label,
          `식별자(${t.label})를 1→2 로 바꾸면 인증 없이 서로 다른 사용자의 개인정보가 같은 형식으로 반환됩니다. 주소창의 번호만 바꿔 임의 사용자의 개인정보를 열람할 수 있는 구조입니다.`,
          `${t.url(1)} / ${t.url(2)} → 상이한 200 JSON, PII 검출(${piiDetail(a1.total >= a2.total ? a1 : a2)})`,
          '객체 접근마다 요청자가 소유자/권한자인지 서버측에서 검증하고, 추측 가능한 순번 식별자 대신 비순차 식별자(UUID)/간접참조를 사용하십시오. 개인정보 응답은 인가된 필드만 직렬화하십시오.',
          'A01:2021', 'CWE-639', 'firm', REF_API));
      } else if (sameTemplate(r1.body, r2.body)) {
        findings.push(make('medium',
          `객체 수준 인가 누락 단서(BOLA): ${t.label}`, host + t.label,
          `식별자(${t.label})를 1→2 로 바꾸면 인증 없이 서로 다른 객체가 같은 JSON 형식으로 반환됩니다. 객체 수준 인가(BOLA) 부재 단서입니다(PII 미검출).`,
          `${t.url(1)}, ${t.url(2)} → 상이한 200 JSON(동일 스키마)`,
          '객체 접근 시 소유자/권한을 서버측에서 검증하고 순번 식별자 사용을 지양하십시오.',
          'A01:2021', 'CWE-639', 'tentative', REF_API));
      }
    }
  }

  ctx.log(`apiexposure: 후보 ${candidates.size}개 중 ${probed}개 점검, 발견 ${findings.length}건`);
  return findings;
}

// ───────────────────────── 빌더 ─────────────────────────
function make(sev: Sev, title: string, target: string, desc: string, evidence: string, remediation: string,
  owasp: string, cwe: string, confidence: Conf, references: string[]): Finding {
  return { ...mk('access', sev, title, target, desc, evidence, remediation), owasp, cwe, confidence, references };
}

// ───────────────────────── PII 분석 ─────────────────────────
export interface PiiAnalysis {
  emails: Set<string>; phones: Set<string>; rrn: boolean; card: boolean;
  sensitiveKeys: Set<string>; total: number; sample: string;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PHONE_RE = /\b01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}\b/g;
const RRN_RE = /\b(\d{6})-?([1-4]\d{6})\b/g;
const KEY_RE = /"([^"\\]{1,40})"\s*:/g;
const SENSITIVE_KEY_RE =
  /(이메일|메일|email|연락처|전화|휴대폰|휴대전화|phone|mobile|tel|이름|성명|성함|name|닉네임|주민|rrn|ssn|생년월일|생일|birth|dob|주소|address|소재지|계좌|account_?no|card|카드|여권|passport|점수|score|평가|심사|등급|grade|rank|합격|선정|지원자|신청자|applicant|회원|member|gender|성별|salary|급여|연봉)/i;
/** 노이즈 도메인(스키마/예시/플레이스홀더) — 단독 1건이면 PII 로 보지 않도록 제외. */
const NOISE_EMAIL = /@(example\.(com|org|net)|email\.com|domain\.com|test\.com|sentry\.io|schema\.org|w3\.org)$/i;

export function analyzePii(text: string, parsed: unknown): PiiAnalysis {
  const emails = new Set<string>();
  for (const m of text.matchAll(EMAIL_RE)) { const e = m[0].toLowerCase(); if (!NOISE_EMAIL.test(e)) emails.add(e); }
  const phones = new Set<string>();
  for (const m of text.matchAll(PHONE_RE)) phones.add(m[0].replace(/\D/g, ''));
  let rrn = false;
  for (const m of text.matchAll(RRN_RE)) { if (validRrn(m[1]! + m[2]!)) { rrn = true; break; } }
  let card = false;
  for (const m of text.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) { if (validCard(m[0])) { card = true; break; } }
  const sensitiveKeys = new Set<string>();
  // 키 이름은 파싱된 객체에서 우선 수집(값 안의 우연한 문자열 매칭 노이즈 억제), 실패 시 텍스트 폴백.
  const keySource = parsed !== undefined ? JSON.stringify(parsed).slice(0, 120_000) : text;
  for (const m of keySource.matchAll(KEY_RE)) { const k = m[1]!; if (SENSITIVE_KEY_RE.test(k)) sensitiveKeys.add(k); }

  const total = emails.size + phones.size + (rrn ? 1 : 0) + (card ? 1 : 0);
  const sampleBits: string[] = [];
  if (rrn) sampleBits.push('주민번호(검증됨)');
  if (card) sampleBits.push('카드(Luhn)');
  const e0 = [...emails][0]; if (e0) sampleBits.push(maskEmail(e0));
  const p0 = [...phones][0]; if (p0) sampleBits.push(maskPhone(p0));
  return { emails, phones, rrn, card, sensitiveKeys, total, sample: sampleBits.slice(0, 3).join(', ') || '-' };
}

function piiDetail(a: PiiAnalysis): string {
  const bits: string[] = [];
  if (a.emails.size) bits.push(`이메일 ${a.emails.size}건`);
  if (a.phones.size) bits.push(`휴대전화 ${a.phones.size}건`);
  if (a.rrn) bits.push('주민등록번호(체크섬 검증)');
  if (a.card) bits.push('신용카드(Luhn 검증)');
  if (a.sensitiveKeys.size) bits.push(`민감필드 ${[...a.sensitiveKeys].slice(0, 4).join('/')}`);
  return bits.join(', ') || '데이터';
}

function validRrn(s13: string): boolean {
  if (!/^\d{13}$/.test(s13)) return false;
  const d = s13.split('').map(Number);
  const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  const sum = w.reduce((acc, x, i) => acc + x * d[i]!, 0);
  return (11 - (sum % 11)) % 10 === d[12];
}
function validCard(raw: string): boolean {
  const d = raw.replace(/[ -]/g, '');
  if (d.length < 13 || d.length > 19) return false;
  if (!/^(4|5[1-5]|3[47]|6011|65|35)/.test(d)) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) { let n = Number(d[i]); if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
  return sum % 10 === 0;
}
function maskEmail(e: string): string {
  const at = e.indexOf('@'); if (at < 1) return '***';
  return e.slice(0, Math.min(2, at)) + '***' + e.slice(at);
}
function maskPhone(d: string): string { return d.length >= 7 ? d.slice(0, 3) + '****' + d.slice(-2) : '01******'; }

// ───────────────────────── JSON/엔드포인트 헬퍼 ─────────────────────────
/** content-type 또는 본문 형태로 JSON 응답인지 판정. HTML 오인 방지. */
function looksJson(r: HttpResp): boolean {
  const ct = (r.headers['content-type'] || '').toLowerCase();
  if (ct.includes('json')) return true;
  const t = r.body.trim();
  if (t[0] !== '{' && t[0] !== '[') return false;
  return !/^<(!doctype|html)/i.test(t);
}
/** 본문을 JSON 으로 파싱. 실패 시 undefined (null 은 유효 JSON 값과 구분하기 위해 undefined 사용). */
export function parseJson(body: string): unknown {
  const t = body.trim();
  if (t[0] !== '{' && t[0] !== '[') return undefined;
  try { return JSON.parse(t); } catch { return undefined; }
}
/** 최상위 또는 흔한 래퍼(data/items/results/content…) 안의 배열 길이로 레코드 수를 추정. */
export function recordCount(parsed: unknown): number {
  if (Array.isArray(parsed)) return parsed.length;
  if (parsed && typeof parsed === 'object') {
    const o = parsed as Record<string, unknown>;
    for (const k of ['data', 'items', 'results', 'list', 'content', 'rows', 'records', 'users', 'members',
      'applicants', 'applications', 'submissions', 'entries', 'payload', 'docs', 'edges']) {
      if (Array.isArray(o[k])) return (o[k] as unknown[]).length;
    }
    const d = o['data'];
    if (d && typeof d === 'object') {
      const dd = d as Record<string, unknown>;
      for (const k of ['content', 'items', 'list', 'results', 'rows']) if (Array.isArray(dd[k])) return (dd[k] as unknown[]).length;
    }
  }
  return 1;
}
/** 텍스트(HTML/JS)에서 동일출처 API 경로 문자열을 추출. */
function extractApiPaths(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/["'`](\/(?:api|rest|graphql|internal|v\d{1,2})\/[A-Za-z0-9_\-./]{1,64})["'`]/g)) {
    let pth = m[1]!.replace(/\/+$/, '');
    if (/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|json)$/i.test(pth) && !/\/(users?|members?|data|list|export)\b/i.test(pth)) continue;
    pth = pth.replace(/\/\d+\b/, '');                  // /api/users/123 → /api/users (컬렉션 후보화)
    if (pth.length > 2) out.add(pth);
  }
  return [...out].slice(0, 30);
}
/** {id} 형 엔드포인트 후보 — 본문 내 /resource/123 URL + OpenAPI {id} 경로 템플릿. */
function collectIdTemplates(base: string, body: string, specEndpoints: Set<string>): { label: string; url: (v: number) => string }[] {
  const out: { label: string; url: (v: number) => string }[] = [];
  const seen = new Set<string>();
  // 본문 내 /api/.../<숫자>
  for (const m of body.matchAll(/["'\s(](\/(?:api|rest|v\d{1,2})\/[A-Za-z0-9_\-/]{1,48}?)\/(\d{1,9})(?=["'/?#)\s]|$)/gi)) {
    const res = m[1]!;
    if (seen.has(res)) continue; seen.add(res);
    out.push({ label: `${res}/{id}`, url: (v) => `${base}${res}/${v}` });
  }
  // OpenAPI {id}/:id 템플릿
  for (const ep of specEndpoints) {
    const norm = ep.replace(/\{[^}]+\}|:[A-Za-z_]+/g, '1');
    if (!/\/1(\/|$)/.test(norm)) continue;
    const key = ep.replace(/\{[^}]+\}|:[A-Za-z_]+/g, '{id}');
    if (seen.has(key)) continue; seen.add(key);
    out.push({ label: key, url: (v) => base + ep.replace(/\{[^}]+\}|:[A-Za-z_]+/g, String(v)) });
  }
  return out;
}
function toAbsolute(raw: string, base: string): string | null {
  if (/^https?:\/\//i.test(raw)) return raw.startsWith(base) ? raw : null;
  if (raw.startsWith('//') || raw.startsWith('data:') || raw.startsWith('#')) return null;
  if (raw.startsWith('/')) return base.replace(/\/$/, '') + raw;
  return base.replace(/\/$/, '') + '/' + raw;
}
/** 두 응답이 사실상 동일한지(soft-404/포괄200 억제, 동일응답 판정). */
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (Math.abs(a.length - b.length) > Math.max(48, Math.min(a.length, b.length) * 0.15)) return false;
  const n = Math.min(a.length, b.length, 600);
  if (n === 0) return false;
  let same = 0;
  for (let i = 0; i < n; i++) if (a[i] === b[i]) same++;
  return same / n > 0.9;
}
/** 같은 JSON 템플릿(동일 형식·다른 데이터)인지. */
function sameTemplate(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (a.slice(0, 40) !== b.slice(0, 40)) return false;
  const lo = Math.min(a.length, b.length), hi = Math.max(a.length, b.length);
  return lo / hi > 0.4;
}
function rnd(): string { return Math.random().toString(36).slice(2, 10); }
