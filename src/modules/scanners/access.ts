/**
 * 접근통제·자동수집 차단 점검 (Broken Access Control & Anti-Automation) — 설계 §4.4 확장 / OWASP A01·A04.
 *
 * 사용자가 요구한 "수작업 기반 해킹" 3종 표면을 모두 비파괴로 필터링·분석한다.
 *  (1) 허가되지 않은 경로 필터링: 관리/내부/디버그 경로가 인증·인가 없이 200 으로 열리는지(인가 누락) vs
 *      401/403/로그인 리다이렉트로 올바르게 차단되는지 분류한다.
 *  (2) 주소창 변조(접근통제 우회): 차단(401/403)된 경로를 경로·헤더 변형(대문자/슬래시/X-Original-URL 등)
 *      으로 재요청해 차단이 우회되는지(403→200), 순차 객체참조(IDOR) 열람 단서(주소창 번호 변경),
 *      권한 파라미터(?admin=true) 변조 반응을 식별한다.
 *  (3) AI 기반 자동 데이터 수집 차단: robots.txt 의 AI 크롤러(GPTBot/ClaudeBot/CCBot/Google-Extended 등)
 *      차단 여부와, 봇 User-Agent 필터링·봇매니지먼트·레이트리밋 부재를 능동 확인한다.
 *
 * 모든 동작은 비파괴 — GET/HEAD/OPTIONS 만 사용하고 로그인·쓰기·익스플로잇을 수행하지 않는다.
 * 발견은 "취약점 존재 가능성의 안전 지표(indicator)"이며 실제 침투를 의미하지 않는다.
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { mk } from './asm.js';
import { scanApiExposure } from './apiexposure.js';

/** 인가 통제가 적용돼야 하는 관리/내부/디버그/민감 기능 경로. */
const PRIVILEGED_PATHS: { path: string; name: string }[] = [
  { path: '/admin', name: '관리자' },
  { path: '/admin/dashboard', name: '관리자 대시보드' },
  { path: '/administrator', name: '관리자' },
  { path: '/manage', name: '관리' },
  { path: '/management', name: '관리' },
  { path: '/dashboard', name: '대시보드' },
  { path: '/console', name: '콘솔' },
  { path: '/settings', name: '설정' },
  { path: '/users', name: '사용자 목록' },
  { path: '/admin/users', name: '사용자 관리' },
  { path: '/api/admin', name: '관리 API' },
  { path: '/api/users', name: '사용자 API' },
  { path: '/api/internal', name: '내부 API' },
  { path: '/internal', name: '내부' },
  { path: '/debug', name: '디버그' },
  { path: '/private', name: '비공개' },
  { path: '/superadmin', name: '슈퍼관리자' },
];

/** AI/LLM 학습·검색 수집 크롤러 (robots.txt 차단 권장 대상). */
const AI_CRAWLERS = [
  'GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-Web', 'anthropic-ai',
  'CCBot', 'Google-Extended', 'PerplexityBot', 'Bytespider', 'Amazonbot', 'Applebot-Extended',
  'Diffbot', 'cohere-ai', 'Omgilibot', 'ImagesiftBot', 'Meta-ExternalAgent', 'FacebookBot', 'YouBot',
];

/** 노골적 자동수집 User-Agent — 기술적 필터링 적용 여부 능동 확인. */
const BOT_AGENTS: { ua: string; label: string }[] = [
  { ua: 'GPTBot/1.0 (+https://openai.com/gptbot)', label: 'GPTBot(OpenAI AI 크롤러)' },
  { ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', label: 'ClaudeBot(Anthropic AI 크롤러)' },
  { ua: 'python-requests/2.31.0', label: 'python-requests(스크립트 수집)' },
  { ua: 'Scrapy/2.11 (+https://scrapy.org)', label: 'Scrapy(스크레이핑 프레임워크)' },
];

const REF_A01 = ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/', 'https://cwe.mitre.org/data/definitions/284.html'];
const REF_BOT = ['https://owasp.org/www-project-automated-threats-to-web-applications/', 'https://www.rfc-editor.org/rfc/rfc9309'];

type Sev = Finding['severity'];
type Conf = Finding['confidence'];

/** 접근통제(A01) 발견 빌더 — OWASP/CWE/참고자료 부착. */
function bac(sev: Sev, title: string, target: string, desc: string, evidence: string, remediation: string, cwe: string, confidence: Conf): Finding {
  return { ...mk('access', sev, title, target, desc, evidence, remediation), owasp: 'A01:2021', cwe, confidence, references: REF_A01 };
}

/**
 * 자동수집/봇 차단(A04/A05) 발견 빌더.
 * confidence 기본값은 'tentative' — 봇/안티자동화 점검 대부분이 "헤더·정책 파일 부재"를 소수 요청으로 관측한
 * 휴리스틱 부재 단서이기 때문이다. robots.txt 존재·내용 분석처럼 콘텐츠 시그니처가 있는 강한 신호에만
 * 명시적으로 'firm' 을 전달한다.
 */
function bot(sev: Sev, title: string, target: string, desc: string, evidence: string, remediation: string, confidence: Conf = 'tentative'): Finding {
  return { ...mk('access', sev, title, target, desc, evidence, remediation), references: REF_BOT, confidence };
}

export const accessScanner: Scanner = {
  module: 'access',
  minIntensity: 'standard',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const base = ctx.asset.type === 'host' ? `http://${ctx.asset.value}` : `https://${ctx.asset.value}`;
    const host = ctx.asset.value;
    const root = await ctx.guard.httpGet(base + '/');
    if (!root) { ctx.log('access: 대상 응답 없음 — 점검 생략'); return findings; }

    // soft-404 베이스라인 — 포괄 200(SPA/catch-all) 사이트의 오탐 제거
    const rnd = `/sentinel-bac-${Math.random().toString(36).slice(2)}`;
    const baseline = await ctx.guard.httpGet(base + rnd);
    const baseBody = baseline?.body ?? '';
    const baseStatus = baseline?.status ?? 404;
    const isSoft404 = (r: { status: number; body: string }) => baseStatus === 200 && r.status === 200 && similar(r.body, baseBody);
    const isLoginRedirect = (r: { status: number; headers: Record<string, string> }) =>
      [301, 302, 303, 307, 308].includes(r.status) && /login|signin|sign-in|auth|sso|account|oauth|로그인/i.test(r.headers['location'] || '');

    // 경로 변형 우회의 오탐 억제: 변형 응답이 (a) soft-404 베이스라인과 다르고, (b) 루트/홈 페이지와도
    // 다르며(트레일링슬래시·정규화로 홈/공통 셸이 되돌려지는 정상 케이스 제외), (c) 로그인 게이트가 아닐 때만
    // "차단 우회"로 본다. 단지 status===200 만으로는 정상 정규화 응답과 구분되지 않으므로 부족하다.
    const rootBody = root.body || '';
    const isGenuineBypass = (r: { status: number; body: string }): boolean =>
      r.status === 200 && !!r.body && !isSoft404(r) && !looksLikeLogin(r.body)
      && !similar(r.body, rootBody) && !similar(r.body, baseBody);

    // ─────────── (1) 허가되지 않은 경로 필터링 ───────────
    const protectedPaths: { path: string; status: number }[] = [];
    let openCount = 0;
    let protectedCount = 0;
    for (const pp of PRIVILEGED_PATHS) {
      const r = await ctx.guard.httpGet(base + pp.path);
      if (!r) continue;
      if (r.status === 401 || r.status === 403) { protectedCount++; protectedPaths.push({ path: pp.path, status: r.status }); continue; }
      if (isLoginRedirect(r)) { protectedCount++; continue; }
      if (r.status === 200 && !isSoft404(r) && r.body) {
        if (looksLikeLogin(r.body)) { protectedCount++; continue; } // 200 이지만 로그인 게이트 = 정상 보호
        // 인증 없이 200 — 인가 통제 누락 가능성. 관리/세션형 콘텐츠 시그니처로 신뢰도 보정.
        // 'high'/'firm' 승격은 진짜 인증/관리 컨텍스트 마커에만 한정한다.
        // '<table' 같은 범용 마크업은 (테이블이 흔하므로) 단독으로는 승격 근거가 될 수 없어 제외.
        const authed = /logout|로그아웃|sign\s?out|log\s?out|admin panel|관리자 패널|관리자 메뉴|user list|사용자 목록|회원 관리|관리자 대시보드|admin dashboard/i.test(r.body);
        openCount++;
        findings.push(bac(authed ? 'high' : 'medium',
          `허가되지 않은 경로 접근 가능(인가 통제 누락): ${pp.path}`, host + pp.path,
          `${pp.name} 경로가 인증/인가 없이 200 으로 응답합니다. 권한 검증 없이 주소창 직접 입력만으로 기능·데이터에 도달할 수 있습니다.`,
          `status=200${authed ? ', 관리/세션 콘텐츠 시그니처 일치' : ''}`,
          '서버측에서 모든 민감 경로에 인증·역할기반 인가를 강제하고, 비인가 접근에는 401/403 또는 로그인 리다이렉트를 반환하십시오. 화면 숨김(메뉴 미노출)만으로는 통제가 되지 않습니다.',
          'CWE-862', authed ? 'firm' : 'tentative'));
      }
    }
    ctx.log(`access: 권한 경로 차단 ${protectedCount}건 / 비인가 접근 가능 ${openCount}건`);

    // ─────────── (2) 주소창 변조 — 접근통제 우회 ───────────
    // 2a) 경로 변형 우회: 차단(401/403)된 경로를 표기만 바꿔 재요청
    for (const prot of protectedPaths.slice(0, 4)) {
      const seg = prot.path.replace(/^\//, '');
      const variants: { variant: string; how: string }[] = [
        { variant: prot.path.toUpperCase(), how: '대문자 경로' },
        { variant: prot.path + '/', how: '끝 슬래시' },
        { variant: prot.path + '/.', how: '"/." 부가' },
        { variant: prot.path + '//', how: '이중 슬래시' },
        { variant: '/./' + seg, how: '"/./" 접두' },
        { variant: prot.path + '%20', how: '"%20" 부가' },
        { variant: prot.path + '..;/', how: '"..;/" 부가' },
      ];
      for (const mv of variants) {
        const r = await ctx.guard.httpGet(base + mv.variant);
        if (r && isGenuineBypass(r)) {
          findings.push(bac('high', `접근통제 우회: ${prot.path} (${mv.how})`, host + prot.path,
            `차단(${prot.status})된 경로가 경로 표기 변형("${mv.variant}")만으로, 홈/공통 셸과도 다른 콘텐츠를 200 으로 반환합니다. 주소창을 살짝 바꾸면 통제가 우회됩니다.`,
            `${prot.status} → 200 via "${mv.variant}" (본문이 루트·soft404 베이스라인과 상이)`,
            '인가 판정을 정규화된 경로/리소스 기준으로 일관 적용하고, 리버스프록시·애플리케이션 계층 간 경로 정규화 불일치(슬래시·대소문자·인코딩)를 제거하십시오.',
            'CWE-639', 'firm'));
          break; // 경로당 1건이면 충분
        }
      }
      // 2b) 헤더 변형 우회 (심층)
      if (ctx.deep) {
        const headerBypass: { headers: Record<string, string>; how: string }[] = [
          { headers: { 'x-original-url': prot.path }, how: 'X-Original-URL 헤더' },
          { headers: { 'x-rewrite-url': prot.path }, how: 'X-Rewrite-URL 헤더' },
          { headers: { 'x-forwarded-for': '127.0.0.1' }, how: 'X-Forwarded-For: 127.0.0.1' },
          { headers: { 'x-custom-ip-authorization': '127.0.0.1' }, how: 'X-Custom-IP-Authorization' },
          { headers: { 'x-originating-ip': '127.0.0.1' }, how: 'X-Originating-IP' },
        ];
        for (const hv of headerBypass) {
          const r = await ctx.guard.httpGet(base + prot.path, { headers: hv.headers });
          if (r && isGenuineBypass(r)) {
            findings.push(bac('high', `접근통제 우회: ${prot.path} (${hv.how})`, host + prot.path,
              `차단(${prot.status})된 경로가 요청 헤더 변조(${hv.how})로, 홈/공통 셸과도 다른 콘텐츠를 200 으로 반환합니다. 클라이언트가 보낸 신뢰 불가 헤더로 통제가 우회됩니다.`,
              `${prot.status} → 200 via ${hv.how} (본문이 루트·soft404 베이스라인과 상이)`,
              '신뢰할 수 없는 요청 헤더(X-Original-URL/X-Rewrite-URL/X-Forwarded-* 등)로 접근통제·내부 라우팅을 우회할 수 없도록 게이트웨이에서 제거·무시하십시오.',
              'CWE-290', 'firm'));
            break;
          }
        }
      }
    }

    // 2c) 순차 객체참조(IDOR) — 주소창 번호 변경으로 타 객체 열람 (심층)
    if (ctx.deep) {
      const picks = collectIdTargets(root.body, base).slice(0, 3);
      for (const t of picks) {
        const orig = await ctx.guard.httpGet(t.url(t.val));
        if (!orig || orig.status !== 200 || !orig.body || isSoft404(orig)) continue;
        const up = await ctx.guard.httpGet(t.url(t.val + 1));
        const down = await ctx.guard.httpGet(t.url(Math.max(1, t.val - 1)));
        const ok = (r: { status: number; body: string } | null): r is { status: number; body: string } =>
          !!r && r.status === 200 && !!r.body && !isSoft404(r);
        if (ok(up) && ok(down) && !similar(up.body, down.body) && sameTemplate(orig.body, up.body)) {
          findings.push(bac('medium', `순차적 객체 참조(IDOR) 열람 단서: ${t.label}`, host,
            `식별자(${t.param})를 ±1 로 바꾸면 인증 없이 서로 다른 객체가 같은 형식으로 반환됩니다. 주소창의 번호만 바꿔 다른 사용자/리소스 데이터에 임의 접근할 수 있습니다.`,
            `${t.param}=${t.val}, ${t.val + 1}, ${Math.max(1, t.val - 1)} 각각 상이한 200 응답(동일 템플릿)`,
            '객체 접근 시 소유자/권한을 서버측에서 검증하고, 추측 가능한 순번 대신 비순차 식별자(UUID) 또는 간접 참조 맵을 사용하십시오.',
            'CWE-639', 'tentative'));
        }
      }

      // 2d) 권한 파라미터 변조 반응 (?admin=true 등)
      const tamper = await ctx.guard.httpGet(`${base}/?admin=true&debug=true&role=admin&isadmin=1&access=1&test=1`);
      if (tamper && tamper.status === 200 && tamper.body && !isSoft404(tamper)) {
        const dbgRe = /traceback|stack trace|whoops|exception|debug\s*=\s*true|sqlstate|warning:.*on line/i;
        if (dbgRe.test(tamper.body) && !dbgRe.test(root.body)) {
          // 디버그/오류 노출 → 매핑 계층이 A03(디버그·오류 노출)로 분류하도록 owasp/cwe 미지정.
          findings.push({ ...mk('access', 'low', '디버그 파라미터 변조로 디버그/오류 정보 노출(?debug=true)', host,
            '디버그 파라미터를 주소창에 추가하면 베이스라인에 없던 디버그·오류 정보가 노출됩니다(클라이언트 토글로 동작 변경).',
            tamper.body.slice(0, 100).replace(/\s+/g, ' '),
            '디버그/관리 동작을 쿼리 파라미터로 토글하지 말고 환경·서버 권한으로만 제어하며, 운영에서 상세 오류를 숨기십시오.'), confidence: 'tentative' });
        }
        const privRe = /(grant|revoke|impersonate|모든 사용자|all users|관리자 전용|admin only|delete user|회원 삭제)/i;
        if (privRe.test(tamper.body) && !privRe.test(root.body) && tamper.body.length > root.body.length * 1.1) {
          findings.push(bac('medium', '권한 파라미터 변조 반응 단서', host,
            '권한 상승 파라미터(?admin=true/role=admin)를 추가하면 베이스라인에 없던 관리자 전용 기능 표시가 응답에 나타납니다.',
            '관리/권한 관련 마커가 변조 응답에서만 관측됨',
            '권한은 서버측 세션·역할로만 판정하고, 클라이언트가 보낸 파라미터로 권한을 부여하지 마십시오.',
            'CWE-639', 'tentative'));
        }
      }
    }

    // ─────────── (3) AI 기반 자동 데이터 수집 차단 ───────────
    // 3a) robots.txt 의 AI 크롤러 차단 여부
    const robots = await ctx.guard.httpGet(base + '/robots.txt');
    const robotsOk = robots && robots.status === 200 && /user-?agent\s*:/i.test(robots.body) && !/<html/i.test(robots.body);
    if (!robotsOk) {
      findings.push(bot('info', 'robots.txt 부재 — 자동 수집/크롤링 정책 없음', host,
        'robots.txt 가 없어 크롤러·AI 수집 봇에 대한 자율 수집 정책이 선언되지 않았습니다.',
        `status=${robots?.status ?? '-'}`,
        '/robots.txt 에 수집 정책을 게시하되, 자율 규약은 악성 수집을 막지 못하므로 (3c)의 기술적 차단을 병행하십시오.'));
    } else {
      const txt = robots!.body.toLowerCase();
      const blockedAi = AI_CRAWLERS.filter((b) => txt.includes(b.toLowerCase()));
      const missingAi = AI_CRAWLERS.filter((b) => !txt.includes(b.toLowerCase()));
      if (blockedAi.length === 0) {
        findings.push(bot('low', 'AI 데이터 수집 봇 미차단 (robots.txt)', host,
          'robots.txt 에 GPTBot/ClaudeBot/CCBot/Google-Extended 등 AI 학습·검색 수집 봇에 대한 차단 선언이 없습니다. AI 데이터 수집을 통제할 의도라면 누락된 상태입니다.',
          `미차단: ${missingAi.slice(0, 8).join(', ')} …`,
          "robots.txt 에 각 AI 크롤러를 'User-agent: <봇명>' + 'Disallow: /' 로 명시하고, 기술적 차단(UA/행위 기반)을 병행하십시오."));
      } else if (missingAi.length > AI_CRAWLERS.length / 2) {
        findings.push(bot('info', `일부 AI 크롤러만 차단 (robots.txt) — 미차단 ${missingAi.length}종`, host,
          `일부 AI 봇만 robots.txt 로 차단되어 있습니다(차단: ${blockedAi.slice(0, 4).join(', ')}). 정책 일관성 점검이 필요합니다.`,
          `미차단: ${missingAi.slice(0, 8).join(', ')}`,
          '차단 정책을 모든 AI 수집 봇으로 확장하고 주기적으로 신규 봇을 반영하십시오.',
          'firm')); // robots.txt 내용에서 차단 선언을 직접 파싱한 콘텐츠 기반 관측 = firm
      }
    }

    // 3b) 봇 User-Agent 필터링 — 기술적 차단 동작 여부 능동 확인
    if (root.status === 200) {
      let blocked = 0;
      const served: string[] = [];
      const agents = ctx.deep ? BOT_AGENTS : BOT_AGENTS.slice(0, 2);
      for (const b of agents) {
        const r = await ctx.guard.httpGet(base + '/', { headers: { 'user-agent': b.ua } });
        if (!r) continue;
        const challenged = /captcha|cf-chl|just a moment|attention required|are you a (human|robot)|automated|verify you are/i.test(r.body);
        if (r.status === 403 || r.status === 429 || r.status === 503 || challenged) blocked++;
        else if (r.status === 200) served.push(b.label);
      }
      if (served.length > 0 && blocked === 0) {
        findings.push(bot('info', `자동수집/AI 봇 User-Agent 필터링 부재 — ${served.length}종 그대로 200 수신`, host,
          '노골적인 자동수집/AI 봇 User-Agent 로 요청해도 정상 페이지가 그대로 반환됩니다. AI 기반 자동 데이터 수집에 대한 기술적 차단이 동작하지 않습니다.',
          `차단 없이 응답: ${served.join(', ')}`,
          '민감/대량 조회 엔드포인트에 봇 매니지먼트(레이트리밋·챌린지·UA/행위 기반 차단)를 적용하십시오. robots.txt 는 자율 규약이라 악성 수집을 막지 못합니다.'));
      } else if (blocked > 0) {
        ctx.log(`access: 봇 UA ${blocked}/${agents.length}종 차단 확인(자동수집 방어 동작)`);
      }
    }

    // 3c) 봇 매니지먼트/레이트리밋 부재 단서 (심층)
    if (ctx.deep) {
      const hdrKeys = Object.keys(root.headers).map((h) => h.toLowerCase());
      const botMgmt = ['cf-mitigated', 'x-datadome', 'x-datadome-cid', 'x-distil-cs', 'x-px', 'x-perimeterx', 'x-akamai-bot', 'x-kasada'];
      const hasBotMgmt = hdrKeys.some((h) => botMgmt.includes(h)) || /datadome|perimeterx|kasada|imperva|incapsula/i.test(JSON.stringify(root.headers));
      const hasRate = hdrKeys.some((h) => /ratelimit|x-rate-limit|retry-after/i.test(h));
      if (!hasBotMgmt && !hasRate) {
        findings.push(bot('info', '봇 매니지먼트·레이트리밋 미관측 — 대량 자동수집 완화 부재 단서', host,
          '봇 관리 솔루션/레이트리밋 헤더가 관측되지 않아, 대량 자동 데이터 수집(스크레이핑)을 완화할 통제가 없을 수 있습니다(부재 단서).',
          '(no bot-management / RateLimit headers)',
          '엣지/애플리케이션에 레이트리밋과 봇 매니지먼트를 도입하고, 이상 트래픽 탐지를 적용하십시오.'));
      }
    }

    // ───── 확장 점검 ─────
    // 공통 헬퍼 (이 run 스코프에서만 사용)
    const ok200 = (r: { status: number; body: string } | null): r is { status: number; body: string } =>
      !!r && r.status === 200 && !!r.body && !isSoft404(r as { status: number; body: string });

    // ── (확장 A) 403/401 우회 기법 확대 — 더 많은 경로 변형 ──
    // 기존 2a 의 변형 집합을 보강하는 추가 인코딩/세그먼트 변형. 차단된 경로 한정.
    for (const prot of protectedPaths.slice(0, 4)) {
      const seg = prot.path.replace(/^\//, '');
      const moreVariants: { variant: string; how: string }[] = [
        { variant: '/%2e/' + seg, how: '"%2e"(점) 인코딩 접두' },
        { variant: prot.path + '%2e', how: '후행 "%2e"' },
        { variant: prot.path + ';/', how: '";/"(세미콜론 슬래시) 부가' },
        { variant: '/..;/' + seg, how: '"/..;/" 접두(파라미터 경로 우회)' },
        { variant: prot.path + '/./', how: '후행 "/./"' },
        { variant: prot.path + '%2f', how: '후행 "%2f"' },
        { variant: prot.path + '#', how: '후행 프래그먼트 "#"' },
        { variant: prot.path + '?', how: '후행 빈 쿼리 "?"' },
        { variant: prot.path + '.json', how: '확장자 ".json" 부가' },
        { variant: capitalizeFirst(prot.path), how: '첫 글자 대문자' },
        { variant: '/%2e' + prot.path, how: '유니코드/점 접두 "%2e"' },
      ];
      for (const mv of moreVariants) {
        const r = await ctx.guard.httpGet(base + mv.variant);
        // 추가 인코딩/세그먼트 변형은 정규화 부수효과로 정상 200 을 돌려줄 여지가 더 크므로,
        // (a) 홈/베이스라인과 다른 콘텐츠일 때만 보고하고, (b) 보수적으로 medium/tentative 로 둔다.
        if (r && isGenuineBypass(r)) {
          findings.push(bac('medium', `접근통제 우회 가능성: ${prot.path} (${mv.how})`, host + prot.path,
            `차단(${prot.status})된 경로가 경로 표기 변형("${mv.variant}")으로, 홈/공통 셸과도 다른 콘텐츠를 200 으로 반환합니다. 경로 정규화 불일치로 인가 통제가 우회되는 단서입니다(휴리스틱, 정상 정규화 응답일 수 있어 검증 필요).`,
            `${prot.status} → 200 via "${mv.variant}" (본문이 루트·soft404 베이스라인과 상이)`,
            '리버스프록시·WAF·애플리케이션의 경로 정규화(점·세미콜론·인코딩·확장자·대소문자)를 일치시키고, 인가 판정은 정규화된 리소스 기준으로 일관 적용하십시오.',
            'CWE-639', 'tentative'));
          break;
        }
      }
    }

    // ── (확장 B) 403/401 우회 — 추가 헤더 변형 (심층) ──
    if (ctx.deep) {
      for (const prot of protectedPaths.slice(0, 3)) {
        const moreHeaderBypass: { headers: Record<string, string>; how: string }[] = [
          { headers: { 'x-forwarded-host': host }, how: 'X-Forwarded-Host' },
          { headers: { 'x-forwarded-scheme': 'http' }, how: 'X-Forwarded-Scheme: http' },
          { headers: { 'x-real-ip': '127.0.0.1' }, how: 'X-Real-IP: 127.0.0.1' },
          { headers: { 'x-client-ip': '127.0.0.1' }, how: 'X-Client-IP: 127.0.0.1' },
          { headers: { 'x-forwarded-server': 'localhost' }, how: 'X-Forwarded-Server: localhost' },
          { headers: { 'referer': base + prot.path }, how: 'Referer(동일 경로) 위조' },
          { headers: { 'x-host': host }, how: 'X-Host' },
          { headers: { 'x-forwarded-for': '127.0.0.1, 127.0.0.1' }, how: 'X-Forwarded-For 체인' },
        ];
        for (const hv of moreHeaderBypass) {
          const r = await ctx.guard.httpGet(base + prot.path, { headers: hv.headers });
          if (r && isGenuineBypass(r)) {
            findings.push(bac('high', `접근통제 우회: ${prot.path} (${hv.how})`, host + prot.path,
              `차단(${prot.status})된 경로가 신뢰 불가 요청 헤더 변조(${hv.how})로, 홈/공통 셸과도 다른 콘텐츠를 200 으로 반환합니다. 클라이언트 제어 헤더로 통제가 우회됩니다.`,
              `${prot.status} → 200 via ${hv.how} (본문이 루트·soft404 베이스라인과 상이)`,
              '게이트웨이에서 X-Forwarded-*/X-Real-IP/X-Client-IP/X-Original-URL/Referer 기반 인가 우회를 차단하고, 신뢰 경계 내부에서만 설정된 헤더만 신뢰하십시오.',
              'CWE-290', 'firm'));
            break;
          }
        }
      }
    }

    // ── (확장 C) HTTP 메서드 오버라이드 표면 (GET 으로만 관측) ──
    // X-HTTP-Method-Override 가 GET 요청에서도 반영되어 동작이 달라지는지(비파괴: GET 유지).
    if (ctx.deep) {
      const ovrHeaders: Record<string, string>[] = [
        { 'x-http-method-override': 'PUT' },
        { 'x-http-method-override': 'DELETE' },
        { 'x-method-override': 'DELETE' },
        { 'x-http-method': 'DELETE' },
      ];
      for (const oh of ovrHeaders) {
        const r = await ctx.guard.httpGet(base + '/', { headers: oh });
        const key = Object.keys(oh)[0]!;
        const val = oh[key as keyof typeof oh];
        // 메서드 오버라이드가 "수용"되어 405/501 등으로 동작 변화가 보이면 표면 존재 단서.
        if (r && r.status !== root.status && [405, 501, 400, 403].includes(r.status)) {
          findings.push(bac('low', `HTTP 메서드 오버라이드 헤더 처리 표면(${key})`, host,
            `${key}: ${val} 헤더를 GET 요청에 부가하면 베이스라인(status=${root.status})과 다른 status=${r.status}를 반환합니다. 서버가 클라이언트 메서드 오버라이드 헤더를 해석하므로, 인가가 메서드 기준이면 PUT/DELETE 등으로 우회될 표면이 존재합니다(비파괴로 GET 만 전송).`,
            `GET + ${key}:${val} → status=${r.status} (baseline ${root.status})`,
            '메서드 오버라이드 헤더(X-HTTP-Method-Override 등)를 비활성화하거나, 인가 판정을 오버라이드 후 실효 메서드 기준으로 일관 적용하십시오.',
            'CWE-650', 'tentative'));
          break;
        }
      }
    }

    // ── (확장 D) 권한 파라미터 변조 확대 — 개별 파라미터 반영 단서 ──
    if (ctx.deep) {
      const privParams = ['preview=true', 'internal=true', 'is_admin=1', 'test=1', 'debug=1', 'account_id=1'];
      const privUrl = `${base}/?${privParams.join('&')}`;
      const pr = await ctx.guard.httpGet(privUrl);
      if (pr && pr.status === 200 && pr.body && !isSoft404(pr)) {
        const previewRe = /(preview\s*mode|미리보기|draft|초안|staging|coming\s*soon|unpublished|비공개\s*콘텐츠)/i;
        if (previewRe.test(pr.body) && !previewRe.test(root.body) && pr.body.length > root.body.length * 1.05) {
          findings.push(bac('medium', '미리보기/내부 파라미터 변조로 비공개 콘텐츠 노출 단서(?preview/internal)', host,
            '미리보기·내부용 파라미터(?preview=true/internal=true)를 추가하면 베이스라인에 없던 초안/비공개/스테이징 콘텐츠 표시가 응답에 나타납니다. 클라이언트 파라미터로 공개 범위가 토글됩니다.',
            '미리보기/내부 콘텐츠 마커가 변조 응답에서만 관측됨',
            '콘텐츠 공개 여부는 서버측 권한/상태로만 판정하고, 쿼리 파라미터로 미공개 콘텐츠를 노출하지 마십시오.',
            'CWE-639', 'tentative'));
        }
      }
    }

    // ── (확장 E) BOLA/BFLA — API 인가 단서 ──
    if (ctx.deep) {
      // 5a) /api/v1/admin 류 기능 수준 인가(BFLA) 미적용 단서.
      //     '/api/admin'·'/api/admin/users' 는 (1) PRIVILEGED_PATHS 에서 이미 점검되므로 중복 방지 위해 제외.
      const adminApis = ['/api/v1/admin', '/api/v2/admin', '/api/management', '/api/internal/users'];
      for (const ap of adminApis) {
        const r = await ctx.guard.httpGet(base + ap, { headers: { accept: 'application/json' } });
        if (!r || r.status !== 200 || !r.body || isSoft404(r)) continue;
        if (looksLikeLogin(r.body)) continue;
        if (looksLikeJson(r.body) && /[\[{]/.test(r.body.trim()[0] || '')) {
          findings.push(bac('high', `관리 API 기능 수준 인가 누락 단서(BFLA): ${ap}`, host + ap,
            `관리/내부 API(${ap})가 인증 없이 JSON 데이터를 200 으로 반환합니다. 기능 수준 인가(BFLA) 부재로 관리 기능에 직접 접근할 수 있는 단서입니다.`,
            `status=200, content-type≈json, body[0]="${(r.body.trim()[0] || '')}"`,
            '모든 관리/내부 API에 인증·역할기반 인가를 강제하고, 미인증 요청에는 401/403 을 반환하십시오.',
            'CWE-862', 'firm'));
          break;
        }
      }

      // 5b) /api/v1/users/{id} 순차 객체 인가(BOLA) — 인접 식별자가 동일 형식으로 열리는지
      const idApiBases = ['/api/v1/users/', '/api/users/', '/api/v1/accounts/', '/api/orders/'];
      for (const ab of idApiBases) {
        const a = await ctx.guard.httpGet(base + ab + '1', { headers: { accept: 'application/json' } });
        if (!ok200(a) || !looksLikeJson(a.body) || looksLikeLogin(a.body)) continue;
        const b = await ctx.guard.httpGet(base + ab + '2', { headers: { accept: 'application/json' } });
        if (ok200(b) && looksLikeJson(b.body) && !looksLikeLogin(b.body) && !similar(a.body, b.body) && sameTemplate(a.body, b.body)) {
          findings.push(bac('high', `객체 수준 인가 누락 단서(BOLA): ${ab}{id}`, host + ab + '{id}',
            `${ab}1 과 ${ab}2 가 인증 없이 서로 다른 객체를 같은 JSON 형식으로 200 반환합니다. 식별자만 바꿔 타 사용자/리소스 데이터에 접근할 수 있는 객체 수준 인가(BOLA) 부재 단서입니다.`,
            `${ab}1, ${ab}2 → 상이한 200 JSON(동일 스키마)`,
            '객체 접근 시 요청자가 해당 객체의 소유자/권한자인지 서버측에서 검증하고, 추측 가능한 순번 식별자 사용을 지양하십시오.',
            'CWE-639', 'tentative'));
          break;
        }
      }
    }

    // ── (확장 F) GUID/UUID/Base64 식별자 기반 IDOR 추론 단서 ──
    if (ctx.deep) {
      const guidTargets = collectOpaqueIdTargets(root.body, base).slice(0, 2);
      for (const gt of guidTargets) {
        findings.push(bac('info', `불투명 식별자 직접 노출 — 객체 참조 표면(${gt.kind})`, host,
          `페이지에서 ${gt.kind} 형식의 객체 식별자(${gt.sample})가 URL 에 직접 노출됩니다. 접근 객체가 서버측 인가 없이 식별자만으로 조회된다면 IDOR 표면이 됩니다(노출 단서, 추론).`,
          `${gt.kind}: ${gt.sample}`,
          '식별자 노출 자체보다 객체 접근 시 소유자/권한 검증을 서버측에서 강제하는 것이 핵심입니다. 인가 없이 조회되지 않는지 확인하십시오.',
          'CWE-200', 'tentative'));
      }
    }

    // ── (확장 G) 안티봇 — AI 크롤러 정책 파일 (/ai.txt, /llms.txt) ──
    for (const f of ['/ai.txt', '/llms.txt']) {
      const r = await ctx.guard.httpGet(base + f);
      const present = r && r.status === 200 && r.body && !/<html/i.test(r.body) && r.body.length < 100_000;
      if (present) {
        ctx.log(`access: AI 정책 파일 ${f} 존재(자율 수집 정책 선언)`);
      }
    }
    // ai.txt/llms.txt 둘 다 없으면 정보성 단서 1건 (robots 의 AI 차단과 별개로 LLM 정책 부재)
    {
      const aiTxt = await ctx.guard.httpGet(base + '/llms.txt');
      const hasLlms = aiTxt && aiTxt.status === 200 && aiTxt.body && !/<html/i.test(aiTxt.body);
      if (!hasLlms) {
        findings.push(bot('info', 'LLM 수집 정책 파일(llms.txt/ai.txt) 부재', host,
          'llms.txt/ai.txt 와 같은 LLM 친화/수집 정책 파일이 없습니다. AI 수집 통제를 명시적으로 선언할 의도라면 누락된 상태입니다(자율 규약이라 강제력은 없음).',
          `status=${aiTxt?.status ?? '-'}`,
          '필요 시 /llms.txt 또는 /ai.txt 로 LLM 수집 정책을 선언하되, 기술적 차단(UA·행위 기반)을 함께 적용하십시오.'));
      }
    }

    // ── (확장 H) X-Robots-Tag noai/noimageai 헤더 관측 ──
    {
      const xrt = (root.headers['x-robots-tag'] || '').toLowerCase();
      if (xrt) {
        const hasNoAi = /\bnoai\b|\bnoimageai\b/i.test(xrt);
        if (!hasNoAi) {
          findings.push(bot('info', 'X-Robots-Tag 에 noai/noimageai 미선언', host,
            `응답 X-Robots-Tag 헤더("${xrt.slice(0, 80)}")에 AI 수집 거부(noai/noimageai) 지시어가 없습니다. AI 학습 수집을 헤더로 통제할 의도라면 누락된 상태입니다.`,
            `x-robots-tag: ${xrt.slice(0, 80)}`,
            'AI 수집을 거부하려면 X-Robots-Tag 에 noai, noimageai 지시어를 추가하십시오(자율 규약).'));
        }
      }
    }

    // ── (확장 I) AI 크롤러 UA 확대 — robots 미차단 + 기술적 미차단 교차 (심층) ──
    if (ctx.deep && root.status === 200) {
      let served = 0;
      let blocked = 0;
      const servedNames: string[] = [];
      for (const ua of EXTENDED_AI_AGENTS) {
        const r = await ctx.guard.httpGet(base + '/', { headers: { 'user-agent': ua.ua } });
        if (!r) continue;
        const challenged = /captcha|cf-chl|just a moment|attention required|are you a (human|robot)|verify you are/i.test(r.body);
        if (r.status === 403 || r.status === 429 || r.status === 503 || challenged) blocked++;
        else if (r.status === 200) { served++; servedNames.push(ua.label); }
      }
      if (served >= 4 && blocked === 0) {
        findings.push(bot('low', `확장 AI 크롤러 UA 다수 미차단 — ${served}종 그대로 200 수신`, host,
          `Google-Extended/PerplexityBot/Bytespider/Amazonbot/Applebot-Extended/Diffbot/Meta-ExternalAgent/cohere-ai/YouBot/Timpibot/ImagesiftBot 등 확장 AI 수집 UA ${served}종이 차단·챌린지 없이 정상 페이지를 수신합니다. AI 자동 데이터 수집에 대한 기술적 차단이 동작하지 않습니다.`,
          `차단 없이 응답: ${servedNames.slice(0, 10).join(', ')}`,
          '대량·민감 조회 경로에 UA/행위 기반 봇 매니지먼트와 레이트리밋을 적용하십시오. robots.txt 는 자율 규약이라 악성 수집을 막지 못합니다.'));
      }
    }

    // ── (확장 J) 레이트리밋 경량 관측 (요청 3~4개, 절대 브루트포스 아님) ──
    if (ctx.deep && root.status === 200) {
      let sawLimitHeader = false;
      let saw429 = false;
      let retryAfter = '';
      const probes = 3; // 최소 요청만
      for (let i = 0; i < probes; i++) {
        const r = await ctx.guard.httpGet(base + '/');
        if (!r) break;
        const hk = Object.keys(r.headers).map((h) => h.toLowerCase());
        if (hk.some((h) => /^(x-)?ratelimit/i.test(h) || h === 'ratelimit-limit' || h === 'ratelimit-remaining')) sawLimitHeader = true;
        if (r.status === 429) { saw429 = true; retryAfter = r.headers['retry-after'] || ''; }
      }
      if (saw429) {
        ctx.log(`access: 레이트리밋 동작 관측(429${retryAfter ? `, Retry-After=${retryAfter}` : ''}) — 방어 정상`);
      } else if (!sawLimitHeader) {
        findings.push(bot('info', '레이트리밋 헤더 미관측 — 경량 관측(요청 3개)', host,
          `소수(3개) 요청에서 RateLimit/X-RateLimit/Retry-After 헤더나 429 응답이 관측되지 않았습니다. 레이트리밋 정책이 헤더로 노출되지 않거나 부재할 수 있습니다(부재 단서, 브루트포스 아님).`,
          '(no RateLimit/X-RateLimit/Retry-After headers in 3 probes; no 429)',
          'IETF RateLimit 헤더로 정책을 노출하고, 자동수집/남용 완화를 위해 엔드포인트별 레이트리밋을 적용하십시오.'));
      }
    }

    // ── (확장 K) CAPTCHA/챌린지 시그니처 식별 (루트 본문 기반) ──
    {
      const sig = detectChallengeSignature(root.body, root.headers);
      if (sig) {
        findings.push(bot('info', `봇 챌린지/CAPTCHA 시그니처 관측: ${sig}`, host,
          `루트 응답에서 봇 챌린지/CAPTCHA(${sig}) 시그니처가 관측됩니다. 자동수집 완화 통제가 동작 중일 가능성이 높습니다(긍정 신호, 참고용).`,
          `challenge signature: ${sig}`,
          '챌린지가 정상 사용자 경험을 과도하게 저해하지 않는지, 그리고 API/민감 경로에도 일관 적용되는지 확인하십시오.',
          'firm')); // 본문/헤더의 실제 챌린지 시그니처를 매칭한 콘텐츠 기반 긍정 관측 = firm
      }
    }

    // ── (확장 L) 세션 쿠키 보안 속성 + JWT alg 노출 단서 ──
    {
      const setCookie = root.headers['set-cookie'] || '';
      if (setCookie) {
        const lc = setCookie.toLowerCase();
        const sessionish = /(session|sess|sid|auth|token|jwt|jsessionid|phpsessid|connect\.sid)/i.test(setCookie);
        if (sessionish) {
          const missing: string[] = [];
          if (!/httponly/.test(lc)) missing.push('HttpOnly');
          if (!/secure/.test(lc) && ctx.asset.type !== 'host') missing.push('Secure');
          if (!/samesite/.test(lc)) missing.push('SameSite');
          if (missing.length > 0) {
            findings.push({ ...mk('access', missing.includes('HttpOnly') ? 'medium' : 'low',
              `세션 쿠키 보안 속성 누락: ${missing.join(', ')}`, host,
              `세션/인증 추정 쿠키에 보안 속성(${missing.join(', ')})이 누락되어 있습니다. HttpOnly 미설정은 XSS 를 통한 세션 탈취, Secure 미설정은 평문 전송 노출, SameSite 미설정은 CSRF 위험을 키웁니다.`,
              `Set-Cookie: ${setCookie.slice(0, 100).replace(/\s+/g, ' ')}`,
              '세션/인증 쿠키에 HttpOnly·Secure·SameSite=Lax(또는 Strict) 속성을 설정하십시오.'),
              owasp: 'A05:2021', cwe: 'CWE-1004', confidence: 'firm', references: REF_A01 });
          }
          // JWT alg=none / HS 노출 단서 (쿠키 값에 JWT 형태가 직접 노출되는 경우)
          const jwt = detectJwtAlg(setCookie);
          if (jwt) {
            const crit = jwt.alg.toLowerCase() === 'none';
            findings.push({ ...mk('access', crit ? 'high' : 'low',
              `쿠키 내 JWT 헤더 alg 노출: alg=${jwt.alg}`, host,
              crit
                ? 'Set-Cookie 로 전달된 JWT 의 헤더 alg 가 "none" 으로 디코딩됩니다. 서명 검증이 없는 토큰이면 위변조 위험이 매우 큽니다(비파괴 디코딩, 위변조 미시도).'
                : `Set-Cookie 로 전달된 JWT 의 헤더 alg=${jwt.alg}(대칭키 HMAC 추정)가 노출됩니다. 약한 시크릿/혼동 공격(alg confusion) 표면을 점검할 단서입니다.`,
              `JWT header(base64url decoded): {"alg":"${jwt.alg}"${jwt.typ ? `,"typ":"${jwt.typ}"` : ''}}`,
              'JWT 는 강한 비대칭 서명(RS/ES) 또는 충분히 긴 비밀키의 HMAC 으로 서명·검증하고, alg=none 을 거부하며 서버가 허용 alg 를 고정하십시오.'),
              owasp: 'A02:2021', cwe: crit ? 'CWE-347' : 'CWE-327', confidence: 'firm', references: REF_A01 });
          }
        }
      }
    }

    // ─────────── (4) 비인가 API 개인정보·과다 노출 (실제 유출 사고 클래스) ───────────
    // "API 요청 시 개인정보를 무분별하게 제공하는 구조" — 관리자 페이지가 아니라 인증 없이 호출되는
    // 데이터 API 가 PII 를 그대로 반환하는 표면을 발견·분석한다. 비파괴(GET/HEAD/OPTIONS, 식별자 소량 표본).
    try {
      const apiFindings = await scanApiExposure({ ctx, base, host, root, baseStatus, baseBody });
      findings.push(...apiFindings);
    } catch (e) {
      ctx.log(`access: API 노출 점검 오류 — ${(e as Error).message}`);
    }

    return findings;
  },
};

/**
 * 두 응답 본문이 사실상 동일한지(포괄 200 / soft-404 판정용).
 * 길이 근접 + 앞부분 문자 일치율로 근사한다.
 */
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (Math.abs(a.length - b.length) > Math.max(48, Math.min(a.length, b.length) * 0.15)) return false;
  const n = Math.min(a.length, b.length, 600);
  if (n === 0) return false;
  let same = 0;
  for (let i = 0; i < n; i++) if (a[i] === b[i]) same++;
  return same / n > 0.9;
}

/**
 * 200 응답이 로그인/인증 게이트 페이지인지 판정.
 * 관리 경로가 200 으로 "로그인 폼"을 반환하면 인가 누락이 아니라 정상 보호다(오탐 억제).
 */
function looksLikeLogin(body: string): boolean {
  if (/type\s*=\s*["']password["']/i.test(body)) return true;
  const b = body.slice(0, 30_000).toLowerCase();
  const loginWords = /(로그인|로그인이 필요|sign\s?in|log\s?in|please log in|authentication required|unauthorized|권한이 없|접근 권한|비밀번호)/i;
  return loginWords.test(b) && body.length < 24_000;
}

/** 같은 페이지 템플릿인지(IDOR: 동일 형식·다른 데이터 판정). 앞부분 일치 + 길이 동급. */
function sameTemplate(a: string, b: string): boolean {
  if (!a || !b) return false;
  const head = 60;
  if (a.slice(0, head) !== b.slice(0, head)) return false;
  const lo = Math.min(a.length, b.length);
  const hi = Math.max(a.length, b.length);
  return lo / hi > 0.4; // 데이터 차이로 길이는 달라질 수 있으나 같은 템플릿이면 동급
}

/** 본문에서 비순차 추측 가능한 숫자 식별자 대상(쿼리/경로)을 추출하고 URL 빌더를 생성. */
function collectIdTargets(body: string, base: string): { param: string; val: number; label: string; url: (v: number) => string }[] {
  const out: { param: string; val: number; label: string; url: (v: number) => string }[] = [];
  const seen = new Set<string>();
  const ID_PARAMS = /(id|uid|userid|user|account|order|orderid|no|seq|num|pid|doc|docid|file|fileid|idx)/i;

  // 쿼리형: href/src/action 안의 절대/상대 URL + 숫자 id 파라미터
  for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
    const raw = m[1]!;
    const pm = new RegExp(`[?&](${ID_PARAMS.source})=(\\d{1,9})\\b`, 'i').exec(raw);
    if (!pm) continue;
    const param = pm[1]!;
    const val = Number(pm[2]!);
    if (!(val >= 1 && val < 1e9)) continue;
    const key = `q:${param}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const abs = toAbsolute(raw, base);
    if (!abs) continue;
    out.push({
      param, val, label: `${stripOrigin(abs, base)}`,
      url: (v: number) => abs.replace(new RegExp(`([?&]${param}=)\\d+`, 'i'), `$1${v}`),
    });
  }

  // 경로형: /resource/123
  for (const m of body.matchAll(/["'\s(](\/[a-z][a-z0-9_\-]{1,24})\/(\d{1,9})(?=["'\/?#)\s]|$)/gi)) {
    const resource = m[1]!;
    const val = Number(m[2]!);
    if (!(val >= 1 && val < 1e9)) continue;
    const key = `p:${resource}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      param: resource.replace(/^\//, '') + '/{id}', val, label: `${resource}/${val}`,
      url: (v: number) => `${base}${resource}/${v}`,
    });
  }
  return out;
}

/** 상대/절대 URL 을 같은 출처(base) 기준 절대 URL 로 변환. 외부 출처/비HTTP 는 제외. */
function toAbsolute(raw: string, base: string): string | null {
  if (/^https?:\/\//i.test(raw)) return raw.startsWith(base) ? raw : null; // 동일 출처만
  if (raw.startsWith('//') || raw.startsWith('mailto:') || raw.startsWith('javascript:') || raw.startsWith('#')) return null;
  if (raw.startsWith('/')) return base.replace(/\/$/, '') + raw;
  return base.replace(/\/$/, '') + '/' + raw;
}

function stripOrigin(url: string, base: string): string {
  return url.startsWith(base) ? url.slice(base.replace(/\/$/, '').length) || '/' : url;
}

/** 경로의 첫 글자(슬래시 다음)를 대문자화한 변형을 생성. */
function capitalizeFirst(path: string): string {
  const m = /^\/([a-z])(.*)$/.exec(path);
  if (!m) return path;
  return '/' + m[1]!.toUpperCase() + m[2]!;
}

/** 본문이 JSON(객체/배열) 형태로 보이는지 가벼운 휴리스틱. */
function looksLikeJson(body: string): boolean {
  const t = body.trim();
  if (!t) return false;
  const first = t[0];
  if (first !== '{' && first !== '[') return false;
  // HTML 오인 방지
  if (/<html|<!doctype/i.test(t.slice(0, 200))) return false;
  return /["}\]]/.test(t.slice(0, 200));
}

/** 확장 AI/LLM 크롤러 User-Agent 집합 — 기술적 차단 동작 능동 확인용. */
const EXTENDED_AI_AGENTS: { ua: string; label: string }[] = [
  { ua: 'Mozilla/5.0 (compatible; Google-Extended)', label: 'Google-Extended' },
  { ua: 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)', label: 'PerplexityBot' },
  { ua: 'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)', label: 'Bytespider' },
  { ua: 'Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)', label: 'Amazonbot' },
  { ua: 'Mozilla/5.0 (compatible; Applebot-Extended/0.1)', label: 'Applebot-Extended' },
  { ua: 'Mozilla/5.0 (compatible; Diffbot/0.1; +https://www.diffbot.com)', label: 'Diffbot' },
  { ua: 'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)', label: 'Meta-ExternalAgent' },
  { ua: 'cohere-ai', label: 'cohere-ai' },
  { ua: 'Mozilla/5.0 (compatible; YouBot (+http://you.com))', label: 'YouBot' },
  { ua: 'Timpibot/0.1 (+http://www.timpi.io)', label: 'Timpibot' },
  { ua: 'Mozilla/5.0 (compatible; ImagesiftBot; +imagesift.com)', label: 'ImagesiftBot' },
  { ua: 'Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)', label: 'CCBot' },
];

/** 본문/헤더에서 봇 챌린지·CAPTCHA 시그니처를 식별. 일치 시 라벨 반환. */
function detectChallengeSignature(body: string, headers: Record<string, string>): string | null {
  const hj = JSON.stringify(headers).toLowerCase();
  if (/cf-mitigated|cf-chl|__cf_chl/i.test(body) || /cf-mitigated/.test(hj)) return 'Cloudflare 챌린지';
  if (/just a moment|attention required/i.test(body)) return 'Cloudflare "Just a moment"';
  if (/datadome/i.test(body) || /datadome/.test(hj)) return 'DataDome';
  if (/perimeterx|_px(2|3|hd)?/i.test(body) || /perimeterx|x-px/.test(hj)) return 'PerimeterX/HUMAN';
  if (/kasada|kpsdk/i.test(body) || /kasada/.test(hj)) return 'Kasada';
  if (/imperva|incapsula|_incap_/i.test(body) || /incapsula|imperva/.test(hj)) return 'Imperva/Incapsula';
  if (/g-recaptcha|recaptcha\/api\.js|grecaptcha/i.test(body)) return 'Google reCAPTCHA';
  if (/hcaptcha\.com|h-captcha/i.test(body)) return 'hCaptcha';
  if (/challenges\.cloudflare\.com\/turnstile|cf-turnstile/i.test(body)) return 'Cloudflare Turnstile';
  return null;
}

/** Set-Cookie 문자열에서 JWT 형태 값의 헤더 alg 를 비파괴로 디코딩(첫 세그먼트 base64url). */
function detectJwtAlg(setCookie: string): { alg: string; typ?: string } | null {
  // eyJ... 로 시작하는 3-세그먼트 JWT 후보 추출
  const m = /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/.exec(setCookie);
  if (!m) return null;
  const headSeg = m[0].split('.')[0]!;
  try {
    const b64 = headSeg.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64 + '==='.slice((b64.length + 3) % 4);
    const json = Buffer.from(pad, 'base64').toString('utf8');
    const obj = JSON.parse(json) as { alg?: unknown; typ?: unknown };
    if (typeof obj.alg !== 'string') return null;
    return { alg: obj.alg, typ: typeof obj.typ === 'string' ? obj.typ : undefined };
  } catch {
    return null;
  }
}

/** 본문에서 불투명 식별자(UUID/GUID/긴 base64url 토큰)가 URL 에 직접 노출되는 대상을 추출. */
function collectOpaqueIdTargets(body: string, base: string): { kind: string; sample: string }[] {
  const out: { kind: string; sample: string }[] = [];
  const seen = new Set<string>();
  // href/src/action URL 내부의 식별자만(노이즈 억제)
  for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
    const raw = m[1]!;
    const abs = toAbsolute(raw, base);
    if (!abs) continue;
    const uuid = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.exec(raw);
    if (uuid && !seen.has('uuid')) {
      seen.add('uuid');
      out.push({ kind: 'UUID/GUID', sample: stripOrigin(abs, base) });
      continue;
    }
    // 경로/쿼리에 등장하는 길이 16+ base64url 토큰(시간/캐시버스터 회피 위해 길이 제한)
    const b64 = /[?&/](?:id|token|ref|key|hash|t)=([A-Za-z0-9_-]{16,64})\b/i.exec(raw)
      || /\/([A-Za-z0-9_-]{22,64})(?=["'/?#]|$)/.exec(raw);
    if (b64 && /[A-Za-z]/.test(b64[1]!) && /[0-9]/.test(b64[1]!) && !seen.has('b64')) {
      seen.add('b64');
      out.push({ kind: 'Base64URL/불투명 토큰', sample: stripOrigin(abs, base) });
    }
  }
  return out;
}
