/**
 * 설정·구성 점검 (Configuration Audit) — 설계 §4.2 (전문 확장판).
 * HTTP 보안 헤더(현행 권장 전체), CORS 구성 오류, 허용 HTTP 메서드(TRACE 등),
 * 쿠키 플래그 심층 분석, security.txt 모범사례, 정밀 민감 경로 노출(콘텐츠 검증 +
 * soft-404 베이스라이닝으로 오탐 제거)을 비파괴 HTTP 요청으로 점검한다.
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { mk } from './asm.js';
import { CVE_FEED, lessThan } from './feed.js';

interface HeaderRule { header: string; title: string; severity: Finding['severity']; remediation: string; }

const SECURITY_HEADERS: HeaderRule[] = [
  { header: 'strict-transport-security', title: 'HSTS 헤더 누락', severity: 'medium', remediation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload 적용' },
  { header: 'content-security-policy', title: 'CSP 헤더 누락', severity: 'medium', remediation: "Content-Security-Policy 로 default-src 'self' 등 출처를 제한" },
  { header: 'x-frame-options', title: 'X-Frame-Options 누락 (클릭재킹)', severity: 'low', remediation: 'X-Frame-Options: DENY 또는 CSP frame-ancestors 적용' },
  { header: 'x-content-type-options', title: 'X-Content-Type-Options 누락 (MIME 스니핑)', severity: 'low', remediation: 'X-Content-Type-Options: nosniff 적용' },
  { header: 'referrer-policy', title: 'Referrer-Policy 누락', severity: 'info', remediation: 'Referrer-Policy: strict-origin-when-cross-origin 적용' },
  { header: 'permissions-policy', title: 'Permissions-Policy 누락', severity: 'info', remediation: 'Permissions-Policy 로 카메라·마이크·위치 등 브라우저 기능 사용을 제한' },
  { header: 'cross-origin-opener-policy', title: 'COOP(Cross-Origin-Opener-Policy) 누락', severity: 'info', remediation: 'Cross-Origin-Opener-Policy: same-origin 적용 (XS-Leaks 완화)' },
  { header: 'cross-origin-resource-policy', title: 'CORP(Cross-Origin-Resource-Policy) 누락', severity: 'info', remediation: 'Cross-Origin-Resource-Policy: same-origin 적용' },
];

/** 정밀 민감 경로 — 콘텐츠 시그니처로 검증하여 오탐을 제거한다. */
interface PathRule { path: string; title: string; severity: Finding['severity']; sig: (b: string) => boolean; remediation: string; }
const SENSITIVE_PATHS: PathRule[] = [
  { path: '/.env', title: '.env 환경설정 노출', severity: 'critical', sig: (b) => /(^|\n)\s*[A-Z0-9_]+\s*=/.test(b) && !/<html/i.test(b), remediation: '외부 접근 차단 및 노출된 모든 비밀키 즉시 폐기·재발급' },
  { path: '/.git/HEAD', title: '.git 저장소 노출', severity: 'high', sig: (b) => /ref:\s*refs\//.test(b), remediation: '.git 디렉터리 외부 접근 차단' },
  { path: '/.git/config', title: '.git/config 노출', severity: 'high', sig: (b) => /\[core\]|\[remote/.test(b), remediation: '.git 디렉터리 외부 접근 차단' },
  { path: '/.svn/entries', title: '.svn 메타 노출', severity: 'high', sig: (b) => /^\d+\s|svn:/.test(b), remediation: '.svn 디렉터리 외부 접근 차단' },
  { path: '/.DS_Store', title: 'macOS .DS_Store 노출', severity: 'low', sig: (b) => b.includes('Bud1') || /\x00\x00\x00/.test(b), remediation: '.DS_Store 파일 제거 및 배포 제외' },
  { path: '/server-status', title: 'Apache server-status 노출', severity: 'high', sig: (b) => /Apache Server Status|Server uptime/i.test(b), remediation: 'mod_status 접근을 내부망/허용 IP로 제한' },
  { path: '/actuator', title: 'Spring Boot Actuator 노출', severity: 'high', sig: (b) => /"_links"|"health"|"actuator"/.test(b), remediation: 'Actuator 엔드포인트 인증 적용 및 노출 최소화' },
  { path: '/actuator/env', title: 'Actuator /env (환경변수) 노출', severity: 'critical', sig: (b) => /"propertySources"|"activeProfiles"/.test(b), remediation: 'Actuator env 비활성화 또는 인증 적용' },
  { path: '/phpinfo.php', title: 'phpinfo() 노출', severity: 'medium', sig: (b) => /phpinfo\(\)|PHP Version/i.test(b), remediation: 'phpinfo 페이지 제거' },
  { path: '/.aws/credentials', title: 'AWS 자격증명 파일 노출', severity: 'critical', sig: (b) => /aws_access_key_id/i.test(b), remediation: '즉시 차단 및 해당 IAM 키 폐기·교체' },
  { path: '/swagger.json', title: 'API 스펙(Swagger) 노출', severity: 'low', sig: (b) => /"swagger"|"openapi"/.test(b), remediation: '운영 환경에서 API 문서 노출 여부 검토·제한' },
  { path: '/wp-config.php.bak', title: 'WordPress 설정 백업 노출', severity: 'critical', sig: (b) => /DB_PASSWORD|DB_NAME/.test(b), remediation: '백업 파일 제거 및 DB 자격증명 교체' },
  { path: '/.htaccess', title: '.htaccess 노출', severity: 'medium', sig: (b) => /RewriteRule|RewriteEngine|<Files/i.test(b), remediation: '.htaccess 외부 접근 차단' },
  { path: '/backup.zip', title: '백업 아카이브 노출', severity: 'high', sig: (b) => b.startsWith('PK') || /\x50\x4b\x03\x04/.test(b), remediation: '백업 파일을 웹루트에서 제거' },
];

export const configScanner: Scanner = {
  module: 'config',
  minIntensity: 'standard',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const base = ctx.asset.type === 'host' ? `http://${ctx.asset.value}` : `https://${ctx.asset.value}`;
    const root = await ctx.guard.httpGet(base + '/');
    if (!root) {
      ctx.log('config: HTTP 응답 없음 — 점검 생략');
      return findings;
    }

    // soft-404 베이스라인 — SPA/포괄 200 응답 사이트의 오탐 제거
    const rnd = `/sentinel-404-${Math.random().toString(36).slice(2)}`;
    const baseline = await ctx.guard.httpGet(base + rnd);
    const baseBody = baseline?.body ?? '';
    const baseStatus = baseline?.status ?? 404;
    const isSoft404 = (r: { status: number; body: string }) =>
      (baseStatus === 200 && r.status === 200 && similar(r.body, baseBody));

    // 1) 보안 헤더 — 근거는 "요청 + 실제 수신 헤더 목록 + 해당 헤더 부재"를 모두 보여 검증 가능하게 한다.
    const recvHeaderNames = Object.keys(root.headers);
    for (const h of SECURITY_HEADERS) {
      if (!(h.header in root.headers)) {
        const evidence =
          `요청: GET ${base}/  →  HTTP ${root.status}\n` +
          `관측: 응답 헤더에 '${h.header}' 없음\n` +
          `수신한 헤더(${recvHeaderNames.length}개): ${recvHeaderNames.join(', ') || '(없음)'}`;
        findings.push({ ...mk('config', h.severity, h.title, ctx.asset.value, `응답에 ${h.header} 헤더가 없습니다.`, evidence, h.remediation), confidence: 'firm' });
      }
    }
    // 레거시/위험 헤더 값
    if (root.headers['x-xss-protection'] && root.headers['x-xss-protection'].startsWith('1')) {
      findings.push(mk('config', 'low', 'X-XSS-Protection 활성(폐기된 헤더)', ctx.asset.value, '구형 XSS 필터는 우회·부작용 위험이 있어 비활성(0) 권장.', `x-xss-protection: ${root.headers['x-xss-protection']}`, 'X-XSS-Protection: 0 으로 설정하고 CSP 로 대체'));
    }

    // 2) 정보 노출 헤더
    const leak = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'].filter((k) => root.headers[k]);
    if (leak.length) {
      findings.push(mk('config', 'low', '서버 정보 노출 헤더', ctx.asset.value, '제품/버전 정보가 헤더로 노출되어 공격 표면 식별에 악용될 수 있습니다.', leak.map((k) => `${k}: ${root.headers[k]}`).join('\n'), '불필요한 식별 헤더를 제거하거나 일반화하십시오.'));
    }

    // 3) 쿠키 플래그 심층
    const setCookie = root.headers['set-cookie'];
    if (setCookie) {
      const lc = setCookie.toLowerCase();
      const missing: string[] = [];
      if (!lc.includes('secure')) missing.push('Secure');
      if (!lc.includes('httponly')) missing.push('HttpOnly');
      if (!lc.includes('samesite')) missing.push('SameSite');
      if (missing.length) {
        findings.push(mk('config', 'medium', `쿠키 보안 플래그 누락: ${missing.join(', ')}`, ctx.asset.value, '세션 쿠키에 보안 플래그가 누락되어 탈취/CSRF 위험이 있습니다.', setCookie.slice(0, 200), '쿠키에 Secure; HttpOnly; SameSite=Lax|Strict 적용.'));
      }
    }

    // 4) CORS 구성 오류 — Origin 반사 + 자격증명 허용 여부
    const cors = await ctx.guard.httpGet(base + '/', { headers: { origin: 'https://sentinel-cors-probe.example' } });
    if (cors) {
      const acao = cors.headers['access-control-allow-origin'];
      const acac = cors.headers['access-control-allow-credentials'];
      if (acao === '*' && acac === 'true') {
        findings.push(mk('config', 'high', 'CORS 구성 오류: 와일드카드 + 자격증명 허용', ctx.asset.value, 'Access-Control-Allow-Origin:* 와 Allow-Credentials:true 조합은 사양 위반이자 자격증명 탈취 위험입니다.', `ACAO=${acao}, ACAC=${acac}`, '신뢰 출처 화이트리스트로 ACAO 를 동적 설정하고 와일드카드+credentials 조합을 제거.'));
      } else if (acao === 'https://sentinel-cors-probe.example') {
        findings.push(mk('config', acac === 'true' ? 'high' : 'medium', 'CORS Origin 무검증 반사', ctx.asset.value, '임의 Origin 을 그대로 반사하여 교차 출처 데이터 접근이 가능합니다.', `반사된 ACAO=${acao}, ACAC=${acac ?? '-'}`, 'Origin 을 신뢰 목록과 대조 후 허용.'));
      }
    }

    // 5) 허용 HTTP 메서드 — TRACE/PUT/DELETE 노출
    const opt = await ctx.guard.httpGet(base + '/', { method: 'OPTIONS' });
    const allow = (opt?.headers['allow'] || '').toUpperCase();
    if (allow) {
      const risky = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'].filter((m) => allow.includes(m));
      if (risky.length) {
        findings.push(mk('config', risky.includes('TRACE') || risky.includes('PUT') ? 'medium' : 'low', `위험 HTTP 메서드 허용: ${risky.join(', ')}`, ctx.asset.value, '불필요한 메서드 허용은 XST·파일 변조 등 공격 표면을 넓힙니다.', `Allow: ${allow}`, '필요한 메서드(GET/POST/HEAD)만 허용하고 TRACE/PUT/DELETE 비활성화.'));
      }
    }

    // 6) security.txt 모범사례 (RFC 9116)
    const sectxt = await ctx.guard.httpGet(base + '/.well-known/security.txt');
    if (!sectxt || sectxt.status !== 200 || !/contact:/i.test(sectxt.body)) {
      findings.push(mk('config', 'info', 'security.txt 미제공 (취약점 신고 창구 부재)', ctx.asset.value, '연구자가 취약점을 신고할 표준 창구(RFC 9116)가 없습니다.', `status=${sectxt?.status ?? '-'}`, '/.well-known/security.txt 에 Contact·Policy 를 게시.'));
    }

    // 7) 정밀 민감 경로 (콘텐츠 검증 + soft-404 가드)
    const paths = ctx.deep ? [...SENSITIVE_PATHS, ...DEEP_PATHS] : SENSITIVE_PATHS;
    for (const p of paths) {
      const r = await ctx.guard.httpGet(base + p.path);
      if (!r || r.status !== 200 || !r.body) continue;
      if (isSoft404(r)) continue;          // 포괄 200 응답 → 오탐 제거
      if (!p.sig(r.body)) continue;        // 콘텐츠 시그니처 불일치 → 오탐 제거
      findings.push({ ...mk('config', p.severity, p.title, ctx.asset.value + p.path, '소스/설정/민감 정보가 외부에 노출되어 있습니다.', `status=200, sig=match, ${r.body.slice(0, 60).replace(/\s+/g, ' ')}`, p.remediation), confidence: 'confirmed' });
    }

    // ───────── 심층 정밀 점검 (토시 하나까지) ─────────
    if (ctx.deep) {
      // CSP 품질 분석 (존재해도 약하면 지적)
      const csp = root.headers['content-security-policy'];
      if (csp) {
        const weak: string[] = [];
        if (/unsafe-inline/.test(csp)) weak.push("'unsafe-inline' 허용");
        if (/unsafe-eval/.test(csp)) weak.push("'unsafe-eval' 허용");
        if (/(^|\s)\*(\s|;|$)/.test(csp) || /default-src[^;]*\*/.test(csp)) weak.push('와일드카드(*) 출처');
        if (!/object-src/.test(csp)) weak.push('object-src 미지정');
        if (!/base-uri/.test(csp)) weak.push('base-uri 미지정');
        if (!/frame-ancestors/.test(csp)) weak.push('frame-ancestors 미지정');
        if (weak.length) findings.push({ ...mk('config', 'medium', `CSP 정책 약점: ${weak.join(', ')}`, ctx.asset.value, 'CSP 가 존재하나 우회 가능한 약한 지시문을 포함합니다.', csp.slice(0, 200), "nonce/해시 기반 정책으로 unsafe-inline 제거, object-src 'none', base-uri 'self', frame-ancestors 지정."), confidence: 'firm' });
      }
      // HSTS 품질
      const hsts = root.headers['strict-transport-security'];
      if (hsts) {
        const maxAge = Number((hsts.match(/max-age=(\d+)/) || [])[1] || 0);
        const issues: string[] = [];
        if (maxAge < 31536000) issues.push(`max-age 부족(${maxAge} < 31536000)`);
        if (!/includesubdomains/i.test(hsts)) issues.push('includeSubDomains 누락');
        if (!/preload/i.test(hsts)) issues.push('preload 누락');
        if (issues.length) findings.push({ ...mk('config', 'low', `HSTS 정책 미흡: ${issues.join(', ')}`, ctx.asset.value, 'HSTS 가 존재하나 보호 범위/기간이 권장 기준에 미달합니다.', hsts, 'max-age=31536000; includeSubDomains; preload 로 강화.'), confidence: 'firm' });
      }
      // 쿠키 개별 분석 (__Host-/__Secure- 접두 규칙 포함)
      const sc = root.headers['set-cookie'];
      if (sc) {
        for (const cookie of sc.split(/,(?=[^;]+=)/)) {
          const name = (cookie.split('=')[0] || '').trim();
          const lc = cookie.toLowerCase();
          if (name.startsWith('__Host-') && (!lc.includes('secure') || !/path=\/(;|$)/.test(lc) || lc.includes('domain='))) {
            findings.push(mk('config', 'medium', `__Host- 쿠키 규칙 위반: ${name}`, ctx.asset.value, '__Host- 접두 쿠키는 Secure + Path=/ + Domain 미지정이어야 합니다.', cookie.slice(0, 120), '__Host- 접두 규칙을 준수하도록 쿠키 속성을 수정.'));
          }
        }
      }
      // 혼합 콘텐츠 (HTTPS 페이지의 http:// 리소스)
      if (ctx.asset.type !== 'host') {
        const mixed = [...root.body.matchAll(/(?:src|href)=["']http:\/\/[^"']+/gi)].slice(0, 5);
        if (mixed.length) findings.push(mk('config', 'low', `혼합 콘텐츠(Mixed Content) ${mixed.length}건+`, ctx.asset.value, 'HTTPS 페이지가 평문 HTTP 리소스를 로드하여 가로채기/변조 위험이 있습니다.', mixed.map((m) => m[0].slice(0, 60)).join('\n'), '모든 리소스를 HTTPS 로 로드하고 upgrade-insecure-requests 적용.'));
      }
      // 캐시 제어 (민감 응답 캐싱 방지)
      const cache = (root.headers['cache-control'] || '').toLowerCase();
      if (root.headers['set-cookie'] && !/no-store|private/.test(cache)) {
        findings.push(mk('config', 'info', '인증 응답 캐시 제어 미흡', ctx.asset.value, '세션 쿠키를 설정하는 응답에 no-store/private 캐시 정책이 없습니다.', `cache-control: ${root.headers['cache-control'] || '(없음)'}`, '인증/민감 응답에 Cache-Control: no-store 적용.'));
      }
      // ── §3 헤더 심층 ──
      // Trusted Types 미적용 (DOM XSS 완화 부재)
      if (csp && !/require-trusted-types-for/i.test(csp)) {
        findings.push(mk('config', 'info', 'Trusted Types 미적용', ctx.asset.value, 'CSP 가 있으나 require-trusted-types-for 가 없어 DOM 기반 XSS 완화가 부족합니다.', csp.slice(0, 120), "require-trusted-types-for 'script' 적용을 검토하십시오."));
      }
      // ── 보안 리포팅 인프라 (Report-To / NEL / Expect-CT) ──
      if (!root.headers['report-to'] && !root.headers['reporting-endpoints']) {
        findings.push(mk('config', 'info', 'Report-To/Reporting-Endpoints 미설정', ctx.asset.value, '브라우저 보안 위반 리포트(CSP·COOP·NEL 등)를 수신하는 엔드포인트가 없어 공격 시도를 가시화할 수 없습니다.', 'no Report-To', 'Reporting-Endpoints 헤더와 CSP report-to 지시문을 설정하십시오.'));
      }
      if (!root.headers['nel']) {
        findings.push(mk('config', 'info', 'NEL(Network Error Logging) 미설정', ctx.asset.value, '네트워크 오류·연결 실패 이상이 모니터링되지 않습니다.', 'no NEL', 'NEL 헤더를 설정하여 네트워크 이상을 수집하십시오.'));
      }
      // Expect-CT 는 폐기됐지만 잔존 시 max-age=0 권고
      if (root.headers['expect-ct'] && !/max-age=0/.test(root.headers['expect-ct']!)) {
        findings.push(mk('config', 'info', 'Expect-CT 잔존(폐기 헤더)', ctx.asset.value, 'Expect-CT 는 Chrome 브라우저에서 폐기되었습니다(2022). max-age=0 으로 비활성화하거나 제거하십시오.', root.headers['expect-ct'], 'Expect-CT 를 제거하거나 max-age=0 으로 설정하십시오.'));
      }

      // ── 서버 헤더 버전 → CVE 피드 대조 (경쟁사 대비 심화) ──
      const serverHeader = root.headers['server'] || root.headers['x-powered-by'] || '';
      if (serverHeader && ctx.deep) {
        const serverCveRules: { re: RegExp; product: string }[] = [
          { re: /nginx\/([\d.]+)/i, product: 'nginx' },
          { re: /apache\/([\d.]+)/i, product: 'apache' },
          { re: /openssl\/([\d.]+)/i, product: 'openssl' },
          { re: /microsoft-iis\/([\d.]+)/i, product: 'iis' },
          { re: /php\/([\d.]+)/i, product: 'php' },
        ];
        for (const rule of serverCveRules) {
          const m = rule.re.exec(serverHeader);
          if (m && m[1]) {
            for (const entry of CVE_FEED) {
              if (entry.product === rule.product && entry.ecosystem === 'service' && lessThan(m[1], entry.vulnerableBelow)) {
                const sev: Finding['severity'] = entry.cvss >= 9 ? 'critical' : entry.cvss >= 7 ? 'high' : 'medium';
                findings.push({ ...mk('config', sev, `${entry.cve}: ${entry.title} (서버 헤더 버전 탐지)`, ctx.asset.value, `서버 헤더에서 ${rule.product} ${m[1]} 버전이 탐지되어 알려진 CVE 에 노출됩니다.`, `${serverHeader.slice(0, 60)} → ${rule.product}@${m[1]}`, entry.remediation), cvss: entry.cvss, epss: entry.epss, cve: entry.cve });
              }
            }
          }
        }
      }

      // Vary 헤더 부재 (캐시 포이즈닝/콘텐츠 협상 오류 표면)
      if (!('vary' in root.headers) && root.headers['cache-control'] && !/no-store/.test((root.headers['cache-control'] || '').toLowerCase())) {
        findings.push(mk('config', 'info', 'Vary 헤더 부재', ctx.asset.value, '캐시되는 응답에 Vary 가 없어 캐시 포이즈닝/콘텐츠 혼선 표면이 됩니다.', `cache-control=${root.headers['cache-control']}`, 'Vary 로 캐시 키에 영향을 주는 헤더를 명시하십시오.'));
      }
      // 이중 클릭재킹 무방비 (XFO 와 CSP frame-ancestors 모두 부재)
      if (!('x-frame-options' in root.headers) && !(csp && /frame-ancestors/i.test(csp))) {
        findings.push(mk('config', 'medium', '클릭재킹 무방비 (XFO·frame-ancestors 모두 없음)', ctx.asset.value, '프레임 차단 수단이 전혀 없어 클릭재킹에 노출됩니다.', 'no XFO, no CSP frame-ancestors', "X-Frame-Options: DENY 또는 CSP frame-ancestors 'none' 적용."));
      }
      // 쿠키 프레임워크 지문
      if (sc) {
        const FW_COOKIES: [string, string][] = [['JSESSIONID', 'Java/Tomcat'], ['PHPSESSID', 'PHP'], ['connect.sid', 'Node/Express'], ['ASP.NET_SessionId', 'ASP.NET'], ['laravel_session', 'Laravel'], ['_django', 'Django']];
        const fp = FW_COOKIES.find(([n]) => sc.includes(n));
        if (fp) findings.push(mk('config', 'info', `세션 쿠키로 기술 스택 노출: ${fp[1]}`, ctx.asset.value, `세션 쿠키 명(${fp[0]})으로 백엔드 프레임워크가 식별됩니다.`, fp[0], '쿠키 명을 일반화하여 기술 스택 노출을 줄이십시오.'));
      }
      // CORS null origin + 정규식 결함
      const corsNull = await ctx.guard.httpGet(base + '/', { headers: { origin: 'null' } });
      if (corsNull && corsNull.headers['access-control-allow-origin'] === 'null') {
        findings.push(mk('config', 'high', "CORS 'null' origin 허용", ctx.asset.value, "Origin: null 을 허용하면 sandboxed iframe·data: 문서에서 교차출처 접근이 가능합니다.", 'ACAO=null', "'null' origin 을 허용하지 마십시오."));
      }
      const corsRegex = await ctx.guard.httpGet(base + '/', { headers: { origin: `https://${ctx.asset.value}.sentinel-evil.example` } });
      if (corsRegex && (corsRegex.headers['access-control-allow-origin'] || '').includes('sentinel-evil.example')) {
        findings.push(mk('config', 'high', 'CORS Origin 정규식 검증 결함', ctx.asset.value, `접미사 일치 결함으로 '도메인.공격자.com' 형태가 허용됩니다.`, `ACAO=${corsRegex.headers['access-control-allow-origin']}`, 'Origin 을 정확 일치(==)로 검증하십시오.'));
      }
      // CDN/WAF 핑거프린팅
      const CDN_SIG: [string, string][] = [['cf-ray', 'Cloudflare'], ['x-amz-cf-id', 'AWS CloudFront'], ['x-sucuri-id', 'Sucuri WAF'], ['x-akamai-transformed', 'Akamai'], ['x-iinfo', 'Imperva/Incapsula'], ['server', '']];
      const cdnSig = CDN_SIG.map(([h, n]) => root.headers[h] ? (n || root.headers[h]) : null).filter(Boolean);
      if (cdnSig.length) findings.push(mk('config', 'info', `CDN/WAF/서버 지문: ${cdnSig.slice(0, 3).join(', ')}`, ctx.asset.value, '응답 헤더로 CDN/WAF/서버 스택이 식별됩니다(오리진 직접 접근·우회 표면 점검 권장).', cdnSig.join(' | '), '오리진 IP 직접 노출 여부 및 WAF 우회 경로를 점검하십시오.'));

      // ── §5 API 심층 ──
      // GraphQL 노출 탐지: 비파괴 GET 만 사용(쿼리 파라미터로 읽기전용 introspection-lite).
      // POST 금지(상태 변경/뮤테이션 트리거 위험). 안전 마커 쿼리만 송신.
      const gql = await ctx.guard.httpGet(base + '/graphql?query=' + encodeURIComponent('{__typename}'));
      const gqlExposed = !!gql && gql.status < 500 && /__schema|__typename|"data"|GraphQL|graphql|errors/i.test(gql.body);
      if (gqlExposed && gql) {
        findings.push(mk('config', 'low', 'GraphQL 엔드포인트 노출', ctx.asset.value, 'GraphQL 이 외부에 노출되어 인트로스펙션으로 스키마가 유출될 수 있습니다.', `status=${gql.status}`, '운영에서 인트로스펙션 비활성화 및 인증 적용.'));
        // 필드 제안(field suggestion) 누출 — 의도적 오타 쿼리를 GET 으로만 송신(읽기전용).
        const sug = await ctx.guard.httpGet(base + '/graphql?query=' + encodeURIComponent('{__typ}'));
        if (sug && /Did you mean|있습니까|suggest/i.test(sug.body)) {
          findings.push(mk('config', 'low', 'GraphQL 필드 제안(field suggestion) 누출', ctx.asset.value, '오타 시 유사 필드를 제안하여 인트로스펙션이 꺼져 있어도 스키마를 추론할 수 있습니다.', sug.body.slice(0, 80), '운영에서 필드 제안을 비활성화하십시오.'));
        }
      }
      // REST 버전 병존 (폐기본 잔존)
      for (const v of ['/v1/', '/api/v1/', '/v2/']) {
        const rv = await ctx.guard.httpGet(base + v);
        if (rv && [200, 401, 403].includes(rv.status) && !isSoft404(rv)) {
          findings.push(mk('config', 'info', `API 버전 경로 노출: ${v}`, ctx.asset.value + v, '버전 경로가 응답합니다. 폐기된 구버전 API 가 잔존하는지 확인이 필요합니다.', `status=${rv.status}`, '폐기 버전은 제거하고 사용 중 버전만 노출하십시오.'));
        }
      }
      // 레이트리밋 헤더 부재 (브루트포스/DoS 완화 신호)
      if (!Object.keys(root.headers).some((h) => /ratelimit|x-rate-limit|retry-after/i.test(h))) {
        findings.push(mk('config', 'info', '레이트리밋 헤더 미관측', ctx.asset.value, '응답에 RateLimit 헤더가 없어 브루트포스/남용 완화 정책이 노출되지 않습니다(부재일 수 있음).', '(no RateLimit headers)', '인증/민감 엔드포인트에 레이트리밋을 적용하고 표준 헤더를 노출하십시오.'));
      }

      // ── §6 공급망·코드 노출 ──
      // 빌드/메타 파일 노출
      for (const p of ['/version.json', '/build-info.json', '/humans.txt', '/.well-known/']) {
        const r = await ctx.guard.httpGet(base + p);
        if (r && r.status === 200 && r.body && !isSoft404(r)) {
          findings.push(mk('config', 'info', `빌드/메타 노출: ${p}`, ctx.asset.value + p, '버전·빌드·인프라 메타가 노출되어 정찰에 활용될 수 있습니다.', r.body.slice(0, 80).replace(/\s+/g, ' '), '운영 환경에서 불필요한 메타 파일을 제거하십시오.'));
        }
      }
      // 프론트엔드 번들: 소스맵 노출 + 하드코딩 시크릿 + SRI 누락
      const scripts = [...root.body.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)].slice(0, 6);
      for (const m of scripts) {
        const raw = m[1]!;
        const full = m[0]!;
        const url = raw.startsWith('http') ? raw : base.replace(/\/$/, '') + (raw.startsWith('/') ? raw : '/' + raw);
        const external = /^https?:\/\//.test(raw) && !url.startsWith(base);
        // SRI 누락 (외부 스크립트)
        if (external && !/\bintegrity=/.test(full)) {
          findings.push(mk('config', 'low', `외부 스크립트 SRI(integrity) 누락`, ctx.asset.value, '서드파티 스크립트에 무결성 검증(SRI)이 없어 공급망 변조 시 그대로 실행됩니다.', raw.slice(0, 80), 'integrity + crossorigin 속성을 적용하십시오.'));
        }
        // 동일 출처 번들만 본문 스캔(범위 준수)
        if (!external) {
          const js = await ctx.guard.httpGet(url);
          if (js && js.status === 200 && js.body) {
            // 소스맵 노출
            const mapRef = /sourceMappingURL=([^\s'"]+\.map)/.exec(js.body);
            if (mapRef) {
              const mapUrl = mapRef[1]!.startsWith('http') ? mapRef[1]! : url.replace(/\/[^/]*$/, '/') + mapRef[1]!;
              const mp = await ctx.guard.httpGet(mapUrl);
              if (mp && mp.status === 200 && /"sources"\s*:/.test(mp.body)) {
                findings.push({ ...mk('config', 'medium', '소스맵(.map) 노출 — 원본 소스 복원 가능', ctx.asset.value, '소스맵으로 난독화 이전의 전체 프론트엔드 소스를 복원할 수 있습니다.', mapUrl, '운영 배포에서 소스맵을 제외하거나 접근을 차단하십시오.'), confidence: 'confirmed' });
              }
            }
            // 하드코딩 시크릿
            const secretRules: [RegExp, string][] = [
              [/AKIA[0-9A-Z]{16}/, 'AWS Access Key'],
              [/sk_live_[0-9a-zA-Z]{16,}/, 'Stripe Secret Key'],
              [/xox[baprs]-[0-9A-Za-z-]{10,}/, 'Slack Token'],
              [/AIza[0-9A-Za-z_\-]{35}/, 'Google API Key'],
              [/gh[pousr]_[0-9A-Za-z]{30,}/, 'GitHub Token'],
              [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'Private Key'],
            ];
            for (const [re, label] of secretRules) {
              const hit = re.exec(js.body);
              if (hit) {
                findings.push({ ...mk('config', 'critical', `프론트엔드 번들 하드코딩 시크릿: ${label}`, ctx.asset.value, `JS 번들에 ${label} 로 보이는 시크릿이 노출되어 있습니다.`, `${url} → ${hit[0].slice(0, 8)}…`, '시크릿을 코드에서 제거하고 즉시 폐기·재발급하십시오.'), confidence: 'confirmed' });
                break;
              }
            }
            // 미참조 소스맵 직접 확인 (sourceMappingURL 주석 제거 케이스)
            if (!mapRef) {
              const mp2 = await ctx.guard.httpGet(url + '.map');
              if (mp2 && mp2.status === 200 && /"sources"\s*:/.test(mp2.body)) {
                findings.push({ ...mk('config', 'medium', '소스맵(.map) 직접 노출 — 원본 소스 복원 가능', ctx.asset.value, '주석 참조가 없어도 .map 이 직접 접근되어 원본 소스를 복원할 수 있습니다.', url + '.map', '운영 배포에서 .map 접근을 차단하십시오.'), confidence: 'confirmed' });
              }
            }
            // 세션 토큰 URL/localStorage 사용 신호
            if (/localStorage\.setItem\(\s*['"](?:access_?token|jwt|auth_?token|id_?token)/i.test(js.body)) findings.push(mk('config', 'medium', '토큰을 localStorage 에 저장(XSS 탈취 표면)', ctx.asset.value, '인증 토큰을 localStorage 에 보관하면 XSS 발생 시 탈취됩니다.', url, 'HttpOnly 쿠키 기반 세션으로 전환하십시오.'));
          }
        }
      }

      // ── §3 추가 헤더 품질 ──
      // COEP / 보조 헤더군
      const coop = root.headers['cross-origin-opener-policy'];
      if (coop && !root.headers['cross-origin-embedder-policy']) findings.push(mk('config', 'info', 'COEP 미설정(교차출처 격리 미완성)', ctx.asset.value, 'COOP 는 있으나 COEP 가 없어 crossOriginIsolated 가 미달성되어 Spectre 완화가 불완전합니다.', 'no Cross-Origin-Embedder-Policy', 'Cross-Origin-Embedder-Policy: require-corp 적용을 검토하십시오.'));
      if (root.headers['x-permitted-cross-domain-policies'] === 'all') findings.push(mk('config', 'low', 'X-Permitted-Cross-Domain-Policies: all (과허용)', ctx.asset.value, 'Adobe 교차도메인 정책이 전체 허용입니다.', 'all', "'none' 으로 제한하십시오."));
      // Permissions-Policy 품질
      const pp = root.headers['permissions-policy'];
      if (pp && /(geolocation|camera|microphone|payment|usb)=\*/.test(pp)) findings.push(mk('config', 'info', 'Permissions-Policy 광범위 허용', ctx.asset.value, '민감 브라우저 기능이 전체(*) 허용되어 있습니다.', pp.slice(0, 120), '필요한 출처(self)로 제한하십시오.'));
      // Referrer-Policy 품질
      const rp = root.headers['referrer-policy'];
      if (rp && /unsafe-url|no-referrer-when-downgrade/i.test(rp)) findings.push(mk('config', 'low', `약한 Referrer-Policy: ${rp}`, ctx.asset.value, '전체 URL(토큰 포함)이 교차출처/평문으로 누출될 수 있습니다.', rp, 'strict-origin-when-cross-origin 으로 변경하십시오.'));
      // 디버그/추적 헤더
      const dbgHeaders = Object.keys(root.headers).filter((h) => /^(x-debug|x-debug-token|x-trace-id|x-request-id|x-correlation-id|x-amzn-trace-id|x-runtime|x-application-context|x-envoy-upstream-service-time|x-backend-server|x-served-by)$/i.test(h));
      if (dbgHeaders.length) findings.push(mk('config', root.headers['x-debug-token-link'] ? 'medium' : 'low', `디버그/추적 헤더 노출: ${dbgHeaders.slice(0, 4).join(', ')}`, ctx.asset.value, '게이트웨이/분산추적/내부 백엔드 식별 정보가 헤더로 노출됩니다.', dbgHeaders.map((h) => `${h}: ${root.headers[h]}`).join('\n').slice(0, 160), '운영에서 디버그/내부 식별 헤더를 제거하십시오.'));
      // 캐시 공유 위험 (인증 응답이 공유캐시에 저장될 신호)
      const xcache = ['x-cache', 'cf-cache-status', 'x-varnish', 'age'].filter((h) => root.headers[h]);
      if (setCookie && xcache.length && /public/i.test(root.headers['cache-control'] || '')) findings.push(mk('config', 'medium', '인증 응답 공유캐시 저장 위험(web cache)', ctx.asset.value, '쿠키 설정 응답이 public 캐시 가능 + 캐시 계층 존재로 사용자별 응답이 공유될 수 있습니다.', `${xcache.join(',')} | cache-control=${root.headers['cache-control']}`, '인증 응답에 Cache-Control: private, no-store 적용.'));

      // ── §3 응답 본문 정보 노출 ──
      const intLeak = scanInternal(root.body, root.headers, ctx.asset.value);
      if (intLeak.length) findings.push(mk('config', 'medium', `응답 내 내부 정보 노출 ${intLeak.length}건(사설IP/내부경로)`, ctx.asset.value, '응답에 사설 IP·서버 절대경로·내부 호스트명이 노출됩니다.', intLeak.slice(0, 6).join('\n'), '에러/응답에서 내부 토폴로지 정보를 제거하십시오.'));
      // HTML/주석 시크릿
      for (const s of scanSecrets(root.body, 'HTML/주석')) findings.push({ ...mk('config', 'critical', `응답 본문 하드코딩 시크릿: ${s.label}`, ctx.asset.value, `HTML/주석에 ${s.label} 로 보이는 시크릿이 노출됩니다.`, `${s.where} → ${s.sample}`, '시크릿 제거 및 즉시 폐기·재발급.'), confidence: 'firm' });
      // 응답 내 JWT 구조 약점
      for (const f of scanJwt(root.body + ' ' + (setCookie || ''), ctx.asset.value)) findings.push(f);

      // ── §6 robots/sitemap 역노출 ──
      const robots = await ctx.guard.httpGet(base + '/robots.txt');
      if (robots && robots.status === 200 && /(^|\n)\s*(dis)?allow:/i.test(robots.body) && !/<html/i.test(robots.body)) {
        const paths = [...robots.body.matchAll(/(?:disallow|allow):\s*(\S+)/gi)].map((m) => m[1]!).filter((p) => /admin|backup|private|internal|config|db|secret|\.git|\.env|old|tmp|test|staging|wp-admin|cgi-bin|server-status|api|upload/i.test(p));
        if (paths.length) findings.push(mk('config', 'low', `robots.txt 가 민감 경로 ${paths.length}건 역노출`, ctx.asset.value, 'robots.txt 의 Disallow 가 오히려 숨기려는(=존재하는) 민감 경로를 알려줍니다.', paths.slice(0, 8).join('\n'), 'robots.txt 로 민감 경로를 노출하지 말고 접근통제를 적용하십시오.'));
      }

      // ── §6 빌드/메타 + 런타임 설정 ──
      for (const p of ['/version.json', '/build-info.json', '/humans.txt', '/env.js', '/config.json', '/runtime-config.json', '/assets/config.json']) {
        const r = await ctx.guard.httpGet(base + p);
        if (r && r.status === 200 && r.body && !isSoft404(r) && !/<html/i.test(r.body)) {
          const sev = /env\.js|config/.test(p) ? 'medium' : 'info';
          findings.push(mk('config', sev as Finding['severity'], `빌드/런타임 설정 노출: ${p}`, ctx.asset.value + p, '버전·빌드·런타임 설정(내부 API/플래그/키)이 노출될 수 있습니다.', r.body.slice(0, 100).replace(/\s+/g, ' '), '운영에서 불필요한 메타/설정 노출을 제거하십시오.'));
          for (const s of scanSecrets(r.body, p)) findings.push({ ...mk('config', 'critical', `설정 파일 하드코딩 시크릿: ${s.label} (${p})`, ctx.asset.value + p, `${p} 에 ${s.label} 로 보이는 시크릿이 노출됩니다.`, s.sample, '시크릿 제거 및 폐기·재발급.'), confidence: 'firm' });
        }
      }

      // ── §6 백업/임시 파생 파일 ──
      for (const f of ['/index.php', '/config.php', '/app.js', '/main.js', '/web.config', '/.env']) {
        for (const ext of ['~', '.bak', '.old', '.save', '.swp']) {
          const r = await ctx.guard.httpGet(base + f + ext);
          if (r && r.status === 200 && r.body && !isSoft404(r) && (/<\?php|=|function|server\.|<configuration/i.test(r.body)) && !/<!doctype html|<html/i.test(r.body.slice(0, 200))) {
            findings.push({ ...mk('config', 'high', `백업/임시 파일 노출: ${f}${ext}`, ctx.asset.value + f + ext, '소스/설정의 백업·임시 사본이 외부에 노출됩니다.', r.body.slice(0, 60).replace(/\s+/g, ' '), '백업/임시 파일을 웹루트에서 제거하십시오.'), confidence: 'firm' });
            break;
          }
        }
      }

      // ── §10 .well-known 표준 리소스 ──
      for (const [p, sev, note] of [['/.well-known/security.txt', 'info', 'security.txt'], ['/.well-known/change-password', 'info', 'change-password'], ['/.well-known/assetlinks.json', 'info', 'Android assetlinks'], ['/.well-known/apple-app-site-association', 'info', 'iOS AASA'], ['/.well-known/nodeinfo', 'info', 'nodeinfo'], ['/.well-known/ai-plugin.json', 'low', 'AI plugin manifest']] as [string, Finding['severity'], string][]) {
        const r = await ctx.guard.httpGet(base + p);
        if (r && r.status === 200 && r.body && !/<html/i.test(r.body.slice(0, 100))) {
          if (/aasa|apple-app/i.test(note) && /applinks|appID|webcredentials/i.test(r.body)) findings.push(mk('config', 'info', `iOS AASA 노출(앱 식별/경로 패턴)`, ctx.asset.value + p, '앱 ID·내부 경로 패턴이 노출됩니다.', r.body.slice(0, 100).replace(/\s+/g, ' '), '의도된 노출인지 확인하십시오.'));
        }
      }
      // JWKS 약한 키
      const jwks = await ctx.guard.httpGet(base + '/.well-known/jwks.json');
      if (jwks && jwks.status === 200 && /"keys"\s*:/.test(jwks.body)) {
        if (/"alg"\s*:\s*"(none|HS\d+)"/i.test(jwks.body)) findings.push(mk('config', 'medium', 'JWKS 약한 alg(none/HS) 노출', ctx.asset.value, 'JWKS 에 none/대칭(HS) 알고리즘이 포함되어 토큰 위조 표면이 됩니다.', jwks.body.slice(0, 120), '비대칭(RS/ES) 서명만 허용하십시오.'));
      }

      // ── §4 인증/세션 ──
      // 로그인 폼 CSRF / 평문 전송
      for (const lp of ['/login', '/signin', '/admin', '/user/login', '/account/login', '/wp-login.php']) {
        const r = await ctx.guard.httpGet(base + lp);
        if (!r || r.status !== 200 || !/<form[^>]*method\s*=\s*["']?post/i.test(r.body)) continue;
        const form = (r.body.match(/<form[\s\S]{0,1200}?<\/form>/i) || [''])[0]!;
        const hasCsrf = /name=["'](csrf|_token|authenticity_token|__RequestVerificationToken|xsrf|_csrf)/i.test(form) || /xsrf-token|csrf-token/i.test(r.headers['set-cookie'] || '') || /<meta[^>]+csrf-token/i.test(r.body);
        if (/type=["']password/i.test(form) && !hasCsrf) findings.push({ ...mk('config', 'medium', `로그인 폼 CSRF 방어 미관측: ${lp}`, ctx.asset.value + lp, 'CSRF 토큰/SameSite 신호가 관측되지 않습니다(SPA 런타임 주입 가능).', lp, 'CSRF 토큰 또는 SameSite=Strict 쿠키를 적용하십시오.'), confidence: 'tentative' });
        const actionHttp = /<form[^>]+action=["']http:\/\//i.test(form);
        if (/type=["']password/i.test(form) && actionHttp) findings.push(mk('config', 'high', `로그인 폼 평문(HTTP) 전송: ${lp}`, ctx.asset.value + lp, '자격증명 폼이 평문 HTTP 로 전송됩니다(도청 위험).', form.match(/action=["']([^"']+)/i)?.[1] || '', '폼 action 을 HTTPS 로 전환하십시오.'));
        break;
      }
      // OIDC discovery 약점
      const oidc = await ctx.guard.httpGet(base + '/.well-known/openid-configuration');
      if (oidc && oidc.status === 200 && /"issuer"|"authorization_endpoint"/.test(oidc.body)) {
        try {
          const j = JSON.parse(oidc.body);
          const w: string[] = [];
          if ((j.token_endpoint_auth_methods_supported || []).includes('none')) w.push('공개클라이언트 무인증(none)');
          if (j.code_challenge_methods_supported && !j.code_challenge_methods_supported.includes('S256')) w.push('PKCE S256 미지원');
          if ((j.response_types_supported || []).some((t: string) => /token/.test(t))) w.push('암묵흐름(implicit) 허용');
          if ((j.grant_types_supported || []).includes('password')) w.push('ROPC(password) 허용');
          if ((j.id_token_signing_alg_values_supported || []).some((a: string) => /none|HS/i.test(a))) w.push('id_token none/HS 서명');
          if (typeof j.jwks_uri === 'string' && j.jwks_uri.startsWith('http://')) w.push('jwks_uri 평문');
          if (w.length) findings.push(mk('config', 'medium', `OIDC 구성 약점: ${w.join(', ')}`, ctx.asset.value, 'OIDC discovery 문서에 위험 설정이 노출됩니다.', w.join(' / '), '공개 흐름 제거, PKCE S256, 비대칭 서명, HTTPS jwks 를 적용하십시오.'));
        } catch { /* */ }
      }

      // ── §5 API ──
      // OpenAPI/Swagger 파싱 → 숨은 엔드포인트/인증 누락
      for (const sp of ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/swagger/v1/swagger.json']) {
        const r = await ctx.guard.httpGet(base + sp);
        if (!r || r.status !== 200 || !/"(openapi|swagger)"\s*:/.test(r.body)) continue;
        try {
          const spec = JSON.parse(r.body);
          const paths = Object.keys(spec.paths || {});
          const adminPaths = paths.filter((p) => /admin|internal|debug|secret|delete|drop/i.test(p));
          findings.push(mk('config', 'medium', `OpenAPI 스펙 공개 — 엔드포인트 ${paths.length}건 노출`, ctx.asset.value + sp, 'API 명세가 공개되어 전체 엔드포인트·파라미터가 드러납니다.', `paths=${paths.length}${adminPaths.length ? ` (관리/위험: ${adminPaths.slice(0, 4).join(', ')})` : ''}`, '운영에서 API 문서 노출을 인증 뒤로 제한하십시오.'));
          if (!spec.security && !spec.components?.securitySchemes) findings.push(mk('config', 'low', 'OpenAPI 전역 보안 정의 부재', ctx.asset.value + sp, '스펙에 보안 스킴이 정의되지 않아 인증 없는 엔드포인트일 수 있습니다.', 'no security/securitySchemes', 'API 인증 스킴을 정의·적용하십시오.'));
        } catch { /* */ }
        break;
      }
      // CORS preflight 과허용
      const pre = await ctx.guard.httpGet(base + '/', { method: 'OPTIONS', headers: { origin: 'https://sentinel-cors-probe.example', 'access-control-request-method': 'DELETE', 'access-control-request-headers': 'authorization,x-custom' } });
      if (pre) {
        const acm = (pre.headers['access-control-allow-methods'] || '').toUpperCase();
        const ah = (pre.headers['access-control-allow-headers'] || '');
        if (/PUT|DELETE|PATCH/.test(acm) && pre.headers['access-control-allow-origin']) findings.push(mk('config', 'medium', `CORS preflight 변경 메서드 과허용: ${acm}`, ctx.asset.value, 'preflight 가 PUT/DELETE/PATCH 등 상태변경 메서드를 교차출처에 허용합니다.', `Allow-Methods=${acm} Allow-Headers=${ah}`, '교차출처 허용 메서드를 최소화하십시오.'));
        if (ah === '*' || /authorization/i.test(ah)) findings.push(mk('config', 'low', 'CORS preflight Authorization 헤더 허용', ctx.asset.value, 'Authorization 등 민감 헤더를 교차출처 요청에 허용합니다.', `Allow-Headers=${ah}`, '허용 헤더를 신뢰 출처·필수 헤더로 제한하십시오.'));
      }
      // GraphQL GET 실행 표면 (비파괴 GET 만; POST 배칭 프로브는 증폭/상태변경 위험으로 제거)
      if (gqlExposed) {
        const get = await ctx.guard.httpGet(base + '/graphql?query=' + encodeURIComponent('{__typename}'));
        if (get && get.status === 200 && /"__typename"|"data"/.test(get.body)) findings.push(mk('config', 'medium', 'GraphQL GET 실행 허용(CSRF 표면)', ctx.asset.value, 'GET 으로 GraphQL 쿼리가 실행되어 CSRF 표면이 됩니다.', get.body.slice(0, 60), 'GET 실행을 비활성화하고 POST+CSRF 보호를 적용하십시오.'));
      }

      // ── §5 WebSocket 노출 단서 ──
      const wsRefs = [...root.body.matchAll(/wss?:\/\/[^"'\s]+|new\s+WebSocket\s*\(/gi)].slice(0, 3);
      if (wsRefs.length) {
        const plain = root.body.match(/ws:\/\/[^"'\s]+/i);
        findings.push(mk('config', plain ? 'medium' : 'info', plain ? 'WebSocket 평문(ws://) 사용' : 'WebSocket 엔드포인트 노출', ctx.asset.value, plain ? '평문 ws:// 연결은 도청·변조에 취약합니다(CSWSH Origin 검증도 확인 필요).' : 'WebSocket 엔드포인트가 식별됩니다. Origin 검증(CSWSH) 적용을 확인하십시오.', (plain ? plain[0] : wsRefs[0]![0]).slice(0, 80), 'wss:// 사용 및 서버측 Origin 검증을 적용하십시오.'));
      }
    }

    // ───── 확장 점검 ─────
    {
      const H = root.headers;
      const csp2 = H['content-security-policy'];
      const cspRO = H['content-security-policy-report-only'];
      const setCookie2 = H['set-cookie'];
      const ct = (H['content-type'] || '').toLowerCase();
      const isHtml = /text\/html/.test(ct) || /<html|<!doctype/i.test(root.body.slice(0, 200));

      // ── 추가 보안 헤더(저비용, 항상 수행) ──
      // 1) Origin-Agent-Cluster 미설정
      if (isHtml && !('origin-agent-cluster' in H)) {
        findings.push({ ...mk('config', 'info', 'Origin-Agent-Cluster 미설정', ctx.asset.value, '오리진 단위 에이전트 클러스터링이 비활성화되어 동일 사이트 문서 간 메모리 격리가 약화됩니다.', 'no Origin-Agent-Cluster', 'Origin-Agent-Cluster: ?1 헤더를 적용하여 오리진 격리를 강화하십시오.'), owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm', references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Origin-Agent-Cluster'] });
      }
      // 2) X-DNS-Prefetch-Control 미설정/허용
      if (H['x-dns-prefetch-control'] && /on/i.test(H['x-dns-prefetch-control'])) {
        findings.push({ ...mk('config', 'info', 'X-DNS-Prefetch-Control: on (프라이버시 누출)', ctx.asset.value, 'DNS 프리페치가 활성화되어 사용자가 따라가지 않은 링크의 호스트까지 DNS 질의가 발생합니다.', `x-dns-prefetch-control: ${H['x-dns-prefetch-control']}`, '민감 페이지에서 X-DNS-Prefetch-Control: off 를 적용하십시오.'), owasp: 'A05:2021', cwe: 'CWE-200', confidence: 'firm' });
      }
      // 3) X-Download-Options 미설정 (IE 레거시지만 IIS 환경 권고)
      if (/microsoft-iis|asp\.net/i.test((H['server'] || '') + (H['x-powered-by'] || '')) && !('x-download-options' in H)) {
        findings.push({ ...mk('config', 'info', 'X-Download-Options 미설정 (IIS/레거시)', ctx.asset.value, 'IE 계열에서 다운로드 파일이 사이트 컨텍스트로 직접 열려 저장형 XSS 표면이 될 수 있습니다.', 'no X-Download-Options', 'X-Download-Options: noopen 을 적용하십시오.'), owasp: 'A05:2021', cwe: 'CWE-79', confidence: 'tentative' });
      }
      // 4) Document-Policy 부재(고성능/격리 정책 미사용) — 정보성
      if (isHtml && (H['cross-origin-embedder-policy'] || H['cross-origin-opener-policy']) && !('document-policy' in H)) {
        findings.push({ ...mk('config', 'info', 'Document-Policy 미설정', ctx.asset.value, '교차출처 격리 헤더는 있으나 Document-Policy 로 위험 기능(document.write, unsized-media 등) 제한이 없습니다.', 'no Document-Policy', "Document-Policy 로 'document-write', 'unsized-media' 등을 제한하십시오."), owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'tentative' });
      }
      // 5) Clear-Site-Data 오남용 (일반 200 응답에 광범위 지정)
      if (H['clear-site-data'] && root.status === 200 && /\*|"cache"/.test(H['clear-site-data'])) {
        findings.push({ ...mk('config', 'low', 'Clear-Site-Data 오남용 (일반 응답에 광범위 지정)', ctx.asset.value, '로그아웃 외 일반 응답에서 Clear-Site-Data 가 광범위(*/cache)하게 설정되면 가용성/UX 문제 및 의도치 않은 상태 삭제가 발생합니다.', `clear-site-data: ${H['clear-site-data']}`, 'Clear-Site-Data 는 로그아웃 등 특정 엔드포인트에서 필요한 유형만 지정하십시오.'), owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm' });
      }
      // 6) COEP 단독 누락(격리 페이지 단서가 있을 때) — SECURITY_HEADERS 미포함이라 신규
      if (isHtml && H['cross-origin-opener-policy'] === 'same-origin' && !('cross-origin-embedder-policy' in H) && !findings.some((f) => f.title.includes('COEP'))) {
        findings.push({ ...mk('config', 'info', 'Cross-Origin-Embedder-Policy(COEP) 누락', ctx.asset.value, 'COOP: same-origin 이 설정됐으나 COEP 가 없어 crossOriginIsolated 가 미달성되어 고정밀 타이머/SharedArrayBuffer 보호가 불완전합니다.', 'no Cross-Origin-Embedder-Policy', 'Cross-Origin-Embedder-Policy: require-corp 를 적용하십시오.'), owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm' });
      }
      // 7) 민감(쿠키 설정) 응답 Cache-Control 누락 — no-store/private 둘 다 없음
      if (setCookie2 && !('cache-control' in H) && !('pragma' in H)) {
        findings.push({ ...mk('config', 'low', '민감 응답 Cache-Control 헤더 전무', ctx.asset.value, '세션 쿠키를 설정하는 응답에 Cache-Control 자체가 없어 중간 캐시가 임의 정책으로 저장할 수 있습니다.', 'set-cookie present, no Cache-Control', '인증/민감 응답에 Cache-Control: no-store 를 명시하십시오.'), owasp: 'A05:2021', cwe: 'CWE-525', confidence: 'firm' });
      }

      // ── CSP 추가 약점 (존재 시, 저비용) ──
      const cspText = csp2 || '';
      if (cspText && /script-src/.test(cspText)) {
        const scriptSrc = (cspText.match(/script-src[^;]*/i) || [''])[0]!;
        const cspWeak: string[] = [];
        if (!/'nonce-|'sha(256|384|512)-/.test(cspText)) cspWeak.push('nonce/해시 미사용');
        if (!/'strict-dynamic'/.test(cspText)) cspWeak.push("'strict-dynamic' 미사용");
        if (/(^|\s)https?:(\s|;|$)/.test(scriptSrc) || /\bhttp:\/\//.test(scriptSrc)) cspWeak.push('http(s): 스킴 광범위 출처');
        if (/'self'/.test(scriptSrc) && /data:/.test(scriptSrc)) cspWeak.push('script-src data: 허용');
        if (cspWeak.length) {
          findings.push({ ...mk('config', 'low', `CSP script-src 추가 약점: ${cspWeak.join(', ')}`, ctx.asset.value, 'CSP 가 있으나 script-src 가 nonce/strict-dynamic 없이 광범위 출처를 허용하여 우회 가능성이 있습니다.', scriptSrc.slice(0, 160), "nonce + 'strict-dynamic' 기반 정책으로 전환하고 스킴 출처를 제거하십시오."), owasp: 'A05:2021', cwe: 'CWE-1021', confidence: 'firm' });
        }
      }
      // CSP report-only 만 있고 enforce 없음
      if (cspRO && !csp2) {
        findings.push({ ...mk('config', 'low', 'CSP가 Report-Only 전용 (강제 미적용)', ctx.asset.value, 'Content-Security-Policy-Report-Only 만 존재하여 위반이 보고만 되고 차단되지 않습니다.', cspRO.slice(0, 120), '검증 완료 후 Content-Security-Policy(강제)로 승격하십시오.'), owasp: 'A05:2021', cwe: 'CWE-693', confidence: 'firm' });
      }
      // CSP report-uri/report-to 없음 (모니터링 부재)
      if (csp2 && !/report-uri|report-to/i.test(csp2)) {
        findings.push({ ...mk('config', 'info', 'CSP 위반 보고 대상 미설정', ctx.asset.value, 'CSP 에 report-uri/report-to 가 없어 위반 시도를 수집·가시화할 수 없습니다.', csp2.slice(0, 120), 'report-to 지시문과 Reporting-Endpoints 를 설정하십시오.'), owasp: 'A09:2021', cwe: 'CWE-778', confidence: 'firm' });
      }
      // CSP frame-ancestors 와일드카드/광범위
      if (csp2 && /frame-ancestors[^;]*(\*|https?:)/i.test(csp2)) {
        findings.push({ ...mk('config', 'low', 'CSP frame-ancestors 광범위 허용', ctx.asset.value, 'frame-ancestors 에 * 또는 스킴 출처가 있어 클릭재킹 방어가 무력화됩니다.', (csp2.match(/frame-ancestors[^;]*/i) || [''])[0]!.slice(0, 120), "frame-ancestors 를 'self' 또는 신뢰 출처로 제한하십시오."), owasp: 'A05:2021', cwe: 'CWE-1021', confidence: 'firm' });
      }
      // upgrade-insecure-requests 미적용(HTTPS 사이트)
      if (csp2 && ctx.asset.type !== 'host' && !/upgrade-insecure-requests/i.test(csp2)) {
        findings.push({ ...mk('config', 'info', 'CSP upgrade-insecure-requests 미적용', ctx.asset.value, 'HTTPS 사이트의 CSP 에 upgrade-insecure-requests 가 없어 평문 하위 리소스가 차단되지 않습니다.', csp2.slice(0, 100), 'CSP 에 upgrade-insecure-requests 를 추가하십시오.'), owasp: 'A05:2021', cwe: 'CWE-319', confidence: 'firm' });
      }

      // ── 쿠키 추가 분석 (저비용) ──
      if (setCookie2) {
        for (const cookie of setCookie2.split(/,(?=[^;]+=)/)) {
          const name = (cookie.split('=')[0] || '').trim();
          const lc = cookie.toLowerCase();
          // SameSite=None 인데 Secure 없음
          if (/samesite\s*=\s*none/.test(lc) && !/(^|;|\s)secure(;|$|\s)/.test(lc)) {
            findings.push({ ...mk('config', 'medium', `쿠키 SameSite=None + Secure 누락: ${name || '(이름없음)'}`, ctx.asset.value, 'SameSite=None 쿠키는 Secure 가 필수이며, 없으면 최신 브라우저가 거부하거나 평문 전송됩니다.', cookie.slice(0, 120), 'SameSite=None 쿠키에는 반드시 Secure 를 함께 지정하십시오.'), owasp: 'A05:2021', cwe: 'CWE-1275', confidence: 'firm' });
          }
          // 과도한 만료 (Max-Age 1년 초과 또는 먼 Expires)
          const maxAgeM = lc.match(/max-age\s*=\s*(\d+)/);
          if (maxAgeM && maxAgeM[1] && Number(maxAgeM[1]) > 34560000) {
            findings.push({ ...mk('config', 'info', `쿠키 과도한 만료(Max-Age ${maxAgeM[1]}): ${name || '(이름없음)'}`, ctx.asset.value, '쿠키 수명이 비정상적으로 길어(>400일) 탈취 시 장기 악용 위험이 있습니다.', cookie.slice(0, 120), '세션/인증 쿠키의 수명을 최소화하고 정기 회전하십시오.'), owasp: 'A05:2021', cwe: 'CWE-613', confidence: 'tentative' });
          }
          // 광범위 Domain (선행 점 + 짧은 등록 도메인) — 휴리스틱
          const domM = lc.match(/domain\s*=\s*\.?([^;]+)/);
          if (domM && domM[1] && domM[1].trim().split('.').length <= 2 && !/localhost/.test(domM[1])) {
            findings.push({ ...mk('config', 'info', `쿠키 광범위 Domain 지정: ${name || '(이름없음)'}`, ctx.asset.value, '등록 도메인 전체로 쿠키 범위가 넓어 하위 모든 서브도메인(잠재적 취약 호스트 포함)으로 전송됩니다.', cookie.slice(0, 120), '쿠키 Domain 을 필요한 호스트로 최소화하십시오.'), owasp: 'A05:2021', cwe: 'CWE-565', confidence: 'tentative' });
          }
          // __Secure- 접두 규칙 위반 (Secure 없음)
          if (name.startsWith('__Secure-') && !/(^|;|\s)secure(;|$|\s)/.test(lc)) {
            findings.push({ ...mk('config', 'medium', `__Secure- 쿠키 규칙 위반: ${name}`, ctx.asset.value, '__Secure- 접두 쿠키는 Secure 속성이 필수이나 누락되어 브라우저가 거부합니다.', cookie.slice(0, 120), '__Secure- 쿠키에 Secure 속성을 적용하십시오.'), owasp: 'A05:2021', cwe: 'CWE-1275', confidence: 'firm' });
          }
        }
      }

      // ── CORS 추가: Vary:Origin 부재 (앞 단계에서 ACAO 반사/동적 신호가 있을 때) ──
      const sawCors = findings.some((f) => f.title.includes('CORS'));
      const varyH = (H['vary'] || '').toLowerCase();
      if (sawCors && !varyH.includes('origin')) {
        findings.push({ ...mk('config', 'low', 'CORS 동적 Origin인데 Vary: Origin 부재', ctx.asset.value, 'Origin 별로 ACAO 가 달라지는데 Vary: Origin 이 없어 공유 캐시가 한 Origin 의 CORS 응답을 다른 Origin 에 제공할 수 있습니다(캐시 포이즈닝).', `vary=${H['vary'] || '(없음)'}`, '동적 CORS 응답에는 Vary: Origin 을 반드시 추가하십시오.'), owasp: 'A05:2021', cwe: 'CWE-525', confidence: 'firm' });
      }

      // ── 기술스택 핑거프린트 → 버전 노출 지적 (저비용, 헤더/쿠키/본문) ──
      const fpBlob = [H['server'] || '', H['x-powered-by'] || '', H['x-generator'] || '', H['x-aspnet-version'] || '', H['x-drupal-cache'] || '', setCookie2 || '', root.body.slice(0, 4000)].join('\n');
      for (const fr of STACK_FINGERPRINTS) {
        const fm = fr.re.exec(fpBlob);
        if (fm) {
          const ver = fm[1];
          findings.push({ ...mk('config', ver ? 'low' : 'info', ver ? `기술스택 버전 노출: ${fr.name} ${ver}` : `기술스택 지문: ${fr.name}`, ctx.asset.value, ver ? `${fr.name} ${ver} 버전이 노출되어 알려진 취약점 매칭·표적 공격에 활용될 수 있습니다.` : `${fr.name} 사용이 식별됩니다.`, fm[0].slice(0, 80), ver ? '제품·버전 식별 정보를 헤더/메타에서 제거하거나 일반화하십시오.' : '불필요한 기술 식별 신호를 제거하십시오.'), owasp: 'A05:2021', cwe: 'CWE-200', confidence: ver ? 'firm' : 'tentative' });
        }
      }
      // 메타 generator 버전 노출 (WordPress 등)
      const genMeta = root.body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
      if (genMeta && genMeta[1] && /\d/.test(genMeta[1])) {
        findings.push({ ...mk('config', 'low', `메타 generator 버전 노출: ${genMeta[1].slice(0, 60)}`, ctx.asset.value, 'HTML meta generator 태그가 CMS/프레임워크 버전을 노출합니다.', genMeta[1].slice(0, 80), 'generator 메타 태그를 제거하십시오.'), owasp: 'A05:2021', cwe: 'CWE-200', confidence: 'confirmed' });
      }
    }

    if (ctx.deep) {
      // ── WebDAV/추가 메서드 (OPTIONS 로만 확인, 비파괴) ──
      const opt2 = await ctx.guard.httpGet(base + '/', { method: 'OPTIONS' });
      const allow2 = ((opt2?.headers['allow'] || '') + ' ' + (opt2?.headers['dav'] || '')).toUpperCase();
      const davMethods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'].filter((m) => allow2.includes(m));
      if (davMethods.length || (opt2 && 'dav' in opt2.headers)) {
        findings.push({ ...mk('config', 'medium', `WebDAV 활성 신호: ${davMethods.join(', ') || 'DAV 헤더'}`, ctx.asset.value, 'WebDAV 메서드/DAV 헤더가 노출되어 파일 조작·업로드 표면이 될 수 있습니다.', `Allow/DAV: ${allow2.slice(0, 120)}`, '불필요하면 WebDAV 모듈을 비활성화하고 인증·경로를 제한하십시오.'), owasp: 'A05:2021', cwe: 'CWE-650', confidence: 'firm' });
      }
      if (allow2.includes('TRACK') && !findings.some((f) => f.title.includes('위험 HTTP 메서드'))) {
        findings.push({ ...mk('config', 'low', 'HTTP TRACK 메서드 허용', ctx.asset.value, 'TRACK(MS 변형 TRACE)이 허용되어 XST 표면이 될 수 있습니다.', `Allow: ${allow2.slice(0, 80)}`, 'TRACK/TRACE 메서드를 비활성화하십시오.'), owasp: 'A05:2021', cwe: 'CWE-693', confidence: 'firm' });
      }

      // ── 캐시 디셉션 표면 (확장자 붙인 경로가 200 + 캐시가능 헤더) ──
      const deceptionPath = '/sentinel-cache-decept-' + Math.random().toString(36).slice(2) + '.css';
      const dec = await ctx.guard.httpGet(base + deceptionPath);
      if (dec && dec.status === 200 && !isSoft404(dec)) {
        const cc = (dec.headers['cache-control'] || '').toLowerCase();
        const cacheable = (dec.headers['x-cache'] || dec.headers['cf-cache-status'] || dec.headers['age']) && !/no-store|private/.test(cc);
        if (cacheable || /public|max-age=[1-9]/.test(cc)) {
          findings.push({ ...mk('config', 'medium', '웹 캐시 디셉션 표면 (확장자 경로가 캐시가능 동적응답)', ctx.asset.value, '존재하지 않는 .css 확장자 경로가 200 으로 동적 응답되며 캐시 가능하여, 인증 페이지를 정적자원처럼 캐시에 저장·유출시키는 캐시 디셉션 표면이 됩니다.', `path=${deceptionPath} status=200 cache-control=${dec.headers['cache-control'] || '-'} x-cache=${dec.headers['x-cache'] || dec.headers['cf-cache-status'] || '-'}`, '확장자가 라우팅을 우회하지 못하게 하고, 동적 응답을 정적 확장자로 캐시하지 마십시오.'), owasp: 'A05:2021', cwe: 'CWE-525', confidence: 'tentative' });
        }
      }

      // ── 추가 민감 파일/경로 (콘텐츠 시그니처 + soft-404 가드) ──
      for (const p of EXTRA_SENSITIVE_PATHS) {
        const r = await ctx.guard.httpGet(base + p.path);
        if (!r || r.status !== 200 || !r.body) continue;
        if (isSoft404(r)) continue;
        if (/<html|<!doctype html/i.test(r.body.slice(0, 200)) && !p.allowHtml) continue;
        if (!p.sig(r.body)) continue;
        findings.push({ ...mk('config', p.severity, p.title, ctx.asset.value + p.path, '소스/설정/민감 정보가 외부에 노출되어 있습니다.', `status=200, sig=match, ${r.body.slice(0, 60).replace(/\s+/g, ' ')}`, p.remediation), owasp: p.owasp, cwe: p.cwe, confidence: 'confirmed' });
      }

      // ── sitemap.xml 내 민감 경로 역노출 ──
      const sitemap = await ctx.guard.httpGet(base + '/sitemap.xml');
      if (sitemap && sitemap.status === 200 && /<urlset|<sitemapindex|<loc>/i.test(sitemap.body)) {
        const locs = [...sitemap.body.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)].map((m) => m[1]!);
        const sensitive = locs.filter((u) => /admin|internal|private|backup|config|staging|test|dev|secret|api\/|wp-admin|phpmyadmin|debug/i.test(u)).slice(0, 8);
        if (sensitive.length) {
          findings.push({ ...mk('config', 'low', `sitemap.xml 민감 경로 ${sensitive.length}건 역노출`, ctx.asset.value, 'sitemap.xml 이 관리/내부/스테이징 경로를 색인 대상으로 노출합니다.', sensitive.join('\n').slice(0, 200), 'sitemap 에서 비공개 경로를 제거하고 접근통제를 적용하십시오.'), owasp: 'A01:2021', cwe: 'CWE-200', confidence: 'firm' });
        }
      }

      // ── security.txt 품질(존재 시) ──
      const sectxt2 = await ctx.guard.httpGet(base + '/.well-known/security.txt');
      if (sectxt2 && sectxt2.status === 200 && /contact:/i.test(sectxt2.body)) {
        const sissues: string[] = [];
        if (!/expires:/i.test(sectxt2.body)) sissues.push('Expires 필드 부재(RFC 9116 위반)');
        const expM = sectxt2.body.match(/expires:\s*([^\r\n]+)/i);
        if (expM && expM[1]) { const exp = Date.parse(expM[1].trim()); if (!Number.isNaN(exp) && exp < Date.now()) sissues.push('Expires 만료됨'); }
        if (/contact:\s*http:\/\//i.test(sectxt2.body)) sissues.push('Contact 평문 HTTP');
        if (!/encryption:/i.test(sectxt2.body)) sissues.push('Encryption(PGP) 키 부재');
        if (!/-----BEGIN PGP SIGNATURE-----/.test(sectxt2.body)) sissues.push('PGP 서명 부재');
        if (sissues.length) {
          findings.push({ ...mk('config', 'info', `security.txt 품질 미흡: ${sissues.join(', ')}`, ctx.asset.value, 'security.txt 가 존재하나 RFC 9116 권고(Expires/서명/암호화 등)를 충족하지 못합니다.', sissues.join(' / '), 'Expires(미래)·Encryption·PGP 서명을 포함하고 Contact 를 HTTPS/mailto 로 지정하십시오.'), owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm' });
        }
      }

      // ── 추가 .well-known 리소스 노출 ──
      for (const wk of EXTRA_WELLKNOWN) {
        const r = await ctx.guard.httpGet(base + wk.path);
        if (!r || r.status !== 200 || !r.body) continue;
        if (/<html/i.test(r.body.slice(0, 100))) continue;
        if (!wk.sig(r.body)) continue;
        findings.push({ ...mk('config', wk.severity, wk.title, ctx.asset.value + wk.path, wk.desc, r.body.slice(0, 100).replace(/\s+/g, ' '), wk.remediation), owasp: 'A05:2021', cwe: 'CWE-200', confidence: 'firm' });
      }

      // ── 디렉터리 리스팅 노출 ──
      for (const dp of ['/uploads/', '/files/', '/images/', '/static/', '/assets/', '/backup/']) {
        const r = await ctx.guard.httpGet(base + dp);
        if (r && r.status === 200 && /<title>Index of|Directory listing for|\[To Parent Directory\]/i.test(r.body)) {
          findings.push({ ...mk('config', 'medium', `디렉터리 리스팅 노출: ${dp}`, ctx.asset.value + dp, '디렉터리 자동 색인이 켜져 있어 파일 목록이 그대로 노출됩니다.', r.body.slice(0, 80).replace(/\s+/g, ' '), '웹서버에서 디렉터리 자동 색인(autoindex/Options Indexes)을 비활성화하십시오.'), owasp: 'A05:2021', cwe: 'CWE-548', confidence: 'confirmed' });
          break;
        }
      }
    }

    return findings;
  },
};

/** 응답 본문/헤더의 내부 정보(사설IP/절대경로/내부호스트) 추출. */
function scanInternal(body: string, headers: Record<string, string>, selfHost: string): string[] {
  const hits: string[] = [];
  const text = body.slice(0, 60_000) + ' ' + ['location', 'x-backend-server', 'x-served-by', 'x-real-ip', 'via'].map((h) => headers[h] || '').join(' ');
  for (const m of text.matchAll(/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/g)) {
    if (m[1] && !m[1].includes(selfHost)) hits.push(`사설IP: ${m[1]}`);
    if (hits.length > 8) break;
  }
  for (const m of text.matchAll(/(\/var\/www\/[^\s"'<]+|\/home\/[\w.-]+\/[^\s"'<]+|C:\\(?:inetpub|Users|xampp)\\[^\s"'<]+|\/srv\/[^\s"'<]+)/g)) { hits.push(`경로: ${m[1]!.slice(0, 60)}`); if (hits.length > 12) break; }
  for (const m of text.matchAll(/\b[\w-]+\.(?:internal|local|corp|svc\.cluster\.local)\b/g)) { hits.push(`내부호스트: ${m[0]}`); if (hits.length > 16) break; }
  return [...new Set(hits)];
}

/** 본문/쿠키 내 JWT 추출·구조 약점 판정. */
function scanJwt(text: string, selfHost: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]*)/g)) {
    const tok = m[0]!; if (seen.has(tok) || seen.size > 3) continue; seen.add(tok);
    try {
      const header = JSON.parse(Buffer.from(tok.split('.')[0]!, 'base64url').toString('utf8'));
      const payload = JSON.parse(Buffer.from(tok.split('.')[1]!, 'base64url').toString('utf8'));
      if (String(header.alg).toLowerCase() === 'none' || !m[1]) out.push({ ...mk('config', 'high', 'JWT alg:none/서명없음(위조 가능)', selfHost, '응답에 노출된 JWT 가 서명이 없어 위조 가능합니다.', `alg=${header.alg}`, 'alg 를 서버에서 고정 검증하고 none 을 거부하십시오.'), confidence: 'firm' });
      else if (/^HS/i.test(String(header.alg))) out.push(mk('config', 'medium', `JWT 대칭키 서명(${header.alg})`, selfHost, '대칭키(HS) 서명은 키 유출 시 위조가 가능합니다.', `alg=${header.alg}`, '비대칭(RS/ES) 서명을 사용하십시오.'));
      if (!payload.exp) out.push(mk('config', 'medium', 'JWT 만료(exp) 부재(영구 토큰)', selfHost, '노출된 JWT 에 만료가 없어 탈취 시 영구 사용됩니다.', 'no exp', 'exp 를 설정하십시오.'));
      if (payload.password || payload.is_admin || payload.role || payload.ssn) out.push(mk('config', 'info', 'JWT 페이로드 민감 클레임 평문', selfHost, 'JWT payload 는 누구나 디코드 가능하므로 민감 정보를 담지 마십시오.', Object.keys(payload).filter((k) => /password|admin|role|ssn/.test(k)).join(','), '민감 클레임을 제거하십시오.'));
    } catch { /* JWT 아님 */ }
  }
  return out;
}

/** 심층 점검 전용 추가 민감 경로 (콘텐츠 검증). */
const DEEP_PATHS: PathRule[] = [
  { path: '/.env.local', title: '.env.local 노출', severity: 'critical', sig: (b) => /=/.test(b) && !/<html/i.test(b), remediation: '외부 접근 차단 및 비밀키 교체' },
  { path: '/.env.production', title: '.env.production 노출', severity: 'critical', sig: (b) => /=/.test(b) && !/<html/i.test(b), remediation: '외부 접근 차단 및 비밀키 교체' },
  { path: '/docker-compose.yml', title: 'docker-compose.yml 노출', severity: 'high', sig: (b) => /services:|image:|version:/.test(b), remediation: '배포 산출물에서 제외' },
  { path: '/.gitlab-ci.yml', title: 'CI 설정(.gitlab-ci.yml) 노출', severity: 'medium', sig: (b) => /stages:|script:/.test(b), remediation: 'CI 설정 외부 노출 차단' },
  { path: '/.npmrc', title: '.npmrc(토큰 가능) 노출', severity: 'high', sig: (b) => /_authToken|registry=/.test(b), remediation: '차단 및 노출 토큰 폐기' },
  { path: '/id_rsa', title: 'SSH 개인키 노출', severity: 'critical', sig: (b) => /PRIVATE KEY/.test(b), remediation: '즉시 차단 및 키 폐기·재발급' },
  { path: '/web.config', title: 'IIS web.config 노출', severity: 'high', sig: (b) => /<configuration|<system\.webServer/.test(b), remediation: 'web.config 외부 접근 차단' },
  { path: '/appsettings.json', title: '.NET appsettings.json 노출', severity: 'high', sig: (b) => /ConnectionStrings|"Logging"/.test(b), remediation: '설정 파일 외부 접근 차단' },
  { path: '/composer.lock', title: 'composer.lock 노출', severity: 'low', sig: (b) => /"packages"|"content-hash"/.test(b), remediation: '의존성 잠금 파일 노출 검토' },
  { path: '/yarn.lock', title: 'yarn.lock 노출', severity: 'low', sig: (b) => /# yarn lockfile|resolved "/.test(b), remediation: '의존성 잠금 파일 노출 검토' },
  { path: '/.git/logs/HEAD', title: '.git 커밋 로그 노출', severity: 'high', sig: (b) => /commit|checkout:/.test(b), remediation: '.git 외부 접근 차단' },
  { path: '/trace.axd', title: 'ASP.NET trace.axd 노출', severity: 'medium', sig: (b) => /Application Trace|Request Details/i.test(b), remediation: 'trace 비활성화' },
  { path: '/elmah.axd', title: 'ELMAH 오류 로그 노출', severity: 'high', sig: (b) => /Error Log for|ELMAH/i.test(b), remediation: 'ELMAH 접근 제한' },
  { path: '/crossdomain.xml', title: 'crossdomain.xml 와일드카드', severity: 'low', sig: (b) => /allow-access-from domain="\*"/.test(b), remediation: '교차 도메인 정책을 신뢰 도메인으로 제한' },
  { path: '/.vscode/settings.json', title: '.vscode 설정 노출', severity: 'low', sig: (b) => /"[\w.]+":/.test(b) && !/<html/i.test(b), remediation: '.vscode 디렉터리 배포 제외' },
  { path: '/.idea/workspace.xml', title: 'JetBrains .idea 노출', severity: 'low', sig: (b) => /<project|<component/.test(b), remediation: '.idea 디렉터리 배포 제외' },
  { path: '/.bash_history', title: '.bash_history 노출', severity: 'high', sig: (b) => /\b(cd|ls|export|sudo|ssh|curl|git)\b/.test(b) && !/<html/i.test(b), remediation: '셸 히스토리 파일 제거·차단' },
  { path: '/.netrc', title: '.netrc 자격증명 노출', severity: 'critical', sig: (b) => /machine\s+\S+\s+login/.test(b), remediation: '차단 및 자격증명 폐기' },
  { path: '/.pgpass', title: 'PostgreSQL .pgpass 노출', severity: 'critical', sig: (b) => /:\d{2,5}:.*:.*:/.test(b) && !/<html/i.test(b), remediation: '차단 및 DB 비밀번호 교체' },
  { path: '/.docker/config.json', title: 'Docker 레지스트리 자격증명 노출', severity: 'critical', sig: (b) => /"auths"/.test(b), remediation: '차단 및 레지스트리 토큰 폐기' },
  { path: '/.kube/config', title: 'Kubernetes kubeconfig 노출', severity: 'critical', sig: (b) => /apiVersion:|clusters:|client-key-data/.test(b), remediation: '차단 및 클러스터 자격증명 교체' },
  { path: '/terraform.tfstate', title: 'Terraform state 노출', severity: 'critical', sig: (b) => /"terraform_version"|"resources"/.test(b), remediation: 'tfstate 를 원격 백엔드로 이전·차단' },
  { path: '/credentials.json', title: 'GCP 서비스계정 키 노출', severity: 'critical', sig: (b) => /"private_key_id"|"private_key"/.test(b), remediation: '차단 및 서비스계정 키 폐기' },
  { path: '/dump.sql', title: 'DB 덤프(dump.sql) 노출', severity: 'critical', sig: (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b), remediation: 'DB 덤프 제거·차단' },
  { path: '/WEB-INF/web.xml', title: 'Java web.xml 노출', severity: 'high', sig: (b) => /<web-app|<servlet/.test(b), remediation: 'WEB-INF 외부 접근 차단' },
  { path: '/server.key', title: 'TLS 개인키(server.key) 노출', severity: 'critical', sig: (b) => /PRIVATE KEY/.test(b), remediation: '즉시 차단 및 인증서·키 재발급' },
];

/** 시크릿 정규식 (HTML/JS/JSON 공통, 플레이스홀더 제외). */
const SECRET_RULES: [RegExp, string][] = [
  [/AKIA[0-9A-Z]{16}/, 'AWS Access Key'],
  [/sk_live_[0-9a-zA-Z]{16,}/, 'Stripe Secret Key'],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/, 'Slack Token'],
  [/AIza[0-9A-Za-z_\-]{35}/, 'Google API Key'],
  [/gh[pousr]_[0-9A-Za-z]{30,}/, 'GitHub Token'],
  [/github_pat_[0-9A-Za-z_]{60,}/, 'GitHub Fine-grained PAT'],
  [/glpat-[0-9A-Za-z_-]{20}/, 'GitLab Token'],
  [/npm_[A-Za-z0-9]{36}/, 'npm Token'],
  [/SG\.[\w-]{22}\.[\w-]{43}/, 'SendGrid Key'],
  [/SK[0-9a-f]{32}/, 'Twilio Key'],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/, 'JWT'],
  [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'Private Key'],
  [/(?:aws_secret_access_key|secret_access_key)["'\s:=]+[A-Za-z0-9/+]{40}/i, 'AWS Secret Key'],
];
function scanSecrets(text: string, where: string): { label: string; where: string; sample: string }[] {
  const out: { label: string; where: string; sample: string }[] = [];
  for (const [re, label] of SECRET_RULES) {
    const m = re.exec(text);
    if (m && !/CHANGEME|xxxx|example|placeholder|YOUR_|<.*>|\$\{/i.test(m[0])) out.push({ label, where, sample: m[0].slice(0, 10) + '…' });
  }
  return out;
}

/** 기술스택 핑거프린트 — 헤더/쿠키/본문에서 제품(및 버전) 식별. 캡처그룹 1=버전(선택). */
const STACK_FINGERPRINTS: { name: string; re: RegExp }[] = [
  { name: 'WordPress', re: /wp-content|wordpress\s*([\d.]+)?/i },
  { name: 'Drupal', re: /(?:x-drupal|Drupal)\s*[\/ ]?([\d.]+)?/i },
  { name: 'Joomla', re: /joomla!?\s*([\d.]+)?/i },
  // Express: 'express' 단어는 일반 본문에 흔하므로 X-Powered-By 헤더 또는 connect.sid 쿠키 앵커로만 식별(오탐 억제).
  { name: 'Express', re: /x-powered-by:\s*express(?:[\/ ]([\d.]+))?|(?:^|\n|;|\s)connect\.sid=/i },
  { name: 'Next.js', re: /(?:x-powered-by:\s*)?Next\.js\s*([\d.]+)?/i },
  { name: 'Nuxt', re: /__NUXT__|nuxt\s*([\d.]+)?/i },
  { name: 'Laravel', re: /laravel_session|Laravel\s*([\d.]+)?/i },
  // Django: 'csrftoken' 문자열은 다른 앱 JS 에도 흔하므로 쿠키 토큰(csrftoken=) 또는 명시적 'Django' 버전 문자열만 인정.
  { name: 'Django', re: /(?:^|\n|;|\s)csrftoken=|Django\s*([\d.]+)?/i },
  // Rails: '_session_id' 부분일치는 오탐이 많으므로 쿠키 토큰(_session_id=) 경계 또는 명시 제품명만 인정.
  { name: 'Rails', re: /(?:^|\n|;|\s)_session_id=|Ruby on Rails|Phusion Passenger\s*([\d.]+)?/i },
  { name: 'ASP.NET', re: /ASP\.NET(?:\s+Version:?\s*([\d.]+))?/i },
  { name: 'Tomcat', re: /Apache Tomcat\/?([\d.]+)?/i },
  { name: 'Jetty', re: /Jetty\(?([\d.]+)?\)?/i },
  { name: 'Gunicorn', re: /gunicorn\/?([\d.]+)?/i },
  { name: 'Werkzeug', re: /Werkzeug\/?([\d.]+)?/i },
  { name: 'WordPress WooCommerce', re: /woocommerce(?:[-/ ]([\d.]+))?/i },
];

interface ExtraPathRule { path: string; title: string; severity: Finding['severity']; sig: (b: string) => boolean; remediation: string; owasp?: string; cwe?: string; allowHtml?: boolean; }
/** 확장 민감 파일/경로 — 콘텐츠 시그니처 + soft-404 가드(deep 전용, SENSITIVE/DEEP_PATHS 와 비중복). */
const EXTRA_SENSITIVE_PATHS: ExtraPathRule[] = [
  { path: '/.pypirc', title: '.pypirc(PyPI 자격증명) 노출', severity: 'high', sig: (b) => /\[(pypi|distutils)\]|username\s*=|password\s*=/i.test(b), remediation: '차단 및 PyPI 토큰 폐기·재발급', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/.dockerignore', title: '.dockerignore 노출', severity: 'info', sig: (b) => /(^|\n)\s*(node_modules|\.git|\*)/.test(b) && !/<html/i.test(b), remediation: '배포 산출물에서 제외', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/Dockerfile', title: 'Dockerfile 노출', severity: 'medium', sig: (b) => /^\s*(FROM|RUN|COPY|ENV|CMD|ENTRYPOINT)\b/im.test(b), remediation: 'Dockerfile 을 웹루트에서 제거', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.github/workflows/ci.yml', title: 'GitHub Actions 워크플로 노출', severity: 'medium', sig: (b) => /(^|\n)\s*(on:|jobs:|runs-on:|steps:)/.test(b), remediation: 'CI 워크플로 노출 차단 및 시크릿 점검', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/application.properties', title: 'Spring application.properties 노출', severity: 'high', sig: (b) => /spring\.|server\.port|datasource|jdbc:/i.test(b), remediation: '설정 파일 외부 접근 차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/application.yml', title: 'Spring application.yml 노출', severity: 'high', sig: (b) => /spring:|datasource:|jdbc:|server:/i.test(b) && !/<html/i.test(b), remediation: '설정 파일 외부 접근 차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/secrets.yaml', title: 'secrets.yaml 노출', severity: 'critical', sig: (b) => /(password|secret|token|api[_-]?key)\s*:/i.test(b) && !/<html/i.test(b), remediation: '즉시 차단 및 노출 시크릿 폐기', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/.terraform/terraform.tfstate', title: 'Terraform 작업 디렉터리 state 노출', severity: 'critical', sig: (b) => /"terraform_version"|"resources"/.test(b), remediation: '원격 백엔드 이전 및 접근 차단', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/.ansible/hosts', title: 'Ansible 인벤토리 노출', severity: 'medium', sig: (b) => /\[[\w-]+\]|ansible_host|ansible_user/i.test(b) && !/<html/i.test(b), remediation: 'IaC 산출물을 웹루트에서 제거', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.ssh/id_rsa', title: '.ssh/id_rsa 개인키 노출', severity: 'critical', sig: (b) => /PRIVATE KEY/.test(b), remediation: '즉시 차단 및 SSH 키 폐기·교체', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/.ssh/authorized_keys', title: '.ssh/authorized_keys 노출', severity: 'high', sig: (b) => /ssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/]/.test(b), remediation: '차단하고 허용 키를 점검·회전하십시오.', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.vscode/sftp.json', title: '.vscode/sftp.json(배포 자격증명) 노출', severity: 'critical', sig: (b) => /"host"|"username"|"password"|"privateKeyPath"/i.test(b), remediation: '차단 및 배포 자격증명 교체', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/php.ini', title: 'php.ini 노출', severity: 'medium', sig: (b) => /\[PHP\]|display_errors|allow_url_fopen|expose_php/i.test(b), remediation: 'php.ini 외부 접근 차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.user.ini', title: '.user.ini 노출', severity: 'medium', sig: (b) => /=\s*/.test(b) && /(php|engine|auto_prepend|open_basedir)/i.test(b), remediation: '.user.ini 외부 접근 차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/package.json', title: '루트 package.json 노출', severity: 'low', sig: (b) => /"dependencies"|"scripts"|"name"\s*:/.test(b) && !/<html/i.test(b), remediation: '웹루트에서 package.json 노출을 차단하십시오.', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/config.php.bak', title: 'config.php.bak 노출', severity: 'critical', sig: (b) => /<\?php|define\(|DB_|password/i.test(b), remediation: '백업 파일 제거 및 자격증명 교체', owasp: 'A05:2021', cwe: 'CWE-530' },
  { path: '/db.sqlite', title: 'SQLite DB 파일(db.sqlite) 노출', severity: 'critical', sig: (b) => b.startsWith('SQLite format 3') || /SQLite format 3/.test(b.slice(0, 32)), remediation: 'DB 파일을 웹루트에서 제거·차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/database.sqlite', title: 'SQLite DB 파일(database.sqlite) 노출', severity: 'critical', sig: (b) => b.startsWith('SQLite format 3'), remediation: 'DB 파일을 웹루트에서 제거·차단', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.env.development', title: '.env.development 노출', severity: 'high', sig: (b) => /(^|\n)\s*[A-Z0-9_]+\s*=/.test(b) && !/<html/i.test(b), remediation: '차단 및 비밀키 교체', owasp: 'A05:2021', cwe: 'CWE-522' },
  { path: '/.env.bak', title: '.env.bak 노출', severity: 'critical', sig: (b) => /(^|\n)\s*[A-Z0-9_]+\s*=/.test(b) && !/<html/i.test(b), remediation: '차단 및 노출된 모든 비밀키 폐기·재발급', owasp: 'A05:2021', cwe: 'CWE-530' },
  { path: '/Gemfile', title: 'Ruby Gemfile 노출', severity: 'low', sig: (b) => /^\s*(source|gem|ruby)\b/im.test(b) && !/<html/i.test(b), remediation: '의존성 매니페스트 노출 검토', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/requirements.txt', title: 'Python requirements.txt 노출', severity: 'info', sig: (b) => /^[\w.-]+[=<>~]=?[\d.]/m.test(b) && !/<html/i.test(b), remediation: '의존성 노출 여부 검토 및 버전 취약점 점검', owasp: 'A06:2021', cwe: 'CWE-200' },
  { path: '/Procfile', title: 'Procfile 노출', severity: 'info', sig: (b) => /^(web|worker|release):/m.test(b) && !/<html/i.test(b), remediation: '배포 산출물 노출 검토', owasp: 'A05:2021', cwe: 'CWE-200' },
  { path: '/.editorconfig', title: '.editorconfig 노출', severity: 'info', sig: (b) => /\[\*\]|root\s*=\s*true|indent_style/i.test(b) && !/<html/i.test(b), remediation: '개발 산출물 배포 제외', owasp: 'A05:2021', cwe: 'CWE-200' },
];

/** 확장 .well-known 리소스 — 노출/약점. */
const EXTRA_WELLKNOWN: { path: string; title: string; severity: Finding['severity']; sig: (b: string) => boolean; desc: string; remediation: string }[] = [
  { path: '/.well-known/dnt-policy.txt', title: 'DNT 정책 노출', severity: 'info', sig: (b) => /tracking|do not track/i.test(b), desc: 'Do-Not-Track 정책 파일이 노출됩니다.', remediation: '의도된 게시인지 확인하십시오.' },
  { path: '/.well-known/host-meta', title: 'host-meta(서비스 디스커버리) 노출', severity: 'info', sig: (b) => /<XRD|<Link/i.test(b), desc: 'host-meta 가 내부 서비스/엔드포인트를 노출할 수 있습니다.', remediation: '불필요한 디스커버리 노출을 제한하십시오.' },
  { path: '/.well-known/webfinger', title: 'WebFinger 계정 열거 표면', severity: 'low', sig: (b) => /"subject"|"links"/.test(b), desc: 'WebFinger 가 계정/식별자 열거 표면이 될 수 있습니다.', remediation: '레이트리밋·인증으로 열거를 제한하십시오.' },
  { path: '/.well-known/openpgpkey/policy', title: 'OpenPGP 정책 노출', severity: 'info', sig: (b) => /./.test(b), desc: 'OpenPGP 웹키 디렉터리 정책이 노출됩니다.', remediation: '의도된 게시인지 확인하십시오.' },
  { path: '/.well-known/acme-challenge/sentinel-probe', title: 'ACME challenge 디렉터리 접근 가능', severity: 'info', sig: (b) => /./.test(b) && !/not found/i.test(b), desc: 'ACME 챌린지 경로가 임의 콘텐츠를 반환하여 검증 우회/혼선 표면이 될 수 있습니다.', remediation: 'ACME 챌린지 경로는 인증서 발급 중에만 노출되도록 제한하십시오.' },
  { path: '/.well-known/traffic-advice', title: 'traffic-advice(프리페치 정책) 노출', severity: 'info', sig: (b) => /user_agent|google-safety|disallow/i.test(b), desc: '프록시 프리페치 정책이 노출됩니다.', remediation: '의도된 게시인지 확인하십시오.' },
];

/** 두 응답 본문이 사실상 동일한지(soft-404 판정). 길이 + 접두 비교. */
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (a === b) return true;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) / Math.max(la, lb) < 0.05) return a.slice(0, 256) === b.slice(0, 256);
  return false;
}
