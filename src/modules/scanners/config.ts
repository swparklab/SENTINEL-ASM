/**
 * 설정·구성 점검 (Configuration Audit) — 설계 §4.2 (전문 확장판).
 * HTTP 보안 헤더(현행 권장 전체), CORS 구성 오류, 허용 HTTP 메서드(TRACE 등),
 * 쿠키 플래그 심층 분석, security.txt 모범사례, 정밀 민감 경로 노출(콘텐츠 검증 +
 * soft-404 베이스라이닝으로 오탐 제거)을 비파괴 HTTP 요청으로 점검한다.
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { mk } from './asm.js';

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

    // 1) 보안 헤더
    for (const h of SECURITY_HEADERS) {
      if (!(h.header in root.headers)) {
        findings.push({ ...mk('config', h.severity, h.title, ctx.asset.value, `응답에 ${h.header} 헤더가 없습니다.`, `status=${root.status}`, h.remediation), confidence: 'firm' });
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
      // GraphQL 인트로스펙션 노출
      const gql = await ctx.guard.httpGet(base + '/graphql', { method: 'POST', headers: { 'content-type': 'application/json' } });
      if (gql && gql.status < 500 && /__schema|"data"|GraphQL/i.test(gql.body)) {
        findings.push(mk('config', 'low', 'GraphQL 엔드포인트 노출', ctx.asset.value, 'GraphQL 이 외부에 노출되어 인트로스펙션으로 스키마가 유출될 수 있습니다.', `status=${gql.status}`, '운영에서 인트로스펙션 비활성화 및 인증 적용.'));
      }
    }

    return findings;
  },
};

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
  { path: '/.well-known/openid-configuration', title: 'OIDC 설정 노출(정보)', severity: 'info', sig: (b) => /authorization_endpoint|issuer/.test(b), remediation: '의도된 노출인지 확인(일반적으로 정상)' },
];

/** 두 응답 본문이 사실상 동일한지(soft-404 판정). 길이 + 접두 비교. */
function similar(a: string, b: string): boolean {
  if (!a || !b) return false;
  if (a === b) return true;
  const la = a.length, lb = b.length;
  if (Math.abs(la - lb) / Math.max(la, lb) < 0.05) return a.slice(0, 256) === b.slice(0, 256);
  return false;
}
