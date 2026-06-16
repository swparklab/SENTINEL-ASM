/**
 * 동적 점검 (DAST, 동의 대상 한정) — 설계 §4.4.
 * OWASP Top 10 기반 "비파괴" 점검: 익스플로잇 실행이 아니라 취약점 존재 여부의
 * 안전 지표(indicator)만 식별한다. 운영에서는 OWASP ZAP/Nuclei 를 안전 프로파일로
 * 래핑해 운용하며, 본 구현은 동일 철학의 비파괴 표준 점검 세트를 제공한다.
 * Aggressive 프로파일은 게이트의 추가 서면 승인을 통과한 경우에만 호출된다.
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { mk } from './asm.js';

export const dastScanner: Scanner = {
  module: 'dast',
  minIntensity: 'standard',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const base = ctx.asset.type === 'host' ? `http://${ctx.asset.value}` : `https://${ctx.asset.value}`;
    const root = await ctx.guard.httpGet(base + '/');
    if (!root) {
      ctx.log('dast: 대상 응답 없음');
      return findings;
    }

    // A05/A07: 보안 설정 오류 — 기본 관리자 경로 노출 여부 (비파괴 GET, 인증 시도 없음)
    const adminPaths = ['/admin', '/wp-admin', '/manager/html', '/phpmyadmin'];
    for (const p of adminPaths) {
      const r = await ctx.guard.httpGet(base + p);
      if (r && (r.status === 200 || r.status === 401 || r.status === 403)) {
        findings.push(mk('dast', r.status === 200 ? 'medium' : 'low',
          `관리 인터페이스 노출 가능성: ${p}`, ctx.asset.value + p,
          `관리자 경로가 외부에서 접근 가능합니다 (status=${r.status}).`, `status=${r.status}`,
          '관리 인터페이스는 IP 허용목록/VPN 뒤로 이동하고 기본 경로를 변경하십시오.'));
      }
    }

    // A02: 전송계층 — HTTP→HTTPS 강제 여부 (리다이렉트 미설정)
    if (ctx.asset.type !== 'host') {
      const http = await ctx.guard.httpGet(`http://${ctx.asset.value}/`);
      if (http && http.status === 200 && !http.headers['location']) {
        findings.push(mk('dast', 'medium', 'HTTP→HTTPS 리다이렉트 미설정', ctx.asset.value,
          '평문 HTTP 가 HTTPS 로 강제 전환되지 않습니다.', `http status=${http.status}`,
          '모든 HTTP 요청을 HTTPS 로 301 리다이렉트하고 HSTS 를 적용하십시오.'));
      }
    }

    // A06: 취약·구식 컴포넌트 단서 — 디렉터리 리스팅 (Index of)
    if (/<title>Index of/i.test(root.body) || /Directory listing for/i.test(root.body)) {
      findings.push(mk('dast', 'medium', '디렉터리 인덱싱 활성화', ctx.asset.value,
        '디렉터리 자동 목록이 노출되어 내부 파일 구조가 드러납니다.', root.body.slice(0, 80),
        '웹서버에서 자동 디렉터리 인덱싱을 비활성화하십시오.'));
    }

    // 입력값 반사(잠재적 XSS 표면) — 비파괴 마커 반사만 확인
    const reflect = await ctx.guard.httpGet(`${base}/?q=sentinel_probe_marker`);
    if (reflect && reflect.body.includes('sentinel_probe_marker')) {
      findings.push(mk('dast', 'high', '입력값 반사(잠재적 XSS 표면)', ctx.asset.value,
        '쿼리 파라미터가 응답에 그대로 반사됩니다. XSS 가능성을 추가 검토하십시오.',
        'reflected: sentinel_probe_marker', '출력 인코딩 및 입력 검증을 적용하고 CSP 를 강화하십시오.'));
    }

    // ───────── 심층 DAST (토시 하나까지, 비파괴) ─────────
    if (ctx.deep) {
      // 추가 로그인/관리 경로 전수
      const deepPaths = ['/login', '/signin', '/administrator', '/admin/login', '/user/login', '/api', '/api/v1', '/.well-known/security.txt', '/debug', '/console', '/actuator/health'];
      for (const p of deepPaths) {
        const r = await ctx.guard.httpGet(base + p);
        if (r && (r.status === 200 || r.status === 401 || r.status === 403)) {
          findings.push(mk('dast', r.status === 200 ? 'low' : 'info', `노출 경로 식별: ${p} (status=${r.status})`, ctx.asset.value + p,
            '인증/관리/디버그 관련 경로가 외부에서 응답합니다.', `status=${r.status}`, '불필요 경로는 차단하고 관리 인터페이스는 접근통제하십시오.'));
        }
      }
      // 오픈 리다이렉트 휴리스틱 (비파괴 — 외부로 실제 이동하지 않고 Location 만 확인)
      const orUrl = `${base}/?next=https://sentinel-openredirect.example/&redirect=https://sentinel-openredirect.example/&url=https://sentinel-openredirect.example/`;
      const orr = await ctx.guard.httpGet(orUrl);
      if (orr && [301, 302, 303, 307, 308].includes(orr.status) && (orr.headers['location'] || '').includes('sentinel-openredirect.example')) {
        findings.push(mk('dast', 'medium', '오픈 리다이렉트 가능성', ctx.asset.value + '/?next=…',
          '리다이렉트 파라미터가 외부 도메인으로 그대로 전달됩니다(피싱 악용 가능).', `Location: ${orr.headers['location']}`,
          '리다이렉트 대상은 화이트리스트/상대경로로 제한하십시오.'));
      }
      // Host 헤더 반사 (캐시 포이즈닝/비밀번호 재설정 오염 단서)
      const hostInj = await ctx.guard.httpGet(base + '/', { headers: { host: 'sentinel-host-injection.example' } });
      if (hostInj && hostInj.body.includes('sentinel-host-injection.example')) {
        findings.push(mk('dast', 'medium', 'Host 헤더 반사', ctx.asset.value,
          '요청 Host 헤더 값이 응답에 반사되어 캐시 포이즈닝/링크 오염에 악용될 수 있습니다.', 'reflected Host header',
          'Host 헤더를 신뢰하지 말고 고정 도메인/허용목록으로 검증하십시오.'));
      }

      // 오류 응답 스택트레이스/디버그 모드 노출 (비파괴 트리거)
      const errResp = await ctx.guard.httpGet(`${base}/sentinel-nonexistent-${Math.random().toString(36).slice(2)}`, { headers: { accept: 'application/json, %%%' } });
      if (errResp && errResp.body) {
        const sig = matchStackTrace(errResp.body);
        if (sig) findings.push(mk('dast', 'high', `상세 오류/스택트레이스 노출: ${sig}`, ctx.asset.value, '오류 응답에 스택트레이스/디버그 정보가 노출되어 내부 구조가 드러납니다.', errResp.body.slice(0, 120).replace(/\s+/g, ' '), '운영에서 상세 오류를 숨기고 일반 오류 페이지를 반환하십시오(디버그 모드 비활성).'));
      }

      // SQL 오류 메시지 노출 (단일 따옴표 1개만, 비파괴)
      const baseQ = await ctx.guard.httpGet(`${base}/?id=1`);
      const quoteQ = await ctx.guard.httpGet(`${base}/?id=1%27`);
      if (quoteQ && quoteQ.body) {
        const dberr = matchSqlError(quoteQ.body);
        if (dberr && !(baseQ && matchSqlError(baseQ.body))) findings.push(mk('dast', 'high', `DB SQL 오류 노출(잠재적 SQLi 표면): ${dberr}`, ctx.asset.value, '단일 따옴표 입력으로 DBMS 오류가 노출됩니다(SQL 인젝션 표면). 익스플로잇은 수행하지 않았습니다.', quoteQ.body.slice(0, 120).replace(/\s+/g, ' '), '파라미터화 쿼리(Prepared Statement)를 사용하고 상세 DB 오류를 숨기십시오.'));
      }

      // 디렉터리 트래버설 단서 (안전 마커, 콘텐츠 시그니처)
      const trav = await ctx.guard.httpGet(`${base}/?file=....//....//....//etc/passwd`);
      if (trav && /root:.*:0:0:/.test(trav.body)) findings.push(mk('dast', 'critical', '디렉터리 트래버설/LFI 가능성', ctx.asset.value, '경로 트래버설 입력으로 시스템 파일(/etc/passwd) 내용이 응답에 나타납니다.', trav.body.slice(0, 80).replace(/\s+/g, ' '), '파일 경로 입력을 화이트리스트·정규화로 검증하십시오.'));

      // PII 평문 노출 (검증 로직으로 오탐 억제)
      const pii = scanPii(root.body);
      if (pii.length) findings.push(mk('dast', 'high', `응답 내 개인정보(PII) 평문 노출: ${pii.map((p) => p.type).join(', ')}`, ctx.asset.value, '응답에 검증된 개인정보(주민번호/카드/전화)가 평문으로 노출됩니다(ISMS-P/개인정보보호법 위반).', pii.map((p) => `${p.type}: ${p.masked}`).join('\n'), '개인정보를 마스킹·암호화하고 노출 경로를 차단하십시오.'));

      // 기본자격증명 가능 제품 / 데브옵스 패널 노출 (지문, 로그인 시도 없음)
      for (const [p, sig, name] of DEVOPS_PANELS) {
        const r = await ctx.guard.httpGet(base + p);
        if (r && (r.status === 200 || r.status === 401 || r.status === 403) && (sig.test(r.body) || sig.test(JSON.stringify(r.headers)))) {
          findings.push(mk('dast', 'medium', `관리/데브옵스 패널 노출: ${name} (${p})`, ctx.asset.value + p, `${name} 콘솔이 외부에서 식별됩니다. 기본 자격증명/무인증 접근 위험을 점검하십시오.`, `status=${r.status}`, '관리 콘솔을 VPN/IP 허용목록 뒤로 옮기고 기본 자격증명을 변경하십시오.'));
        }
      }

      // 클라우드 메타데이터 SSRF 표면 단서 (입력 표면 + 유출 흔적, 익스플로잇 미수행)
      const ssrfParams = [...root.body.matchAll(/[?&](url|uri|target|dest|redirect|callback|webhook|image_url|feed|proxy|fetch)=/gi)].map((m) => m[1]!);
      if (ssrfParams.length) findings.push(mk('dast', 'low', `SSRF 입력 표면 존재: ${[...new Set(ssrfParams)].slice(0, 5).join(', ')}`, ctx.asset.value, '외부 URL 을 받는 파라미터가 있어 SSRF 검토가 필요합니다(오픈 리다이렉트와 결합 시 위험 증가).', [...new Set(ssrfParams)].join(', '), 'URL 파라미터를 화이트리스트로 제한하고 내부 대역 접근을 차단하십시오.'));
      if (/AccessKeyId|InstanceProfile|ami-[0-9a-f]{8}|metadata\.google\.internal|computeMetadata/i.test(root.body)) findings.push(mk('dast', 'high', '클라우드 메타데이터 유출 흔적', ctx.asset.value, '응답에 클라우드 인스턴스 메타데이터로 보이는 내용이 포함되어 SSRF 침해 흔적일 수 있습니다.', root.body.slice(0, 100).replace(/\s+/g, ' '), 'IMDSv2 강제 및 메타데이터 접근 통제를 적용하십시오.'));
    }

    return findings;
  },
};

const DEVOPS_PANELS: [string, RegExp, string][] = [
  ['/manager/html', /tomcat|apache tomcat/i, 'Tomcat Manager'],
  ['/phpmyadmin/', /phpmyadmin/i, 'phpMyAdmin'],
  ['/grafana/login', /grafana/i, 'Grafana'],
  ['/login?from=%2F', /x-jenkins|jenkins/i, 'Jenkins'],
  ['/-/healthy', /prometheus/i, 'Prometheus'],
  ['/v1/status/leader', /^"?\d|consul/i, 'Consul'],
  ['/dashboard/', /traefik/i, 'Traefik'],
  ['/adminer.php', /adminer/i, 'Adminer'],
  ['/solr/', /solr admin|apache solr/i, 'Apache Solr'],
  ['/api/v2.0/systeminfo', /harbor/i, 'Harbor'],
];

/** 다국어 스택트레이스/디버그 모드 시그니처. */
function matchStackTrace(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/at [\w.$]+\([\w]+\.java:\d+\)|org\.springframework|Exception in thread/, 'Java/Spring'],
    [/System\.\w+Exception|at .+ in .+:line \d+|customErrors mode="Off"/, '.NET'],
    [/Fatal error:|Stack trace:\s*#0|<b>Warning<\/b>:.*on line/, 'PHP'],
    [/Traceback \(most recent call last\)|Werkzeug Debugger|DEBUG = True/, 'Python'],
    [/at \w+ \(\/.+:\d+:\d+\)|node_modules/, 'Node.js'],
    [/\.rb:\d+:in |ActionController|Rails\.root/, 'Ruby/Rails'],
    [/Whoops\\|laravel|Symfony.*Exception/i, 'PHP framework'],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}

/** DBMS 오류 시그니처. */
function matchSqlError(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/You have an error in your SQL syntax|mysql_fetch|MySqlException/i, 'MySQL'],
    [/PG::\w+Error|unterminated quoted string|PostgreSQL.*ERROR/i, 'PostgreSQL'],
    [/Unclosed quotation mark|System\.Data\.SqlClient|SqlException/i, 'MSSQL'],
    [/ORA-\d{5}/i, 'Oracle'],
    [/SQLITE_ERROR|sqlite3\./i, 'SQLite'],
    [/SQLSTATE\[|syntax error at or near/i, 'SQL'],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}

/** 검증 로직으로 오탐을 억제한 PII 스캔(주민번호/카드/전화). */
function scanPii(b: string): { type: string; masked: string }[] {
  const out: { type: string; masked: string }[] = [];
  // 주민등록번호 (가중합 체크섬)
  for (const m of b.matchAll(/\b(\d{6})-?([1-4]\d{6})\b/g)) {
    const digits = (m[1]! + m[2]!).split('').map(Number);
    const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    const sum = w.reduce((s, x, i) => s + x * digits[i]!, 0);
    const chk = (11 - (sum % 11)) % 10;
    if (chk === digits[12]) { out.push({ type: '주민등록번호', masked: m[1]! + '-*******' }); break; }
  }
  // 신용카드 (Luhn)
  for (const m of b.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) {
    const d = m[0].replace(/[ -]/g, '');
    if (d.length < 13 || d.length > 19) continue;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) { let n = Number(d[i]); if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
    if (sum % 10 === 0 && /^(4|5[1-5]|3[47]|6011)/.test(d)) { out.push({ type: '신용카드', masked: d.slice(0, 4) + '********' + d.slice(-2) }); break; }
  }
  // 휴대전화
  const ph = b.match(/\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b/);
  if (ph) out.push({ type: '휴대전화', masked: ph[0].slice(0, 4) + '****' });
  return out;
}
