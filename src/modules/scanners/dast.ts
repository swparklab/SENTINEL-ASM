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
import { runActiveConfirmation } from './active.js';

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

    // 소프트-404 베이스라인 (포괄 200/SPA 오탐 억제용). 랜덤 경로 GET → baseStatus/baseBody.
    // 경로 존재 점검은 모두 이 베이스라인과 비교해 catch-all 200(동일 본문)을 억제한다.
    const rnd = () => Math.random().toString(36).slice(2);
    const baseProbe = await ctx.guard.httpGet(`${base}/sentinel-baseline-${rnd()}`);
    const baseStatus = baseProbe?.status ?? 404;
    const baseBody = baseProbe?.body ?? '';
    const isCatchAll = baseStatus === 200 && baseBody.length > 0;
    // 두 경로가 같은 catch-all 200 응답인지(존재하지 않는 경로와 사실상 동일) 판정.
    const sameAsBaseline = (r: { status: number; body: string }): boolean =>
      isCatchAll && r.status === 200 && r.body === baseBody;

    // A05/A07: 보안 설정 오류 — 기본 관리자 경로 노출 여부 (비파괴 GET, 인증 시도 없음)
    const adminPaths = ['/admin', '/wp-admin', '/manager/html', '/phpmyadmin'];
    for (const p of adminPaths) {
      const r = await ctx.guard.httpGet(base + p);
      // 포괄-200 사이트: baseline 과 동일 본문이면 실제 경로 존재가 아니므로 억제.
      if (r && (r.status === 200 || r.status === 401 || r.status === 403) && !sameAsBaseline(r)) {
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
        // 포괄-200 사이트: baseline 과 동일 본문이면 실제 경로 존재가 아니므로 억제.
        if (r && (r.status === 200 || r.status === 401 || r.status === 403) && !sameAsBaseline(r)) {
          findings.push(mk('dast', r.status === 200 ? 'low' : 'info', `노출 경로 식별: ${p} (status=${r.status})`, ctx.asset.value + p,
            '인증/관리/디버그 관련 경로가 외부에서 응답합니다.', `status=${r.status}`, '불필요 경로는 차단하고 관리 인터페이스는 접근통제하십시오.'));
        }
      }
      // 오픈 리다이렉트는 아래 [3] 확장 점검(OPEN_REDIRECT_VARIANTS, A01/CWE-601)으로 통합되었다.
      // Host 헤더 반사는 아래 [4] 확장 점검(X-Forwarded-Host 등)으로 통합되었다.
      // (원본 Host 헤더 주입은 undici 의 forbidden header 인 'host' 를 silently drop 하여 동작 불능이었음.)

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

      // (SSRF 입력 표면·클라우드 메타데이터 흔적 점검은 아래 [10] 확장 점검으로 통합되었다.
      //  원본은 owasp/cwe 누락·중복 finding 문제를 유발하여 제거.)

      // ───────── 확장 점검 ─────────
      // (소프트-404 베이스라인 rnd/baseStatus/baseBody/isCatchAll 은 run() 상단에서 1회 계산하여 공유한다.)

      // [1] SSTI 표면 — 다양한 템플릿 표현식 반사/평가 결과(49) 또는 엔진 오류 시그니처
      const sstiPayloads = [
        { p: '{{7*7}}', eng: 'Jinja2/Twig/Nunjucks' },
        { p: '${7*7}', eng: 'FreeMarker/JSP-EL/Velocity' },
        { p: '<%=7*7%>', eng: 'ERB/JSP' },
        { p: '#{7*7}', eng: 'Ruby/Thymeleaf' },
        { p: '{7*7}', eng: 'Smarty(brace)' },
      ];
      for (const { p, eng } of sstiPayloads) {
        const r = await ctx.guard.httpGet(`${base}/?q=${encodeURIComponent('sstipre' + p + 'sstipost')}`);
        if (!r || !r.body) continue;
        // 입력이 그대로 반사되었는지(미평가) 와 49로 평가되었는지 구분
        if (r.body.includes('sstipre49sstipost')) {
          findings.push({ ...mk('dast', 'high', `SSTI(서버측 템플릿 인젝션) 가능성: ${eng}`, ctx.asset.value,
            `템플릿 표현식 ${p} 가 서버에서 49 로 평가되어 반사됩니다. 서버측 템플릿 인젝션 표면입니다(익스플로잇 미수행).`,
            `payload=${p} → '...49...' 반사`, '사용자 입력을 템플릿에 직접 보간하지 말고 샌드박스/자동이스케이프를 사용하십시오.'),
            owasp: 'A03:2021', cwe: 'CWE-1336', confidence: 'firm',
            references: ['https://portswigger.net/web-security/server-side-template-injection'] });
          break;
        }
        const terr = matchTemplateError(r.body);
        if (terr && !(isCatchAll && r.body === baseBody)) {
          findings.push({ ...mk('dast', 'medium', `SSTI 오류 시그니처 노출: ${terr}`, ctx.asset.value,
            `템플릿 표현식 주입 시 템플릿 엔진 오류(${terr})가 노출됩니다. SSTI 표면일 수 있습니다.`,
            r.body.slice(0, 120).replace(/\s+/g, ' '), '템플릿 입력 보간을 제거하고 상세 오류를 숨기십시오.'),
            owasp: 'A03:2021', cwe: 'CWE-1336', confidence: 'tentative',
            references: ['https://portswigger.net/web-security/server-side-template-injection'] });
          break;
        }
      }

      // [2] CRLF / HTTP 응답 분할 — 인코딩된 개행으로 헤더 주입 후 응답 헤더 반사 확인
      const crlfMarker = 'sentinel-crlf-' + rnd();
      const crlf = await ctx.guard.httpGet(`${base}/?p=${encodeURIComponent('1')}%0d%0aSentinel-Probe:%20${crlfMarker}`);
      if (crlf && (crlf.headers['sentinel-probe'] || '').includes(crlfMarker)) {
        findings.push({ ...mk('dast', 'high', 'CRLF 주입 / HTTP 응답 분할 가능성', ctx.asset.value,
          '인코딩된 개행(%0d%0a)을 포함한 파라미터가 응답 헤더로 주입되어 헤더 분할/캐시 포이즈닝에 악용될 수 있습니다.',
          `injected header Sentinel-Probe: ${crlfMarker}`, '입력값에서 CR/LF 를 제거하고 헤더 값 인코딩을 적용하십시오.'),
          owasp: 'A03:2021', cwe: 'CWE-113', confidence: 'firm',
          references: ['https://owasp.org/www-community/vulnerabilities/CRLF_Injection'] });
      }

      // [3] 오픈 리다이렉트 변형 확대 — //evil, /\evil, https:evil, 인코딩, 다양한 파라미터명
      const orToken = 'sentinel-or-' + rnd() + '.example';
      for (const variant of OPEN_REDIRECT_VARIANTS) {
        const val = variant.replace('EVIL', orToken);
        const qs = OPEN_REDIRECT_PARAMS.map((n) => `${n}=${encodeURIComponent(val)}`).join('&');
        const r = await ctx.guard.httpGet(`${base}/?${qs}`);
        if (r && [301, 302, 303, 307, 308].includes(r.status)) {
          const loc = r.headers['location'] || '';
          if (loc.includes(orToken)) {
            findings.push({ ...mk('dast', 'medium', `오픈 리다이렉트 변형 가능성: ${variant}`, ctx.asset.value,
              `리다이렉트 파라미터가 외부 대상(${variant})으로 그대로 전달됩니다. 우회 변형으로도 차단되지 않습니다.`,
              `Location: ${loc}`, '리다이렉트 대상은 화이트리스트/상대경로로 제한하고 우회 변형(//, \\, 인코딩)을 정규화하십시오.'),
              owasp: 'A01:2021', cwe: 'CWE-601', confidence: 'firm',
              references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'] });
            break;
          }
        }
      }

      // [4] Host 헤더 공격 변형 — X-Forwarded-Host / X-Host 등 헤더 오염 반사·리다이렉트
      const xfhToken = 'sentinel-xfh-' + rnd() + '.example';
      for (const hname of FORWARDED_HOST_HEADERS) {
        const r = await ctx.guard.httpGet(base + '/', { headers: { [hname]: xfhToken } });
        if (!r) continue;
        const loc = r.headers['location'] || '';
        const reflectedInBody = r.body.includes(xfhToken);
        const reflectedInLoc = loc.includes(xfhToken);
        if (reflectedInLoc || reflectedInBody) {
          findings.push({ ...mk('dast', 'medium', `Host 헤더 오염 반사: ${hname}`, ctx.asset.value,
            `${hname} 헤더 값이 ${reflectedInLoc ? 'Location 헤더' : '응답 본문'}에 반사됩니다. 비밀번호 재설정 링크 오염/캐시 포이즈닝에 악용될 수 있습니다.`,
            reflectedInLoc ? `Location: ${loc}` : `body reflects ${xfhToken}`,
            '프록시 헤더(X-Forwarded-Host 등)를 신뢰하지 말고 절대 URL 생성 시 고정 도메인을 사용하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-644', confidence: 'firm',
            references: ['https://portswigger.net/web-security/host-header'] });
          break;
        }
      }

      // [5] XSS 컨텍스트 확대 — 속성/JS/URL 컨텍스트 마커, 미인코딩 여부로 심각도 구분
      const xssMarker = 'sentinelXSS' + rnd().replace(/[^a-z0-9]/g, '');
      const xssProbe = `"'></tag><${xssMarker}>`;
      const xr = await ctx.guard.httpGet(`${base}/?q=${encodeURIComponent(xssProbe)}`);
      if (xr && xr.body && !(isCatchAll && xr.body === baseBody)) {
        const rawTag = xr.body.includes(`<${xssMarker}>`);
        const rawBreakout = xr.body.includes(`</tag><`) || xr.body.includes(`"'>`);
        if (rawTag || rawBreakout) {
          findings.push({ ...mk('dast', 'high', '반사형 XSS 가능성(미인코딩 HTML 컨텍스트)', ctx.asset.value,
            '특수문자(< > " \')가 인코딩 없이 응답에 반사되어 HTML/속성 컨텍스트 탈출이 가능합니다. 반사형 XSS 표면입니다.',
            `reflected raw: ${rawTag ? `<${xssMarker}>` : xssProbe.slice(0, 20)}`,
            '컨텍스트별 출력 인코딩(HTML/속성/JS)을 적용하고 CSP 를 강화하십시오.'),
            owasp: 'A03:2021', cwe: 'CWE-79', confidence: 'firm',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'] });
        } else if (xr.body.includes(xssMarker)) {
          // 마커는 반사되나 특수문자가 인코딩됨 → 표면은 있으나 위험 낮음
          findings.push({ ...mk('dast', 'low', '입력 반사(특수문자 인코딩됨, XSS 표면 낮음)', ctx.asset.value,
            '입력 마커는 반사되나 특수문자가 엔티티 인코딩되어 즉시 실행 위험은 낮습니다. JS/URL 컨텍스트 반사는 별도 검토가 필요합니다.',
            `reflected (encoded): ${xssMarker}`, '컨텍스트별 인코딩을 유지하고 추가 컨텍스트(JS/속성/URL)도 점검하십시오.'),
            owasp: 'A03:2021', cwe: 'CWE-79', confidence: 'tentative' });
        }
      }

      // [6] NoSQL/LDAP/XPath 인젝션 오류 시그니처
      const nosqlProbe = await ctx.guard.httpGet(`${base}/?id=${encodeURIComponent("'\"`{};$where:1//")}`);
      if (nosqlProbe && nosqlProbe.body && !(isCatchAll && nosqlProbe.body === baseBody)) {
        const inj = matchInjectionError(nosqlProbe.body);
        if (inj) {
          findings.push({ ...mk('dast', 'high', `${inj.kind} 인젝션 오류 시그니처 노출: ${inj.label}`, ctx.asset.value,
            `${inj.kind} 관련 오류(${inj.label})가 입력 주입 시 노출됩니다. 인젝션 표면입니다(익스플로잇 미수행).`,
            nosqlProbe.body.slice(0, 120).replace(/\s+/g, ' '),
            '입력을 파라미터화/이스케이프하고 상세 오류를 숨기십시오.'),
            owasp: 'A03:2021', cwe: inj.cwe, confidence: 'tentative',
            references: ['https://owasp.org/www-community/Injection_Flaws'] });
        }
      }

      // [7] XXE 표면 — application/xml 본문 수용 여부 + XML echo/오류 (안전 마커, 외부엔티티 미사용)
      const xxeMarker = 'sentinel-xxe-' + rnd();
      const xmlBody = `<?xml version="1.0"?><sentinel>${xxeMarker}</sentinel>`;
      const xxe = await ctx.guard.httpGet(base + '/', { method: 'OPTIONS' });
      // OPTIONS 로 메서드 협상 확인 후, XML 수용 표면은 본문 echo 로만 판정(POST 금지 → GET 불가하므로 본문 echo는 root 기반 휴리스틱)
      void xxe; void xmlBody;
      const xmlAccept = await ctx.guard.httpGet(`${base}/?format=xml&output=xml`, { headers: { accept: 'application/xml' } });
      if (xmlAccept && /<\?xml|<!DOCTYPE|application\/xml/i.test((xmlAccept.headers['content-type'] || '') + xmlAccept.body.slice(0, 200))) {
        findings.push({ ...mk('dast', 'low', 'XML 처리 표면 노출(XXE 검토 필요)', ctx.asset.value,
          '엔드포인트가 XML 응답/처리를 수행합니다. XML 파서가 외부 엔티티(DOCTYPE/SYSTEM)를 허용하면 XXE 위험이 있습니다(파괴적 페이로드 미전송).',
          (xmlAccept.headers['content-type'] || '') + ' | ' + xmlAccept.body.slice(0, 60).replace(/\s+/g, ' '),
          'XML 파서에서 DTD/외부 엔티티 처리를 비활성화하십시오(secure processing).'),
          owasp: 'A05:2021', cwe: 'CWE-611', confidence: 'tentative',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'] });
      }

      // [8] 역직렬화 단서 — __VIEWSTATE, rO0AB(java serialized base64), node deserialize 흔적
      const deserSig = matchDeserialization(root.body + JSON.stringify(root.headers));
      if (deserSig) {
        findings.push({ ...mk('dast', 'medium', `안전하지 않은 역직렬화 단서: ${deserSig.label}`, ctx.asset.value,
          `${deserSig.label} 형태의 직렬화 데이터가 노출됩니다. 신뢰되지 않은 입력 역직렬화 시 RCE 위험이 있습니다.`,
          deserSig.evidence, '서명/암호화된 토큰을 사용하고 신뢰되지 않은 데이터의 역직렬화를 금지하십시오.'),
          owasp: 'A08:2021', cwe: 'CWE-502', confidence: 'tentative',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'] });
      }

      // [9] 명령 주입 단서 — 안전 마커 반사/오류 (실제 실행 유도 아님, 반사·오류만)
      const ciMarker = 'sentinelCMD' + rnd().replace(/[^a-z0-9]/g, '');
      const ciProbe = await ctx.guard.httpGet(`${base}/?cmd=${encodeURIComponent(';echo ' + ciMarker)}`);
      if (ciProbe && ciProbe.body && !(isCatchAll && ciProbe.body === baseBody)) {
        const cierr = matchCommandError(ciProbe.body);
        if (cierr) {
          findings.push({ ...mk('dast', 'high', `명령 주입 오류 시그니처 노출: ${cierr}`, ctx.asset.value,
            `명령 구분자 입력 시 셸/명령 실행 오류(${cierr})가 노출됩니다. OS 명령 주입 표면입니다(실제 명령 실행 유도 미수행).`,
            ciProbe.body.slice(0, 120).replace(/\s+/g, ' '),
            '사용자 입력을 셸로 전달하지 말고 인수 배열/화이트리스트를 사용하십시오.'),
            owasp: 'A03:2021', cwe: 'CWE-78', confidence: 'tentative',
            references: ['https://owasp.org/www-community/attacks/Command_Injection'] });
        }
      }

      // [10] SSRF 입력 표면 확대 + 메타데이터 흔적 시그니처 추가
      const ssrfExtParams = [...root.body.matchAll(/[?&](next_url|return_url|continue|domain|host|server|port|page|path|file_url|avatar|source|src|link|out|go|forward)=/gi)].map((m) => m[1]!);
      if (ssrfExtParams.length) {
        findings.push({ ...mk('dast', 'low', `SSRF 추가 입력 표면: ${[...new Set(ssrfExtParams)].slice(0, 6).join(', ')}`, ctx.asset.value,
          'URL/호스트/경로를 받는 추가 파라미터가 식별되어 SSRF 검토가 필요합니다.',
          [...new Set(ssrfExtParams)].join(', '), 'URL/호스트 입력을 화이트리스트로 제한하고 내부 대역(169.254.0.0/16 등) 접근을 차단하십시오.'),
          owasp: 'A10:2021', cwe: 'CWE-918', confidence: 'tentative',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'] });
      }
      if (MORE_METADATA_RE.test(root.body)) {
        findings.push({ ...mk('dast', 'high', '클라우드/오케스트레이션 메타데이터 흔적(확장)', ctx.asset.value,
          '응답에 메타데이터 서비스(IMDS/GCP/Azure/Kubernetes) 흔적이 포함되어 SSRF 유출 가능성이 있습니다.',
          root.body.slice(0, 100).replace(/\s+/g, ' '), 'IMDSv2 강제, 메타데이터 엔드포인트 접근 통제, 서비스 토큰 노출 점검을 수행하십시오.'),
          owasp: 'A10:2021', cwe: 'CWE-918', confidence: 'tentative' });
      }

      // [11] 디버그/스택트레이스 시그니처 다국어 확대 (기존 matchStackTrace 와 다른 시그니처)
      const dbgResp = await ctx.guard.httpGet(`${base}/?debug=true&test=${rnd()}`, { headers: { accept: 'application/json' } });
      if (dbgResp && dbgResp.body && !(isCatchAll && dbgResp.body === baseBody)) {
        const dbg = matchDebugSignature(dbgResp.body);
        if (dbg) {
          findings.push({ ...mk('dast', 'medium', `디버그/내부정보 노출: ${dbg}`, ctx.asset.value,
            `응답에 디버그/프레임워크 내부 정보(${dbg})가 노출됩니다.`,
            dbgResp.body.slice(0, 120).replace(/\s+/g, ' '), '운영 환경에서 디버그 모드를 비활성화하고 내부 정보를 숨기십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-489', confidence: 'tentative',
            references: ['https://owasp.org/www-community/Improper_Error_Handling'] });
        }
      }

      // [12] 버전/내부 경로 노출 시그니처
      const vsig = matchVersionLeak(root.body + JSON.stringify(root.headers));
      if (vsig) {
        findings.push({ ...mk('dast', 'low', `버전/내부 경로 정보 노출: ${vsig.label}`, ctx.asset.value,
          `${vsig.label} 정보가 노출되어 공격자가 알려진 취약점 매핑에 활용할 수 있습니다.`,
          vsig.evidence, '서버/프레임워크 버전 배너와 내부 경로 노출을 제거하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-200', confidence: 'tentative' });
      }

      // [13] 파일/디렉터리 업로드 엔드포인트 노출 식별 (GET 으로 폼/엔드포인트 존재만 확인)
      for (const up of UPLOAD_PATHS) {
        const r = await ctx.guard.httpGet(base + up);
        if (r && (r.status === 200 || r.status === 401 || r.status === 403)) {
          const hasForm = /multipart\/form-data|type=["']file["']|<input[^>]+file|upload/i.test(r.body);
          if (r.status !== 200 || hasForm) {
            findings.push({ ...mk('dast', 'low', `업로드 엔드포인트 노출: ${up} (status=${r.status})`, ctx.asset.value + up,
              '파일 업로드 관련 엔드포인트가 식별됩니다. 무제한/무검증 업로드는 웹셸 업로드 위험이 있습니다(업로드 미수행).',
              `status=${r.status}${hasForm ? ', form detected' : ''}`,
              '업로드 확장자/MIME/크기 검증, 실행 디렉터리 분리, 무작위 파일명을 적용하십시오.'),
              owasp: 'A04:2021', cwe: 'CWE-434', confidence: 'tentative',
              references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'] });
          }
        }
      }

      // [14] 쿠키 속성 미흡 (Set-Cookie 의 Secure/HttpOnly/SameSite 부재)
      const setCookie = root.headers['set-cookie'] || '';
      if (setCookie) {
        const missing: string[] = [];
        if (!/;\s*secure/i.test(setCookie)) missing.push('Secure');
        if (!/;\s*httponly/i.test(setCookie)) missing.push('HttpOnly');
        if (!/;\s*samesite/i.test(setCookie)) missing.push('SameSite');
        if (missing.length) {
          findings.push({ ...mk('dast', 'low', `세션 쿠키 보안 속성 누락: ${missing.join(', ')}`, ctx.asset.value,
            `Set-Cookie 에 ${missing.join(', ')} 속성이 없어 탈취/CSRF/하향 위험이 있습니다.`,
            setCookie.slice(0, 100), '세션 쿠키에 Secure; HttpOnly; SameSite=Lax|Strict 를 설정하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-614', confidence: 'firm',
            references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'] });
        }
      }

      // [15] 쿠키 값 반사 (세션 토큰이 본문에 반사되면 누출 위험)
      const cookieRefl = await ctx.guard.httpGet(base + '/', { headers: { cookie: `sentinelck=${'sentinel-ck-' + rnd()}` } });
      void cookieRefl;
      const cookieName = (setCookie.match(/^([^=;\s]+)=/) || [])[1];
      if (cookieName && new RegExp(cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*[=:]').test(root.body) && /sess|token|jwt|auth/i.test(cookieName)) {
        findings.push({ ...mk('dast', 'medium', `세션 식별자 본문 노출 가능성: ${cookieName}`, ctx.asset.value,
          '세션/토큰 쿠키 이름이 응답 본문에 노출됩니다. 토큰 값이 본문/URL 로 새어나가는지 점검이 필요합니다.',
          cookieName, '세션 식별자를 본문/URL 에 출력하지 말고 HttpOnly 쿠키로만 전달하십시오.'),
          owasp: 'A07:2021', cwe: 'CWE-200', confidence: 'tentative' });
      }

      // [16] Verbose error — 파라미터 타입 깨짐 시 상세 오류/내부 경로 노출
      const verbose = await ctx.guard.httpGet(`${base}/?id[]=1&page=-1e999&format=%00`);
      if (verbose && verbose.body && !(isCatchAll && verbose.body === baseBody)) {
        const vpath = matchInternalPath(verbose.body);
        if (vpath) {
          findings.push({ ...mk('dast', 'low', `상세 오류 내 내부 경로 노출: ${vpath}`, ctx.asset.value,
            '비정상 입력 시 응답에 서버 내부 파일 경로가 노출됩니다.',
            vpath, '상세 오류와 절대 경로 노출을 제거하고 일반 오류 페이지를 반환하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-209', confidence: 'tentative' });
        }
      }

      // [17] GraphQL 인트로스펙션/엔드포인트 노출 (비파괴 GET, 스키마 노출만)
      for (const gp of ['/graphql', '/api/graphql', '/v1/graphql']) {
        const r = await ctx.guard.httpGet(base + gp + '?query=' + encodeURIComponent('{__typename}'));
        if (r && r.status === 200 && /__typename|"data"\s*:|GraphQL|graphql-playground|"errors"\s*:.*query/i.test(r.body)) {
          findings.push({ ...mk('dast', 'low', `GraphQL 엔드포인트 노출: ${gp}`, ctx.asset.value + gp,
            'GraphQL 엔드포인트가 응답합니다. 인트로스펙션이 켜져 있으면 전체 스키마가 노출될 수 있습니다.',
            r.body.slice(0, 80).replace(/\s+/g, ' '),
            '운영에서 인트로스펙션을 비활성화하고 쿼리 깊이/복잡도 제한과 인증을 적용하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-200', confidence: 'firm',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'] });
          break;
        }
      }

      // [18] CORS 설정 오류 — Origin 반사 + 자격증명 허용
      const corsOrigin = 'https://sentinel-cors-' + rnd() + '.example';
      const cors = await ctx.guard.httpGet(base + '/', { headers: { origin: corsOrigin } });
      if (cors) {
        const acao = cors.headers['access-control-allow-origin'] || '';
        const acac = (cors.headers['access-control-allow-credentials'] || '').toLowerCase();
        if (acao === corsOrigin && acac === 'true') {
          findings.push({ ...mk('dast', 'high', 'CORS 설정 오류(Origin 반사 + 자격증명 허용)', ctx.asset.value,
            '임의 Origin 이 반사되고 Access-Control-Allow-Credentials: true 가 설정되어 교차 출처 자격증명 탈취가 가능합니다.',
            `ACAO: ${acao}; ACAC: ${acac}`, 'Origin 화이트리스트를 적용하고 신뢰 출처에만 자격증명을 허용하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-942', confidence: 'firm',
            references: ['https://portswigger.net/web-security/cors'] });
        } else if (acao === '*' && acac === 'true') {
          findings.push({ ...mk('dast', 'high', 'CORS 설정 오류(와일드카드 + 자격증명)', ctx.asset.value,
            'Access-Control-Allow-Origin: * 와 자격증명 허용이 함께 설정되어 위험합니다.',
            `ACAO: *; ACAC: ${acac}`, '와일드카드와 자격증명 허용을 동시에 사용하지 마십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-942', confidence: 'firm' });
        } else if (acao === corsOrigin) {
          findings.push({ ...mk('dast', 'low', 'CORS Origin 반사(자격증명 미허용)', ctx.asset.value,
            '임의 Origin 이 반사되나 자격증명은 허용되지 않습니다. 민감 데이터 노출 여부를 검토하십시오.',
            `ACAO: ${acao}`, 'Origin 화이트리스트를 적용하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-942', confidence: 'tentative' });
        }
      }

      // [19] HTTP 메서드/TRACE — OPTIONS 로 허용 메서드 확인, TRACE/위험 메서드 노출
      const optResp = await ctx.guard.httpGet(base + '/', { method: 'OPTIONS' });
      if (optResp) {
        const allow = (optResp.headers['allow'] || optResp.headers['access-control-allow-methods'] || '').toUpperCase();
        const risky = ['TRACE', 'TRACK', 'CONNECT', 'DELETE', 'PUT', 'PATCH'].filter((m) => allow.includes(m));
        if (risky.length) {
          findings.push({ ...mk('dast', 'low', `위험 HTTP 메서드 허용: ${risky.join(', ')}`, ctx.asset.value,
            `OPTIONS 응답의 Allow 헤더에 위험 메서드(${risky.join(', ')})가 포함됩니다. TRACE 는 XST, 쓰기 메서드는 변경 위험이 있습니다.`,
            `Allow: ${allow}`, '불필요한 HTTP 메서드(TRACE/TRACK/PUT/DELETE 등)를 비활성화하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-650', confidence: 'firm',
            references: ['https://owasp.org/www-community/attacks/Cross_Site_Tracing'] });
        }
      }

      // [20] 백업/소스/설정 파일 노출 (소프트-404 베이스라인 대비)
      for (const bf of BACKUP_PATHS) {
        const r = await ctx.guard.httpGet(base + bf.path);
        if (r && r.status === 200 && r.body && r.body !== baseBody && bf.sig.test(r.body)) {
          findings.push({ ...mk('dast', 'high', `민감 파일 노출: ${bf.path} (${bf.label})`, ctx.asset.value + bf.path,
            `${bf.label} 파일이 외부에서 접근 가능합니다. 자격증명/소스/설정이 유출될 수 있습니다.`,
            r.body.slice(0, 80).replace(/\s+/g, ' '), '버전관리/백업/설정 파일을 웹 루트에서 제거하고 접근을 차단하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-538', confidence: 'firm',
            references: ['https://owasp.org/www-project-web-security-testing-guide/'] });
        }
      }

      // [21] CSRF 토큰 부재 휴리스틱 (상태변경 폼에 토큰/SameSite 없음)
      if (/<form[^>]*method=["']?post/i.test(root.body)) {
        const hasCsrf = /csrf|_token|authenticity_token|__requestverificationtoken|xsrf/i.test(root.body);
        const sameSite = /;\s*samesite/i.test(setCookie);
        if (!hasCsrf && !sameSite) {
          findings.push({ ...mk('dast', 'low', 'CSRF 방어 부재 가능성(POST 폼에 토큰/SameSite 없음)', ctx.asset.value,
            'POST 폼이 존재하나 CSRF 토큰 필드와 SameSite 쿠키가 모두 확인되지 않습니다.',
            'form[method=post] without csrf token / samesite', 'CSRF 토큰(동기화 토큰)과 SameSite 쿠키를 적용하십시오.'),
            owasp: 'A01:2021', cwe: 'CWE-352', confidence: 'tentative',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'] });
        }
      }

      // [22] Clickjacking — X-Frame-Options / CSP frame-ancestors 부재
      const xfo = root.headers['x-frame-options'] || '';
      const cspH = root.headers['content-security-policy'] || '';
      if (!xfo && !/frame-ancestors/i.test(cspH)) {
        findings.push({ ...mk('dast', 'low', '클릭재킹 방어 부재(X-Frame-Options/frame-ancestors 없음)', ctx.asset.value,
          'X-Frame-Options 헤더와 CSP frame-ancestors 가 모두 없어 iframe 삽입(클릭재킹)이 가능합니다.',
          'no X-Frame-Options / frame-ancestors', "X-Frame-Options: DENY 또는 CSP frame-ancestors 'none' 을 설정하십시오."),
          owasp: 'A05:2021', cwe: 'CWE-1021', confidence: 'firm',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'] });
      }

      // [23] 비밀/토큰 본문 노출 (API 키/JWT/시크릿 패턴)
      const secret = matchSecretLeak(root.body);
      if (secret) {
        findings.push({ ...mk('dast', 'high', `응답 내 비밀정보 노출 가능성: ${secret.label}`, ctx.asset.value,
          `응답 본문에 ${secret.label} 형태의 비밀정보가 노출됩니다. 자격증명 유출 위험이 있습니다.`,
          secret.evidence, '비밀정보를 응답에서 제거하고 노출 시 즉시 폐기/재발급하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-312', confidence: 'tentative',
          references: ['https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url'] });
      }

      // [24] HTTP 파라미터 오염(HPP) — 동일 파라미터 중복 시 동작 차이 반사
      const hpp = await ctx.guard.httpGet(`${base}/?role=user&role=sentinel${rnd()}`);
      if (hpp && hpp.body && hpp.body.includes('sentinel') && !(isCatchAll && hpp.body === baseBody)) {
        findings.push({ ...mk('dast', 'info', 'HTTP 파라미터 오염(HPP) 표면', ctx.asset.value,
          '동일 파라미터를 중복 전달했을 때 마지막 값이 반사됩니다. 파라미터 우선순위 차이를 이용한 우회 가능성을 검토하십시오.',
          'duplicate param last-wins reflected', '서버/프록시 간 파라미터 파싱 일관성을 확보하고 중복 파라미터를 거부하십시오.'),
          owasp: 'A03:2021', cwe: 'CWE-235', confidence: 'tentative' });
      }

      // [25] 캐시 가능 민감 응답 — 인증/개인 페이지에 캐시 허용 헤더
      const cc = (root.headers['cache-control'] || '').toLowerCase();
      if ((/set-cookie/i.test(JSON.stringify(root.headers)) || /logout|account|profile|dashboard/i.test(root.body)) &&
          cc && !/no-store|no-cache|private/.test(cc) && /public|max-age=[1-9]/.test(cc)) {
        findings.push({ ...mk('dast', 'low', '민감 응답 캐시 허용', ctx.asset.value,
          '세션/개인화로 보이는 응답에 공개 캐시가 허용됩니다(프록시/CDN 캐시 누출 위험).',
          `Cache-Control: ${cc}`, '인증/개인 응답에 Cache-Control: no-store, private 를 설정하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-525', confidence: 'tentative' });
      }

      // [26] Mixed content — HTTPS 페이지가 http:// 리소스 참조
      if (ctx.asset.type !== 'host' && /src=["']http:\/\/|href=["']http:\/\//i.test(root.body)) {
        const sample = (root.body.match(/(?:src|href)=["']http:\/\/[^"']{1,60}/i) || [])[0] || '';
        findings.push({ ...mk('dast', 'low', '혼합 콘텐츠(HTTPS 페이지의 평문 HTTP 리소스)', ctx.asset.value,
          'HTTPS 페이지가 평문 HTTP 리소스를 참조하여 중간자 변조/다운그레이드 위험이 있습니다.',
          sample, '모든 리소스를 HTTPS 로 로드하고 CSP upgrade-insecure-requests 를 적용하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-311', confidence: 'firm' });
      }

      // [27] 위험 자바스크립트 라이브러리/인라인 eval 단서 (정보성)
      const jslib = matchJsRisk(root.body);
      if (jslib) {
        findings.push({ ...mk('dast', 'info', `클라이언트측 위험 단서: ${jslib}`, ctx.asset.value,
          `응답에 위험 클라이언트 패턴(${jslib})이 포함됩니다. DOM 기반 XSS 등 추가 검토가 필요합니다.`,
          jslib, '위험 sink(innerHTML/eval/document.write)와 신뢰 입력 흐름을 점검하고 CSP 를 적용하십시오.'),
          owasp: 'A03:2021', cwe: 'CWE-79', confidence: 'tentative' });
      }

      // [28] CSP 부재/취약 (unsafe-inline/unsafe-eval 또는 헤더 자체 부재)
      if (!cspH) {
        findings.push({ ...mk('dast', 'low', 'Content-Security-Policy 헤더 부재', ctx.asset.value,
          'CSP 헤더가 없어 XSS/데이터 인젝션 완화 계층이 부재합니다.',
          'no Content-Security-Policy', '스크립트 출처를 제한하는 CSP 를 단계적으로 도입하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-693', confidence: 'firm',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'] });
      } else if (/unsafe-inline|unsafe-eval/i.test(cspH)) {
        findings.push({ ...mk('dast', 'low', "CSP 약화 지시어 사용(unsafe-inline/unsafe-eval)", ctx.asset.value,
          'CSP 에 unsafe-inline/unsafe-eval 가 포함되어 XSS 완화 효과가 크게 약화됩니다.',
          cspH.slice(0, 100), 'nonce/해시 기반 CSP 로 전환하고 unsafe-inline/eval 을 제거하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-693', confidence: 'firm' });
      }

      // [29] open redirect via Referer/메타 refresh 본문 단서 (정보성)
      if (/<meta[^>]+http-equiv=["']?refresh["']?[^>]+url=https?:\/\//i.test(root.body)) {
        const mr = (root.body.match(/<meta[^>]+refresh[^>]+url=[^"'>]{1,80}/i) || [])[0] || '';
        findings.push({ ...mk('dast', 'info', 'meta refresh 외부 리다이렉트 단서', ctx.asset.value,
          'meta http-equiv=refresh 로 외부 URL 리다이렉트가 설정되어 있습니다. 동적 제어 가능 시 오픈 리다이렉트 위험을 검토하십시오.',
          mr, 'meta refresh 대상이 사용자 입력으로 제어되지 않도록 하십시오.'),
          owasp: 'A01:2021', cwe: 'CWE-601', confidence: 'tentative' });
      }
    }

    // 활성(침투) 검증 — 게이트에서 aggressive + 4-eyes 통과 시에만 true. 취약점을 실제 트리거해 확정(비파괴 한정).
    if (ctx.active) {
      try {
        findings.push(...await runActiveConfirmation(ctx, base, ctx.asset.value, root, baseStatus, baseBody));
      } catch (e) {
        ctx.log(`dast: 활성 검증 오류 — ${(e as Error).message}`);
      }
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

// ───────── 확장 헬퍼/상수 ─────────

/** 오픈 리다이렉트 우회 변형 (EVIL 은 안전 토큰으로 치환). */
const OPEN_REDIRECT_VARIANTS: string[] = [
  '//EVIL', '/\\EVIL', 'https:EVIL', 'https:/EVIL', '/%2f%2fEVIL',
  '%2f%2fEVIL', 'https://EVIL', '\\/\\/EVIL', 'http:\\\\EVIL', '////EVIL',
];

/** 오픈 리다이렉트에 흔히 쓰이는 파라미터명. */
const OPEN_REDIRECT_PARAMS: string[] = [
  'next', 'redirect', 'url', 'return', 'returnUrl', 'dest', 'destination',
  'continue', 'goto', 'returnTo', 'redirect_uri', 'callback', 'r', 'u',
];

/** Host 헤더 오염에 사용되는 프록시 헤더명. */
const FORWARDED_HOST_HEADERS: string[] = [
  'x-forwarded-host', 'x-host', 'x-forwarded-server', 'x-http-host-override', 'forwarded',
];

/** 메타데이터 흔적(확장) 시그니처. */
const MORE_METADATA_RE = /169\.254\.169\.254|metadata\.google\.internal|computeMetadata\/v1|\/latest\/meta-data\/|IMDSv2|Metadata-Flavor|"Token"\s*:\s*"AQ|kubernetes\.default\.svc|\/var\/run\/secrets\/kubernetes/i;

/** 업로드 관련 엔드포인트 후보. */
const UPLOAD_PATHS: string[] = [
  '/upload', '/uploads', '/api/upload', '/file/upload', '/files/upload',
  '/admin/upload', '/media/upload', '/fileupload', '/upload.php', '/upload.aspx',
];

/** 백업/소스/설정 파일 후보 + 콘텐츠 시그니처. */
const BACKUP_PATHS: { path: string; label: string; sig: RegExp }[] = [
  { path: '/.env', label: '환경설정(.env)', sig: /^[A-Z0-9_]+\s*=|APP_KEY|DB_PASSWORD|SECRET|API_KEY/im },
  { path: '/.git/config', label: 'Git 설정', sig: /\[core\]|\[remote |repositoryformatversion/i },
  { path: '/config.php.bak', label: 'PHP 설정 백업', sig: /<\?php|define\(|\$config/i },
  { path: '/web.config.bak', label: 'web.config 백업', sig: /<configuration|<appSettings|connectionString/i },
  { path: '/wp-config.php.bak', label: 'WordPress 설정 백업', sig: /DB_PASSWORD|DB_NAME|wp-settings/i },
  { path: '/backup.sql', label: 'SQL 덤프', sig: /INSERT INTO|CREATE TABLE|DROP TABLE|-- MySQL dump/i },
  { path: '/.htpasswd', label: '.htpasswd', sig: /^[^:\s]+:\$(apr1|2y|1|6)\$/im },
  { path: '/composer.json', label: 'composer.json', sig: /"require"\s*:|"autoload"\s*:/i },
  { path: '/package.json', label: 'package.json', sig: /"dependencies"\s*:|"scripts"\s*:/i },
  { path: '/.DS_Store', label: '.DS_Store', sig: /Bud1|\x00\x00\x00\x01Bud1/ },
];

/** 템플릿 엔진 오류 시그니처(SSTI). */
function matchTemplateError(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/jinja2\.exceptions|TemplateSyntaxError|UndefinedError|jinja2\.Undefined/i, 'Jinja2'],
    [/freemarker\.core|FreeMarker template error|TemplateException/i, 'FreeMarker'],
    [/Twig\\Error|Twig_Error|Unexpected token .* in .* at line/i, 'Twig'],
    [/org\.thymeleaf|TemplateProcessingException/i, 'Thymeleaf'],
    [/Smarty: \[in|SmartyCompilerException/i, 'Smarty'],
    [/velocity\.exception|ParseErrorException/i, 'Velocity'],
    [/nunjucks|Template render error/i, 'Nunjucks'],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}

/** NoSQL/LDAP/XPath 인젝션 오류 시그니처. */
function matchInjectionError(b: string): { kind: string; label: string; cwe: string } | null {
  const rules: { re: RegExp; kind: string; label: string; cwe: string }[] = [
    { re: /MongoError|MongoServerError|BSONError|\$where|MongoDB.*operator/i, kind: 'NoSQL', label: 'MongoDB', cwe: 'CWE-943' },
    { re: /CouchDB|couch.*error|"error"\s*:\s*"query_parse_error"/i, kind: 'NoSQL', label: 'CouchDB', cwe: 'CWE-943' },
    { re: /LDAP: error code \d+|javax\.naming\.directory|InvalidSearchFilterException|com\.sun\.jndi\.ldap/i, kind: 'LDAP', label: 'LDAP', cwe: 'CWE-90' },
    { re: /XPathException|org\.apache\.xpath|Invalid XPath expression|MS\.Internal\.Xml/i, kind: 'XPath', label: 'XPath', cwe: 'CWE-643' },
    { re: /Redis.*ERR|WRONGTYPE Operation/i, kind: 'NoSQL', label: 'Redis', cwe: 'CWE-943' },
  ];
  for (const r of rules) if (r.re.test(b)) return { kind: r.kind, label: r.label, cwe: r.cwe };
  return null;
}

/** 역직렬화 단서 시그니처. */
function matchDeserialization(b: string): { label: string; evidence: string } | null {
  if (/__VIEWSTATE/i.test(b)) return { label: 'ASP.NET ViewState(__VIEWSTATE)', evidence: '__VIEWSTATE 필드 노출' };
  const java = b.match(/rO0AB[A-Za-z0-9+/=]{8,}/);
  if (java) return { label: 'Java 직렬화 객체(base64 rO0AB)', evidence: java[0].slice(0, 40) + '...' };
  const javaHex = b.match(/\xac\xed\x00\x05/);
  if (javaHex) return { label: 'Java 직렬화 매직바이트(0xACED0005)', evidence: 'ACED0005 magic' };
  if (/_serialized|node-serialize|"rce"\s*:|\$\$ND_FUNC\$\$/i.test(b)) return { label: 'Node.js 역직렬화 흔적', evidence: 'node-serialize/$$ND_FUNC$$' };
  const php = b.match(/[aOs]:\d+:\{|[aOs]:\d+:"/);
  if (php && /O:\d+:"[A-Za-z_\\]+":\d+:\{/.test(b)) return { label: 'PHP 직렬화 객체(O:..)', evidence: (php[0] || '').slice(0, 40) };
  return null;
}

/** 명령 실행/셸 오류 시그니처. */
function matchCommandError(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/sh: \d+: .*not found|\/bin\/sh: .*: command not found/i, 'sh'],
    [/'[^']+' is not recognized as an internal or external command/i, 'cmd.exe'],
    [/syntax error near unexpected token/i, 'bash'],
    [/system\(\)|popen\(\)|proc_open|shell_exec.*failed/i, 'PHP exec'],
    [/Cannot run program|java\.io\.IOException.*exec/i, 'Java Runtime.exec'],
    [/os\.system|subprocess\.(Popen|call).*OSError/i, 'Python subprocess'],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}

/** 추가 디버그/프레임워크 내부정보 시그니처(기존 스택트레이스와 비중복). */
function matchDebugSignature(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/APP_DEBUG\s*[:=]\s*true|"debug"\s*:\s*true/i, '디버그 플래그(debug=true)'],
    [/X-Debug-Token|phpdebugbar|symfony-profiler|_profiler/i, 'Symfony Profiler'],
    [/django\.views\.debug|settings\.DEBUG|EXCEPTION_TYPE/i, 'Django DEBUG'],
    [/__debug__|werkzeug|console-enabled/i, 'Werkzeug/Flask'],
    [/whoops-container|Whoops\\Run/i, 'Whoops debugger'],
    [/spring\.profiles\.active|management\.endpoints|"profiles"\s*:\s*\[/i, 'Spring 환경정보'],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}

/** 버전/내부 경로 정보 노출 시그니처. */
function matchVersionLeak(b: string): { label: string; evidence: string } | null {
  const banner = b.match(/(?:Server|X-Powered-By|X-AspNet-Version|X-Generator)["':\s]+([A-Za-z][\w.\-/ ]{2,40}\d[\w.\-/ ]*)/i);
  if (banner) return { label: '서버/프레임워크 버전 배너', evidence: banner[0].slice(0, 80) };
  const path = b.match(/(?:[A-Za-z]:\\[\w\\.$-]{4,80}|\/(?:var|home|usr|opt|srv|app)\/[\w./$-]{4,80})/);
  if (path) return { label: '내부 파일 경로', evidence: path[0].slice(0, 80) };
  return null;
}

/** 내부 절대경로 추출(verbose error 전용). */
function matchInternalPath(b: string): string | null {
  const m = b.match(/(?:[A-Za-z]:\\[\w\\.$-]{4,100}|\/(?:var|home|usr|opt|srv|app|www|data)\/[\w./$-]{4,100})/);
  return m ? m[0].slice(0, 100) : null;
}

/** 비밀/토큰 본문 노출 시그니처(휴리스틱). */
function matchSecretLeak(b: string): { label: string; evidence: string } | null {
  const rules: { re: RegExp; label: string }[] = [
    { re: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key ID' },
    { re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, label: 'JWT' },
    { re: /gh[posru]_[A-Za-z0-9]{30,}/, label: 'GitHub 토큰' },
    { re: /xox[baprs]-[A-Za-z0-9-]{10,}/, label: 'Slack 토큰' },
    { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, label: '개인키(PEM)' },
    { re: /AIza[0-9A-Za-z_-]{35}/, label: 'Google API Key' },
    { re: /sk_live_[0-9a-zA-Z]{24,}/, label: 'Stripe 라이브 키' },
  ];
  for (const r of rules) {
    const m = b.match(r.re);
    if (m) return { label: r.label, evidence: m[0].slice(0, 12) + '…(redacted)' };
  }
  return null;
}

/** 클라이언트측 위험 sink/취약 라이브러리 단서. */
function matchJsRisk(b: string): string | null {
  const rules: [RegExp, string][] = [
    [/\.innerHTML\s*=|document\.write\s*\(|eval\s*\(|new Function\s*\(/i, '위험 sink(innerHTML/eval/document.write)'],
    [/jquery[.-]1\.\d|jquery[.-]2\.[01]/i, '구버전 jQuery'],
    [/angular\.js\/1\.[0-5]\.|AngularJS/i, '구버전 AngularJS'],
    [/location\.hash|location\.href\s*=\s*[^;]*location/i, 'DOM 기반 리다이렉트 단서'],
    [/postMessage\([^,]+,\s*["']\*["']\)/i, "postMessage 와일드카드 origin"],
  ];
  for (const [re, name] of rules) if (re.test(b)) return name;
  return null;
}
