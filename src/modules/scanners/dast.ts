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
    }

    return findings;
  },
};
