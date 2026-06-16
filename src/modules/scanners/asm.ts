/**
 * 공격표면관리 (ASM) — 설계 §4.1.
 * 서브도메인 열거, 노출 자산/오픈 포트 핑거프린팅, 인증서 만료·체인 검증,
 * Shadow IT/미관리 자산·클라우드 노출 식별. 모든 동작은 비파괴(connect-only/읽기).
 */
import { id, now } from '../../util.js';
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { PORT_SERVICE, STANDARD_PORTS, DEEP_PORTS } from './types.js';

/** passive DNS / CT 로그 기반 서브도메인 후보 (대상에 직접 트래픽 미발생). */
const SUBDOMAIN_WORDLIST = ['www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'vpn', 'gw', 'git', 'jenkins', 'portal', 'beta', 'old', 'backup'];
/** 심층 점검용 확장 서브도메인 사전. */
const SUBDOMAIN_DEEP = [...SUBDOMAIN_WORDLIST,
  'm', 'mobile', 'app', 'apps', 'cdn', 'static', 'assets', 'img', 'media', 'files', 'download', 'upload',
  'auth', 'sso', 'login', 'oauth', 'id', 'account', 'secure', 'pay', 'payment', 'billing',
  'dashboard', 'console', 'manage', 'cpanel', 'webmail', 'smtp', 'imap', 'pop', 'ns1', 'ns2', 'mx',
  'db', 'sql', 'mysql', 'redis', 'mongo', 'elastic', 'kibana', 'grafana', 'prometheus', 'status', 'health',
  'ci', 'cd', 'gitlab', 'github', 'jira', 'confluence', 'wiki', 'docs', 'support', 'help', 'blog', 'shop', 'store',
  'demo', 'sandbox', 'uat', 'qa', 'preprod', 'prod', 'internal', 'intranet', 'corp', 'vpn2', 's3', 'storage'];
/** 심층 DKIM 셀렉터 후보. */
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim', 's1', 's2', 'mandrill', 'mailjet'];
/** 서브도메인 탈취 가능 SaaS CNAME 지문. */
const TAKEOVER_FINGERPRINTS = ['github.io', 'herokuapp.com', 's3.amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'cname.vercel-dns.com', 'netlify.app', 'pages.dev', 'fastly.net', 'wpengine.com', 'ghost.io', 'surge.sh', 'bitbucket.io', 'readthedocs.io'];

const DANGEROUS_PORTS = new Set([21, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2379, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);

export const asmScanner: Scanner = {
  module: 'asm',
  minIntensity: 'passive',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const host = ctx.asset.value;

    // 1) 서브도메인 열거 (설계 §4.1) — 후보를 DNS 로 확인, 범위 내 자산만 인벤토리화
    if (ctx.asset.type === 'domain') {
      const wordlist = ctx.deep ? SUBDOMAIN_DEEP : SUBDOMAIN_WORDLIST;
      const discovered: { sub: string; ip: string; cname?: string }[] = [];
      for (const w of wordlist) {
        const sub = `${w}.${host}`;
        const addrs = await ctx.guard.resolveDns(sub);
        if (addrs.length) {
          const entry: { sub: string; ip: string; cname?: string } = { sub, ip: addrs[0]! };
          if (ctx.deep) {
            const cn = await ctx.guard.resolveCname(sub);
            if (cn.length) entry.cname = cn[0];
          }
          discovered.push(entry);
        }
      }
      if (discovered.length) {
        findings.push(mk('asm', 'info', `서브도메인 ${discovered.length}건 식별`, host,
          `passive DNS 기반 노출 서브도메인 인벤토리.`, discovered.map((d) => `${d.sub} (${d.ip})${d.cname ? ` → ${d.cname}` : ''}`).join('\n'),
          '불필요/미관리(Shadow IT) 서브도메인은 폐기하거나 접근통제를 적용하십시오.'));
      }

      // 심층: 서브도메인 탈취 가능성 (dangling CNAME → 미점유 SaaS)
      if (ctx.deep) {
        for (const d of discovered) {
          if (!d.cname) continue;
          const fp = TAKEOVER_FINGERPRINTS.find((f) => d.cname!.includes(f));
          if (fp && !(await ctx.guard.resolveDns(d.sub)).length) {
            findings.push(mk('asm', 'high', `서브도메인 탈취 가능성: ${d.sub}`, d.sub,
              `CNAME(${d.cname})이 미점유 SaaS(${fp})를 가리켜 공격자가 해당 리소스를 선점·탈취할 수 있습니다.`,
              `CNAME=${d.cname}`, '미사용 CNAME 레코드를 제거하거나 대상 리소스를 재점유하십시오.'));
          }
        }
        // 심층: NS/SOA/MX 인벤토리
        const ns = await ctx.guard.resolveDns(host).catch(() => []);
        if (ns) { /* A 레코드는 위에서 처리 */ }
      }

      // 이메일/DNS 보안 자세 (스푸핑 방지) — 비파괴 DNS 조회
      const txt = await ctx.guard.resolveTxt(host);
      const spf = txt.find((r) => r.toLowerCase().startsWith('v=spf1'));
      if (!spf) {
        findings.push(mk('asm', 'medium', 'SPF 레코드 미설정 (이메일 스푸핑 위험)', host,
          '발신 도메인 인증(SPF)이 없어 공격자가 해당 도메인을 사칭한 메일을 보낼 수 있습니다.', 'no v=spf1 TXT',
          'SPF TXT 레코드를 설정하고 마지막을 -all(hardfail)로 마감하십시오.'));
      } else {
        if (spf.includes('+all')) {
          findings.push(mk('asm', 'high', 'SPF +all (전체 허용 — 스푸핑 무방비)', host, 'SPF 가 모든 발신을 허용하여 사실상 보호가 없습니다.', spf.slice(0, 160), 'SPF 를 -all(hardfail)로 교체하십시오.'));
        } else if (/[?~]all\s*$/.test(spf)) {
          findings.push(mk('asm', 'low', 'SPF 정책이 느슨함(softfail/neutral)', host, 'SPF 가 ~all/?all 로 끝나 차단이 약합니다.', spf.slice(0, 160), 'SPF 를 -all 로 강화하십시오.'));
        }
        // 심층: RFC 7208 §4.6.4 — DNS 룩업 10회 초과 시 PermError → SPF 무력화
        if (ctx.deep) {
          const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/g) || []).length;
          if (lookups > 10) {
            findings.push(mk('asm', 'medium', `SPF DNS 룩업 초과 (${lookups} > 10, PermError 유발)`, host,
              'RFC 7208 의 10회 DNS 룩업 한도를 초과하면 검증기가 PermError 로 처리해 SPF 가 무력화됩니다.', `lookups=${lookups}`,
              'include 평탄화(flattening)로 DNS 룩업 수를 10 이하로 줄이십시오.'));
          }
        }
      }
      const dmarc = (await ctx.guard.resolveTxt(`_dmarc.${host}`)).find((r) => r.toLowerCase().includes('v=dmarc1'));
      if (!dmarc) {
        findings.push(mk('asm', 'medium', 'DMARC 레코드 미설정', host,
          'DMARC 정책이 없어 스푸핑 메일에 대한 처리·리포팅이 동작하지 않습니다.', 'no _dmarc TXT',
          '_dmarc TXT 에 v=DMARC1; p=quarantine|reject; rua=... 를 설정하십시오.'));
      } else {
        if (/p=none/i.test(dmarc)) {
          findings.push(mk('asm', 'low', 'DMARC 정책이 모니터링(p=none)', host, '스푸핑 메일을 탐지만 하고 차단하지 않습니다.', dmarc.slice(0, 160), 'DMARC 정책을 p=quarantine 또는 p=reject 로 상향하십시오.'));
        }
        if (ctx.deep) {
          // 서브도메인 정책(sp=) 부재 → 서브도메인 스푸핑 우회
          if (!/sp=/i.test(dmarc) && /p=(quarantine|reject)/i.test(dmarc)) {
            findings.push(mk('asm', 'low', 'DMARC 서브도메인 정책(sp=) 부재', host, 'sp= 가 없으면 서브도메인이 상위 p 정책을 상속하지 않아 서브도메인 스푸핑 우회가 가능할 수 있습니다.', dmarc.slice(0, 160), 'sp=reject 를 명시하십시오.'));
          }
          // 정렬 모드 relaxed (aspf/adkim = r 또는 미지정)
          if (/aspf=r|adkim=r/i.test(dmarc) || (!/aspf=/i.test(dmarc) && /p=(quarantine|reject)/i.test(dmarc))) {
            findings.push(mk('asm', 'info', 'DMARC 정렬(alignment) relaxed', host, 'relaxed 정렬은 strict 대비 우회 여지가 넓습니다.', dmarc.slice(0, 160), '민감 도메인은 aspf=s; adkim=s (strict) 적용을 검토하십시오.'));
          }
          if (!/rua=/i.test(dmarc)) {
            findings.push(mk('asm', 'info', 'DMARC 집계 리포트(rua) 미설정', host, '리포트 수신이 없으면 스푸핑 시도를 가시화할 수 없습니다.', dmarc.slice(0, 160), 'rua=mailto:... 를 설정하십시오.'));
          }
        }
      }
      const caa = await ctx.guard.resolveCaa(host);
      if (!caa.length) {
        findings.push(mk('asm', 'info', 'CAA 레코드 미설정', host, '인증서 발급 기관을 제한하는 CAA 가 없어 무단 인증서 발급 위험이 있습니다.', 'no CAA',
          'CAA 레코드로 신뢰 CA 만 발급 가능하도록 제한하십시오.'));
      }

      // 심층: DKIM 정밀 · MTA-STS · TLS-RPT · IPv6 · NS SPOF
      if (ctx.deep) {
        let dkim: string | undefined; let dkimSel = '';
        for (const sel of DKIM_SELECTORS) {
          const rec = await ctx.guard.resolveTxt(`${sel}._domainkey.${host}`);
          const found = rec.find((r) => /v=DKIM1|p=/.test(r));
          if (found) { dkim = found; dkimSel = sel; break; }
        }
        const mx = await ctx.guard.resolveMx(host);
        if (mx.length && !dkim) {
          findings.push(mk('asm', 'low', 'DKIM 서명 미탐지 (메일 사용 도메인)', host, 'MX 가 있으나 표준 셀렉터에서 DKIM 키를 찾지 못했습니다.', `MX=${mx.map((m) => m.exchange).join(',')}`, 'DKIM 서명을 설정하십시오.'));
        }
        if (dkim) {
          if (/t=y/i.test(dkim)) findings.push(mk('asm', 'low', `DKIM 테스트 모드(t=y): ${dkimSel}`, host, 'DKIM 이 테스트 모드라 수신측이 검증을 강제하지 않습니다.', dkim.slice(0, 120), 't=y 플래그를 제거하십시오.'));
          if (/rsa-sha1|a=.*sha1/i.test(dkim)) findings.push(mk('asm', 'low', `DKIM 약한 해시(sha1): ${dkimSel}`, host, 'SHA-1 서명은 충돌 위험이 있습니다.', dkim.slice(0, 120), 'rsa-sha256 으로 재발급하십시오.'));
        }
        // MTA-STS
        const mtaSts = await ctx.guard.httpGet(`https://mta-sts.${host}/.well-known/mta-sts.txt`);
        if (mx.length) {
          if (!mtaSts || mtaSts.status !== 200 || !/version:\s*STSv1/i.test(mtaSts.body)) {
            findings.push(mk('asm', 'info', 'MTA-STS 미설정', host, 'SMTP 전송 구간 TLS 다운그레이드 공격을 막는 MTA-STS 정책이 없습니다.', `status=${mtaSts?.status ?? '-'}`, '/.well-known/mta-sts.txt 에 mode: enforce 정책을 게시하십시오.'));
          } else if (/mode:\s*testing/i.test(mtaSts.body)) {
            findings.push(mk('asm', 'info', 'MTA-STS 모드가 testing', host, 'testing 모드는 강제하지 않습니다.', mtaSts.body.slice(0, 120), 'mode: enforce 로 전환하십시오.'));
          }
          // TLS-RPT
          const tlsrpt = (await ctx.guard.resolveTxt(`_smtp._tls.${host}`)).find((r) => /v=TLSRPTv1/i.test(r));
          if (!tlsrpt) findings.push(mk('asm', 'info', 'TLS-RPT 미설정', host, 'SMTP TLS 실패 리포팅(TLS-RPT)이 없습니다.', 'no _smtp._tls TXT', '_smtp._tls TXT 에 v=TLSRPTv1; rua=... 를 설정하십시오.'));
        }
        // IPv6 그림자 자산 (IPv4만 보호하고 IPv6 노출 비대칭)
        const aaaa = await ctx.guard.resolve6(host);
        if (aaaa.length) {
          findings.push(mk('asm', 'info', `IPv6(AAAA) 노출 — 보호 비대칭 점검 필요`, host, 'IPv6 주소가 노출되어 있습니다. IPv4와 동일한 방화벽/접근통제가 적용되는지 확인이 필요합니다.', `AAAA=${aaaa.slice(0, 3).join(', ')}`, 'IPv6에도 IPv4와 동등한 보안 통제를 적용하십시오.'));
        }
        // NS SPOF (단일 DNS 사업자 의존)
        const ns = await ctx.guard.resolveNs(host);
        if (ns.length) {
          const providers = new Set(ns.map((n) => n.split('.').slice(-2).join('.').toLowerCase()));
          if (providers.size === 1) {
            findings.push(mk('asm', 'info', `단일 DNS 사업자 의존(SPOF): ${[...providers][0]}`, host, '모든 NS 가 단일 사업자라 해당 사업자 장애 시 도메인 전체 가용성에 영향이 있습니다.', `NS=${ns.join(', ')}`, '복수 DNS 사업자(secondary DNS)로 이중화를 검토하십시오.'));
          }
        }
      }
    }

    // passive 프로파일은 대상에 트래픽을 발생시키지 않으므로 능동 포트/TLS 점검 생략
    if (ctx.intensity === 'passive') {
      ctx.log('ASM passive: DNS/공개정보 기반 인벤토리만 수행');
      return findings;
    }

    // 2) 오픈 포트·서비스 핑거프린팅 (비파괴 connect-only) — 심층은 확장 포트 전수
    const ports = ctx.deep ? DEEP_PORTS : (ctx.allowedPorts.length ? ctx.allowedPorts : STANDARD_PORTS);
    const open: number[] = [];
    for (const p of ports) {
      if (await ctx.guard.tcpProbe(host, p)) open.push(p);
    }
    if (open.length) {
      findings.push(mk('asm', 'low', `오픈 포트 ${open.length}개 탐지`, host,
        '외부 노출 포트 및 서비스 핑거프린트.', open.map((p) => `${p}/${PORT_SERVICE[p] ?? 'unknown'}`).join(', '),
        '불필요한 포트는 방화벽으로 차단하고 관리 포트는 VPN/허용목록으로 제한하십시오.'));
    }
    for (const p of open) {
      if (DANGEROUS_PORTS.has(p)) {
        findings.push(mk('asm', 'high', `민감 서비스 포트 외부 노출: ${p}/${PORT_SERVICE[p]}`, `${host}:${p}`,
          `데이터베이스/원격관리/파일공유 등 민감 서비스가 외부에 직접 노출되어 있습니다.`,
          `port=${p} service=${PORT_SERVICE[p]}`,
          '해당 서비스는 인터넷에 직접 노출하지 말고 사설망/배스천을 경유하도록 구성하십시오.'));
      }
    }

    // 3) 인증서 만료·프로토콜 검증 (설계 §4.1)
    if (open.includes(443) || ctx.asset.type !== 'host') {
      const tlsInfo = await ctx.guard.tlsInspect(host, 443);
      if (tlsInfo) {
        if (tlsInfo.daysToExpiry !== null && tlsInfo.daysToExpiry < 30) {
          const sev = tlsInfo.daysToExpiry < 0 ? 'critical' : 'medium';
          findings.push(mk('asm', sev as Finding['severity'],
            tlsInfo.daysToExpiry < 0 ? 'TLS 인증서 만료됨' : `TLS 인증서 만료 임박 (${tlsInfo.daysToExpiry}일)`, host,
            `CN=${tlsInfo.subject ?? '?'} 만료일=${tlsInfo.validTo}`, `protocol=${tlsInfo.protocol}`,
            '인증서를 갱신하고 자동 갱신(ACME 등) 파이프라인을 구성하십시오.'));
        }
        // 취약 프로토콜 버전 (TLSv1.0/1.1 은 PCI-DSS 등에서 금지)
        if (tlsInfo.protocol && /TLSv1(\.0|\.1)?$/.test(tlsInfo.protocol)) {
          findings.push(mk('asm', 'medium', `취약 TLS 프로토콜 사용: ${tlsInfo.protocol}`, host,
            'TLS 1.0/1.1 은 알려진 약점이 있어 표준에서 폐기되었습니다.', `negotiated=${tlsInfo.protocol}`,
            'TLS 1.2 이상만 허용하고 1.0/1.1 을 비활성화하십시오.'));
        }
      }
    }

    return findings;
  },
};

export function mk(
  module: Finding['module'], severity: Finding['severity'], title: string,
  target: string, description: string, evidence?: string, remediation?: string,
): Finding {
  return { id: id('fnd'), module, severity, title, target, description, evidence, remediation };
}

export const _now = now;
