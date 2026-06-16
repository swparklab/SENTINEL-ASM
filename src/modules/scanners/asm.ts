/**
 * 공격표면관리 (ASM) — 설계 §4.1 (전문 확장판).
 * 서브도메인 열거(워드리스트+인증서 SAN), 와일드카드 DNS 보정, 사설IP 노출,
 * 오픈 포트·배너 그랩·무인증 데이터스토어 단서, 이메일/DNS 정밀(SPF·DMARC·DKIM·SOA·SRV·
 * CAA·NS/CNAME 위생·PTR·MX), TLS 전수 점검(버전 매트릭스·약한 암호·인증서 위생).
 * 모든 동작은 비파괴(connect-only/읽기전용 명령/핸드셰이크).
 */
import { id, now } from '../../util.js';
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { PORT_SERVICE, STANDARD_PORTS, DEEP_PORTS } from './types.js';
import { CVE_FEED, lessThan } from './feed.js';

const SUBDOMAIN_WORDLIST = ['www', 'mail', 'api', 'dev', 'staging', 'test', 'admin', 'vpn', 'gw', 'git', 'jenkins', 'portal', 'beta', 'old', 'backup'];
const SUBDOMAIN_DEEP = [...SUBDOMAIN_WORDLIST,
  'm', 'mobile', 'app', 'apps', 'cdn', 'static', 'assets', 'img', 'media', 'files', 'download', 'upload',
  'auth', 'sso', 'login', 'oauth', 'id', 'account', 'secure', 'pay', 'payment', 'billing',
  'dashboard', 'console', 'manage', 'cpanel', 'webmail', 'smtp', 'imap', 'pop', 'ns1', 'ns2', 'mx',
  'db', 'sql', 'mysql', 'redis', 'mongo', 'elastic', 'kibana', 'grafana', 'prometheus', 'status', 'health',
  'ci', 'cd', 'gitlab', 'github', 'jira', 'confluence', 'wiki', 'docs', 'support', 'help', 'blog', 'shop', 'store',
  'demo', 'sandbox', 'uat', 'qa', 'preprod', 'prod', 'internal', 'intranet', 'corp', 'vpn2', 's3', 'storage'];
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim', 's1', 's2', 'mandrill', 'mailjet'];
const TAKEOVER_FINGERPRINTS = ['github.io', 'herokuapp.com', 's3.amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'cname.vercel-dns.com', 'netlify.app', 'pages.dev', 'fastly.net', 'wpengine.com', 'ghost.io', 'surge.sh', 'bitbucket.io', 'readthedocs.io'];
const SRV_LABELS = ['_sip._tcp', '_sips._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp', '_ldap._tcp', '_kerberos._tcp', '_kerberos._udp', '_autodiscover._tcp', '_imaps._tcp', '_submission._tcp', '_gc._tcp', '_vlmcs._tcp'];
const SAAS_TXT = [['google-site-verification', 'Google'], ['ms=', 'Microsoft 365'], ['facebook-domain-verification', 'Facebook'], ['atlassian-domain-verification', 'Atlassian'], ['docusign', 'DocuSign'], ['stripe-verification', 'Stripe'], ['_github-challenge', 'GitHub'], ['adobe-idp-site-verification', 'Adobe'], ['zoom', 'Zoom']];

const DANGEROUS_PORTS = new Set([21, 23, 135, 139, 445, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379, 3306, 3389, 4369, 5432, 5900, 5984, 6379, 6443, 8086, 8500, 9042, 9200, 9300, 10250, 11211, 15672, 25672, 27017]);
/** connect 후 서버가 먼저 배너를 보내는 포트 (배너 그랩 대상). */
const BANNER_PORTS = new Set([21, 22, 25, 110, 143, 587]);

export const asmScanner: Scanner = {
  module: 'asm',
  minIntensity: 'passive',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const host = ctx.asset.value;

    if (ctx.asset.type === 'domain') {
      // 와일드카드 DNS 탐지 — 임의 라벨이 응답하면 catch-all (열거 오탐 베이스라인)
      let wildcardIps: Set<string> | null = null;
      if (ctx.deep) {
        const probes = await Promise.all([0, 1, 2].map((i) => ctx.guard.resolveDns(`zzq8x7w-nope${i}-${Math.random().toString(36).slice(2, 8)}.${host}`)));
        const flat = probes.flat();
        if (flat.length) {
          wildcardIps = new Set(flat);
          findings.push(mk('asm', 'info', '와일드카드 DNS(catch-all) 설정', host, '임의 서브도메인이 모두 응답합니다. 피싱·쿠키 범위 오염·열거 오탐의 원인이 됩니다.', `wildcard→${[...wildcardIps].slice(0, 3).join(', ')}`, '와일드카드 레코드 사용을 최소화하고 명시적 레코드를 사용하십시오.'));
        }
      }

      // 서브도메인 열거 (워드리스트)
      const wordlist = ctx.deep ? SUBDOMAIN_DEEP : SUBDOMAIN_WORDLIST;
      const discovered: { sub: string; ip: string; cname?: string }[] = [];
      for (const w of wordlist) {
        const sub = `${w}.${host}`;
        const addrs = await ctx.guard.resolveDns(sub);
        if (!addrs.length) continue;
        if (wildcardIps && addrs.every((a) => wildcardIps!.has(a))) continue; // 와일드카드 응답 제외
        const entry: { sub: string; ip: string; cname?: string } = { sub, ip: addrs[0]! };
        if (ctx.deep) { const cn = await ctx.guard.resolveCname(sub); if (cn.length) entry.cname = cn[0]; }
        discovered.push(entry);
      }

      // 인증서 SAN 마이닝 — 워드리스트로 못 찾은 서브도메인 추가 발견
      if (ctx.deep) {
        const tlsApex = await ctx.guard.tlsInspect(host, 443);
        const sans = (tlsApex?.san || []).filter((s) => s && !s.startsWith('*'));
        const extra = sans.filter((s) => s !== host && s.endsWith('.' + host) && !discovered.some((d) => d.sub === s));
        for (const s of extra.slice(0, 20)) {
          const addrs = await ctx.guard.resolveDns(s);
          if (addrs.length && !(wildcardIps && addrs.every((a) => wildcardIps!.has(a)))) discovered.push({ sub: s, ip: addrs[0]! });
        }
        const foreign = (tlsApex?.san || []).filter((s) => s && !s.startsWith('*') && s !== host && !s.endsWith('.' + host));
        if (foreign.length) findings.push(mk('asm', 'info', `공유 인증서 — 무관 도메인 ${foreign.length}건 SAN 포함`, host, '한 인증서에 다른 조직 도메인이 함께 들어있어 인프라 상관/공유 호스팅이 드러납니다.', `SAN=${foreign.slice(0, 6).join(', ')}`, '도메인별 분리 인증서 사용을 검토하십시오.'));
      }

      if (discovered.length) {
        findings.push(mk('asm', 'info', `서브도메인 ${discovered.length}건 식별`, host, 'passive DNS/인증서 SAN 기반 노출 서브도메인 인벤토리.', discovered.map((d) => `${d.sub} (${d.ip})${d.cname ? ` → ${d.cname}` : ''}`).join('\n'), '불필요/미관리(Shadow IT) 서브도메인은 폐기하거나 접근통제를 적용하십시오.'));
      }

      // 공개 DNS 의 사설 IP 노출 (apex + 서브도메인)
      const apexA = await ctx.guard.resolveDns(host);
      const apexAAAA = await ctx.guard.resolve6(host);
      const privateHits: string[] = [];
      for (const ip of [...apexA, ...apexAAAA]) if (isPrivateIp(ip)) privateHits.push(`${host}→${ip}`);
      for (const d of discovered) if (isPrivateIp(d.ip)) privateHits.push(`${d.sub}→${d.ip}`);
      if (privateHits.length) {
        findings.push(mk('asm', 'medium', '공개 DNS 에 사설 IP 노출', host, '공개 DNS 레코드가 사설/내부 IP(RFC1918 등)를 가리켜 내부 토폴로지 누출 및 DNS rebinding 표적이 됩니다.', privateHits.slice(0, 8).join('\n'), '내부 IP 는 공개 DNS 에 게시하지 말고 분할 DNS(split-horizon)를 사용하십시오.'));
      }

      // 서브도메인 탈취 + CNAME 체인 위생
      if (ctx.deep) {
        for (const d of discovered) {
          if (!d.cname) continue;
          const fp = TAKEOVER_FINGERPRINTS.find((f) => d.cname!.includes(f));
          if (fp && !(await ctx.guard.resolveDns(d.cname!)).length) {
            findings.push(mk('asm', 'high', `서브도메인 탈취 가능성: ${d.sub}`, d.sub, `CNAME(${d.cname})이 미점유 SaaS(${fp})를 가리켜 공격자가 선점·탈취할 수 있습니다.`, `CNAME=${d.cname}`, '미사용 CNAME 레코드를 제거하거나 대상 리소스를 재점유하십시오.'));
          }
        }
      }

      // 이메일/DNS 보안 자세
      const txt = await ctx.guard.resolveTxt(host);
      const spfRecords = txt.filter((r) => r.toLowerCase().startsWith('v=spf1'));
      const spf = spfRecords[0];
      if (!spf) {
        findings.push(mk('asm', 'medium', 'SPF 레코드 미설정 (이메일 스푸핑 위험)', host, '발신 도메인 인증(SPF)이 없어 도메인 사칭 메일이 가능합니다.', 'no v=spf1 TXT', 'SPF TXT 를 설정하고 -all 로 마감하십시오.'));
      } else {
        if (spf.includes('+all')) findings.push(mk('asm', 'high', 'SPF +all (전체 허용 — 스푸핑 무방비)', host, 'SPF 가 모든 발신을 허용해 사실상 보호가 없습니다.', spf.slice(0, 160), 'SPF 를 -all 로 교체하십시오.'));
        else if (/[?~]all\s*$/.test(spf)) findings.push(mk('asm', 'low', 'SPF 정책이 느슨함(softfail/neutral)', host, 'SPF 가 ~all/?all 로 끝나 차단이 약합니다.', spf.slice(0, 160), 'SPF 를 -all 로 강화하십시오.'));
        if (ctx.deep) {
          if (spfRecords.length > 1) findings.push(mk('asm', 'medium', 'SPF 레코드 중복 (PermError)', host, 'v=spf1 TXT 가 2개 이상이면 RFC7208 상 PermError 로 SPF 가 무력화됩니다.', `${spfRecords.length}개`, 'SPF TXT 를 하나로 통합하십시오.'));
          const lookups = (spf.match(/\b(include|a|mx|ptr|exists|redirect)[:=]/g) || []).length;
          if (lookups > 10) findings.push(mk('asm', 'medium', `SPF DNS 룩업 초과 (${lookups} > 10, PermError)`, host, '10회 DNS 룩업 한도 초과 시 PermError 로 SPF 가 무력화됩니다.', `lookups=${lookups}`, 'include 평탄화로 룩업을 10 이하로 줄이십시오.'));
          if (/\bptr[:\s]/i.test(spf)) findings.push(mk('asm', 'low', 'SPF ptr 메커니즘 사용(폐기 권고)', host, 'ptr 메커니즘은 느리고 신뢰할 수 없어 사용이 권고되지 않습니다.', spf.slice(0, 160), 'ptr 대신 ip4/ip6/include 를 사용하십시오.'));
        }
      }
      const dmarc = (await ctx.guard.resolveTxt(`_dmarc.${host}`)).find((r) => r.toLowerCase().includes('v=dmarc1'));
      if (!dmarc) {
        findings.push(mk('asm', 'medium', 'DMARC 레코드 미설정', host, 'DMARC 가 없어 스푸핑 처리·리포팅이 동작하지 않습니다.', 'no _dmarc TXT', '_dmarc TXT 에 v=DMARC1; p=quarantine|reject; rua=... 설정.'));
      } else {
        if (/p=none/i.test(dmarc)) findings.push(mk('asm', 'low', 'DMARC 정책이 모니터링(p=none)', host, '스푸핑을 탐지만 하고 차단하지 않습니다.', dmarc.slice(0, 160), 'p=quarantine/reject 로 상향하십시오.'));
        if (ctx.deep) {
          if (!/sp=/i.test(dmarc) && /p=(quarantine|reject)/i.test(dmarc)) findings.push(mk('asm', 'low', 'DMARC 서브도메인 정책(sp=) 부재', host, 'sp= 가 없으면 서브도메인 스푸핑 우회가 가능합니다.', dmarc.slice(0, 160), 'sp=reject 를 명시하십시오.'));
          if (/aspf=r|adkim=r/i.test(dmarc) || (!/aspf=/i.test(dmarc) && /p=(quarantine|reject)/i.test(dmarc))) findings.push(mk('asm', 'info', 'DMARC 정렬(alignment) relaxed', host, 'relaxed 정렬은 strict 대비 우회 여지가 넓습니다.', dmarc.slice(0, 160), '민감 도메인은 aspf=s; adkim=s 검토.'));
          if (!/rua=/i.test(dmarc)) findings.push(mk('asm', 'info', 'DMARC 집계 리포트(rua) 미설정', host, '리포트 수신이 없으면 스푸핑 시도를 가시화할 수 없습니다.', dmarc.slice(0, 160), 'rua=mailto:... 설정.'));
          const pct = (dmarc.match(/pct=(\d+)/i) || [])[1];
          if (pct && Number(pct) < 100) findings.push(mk('asm', 'info', `DMARC 부분 적용(pct=${pct})`, host, '일부 메일에만 정책이 적용됩니다.', dmarc.slice(0, 160), 'pct=100 으로 전체 적용하십시오.'));
        }
      }
      const caa = await ctx.guard.resolveCaa(host);
      if (!caa.length) findings.push(mk('asm', 'info', 'CAA 레코드 미설정', host, '발급 CA 를 제한하는 CAA 가 없어 무단 인증서 발급 위험이 있습니다.', 'no CAA', 'CAA 로 신뢰 CA 만 발급 가능하도록 제한하십시오.'));

      // 심층 DNS 위생: SOA / SRV / NS dangling / TXT 마이닝 / PTR / MX
      if (ctx.deep) {
        // SOA
        const soa = await ctx.guard.resolveSoa(host);
        const nsList = await ctx.guard.resolveNs(host);
        if (soa) {
          if (nsList.length && !nsList.map((n) => n.toLowerCase().replace(/\.$/, '')).includes(soa.nsname.toLowerCase().replace(/\.$/, ''))) {
            findings.push(mk('asm', 'low', 'SOA primary(MNAME)가 NS 집합에 없음(stealth/불일치)', host, 'SOA MNAME 이 위임 NS 와 불일치하여 stealth primary 또는 설정 오류 신호입니다.', `MNAME=${soa.nsname} NS=${nsList.join(',')}`, 'SOA MNAME 과 NS 위임을 일치시키십시오.'));
          }
          if (soa.expire < soa.refresh) findings.push(mk('asm', 'low', 'SOA expire < refresh (가용성 위험)', host, 'secondary 만료 값이 비정상적이라 영역 가용성에 영향이 있습니다.', `refresh=${soa.refresh} expire=${soa.expire}`, 'SOA 타이머를 권장값으로 조정하십시오.'));
        }
        // dangling NS
        if (nsList.length === 0) findings.push(mk('asm', 'medium', 'NS 위임 조회 실패(lame delegation 단서)', host, 'NS 레코드를 확인할 수 없어 위임 구성 오류 가능성이 있습니다.', 'resolveNs empty', 'DNS 위임 구성을 점검하십시오.'));
        let danglingNs = 0;
        for (const ns of nsList) { if (!(await ctx.guard.resolveDns(ns)).length && !(await ctx.guard.resolve6(ns)).length) danglingNs++; }
        if (danglingNs > 0) findings.push(mk('asm', danglingNs === nsList.length ? 'high' : 'low', `Dangling NS ${danglingNs}/${nsList.length}건 (영역 하이재킹 위험)`, host, '위임 NS 호스트가 해석되지 않아 공격자가 NS 호스트명을 선점하면 영역을 탈취할 수 있습니다.', `NS=${nsList.join(', ')}`, '미해석 NS 위임을 제거하거나 NS 호스트를 복구하십시오.'));
        // SRV 디스커버리
        const srvHits: string[] = [];
        for (const lbl of SRV_LABELS) { const r = await ctx.guard.resolveSrv(`${lbl}.${host}`); if (r.length) srvHits.push(`${lbl}→${r[0]!.name}:${r[0]!.port}`); }
        if (srvHits.length) findings.push(mk('asm', /_ldap|_kerberos|_gc/.test(srvHits.join()) ? 'low' : 'info', `SRV 서비스 디스커버리 노출 ${srvHits.length}건`, host, '_ldap/_kerberos/_gc 등 SRV 노출은 내부 AD/협업 인프라 토폴로지를 드러냅니다.', srvHits.join('\n'), '불필요한 SRV 공개를 제한하십시오.'));
        // TXT 마이닝
        const saas = SAAS_TXT.filter(([k]) => txt.some((r) => r.toLowerCase().includes(k!.toLowerCase()))).map(([, n]) => n);
        if (saas.length >= 3) findings.push(mk('asm', 'info', `SaaS 검증 토큰 다수(${saas.length}) — 공급망 표면`, host, 'TXT 의 SaaS 검증 토큰으로 사용 중인 외부 서비스가 드러납니다.', saas.join(', '), '미사용 검증 토큰 TXT 를 정리하십시오.'));
        // MX 위생 (null MX = 메일 미사용 의도 → 제외)
        const mxAll = await ctx.guard.resolveMx(host);
        const nullMx = mxAll.some((m) => !m.exchange || m.exchange === '.');
        const mx = mxAll.filter((m) => m.exchange && m.exchange !== '.');
        for (const m of mx) {
          const mxip = [...(await ctx.guard.resolveDns(m.exchange)), ...(await ctx.guard.resolve6(m.exchange))];
          if (mxip.some(isPrivateIp)) findings.push(mk('asm', 'medium', `MX 호스트가 사설 IP: ${m.exchange}`, host, 'MX 가 사설 IP 로 해석되어 내부 노출/전달성 문제가 있습니다.', mxip.filter(isPrivateIp).join(','), '메일 게이트웨이를 공인 IP/사설망 분리로 구성하십시오.'));
          else if (!mxip.length) findings.push(mk('asm', 'low', `MX 호스트 미해석: ${m.exchange}`, host, 'MX 대상이 해석되지 않아 메일 수신 결함 가능성이 있습니다.', m.exchange, 'MX 대상 레코드를 점검하십시오.'));
        }
        if (nullMx && !mx.length) ctx.log('asm: null MX(메일 미사용) — 메일 보안 점검 생략');
        // PTR / 호스팅 식별
        for (const ip of apexA.slice(0, 2)) {
          const ptr = await ctx.guard.reverse(ip);
          if (ptr.some((p) => /internal|\.local|\.corp|bastion|dc\d/i.test(p))) findings.push(mk('asm', 'info', `PTR 내부 호스트명 노출: ${ip}`, host, '역방향 DNS 에 내부 명명 규칙이 노출됩니다.', ptr.join(', '), 'PTR 에 내부 호스트명을 노출하지 마십시오.'));
        }
        // DKIM / MTA-STS / TLS-RPT
        let dkim: string | undefined; let dkimSel = '';
        for (const sel of DKIM_SELECTORS) { const rec = await ctx.guard.resolveTxt(`${sel}._domainkey.${host}`); const f = rec.find((r) => /v=DKIM1|p=/.test(r)); if (f) { dkim = f; dkimSel = sel; break; } }
        if (mx.length && !dkim) findings.push(mk('asm', 'low', 'DKIM 서명 미탐지 (메일 사용 도메인)', host, 'MX 가 있으나 표준 셀렉터에서 DKIM 키를 못 찾았습니다.', `MX=${mx.map((m) => m.exchange).join(',')}`, 'DKIM 서명을 설정하십시오.'));
        if (dkim) {
          if (/t=y/i.test(dkim)) findings.push(mk('asm', 'low', `DKIM 테스트 모드(t=y): ${dkimSel}`, host, '테스트 모드라 수신측이 검증을 강제하지 않습니다.', dkim.slice(0, 120), 't=y 를 제거하십시오.'));
          if (/sha1/i.test(dkim)) findings.push(mk('asm', 'low', `DKIM 약한 해시(sha1): ${dkimSel}`, host, 'SHA-1 서명은 충돌 위험이 있습니다.', dkim.slice(0, 120), 'rsa-sha256 으로 재발급하십시오.'));
        }
        const mtaSts = await ctx.guard.httpGet(`https://mta-sts.${host}/.well-known/mta-sts.txt`);
        if (mx.length) {
          if (!mtaSts || mtaSts.status !== 200 || !/version:\s*STSv1/i.test(mtaSts.body)) findings.push(mk('asm', 'info', 'MTA-STS 미설정', host, 'SMTP 전송 구간 TLS 다운그레이드를 막는 MTA-STS 가 없습니다.', `status=${mtaSts?.status ?? '-'}`, '/.well-known/mta-sts.txt 에 mode: enforce 게시.'));
          else if (/mode:\s*testing/i.test(mtaSts.body)) findings.push(mk('asm', 'info', 'MTA-STS 모드가 testing', host, 'testing 모드는 강제하지 않습니다.', mtaSts.body.slice(0, 120), 'mode: enforce 로 전환.'));
          const tlsrpt = (await ctx.guard.resolveTxt(`_smtp._tls.${host}`)).find((r) => /v=TLSRPTv1/i.test(r));
          if (!tlsrpt) findings.push(mk('asm', 'info', 'TLS-RPT 미설정', host, 'SMTP TLS 실패 리포팅이 없습니다.', 'no _smtp._tls TXT', '_smtp._tls TXT 에 v=TLSRPTv1; rua=... 설정.'));
        }
        if (apexAAAA.length) findings.push(mk('asm', 'info', 'IPv6(AAAA) 노출 — 보호 비대칭 점검 필요', host, 'IPv6 주소가 노출되어 있습니다. IPv4 와 동등한 통제 적용을 확인하십시오.', `AAAA=${apexAAAA.slice(0, 3).join(', ')}`, 'IPv6 에도 동등한 방화벽/접근통제를 적용하십시오.'));
        if (nsList.length) { const provs = new Set(nsList.map((n) => n.split('.').slice(-2).join('.').toLowerCase())); if (provs.size === 1) findings.push(mk('asm', 'info', `단일 DNS 사업자 의존(SPOF): ${[...provs][0]}`, host, '모든 NS 가 단일 사업자라 사업자 장애 시 도메인 전체 가용성에 영향이 있습니다.', `NS=${nsList.join(', ')}`, '복수 DNS 사업자로 이중화하십시오.'));
        }
      }
    }

    if (ctx.intensity === 'passive') { ctx.log('ASM passive: DNS/공개정보 기반 인벤토리만 수행'); return findings; }

    // 오픈 포트·서비스 핑거프린팅 (connect-only)
    const ports = ctx.deep ? DEEP_PORTS : (ctx.allowedPorts.length ? ctx.allowedPorts : STANDARD_PORTS);
    const open: number[] = [];
    for (const p of ports) if (await ctx.guard.tcpProbe(host, p)) open.push(p);
    if (open.length) findings.push(mk('asm', 'low', `오픈 포트 ${open.length}개 탐지`, host, '외부 노출 포트 및 서비스 핑거프린트.', open.map((p) => `${p}/${PORT_SERVICE[p] ?? 'unknown'}`).join(', '), '불필요한 포트는 방화벽으로 차단하고 관리 포트는 VPN/허용목록으로 제한하십시오.'));
    for (const p of open) {
      if (DANGEROUS_PORTS.has(p)) findings.push(mk('asm', 'high', `민감 서비스 포트 외부 노출: ${p}/${PORT_SERVICE[p]}`, `${host}:${p}`, '데이터베이스/원격관리/메시징 등 민감 서비스가 외부에 직접 노출되어 있습니다.', `port=${p} service=${PORT_SERVICE[p]}`, '인터넷 직접 노출을 막고 사설망/배스천을 경유하도록 구성하십시오.'));
    }

    // 심층: 배너 그랩 + 무인증 데이터스토어 단서
    if (ctx.deep) {
      for (const p of open) {
        if (BANNER_PORTS.has(p)) {
          const banner = await ctx.guard.tcpBanner(host, p);
          if (banner && banner.trim()) {
            const v = bannerVersion(banner);
            findings.push(mk('asm', 'info', `서비스 배너: ${p}/${PORT_SERVICE[p] ?? '?'}`, `${host}:${p}`, '서버 자발적 배너로 제품/버전이 식별됩니다.', banner.slice(0, 120).replace(/[\r\n]+/g, ' '), '배너에서 버전 노출을 제거하십시오.'));
            if (v) findings.push(...matchServiceCve(v.product, v.version, `${host}:${p}`));
          }
        }
      }
      // Redis 무인증
      if (open.includes(6379)) {
        const r = await ctx.guard.cmdProbe(host, 6379, 'PING\r\n');
        if (r && /\+PONG/.test(r)) findings.push(mk('asm', 'critical', 'Redis 무인증 노출', `${host}:6379`, '인증 없이 Redis 명령이 수락됩니다(데이터 탈취·RCE 표면).', `PING→${r.slice(0, 20).trim()}`, 'requirepass/ACL 설정 및 외부 노출 차단.'));
      }
      // Memcached 무인증
      if (open.includes(11211)) {
        const r = await ctx.guard.cmdProbe(host, 11211, 'version\r\n');
        if (r && /VERSION/i.test(r)) findings.push(mk('asm', 'critical', 'Memcached 무인증 노출', `${host}:11211`, '인증 없이 Memcached 가 응답합니다(증폭 DDoS·캐시 탈취 표면).', r.slice(0, 40).trim(), 'SASL 인증 적용 및 외부 노출 차단.'));
      }
      // Elasticsearch / Kibana / CouchDB 무인증 (HTTP)
      for (const [port, path, sig, name] of [[9200, '/', /"cluster_name"|"number"\s*:/, 'Elasticsearch'], [5601, '/api/status', /"version"|kibana/i, 'Kibana'], [5984, '/', /"couchdb"\s*:\s*"Welcome"/, 'CouchDB']] as [number, string, RegExp, string][]) {
        if (!open.includes(port)) continue;
        const r = await ctx.guard.httpGet(`http://${host}:${port}${path}`);
        if (r && r.status === 200 && sig.test(r.body)) findings.push(mk('asm', 'critical', `${name} 무인증 노출`, `${host}:${port}`, `${name} 가 인증 없이 메타/헬스에 응답합니다(데이터 노출).`, r.body.slice(0, 100).replace(/\s+/g, ' '), '인증·접근통제를 적용하고 외부 노출을 차단하십시오.'));
      }
    }

    // TLS 전수 점검 (인증서 위생 + 버전 매트릭스 + 약한 암호)
    if (open.includes(443) || ctx.asset.type !== 'host') {
      const t = await ctx.guard.tlsInspect(host, 443);
      if (t && (t.subject || t.san.length)) {
        if (t.daysToExpiry !== null && t.daysToExpiry < 30) findings.push(mk('asm', t.daysToExpiry < 0 ? 'critical' : 'medium', t.daysToExpiry < 0 ? 'TLS 인증서 만료됨' : `TLS 인증서 만료 임박 (${t.daysToExpiry}일)`, host, `CN=${t.subject ?? '?'} 만료=${t.validTo}`, `protocol=${t.protocol}`, '인증서를 갱신하고 자동 갱신(ACME)을 구성하십시오.'));
        if (t.hostnameMismatch) findings.push(mk('asm', 'high', 'TLS 인증서 호스트명/SAN 불일치', host, '제시된 인증서가 요청 호스트명과 일치하지 않습니다(MITM/오구성).', `host=${host} SAN=${t.san.slice(0, 8).join(',')}`, '대상 호스트명을 포함하는 올바른 인증서를 배포하십시오.'));
        if (t.selfSigned) findings.push(mk('asm', 'high', '자가서명/사설 CA 인증서', host, '공인 신뢰 체인에 연결되지 않아 브라우저 경고·MITM 표면이 됩니다.', `subject=${t.subject} issuer=${t.issuer}`, '공인 CA 발급 인증서로 교체하십시오.'));
        if (t.keyBits !== null && t.keyType === 'rsa' && t.keyBits < 2048) findings.push(mk('asm', 'high', `짧은 RSA 키(${t.keyBits}bit)`, host, '2048bit 미만 RSA 키는 약합니다.', `bits=${t.keyBits}`, 'RSA 2048bit 이상(또는 ECDSA P-256+)로 재발급하십시오.'));
        if (t.sigalg && /sha1|md5/i.test(t.sigalg)) findings.push(mk('asm', 'high', `약한 인증서 서명알고리즘: ${t.sigalg}`, host, 'SHA-1/MD5 서명은 충돌 위험으로 폐기되었습니다.', t.sigalg, 'SHA-256 이상 서명 인증서로 재발급하십시오.'));
        if (t.validityDays !== null && t.validityDays > 398) findings.push(mk('asm', 'low', `인증서 유효기간 과다(${t.validityDays}일 > 398)`, host, 'CA/B 포럼 한도(398일)를 초과합니다.', `validity=${t.validityDays}d`, '유효기간을 398일 이하로 발급하십시오.'));
        if (t.validFrom && Date.parse(t.validFrom) > Date.now()) findings.push(mk('asm', 'medium', '인증서 notBefore 미래(미시작)', host, '인증서 시작일이 미래입니다(시계 오류/미시작).', `validFrom=${t.validFrom}`, '시스템 시계와 발급 시점을 점검하십시오.'));

        if (ctx.deep) {
          // 버전 매트릭스
          for (const v of ['TLSv1', 'TLSv1.1'] as const) {
            if (await ctx.guard.tlsVersionAccepted(host, v, 443)) findings.push(mk('asm', 'medium', `취약 TLS 프로토콜 수용: ${v}`, host, `${v} 은(는) 폐기된 프로토콜로 다운그레이드 공격에 취약합니다.`, `${v}=accepted`, 'TLS 1.2 이상만 허용하고 1.0/1.1 을 비활성화하십시오.'));
          }
          if (!(await ctx.guard.tlsVersionAccepted(host, 'TLSv1.3', 443))) findings.push(mk('asm', 'info', 'TLS 1.3 미지원', host, '최신 TLS 1.3 을 지원하지 않습니다.', 'TLSv1.3=not accepted', 'TLS 1.3 지원을 활성화하십시오.'));
          // 약한 암호군
          for (const [grp, cipher] of [['RC4', 'RC4@SECLEVEL=0'], ['3DES', 'DES-CBC3-SHA:3DES@SECLEVEL=0'], ['NULL', 'NULL@SECLEVEL=0'], ['EXPORT', 'EXPORT@SECLEVEL=0'], ['aNULL', 'aNULL@SECLEVEL=0']] as [string, string][]) {
            const c = await ctx.guard.tlsWeakCipherAccepted(host, cipher, 443);
            if (c) findings.push(mk('asm', 'high', `약한 암호스위트 수용: ${grp}`, host, `${grp} 계열 암호스위트가 수용되어 통신 기밀성이 약화됩니다.`, `negotiated=${c}`, `${grp} 암호군을 비활성화하고 AEAD(GCM/ChaCha20) 만 허용하십시오.`));
          }
          // PFS 미지원 (정적 RSA 키교환)
          const kRsa = await ctx.guard.tlsWeakCipherAccepted(host, 'kRSA@SECLEVEL=0', 443);
          if (kRsa && !/ECDHE|DHE/i.test(kRsa)) findings.push(mk('asm', 'medium', 'PFS(전방향 비밀성) 미지원 — 정적 RSA 키교환', host, 'ECDHE/DHE 없이 정적 RSA 키교환이 가능해 키 유출 시 과거 트래픽이 복호화됩니다.', `negotiated=${kRsa}`, 'ECDHE 키교환만 허용하십시오.'));
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

/** RFC1918/링크로컬/루프백/CGNAT/ULA 등 사설·내부 IP 판정. */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  const v = ip.replace(/^::ffff:/i, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    const o = v.split('.').map(Number);
    return o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168) ||
      (o[0] === 172 && o[1]! >= 16 && o[1]! <= 31) || (o[0] === 169 && o[1] === 254) ||
      (o[0] === 100 && o[1]! >= 64 && o[1]! <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd');
}

/** 배너에서 제품/버전 추출. */
function bannerVersion(b: string): { product: string; version: string } | null {
  const rules: [RegExp, string][] = [
    [/SSH-2\.0-OpenSSH[_-]([\d.]+p?\d*)/i, 'openssh'],
    [/vsFTPd ([\d.]+)/i, 'vsftpd'],
    [/Exim ([\d.]+)/i, 'exim'],
    [/Postfix/i, 'postfix'],
    [/ProFTPD ([\d.]+)/i, 'proftpd'],
  ];
  for (const [re, product] of rules) { const m = re.exec(b); if (m) return { product, version: m[1] || '' }; }
  return null;
}

/** 배너 버전을 CVE 피드와 대조. */
function matchServiceCve(product: string, version: string, target: string): Finding[] {
  if (!version) return [];
  const out: Finding[] = [];
  for (const e of CVE_FEED) {
    if (e.product === product && lessThan(version, e.vulnerableBelow)) {
      const sev: Finding['severity'] = e.cvss >= 9 ? 'critical' : e.cvss >= 7 ? 'high' : e.cvss >= 4 ? 'medium' : 'low';
      out.push({ ...mk('asm', sev, `${e.cve}: ${e.title}`, target, `배너 식별 ${product} ${version} 은(는) ${e.vulnerableBelow} 미만으로 취약합니다.`, `banner ${product}@${version}`, e.remediation), cvss: e.cvss, epss: e.epss, kev: e.kev, cve: e.cve });
    }
  }
  return out;
}

export const _now = now;
