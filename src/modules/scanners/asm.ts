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
import { queryCrtSh, detectInternalNaming } from './ctlog.js';
import { checkIndicatorsAndEnrich, type Indicator } from '../threatintel/cti.js';

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

      // ── CT 로그 마이닝 (심층, crt.sh 무료 공개 API) ──────────────────────
      if (ctx.deep) {
        ctx.log('asm: crt.sh CT 로그 조회 중…');
        const ctEntries = await queryCrtSh(host).catch(() => []);
        if (ctEntries.length) {
          // 내부 명명 규칙 탐지 (staging-/vpn-/internal- 등)
          const internalNames = detectInternalNaming(ctEntries);
          if (internalNames.length) {
            findings.push(mk('asm', 'medium', `CT 로그 내부 호스트명 노출 ${internalNames.length}건`, host,
              '공인 인증서 SAN 필드에 내부 명명 규칙(staging/vpn/internal 등)이 포함되어 인프라 구조가 드러납니다.',
              internalNames.slice(0, 10).join('\n'),
              '내부 호스트명 인증서는 사설 CA 또는 와일드카드로 발급하고 공인 CT 로그에 기록되지 않도록 분리하십시오.'));
          }
          // 워드리스트가 놓친 추가 서브도메인 인벤토리
          const newHosts = ctEntries.map(e => e.hostname).filter(h => !h.startsWith('*') && h !== host);
          if (newHosts.length > 0) {
            findings.push(mk('asm', 'info', `CT 로그 기반 서브도메인 ${newHosts.length}건 발견`, host,
              '공인 CT 로그에 등록된 인증서로부터 워드리스트 열거가 놓친 서브도메인을 추가 식별했습니다.',
              [...new Set(newHosts)].slice(0, 20).join('\n'),
              '불필요한 서브도메인 인증서는 폐기하고 미사용 호스트는 제거하십시오.'));
          }
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

      // ── 위협 인텔/IoC 대조 — 발견 IP/도메인/CNAME 을 known-bad 와 대조(외부 CTI 소비, 대상 미발신) ──
      const indicators: Indicator[] = [
        ...[...apexA, ...apexAAAA].map((ip) => ({ type: 'ip' as const, value: ip })),
        { type: 'domain' as const, value: host },
        ...discovered.map((d) => ({ type: 'domain' as const, value: d.sub })),
        ...discovered.filter((d) => d.ip).map((d) => ({ type: 'ip' as const, value: d.ip })),
        ...discovered.filter((d) => d.cname).map((d) => ({ type: 'cname' as const, value: d.cname! })),
      ];
      findings.push(...await checkIndicatorsAndEnrich(ctx, indicators));

      // ── 서브도메인 탈취(dangling CNAME) — 비파괴 다중신호 판정(실 클레임/등록 금지, GET 만) ──
      if (ctx.deep) {
        // CT 로그 호스트도 탈취 점검 대상에 흡수(인증서는 발급됐으나 DNS 폐기 가능성).
        for (const d of discovered.slice(0, 40)) {
          const f = await classifyTakeover(ctx, d, wildcardIps);
          if (f) findings.push(f);
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

        // DNSSEC — DoH(Cloudflare)로 DNSKEY 존재 여부 확인 (비파괴 공개 API)
        try {
          const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${host}&type=DNSKEY`, {
            signal: AbortSignal.timeout(5000),
            headers: { accept: 'application/dns-json' },
          });
          const dohJson = await dohRes.json() as any;
          const hasDnsKey = dohJson?.Answer?.some((r: any) => r.type === 48);
          if (!hasDnsKey) {
            findings.push(mk('asm', 'info', 'DNSSEC 미적용', host, 'DNSSEC 가 없으면 DNS 캐시 포이즈닝(카밍스키 공격)에 취약합니다.', 'no DNSKEY', 'DNSSEC 를 적용하고 상위 존에 DS 레코드를 등록하십시오.'));
          }
        } catch { /* DoH 접근 불가 — 생략 */ }

        // BIMI (Brand Indicators for Message Identification) — 이메일 브랜딩 보안
        const bimiTxt = (await ctx.guard.resolveTxt(`default._bimi.${host}`)).find(r => /v=bimi1/i.test(r));
        if (!bimiTxt && mx.length) {
          findings.push(mk('asm', 'info', 'BIMI 레코드 미설정', host, 'BIMI 가 없으면 브랜드 로고 메일 표시(지원 클라이언트)가 불가하고 이메일 인증 완성도가 낮습니다.', 'no default._bimi TXT', 'DMARC p=quarantine|reject 달성 후 BIMI 레코드를 게시하십시오.'));
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
        if (t.daysToExpiry !== null && t.daysToExpiry < 30) {
          const d = t.daysToExpiry;
          const sev: Finding['severity'] = d < 0 ? (d < -7 ? 'critical' : 'high') : d < 14 ? 'medium' : 'low';
          const title = d < 0 ? `TLS 인증서 만료됨 (${Math.abs(d)}일 경과)` : d < 14 ? `TLS 인증서 만료 임박 (${d}일)` : `TLS 인증서 만료 예정 (${d}일)`;
          findings.push({ ...mk('asm', sev, title, host, `CN=${t.subject ?? '?'} 만료=${t.validTo} (D${d >= 0 ? '-' : '+'}${Math.abs(d)})`, `validTo=${t.validTo} daysToExpiry=${d} issuer=${t.issuer ?? '?'}`, '인증서를 갱신하고 자동 갱신(ACME)을 구성해 만료로 인한 서비스 중단·신뢰 경고를 예방하십시오.'), owasp: 'A02:2021', cwe: 'CWE-298', confidence: 'firm' });
        }
        if (t.hostnameMismatch) findings.push(mk('asm', 'high', 'TLS 인증서 호스트명/SAN 불일치', host, '제시된 인증서가 요청 호스트명과 일치하지 않습니다(MITM/오구성).', `host=${host} SAN=${t.san.slice(0, 8).join(',')}`, '대상 호스트명을 포함하는 올바른 인증서를 배포하십시오.'));
        if (t.selfSigned) findings.push(mk('asm', 'high', '자가서명/사설 CA 인증서', host, '공인 신뢰 체인에 연결되지 않아 브라우저 경고·MITM 표면이 됩니다.', `subject=${t.subject} issuer=${t.issuer}`, '공인 CA 발급 인증서로 교체하십시오.'));
        if (t.keyBits !== null && t.keyType === 'rsa' && t.keyBits < 2048) findings.push(mk('asm', 'high', `짧은 RSA 키(${t.keyBits}bit)`, host, '2048bit 미만 RSA 키는 약합니다.', `bits=${t.keyBits}`, 'RSA 2048bit 이상(또는 ECDSA P-256+)로 재발급하십시오.'));
        if (t.sigalg && /sha1|md5/i.test(t.sigalg)) findings.push(mk('asm', 'high', `약한 인증서 서명알고리즘: ${t.sigalg}`, host, 'SHA-1/MD5 서명은 충돌 위험으로 폐기되었습니다.', t.sigalg, 'SHA-256 이상 서명 인증서로 재발급하십시오.'));
        if (t.validityDays !== null && t.validityDays > 398) findings.push(mk('asm', 'low', `인증서 유효기간 과다(${t.validityDays}일 > 398)`, host, 'CA/B 포럼 한도(398일)를 초과합니다.', `validity=${t.validityDays}d`, '유효기간을 398일 이하로 발급하십시오.'));
        if (t.validFrom && Date.parse(t.validFrom) > Date.now()) findings.push(mk('asm', 'medium', '인증서 notBefore 미래(미시작)', host, '인증서 시작일이 미래입니다(시계 오류/미시작).', `validFrom=${t.validFrom}`, '시스템 시계와 발급 시점을 점검하십시오.'));
        // HTTP/2 지원 여부 (ALPN)
        if (t.alpn) {
          if (!t.http2) findings.push(mk('asm', 'info', `HTTP/2 미지원 (ALPN: ${t.alpn})`, host, 'HTTP/2 를 지원하지 않습니다. 성능·보안 헤더 효율성이 낮습니다.', `alpn=${t.alpn}`, 'HTTP/2(h2) 를 활성화하십시오.'));
        }
        // OCSP Stapling — 인증서 해지 확인 효율성
        if (!t.ocspUrl) findings.push(mk('asm', 'info', 'OCSP URL 부재 (해지 확인 경로 없음)', host, 'OCSP URL 이 없어 클라이언트가 인증서 해지 상태를 실시간 확인하기 어렵습니다.', 'no OCSP AIA', 'OCSP URL 을 포함한 인증서로 재발급하고 OCSP Stapling 을 서버에서 활성화하십시오.'));

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

    // ───── 확장 점검 ─────────────────────────────────────────────────────
    // (비파괴: GET/HEAD/OPTIONS·connect·읽기전용 cmd·핸드셰이크·리졸버 질의만)

    if (ctx.asset.type === 'domain' && ctx.deep) {
      // [DNS-1] CDS/CDNSKEY 게시 — DNSSEC 키 롤오버/위임 자동화 신호 (RFC7344)
      try {
        const cds = await dohQuery(host, 'CDS');
        const cdnskey = await dohQuery(host, 'CDNSKEY');
        const cdsAns = (cds?.Answer || []).filter((r: any) => r.type === 59);
        const cdnAns = (cdnskey?.Answer || []).filter((r: any) => r.type === 60);
        if (cdsAns.length || cdnAns.length) {
          // CDS 0 0 0 0 = DNSSEC 제거 신호 → 상위 DS 삭제 요청. 의도치 않으면 위험.
          const deleteSignal = cdsAns.some((r: any) => /(^|\s)0\s+0\s+0\s+0\s*$/.test((r.data || '').trim()));
          findings.push({ ...mk('asm', deleteSignal ? 'medium' : 'info',
            deleteSignal ? 'CDS/CDNSKEY DNSSEC 제거 신호(0 0 0 0) 게시' : 'CDS/CDNSKEY 자동 위임 레코드 게시', host,
            deleteSignal
              ? 'CDS "0 0 0 0" 는 상위 존에 DS 삭제(=DNSSEC 비활성)를 요청하는 신호입니다. 의도치 않은 게시면 DNSSEC 가 해제되어 캐시 포이즈닝에 노출됩니다.'
              : 'CDS/CDNSKEY 로 상위 위임의 자동 키 롤오버가 동작합니다. 키 관리 위생을 확인하십시오.',
            `CDS=${cdsAns.length} CDNSKEY=${cdnAns.length}`,
            deleteSignal ? 'DNSSEC 유지가 의도라면 CDS 0 0 0 0 게시를 즉시 제거하십시오.' : '키 롤오버 절차와 상위 DS 동기화를 정기 점검하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-345', confidence: 'firm',
            references: ['https://datatracker.ietf.org/doc/html/rfc7344'] });
        }
      } catch { /* DoH 불가 */ }

      // [DNS-2] DNAME 레코드 — 서브트리 리다이렉션(설정 오류·범위 오염 시 위험)
      try {
        const dn = await dohQuery(host, 'DNAME');
        const dnAns = (dn?.Answer || []).filter((r: any) => r.type === 39);
        if (dnAns.length) findings.push({ ...mk('asm', 'low', 'DNAME 서브트리 리다이렉션 설정', host,
          'DNAME 은 전체 서브도메인 트리를 다른 도메인으로 매핑합니다. 매핑 대상이 미점유/오설정이면 광범위 트래픽 오리다이렉트·탈취 위험이 있습니다.',
          dnAns.map((r: any) => r.data).slice(0, 4).join('\n'),
          'DNAME 매핑 대상의 점유·정합성을 확인하고 불필요한 서브트리 리다이렉션을 제거하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-350', confidence: 'firm' });
      } catch { /* */ }

      // [DNS-3] NSEC/NSEC3 존재 — 영역 워킹(zone enumeration) 가능 힌트 (질의만)
      // DNSSEC-OK(do=1) 질의로 Authority 섹션의 NSEC/NSEC3 를 보존해야 탐지가 동작한다.
      try {
        const nsecProbe = await dohQuery(`zzq8x-nope-${Math.random().toString(36).slice(2, 8)}.${host}`, 'A', true);
        const auth = (nsecProbe?.Authority || []) as { type?: number; data?: string }[];
        const hasNsec = auth.some((r) => r.type === 47);
        const hasNsec3 = auth.some((r) => r.type === 50);
        if (hasNsec) findings.push({ ...mk('asm', 'low', 'DNSSEC NSEC 사용 — 영역 워킹(전체 레코드 열거) 가능', host,
          'NSEC 레코드는 부재 증명을 위해 다음 존재 이름을 평문 노출합니다. 공격자가 NSEC 체인을 따라가 영역 전체 레코드를 열거(zone walking)할 수 있습니다.',
          'NSEC in Authority section', 'NSEC3(해시) 또는 NSEC3 화이트 라이즈/블랙 라이즈로 전환하여 영역 워킹을 차단하십시오.'),
          owasp: 'A01:2021', cwe: 'CWE-200', confidence: 'firm',
          references: ['https://datatracker.ietf.org/doc/html/rfc5155'] });
        else if (hasNsec3) {
          // NSEC3 RDATA presentation: "<hash-alg> <flags> <iterations> <salt> <next-hashed> [types...]"
          // 예) "1 0 0 -"  → iterations = 3번째 필드. 첫 공백숫자(hash-alg)를 캡처하면 안 됨.
          const n3 = auth.find((r) => r.type === 50);
          const fields = (n3?.data || '').trim().split(/\s+/);
          const iters = fields.length >= 3 && /^\d+$/.test(fields[2]!) ? Number(fields[2]) : null;
          if (iters !== null && iters > 0) findings.push({ ...mk('asm', 'info', `NSEC3 반복(iterations=${iters}) — 0 권고`, host,
            'NSEC3 반복 횟수가 0 보다 크면 검증 부하만 늘고 오프라인 사전공격 방어 효과는 미미합니다(RFC9276). iterations=0 이 권고됩니다.',
            `NSEC3 iterations=${iters}`, 'NSEC3 iterations 를 0 으로 설정하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-327', confidence: 'tentative',
            references: ['https://datatracker.ietf.org/doc/html/rfc9276'] });
        }
      } catch { /* */ }

      // [DNS-4] 추가 SRV 라벨 — 자동발견 표면(autodiscover/Teams/STUN 등)
      const srvExtra: string[] = [];
      for (const lbl of SRV_LABELS_EXT) {
        const r = await ctx.guard.resolveSrv(`${lbl}.${host}`);
        if (r.length && r[0]) srvExtra.push(`${lbl}→${r[0].name}:${r[0].port}`);
      }
      if (srvExtra.length) findings.push({ ...mk('asm', 'info', `추가 SRV 자동발견 라벨 노출 ${srvExtra.length}건`, host,
        '협업/통신(STUN/TURN/SIP-TLS/MS Teams federation/CalDAV 등) SRV 가 노출되어 사용 중인 서비스·내부 토폴로지가 드러납니다.',
        srvExtra.join('\n'), '불필요한 SRV 공개를 제한하고 내부 자동발견은 분할 DNS 로 분리하십시오.'),
        owasp: 'A01:2021', cwe: 'CWE-200', confidence: 'firm' });

      // [DNS-5] 추가 SaaS/공급망 검증 TXT 토큰 (기존 SAAS_TXT 외 신규 벤더)
      const txtAll = await ctx.guard.resolveTxt(host);
      const saasExtra = SAAS_TXT_EXT.filter(([k]) => txtAll.some((r) => r.toLowerCase().includes(k.toLowerCase()))).map(([, n]) => n);
      if (saasExtra.length) findings.push({ ...mk('asm', 'info', `추가 SaaS/벤더 검증 토큰 ${saasExtra.length}건 — 공급망 표면`, host,
        'TXT 의 추가 SaaS 검증 토큰으로 사용 중인 외부 SaaS(공급망)가 식별됩니다. 미사용 벤더 토큰은 공급망 공격면을 넓힙니다.',
        saasExtra.join(', '), '미사용 검증 토큰 TXT 를 정리하고 활성 SaaS 만 유지하십시오.'),
        owasp: 'A06:2021', cwe: 'CWE-200', confidence: 'firm' });

      const mxForArc = await ctx.guard.resolveMx(host);
      const hasMx = mxForArc.some((m) => m.exchange && m.exchange !== '.');

      // [MAIL-1] DKIM ADSP/구식 정책 라벨(_adsp._domainkey) 노출 — 폐기된 메커니즘
      if (hasMx) {
        const adsp = (await ctx.guard.resolveTxt(`_adsp._domainkey.${host}`)).find((r) => /dkim=/i.test(r));
        if (adsp) findings.push({ ...mk('asm', 'info', 'DKIM ADSP(_adsp) 폐기 메커니즘 게시', host,
          'ADSP(RFC5617)는 폐기되었고 DMARC 로 대체되었습니다. 게시되어 있어도 효과가 없고 설정 노후 신호입니다.',
          adsp.slice(0, 120), 'ADSP 레코드를 제거하고 DMARC 로 정책을 표현하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm' });
      }

      // [MAIL-2] 추가 DKIM 셀렉터 — 벤더별 셀렉터 광범위 점검(기존 DKIM_SELECTORS 외)
      if (hasMx) {
        let extraDkimSel = '';
        for (const sel of DKIM_SELECTORS_EXT) {
          const rec = await ctx.guard.resolveTxt(`${sel}._domainkey.${host}`);
          if (rec.some((r) => /v=DKIM1|p=/i.test(r))) { extraDkimSel = sel; break; }
        }
        if (extraDkimSel) findings.push({ ...mk('asm', 'info', `벤더 DKIM 셀렉터 노출: ${extraDkimSel}`, host,
          `벤더 특화 DKIM 셀렉터(${extraDkimSel})가 발견되어 사용 중인 메일 발송 서비스가 식별됩니다.`,
          `selector=${extraDkimSel}._domainkey`, '미사용 발송 서비스의 DKIM 셀렉터를 폐기하십시오.'),
          owasp: 'A06:2021', cwe: 'CWE-200', confidence: 'firm' });
      }

      // [MAIL-3] DMARC ruf(포렌식 리포트) 외부 도메인 위임 — 민감정보 유출/외부 위임 위생
      const dmarcRec = (await ctx.guard.resolveTxt(`_dmarc.${host}`)).find((r) => /v=dmarc1/i.test(r));
      if (dmarcRec) {
        const ruf = /ruf=([^;]+)/i.exec(dmarcRec);
        if (ruf && ruf[1]) {
          const rufDomains = [...ruf[1].matchAll(/mailto:[^@\s,]+@([^\s,;!]+)/gi)].map((m) => (m[1] || '').toLowerCase());
          const external = rufDomains.filter((d) => d && d !== host && !d.endsWith('.' + host));
          if (external.length) findings.push({ ...mk('asm', 'low', 'DMARC ruf(포렌식 리포트) 외부 도메인 위임', host,
            'ruf 포렌식 리포트가 외부 도메인으로 전송됩니다. 포렌식 리포트에는 원문 메일 헤더/본문 일부가 포함될 수 있어 민감정보가 제3자에 노출될 수 있습니다(외부 수신처는 별도 권한 TXT 도 필요).',
            `ruf→${external.slice(0, 4).join(', ')}`, 'ruf 수신처를 자사 도메인으로 제한하거나 ruf 사용 필요성을 재검토하십시오.'),
            owasp: 'A01:2021', cwe: 'CWE-200', confidence: 'firm' });
        }
      }

      // [MAIL-4] BIMI VMC(a= 태그/인증마크 인증서) 검증 — 로고 인증 완성도
      const bimi = (await ctx.guard.resolveTxt(`default._bimi.${host}`)).find((r) => /v=bimi1/i.test(r));
      if (bimi) {
        const hasA = /(^|;)\s*a=/i.test(bimi);
        const hasL = /(^|;)\s*l=\S/i.test(bimi);
        const lNonHttps = hasL && !/(^|;)\s*l=https:\/\//i.test(bimi);
        if (!hasA && hasL) findings.push({ ...mk('asm', 'info', 'BIMI VMC(a=) 미설정 — 인증마크 인증서 부재', host,
          'BIMI 가 게시되었으나 VMC(Verified Mark Certificate, a= 태그)가 없어 주요 메일 클라이언트(Gmail/Apple)에서 로고가 표시되지 않습니다.',
          bimi.slice(0, 140), '공인 VMC 를 발급받아 BIMI a= 태그에 게시하십시오.'),
          owasp: 'A07:2021', cwe: 'CWE-295', confidence: 'firm' });
        if (lNonHttps) findings.push({ ...mk('asm', 'low', 'BIMI 로고 URL 이 비-HTTPS', host,
          'BIMI 로고(l=) 가 HTTPS 가 아니면 변조/혼합콘텐츠 위험이 있습니다.', bimi.slice(0, 140),
          'BIMI l= 를 HTTPS SVG Tiny PS 로 게시하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-319', confidence: 'firm' });
      }

      // [MAIL-5] MTA-STS DNS 레코드(_mta-sts TXT) 부재 — 정책 파일과 DNS 레코드 정합
      if (hasMx) {
        const mtaStsTxt = (await ctx.guard.resolveTxt(`_mta-sts.${host}`)).find((r) => /v=stsv1/i.test(r));
        if (!mtaStsTxt) findings.push({ ...mk('asm', 'info', 'MTA-STS DNS 레코드(_mta-sts TXT) 미설정', host,
          'MTA-STS 정책 파일이 있어도 _mta-sts TXT(id=) 가 없으면 발신 MTA 가 정책 갱신을 인지하지 못합니다.',
          'no _mta-sts TXT', '_mta-sts.<도메인> 에 v=STSv1; id=... TXT 를 게시하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-16', confidence: 'firm' });
      }

      // [TLS-1] 와일드카드 인증서 과범위 SAN — 단일 와일드카드가 다수 서브트리 커버
      const tlsApex2 = await ctx.guard.tlsInspect(host, 443);
      if (tlsApex2 && tlsApex2.san.length) {
        const wildSan = tlsApex2.san.filter((s) => s.startsWith('*.'));
        if (wildSan.length) {
          const broad = wildSan.some((s) => (s.match(/\./g) || []).length <= 1); // *.com 류(과도)
          findings.push({ ...mk('asm', broad ? 'medium' : 'low', `와일드카드 인증서 SAN ${wildSan.length}건 — 과범위 키 공유 위험`, host,
            '와일드카드 인증서는 다수 호스트가 단일 개인키를 공유합니다. 한 호스트 침해 시 동일 키로 전체 서브도메인 위장이 가능합니다.',
            `wildcard SAN=${wildSan.slice(0, 6).join(', ')}`,
            '민감 서비스는 호스트별 전용 인증서를 사용하고 와일드카드 범위를 최소화하십시오.'),
            owasp: 'A02:2021', cwe: 'CWE-295', confidence: 'firm',
            references: ['https://owasp.org/www-project-web-security-testing-guide/'] });
        }
      }
    }

    // ── 능동 TLS 심화(443 핸드셰이크) — passive 제외, host 자산은 443 오픈 확인 ──
    if (ctx.deep && (ctx.asset.type !== 'host' || (await ctx.guard.tcpProbe(host, 443)))) {
      const t2 = await ctx.guard.tlsInspect(host, 443);
      if (t2) {
        // [TLS-2] 제거: t2.ocspUrl 존재만으로 무조건 발생하는 info 노이즈였고(공인 인증서는 대부분
        //  AIA 에 OCSP URL 포함), Must-Staple 강제 여부를 핸드셰이크로 확정할 수 없어 실질 취약 신호가
        //  아니라 메서드 한계를 토로하는 수준이므로 삭제.

        // [TLS-3] SCT(CT) 부족 — CT 정책 미준수 신호
        if (t2.sctCount === 0) findings.push({ ...mk('asm', 'info', 'SCT(인증서 투명성) 미포함', host,
          '인증서에 SCT(서명된 인증서 타임스탬프)가 없어 CT 로그 게재가 확인되지 않습니다. 일부 클라이언트는 CT 미준수 인증서를 거부합니다.',
          `sctCount=${t2.sctCount}`, 'CT 로그에 게재되고 SCT 가 포함된 인증서를 발급하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-295', confidence: 'firm' });

        // [TLS-4] CRIME(TLS 압축) 힌트 — TLS 1.2 이하 + 정적 RSA 협상 시 압축 위험 추정
        // (압축 활성 직접 관측 메서드 없음 → 약한 cipher 매트릭스로 레거시 스택 추정, tentative)
        const legacyKex = await ctx.guard.tlsWeakCipherAccepted(host, 'DES-CBC3-SHA:CAMELLIA@SECLEVEL=0', 443);
        if (legacyKex) findings.push({ ...mk('asm', 'low', 'TLS 압축(CRIME)·레거시 스택 가능성', host,
          '레거시 블록 암호(3DES/CAMELLIA CBC)가 협상되어 구형 TLS 스택일 가능성이 있습니다. 구형 스택은 TLS 압축(CRIME) 활성 위험이 있습니다.',
          `negotiated=${legacyKex}`, 'TLS 압축을 비활성화하고 AEAD(GCM/ChaCha20) 전용으로 전환하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-310', confidence: 'tentative' });

        // [TLS-5] 약한 cipher 매트릭스 확대(기존 RC4/3DES/NULL/EXPORT/aNULL 외)
        for (const [grp, cipher, cwe] of TLS_WEAK_CIPHERS_EXT) {
          const c = await ctx.guard.tlsWeakCipherAccepted(host, cipher, 443);
          if (c) findings.push({ ...mk('asm', 'medium', `약한 암호스위트 수용: ${grp}`, host,
            `${grp} 계열 암호스위트가 수용되어 기밀성/무결성이 약화됩니다.`, `negotiated=${c}`,
            `${grp} 를 비활성화하고 ECDHE + AEAD(AES-GCM/ChaCha20-Poly1305) 만 허용하십시오.`),
            owasp: 'A02:2021', cwe, confidence: 'firm' });
        }

        // [TLS-6] 짧은 DH 그룹(1024bit 이하) — DHE 약화(Logjam 계열)
        const weakDh = await ctx.guard.tlsWeakCipherAccepted(host, 'DHE@SECLEVEL=0:EDH@SECLEVEL=0', 443);
        if (weakDh && /DHE/i.test(weakDh)) findings.push({ ...mk('asm', 'medium', 'DHE 키교환 수용 — 짧은 DH 파라미터 가능성(Logjam)', host,
          'DHE 키교환이 수용됩니다. 1024bit 이하 DH 그룹이면 Logjam 다운그레이드/오프라인 공격에 취약합니다.',
          `negotiated=${weakDh}`, 'DHE 를 ECDHE 로 교체하거나 2048bit 이상 DH 그룹만 사용하십시오.'),
          owasp: 'A02:2021', cwe: 'CWE-326', confidence: 'tentative',
          references: ['https://weakdh.org/'] });

        // [TLS-7] 인증서 체인/AIA(issuer CA URL) — 중간 인증서 누락 시 신뢰 실패
        if (!t2.selfSigned && t2.issuer && t2.subject && t2.issuer === t2.subject) {
          findings.push({ ...mk('asm', 'low', '인증서 issuer=subject(중간 인증서/AIA 점검 필요)', host,
            'issuer 와 subject 의 CN 이 동일해 체인 구성/중간 인증서 제공에 오류가 있을 수 있습니다(일부 클라이언트 신뢰 실패).',
            `subject=${t2.subject} issuer=${t2.issuer}`, '서버가 전체 인증서 체인(중간 CA 포함)을 제시하도록 구성하십시오.'),
            owasp: 'A02:2021', cwe: 'CWE-295', confidence: 'tentative' });
        }
      }
    }

    // ── 무인증 데이터스토어/관리 서비스 프로브 확대 (능동, deep) ──────────
    if (ctx.deep) {
      // open 포트 집합 재확인(스코프 안전): 위 open 변수는 passive 분기에서 채워지므로 재사용
      const httpProbes: { port: number; path: string; sig: RegExp; name: string; sev: Finding['severity']; cwe: string; desc: string; remed: string }[] = [
        { port: 2379, path: '/version', sig: /etcdserver|etcdcluster/i, name: 'etcd', sev: 'critical', cwe: 'CWE-306',
          desc: 'etcd 가 인증 없이 /version 에 응답합니다(클러스터 키-값 저장소·시크릿 노출 표면).', remed: 'etcd 클라이언트/피어 TLS 인증을 적용하고 외부 노출을 차단하십시오.' },
        { port: 8500, path: '/v1/agent/self', sig: /"Config"|"Member"|"NodeName"/, name: 'Consul', sev: 'critical', cwe: 'CWE-306',
          desc: 'Consul agent 가 인증 없이 /v1/agent/self 에 응답합니다(서비스 메시·KV·ACL 우회 표면).', remed: 'Consul ACL(default deny)·TLS 를 적용하고 외부 노출을 차단하십시오.' },
        { port: 8086, path: '/ping', sig: /^$/, name: 'InfluxDB', sev: 'high', cwe: 'CWE-306',
          desc: 'InfluxDB 가 /ping(204) 에 응답합니다. 시계열 DB 가 외부에 노출되어 있습니다.', remed: 'InfluxDB 인증을 활성화하고 외부 노출을 차단하십시오.' },
        { port: 9090, path: '/-/healthy', sig: /Prometheus( Server)? is Healthy|Healthy/i, name: 'Prometheus', sev: 'high', cwe: 'CWE-306',
          desc: 'Prometheus 가 인증 없이 /-/healthy 에 응답합니다(메트릭·타깃·내부 토폴로지 노출).', remed: 'Prometheus 앞단에 인증 프록시를 두고 외부 노출을 차단하십시오.' },
        { port: 3000, path: '/api/health', sig: /"database"\s*:\s*"ok"/i, name: 'Grafana', sev: 'medium', cwe: 'CWE-306',
          desc: 'Grafana 가 /api/health 에 Grafana 고유 응답("database":"ok")으로 응답합니다. 익명 접근/기본 자격이면 대시보드·데이터소스가 노출됩니다.', remed: '익명 접근을 비활성화하고 강한 관리자 자격·외부 차단을 적용하십시오.' },
        { port: 9000, path: '/api/system/status', sig: /"status"\s*:\s*"(UP|DOWN|STARTING|RESTARTING|DB_MIGRATION_(NEEDED|RUNNING))"/, name: 'SonarQube', sev: 'medium', cwe: 'CWE-306',
          desc: 'SonarQube 가 상태 API 에 SonarQube 고유 status 값으로 응답합니다. 익명 접근 시 소스/이슈 메타가 노출될 수 있습니다.', remed: 'force authentication 을 활성화하고 외부 노출을 차단하십시오.' },
      ];
      for (const pr of httpProbes) {
        if (!(await ctx.guard.tcpProbe(host, pr.port))) continue;
        const r = await ctx.guard.httpGet(`http://${host}:${pr.port}${pr.path}`, { timeoutMs: 4000 });
        if (!r) continue;
        // InfluxDB /ping = 204 no content / Prometheus 200
        const ok = (pr.port === 8086 ? (r.status === 204 || r.status === 200) : r.status === 200) && (pr.sig.source === '^$' ? true : pr.sig.test(r.body));
        if (ok) findings.push({ ...mk('asm', pr.sev, `${pr.name} 무인증/노출 단서`, `${host}:${pr.port}`, pr.desc,
          `status=${r.status} ${r.body.slice(0, 80).replace(/\s+/g, ' ')}`.trim(), pr.remed),
          owasp: 'A05:2021', cwe: pr.cwe, confidence: 'firm' });
      }

      // 인증 필요(401/403) 이지만 노출 자체가 표면인 관리 콘솔
      const authGated: { port: number; path: string; name: string; cwe: string }[] = [
        { port: 15672, path: '/api/overview', name: 'RabbitMQ Management', cwe: 'CWE-306' },
        { port: 8080, path: '/api/json', name: 'Jenkins', cwe: 'CWE-306' },
        { port: 5601, path: '/api/status', name: 'Kibana', cwe: 'CWE-306' },
      ];
      for (const g of authGated) {
        if (!(await ctx.guard.tcpProbe(host, g.port))) continue;
        const r = await ctx.guard.httpGet(`http://${host}:${g.port}${g.path}`, { timeoutMs: 4000 });
        if (!r) continue;
        if (r.status === 200) {
          findings.push({ ...mk('asm', 'critical', `${g.name} 무인증 노출`, `${host}:${g.port}`,
            `${g.name} 관리 API 가 인증 없이 200 으로 응답합니다(관리 기능·메타 노출).`,
            `status=200 ${r.body.slice(0, 80).replace(/\s+/g, ' ')}`.trim(),
            '인증을 강제하고 관리 인터페이스를 사설망/배스천으로 제한하십시오.'),
            owasp: 'A07:2021', cwe: g.cwe, confidence: 'firm' });
        } else if (r.status === 401 || r.status === 403) {
          findings.push({ ...mk('asm', 'medium', `${g.name} 관리 인터페이스 외부 노출(인증요구)`, `${host}:${g.port}`,
            `${g.name} 관리 엔드포인트가 외부에 노출되어 있습니다(현재 인증 요구). 브루트포스·취약점 표적이 됩니다.`,
            `status=${r.status}`, '관리 인터페이스를 사설망/VPN/허용목록으로 제한하십시오.'),
            owasp: 'A05:2021', cwe: 'CWE-284', confidence: 'firm' });
        }
      }

      // ZooKeeper 'envi' / Cassandra 배너 / Docker API / MongoDB HTTP / Kubelet
      if (await ctx.guard.tcpProbe(host, 2181)) {
        const r = await ctx.guard.cmdProbe(host, 2181, 'envi');
        if (r && /Environment|zookeeper\.version|java\.version/i.test(r)) findings.push({ ...mk('asm', 'critical', 'ZooKeeper 무인증(4자 명령 envi) 노출', `${host}:2181`,
          'ZooKeeper 가 인증 없이 4자 명령(envi)에 응답해 환경/버전이 노출됩니다(설정 탈취·코디네이션 조작 표면).',
          r.slice(0, 100).replace(/\s+/g, ' ').trim(), '4lw 명령 화이트리스트를 제한하고 SASL 인증·외부 차단을 적용하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-306', confidence: 'firm' });
      }
      if (await ctx.guard.tcpProbe(host, 2375)) {
        const r = await ctx.guard.httpGet(`http://${host}:2375/version`, { timeoutMs: 4000 });
        if (r && r.status === 200 && /"ApiVersion"|"GitCommit"|"Os"\s*:/.test(r.body)) findings.push({ ...mk('asm', 'critical', 'Docker Engine API 무인증(2375) 노출', `${host}:2375`,
          '암호화·인증 없는 Docker API(2375)가 노출되어 컨테이너 생성/호스트 장악(RCE)으로 직결됩니다.',
          r.body.slice(0, 100).replace(/\s+/g, ' '), 'TLS 상호인증(2376)으로 전환하거나 소켓을 외부에 노출하지 마십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-306', confidence: 'confirmed' });
      }
      if (await ctx.guard.tcpProbe(host, 27017)) {
        // MongoDB HTTP 인터페이스(구버전 28017) 또는 27017 HTTP GET 시 안내 문자열
        const r = await ctx.guard.httpGet(`http://${host}:27017/`, { timeoutMs: 4000 });
        if (r && /It looks like you are trying to access MongoDB over HTTP/i.test(r.body)) findings.push({ ...mk('asm', 'high', 'MongoDB 포트(27017) 외부 노출 확인', `${host}:27017`,
          'MongoDB 가 HTTP GET 에 드라이버 안내 문자열로 응답해 외부 노출이 확인됩니다. 인증 미설정 시 데이터 전체 노출 위험입니다.',
          r.body.slice(0, 80), 'SCRAM 인증·bindIp 제한·방화벽으로 외부 노출을 차단하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-306', confidence: 'firm' });
      }
      if (await ctx.guard.tcpProbe(host, 10250)) {
        const r = await ctx.guard.httpGet(`https://${host}:10250/healthz`, { timeoutMs: 4000 });
        if (r && r.status === 200 && /ok/i.test(r.body)) findings.push({ ...mk('asm', 'high', 'Kubelet API(10250) 외부 노출', `${host}:10250`,
          'Kubelet 읽기/실행 API(10250)가 외부에 노출되어 있습니다. 익명 인가가 켜져 있으면 파드 실행/로그 접근(노드 장악) 표면이 됩니다.',
          `healthz=${r.status}`, 'kubelet --anonymous-auth=false, --authorization-mode=Webhook 적용 및 외부 차단.'),
          owasp: 'A05:2021', cwe: 'CWE-306', confidence: 'firm' });
      }
      // (Cassandra 9042 단순 포트 오픈 점검 제거: 9042 는 DANGEROUS_PORTS 에 포함되어
      //  '민감 서비스 포트 외부 노출'(high)로 이미 보고되며, connect-only 만으로 인증 부재를
      //  단정해 CWE-306/firm 을 중복 부여하는 것은 과장이므로 삭제. 인증 부재 시그니처가 없음.)
    }

    // ── 클라우드 스토리지 버킷 참조 노출 (대상 host 응답 본문에서 추출) ────
    if (ctx.deep && ctx.asset.type !== 'host') {
      const homeUrl = `https://${host}/`;
      const page = await ctx.guard.httpGet(homeUrl, { timeoutMs: 6000 });
      const bodyText = (page?.body || '') + ' ' + Object.values(page?.headers || {}).join(' ');
      if (bodyText.trim()) {
        const buckets = new Set<string>();
        for (const re of BUCKET_URL_PATTERNS) {
          for (const m of bodyText.matchAll(re)) { if (m[0]) buckets.add(m[0]); }
        }
        if (buckets.size) findings.push({ ...mk('asm', 'info', `클라우드 스토리지 버킷 참조 ${buckets.size}건 노출`, host,
          '페이지/헤더에서 클라우드 스토리지 버킷 URL 이 참조됩니다. 버킷 권한이 공개/리스트 가능하면 데이터 노출 위험이 있습니다(버킷 자체는 외부 host 라 비파괴 점검 범위 밖).',
          [...buckets].slice(0, 8).join('\n'), '참조된 버킷의 공개 ACL/리스팅을 비공개로 잠그고 서명 URL/오리진 접근만 허용하십시오.'),
          owasp: 'A05:2021', cwe: 'CWE-732', confidence: 'tentative',
          references: ['https://owasp.org/www-project-cloud-security/'] });
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

/** 미점유(unclaimed) 호스팅 배너 시그니처 — 서브도메인 탈취 확정 신호. */
const TAKEOVER_SIGNATURES: { re: RegExp; svc: string }[] = [
  { re: /there isn't a github pages site here/i, svc: 'GitHub Pages' },
  { re: /\bno such app\b|herokucdn\.com\/error-pages\/no-such-app/i, svc: 'Heroku' },
  { re: /nosuchbucket|the specified bucket does not exist/i, svc: 'AWS S3' },
  { re: /deployment_not_found|the deployment could not be found/i, svc: 'Vercel' },
  { re: /\bproject not found\b/i, svc: 'Surge/Vercel' },
  { re: /fastly error: unknown domain/i, svc: 'Fastly' },
  { re: /do not have access to view this domain|not found - request id/i, svc: 'Netlify' },
  { re: /nothing is here yet|this page is not published/i, svc: 'Cloudflare Pages' },
  { re: /the thing you were looking for is no longer here|domain error/i, svc: 'Ghost' },
  { re: /unknown to read the docs|is unknown to read/i, svc: 'ReadTheDocs' },
  { re: /this domain is successfully pointed at wp engine.*but is not configured/i, svc: 'WP Engine' },
];
function matchTakeoverSig(body: string): string | null {
  for (const s of TAKEOVER_SIGNATURES) if (s.re.test(body)) return s.svc;
  return null;
}

/**
 * 서브도메인 탈취(dangling CNAME) 비파괴 판정. 외부 리소스 점유(claim/register) 시도는 절대 하지 않으며
 * DNS 해석(resolveDns/resolve6)과 HTTP GET(미점유 배너 읽기)만 수행한다.
 * 반환: 탈취 가능 finding 또는 null(정상/와일드카드/판단불가).
 */
export async function classifyTakeover(ctx: ScanContext, d: { sub: string; ip: string; cname?: string }, wildcardIps: Set<string> | null): Promise<Finding | null> {
  if (!d.cname) return null;
  const cname = d.cname.toLowerCase().replace(/\.$/, '');
  const fp = TAKEOVER_FINGERPRINTS.find((f) => cname.includes(f));
  if (!fp) return null;
  // 와일드카드 catch-all 응답이면 dangling 아님(오탐 억제).
  if (wildcardIps && d.ip && wildcardIps.has(d.ip)) return null;

  // (1) CNAME 타깃 미해석 → dangling(NXDOMAIN)
  const a = await ctx.guard.resolveDns(cname).catch(() => [] as string[]);
  const aaaa = await ctx.guard.resolve6(cname).catch(() => [] as string[]);
  const unresolved = a.length === 0 && aaaa.length === 0;

  // (2) 미점유 배너 시그니처(GET, 비파괴) — https/http 모두 시도하고 시그니처 발견 시에만 중단(빈 응답에 안 멈춤).
  let sig: string | null = null;
  for (const scheme of ['https', 'http']) {
    let r: { status: number; body: string } | null = null;
    try { r = await ctx.guard.httpGet(`${scheme}://${d.sub}/`, { timeoutMs: 5000 }); } catch { r = null; }
    if (r && r.body) { sig = matchTakeoverSig(r.body); if (sig) break; }
  }

  if (!unresolved && !sig) return null; // 정상 점유 서비스 → 오탐 억제
  // 미점유 배너 시그니처=확정(firm), CNAME 타깃 미해석(NXDOMAIN)만=정황(tentative).
  const conf: Finding['confidence'] = sig ? 'firm' : 'tentative';
  return {
    ...mk('asm', 'high', `서브도메인 탈취 가능성: ${d.sub}`, d.sub,
      `CNAME(${d.cname})이 외부 SaaS/CDN(${fp})을 가리키며, ${sig ? `미점유 배너(${sig})가 관측` : 'CNAME 타깃이 미해석(dangling)'}됩니다. 공격자가 해당 리소스를 선점·등록해 서브도메인을 탈취할 수 있습니다(비파괴 판정 — 실제 점유 미시도).`,
      `CNAME=${d.cname} (${fp}); ${sig ? `takeover signature: ${sig}` : 'target unresolved(NXDOMAIN)'}`,
      '미사용 CNAME 레코드를 즉시 제거하거나, 가리키는 외부 리소스를 정당 소유자가 재점유(claim)하십시오.'),
    owasp: 'A05:2021', cwe: 'CWE-350', confidence: conf, references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover'],
  };
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

// ───── 확장 점검용 상수/헬퍼 ─────────────────────────────────────────────

/** 추가 SRV 자동발견 라벨 (기존 SRV_LABELS 와 비중복). */
const SRV_LABELS_EXT = [
  '_stun._udp', '_stuns._tcp', '_turn._udp', '_turns._tcp', '_sip._tls', '_sipfederationtls._tcp',
  '_caldav._tcp', '_caldavs._tcp', '_carddav._tcp', '_carddavs._tcp',
  '_minecraft._tcp', '_mongodb._tcp', '_etcd-server._tcp', '_etcd-client._tcp',
  '_h323cs._tcp', '_diameter._tcp', '_pop3s._tcp', '_smtps._tcp', '_jmcp._tcp',
];

/** 추가 SaaS/벤더 검증 TXT 토큰 (기존 SAAS_TXT 와 비중복). [토큰부분문자열, 벤더명] */
const SAAS_TXT_EXT: [string, string][] = [
  ['apple-domain-verification', 'Apple Business'],
  ['amazonses', 'Amazon SES'],
  ['sendgrid', 'SendGrid'],
  ['mailgun', 'Mailgun'],
  ['pardot', 'Salesforce Pardot'],
  ['salesforce', 'Salesforce'],
  ['logmein-verification', 'LogMeIn'],
  ['dropbox-domain-verification', 'Dropbox'],
  ['cloudflare-verify', 'Cloudflare'],
  ['globalsign-domain-verification', 'GlobalSign'],
  ['onetrust', 'OneTrust'],
  ['notion', 'Notion'],
  ['miro-verification', 'Miro'],
  ['workplace-domain-verification', 'Meta Workplace'],
  ['citrix-verification-code', 'Citrix'],
  ['webex', 'Cisco Webex'],
  ['slack-domain-verification', 'Slack'],
  ['shopify', 'Shopify'],
  ['hubspot', 'HubSpot'],
];

/** 추가 DKIM 셀렉터 (기존 DKIM_SELECTORS 와 비중복) — 벤더 특화. */
const DKIM_SELECTORS_EXT = [
  'amazonses', 's1024', 'smtpapi', 'sig1', 'scph0', 'scph1', 'fm1', 'fm2', 'fm3',
  'sm', 'smtp', 'protonmail', 'protonmail2', 'pic', 'zmail', 'mxvault', 'turbo-smtp',
  'sparkpost', 'krs', 'cm', 'dkim1', 'dkim2', 'sib', 'litesrv',
];

/** 확대된 약한 암호스위트 매트릭스 (기존 RC4/3DES/NULL/EXPORT/aNULL/kRSA 와 비중복). */
const TLS_WEAK_CIPHERS_EXT: [string, string, string][] = [
  ['CBC-SHA1 (BEAST/Lucky13 계열)', 'AES128-SHA:AES256-SHA@SECLEVEL=0', 'CWE-326'],
  ['CAMELLIA', 'CAMELLIA128-SHA:CAMELLIA256-SHA@SECLEVEL=0', 'CWE-327'],
  ['SEED', 'SEED-SHA@SECLEVEL=0', 'CWE-327'],
  ['IDEA', 'IDEA-CBC-SHA@SECLEVEL=0', 'CWE-327'],
  ['DES (single)', 'DES-CBC-SHA@SECLEVEL=0', 'CWE-326'],
  ['ARIA', 'ARIA128-GCM-SHA256:ARIA256-GCM-SHA384@SECLEVEL=0', 'CWE-327'],
];

/** 클라우드 스토리지 버킷 URL 참조 패턴 (응답 본문/헤더에서 추출). */
const BUCKET_URL_PATTERNS: RegExp[] = [
  /https?:\/\/[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/gi,
  /https?:\/\/s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\/[a-z0-9._-]+/gi,
  /https?:\/\/[a-z0-9._-]+\.storage\.googleapis\.com/gi,
  /https?:\/\/storage\.googleapis\.com\/[a-z0-9._-]+/gi,
  /https?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net/gi,
  /https?:\/\/[a-z0-9-]+\.r2\.cloudflarestorage\.com/gi,
  /https?:\/\/[a-z0-9.-]+\.(?:digitaloceanspaces|fra1\.cdn\.digitaloceanspaces)\.com/gi,
];

/**
 * Cloudflare DoH(JSON) 질의 — 리졸버 질의(대상 패킷 미발신, 비파괴 공개 API).
 * dnssec=true 면 DNSSEC-OK(do=1) 를 설정해 Authority 섹션의 NSEC/NSEC3/RRSIG 를 보존한다.
 */
async function dohQuery(name: string, type: string, dnssec = false): Promise<{ Answer?: unknown[]; Authority?: unknown[] } | null> {
  try {
    const doParam = dnssec ? '&do=true&cd=false' : '';
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}${doParam}`, {
      signal: AbortSignal.timeout(5000),
      headers: { accept: 'application/dns-json' },
    });
    return await res.json() as { Answer?: unknown[]; Authority?: unknown[] };
  } catch { return null; }
}
