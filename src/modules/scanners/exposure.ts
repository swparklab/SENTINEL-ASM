/**
 * 노출·정보 유출 정밀 점검 (클라우드 스토리지·프론트엔드 시크릿·운영 파일) — 설계 §4.4 확장.
 * SaaS 보안 진단 수준으로 확장하기 위한 항목들: 클라우드 버킷/Firebase 노출, 클라이언트 토큰/API키/소스맵,
 * robots.txt 민감 경로, 백업/소스 파일 노출. dast.ts 가 호출한다.
 *
 * 비파괴 엄수: 동일 출처 GET 만(EgressGuard 강제), 외부 클라우드 호스트로는 능동 접근하지 않고 "참조 노출"만
 * 보고한다(범위 밖 발신 금지). 시크릿은 evidence 에서 마스킹한다.
 */
import type { Finding } from '../../types.js';
import type { ScanContext } from './types.js';
import { mk } from './asm.js';

type HttpResp = { ok: boolean; status: number; headers: Record<string, string>; body: string };
type Sev = Finding['severity'];
type Conf = Finding['confidence'];

const PLACEHOLDER = /your[_-]?|example|xxxx+|placeholder|<[^>]+>|dummy|test[_-]?key|0{8,}|abcdef0123|changeme|insert[_-]?|sample|foobar/i;

function f(sev: Sev, title: string, target: string, desc: string, evidence: string, remediation: string, owasp: string, cwe: string, confidence: Conf, refs?: string[]): Finding {
  return { ...mk('dast', sev, title, target, desc, evidence, remediation), owasp, cwe, confidence, references: refs ?? ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'] };
}

export async function runExposureScan(ctx: ScanContext, base: string, host: string, root: HttpResp, baseStatus: number, baseBody: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const isSoft404 = (r: HttpResp | null): boolean => !!r && baseStatus === 200 && r.status === 200 && r.body === baseBody;
  try {
    // 동일 출처 번들 JS 수집(코퍼스)
    const jsUrls = [...root.body.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]!).filter((s) => /\.js(\?|$)/i.test(s));
    const jsList: { url: string; body: string }[] = [];
    for (const s of jsUrls.slice(0, 8)) {
      const abs = sameOrigin(s, base, host); if (!abs) continue;
      try { const r = await ctx.guard.httpGet(abs, { timeoutMs: 7000 }); if (r && r.status === 200 && r.body) jsList.push({ url: abs, body: r.body }); } catch { /* */ }
    }
    const corpus = root.body + '\n' + jsList.map((j) => j.body).join('\n');

    // ── 클라우드 스토리지/백엔드 참조 노출(외부 능동접근 없이 참조만) ──
    cloudRefs(corpus, host, findings);

    // ── 프론트엔드: localStorage 토큰, 클라이언트 시크릿/API 키 ──
    if (/(local|session)Storage\.setItem\(\s*["'`]?[^"'`)]*(token|jwt|auth|access[_-]?token|api[_-]?key|secret|password|credential)/i.test(corpus)) {
      // evidence 는 저장소 종류 + 키 이름만(값 리터럴은 절대 포함하지 않음 — 시크릿 마스킹).
      const km = /((?:local|session)Storage)\.setItem\(\s*["'`]?([A-Za-z0-9_.\-]{1,40})/i.exec(corpus);
      findings.push(f('medium', '민감 토큰 클라이언트 저장(localStorage/sessionStorage)', host,
        '인증 토큰/시크릿을 localStorage/sessionStorage 에 저장합니다. XSS 발생 시 토큰이 탈취되고 HttpOnly 보호를 받지 못합니다.',
        `${km?.[1] || 'localStorage'}.setItem('${km?.[2] || '?'}', …) — 값 비표시(마스킹)`, '세션 토큰은 HttpOnly·Secure 쿠키로 저장하고, 부득이하면 메모리/짧은 만료를 사용하십시오.',
        'A05:2021', 'CWE-922', 'firm'));
    }
    clientSecrets(corpus, host, findings);

    // ── SourceMap 노출 ──
    for (const j of jsList.slice(0, 4)) {
      const mapUrl = j.url.replace(/(\?.*)?$/, '') + '.map';
      let r: HttpResp | null = null;
      try { r = await ctx.guard.httpGet(mapUrl, { timeoutMs: 6000 }); } catch { /* */ }
      // .map 이 실제로 접근 가능(200 + sources)하거나, data: URI 인라인 맵일 때만 노출로 본다(dangling 주석 오탐 억제).
      const probeOk = !!r && r.status === 200 && /"sources"|"mappings"|"sourcesContent"/.test(r.body);
      const inlineDataMap = /\/\/[#@]\s*sourceMappingURL=data:application\/json[^,]*,[A-Za-z0-9+/=]{20,}/i.test(j.body);
      if (probeOk || inlineDataMap) {
        findings.push(f('medium', `SourceMap 노출: ${probeOk ? stripOrigin(mapUrl, base) : '(inline data URI)'}`, host,
          '소스맵(.map)이 공개되어 난독화 이전의 원본 소스코드·내부 로직·주석이 복원될 수 있습니다.',
          probeOk ? `${stripOrigin(mapUrl, base)} → 200 (sources 포함)` : 'inline data: URI sourcemap (base64 sources 포함)',
          '운영 빌드에서 소스맵 공개를 비활성화하거나 인증 뒤로 옮기십시오.', 'A05:2021', 'CWE-540', 'firm'));
        break;
      }
    }

    // ── robots.txt 민감 경로 노출 ──
    let robots: HttpResp | null = null;
    try { robots = await ctx.guard.httpGet(base + '/robots.txt', { timeoutMs: 6000 }); } catch { /* */ }
    if (robots && robots.status === 200 && /(dis)?allow\s*:/i.test(robots.body) && !/<html/i.test(robots.body)) {
      const paths = [...robots.body.matchAll(/disallow\s*:\s*(\/[^\s#]{1,60})/gi)].map((m) => m[1]!);
      const SENS_RE = /(^|[/_.-])(admin|internal|private|backup|secret|config|manage|console|test|staging|hidden|portal|dashboard|api)([/_.-]|$)/i;   // 세그먼트 경계(부분문자열 오탐 억제)
      const sensitive = [...new Set(paths)].filter((p) => SENS_RE.test(p)).slice(0, 12);
      if (sensitive.length) {
        findings.push(f('low', `robots.txt 가 민감 경로를 노출 (${sensitive.length}건)`, host,
          'robots.txt 의 Disallow 항목이 관리/내부/백업 등 민감 경로를 그대로 드러냅니다. 공격자에게 숨겨진 경로 지도를 제공합니다.',
          `Disallow: ${sensitive.join(', ')}`, 'robots.txt 에 민감 경로를 나열하지 말고, 접근통제로 보호하십시오(robots 는 비밀 보장 수단이 아닙니다).',
          'A05:2021', 'CWE-200', 'firm', ['https://owasp.org/www-project-web-security-testing-guide/']));
      }
    }

    // ── 백업/소스 파일 전수(비파괴 GET, soft-404 억제) ──
    const apex = host.replace(/:\d+$/, '').split('.')[0] || 'site';
    const backupNames = ['/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql', '/database.sql', '/www.zip', '/site.tar.gz',
      '/.DS_Store', '/index.php.bak', '/config.php.bak', '/config.php~', '/web.config.bak', '/.env.bak', '/.env.local',
      '/app.zip', '/dist.zip', '/release.zip', `/${apex}.zip`, `/${apex}.sql`, '/index.php.old', '/old/', '/bak/', '/.bak'];
    let probed = 0;
    for (const bp of backupNames) {
      if (probed >= (ctx.deep ? backupNames.length : 8)) break;
      probed++;
      let r: HttpResp | null = null;
      try { r = await ctx.guard.httpGet(base + bp, { timeoutMs: 6000 }); } catch { continue; }
      if (!r || r.status !== 200 || !r.body || isSoft404(r)) continue;
      // 바이너리 매직바이트는 text() 디코딩으로 깨지므로 content-type·확장자·텍스트 시그니처로 판정.
      const ct = (r.headers['content-type'] || '').toLowerCase();
      const binaryCt = /application\/(zip|gzip|x-gzip|x-tar|octet-stream|sql)/.test(ct);
      const textSig = /INSERT INTO|CREATE TABLE|-- MySQL dump|DB_PASSWORD|<\?php|\[core\]|repositoryformatversion|Bud1/.test(r.body.slice(0, 400));
      const sig = binaryCt || textSig || /\.(zip|gz|tar|sql|bak|old)$/i.test(bp);
      if (sig) {
        findings.push(f('high', `백업/소스 파일 노출: ${bp}`, host + bp,
          '백업/덤프/소스 압축 파일이 외부에서 접근 가능합니다. 소스코드·자격증명·DB 덤프가 유출될 수 있습니다.',
          `${bp} → 200 (${r.headers['content-type'] || '?'}, ${r.body.length}B)`, '백업/소스 파일을 웹 루트에서 제거하고 접근을 차단하십시오. 배포 파이프라인에서 산출물 노출을 점검하십시오.',
          'A05:2021', 'CWE-530', 'firm', ['https://owasp.org/www-project-web-security-testing-guide/']));
      }
    }

    // ── 로그 파일 노출 ──
    for (const lp of ['/error.log', '/access.log', '/app.log', '/debug.log', '/logs/error.log', '/storage/logs/laravel.log', '/log/production.log']) {
      let r: HttpResp | null = null;
      try { r = await ctx.guard.httpGet(base + lp, { timeoutMs: 6000 }); } catch { continue; }
      if (r && r.status === 200 && r.body && !isSoft404(r) && /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|\bERROR\b|\bWARN\b|Exception|stack trace|\d{1,3}(\.\d{1,3}){3}\b/i.test(r.body.slice(0, 500))) {
        findings.push(f('high', `로그 파일 노출: ${lp}`, host + lp,
          '애플리케이션/접근 로그가 외부에서 접근 가능합니다. 내부 경로·사용자 활동·오류 스택·토큰/세션 등이 유출될 수 있습니다.',
          `${lp} → 200 (${r.body.length}B, 로그 형식)`, '로그 파일을 웹 루트 밖으로 옮기고 접근을 차단하십시오.', 'A05:2021', 'CWE-532', 'firm'));
        break;
      }
    }

    // ── Git 커밋 이력 노출(.git/logs/HEAD) ──
    try {
      const gh = await ctx.guard.httpGet(base + '/.git/logs/HEAD', { timeoutMs: 6000 });
      // reflog 형식(구해시 신해시 작성자…)을 요구해 본문 내 우연한 단일 SHA-1 매칭을 배제.
      if (gh && gh.status === 200 && gh.body && /^[0-9a-f]{40} [0-9a-f]{40} /m.test(gh.body) && !/<html/i.test(gh.body)) {
        findings.push(f('high', 'Git 커밋 이력 노출: /.git/logs/HEAD', host + '/.git/logs/HEAD',
          'Git 커밋 로그가 노출되어 커밋 해시·작성자·이메일·변경 이력이 드러나고, .git 디렉터리로 전체 소스 복원이 가능할 수 있습니다.',
          gh.body.slice(0, 100).replace(/\s+/g, ' '), '.git 디렉터리를 웹 루트에서 제거하고 접근을 차단하십시오(배포 시 .git 제외).', 'A05:2021', 'CWE-527', 'firm'));
      }
    } catch { /* */ }

    // ── 디버그 모드/프레임워크 디버그 노출 ──
    const dbg = matchDebug(root.body + JSON.stringify(root.headers));   // 서버 렌더 HTML·헤더만(번들 JS 제외 — 오탐 억제)
    if (dbg) {
      findings.push(f('medium', `서버 디버그 모드 노출 단서: ${dbg}`, host,
        `운영 응답에 서버측 디버거/디버그 시그니처(${dbg})가 관측됩니다. 상세 오류·내부 경로·설정이 노출되며, 디버거가 켜진 일부 프레임워크는 콘솔 실행 표면이 될 수 있습니다.`,
        dbg, '운영에서 디버그 모드/디버거를 비활성화하고 상세 오류를 숨기십시오.', 'A05:2021', 'CWE-489', 'tentative'));
    }
  } catch (e) {
    ctx.log(`exposure: 점검 오류 — ${(e as Error).message}`);
  }
  ctx.log(`exposure: 노출 정밀 점검 발견 ${findings.length}건`);
  return findings;
}

/** 클라우드 스토리지/백엔드 참조 노출 — 외부 능동접근 없이 참조 패턴만 보고(범위 밖 발신 금지). */
function cloudRefs(corpus: string, host: string, findings: Finding[]) {
  const seen = new Set<string>();
  const push = (sev: Sev, title: string, desc: string, ev: string, rem: string, cwe: string) => {
    if (seen.has(title)) return; seen.add(title);
    findings.push(f(sev, title, host, desc, ev, rem, 'A05:2021', cwe, 'tentative', ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']));
  };
  const s3 = /(?:https?:\/\/)?([a-z0-9.-]{3,63})\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com|s3\.amazonaws\.com\/([a-z0-9.-]{3,63})/i.exec(corpus);
  if (s3) push('high', 'AWS S3 버킷 참조 노출', '클라이언트 코드에 S3 버킷 참조가 노출됩니다. 버킷이 퍼블릭 읽기/목록이면 데이터가 유출됩니다(공개 여부 확인 필요).', `bucket: ${(s3[1] || s3[2] || '').slice(0, 60)}`, 'S3 퍼블릭 액세스 차단(Block Public Access)을 적용하고 버킷 정책을 최소화하십시오. 공개 목록(ListBucket)을 비활성화하십시오.', 'CWE-732');
  const gcs = /storage\.googleapis\.com\/([a-z0-9._-]{3,63})/i.exec(corpus);
  if (gcs) push('high', 'GCP Cloud Storage 버킷 참조 노출', 'GCS 버킷 참조가 노출됩니다. allUsers/allAuthenticatedUsers 공개 시 데이터 유출 위험이 있습니다(공개 여부 확인 필요).', `bucket: ${gcs[1]}`, 'GCS 버킷 IAM 에서 allUsers/allAuthenticatedUsers 를 제거하고 균일 버킷 수준 접근을 적용하십시오.', 'CWE-732');
  const az = /([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9-]{1,63})/i.exec(corpus);
  if (az) push('high', 'Azure Blob 컨테이너 참조 노출', 'Azure Blob 컨테이너 참조가 노출됩니다. 컨테이너 공개 액세스 시 데이터 유출 위험이 있습니다(공개 여부 확인 필요).', `account/container: ${az[1]}/${az[2]}`, 'Blob 컨테이너 공개 액세스를 Private 로 설정하고 SAS/RBAC 로 접근을 통제하십시오.', 'CWE-732');
  const fb = /firebaseio\.com|firebaseConfig|databaseURL\s*:\s*["']https:\/\/[a-z0-9-]+\.firebase/i.test(corpus);
  if (fb) push('high', 'Firebase 설정/DB 참조 노출', '클라이언트에 Firebase 설정(databaseURL/apiKey)이 노출됩니다. 보안 규칙이 느슨하면 인증 없이 DB 가 읽기/쓰기될 수 있습니다(규칙 확인 필요).', snippet(corpus, /databaseURL\s*:\s*["'][^"']{0,60}|firebaseio\.com[^"'\s]{0,40}/i) || 'firebaseConfig 참조', 'Firebase 보안 규칙(read/write)을 인증/권한 기반으로 강제하고, 민감 컬렉션의 공개 접근을 차단하십시오.', 'CWE-200');
}

/** 클라이언트측 시크릿/API 키 패턴(제공자별) — placeholder 제외, 값 마스킹. */
function clientSecrets(corpus: string, host: string, findings: Finding[]) {
  const RES: { re: RegExp; label: string; sev: Sev; requires?: RegExp }[] = [
    { re: /\bAKIA[0-9A-Z]{16}\b/g, label: 'AWS Access Key', sev: 'critical' },
    { re: /\bASIA[0-9A-Z]{16}\b/g, label: 'AWS 임시 키', sev: 'high' },
    { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: 'Google API Key', sev: 'high' },
    { re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g, label: 'Stripe Secret Key', sev: 'critical' },
    { re: /\bpk_live_[0-9A-Za-z]{20,}\b/g, label: 'Stripe Publishable Key', sev: 'low' },
    { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, label: 'GitHub Token', sev: 'critical' },
    { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, label: 'Slack Token', sev: 'high' },
    // Twilio SK 는 'SK'+32 hex 라 MD5 해시 등과 충돌 → twilio/Account SID(AC..) 맥락이 있을 때만.
    { re: /\bSK[0-9a-fA-F]{32}\b/g, label: 'Twilio Key', sev: 'high', requires: /twilio|account[_-]?sid|\bAC[0-9a-f]{32}\b/i },
    { re: /\bya29\.[0-9A-Za-z_-]{20,}\b/g, label: 'Google OAuth Token', sev: 'high' },
    { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, label: '개인키(Private Key)', sev: 'critical' },
  ];
  const seen = new Set<string>();
  for (const r of RES) {
    if (r.requires && !r.requires.test(corpus)) continue;
    for (const m of corpus.matchAll(r.re)) {
      const val = m[0];
      if (PLACEHOLDER.test(val) || seen.has(r.label)) continue;
      seen.add(r.label);
      findings.push(f(r.sev, `클라이언트 시크릿/API 키 노출: ${r.label}`, host,
        `클라이언트 번들/HTML 에 ${r.label} 가 노출됩니다. 추출해 백엔드 자원에 무단 접근·과금·오남용할 수 있습니다.`,
        `${r.label}: ${mask(val)}`, '비밀은 클라이언트에 두지 말고 서버측 프록시로만 호출하십시오. 노출된 키는 즉시 폐기·재발급하고 사용 로그를 점검하십시오.',
        'A02:2021', 'CWE-312', 'firm', ['https://cwe.mitre.org/data/definitions/312.html']));
      break;
    }
  }
}

function matchDebug(s: string): string | null {
  // 클라이언트 번들의 일반 debug:true 플래그는 오탐이 심해 제외하고, 서버측 디버거/디버그 페이지 시그니처만 본다.
  const rules: [RegExp, string][] = [
    [/Werkzeug Debugger|Traceback \(most recent call last\)/, 'Flask/Werkzeug 디버거'],
    [/Whoops\\|laravel.*debug|APP_DEBUG\s*=\s*true/i, 'Laravel APP_DEBUG'],
    [/Rails\.application\.config\.consider_all_requests_local|ActionDispatch::DebugExceptions/, 'Rails 디버그'],
    [/django.*DEBUG\s*=\s*True|You're seeing this error because you have/i, 'Django DEBUG'],
    [/customErrors mode="Off"|<compilation[^>]*debug="true"/i, 'ASP.NET debug=true'],
  ];
  for (const [re, name] of rules) if (re.test(s)) return name;
  return null;
}

function sameOrigin(src: string, base: string, host: string): string | null {
  if (!src || src.startsWith('//') || src.startsWith('#')) return null;
  if (/^https?:\/\//i.test(src)) { try { return new URL(src).host === host ? src : null; } catch { return null; } }
  if (/^[a-z][a-z0-9+.-]*:/i.test(src)) return null;
  if (src.startsWith('/')) return base.replace(/\/$/, '') + src;
  return base.replace(/\/$/, '') + '/' + src.replace(/^\.\//, '');
}
function snippet(s: string, re: RegExp): string { const m = re.exec(s); return m ? m[0].slice(0, 80).replace(/\s+/g, ' ') : ''; }
function stripOrigin(url: string, base: string): string { return url.startsWith(base) ? url.slice(base.replace(/\/$/, '').length) : url; }
function mask(k: string): string { return k.length > 10 ? k.slice(0, 6) + '…' + k.slice(-2) + ' (redacted)' : '***'; }
