/**
 * 소프트웨어 구성요소(SBOM) 정적 취약점 분석 (설계 §4.3 SBOM/CVE 대조).
 * 사용자가 제공한 의존성 매니페스트를 파싱하여 컴포넌트 목록을 만들고, 내장 CVE 피드와
 * 대조한다. **원격 대상에 어떤 트래픽도 발생시키지 않는 순수 정적 분석**이므로 소유권
 * 검증 게이트(§3)의 대상이 아니며, 권한 절차 없이 즉시 수행 가능하다.
 */
import { id } from '../../util.js';
import type { Finding } from '../../types.js';
import { CVE_FEED, lessThan } from './feed.js';

export interface SbomComponent { name: string; version: string; ecosystem?: string; }

const cleanVer = (v: string): string =>
  (v || '').trim().replace(/^[v^~>=<\s]+/, '').replace(/\s.*$/, '').replace(/[,;].*$/, '');

const clean = (s: string): string => (s || '').trim().toLowerCase();

/** 매니페스트 종류를 자동 감지하여 컴포넌트 목록으로 파싱. */
export function parseManifest(filename: string, content: string): { components: SbomComponent[]; format: string } {
  const fn = (filename || '').toLowerCase();
  const text = content || '';

  // yarn.lock / pnpm-lock.yaml (텍스트 lockfile)
  if (fn.includes('yarn.lock') || /^# yarn lockfile/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/^"?([^@\n"]+)@[^:\n]+"?:\s*\n(?:.*\n)*?\s+version:?\s+"?([0-9][^"\n]*)/gm)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'npm' });
    if (out.length) return { format: 'yarn.lock', components: dedupe(out) };
  }
  if (fn.includes('pnpm-lock') || /^lockfileVersion:/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/^\s*\/?(@?[\w.-]+(?:\/[\w.-]+)?)[@/]([0-9][\w.+-]*):/gm)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'npm' });
    if (out.length) return { format: 'pnpm-lock', components: dedupe(out) };
  }
  // Gemfile.lock (RubyGems)
  if (fn.includes('gemfile.lock') || /^GEM\s*$/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/^\s{4}([a-z0-9._-]+) \(([0-9][^)]*)\)/gm)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'rubygems' });
    if (out.length) return { format: 'Gemfile.lock', components: dedupe(out) };
  }
  // Cargo.lock (Rust)
  if (fn.includes('cargo.lock') || /^\[\[package\]\]/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"/g)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'cargo' });
    if (out.length) return { format: 'Cargo.lock', components: dedupe(out) };
  }
  // poetry.lock (PyPI)
  if (fn.includes('poetry.lock')) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/\[\[package\]\][\s\S]*?name = "([^"]+)"[\s\S]*?version = "([^"]+)"/g)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'pypi' });
    if (out.length) return { format: 'poetry.lock', components: dedupe(out) };
  }
  // build.gradle (Maven 좌표)
  if (fn.endsWith('.gradle') || fn.endsWith('.gradle.kts')) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/(?:implementation|api|compile|runtimeOnly|testImplementation)[\s(]+['"]([\w.-]+):([\w.-]+):([\w.+-]+)['"]/g)) out.push({ name: clean(m[2]!), version: cleanVer(m[3]!), ecosystem: 'maven' });
    if (out.length) return { format: 'build.gradle', components: dedupe(out) };
  }
  // .csproj / packages.config (NuGet)
  if (fn.endsWith('.csproj') || fn.includes('packages.config') || /<PackageReference|<package\s+id=/.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'nuget' });
    for (const m of text.matchAll(/<package\s+id="([^"]+)"\s+version="([^"]+)"/gi)) out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'nuget' });
    if (out.length) return { format: 'NuGet (.csproj/packages.config)', components: dedupe(out) };
  }

  // 1) JSON 계열 (package.json / package-lock.json / CycloneDX SBOM / Pipfile.lock / composer)
  if (/^\s*[{[]/.test(text)) {
    try {
      const json = JSON.parse(text);
      // Pipfile.lock (PyPI)
      if (json._meta && (json.default || json.develop)) {
        const out: SbomComponent[] = [];
        for (const grp of [json.default, json.develop]) for (const [name, meta] of Object.entries<any>(grp || {})) { const v = cleanVer(String(meta?.version ?? '')); if (v) out.push({ name: clean(name), version: v, ecosystem: 'pypi' }); }
        if (out.length) return { format: 'Pipfile.lock', components: dedupe(out) };
      }
      // composer.lock / composer.json (PHP)
      if (Array.isArray(json.packages) && json.packages[0]?.name && fn.includes('composer')) {
        const out: SbomComponent[] = [];
        for (const grp of [json.packages, json['packages-dev'] || []]) for (const p of grp) if (p?.name && p?.version) out.push({ name: clean(p.name), version: cleanVer(p.version), ecosystem: 'composer' });
        if (out.length) return { format: 'composer.lock', components: dedupe(out) };
      }
      if (fn.includes('composer.json') && (json.require || json['require-dev'])) {
        const deps = { ...(json.require || {}), ...(json['require-dev'] || {}) };
        const out = Object.entries<string>(deps).filter(([n]) => n.includes('/')).map(([name, ver]) => ({ name: clean(name), version: cleanVer(ver), ecosystem: 'composer' as const })).filter((c) => c.version);
        if (out.length) return { format: 'composer.json', components: out };
      }
      // CycloneDX
      if (json.bomFormat === 'CycloneDX' || Array.isArray(json.components)) {
        return {
          format: 'CycloneDX SBOM',
          components: (json.components || []).map((c: any) => ({
            name: clean(c.name), version: cleanVer(String(c.version ?? '')),
            ecosystem: c.purl?.split(':')[1]?.split('/')[0],
          })).filter((c: SbomComponent) => c.name && c.version),
        };
      }
      // package-lock.json (v2/v3: packages, v1: dependencies)
      if (json.lockfileVersion || json.packages || (json.dependencies && fn.includes('lock'))) {
        const out: SbomComponent[] = [];
        const pkgs = json.packages || {};
        for (const [pathKey, meta] of Object.entries<any>(pkgs)) {
          if (!pathKey || !meta?.version) continue;
          const name = pathKey.replace(/^.*node_modules\//, '');
          if (name) out.push({ name: clean(name), version: cleanVer(meta.version), ecosystem: 'npm' });
        }
        for (const [name, meta] of Object.entries<any>(json.dependencies || {})) {
          if (meta?.version) out.push({ name: clean(name), version: cleanVer(meta.version), ecosystem: 'npm' });
        }
        return { format: 'npm lockfile', components: dedupe(out) };
      }
      // package.json
      const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
      const out = Object.entries<string>(deps).map(([name, ver]) => ({ name: clean(name), version: cleanVer(ver), ecosystem: 'npm' }));
      return { format: 'package.json', components: out.filter((c) => c.name && c.version) };
    } catch { /* JSON 아님 → 텍스트 파서로 폴백 */ }
  }

  // 2) pom.xml (Maven)
  if (fn.endsWith('.xml') || /<dependency>/.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g)) {
      out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'maven' });
    }
    if (out.length) return { format: 'Maven pom.xml', components: out };
  }

  // 3) go.mod
  if (fn.endsWith('go.mod') || /^\s*module\s+/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/^\s*([\w./-]+)\s+v(\d[\w.\-+]*)/gm)) {
      const name = m[1]!.split('/').pop()!;
      out.push({ name: clean(name), version: cleanVer(m[2]!), ecosystem: 'go' });
    }
    if (out.length) return { format: 'go.mod', components: out };
  }

  // 4) requirements.txt / 일반 목록 (name==ver, name@ver, name ver)
  const out: SbomComponent[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    let m = line.match(/^([A-Za-z0-9._\-@/]+)\s*(?:==|>=|~=|@|\s)\s*v?(\d[\w.\-+]*)/);
    if (m) {
      const name = m[1]!.replace(/^@[^/]+\//, (s) => s); // scoped npm 유지
      out.push({ name: clean(name), version: cleanVer(m[2]!) });
    }
  }
  return { format: out.length ? 'requirements/목록' : '미인식', components: out };
}

function dedupe(comps: SbomComponent[]): SbomComponent[] {
  const seen = new Set<string>();
  return comps.filter((c) => { const k = `${c.name}@${c.version}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/** 컴포넌트 이름이 피드 제품과 매칭되는지 (정확/접두/부분 일치). */
function matches(compName: string, product: string): boolean {
  const n = compName.replace(/^@[^/]+\//, '');
  return n === product || n.startsWith(product + '-') || n.startsWith(product + '.') || n === product.replace(/-/g, '');
}

const f = (severity: Finding['severity'], title: string, target: string, description: string, evidence?: string, remediation?: string): Finding =>
  ({ id: id('fnd'), module: 'cve', severity, title, target, description, evidence, remediation, confidence: 'firm' });

const FILE_SECRET_RULES: [RegExp, string][] = [
  [/AKIA[0-9A-Z]{16}/, 'AWS Access Key'], [/sk_live_[0-9a-zA-Z]{16,}/, 'Stripe Secret Key'],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/, 'Slack Token'], [/AIza[0-9A-Za-z_\-]{35}/, 'Google API Key'],
  [/gh[pousr]_[0-9A-Za-z]{30,}/, 'GitHub Token'], [/github_pat_[0-9A-Za-z_]{60,}/, 'GitHub PAT'],
  [/glpat-[0-9A-Za-z_-]{20}/, 'GitLab Token'], [/npm_[A-Za-z0-9]{36}/, 'npm Token'],
  [/SG\.[\w-]{22}\.[\w-]{43}/, 'SendGrid Key'], [/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'Private Key'],
  [/(?:password|secret|token|api[_-]?key|access[_-]?key|db[_-]?password|connectionstring)\s*[:=]\s*['"][^'"\s${<]{8,}['"]/i, '하드코딩 자격증명'],
];
const PLACEHOLDER = /CHANGEME|xxxx|example|placeholder|your_|<.*>|\$\{|dummy|test123/i;

/** EOL 런타임 표 (오프라인 정적, 메이저:EOL일자). */
const EOL: Record<string, [string, string][]> = {
  node: [['14', '2023-04-30'], ['16', '2023-09-11'], ['18', '2025-04-30']],
  python: [['2.7', '2020-01-01'], ['3.6', '2021-12-23'], ['3.7', '2023-06-27'], ['3.8', '2024-10-07']],
  php: [['7.2', '2020-11-30'], ['7.3', '2021-12-06'], ['7.4', '2022-11-28'], ['8.0', '2023-11-26']],
  ruby: [['2.6', '2022-03-31'], ['2.7', '2023-03-31'], ['3.0', '2024-03-31']],
  openjdk: [['8', '2030-12-31'], ['11', '2032-01-01']],
  debian: [['8', '2020-06-30'], ['9', '2022-06-30'], ['10', '2024-06-30']],
  ubuntu: [['16.04', '2021-04-30'], ['18.04', '2023-05-31']],
};

/**
 * 업로드된 소프트웨어 파일의 정적 보안 감사 (CVE 대조와 별개).
 * 시크릿·Dockerfile·IaC·CI·EOL·install 훅·비고정 의존성을 비파괴(순수 정적)로 점검.
 */
export function staticFileAudit(filename: string, content: string): Finding[] {
  const out: Finding[] = [];
  const fn = (filename || '').toLowerCase();
  const text = content || '';

  // 1) 하드코딩 시크릿 (모든 업로드 파일)
  for (const [re, label] of FILE_SECRET_RULES) {
    const m = re.exec(text);
    if (m && !PLACEHOLDER.test(m[0])) { out.push(f('critical', `업로드 파일 하드코딩 시크릿: ${label}`, filename || 'file', `파일에 ${label} 로 보이는 비밀정보가 평문 포함되어 있습니다.`, m[0].slice(0, 24) + '…', '비밀정보를 환경변수/시크릿 매니저로 이전하고 노출분을 즉시 폐기·재발급하십시오.')); break; }
  }
  // .npmrc/.pypirc 레지스트리 자격증명
  if (/_authToken=|_auth=|_password=/.test(text) && /\.npmrc/.test(fn + text.slice(0, 20))) out.push(f('high', '.npmrc 레지스트리 토큰 노출', filename || '.npmrc', '레지스트리 인증 토큰이 평문 포함되어 있습니다.', '_authToken=…', '토큰을 환경변수로 이전하고 폐기·재발급하십시오.'));

  // 2) Dockerfile 보안 린트
  if (fn.includes('dockerfile') || /^FROM\s+\S/mi.test(text)) {
    const fromTags = [...text.matchAll(/^FROM\s+(\S+)/gim)].map((m) => m[1]!);
    if (fromTags.some((t) => /:latest$/.test(t) || !/[:@]/.test(t))) out.push(f('medium', 'Dockerfile 베이스 이미지 미고정(:latest/태그없음)', filename || 'Dockerfile', '재현 불가·예기치 않은 변경 위험(CWE-1357).', fromTags.join(', '), '베이스 이미지를 특정 태그 또는 @sha256 다이제스트로 고정하십시오.'));
    if (!/^USER\s+(?!root|0)/mi.test(text)) out.push(f('medium', 'Dockerfile 비-root USER 미설정', filename || 'Dockerfile', '컨테이너가 root 로 실행되어 침해 시 영향이 큽니다(CWE-250).', 'no non-root USER', '최종 스테이지에 USER 비-root 를 지정하십시오.'));
    if (/(curl|wget)\b[^\n]*\|\s*(sh|bash|python|node)/i.test(text)) out.push(f('high', 'Dockerfile 원격 스크립트 파이프 실행(curl|sh)', filename || 'Dockerfile', '무결성 검증 없는 원격 스크립트 실행은 공급망 위험입니다(CWE-494).', 'curl ... | sh', '스크립트를 고정·검증 후 실행하십시오.'));
    if (/^ADD\s+https?:\/\//mi.test(text)) out.push(f('medium', 'Dockerfile 원격 ADD(무결성 미검증)', filename || 'Dockerfile', '원격 URL ADD 는 변조 위험이 있습니다.', 'ADD http(s)://', 'COPY + 체크섬 검증을 사용하십시오.'));
    if (/(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*[=\s]\S/i.test(text)) out.push(f('high', 'Dockerfile ENV/ARG 시크릿', filename || 'Dockerfile', '빌드 인자/환경변수에 시크릿이 포함되어 이미지 레이어에 남습니다(CWE-798).', 'ENV *_SECRET=…', '빌드시 시크릿은 secret mount 를 사용하십시오.'));
  }

  // 3) IaC 린트 (docker-compose / k8s / terraform)
  if (/^services:/m.test(text) || fn.includes('docker-compose') || fn.includes('compose.y')) {
    if (/privileged:\s*true/.test(text)) out.push(f('high', 'compose 컨테이너 privileged:true', filename || 'compose', '특권 컨테이너는 호스트 장악으로 이어질 수 있습니다(CWE-250).', 'privileged: true', '특권 모드를 제거하고 필요한 capability 만 부여하십시오.'));
    if (/\/var\/run\/docker\.sock/.test(text)) out.push(f('high', 'compose Docker 소켓 마운트', filename || 'compose', 'docker.sock 마운트는 사실상 호스트 root 권한입니다.', '/var/run/docker.sock', 'docker 소켓 마운트를 제거하십시오.'));
    if (/network_mode:\s*host|pid:\s*host/.test(text)) out.push(f('medium', 'compose host 네임스페이스 공유', filename || 'compose', 'host 네트워크/PID 공유는 격리를 약화시킵니다.', 'network_mode/pid: host', '호스트 네임스페이스 공유를 피하십시오.'));
  }
  if (/kind:\s*(Deployment|Pod|StatefulSet|DaemonSet)/.test(text)) {
    if (/privileged:\s*true/.test(text)) out.push(f('high', 'k8s privileged 컨테이너', filename || 'k8s', '특권 파드는 노드 장악 위험이 있습니다.', 'privileged: true', 'securityContext.privileged 를 false 로.'));
    if (/hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true/.test(text)) out.push(f('medium', 'k8s host 네임스페이스 사용', filename || 'k8s', 'hostNetwork/PID/IPC 는 격리를 약화시킵니다.', 'host*: true', '호스트 네임스페이스 사용을 제거하십시오.'));
    if (!/runAsNonRoot:\s*true/.test(text)) out.push(f('low', 'k8s runAsNonRoot 미설정', filename || 'k8s', '컨테이너가 root 로 실행될 수 있습니다.', 'no runAsNonRoot', 'securityContext.runAsNonRoot: true 를 설정하십시오.'));
  }
  if (fn.endsWith('.tf') || fn.includes('terraform') || /resource\s+"aws_/.test(text)) {
    if (/cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/.test(text)) out.push(f('high', 'Terraform 0.0.0.0/0 전체 개방', filename || 'terraform', '보안그룹이 전체 인터넷에 개방되어 있습니다(CWE-732).', '0.0.0.0/0', '소스 CIDR 를 필요한 범위로 제한하십시오.'));
    if (/(access_key|secret_key|password)\s*=\s*"[^"${]/.test(text)) out.push(f('critical', 'Terraform 평문 자격증명', filename || 'terraform', 'IaC 에 평문 자격증명이 포함되어 있습니다.', 'access_key/secret_key=…', '변수/시크릿 매니저로 이전하고 폐기·재발급하십시오.'));
    if (/acl\s*=\s*"public-read"/.test(text)) out.push(f('medium', 'Terraform 퍼블릭 ACL', filename || 'terraform', '스토리지가 공개 읽기로 설정되어 있습니다.', 'acl=public-read', '비공개 ACL 로 변경하십시오.'));
  }

  // 4) CI/CD 파이프라인 린트
  if (/\.github\/workflows|\.gitlab-ci|jenkinsfile|azure-pipelines/.test(fn) || /^on:\s|^stages:\s|pipeline\s*\{/m.test(text)) {
    if (/uses:\s*[\w-]+\/[\w-]+@(main|master|v\d+)\b/.test(text)) out.push(f('medium', 'CI 서드파티 액션 SHA 미고정', filename || 'CI', '액션을 가변 태그/브랜치로 참조하면 공급망 변조 위험이 있습니다(CWE-829).', 'uses: …@main', '액션을 커밋 SHA 로 고정하십시오.'));
    if (/pull_request_target/.test(text) && /actions\/checkout/.test(text)) out.push(f('high', 'CI pull_request_target + checkout(권한상승)', filename || 'CI', '신뢰되지 않은 PR 코드가 비밀에 접근할 수 있습니다.', 'pull_request_target', 'pull_request 트리거 사용 또는 권한을 최소화하십시오.'));
  }

  // 5) EOL 런타임 (Dockerfile FROM / 매니페스트 엔진 제약)
  for (const [rt, vers] of Object.entries(EOL)) {
    const m = new RegExp(`\\b${rt}[:@ ="']*v?(\\d+(?:\\.\\d+)?)`, 'i').exec(text);
    if (!m) continue;
    const v = m[1]!;
    const hit = vers.find(([ver]) => v === ver || v.startsWith(ver + '.'));
    if (hit && Date.parse(hit[1]) < Date.now()) out.push(f('high', `EOL 런타임 사용: ${rt} ${v} (지원 종료 ${hit[1]})`, filename || 'manifest', '지원 종료된 런타임은 보안 패치를 받지 못합니다.', `${rt} ${v}`, `${rt} 를 지원 중인 메이저 버전으로 업그레이드하십시오.`));
  }

  // 6) install 훅 + 비고정/원격 의존성 (package.json)
  if (/"scripts"\s*:/.test(text) && /^\s*[{[]/.test(text)) {
    try {
      const j = JSON.parse(text);
      for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
        const s = j.scripts?.[hook];
        if (s && /(curl|wget|node\s+-e|base64\s+-d|eval|child_process|https?:\/\/)/.test(s)) out.push(f('high', `package.json ${hook} 위험 스크립트`, filename || 'package.json', '설치 시 원격/동적 코드를 실행해 공급망 위험이 있습니다(CWE-506).', `${hook}: ${String(s).slice(0, 60)}`, '설치 훅에서 원격 실행을 제거하십시오.'));
      }
      const allDeps = { ...(j.dependencies || {}), ...(j.devDependencies || {}) };
      const nonpinned = Object.entries<string>(allDeps).filter(([, v]) => /^(git\+|github:|https?:|file:|\*|latest)/.test(String(v)));
      if (nonpinned.length) out.push(f('medium', `비고정/원격 소스 의존성 ${nonpinned.length}건`, filename || 'package.json', 'git/URL/latest 의존성은 빌드 비결정·공급망 위험입니다(CWE-1357).', nonpinned.slice(0, 5).map(([n, v]) => `${n}:${v}`).join(', '), '버전을 고정하고 신뢰 레지스트리를 사용하십시오.'));
    } catch { /* */ }
  }

  return out;
}

/** SBOM 컴포넌트를 CVE 피드와 대조하여 발견사항 생성. */
export function matchSbom(components: SbomComponent[]): Finding[] {
  const findings: Finding[] = [];
  for (const comp of components) {
    if (!comp.version) continue;
    for (const entry of CVE_FEED) {
      if (entry.ecosystem && entry.ecosystem !== 'service' && matches(comp.name, entry.product) && lessThan(comp.version, entry.vulnerableBelow)) {
        const sev: Finding['severity'] =
          entry.cvss >= 9 ? 'critical' : entry.cvss >= 7 ? 'high' : entry.cvss >= 4 ? 'medium' : 'low';
        findings.push({
          id: id('fnd'), module: 'cve', severity: sev,
          title: `${entry.cve}: ${entry.title}`,
          target: `${comp.name}@${comp.version}`,
          description: `${comp.name} ${comp.version} 은(는) ${entry.vulnerableBelow} 미만으로 알려진 취약점에 노출됩니다.`,
          evidence: `SBOM(${comp.ecosystem ?? entry.ecosystem}): ${comp.name}@${comp.version}`,
          remediation: entry.remediation,
          cvss: entry.cvss, epss: entry.epss, kev: entry.kev, cve: entry.cve,
        });
      }
    }
  }
  return findings;
}
