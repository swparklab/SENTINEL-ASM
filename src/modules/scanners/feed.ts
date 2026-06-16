/**
 * 취약점 룰셋·CVE 피드 (설계 §4.3 / §6.4).
 * 운영에서는 KISA·NVD·CISA KEV·EPSS 피드를 서명된 채널로 자동 동기화하지만,
 * 본 구현은 동일 스키마의 시드 피드를 내장한다(폐쇄망 오프라인 번들에 대응).
 * 각 엔트리는 제품/버전 범위와 함께 CVSS·EPSS·KEV 메타를 보유한다.
 */
export interface CveEntry {
  cve: string;
  product: string;
  /** semver-lite: 이 버전 미만이면 취약 */
  vulnerableBelow: string;
  cvss: number;
  epss: number;     // 0–1 익스플로잇 확률
  kev: boolean;     // CISA KEV 등재 여부
  title: string;
  remediation: string;
  /** 생태계 — SBOM 매칭/표시용. 미지정 시 서비스 핑거프린트 대상. */
  ecosystem?: 'npm' | 'pypi' | 'maven' | 'service' | 'rubygems' | 'composer' | 'nuget' | 'cargo' | 'go';
}

export const CVE_FEED: CveEntry[] = [
  {
    cve: 'CVE-2021-44228', product: 'log4j', vulnerableBelow: '2.17.0',
    cvss: 10.0, epss: 0.975, kev: true,
    title: 'Apache Log4j2 원격코드실행 (Log4Shell)',
    remediation: 'Log4j 2.17.1 이상으로 업그레이드. JndiLookup 클래스 제거.',
  },
  {
    cve: 'CVE-2014-0160', product: 'openssl', vulnerableBelow: '1.0.1g',
    cvss: 7.5, epss: 0.94, kev: true,
    title: 'OpenSSL Heartbleed 메모리 노출',
    remediation: 'OpenSSL 1.0.1g 이상으로 업그레이드 후 키/인증서 재발급.',
  },
  {
    cve: 'CVE-2017-5638', product: 'struts', vulnerableBelow: '2.3.32',
    cvss: 10.0, epss: 0.97, kev: true,
    title: 'Apache Struts2 OGNL 원격코드실행',
    remediation: 'Struts 2.3.32 / 2.5.10.1 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2019-0211', product: 'apache', vulnerableBelow: '2.4.39',
    cvss: 7.8, epss: 0.42, kev: false,
    title: 'Apache HTTP Server 권한상승',
    remediation: 'Apache httpd 2.4.39 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2021-23017', product: 'nginx', vulnerableBelow: '1.21.0',
    cvss: 7.7, epss: 0.21, kev: false,
    title: 'nginx DNS resolver off-by-one 힙 오버플로',
    remediation: 'nginx 1.21.0 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2018-15473', product: 'openssh', vulnerableBelow: '7.7',
    cvss: 5.3, epss: 0.55, kev: false,
    title: 'OpenSSH 사용자 열거 취약점',
    remediation: 'OpenSSH 7.8 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2022-22965', product: 'spring', vulnerableBelow: '5.3.18',
    cvss: 9.8, epss: 0.91, kev: true,
    title: 'Spring Framework RCE (Spring4Shell)',
    remediation: 'Spring Framework 5.3.18 / 5.2.20 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2023-44487', product: 'nginx', vulnerableBelow: '1.25.3',
    cvss: 7.5, epss: 0.84, kev: true,
    title: 'HTTP/2 Rapid Reset DoS',
    remediation: 'HTTP/2 Rapid Reset 패치 적용 또는 동시 스트림 제한.',
  },
  {
    cve: 'CVE-2021-41773', product: 'apache', vulnerableBelow: '2.4.50',
    cvss: 7.5, epss: 0.96, kev: true,
    title: 'Apache HTTP Server 경로 우회 및 RCE',
    remediation: 'Apache httpd 2.4.51 이상으로 업그레이드.',
  },
  {
    cve: 'CVE-2014-6271', product: 'bash', vulnerableBelow: '4.3',
    cvss: 9.8, epss: 0.97, kev: true,
    title: 'GNU Bash Shellshock 명령 주입',
    remediation: '배포판 보안 패치 적용으로 Bash 업데이트.',
  },
  {
    cve: 'CVE-2021-34527', product: 'iis', vulnerableBelow: '10.0.99999',
    cvss: 8.8, epss: 0.90, kev: true,
    title: 'Windows Print Spooler RCE (PrintNightmare) — 연계 노출',
    remediation: '해당 KB 보안 패치 적용 및 Spooler 서비스 점검.',
  },

  // ───────── npm 생태계 (package.json / package-lock.json) ─────────
  { cve: 'CVE-2021-23337', product: 'lodash', vulnerableBelow: '4.17.21', cvss: 7.2, epss: 0.31, kev: false, ecosystem: 'npm',
    title: 'lodash 명령 주입 (template)', remediation: 'lodash 4.17.21 이상으로 업그레이드.' },
  { cve: 'CVE-2021-44906', product: 'minimist', vulnerableBelow: '1.2.6', cvss: 9.8, epss: 0.74, kev: false, ecosystem: 'npm',
    title: 'minimist 프로토타입 오염', remediation: 'minimist 1.2.6 이상으로 업그레이드.' },
  { cve: 'CVE-2021-3749', product: 'axios', vulnerableBelow: '0.21.2', cvss: 7.5, epss: 0.62, kev: false, ecosystem: 'npm',
    title: 'axios ReDoS (정규식 서비스 거부)', remediation: 'axios 0.21.2 이상으로 업그레이드.' },
  { cve: 'CVE-2022-24999', product: 'express', vulnerableBelow: '4.17.3', cvss: 7.5, epss: 0.44, kev: false, ecosystem: 'npm',
    title: 'express(qs) 프로토타입 오염 DoS', remediation: 'express 4.17.3 이상으로 업그레이드.' },
  { cve: 'CVE-2022-0235', product: 'node-fetch', vulnerableBelow: '2.6.7', cvss: 6.1, epss: 0.18, kev: false, ecosystem: 'npm',
    title: 'node-fetch 리다이렉트 시 인증정보 노출', remediation: 'node-fetch 2.6.7 이상으로 업그레이드.' },
  { cve: 'CVE-2022-46175', product: 'json5', vulnerableBelow: '2.2.2', cvss: 7.1, epss: 0.20, kev: false, ecosystem: 'npm',
    title: 'json5 프로토타입 오염', remediation: 'json5 2.2.2 이상으로 업그레이드.' },

  // ───────── PyPI 생태계 (requirements.txt / poetry / pipfile) ─────────
  { cve: 'CVE-2020-14343', product: 'pyyaml', vulnerableBelow: '5.4', cvss: 9.8, epss: 0.55, kev: false, ecosystem: 'pypi',
    title: 'PyYAML 임의 코드 실행 (full_load)', remediation: 'PyYAML 5.4 이상으로 업그레이드, safe_load 사용.' },
  { cve: 'CVE-2023-32681', product: 'requests', vulnerableBelow: '2.31.0', cvss: 6.1, epss: 0.28, kev: false, ecosystem: 'pypi',
    title: 'requests 프록시 인증정보 누출', remediation: 'requests 2.31.0 이상으로 업그레이드.' },
  { cve: 'CVE-2022-34265', product: 'django', vulnerableBelow: '3.2.14', cvss: 8.8, epss: 0.66, kev: false, ecosystem: 'pypi',
    title: 'Django SQL 주입 (Trunc/Extract)', remediation: 'Django 3.2.14 / 4.0.6 이상으로 업그레이드.' },
  { cve: 'CVE-2023-30861', product: 'flask', vulnerableBelow: '2.2.5', cvss: 7.5, epss: 0.34, kev: false, ecosystem: 'pypi',
    title: 'Flask 세션 쿠키 캐시 노출', remediation: 'Flask 2.2.5 / 2.3.2 이상으로 업그레이드.' },
  { cve: 'CVE-2021-33503', product: 'urllib3', vulnerableBelow: '1.26.5', cvss: 7.5, epss: 0.40, kev: false, ecosystem: 'pypi',
    title: 'urllib3 ReDoS', remediation: 'urllib3 1.26.5 이상으로 업그레이드.' },
  { cve: 'CVE-2020-11022', product: 'jquery', vulnerableBelow: '3.5.0', cvss: 6.1, epss: 0.36, kev: false, ecosystem: 'npm',
    title: 'jQuery 교차사이트 스크립팅(XSS)', remediation: 'jQuery 3.5.0 이상으로 업그레이드.' },
  { cve: 'CVE-2022-37601', product: 'loader-utils', vulnerableBelow: '1.4.1', cvss: 9.8, epss: 0.30, kev: false, ecosystem: 'npm',
    title: 'loader-utils 프로토타입 오염', remediation: 'loader-utils 1.4.2 이상으로 업그레이드.' },
  { cve: 'CVE-2022-24785', product: 'moment', vulnerableBelow: '2.29.2', cvss: 7.5, epss: 0.22, kev: false, ecosystem: 'npm',
    title: 'moment 경로 조작(서버측)', remediation: 'moment 2.29.2 이상으로 업그레이드.' },

  // ───────── Maven 생태계 (pom.xml) ─────────
  { cve: 'CVE-2022-42889', product: 'commons-text', vulnerableBelow: '1.10.0', cvss: 9.8, epss: 0.93, kev: false, ecosystem: 'maven',
    title: 'Apache Commons Text RCE (Text4Shell)', remediation: 'commons-text 1.10.0 이상으로 업그레이드.' },
  { cve: 'CVE-2022-1471', product: 'snakeyaml', vulnerableBelow: '2.0', cvss: 9.8, epss: 0.61, kev: false, ecosystem: 'maven',
    title: 'SnakeYAML 역직렬화 RCE', remediation: 'SnakeYAML 2.0 이상으로 업그레이드, SafeConstructor 사용.' },
  { cve: 'CVE-2020-36518', product: 'jackson-databind', vulnerableBelow: '2.13.2', cvss: 7.5, epss: 0.45, kev: false, ecosystem: 'maven',
    title: 'jackson-databind DoS(깊은 중첩)', remediation: 'jackson-databind 2.13.2.1 이상으로 업그레이드.' },
  { cve: 'CVE-2022-22978', product: 'spring-security', vulnerableBelow: '5.6.4', cvss: 9.1, epss: 0.50, kev: false, ecosystem: 'maven',
    title: 'Spring Security 인가 우회(정규식)', remediation: 'Spring Security 5.6.4 / 5.5.7 이상으로 업그레이드.' },

  // ───────── RubyGems (Gemfile.lock) ─────────
  { cve: 'CVE-2022-32209', product: 'rails-html-sanitizer', vulnerableBelow: '1.4.3', cvss: 8.2, epss: 0.30, kev: false, ecosystem: 'rubygems',
    title: 'rails-html-sanitizer XSS', remediation: 'rails-html-sanitizer 1.4.3 이상으로 업그레이드.' },
  { cve: 'CVE-2022-23633', product: 'rails', vulnerableBelow: '7.0.2.2', cvss: 6.5, epss: 0.20, kev: false, ecosystem: 'rubygems',
    title: 'Rails(actionpack) 세션정보 누출', remediation: 'Rails 7.0.2.2 / 6.1.4.7 이상으로 업그레이드.' },
  { cve: 'CVE-2022-24836', product: 'nokogiri', vulnerableBelow: '1.13.4', cvss: 7.5, epss: 0.25, kev: false, ecosystem: 'rubygems',
    title: 'Nokogiri ReDoS', remediation: 'Nokogiri 1.13.4 이상으로 업그레이드.' },

  // ───────── Composer (PHP) ─────────
  { cve: 'CVE-2023-3823', product: 'symfony', vulnerableBelow: '5.4.26', cvss: 8.0, epss: 0.20, kev: false, ecosystem: 'composer',
    title: 'Symfony XXE/정보노출', remediation: 'Symfony 5.4.26 / 6.2.13 이상으로 업그레이드.' },
  { cve: 'CVE-2022-31090', product: 'guzzlehttp/guzzle', vulnerableBelow: '7.4.5', cvss: 6.5, epss: 0.18, kev: false, ecosystem: 'composer',
    title: 'Guzzle 자격증명 누출(cross-domain)', remediation: 'guzzlehttp/guzzle 7.4.5 이상으로 업그레이드.' },
  { cve: 'CVE-2021-3129', product: 'laravel/framework', vulnerableBelow: '8.4.3', cvss: 9.8, epss: 0.96, kev: false, ecosystem: 'composer',
    title: 'Laravel Ignition RCE (디버그 모드)', remediation: 'laravel/framework 8.4.3 이상으로 업그레이드, 운영 디버그 비활성.' },

  // ───────── NuGet (.NET) ─────────
  { cve: 'CVE-2019-0820', product: 'newtonsoft.json', vulnerableBelow: '12.0.2', cvss: 7.5, epss: 0.22, kev: false, ecosystem: 'nuget',
    title: 'Newtonsoft.Json ReDoS', remediation: 'Newtonsoft.Json 12.0.2 이상으로 업그레이드.' },

  // ───────── Cargo (Rust) ─────────
  { cve: 'RUSTSEC-2023-0001', product: 'openssl', vulnerableBelow: '0.10.48', cvss: 7.5, epss: 0.10, kev: false, ecosystem: 'cargo',
    title: 'rust openssl 크레이트 use-after-free', remediation: 'openssl 크레이트 0.10.48 이상으로 업그레이드.' },

  // ───────── 2023–2024 고위험 CVE ─────────
  { cve: 'CVE-2023-44487', product: 'nginx', vulnerableBelow: '1.25.3', cvss: 7.5, epss: 0.92, kev: true, ecosystem: 'service',
    title: 'HTTP/2 Rapid Reset DoS (nginx)', remediation: 'nginx 1.25.3 이상 업그레이드 또는 http2_max_concurrent_streams 제한.' },
  { cve: 'CVE-2023-25690', product: 'apache', vulnerableBelow: '2.4.56', cvss: 9.8, epss: 0.83, kev: true, ecosystem: 'service',
    title: 'Apache HTTP Server HTTP Request Smuggling', remediation: 'Apache httpd 2.4.56 이상으로 업그레이드.' },
  { cve: 'CVE-2024-4577', product: 'php', vulnerableBelow: '8.3.8', cvss: 9.8, epss: 0.95, kev: true, ecosystem: 'service',
    title: 'PHP CGI 윈도우 인자 주입 RCE', remediation: 'PHP 8.1.29/8.2.20/8.3.8 이상으로 업그레이드.' },
  { cve: 'CVE-2024-6387', product: 'openssh', vulnerableBelow: '9.8p1', cvss: 8.1, epss: 0.88, kev: true, ecosystem: 'service',
    title: 'OpenSSH regreSSHion RCE (race condition)', remediation: 'OpenSSH 9.8p1 이상으로 업그레이드.' },
  { cve: 'CVE-2023-46604', product: 'activemq', vulnerableBelow: '5.15.16', cvss: 10.0, epss: 0.97, kev: true, ecosystem: 'maven',
    title: 'Apache ActiveMQ RCE (랜섬웨어 악용)', remediation: 'ActiveMQ 5.15.16/5.16.7/5.17.6/5.18.3 이상으로 업그레이드.' },
  { cve: 'CVE-2024-21626', product: 'runc', vulnerableBelow: '1.1.12', cvss: 8.6, epss: 0.72, kev: true, ecosystem: 'go',
    title: 'runc Leaky Vessels 컨테이너 탈출', remediation: 'runc 1.1.12 이상으로 업그레이드. Docker/Kubernetes 업데이트.' },
  { cve: 'CVE-2023-20198', product: 'iis', vulnerableBelow: '10.0.99999', cvss: 10.0, epss: 0.97, kev: true, ecosystem: 'service',
    title: 'Cisco IOS XE Web UI 권한상승(제로데이) — IIS 노출 비교 신호', remediation: '관련 서비스 접근 제한 및 패치 적용.' },
  { cve: 'CVE-2024-3094', product: 'xz-utils', vulnerableBelow: '5.6.1', cvss: 10.0, epss: 0.80, kev: true, ecosystem: 'service',
    title: 'XZ Utils 백도어 (sshd 원격 코드 실행)', remediation: 'xz-utils 5.4.x(안전 버전)으로 다운그레이드. 5.6.0/5.6.1 사용 즉시 중단.' },
  // npm 추가
  { cve: 'CVE-2024-29180', product: 'webpack-dev-middleware', vulnerableBelow: '7.1.0', cvss: 7.4, epss: 0.35, kev: false, ecosystem: 'npm',
    title: 'webpack-dev-middleware 경로 우회', remediation: 'webpack-dev-middleware 7.1.0 이상으로 업그레이드.' },
  { cve: 'CVE-2024-37890', product: 'ws', vulnerableBelow: '8.17.1', cvss: 7.5, epss: 0.28, kev: false, ecosystem: 'npm',
    title: 'ws WebSocket 라이브러리 DoS', remediation: 'ws 8.17.1 이상으로 업그레이드.' },
  { cve: 'CVE-2023-26115', product: 'word-wrap', vulnerableBelow: '1.2.4', cvss: 7.5, epss: 0.18, kev: false, ecosystem: 'npm',
    title: 'word-wrap ReDoS', remediation: 'word-wrap 1.2.4 이상으로 업그레이드.' },
  // PyPI 추가
  { cve: 'CVE-2024-3651', product: 'idna', vulnerableBelow: '3.7', cvss: 7.5, epss: 0.25, kev: false, ecosystem: 'pypi',
    title: 'idna DoS (slow codec)', remediation: 'idna 3.7 이상으로 업그레이드.' },
  { cve: 'CVE-2024-35195', product: 'requests', vulnerableBelow: '2.32.0', cvss: 5.6, epss: 0.15, kev: false, ecosystem: 'pypi',
    title: 'requests SSRF via proxies', remediation: 'requests 2.32.0 이상으로 업그레이드.' },
];

/** "1.18.0" 형태를 비교 가능한 숫자 배열로. */
export function parseVersion(v: string): number[] {
  return v.split(/[.\-+]/).map((p) => parseInt(p, 10) || 0);
}

export function lessThan(a: string, b: string): boolean {
  const av = parseVersion(a);
  const bv = parseVersion(b);
  const len = Math.max(av.length, bv.length);
  for (let i = 0; i < len; i++) {
    const x = av[i] ?? 0;
    const y = bv[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}
