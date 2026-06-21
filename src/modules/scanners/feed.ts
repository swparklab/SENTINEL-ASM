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
  // CVE-2023-44487(nginx)는 아래 service 생태계 엔트리(EPSS 0.92)로 단일화 — 중복 제거.
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
  // NOTE: IIS는 Server 배너가 major 버전('10.0')만 노출하므로 OS/패치 수준 CVE
  // (PrintNightmare/HTTP.sys 등)를 배너만으로 확정할 수 없다. '10.0.99999' 같은
  // 센티넬 버전은 모든 IIS 10.0 호스트에 무조건 매칭되어 오탐을 양산하므로 피드에서 제외한다.

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
  // 제거: CVE-2023-20198은 Cisco IOS XE Web UI 0-day로 Microsoft IIS와 무관하다.
  // product:'iis' + 센티넬 버전으로 등록되어 있어 'Microsoft-IIS/10.0' 배너를 가진
  // 모든 호스트에 무관한 critical+KEV 오탐을 발생시켰다. 피드에서 삭제한다.
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

  // ═════════════════════════════════════════════════════════════════
  // 확장 피드 — 서비스/라이브러리 고위험 CVE 대량 추가 (기존과 중복 금지)
  // ═════════════════════════════════════════════════════════════════

  // ───────── 서비스: nginx ─────────
  { cve: 'CVE-2019-9511', product: 'nginx', vulnerableBelow: '1.16.1', cvss: 7.5, epss: 0.45, kev: false, ecosystem: 'service',
    title: 'nginx HTTP/2 Data Dribble DoS', remediation: 'nginx 1.16.1 / 1.17.3 이상으로 업그레이드.' },
  { cve: 'CVE-2022-41741', product: 'nginx', vulnerableBelow: '1.23.2', cvss: 7.0, epss: 0.30, kev: false, ecosystem: 'service',
    title: 'nginx ngx_http_mp4_module 메모리 손상', remediation: 'nginx 1.23.2 / 1.22.1 이상으로 업그레이드 또는 mp4 모듈 비활성.' },

  // ───────── 서비스: apache httpd ─────────
  { cve: 'CVE-2021-40438', product: 'apache', vulnerableBelow: '2.4.49', cvss: 9.0, epss: 0.94, kev: true, ecosystem: 'service',
    title: 'Apache mod_proxy SSRF', remediation: 'Apache httpd 2.4.49 이상으로 업그레이드.' },
  { cve: 'CVE-2024-40725', product: 'apache', vulnerableBelow: '2.4.62', cvss: 5.3, epss: 0.20, kev: false, ecosystem: 'service',
    title: 'Apache httpd mod_proxy 소스코드 노출(부분 요청)', remediation: 'Apache httpd 2.4.62 이상으로 업그레이드.' },
  { cve: 'CVE-2024-38476', product: 'apache', vulnerableBelow: '2.4.60', cvss: 9.8, epss: 0.40, kev: false, ecosystem: 'service',
    title: 'Apache httpd 내부 핸들러 정보노출/SSRF', remediation: 'Apache httpd 2.4.60 이상으로 업그레이드.' },

  // ───────── 서비스: openssh ─────────
  { cve: 'CVE-2023-38408', product: 'openssh', vulnerableBelow: '9.3p2', cvss: 9.8, epss: 0.70, kev: false, ecosystem: 'service',
    title: 'OpenSSH ssh-agent PKCS#11 RCE', remediation: 'OpenSSH 9.3p2 이상으로 업그레이드.' },
  { cve: 'CVE-2016-0777', product: 'openssh', vulnerableBelow: '7.1p2', cvss: 6.5, epss: 0.35, kev: false, ecosystem: 'service',
    title: 'OpenSSH 클라이언트 roaming 정보노출', remediation: 'OpenSSH 7.1p2 이상으로 업그레이드 또는 UseRoaming no.' },

  // ───────── 서비스: openssl ─────────
  { cve: 'CVE-2022-3602', product: 'openssl', vulnerableBelow: '3.0.7', cvss: 7.5, epss: 0.30, kev: false, ecosystem: 'service',
    title: 'OpenSSL X.509 punycode 스택 버퍼 오버플로', remediation: 'OpenSSL 3.0.7 이상으로 업그레이드.' },
  { cve: 'CVE-2016-2107', product: 'openssl', vulnerableBelow: '1.0.2h', cvss: 5.9, epss: 0.50, kev: false, ecosystem: 'service',
    title: 'OpenSSL AES-NI 패딩 오라클(MITM)', remediation: 'OpenSSL 1.0.2h / 1.0.1t 이상으로 업그레이드.' },
  { cve: 'CVE-2014-3566', product: 'openssl', vulnerableBelow: '1.0.1j', cvss: 3.4, epss: 0.60, kev: false, ecosystem: 'service',
    title: 'SSLv3 POODLE 패딩 오라클', remediation: 'SSLv3 비활성화, OpenSSL 1.0.1j 이상으로 업그레이드.' },

  // ───────── 서비스: php ─────────
  { cve: 'CVE-2019-11043', product: 'php', vulnerableBelow: '7.3.11', cvss: 9.8, epss: 0.95, kev: true, ecosystem: 'service',
    title: 'PHP-FPM nginx 연동 RCE', remediation: 'PHP 7.3.11 / 7.2.24 이상으로 업그레이드.' },
  { cve: 'CVE-2018-5711', product: 'php', vulnerableBelow: '7.2.0', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'service',
    title: 'PHP GIF 처리 무한 루프 DoS', remediation: 'PHP 7.2.0 이상으로 업그레이드.' },

  // ───────── 서비스: tomcat ─────────
  { cve: 'CVE-2020-1938', product: 'tomcat', vulnerableBelow: '9.0.31', cvss: 9.8, epss: 0.96, kev: true, ecosystem: 'service',
    title: 'Apache Tomcat AJP Ghostcat 파일 노출/RCE', remediation: 'Tomcat 9.0.31 / 8.5.51 이상으로 업그레이드, AJP 커넥터 비활성/제한.' },
  { cve: 'CVE-2025-24813', product: 'tomcat', vulnerableBelow: '9.0.99', cvss: 9.8, epss: 0.80, kev: false, ecosystem: 'service',
    title: 'Apache Tomcat 부분 PUT 역직렬화 RCE', remediation: 'Tomcat 9.0.99 / 10.1.35 / 11.0.3 이상으로 업그레이드.' },
  { cve: 'CVE-2017-12615', product: 'tomcat', vulnerableBelow: '7.0.81', cvss: 8.1, epss: 0.92, kev: true, ecosystem: 'service',
    title: 'Apache Tomcat PUT JSP 업로드 RCE', remediation: 'Tomcat 7.0.81 이상으로 업그레이드, readonly 기본값 유지.' },

  // ───────── 서비스: iis / windows http.sys ─────────
  // 제거: CVE-2015-1635(MS15-034) / CVE-2021-31166은 Windows HTTP.sys/프로토콜 스택의
  // OS 패치 수준 취약점이다. IIS Server 배너('Microsoft-IIS/10.0')는 major 버전만 노출하여
  // 패치 적용 여부를 알 수 없고, '10.0.99999' 센티넬은 모든 IIS 10.0 호스트에 무조건
  // 매칭되어 critical/high 오탐을 양산한다. 배너 핑거프린트로 확정 불가하므로 피드에서 제외한다.

  // ───────── 서비스: exim / postfix (메일) ─────────
  { cve: 'CVE-2019-10149', product: 'exim', vulnerableBelow: '4.92', cvss: 9.8, epss: 0.97, kev: true, ecosystem: 'service',
    title: 'Exim deliver_message RCE (Return of the WIZard)', remediation: 'Exim 4.92 이상으로 업그레이드.' },
  { cve: 'CVE-2023-42115', product: 'exim', vulnerableBelow: '4.96.1', cvss: 9.8, epss: 0.55, kev: false, ecosystem: 'service',
    title: 'Exim SMTP AUTH 범위초과 쓰기 RCE', remediation: 'Exim 4.96.1 / 4.97 이상으로 업그레이드.' },

  // ───────── 서비스: proftpd / vsftpd (FTP) ─────────
  { cve: 'CVE-2019-12815', product: 'proftpd', vulnerableBelow: '1.3.6', cvss: 9.8, epss: 0.65, kev: false, ecosystem: 'service',
    title: 'ProFTPD mod_copy 임의 파일 복사/RCE', remediation: 'ProFTPD 1.3.6 이상으로 업그레이드, mod_copy 비활성.' },
  { cve: 'CVE-2021-30047', product: 'vsftpd', vulnerableBelow: '3.0.4', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'service',
    title: 'vsftpd 메모리 손상 DoS', remediation: 'vsftpd 3.0.4 이상으로 업그레이드.' },

  // ───────── 서비스: haproxy ─────────
  { cve: 'CVE-2023-25725', product: 'haproxy', vulnerableBelow: '2.7.3', cvss: 9.8, epss: 0.40, kev: false, ecosystem: 'service',
    title: 'HAProxy 헤더 처리 요청 밀반입(smuggling)', remediation: 'HAProxy 2.7.3 / 2.6.9 이상으로 업그레이드.' },
  { cve: 'CVE-2021-40346', product: 'haproxy', vulnerableBelow: '2.4.4', cvss: 8.6, epss: 0.50, kev: false, ecosystem: 'service',
    title: 'HAProxy 정수 오버플로 요청 밀반입', remediation: 'HAProxy 2.4.4 / 2.0.25 이상으로 업그레이드.' },

  // ───────── 서비스: node.js ─────────
  { cve: 'CVE-2021-22931', product: 'node', vulnerableBelow: '16.6.1', cvss: 9.8, epss: 0.30, kev: false, ecosystem: 'service',
    title: 'Node.js DNS rebinding/도메인 검증 우회 RCE', remediation: 'Node.js 16.6.1 / 14.17.5 / 12.22.5 이상으로 업그레이드.' },
  { cve: 'CVE-2023-30589', product: 'node', vulnerableBelow: '18.16.1', cvss: 7.5, epss: 0.18, kev: false, ecosystem: 'service',
    title: 'Node.js HTTP 요청 밀반입(헤더 처리)', remediation: 'Node.js 18.16.1 / 20.3.1 이상으로 업그레이드.' },

  // ───────── 서비스: mysql / mariadb ─────────
  { cve: 'CVE-2021-2154', product: 'mysql', vulnerableBelow: '8.0.24', cvss: 4.9, epss: 0.10, kev: false, ecosystem: 'service',
    title: 'MySQL Server(DML) 원격 DoS', remediation: 'MySQL 8.0.24 이상으로 업그레이드.' },
  { cve: 'CVE-2016-6662', product: 'mysql', vulnerableBelow: '5.7.15', cvss: 8.8, epss: 0.40, kev: false, ecosystem: 'service',
    title: 'MySQL my.cnf 임의 설정 주입 권한상승', remediation: 'MySQL 5.7.15 / 5.6.33 이상으로 업그레이드.' },

  // ───────── 서비스: postgresql ─────────
  { cve: 'CVE-2019-9193', product: 'postgresql', vulnerableBelow: '11.3', cvss: 8.8, epss: 0.30, kev: false, ecosystem: 'service',
    title: 'PostgreSQL COPY FROM PROGRAM 명령 실행', remediation: 'PostgreSQL 권한 제한, superuser 남용 점검.' },
  { cve: 'CVE-2024-10977', product: 'postgresql', vulnerableBelow: '17.1', cvss: 5.3, epss: 0.10, kev: false, ecosystem: 'service',
    title: 'PostgreSQL 클라이언트 위조 오류 메시지 처리', remediation: 'PostgreSQL 17.1 / 16.5 이상으로 업그레이드.' },

  // ───────── 서비스: redis ─────────
  { cve: 'CVE-2022-0543', product: 'redis', vulnerableBelow: '6.2.7', cvss: 10.0, epss: 0.97, kev: true, ecosystem: 'service',
    title: 'Redis Lua 샌드박스 탈출 RCE(데비안/우분투)', remediation: 'Redis 6.2.7 / 7.0.0 이상 또는 배포판 패치 적용.' },
  { cve: 'CVE-2023-28425', product: 'redis', vulnerableBelow: '7.0.10', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'service',
    title: 'Redis MSETNX 비정상 인자 DoS(크래시)', remediation: 'Redis 7.0.10 이상으로 업그레이드.' },

  // ───────── 서비스: mongodb ─────────
  { cve: 'CVE-2021-20329', product: 'mongodb', vulnerableBelow: '4.4.6', cvss: 6.5, epss: 0.15, kev: false, ecosystem: 'service',
    title: 'MongoDB 드라이버 BSON 타입 우회 주입', remediation: 'MongoDB 4.4.6 이상 및 드라이버 업데이트.' },

  // ───────── 서비스: elasticsearch ─────────
  { cve: 'CVE-2015-1427', product: 'elasticsearch', vulnerableBelow: '1.4.3', cvss: 9.8, epss: 0.95, kev: false, ecosystem: 'service',
    title: 'Elasticsearch Groovy 스크립트 샌드박스 우회 RCE', remediation: 'Elasticsearch 1.4.3 이상으로 업그레이드, 동적 스크립트 비활성.' },
  { cve: 'CVE-2014-3120', product: 'elasticsearch', vulnerableBelow: '1.2.0', cvss: 7.5, epss: 0.85, kev: false, ecosystem: 'service',
    title: 'Elasticsearch MVEL 동적 스크립트 RCE', remediation: 'Elasticsearch 1.2.0 이상으로 업그레이드, script.disable_dynamic.' },

  // ───────── 서비스: rabbitmq ─────────
  { cve: 'CVE-2021-32718', product: 'rabbitmq', vulnerableBelow: '3.8.16', cvss: 6.1, epss: 0.12, kev: false, ecosystem: 'service',
    title: 'RabbitMQ 관리 UI 저장형 XSS', remediation: 'RabbitMQ 3.8.16 이상으로 업그레이드.' },

  // ───────── 서비스: haproxy/기타 — proxy 스택 ─────────
  { cve: 'CVE-2023-44487', product: 'haproxy', vulnerableBelow: '2.8.3', cvss: 7.5, epss: 0.84, kev: true, ecosystem: 'service',
    title: 'HTTP/2 Rapid Reset DoS (HAProxy)', remediation: 'HAProxy 2.8.3 이상으로 업그레이드 또는 스트림 제한.' },

  // ───────── 라이브러리: Java/Maven ─────────
  { cve: 'CVE-2015-7501', product: 'commons-collections', vulnerableBelow: '3.2.2', cvss: 9.8, epss: 0.96, kev: false, ecosystem: 'maven',
    title: 'Apache Commons Collections 역직렬화 RCE', remediation: 'commons-collections 3.2.2 / 4.1 이상으로 업그레이드.' },
  { cve: 'CVE-2017-7525', product: 'jackson-databind', vulnerableBelow: '2.8.9', cvss: 9.8, epss: 0.93, kev: false, ecosystem: 'maven',
    title: 'jackson-databind 다형성 역직렬화 RCE', remediation: 'jackson-databind 2.8.9 / 2.7.9.1 이상으로 업그레이드, default typing 비활성.' },
  { cve: 'CVE-2022-25845', product: 'fastjson', vulnerableBelow: '1.2.83', cvss: 8.1, epss: 0.80, kev: false, ecosystem: 'maven',
    title: 'Alibaba Fastjson autotype 역직렬화 RCE', remediation: 'Fastjson 1.2.83 이상으로 업그레이드, safeMode 활성화.' },
  { cve: 'CVE-2022-22963', product: 'spring', vulnerableBelow: '3.1.7', cvss: 9.8, epss: 0.94, kev: true, ecosystem: 'maven',
    title: 'Spring Cloud Function SpEL 주입 RCE', remediation: 'Spring Cloud Function 3.1.7 / 3.2.3 이상으로 업그레이드.' },
  { cve: 'CVE-2016-1000027', product: 'spring', vulnerableBelow: '6.0.0', cvss: 9.8, epss: 0.65, kev: false, ecosystem: 'maven',
    title: 'Spring Framework RemoteInvocationSerializingExporter 역직렬화 RCE', remediation: 'Spring Framework 6.0 이상으로 업그레이드, HTTP invoker 사용 중단.' },
  { cve: 'CVE-2023-34040', product: 'spring', vulnerableBelow: '3.0.10', cvss: 5.3, epss: 0.20, kev: false, ecosystem: 'maven',
    title: 'Spring Kafka 역직렬화(헤더 신뢰) RCE 가능', remediation: 'Spring for Apache Kafka 3.0.10 / 2.9.11 이상으로 업그레이드.' },
  { cve: 'CVE-2017-9805', product: 'struts', vulnerableBelow: '2.5.13', cvss: 8.1, epss: 0.96, kev: true, ecosystem: 'maven',
    title: 'Apache Struts2 REST 플러그인 XStream 역직렬화 RCE', remediation: 'Struts 2.5.13 이상으로 업그레이드.' },
  { cve: 'CVE-2023-50164', product: 'struts', vulnerableBelow: '2.5.33', cvss: 9.8, epss: 0.88, kev: true, ecosystem: 'maven',
    title: 'Apache Struts2 파일 업로드 경로 조작 RCE', remediation: 'Struts 2.5.33 / 6.3.0.2 이상으로 업그레이드.' },
  { cve: 'CVE-2017-15095', product: 'jackson-databind', vulnerableBelow: '2.8.10', cvss: 9.8, epss: 0.70, kev: false, ecosystem: 'maven',
    title: 'jackson-databind 추가 가젯 역직렬화 RCE', remediation: 'jackson-databind 2.8.10 / 2.9.2 이상으로 업그레이드.' },

  // ───────── 라이브러리: npm ─────────
  { cve: 'CVE-2020-7660', product: 'serialize-javascript', vulnerableBelow: '3.1.0', cvss: 8.1, epss: 0.40, kev: false, ecosystem: 'npm',
    title: 'serialize-javascript XSS/코드 주입(역직렬화)', remediation: 'serialize-javascript 3.1.0 이상으로 업그레이드.' },
  { cve: 'CVE-2021-37713', product: 'tar', vulnerableBelow: '6.1.9', cvss: 8.2, epss: 0.30, kev: false, ecosystem: 'npm',
    title: 'node-tar 경로 조작(임의 파일 쓰기, Windows)', remediation: 'tar 6.1.9 / 5.0.10 / 4.4.18 이상으로 업그레이드.' },
  { cve: 'CVE-2019-20149', product: 'kind-of', vulnerableBelow: '6.0.3', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'npm',
    title: 'kind-of 타입 검사 우회', remediation: 'kind-of 6.0.3 이상으로 업그레이드.' },
  { cve: 'CVE-2024-4068', product: 'braces', vulnerableBelow: '3.0.3', cvss: 7.5, epss: 0.25, kev: false, ecosystem: 'npm',
    title: 'braces 메모리 자원 고갈 DoS', remediation: 'braces 3.0.3 이상으로 업그레이드.' },
  { cve: 'CVE-2024-4067', product: 'micromatch', vulnerableBelow: '4.0.8', cvss: 7.5, epss: 0.22, kev: false, ecosystem: 'npm',
    title: 'micromatch ReDoS', remediation: 'micromatch 4.0.8 이상으로 업그레이드.' },
  { cve: 'CVE-2021-3803', product: 'nth-check', vulnerableBelow: '2.0.1', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'npm',
    title: 'nth-check ReDoS', remediation: 'nth-check 2.0.1 이상으로 업그레이드.' },
  { cve: 'CVE-2022-3517', product: 'minimatch', vulnerableBelow: '3.0.5', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'npm',
    title: 'minimatch ReDoS', remediation: 'minimatch 3.0.5 이상으로 업그레이드.' },
  { cve: 'CVE-2024-28849', product: 'follow-redirects', vulnerableBelow: '1.15.6', cvss: 6.5, epss: 0.18, kev: false, ecosystem: 'npm',
    title: 'follow-redirects Proxy-Authorization 헤더 누출', remediation: 'follow-redirects 1.15.6 이상으로 업그레이드.' },
  { cve: 'CVE-2023-29020', product: 'fastify', vulnerableBelow: '4.10.2', cvss: 6.5, epss: 0.12, kev: false, ecosystem: 'npm',
    title: 'Fastify CORS 사전 검증 우회', remediation: 'Fastify 4.10.2 이상 및 @fastify/cors 8.2.1 이상으로 업그레이드.' },
  { cve: 'CVE-2024-37168', product: 'next', vulnerableBelow: '14.2.4', cvss: 5.3, epss: 0.12, kev: false, ecosystem: 'npm',
    title: 'Next.js 서버 액션 DoS(대용량 요청)', remediation: 'Next.js 14.2.4 이상으로 업그레이드.' },
  { cve: 'CVE-2025-29927', product: 'next', vulnerableBelow: '14.2.25', cvss: 9.1, epss: 0.80, kev: true, ecosystem: 'npm',
    title: 'Next.js 미들웨어 인가 우회(x-middleware-subrequest)', remediation: 'Next.js 14.2.25 / 15.2.3 이상으로 업그레이드.' },
  { cve: 'CVE-2025-30208', product: 'vite', vulnerableBelow: '6.2.3', cvss: 5.3, epss: 0.30, kev: false, ecosystem: 'npm',
    title: 'Vite dev server 임의 파일 읽기(@fs 우회)', remediation: 'Vite 6.2.3 / 5.4.15 이상으로 업그레이드, dev 서버 외부노출 금지.' },
  { cve: 'CVE-2024-43788', product: 'webpack', vulnerableBelow: '5.94.0', cvss: 6.4, epss: 0.10, kev: false, ecosystem: 'npm',
    title: 'webpack AutoPublicPathRuntimeModule DOM Clobbering XSS', remediation: 'webpack 5.94.0 이상으로 업그레이드.' },
  { cve: 'CVE-2019-19919', product: 'handlebars', vulnerableBelow: '4.5.3', cvss: 9.8, epss: 0.50, kev: false, ecosystem: 'npm',
    title: 'Handlebars 프로토타입 오염 RCE', remediation: 'handlebars 4.5.3 이상으로 업그레이드.' },
  { cve: 'CVE-2022-21680', product: 'marked', vulnerableBelow: '4.0.10', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'npm',
    title: 'marked 블록 인라인 처리 ReDoS', remediation: 'marked 4.0.10 이상으로 업그레이드.' },
  { cve: 'CVE-2020-26870', product: 'dompurify', vulnerableBelow: '2.0.17', cvss: 6.1, epss: 0.30, kev: false, ecosystem: 'npm',
    title: 'DOMPurify mXSS 우회', remediation: 'DOMPurify 2.0.17 이상으로 업그레이드.' },
  { cve: 'CVE-2024-45801', product: 'dompurify', vulnerableBelow: '3.1.3', cvss: 7.5, epss: 0.18, kev: false, ecosystem: 'npm',
    title: 'DOMPurify 노드 처리 우회 XSS', remediation: 'DOMPurify 3.1.3 이상으로 업그레이드.' },

  // ───────── 라이브러리: PyPI ─────────
  { cve: 'CVE-2022-40897', product: 'setuptools', vulnerableBelow: '65.5.1', cvss: 5.9, epss: 0.20, kev: false, ecosystem: 'pypi',
    title: 'setuptools package_index ReDoS', remediation: 'setuptools 65.5.1 이상으로 업그레이드.' },
  { cve: 'CVE-2023-43804', product: 'urllib3', vulnerableBelow: '2.0.6', cvss: 8.1, epss: 0.25, kev: false, ecosystem: 'pypi',
    title: 'urllib3 리다이렉트 시 Cookie 헤더 누출', remediation: 'urllib3 2.0.6 / 1.26.17 이상으로 업그레이드.' },
  { cve: 'CVE-2024-37891', product: 'urllib3', vulnerableBelow: '2.2.2', cvss: 4.4, epss: 0.10, kev: false, ecosystem: 'pypi',
    title: 'urllib3 Proxy-Authorization 헤더 리다이렉트 누출', remediation: 'urllib3 2.2.2 / 1.26.19 이상으로 업그레이드.' },
  { cve: 'CVE-2024-1135', product: 'gunicorn', vulnerableBelow: '22.0.0', cvss: 8.2, epss: 0.40, kev: false, ecosystem: 'pypi',
    title: 'Gunicorn Transfer-Encoding 요청 밀반입', remediation: 'Gunicorn 22.0.0 이상으로 업그레이드.' },
  { cve: 'CVE-2023-46136', product: 'werkzeug', vulnerableBelow: '3.0.1', cvss: 7.5, epss: 0.30, kev: false, ecosystem: 'pypi',
    title: 'Werkzeug multipart 파싱 DoS', remediation: 'Werkzeug 3.0.1 / 2.3.8 이상으로 업그레이드.' },
  { cve: 'CVE-2024-34069', product: 'werkzeug', vulnerableBelow: '3.0.3', cvss: 7.5, epss: 0.20, kev: false, ecosystem: 'pypi',
    title: 'Werkzeug 디버거 PIN 우회 RCE(개발 서버)', remediation: 'Werkzeug 3.0.3 이상으로 업그레이드, 운영에서 디버거 비활성.' },
  { cve: 'CVE-2024-22195', product: 'jinja2', vulnerableBelow: '3.1.3', cvss: 5.4, epss: 0.18, kev: false, ecosystem: 'pypi',
    title: 'Jinja2 xmlattr 필터 XSS', remediation: 'Jinja2 3.1.3 이상으로 업그레이드.' },
  { cve: 'CVE-2024-3772', product: 'pydantic', vulnerableBelow: '2.4.0', cvss: 7.5, epss: 0.12, kev: false, ecosystem: 'pypi',
    title: 'Pydantic 이메일 정규식 ReDoS', remediation: 'Pydantic 2.4.0 이상으로 업그레이드.' },
  { cve: 'CVE-2023-50447', product: 'pillow', vulnerableBelow: '10.2.0', cvss: 8.1, epss: 0.40, kev: false, ecosystem: 'pypi',
    title: 'Pillow ImageMath 임의 코드 실행', remediation: 'Pillow 10.2.0 이상으로 업그레이드.' },
  { cve: 'CVE-2021-25287', product: 'pillow', vulnerableBelow: '8.2.0', cvss: 9.1, epss: 0.30, kev: false, ecosystem: 'pypi',
    title: 'Pillow BLP 처리 범위초과 읽기', remediation: 'Pillow 8.2.0 이상으로 업그레이드.' },
  { cve: 'CVE-2021-41495', product: 'numpy', vulnerableBelow: '1.22.0', cvss: 5.3, epss: 0.10, kev: false, ecosystem: 'pypi',
    title: 'NumPy null 포인터 역참조 DoS', remediation: 'NumPy 1.22.0 이상으로 업그레이드.' },
  { cve: 'CVE-2023-49083', product: 'cryptography', vulnerableBelow: '41.0.6', cvss: 7.5, epss: 0.15, kev: false, ecosystem: 'pypi',
    title: 'pyca/cryptography PKCS7 NULL 역참조 크래시', remediation: 'cryptography 41.0.6 이상으로 업그레이드.' },
  { cve: 'CVE-2024-26130', product: 'cryptography', vulnerableBelow: '42.0.4', cvss: 7.5, epss: 0.12, kev: false, ecosystem: 'pypi',
    title: 'pyca/cryptography PKCS12 NULL 역참조 DoS', remediation: 'cryptography 42.0.4 이상으로 업그레이드.' },
  { cve: 'CVE-2023-37920', product: 'certifi', vulnerableBelow: '2023.7.22', cvss: 9.8, epss: 0.20, kev: false, ecosystem: 'pypi',
    title: 'certifi 신뢰 제거된 e-Tugra 루트 CA 포함', remediation: 'certifi 2023.7.22 이상으로 업그레이드.' },
  { cve: 'CVE-2022-40023', product: 'django', vulnerableBelow: '4.1.1', cvss: 7.5, epss: 0.15, kev: false, ecosystem: 'pypi',
    title: 'Django(Mako 연계) 템플릿 ReDoS', remediation: 'Django 4.1.1 / 3.2.16 이상으로 업그레이드.' },
  { cve: 'CVE-2024-24762', product: 'fastapi', vulnerableBelow: '0.109.1', cvss: 7.5, epss: 0.25, kev: false, ecosystem: 'pypi',
    title: 'FastAPI(python-multipart) Content-Type ReDoS', remediation: 'python-multipart 0.0.7 이상 및 FastAPI 0.109.1 이상으로 업그레이드.' },
  { cve: 'CVE-2024-40647', product: 'sentry-sdk', vulnerableBelow: '2.8.0', cvss: 5.9, epss: 0.10, kev: false, ecosystem: 'pypi',
    title: 'sentry-sdk 환경변수 정보 누출', remediation: 'sentry-sdk 2.8.0 이상으로 업그레이드.' },

  // ───────── 라이브러리: RubyGems ─────────
  { cve: 'CVE-2023-22796', product: 'rack', vulnerableBelow: '2.0.9.4', cvss: 5.3, epss: 0.18, kev: false, ecosystem: 'rubygems',
    title: 'Rack ContentLength ReDoS', remediation: 'rack 2.0.9.4 / 2.1.4.4 / 2.2.6.3 이상으로 업그레이드.' },
  { cve: 'CVE-2024-26146', product: 'rack', vulnerableBelow: '3.0.9.1', cvss: 7.5, epss: 0.15, kev: false, ecosystem: 'rubygems',
    title: 'Rack 헤더 파싱 ReDoS', remediation: 'rack 3.0.9.1 / 2.2.8.1 이상으로 업그레이드.' },
  { cve: 'CVE-2024-27456', product: 'rails', vulnerableBelow: '7.1.0', cvss: 5.3, epss: 0.10, kev: false, ecosystem: 'rubygems',
    title: 'Rails(actionpack) 쿠키 처리 정보노출', remediation: 'Rails 7.1.0 이상으로 업그레이드.' },
  { cve: 'CVE-2022-23517', product: 'rails-html-sanitizer', vulnerableBelow: '1.4.4', cvss: 7.3, epss: 0.20, kev: false, ecosystem: 'rubygems',
    title: 'rails-html-sanitizer ReDoS', remediation: 'rails-html-sanitizer 1.4.4 이상으로 업그레이드.' },
  { cve: 'CVE-2024-25126', product: 'rack', vulnerableBelow: '3.0.9.2', cvss: 7.5, epss: 0.12, kev: false, ecosystem: 'rubygems',
    title: 'Rack Content-Type 헤더 ReDoS', remediation: 'rack 3.0.9.2 / 2.2.8.1 이상으로 업그레이드.' },
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
