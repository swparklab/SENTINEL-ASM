/**
 * 취약점 분류 및 컴플라이언스 매핑 (설계 §5.2 — 전문 확장판).
 * 각 발견사항을 CWE · OWASP Top 10(2021) · OWASP ASVS · ISMS-P · ISO/IEC 27001 ·
 * PCI-DSS · NIST CSF · GDPR/개인정보보호법 통제로 자동 연계하고 표준 참고자료를 부착한다.
 */
import type { ComplianceMapping, Finding } from '../../types.js';

interface Klass {
  match: (f: Finding) => boolean;
  cwe: string;
  owasp: string;
  references: string[];
  frameworks: ComplianceMapping[];
}

const T10 = {
  A01: 'A01:2021 취약한 접근통제',
  A02: 'A02:2021 암호화 실패',
  A03: 'A03:2021 인젝션',
  A05: 'A05:2021 보안 설정 오류',
  A06: 'A06:2021 취약하거나 오래된 컴포넌트',
  A07: 'A07:2021 식별 및 인증 실패',
  A04: 'A04:2021 안전하지 않은 설계',
  A10: 'A10:2021 서버측 요청 위조(SSRF)',
};

const CLASSES: Klass[] = [
  {
    // 개인정보(PII) 평문 노출
    match: (f) => /개인정보|PII|주민(등록)?번호|신용카드|휴대전화|사업자등록/.test(f.title),
    cwe: 'CWE-359', owasp: T10.A02,
    references: ['https://cwe.mitre.org/data/definitions/359.html', 'https://www.pipc.go.kr'],
    frameworks: [
      { framework: 'ISMS-P', control: '3.2 개인정보 보호조치 / 2.7 암호화' },
      { framework: 'ISO27001', control: 'A.5.34 PII 보호 / A.8.24 암호화' },
      { framework: 'GDPR-PIPA', control: '개인정보보호법 제29조 / GDPR Art.32·34' },
      { framework: 'OWASP-Top10', control: T10.A02 },
      { framework: 'PCI-DSS', control: '3 카드데이터 보호' },
    ],
  },
  {
    // SSRF / 클라우드 메타데이터
    match: (f) => /SSRF|메타데이터|서버측 요청/.test(f.title),
    cwe: 'CWE-918', owasp: T10.A10,
    references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/', 'https://cwe.mitre.org/data/definitions/918.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.11.1 보안 취약점 점검' },
      { framework: 'ISO27001', control: 'A.8.28 보안 코딩' },
      { framework: 'OWASP-ASVS', control: 'V12 파일·리소스 / V5 검증' },
      { framework: 'OWASP-Top10', control: T10.A10 },
    ],
  },
  {
    // 경로 트래버설 / LFI
    match: (f) => /트래버설|traversal|LFI|RFI|경로 우회|passwd/.test(f.title),
    cwe: 'CWE-22', owasp: T10.A01,
    references: ['https://owasp.org/www-community/attacks/Path_Traversal', 'https://cwe.mitre.org/data/definitions/22.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.11.1 보안 취약점 점검' },
      { framework: 'ISO27001', control: 'A.8.28 보안 코딩' },
      { framework: 'OWASP-ASVS', control: 'V12 파일·리소스' },
      { framework: 'OWASP-Top10', control: T10.A01 },
    ],
  },
  {
    // SQL 오류/인젝션 표면
    match: (f) => /SQL|인젝션|injection|스택트레이스|디버그|오류 노출/.test(f.title),
    cwe: 'CWE-89', owasp: T10.A03,
    references: ['https://owasp.org/Top10/A03_2021-Injection/', 'https://cwe.mitre.org/data/definitions/89.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.11.1 보안 취약점 점검' },
      { framework: 'ISO27001', control: 'A.8.28 보안 코딩' },
      { framework: 'OWASP-ASVS', control: 'V5 검증·인젝션' },
      { framework: 'OWASP-Top10', control: T10.A03 },
      { framework: 'PCI-DSS', control: '6.2.4 인젝션 방지' },
    ],
  },
  {
    // IaC/컨테이너/CI 하드닝 (안전하지 않은 설계/설정)
    match: (f) => /Dockerfile|compose|k8s|Terraform|IaC|CI |파이프라인|privileged|런타임/.test(f.title),
    cwe: 'CWE-1357', owasp: T10.A05,
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://cwe.mitre.org/data/definitions/1357.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.10.1 보안시스템 운영 / 2.11.2 취약점 조치' },
      { framework: 'ISO27001', control: 'A.8.9 구성 관리 / A.8.8 기술적 취약성' },
      { framework: 'OWASP-Top10', control: T10.A05 },
      { framework: 'NIST-CSF', control: 'PR.IP-1 보안 기준 구성' },
    ],
  },
  {
    // 인증/세션/토큰 (JWT·OIDC·CSRF·기본자격)
    match: (f) => /JWT|토큰|OIDC|OAuth|CSRF|기본 ?자격|세션 고정|로그인 폼|평문.*전송|Basic/.test(f.title),
    cwe: 'CWE-287', owasp: T10.A07,
    references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/', 'https://cwe.mitre.org/data/definitions/287.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.5 인증 및 권한관리' },
      { framework: 'ISO27001', control: 'A.5.17 인증정보 / A.8.5 보안 인증' },
      { framework: 'OWASP-ASVS', control: 'V2 인증 / V3 세션' },
      { framework: 'OWASP-Top10', control: T10.A07 },
      { framework: 'EFRR', control: '전자금융감독규정 제13조 접근통제' },
    ],
  },
  {
    // 알려진 취약점/구식 컴포넌트 (CVE/SBOM)
    match: (f) => f.module === 'cve' || /구식|버전|컴포넌트|CVE-/.test(f.title),
    cwe: 'CWE-1104', owasp: T10.A06,
    references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/', 'https://cwe.mitre.org/data/definitions/1104.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.11.2 취약점 점검 및 조치' },
      { framework: 'ISO27001', control: 'A.8.8 기술적 취약성 관리' },
      { framework: 'OWASP-ASVS', control: 'V14.2 의존성(구성요소) 보안' },
      { framework: 'OWASP-Top10', control: T10.A06 },
      { framework: 'PCI-DSS', control: '6.3.3 알려진 취약점 패치' },
      { framework: 'NIST-CSF', control: 'ID.RA-1 / PR.IP-12 취약점 식별·관리' },
      { framework: 'EFRR', control: '전자금융감독규정 제17조 해킹 방지 대책' },
    ],
  },
  {
    // 민감 정보/파일 노출 (.env/.git/actuator/백업)
    match: (f) => /\.env|\.git|server-status|actuator|aws|wp-config|백업|민감 경로|정보 노출|\.svn|\.htaccess|swagger|phpinfo/.test(f.title),
    cwe: 'CWE-200', owasp: T10.A05,
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://cwe.mitre.org/data/definitions/200.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.10.1 보안시스템 운영 / 2.9.4 로그·접근통제' },
      { framework: 'ISO27001', control: 'A.8.9 구성 관리 / A.5.10 정보 자산 취급' },
      { framework: 'OWASP-ASVS', control: 'V14.3 정보 노출 / V8 데이터 보호' },
      { framework: 'OWASP-Top10', control: T10.A05 },
      { framework: 'PCI-DSS', control: '6.4 / 2.2 안전한 구성' },
      { framework: 'GDPR-PIPA', control: '개인정보보호법 제29조 안전조치 / GDPR Art.32' },
      { framework: 'NIST-CSF', control: 'PR.DS-5 정보 유출 방지' },
    ],
  },
  {
    // 관리/인증/접근통제 (BAC: 인가 누락·우회·IDOR·권한 파라미터 변조 포함)
    match: (f) => /관리|admin|wp-admin|manager|phpmyadmin|인증|세션|접근통제|인가|객체 참조|idor|권한 파라미터|허가되지 않은/i.test(f.title),
    cwe: 'CWE-284', owasp: T10.A01,
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/', 'https://cwe.mitre.org/data/definitions/284.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.5 인증 및 권한관리 / 2.6.1 네트워크 접근' },
      { framework: 'ISO27001', control: 'A.5.15 접근통제 / A.8.2 권한 접근' },
      { framework: 'OWASP-ASVS', control: 'V1/V4 접근통제 / V3 세션 관리' },
      { framework: 'OWASP-Top10', control: T10.A01 },
      { framework: 'PCI-DSS', control: '7 / 8 접근 제한·인증' },
      { framework: 'NIST-CSF', control: 'PR.AC-1/4 접근통제' },
      { framework: 'EFRR', control: '전자금융감독규정 제13조 접근통제' },
    ],
  },
  {
    // 전송계층/암호화 (TLS/HSTS/인증서/쿠키 Secure/암호스위트/PFS)
    match: (f) => /TLS|HSTS|인증서|HTTPS|암호|프로토콜|secure|쿠키|PFS|키교환|cipher|서명알고리즘|RSA 키|혼합 콘텐츠|평문/i.test(f.title),
    cwe: 'CWE-319', owasp: T10.A02,
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/', 'https://cwe.mitre.org/data/definitions/319.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.7.1 암호정책 / 2.7.2 암호키 관리' },
      { framework: 'ISO27001', control: 'A.8.24 암호화 사용' },
      { framework: 'OWASP-ASVS', control: 'V9 통신 보안 / V6 암호화' },
      { framework: 'OWASP-Top10', control: T10.A02 },
      { framework: 'PCI-DSS', control: '4.2 전송 구간 강한 암호화' },
      { framework: 'GDPR-PIPA', control: '개인정보보호법 제29조 / GDPR Art.32 암호화' },
    ],
  },
  {
    // 인젝션/XSS/CSP
    match: (f) => /csp|xss|인젝션|반사|스크립트|injection/i.test(f.title),
    cwe: 'CWE-79', owasp: T10.A03,
    references: ['https://owasp.org/Top10/A03_2021-Injection/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.11.1 보안 취약점 점검' },
      { framework: 'ISO27001', control: 'A.8.28 보안 코딩' },
      { framework: 'OWASP-ASVS', control: 'V5 검증·인코딩·인젝션' },
      { framework: 'OWASP-Top10', control: T10.A03 },
      { framework: 'PCI-DSS', control: '6.2.4 인젝션 방지 코딩' },
    ],
  },
  {
    // CORS / 메서드 / 클릭재킹 / MIME / Referrer / 헤더 / 인덱싱 / 포트 / 이메일 (설정 오류 전반)
    match: () => true, // 폴백
    cwe: 'CWE-16', owasp: T10.A05,
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
    frameworks: [
      { framework: 'ISMS-P', control: '2.10.1 보안시스템 운영' },
      { framework: 'ISO27001', control: 'A.8.9 구성 관리 / A.8.20 네트워크 보안' },
      { framework: 'OWASP-ASVS', control: 'V14.4 HTTP 보안 헤더 / V14.5 HTTP 요청' },
      { framework: 'OWASP-Top10', control: T10.A05 },
      { framework: 'PCI-DSS', control: '2.2 안전한 시스템 구성' },
      { framework: 'NIST-CSF', control: 'PR.IP-1 보안 기준 구성' },
    ],
  },
];

const CORS_SPECIAL = { match: /CORS/i, cwe: 'CWE-942' };
const CLICKJACK = { match: /클릭재킹|frame/i, cwe: 'CWE-1021' };
const COOKIE = { match: /쿠키/, cwe: 'CWE-614' };
const SPOOF = { match: /SPF|DMARC|스푸핑|CAA|DKIM/i, cwe: 'CWE-290' };

/**
 * OWASP 표기를 정준 라벨형으로 통일한다('A01:2021' → 'A01:2021 취약한 접근통제').
 * 스캐너가 코드형, mapCompliance 폴백이 라벨형을 쓰던 불일치(커버리지 표 중복 집계)를 제거한다.
 */
function canonicalOwasp(owasp: string | undefined): string | undefined {
  if (!owasp) return owasp;
  const code = /^A\d{2}:2021/.exec(owasp)?.[0];
  if (!code) return owasp;
  return Object.values(T10).find((l) => l.startsWith(code)) ?? owasp;
}

/** 발견사항에 CWE·OWASP·참고자료·컴플라이언스 매핑을 부착한다. */
export function mapCompliance(findings: Finding[]): Finding[] {
  for (const f of findings) {
    const k = CLASSES.find((c) => c.match(f)) ?? CLASSES[CLASSES.length - 1]!;
    f.owasp = canonicalOwasp(f.owasp ?? k.owasp);
    // 세부 CWE 보정
    let cwe = k.cwe;
    if (CORS_SPECIAL.match.test(f.title)) cwe = CORS_SPECIAL.cwe;
    else if (CLICKJACK.match.test(f.title)) cwe = CLICKJACK.cwe;
    else if (COOKIE.match.test(f.title)) cwe = COOKIE.cwe;
    else if (SPOOF.match.test(f.title)) cwe = SPOOF.cwe;
    f.cwe = f.cwe ?? cwe;
    f.references = f.references ?? k.references;
    const map = new Map<string, ComplianceMapping>();
    for (const m of k.frameworks) map.set(`${m.framework}:${m.control}`, m);
    // OWASP-Top10 통제를 발견의 실제 owasp 와 일치시킨다.
    // (예: 비인가 API PII 노출은 f.owasp=A01 인데 PII 클래스가 A02 라벨을 부착하던 모순 제거.)
    if (f.owasp) {
      for (const key of [...map.keys()]) if (key.startsWith('OWASP-Top10:')) map.delete(key);
      map.set(`OWASP-Top10:${f.owasp}`, { framework: 'OWASP-Top10', control: f.owasp });
    }
    f.compliance = [...map.values()];
  }
  return findings;
}

/** 작업 전체의 프레임워크별 증빙 커버리지 요약 (리포트용). */
export function complianceSummary(findings: Finding[]): Record<string, { controls: string[]; findings: number }> {
  const out: Record<string, { controls: Set<string>; findings: number }> = {};
  for (const f of findings) {
    for (const m of f.compliance ?? []) {
      out[m.framework] ??= { controls: new Set(), findings: 0 };
      out[m.framework]!.controls.add(m.control);
      out[m.framework]!.findings += 1;
    }
  }
  return Object.fromEntries(
    Object.entries(out).map(([k, v]) => [k, { controls: [...v.controls], findings: v.findings }]),
  );
}

/** OWASP Top 10 / CWE 커버리지 요약 (리포트용). */
export function categorySummary(findings: Finding[]): { owasp: Record<string, number>; cwe: Record<string, number> } {
  const owasp: Record<string, number> = {};
  const cwe: Record<string, number> = {};
  for (const f of findings) {
    if (f.owasp) owasp[f.owasp] = (owasp[f.owasp] ?? 0) + 1;
    if (f.cwe) cwe[f.cwe] = (cwe[f.cwe] ?? 0) + 1;
  }
  return { owasp, cwe };
}
