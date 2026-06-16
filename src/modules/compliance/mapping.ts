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
};

const CLASSES: Klass[] = [
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
    // 관리/인증/접근통제
    match: (f) => /관리|admin|wp-admin|manager|phpmyadmin|인증|세션|접근통제|인가/.test(f.title),
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
    // 전송계층/암호화 (TLS/HSTS/인증서/쿠키 Secure)
    match: (f) => /TLS|HSTS|인증서|HTTPS|암호|프로토콜|secure|쿠키/i.test(f.title),
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

/** 발견사항에 CWE·OWASP·참고자료·컴플라이언스 매핑을 부착한다. */
export function mapCompliance(findings: Finding[]): Finding[] {
  for (const f of findings) {
    const k = CLASSES.find((c) => c.match(f)) ?? CLASSES[CLASSES.length - 1]!;
    f.owasp = f.owasp ?? k.owasp;
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
