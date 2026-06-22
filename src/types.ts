/**
 * SENTINEL-ASM 도메인 타입.
 * 설계문서의 엔티티(테넌트·사용자·자산·동의·점검작업·발견사항·감사로그)를 1:1로 모델링한다.
 */

// ───────────────────────── RBAC / 멀티테넌시 (설계 §6.1) ─────────────────────────
export type Role = 'admin' | 'scanner' | 'auditor' | 'viewer';

export interface Tenant {
  id: string;
  name: string;
  createdAt: string;
}

export interface User {
  id: string;
  tenantId: string;
  email: string;
  /** sha256(salt + password) — 데모용 해시 (운영은 Argon2/bcrypt + Vault) */
  passwordHash: string;
  passwordSalt: string;
  role: Role;
  displayName: string;
  createdAt: string;
}

// ───────────────────────── 자산 (설계 §3, §4.1) ─────────────────────────
export type AssetType = 'domain' | 'host' | 'web' | 'software';

/** 소유권 증명 방식 (설계 §3.1). self-attested: 권한 보유 전자 확인(빠른 점검). */
export type OwnershipMethod = 'dns-txt' | 'file-upload' | 'meta-tag' | 'contract-esign' | 'self-attested';

export type OwnershipStatus = 'unverified' | 'pending' | 'verified' | 'failed';

export interface OwnershipProof {
  method: OwnershipMethod;
  /** 검증 토큰 (DNS TXT 값 / 파일명 / 메타태그 content / 계약 서명 해시) */
  token: string;
  status: OwnershipStatus;
  issuedAt: string;
  verifiedAt?: string;
  lastCheckedAt?: string;
  detail?: string;
}

export interface Asset {
  id: string;
  tenantId: string;
  type: AssetType;
  /** 도메인명 또는 호스트(IP/FQDN) */
  value: string;
  label?: string;
  /** 자산 중요도 — 위험 산정 가중 (설계 §5.1) */
  businessCriticality: 'low' | 'medium' | 'high' | 'critical';
  ownership: OwnershipProof | null;
  createdAt: string;
  createdBy: string;
}

// ───────────────────────── 동의·범위 (설계 §3.2) ─────────────────────────
export type ScanIntensity = 'passive' | 'standard' | 'aggressive';

export interface ConsentScope {
  /** egress allowlist 의 근거 — 허용 호스트/도메인 */
  allowedTargets: string[];
  /** 허용 포트 (비어있으면 표준 점검 포트 세트 사용) */
  allowedPorts: number[];
  maxIntensity: ScanIntensity;
}

export type ConsentStatus = 'active' | 'expired' | 'revoked';

export interface Consent {
  id: string;
  tenantId: string;
  assetId: string;
  scope: ConsentScope;
  /** 점검 기간 (설계 §3.2 start–end) */
  windowStart: string;
  windowEnd: string;
  /** Aggressive 추가 서면 승인 (설계 §4.5 / §9 4-eyes) */
  aggressiveApprovedBy?: string;
  status: ConsentStatus;
  signedBy: string;
  signedAt: string;
  revokedAt?: string;
}

// ───────────────────────── 점검 작업 / 발견사항 (설계 §2.2, §4) ─────────────────────────
export type ScanModule = 'asm' | 'config' | 'cve' | 'dast' | 'access' | 'ai';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'rejected' | 'aborted';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  id: string;
  module: ScanModule;
  title: string;
  description: string;
  target: string;
  severity: Severity;
  /** CVSS 기본점수 0–10 (설계 §5.1) */
  cvss?: number;
  /** CVSS 3.1 벡터 문자열 (산정 근거 추적용, 예: CVSS:3.1/AV:N/AC:L/...) */
  cvssVector?: string;
  /** EPSS 익스플로잇 확률 0–1 (설계 §5.1) */
  epss?: number;
  /** CISA KEV 등재 여부 (설계 §4.3) */
  kev?: boolean;
  cve?: string;
  /** 산정된 우선순위 점수 0–100 (설계 §5.1) */
  riskScore?: number;
  /** 컴플라이언스 매핑 (설계 §5.2) */
  compliance?: ComplianceMapping[];
  /** CWE 분류 (예: CWE-200) */
  cwe?: string;
  /** OWASP Top 10 2021 카테고리 (예: A05:2021 보안 설정 오류) */
  owasp?: string;
  /** 표준·치트시트 참고 링크 */
  references?: string[];
  /** 점검 신뢰도 — 오탐 가능성 보정 (설계 품질) */
  confidence?: 'confirmed' | 'firm' | 'tentative';
  evidence?: string;
  remediation?: string;
  /** 노출 데이터 영향 정량화 (설계 §5.3): 이 발견으로 접근 가능한 레코드 수 + PII 유형 (피해 규모·FAIR 산정 근거).
   *  enumerable: 순차 식별자/열거로 전체 사용자까지 확장 가능. surfaceOnly: 스키마/표면만 확인(실제 PII 레코드 미수집). */
  dataImpact?: { records: number; categories: string[]; enumerable?: boolean; surfaceOnly?: boolean };
}

export interface ComplianceMapping {
  framework: 'ISMS-P' | 'ISO27001' | 'OWASP-ASVS' | 'OWASP-Top10' | 'PCI-DSS' | 'NIST-CSF' | 'GDPR-PIPA' | 'EFRR';
  control: string;
  note?: string;
}

export interface ScanJob {
  id: string;
  tenantId: string;
  assetId: string;
  consentId: string;
  modules: ScanModule[];
  intensity: ScanIntensity;
  /** 점검 깊이 — simple(간단·고신호) / deep(심층·정밀, 시간 소요) */
  depth?: 'simple' | 'deep';
  /** 활성(침투) 검증 모드 — 취약점을 실제 트리거해 확정(비파괴 한정, aggressive+4-eyes 필수) */
  active?: boolean;
  status: ScanStatus;
  /** 실시간 진행률 0–100 (오케스트레이터가 모듈 진행에 따라 갱신) */
  progress?: number;
  /** 현재 단계 라벨 (예: "ASM 점검 중") */
  stage?: string;
  /** 모듈별 상태 추적 */
  moduleStatus?: { module: ScanModule; status: 'pending' | 'running' | 'done' | 'skipped' | 'error'; findings?: number }[];
  /** 게이트 판정 사유 (설계 §3.3) */
  gateDecision?: { allowed: boolean; reason: string; checkedAt: string };
  requestedBy: string;
  queuedAt: string;
  startedAt?: string;
  finishedAt?: string;
  findings: Finding[];
  /** 점검 중 발신이 허용된 대상 (egress allowlist 스냅샷) */
  egressAllowlist: string[];
  error?: string;
}

// ───────────────────────── 감사로그 (설계 §6.2 append-only) ─────────────────────────
export interface AuditEvent {
  id: string;
  ts: string;
  tenantId: string | null;
  actor: string | null;
  action: string;
  target?: string;
  outcome: 'allow' | 'deny' | 'info' | 'error';
  reason?: string;
  meta?: Record<string, unknown>;
  /** 해시 체인 — 변조 탐지 (설계 §6.2 변조 불가) */
  prevHash: string;
  hash: string;
}
