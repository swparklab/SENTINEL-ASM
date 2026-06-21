/**
 * IaC / 클라우드 보안 형상 점검 (CSPM·KSPM) — 설계 §4.4 확장.
 * Terraform · Kubernetes · Dockerfile · docker-compose · CloudFormation 의 잘못된 보안 설정을
 * 정적 규칙으로 탐지한다. 원격 트래픽 없음(파일 분석) → 완전 비파괴, 권한 절차 불필요.
 *
 * 발견은 라인 번호 단위 근거(L<n>: <원문>)를 포함해 "어디가 왜 위험한지" 검증 가능하게 보고한다.
 * 컴플라이언스 매핑은 제목의 'IaC/CSPM' 키워드로 A05(보안 설정 오류, CWE-1357) 클래스에 연결된다.
 */
import { id } from '../../util.js';
import type { Finding } from '../../types.js';

type Sev = Finding['severity'];
type Conf = Finding['confidence'];
type Kind = 'terraform' | 'kubernetes' | 'dockerfile' | 'compose' | 'cloudformation';

const KIND_LABEL: Record<Kind, string> = {
  terraform: 'Terraform', kubernetes: 'k8s', dockerfile: 'Dockerfile', compose: 'compose', cloudformation: 'IaC(CloudFormation)',
};

const REF_CSPM = ['https://owasp.org/www-project-devsecops-guideline/', 'https://cwe.mitre.org/data/definitions/1357.html'];
const REF_K8S = ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'];
const REF_TF = ['https://docs.prowler.com/checks/', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'];
const REF_DOCKER = ['https://docs.docker.com/develop/security-best-practices/'];

interface IacRule {
  id: string;
  kinds: Kind[];
  title: string;
  severity: Sev;
  cwe: string;
  remediation: string;
  references?: string[];
  confidence?: Conf;
  /** 위반 라인 매칭(라인 단위 test, non-global). */
  match?: RegExp;
  /** 이 패턴이 파일 전체에 없으면 위반(부재 점검). */
  absentOf?: RegExp;
  /** absentOf 점검을 이 패턴이 있을 때만 수행(해당 리소스가 있을 때만 '부재'가 의미). */
  onlyIf?: RegExp;
}

const RULES: IacRule[] = [
  // ─────────── 공통: 하드코딩 시크릿 ───────────
  {
    id: 'IAC-SECRET', kinds: ['terraform', 'kubernetes', 'cloudformation', 'compose'],
    title: '하드코딩된 비밀정보(시크릿/비밀번호/키)', severity: 'critical', cwe: 'CWE-798',
    match: /\b(secret|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key|secret[_-]?key|token)\b\s*[:=]\s*["'][^"'$\{][^"']{5,}["']/i,
    remediation: '비밀정보를 코드에 하드코딩하지 말고 Secret Manager/Vault/환경변수·민감 변수(sensitive)로 주입하십시오. 노출된 값은 즉시 폐기·재발급하십시오.',
    references: REF_CSPM,
  },

  // ─────────── Terraform (AWS·Azure·GCP) ───────────
  {
    id: 'TF-S3-PUBLIC-ACL', kinds: ['terraform'], title: 'S3 버킷 퍼블릭 ACL(public-read/-write)', severity: 'high', cwe: 'CWE-732',
    match: /\bacl\s*=\s*"(public-read|public-read-write)"/i,
    remediation: 'S3 ACL 을 private 로 두고 aws_s3_bucket_public_access_block 으로 퍼블릭 접근을 전면 차단하십시오.', references: REF_TF,
  },
  {
    id: 'TF-S3-NO-PAB', kinds: ['terraform'], title: 'S3 퍼블릭 접근 차단(public_access_block) 미설정', severity: 'medium', cwe: 'CWE-732',
    absentOf: /aws_s3_bucket_public_access_block/i, onlyIf: /resource\s+"aws_s3_bucket"/i, confidence: 'tentative',
    remediation: '모든 S3 버킷에 aws_s3_bucket_public_access_block(block_public_acls/ignore_public_acls/block_public_policy/restrict_public_buckets = true)을 적용하십시오.', references: REF_TF,
  },
  {
    id: 'TF-SG-OPEN', kinds: ['terraform', 'cloudformation'], title: '보안그룹/방화벽 전체 개방(0.0.0.0/0)', severity: 'high', cwe: 'CWE-284',
    match: /cidr_blocks?\s*=\s*\[?\s*"0\.0\.0\.0\/0"|"?CidrIp"?\s*[:=]\s*"?0\.0\.0\.0\/0/i,
    remediation: '인바운드 규칙의 소스를 0.0.0.0/0 대신 필요한 CIDR/보안그룹으로 최소화하고, 관리 포트(22/3389)는 절대 전체 개방하지 마십시오.', references: REF_TF,
  },
  {
    id: 'TF-RDS-PUBLIC', kinds: ['terraform'], title: 'DB 인스턴스 퍼블릭 접근 허용(publicly_accessible)', severity: 'high', cwe: 'CWE-284',
    match: /publicly_accessible\s*=\s*true/i,
    remediation: 'DB 는 프라이빗 서브넷에 두고 publicly_accessible = false 로 설정하십시오.', references: REF_TF,
  },
  {
    id: 'TF-UNENCRYPTED', kinds: ['terraform'], title: '저장 데이터 암호화 비활성(encrypted/storage_encrypted = false)', severity: 'high', cwe: 'CWE-311',
    match: /\b(storage_encrypted|encrypted|encryption_enabled|enable_encryption)\s*=\s*false/i,
    remediation: '저장 데이터 암호화(at-rest)를 활성화하고 고객관리키(CMK/KMS)를 사용하십시오.', references: REF_TF,
  },
  {
    id: 'TF-IAM-WILDCARD', kinds: ['terraform', 'cloudformation'], title: 'IAM 정책 와일드카드 권한(Action/Resource = "*")', severity: 'high', cwe: 'CWE-284',
    match: /"(Action|Resource)"\s*[:=]\s*"\*"|\b(actions|resources)\s*=\s*\[?\s*"\*"/i,
    remediation: '최소권한 원칙으로 Action/Resource 를 구체적으로 한정하십시오. 와일드카드(*)는 관리자급 권한 부여와 같습니다.', references: REF_TF,
  },
  {
    id: 'TF-AZURE-BLOB-PUBLIC', kinds: ['terraform'], title: 'Azure 스토리지 퍼블릭 Blob 접근 허용', severity: 'high', cwe: 'CWE-732',
    match: /allow_blob_public_access\s*=\s*true/i,
    remediation: 'allow_blob_public_access = false 로 설정하고 SAS/RBAC 로 접근을 통제하십시오.', references: REF_TF,
  },
  {
    id: 'TF-AZURE-NSG-OPEN', kinds: ['terraform'], title: 'Azure NSG 소스 전체 개방(source_address_prefix = "*")', severity: 'high', cwe: 'CWE-284',
    match: /source_address_prefix\s*=\s*"\*"/i,
    remediation: 'NSG 인바운드 소스를 특정 IP/서브넷으로 제한하십시오.', references: REF_TF,
  },
  {
    id: 'TF-GCP-PUBLIC-IAM', kinds: ['terraform'], title: 'GCP 리소스 전체 공개(allUsers/allAuthenticatedUsers)', severity: 'high', cwe: 'CWE-732',
    match: /"(allUsers|allAuthenticatedUsers)"|\ballUsers\b|\ballAuthenticatedUsers\b/,
    remediation: 'IAM 멤버에 allUsers/allAuthenticatedUsers 부여를 제거하고 특정 주체로 한정하십시오.', references: REF_TF,
  },
  {
    id: 'TF-WEAK-TLS', kinds: ['terraform'], title: '약한 TLS 최소버전(TLS 1.0/1.1)', severity: 'medium', cwe: 'CWE-327',
    match: /(min(imum)?_tls_version)\s*=\s*"?(1\.0|1\.1|1_0|1_1|TLS1_0|TLS1_1|TLSv1|TLSv1\.1)"?/i,
    remediation: '최소 TLS 버전을 1.2 이상(가능하면 1.3)으로 설정하십시오.', references: REF_TF,
  },
  {
    id: 'TF-PUBLIC-IP', kinds: ['terraform'], title: '인스턴스 퍼블릭 IP 자동 할당', severity: 'low', cwe: 'CWE-16',
    match: /associate_public_ip_address\s*=\s*true/i,
    remediation: '불필요한 퍼블릭 IP 노출을 피하고 NAT/배스천 경유로 전환하십시오.', references: REF_TF,
  },
  {
    id: 'TF-LOG-DISABLED', kinds: ['terraform'], title: '감사/접근 로깅 비활성', severity: 'medium', cwe: 'CWE-778',
    match: /\b(enable_logging|logging_enabled|access_logs?[\s\S]{0,40}?enabled)\s*=\s*false/i,
    remediation: 'CloudTrail/Flow Logs/액세스 로그를 활성화해 감사 추적을 확보하십시오.', references: REF_TF,
  },

  // ─────────── Kubernetes (KSPM) ───────────
  {
    id: 'K8S-PRIVILEGED', kinds: ['kubernetes'], title: 'k8s 컨테이너 privileged 권한', severity: 'critical', cwe: 'CWE-250',
    match: /privileged:\s*true/i,
    remediation: 'privileged: true 를 제거하십시오(호스트 전권 획득과 동급). 필요한 능력만 capabilities 로 추가하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-HOST-NS', kinds: ['kubernetes'], title: 'k8s 호스트 네임스페이스 공유(hostNetwork/PID/IPC)', severity: 'high', cwe: 'CWE-250',
    match: /host(Network|PID|IPC):\s*true/i,
    remediation: 'hostNetwork/hostPID/hostIPC 사용을 제거해 컨테이너-호스트 격리를 유지하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-PRIVESC', kinds: ['kubernetes'], title: 'k8s 권한 상승 허용(allowPrivilegeEscalation)', severity: 'high', cwe: 'CWE-250',
    match: /allowPrivilegeEscalation:\s*true/i,
    remediation: 'securityContext.allowPrivilegeEscalation: false 로 설정하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-ROOT', kinds: ['kubernetes'], title: 'k8s 루트(runAsUser: 0) 실행', severity: 'high', cwe: 'CWE-250',
    match: /runAsUser:\s*0\b/,
    remediation: '비루트 UID 로 실행하고 runAsNonRoot: true 를 설정하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-NO-NONROOT', kinds: ['kubernetes'], title: 'k8s runAsNonRoot 미설정(루트 실행 가능)', severity: 'medium', cwe: 'CWE-250',
    absentOf: /runAsNonRoot:\s*true/i, onlyIf: /kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)/i, confidence: 'tentative',
    remediation: 'securityContext.runAsNonRoot: true 를 명시해 루트 실행을 차단하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-CAP', kinds: ['kubernetes'], title: 'k8s 위험 Capability 추가(SYS_ADMIN/NET_ADMIN/ALL)', severity: 'high', cwe: 'CWE-250',
    match: /-\s*["']?(SYS_ADMIN|NET_ADMIN|NET_RAW|ALL)["']?\s*$/i,
    remediation: '위험 capability 추가를 제거하고, capabilities.drop: ["ALL"] 후 필요한 최소 능력만 add 하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-DOCKERSOCK', kinds: ['kubernetes', 'compose'], title: '컨테이너에 Docker 소켓 마운트(/var/run/docker.sock)', severity: 'critical', cwe: 'CWE-250',
    match: /\/var\/run\/docker\.sock/,
    remediation: 'docker.sock 마운트는 호스트 루트 장악과 같습니다. 제거하고 필요한 경우 권한 분리된 빌더(예: kaniko/buildkit)를 사용하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-HOSTPATH', kinds: ['kubernetes'], title: 'k8s hostPath 볼륨 마운트(호스트 파일시스템 노출)', severity: 'medium', cwe: 'CWE-22',
    match: /hostPath:/i,
    remediation: 'hostPath 대신 PVC/emptyDir 등 격리된 볼륨을 사용하십시오. 불가피하면 readOnly 와 경로를 엄격히 제한하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-NO-LIMITS', kinds: ['kubernetes'], title: 'k8s 리소스 제한(limits) 미설정(자원 고갈 위험)', severity: 'low', cwe: 'CWE-400',
    absentOf: /limits:/i, onlyIf: /containers:/i, confidence: 'tentative',
    remediation: 'resources.limits(cpu/memory)를 설정해 노이지 네이버/DoS 를 방지하십시오.', references: REF_K8S,
  },
  {
    id: 'K8S-LATEST', kinds: ['kubernetes', 'compose'], title: '컨테이너 이미지 :latest 태그(재현성·롤백 불가)', severity: 'low', cwe: 'CWE-1104',
    match: /image:\s*["']?\S+:latest\b/i,
    remediation: '이미지를 고정 버전 태그 또는 다이제스트(@sha256:)로 핀하십시오.', references: REF_DOCKER,
  },
  {
    id: 'K8S-RORFS', kinds: ['kubernetes'], title: 'k8s readOnlyRootFilesystem 미설정', severity: 'low', cwe: 'CWE-16',
    absentOf: /readOnlyRootFilesystem:\s*true/i, onlyIf: /securityContext:/i, confidence: 'tentative',
    remediation: 'securityContext.readOnlyRootFilesystem: true 로 루트 파일시스템 쓰기를 차단하십시오.', references: REF_K8S,
  },

  // ─────────── Dockerfile ───────────
  {
    id: 'DOCKER-NO-USER', kinds: ['dockerfile'], title: 'Dockerfile USER 미지정(root 로 실행)', severity: 'medium', cwe: 'CWE-250',
    absentOf: /^\s*USER\s+(?!root\b|0\b)\S+/im, onlyIf: /^\s*FROM\s+\S/im, confidence: 'firm',
    remediation: '비루트 사용자 생성 후 USER 지시어로 전환해 컨테이너를 비루트로 실행하십시오.', references: REF_DOCKER,
  },
  {
    id: 'DOCKER-LATEST', kinds: ['dockerfile'], title: 'Dockerfile FROM :latest 태그(재현성 불가)', severity: 'low', cwe: 'CWE-1104',
    match: /^\s*FROM\s+\S+:latest\b/im,
    remediation: '베이스 이미지를 고정 버전 또는 다이제스트(@sha256:)로 핀하십시오.', references: REF_DOCKER,
  },
  {
    id: 'DOCKER-CURL-PIPE', kinds: ['dockerfile'], title: 'Dockerfile 원격 스크립트 파이프 실행(curl|sh)', severity: 'high', cwe: 'CWE-494',
    match: /(curl|wget)\s+[^\n|]*\|\s*(sh|bash)/i,
    remediation: '원격 스크립트를 파이프로 실행하지 말고, 무결성 검증(체크섬/서명)된 아티팩트를 다운로드 후 실행하십시오.', references: REF_DOCKER,
  },
  {
    id: 'DOCKER-ADD-URL', kinds: ['dockerfile'], title: 'Dockerfile ADD 로 원격 URL 다운로드', severity: 'medium', cwe: 'CWE-494',
    match: /^\s*ADD\s+https?:\/\//im,
    remediation: 'ADD 대신 COPY 를 쓰고, 원격 다운로드는 검증된 절차로 분리하십시오.', references: REF_DOCKER,
  },
  {
    id: 'DOCKER-ENV-SECRET', kinds: ['dockerfile'], title: 'Dockerfile ENV/ARG 에 비밀정보 노출', severity: 'high', cwe: 'CWE-798',
    match: /^\s*(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)\S*\s*[= ]\s*\S/im,
    remediation: '빌드 인자/환경변수로 비밀을 전달하지 말고 BuildKit secret 마운트/런타임 시크릿을 사용하십시오. ENV 는 이미지 레이어에 영구 기록됩니다.', references: REF_DOCKER,
  },
  {
    id: 'DOCKER-CHMOD-777', kinds: ['dockerfile'], title: 'Dockerfile 과도한 권한(chmod 777)', severity: 'low', cwe: 'CWE-732',
    match: /chmod\s+-?R?\s*0?777\b/,
    remediation: '필요한 최소 권한만 부여하십시오(777 금지).', references: REF_DOCKER,
  },

  // ─────────── docker-compose ───────────
  {
    id: 'COMPOSE-PRIVILEGED', kinds: ['compose'], title: 'compose privileged 컨테이너', severity: 'high', cwe: 'CWE-250',
    match: /privileged:\s*true/i,
    remediation: 'privileged: true 를 제거하고 필요한 cap_add 만 사용하십시오.', references: REF_DOCKER,
  },
  {
    id: 'COMPOSE-HOST-NET', kinds: ['compose'], title: 'compose 호스트 네트워크 모드(network_mode: host)', severity: 'medium', cwe: 'CWE-250',
    match: /network_mode:\s*["']?host/i,
    remediation: '호스트 네트워크 대신 격리된 사용자 정의 네트워크를 사용하십시오.', references: REF_DOCKER,
  },
  {
    id: 'COMPOSE-BIND-ALL', kinds: ['compose'], title: 'compose 포트 전체 인터페이스 바인딩(0.0.0.0)', severity: 'low', cwe: 'CWE-16',
    match: /["']?0\.0\.0\.0:\d+/,
    remediation: '필요한 인터페이스(예: 127.0.0.1)로만 바인딩하고 불필요한 외부 노출을 피하십시오.', references: REF_DOCKER,
  },
  {
    id: 'COMPOSE-ENV-SECRET', kinds: ['compose'], title: 'compose 환경변수 평문 비밀정보', severity: 'medium', cwe: 'CWE-798',
    match: /\b(PASSWORD|SECRET|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|API_?KEY|TOKEN)\b\s*[:=]\s*(?!\$\{|\$\()["']?[A-Za-z0-9./+_-]{4,}/i,
    remediation: '평문 비밀 대신 compose secrets 또는 외부 시크릿 주입을 사용하십시오.', references: REF_DOCKER,
  },

  // ─────────── CloudFormation ───────────
  {
    id: 'CFN-S3-PUBLIC', kinds: ['cloudformation'], title: 'IaC(CloudFormation) S3 퍼블릭 접근(AccessControl: PublicRead)', severity: 'high', cwe: 'CWE-732',
    match: /"?AccessControl"?\s*:\s*"?Public(Read|ReadWrite)/i,
    remediation: 'AccessControl 을 Private 로 두고 PublicAccessBlockConfiguration 으로 퍼블릭 접근을 차단하십시오.', references: REF_TF,
  },
];

/** 파일명/내용으로 IaC 종류를 식별. compose→cloudformation→kubernetes 순으로 더 구체적인 것을 먼저 본다. */
function detectKind(filename: string, content: string): Kind | null {
  const fn = (filename || '').toLowerCase();
  if (/(^|\/)dockerfile(\.|$)|\.dockerfile$/.test(fn) || /^\s*FROM\s+\S+/im.test(content.slice(0, 400))) return 'dockerfile';
  if (/docker-compose\.ya?ml$|(^|\/)compose\.ya?ml$/.test(fn) || (/^services:/im.test(content) && /\n\s+(image|build):/i.test(content))) return 'compose';
  if (/\.tf$|\.tfvars$/.test(fn) || /^\s*resource\s+"|^\s*provider\s+"/im.test(content)) return 'terraform';
  if (/AWSTemplateFormatVersion|"?Resources"?\s*:[\s\S]{0,200}?(Type"?\s*:\s*"?AWS::)/i.test(content)) return 'cloudformation';
  if (/\.ya?ml$|\.json$/.test(fn) && /^\s*apiVersion:/im.test(content) && /^\s*kind:\s*\w/im.test(content)) return 'kubernetes';
  return null;
}

/** IaC/CSPM 정적 점검 진입점 — 단일 파일을 받아 Finding[] 반환(module='cve', 비파괴). */
export function runIacScan(filename: string, content: string): Finding[] {
  const kind = detectKind(filename, content);
  if (!kind || !content) return [];
  const lines = content.split(/\r?\n/);
  const out: Finding[] = [];
  for (const rule of RULES) {
    if (!rule.kinds.includes(kind)) continue;
    if (rule.match) {
      const hits: { line: number; text: string }[] = [];
      for (let i = 0; i < lines.length; i++) {
        if (hits.length >= 6) break;
        if (rule.match.test(lines[i]!)) hits.push({ line: i + 1, text: lines[i]!.trim().slice(0, 140) });
      }
      if (hits.length) out.push(mkIac(rule, kind, filename, hits));
    } else if (rule.absentOf) {
      if (rule.onlyIf && !rule.onlyIf.test(content)) continue;
      if (!rule.absentOf.test(content)) out.push(mkIac(rule, kind, filename, [{ line: 1, text: '(파일 전체: 해당 보안 설정 부재)' }]));
    }
  }
  return out;
}

function mkIac(rule: IacRule, kind: Kind, filename: string, hits: { line: number; text: string }[]): Finding {
  const label = KIND_LABEL[kind];
  const where = hits.map((h) => h.line).join(',');
  return {
    id: id('fnd'), module: 'cve', severity: rule.severity,
    title: `[IaC/CSPM·${label}] ${rule.title}`,
    target: `${filename || kind}:${where}`,
    description: `${label} 형상에서 보안 설정 오류가 탐지되었습니다(규칙 ${rule.id}). 클라우드 보안 형상관리(CSPM/KSPM) 기준 위반입니다.`,
    evidence: `파일: ${filename || '(이름없음)'} · 종류: ${label}\n` + hits.map((h) => `L${h.line}: ${h.text}`).join('\n'),
    remediation: rule.remediation,
    cwe: rule.cwe, owasp: 'A05:2021', confidence: rule.confidence ?? 'firm',
    references: rule.references ?? REF_CSPM,
  };
}
