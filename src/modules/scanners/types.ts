/** 점검 모듈 공통 컨텍스트 (설계 §4). */
import type { Asset, Finding, ScanIntensity } from '../../types.js';
import type { EgressGuard } from './egress.js';

export interface ScanContext {
  asset: Asset;
  guard: EgressGuard;
  intensity: ScanIntensity;
  /** 동의 범위에서 허용된 포트 (없으면 표준 세트) */
  allowedPorts: number[];
  tenantId: string;
  jobId: string;
  /** 심층 점검 여부 — true 면 정밀·전수 점검(시간 소요) */
  deep: boolean;
  /** 게이트가 통과시킨 점검 대상 (자산 + 발견 서브도메인) */
  targets: string[];
  log: (msg: string) => void;
}

/** 심층 점검용 확장 포트 세트 (간단 점검보다 광범위). */
export const DEEP_PORTS = [
  20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
  587, 636, 993, 995, 1433, 1521, 2049, 2375, 2379, 3000, 3306, 3389, 5000, 5432,
  5601, 5672, 5900, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9092, 9200, 11211, 27017,
];

export interface Scanner {
  module: 'asm' | 'config' | 'cve' | 'dast';
  /** 이 모듈이 요구하는 최소 강도 */
  minIntensity: ScanIntensity;
  run(ctx: ScanContext): Promise<Finding[]>;
}

/** 표준 점검 포트 세트 (설계 §4.1 오픈 포트 핑거프린팅). */
export const STANDARD_PORTS = [21, 22, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443];

export const PORT_SERVICE: Record<number, string> = {
  20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP-sub',
  636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS',
  2375: 'Docker', 2379: 'etcd', 3000: 'Dev/Grafana', 3306: 'MySQL', 3389: 'RDP',
  5000: 'Flask/UPnP', 5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'AMQP', 5900: 'VNC',
  6379: 'Redis', 7001: 'WebLogic', 8000: 'HTTP-alt', 8008: 'HTTP-alt', 8080: 'HTTP-alt',
  8081: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-alt', 9000: 'SonarQube/PHP-FPM',
  9092: 'Kafka', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
};
