/**
 * 시스템 전역 설정.
 * 설계문서 §7 기술스택 / §8.1 NFR 의 운영 파라미터를 환경변수로 외부화한다.
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

export const config = {
  port: Number(process.env.PORT ?? 8787),
  host: process.env.HOST ?? '0.0.0.0',

  /** 데이터 계층 (설계 §2.1 데이터: PostgreSQL 대체 — 단일 노드 JSON 스토어) */
  dataDir: process.env.DATA_DIR ?? path.join(root, 'data'),
  publicDir: path.join(root, 'public'),

  /** AuthN/AuthZ (설계 §2.1 API 게이트웨이) */
  jwtSecret: process.env.JWT_SECRET ?? 'dev-only-sentinel-secret-change-in-prod',
  jwtExpiresIn: process.env.JWT_TTL ?? '8h',

  /** 점검 윈도우·강도 관련 기본값 (설계 §4.5) */
  scan: {
    /** 워커 동시 실행 수 — 설계 §8.1 수평확장 대체(단일 노드 동시성) */
    concurrency: Number(process.env.SCAN_CONCURRENCY ?? 4),
    /** egress allowlist 강제 여부 (설계 §3.2 / §8.1) — 항상 켜진 상태가 정책 */
    enforceEgressAllowlist: true,
  },

  /** 감사 로그 보존 (설계 §6.2) */
  audit: {
    file: process.env.AUDIT_FILE ?? path.join(root, 'data', 'audit.log.jsonl'),
  },
} as const;
