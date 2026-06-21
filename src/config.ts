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

  /**
   * AI 보안 분석 엔진 (설계 §5.3 — 적응형 점검·분석).
   * LLM 은 "계획·분석"만 하고, 실제 패킷 발신은 기존 비파괴 엔진(EgressGuard, GET/HEAD/OPTIONS)이 수행한다.
   * 키 미설정 시 전체 플랫폼은 그대로 동작하며 AI 기능만 비활성(graceful degradation)된다.
   * 외부 LLM 벤더로 나가는 정보는 fingerprint 단계에서 PII/시크릿을 마스킹·제거한 뒤 전송한다.
   */
  ai: {
    apiKey: process.env.SENTINEL_AI_API_KEY ?? process.env.ANTHROPIC_API_KEY ?? process.env.OPENAI_API_KEY ?? '',
    provider: (process.env.SENTINEL_AI_PROVIDER ?? 'anthropic') as 'anthropic' | 'openai',
    model: process.env.SENTINEL_AI_MODEL ?? 'claude-sonnet-4-6',
    baseUrl: process.env.SENTINEL_AI_BASE_URL ?? '',
    maxProbes: Number(process.env.SENTINEL_AI_MAX_PROBES ?? 18),
    timeoutMs: Number(process.env.SENTINEL_AI_TIMEOUT_MS ?? 30_000),
    maxTokens: Number(process.env.SENTINEL_AI_MAX_TOKENS ?? 2048),
  },
} as const;
