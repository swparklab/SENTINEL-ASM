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

  /**
   * 위협 인텔(CTI/IoC) 연동 (설계 §4.3) — STIX2.1/TAXII2.1 또는 단순 IoC 피드를 "소비(consume)"만 한다.
   * 발견된 지표(IP/도메인/CNAME)를 known-bad 와 대조해 enrich 한다. 외부 CTI 인프라 호출(대상 미발신).
   * 미설정 시에도 데모 지표 세트(RFC5737/RFC2606 예약대역)로 파이프라인이 동작하며 매칭은 'tentative·데모'로 표기.
   */
  cti: {
    taxiiUrl: process.env.SENTINEL_CTI_TAXII_URL ?? '',
    apiRoot: process.env.SENTINEL_CTI_TAXII_API_ROOT ?? '',
    collection: process.env.SENTINEL_CTI_TAXII_COLLECTION ?? '',
    token: process.env.SENTINEL_CTI_TAXII_TOKEN ?? '',
    feedUrls: (process.env.SENTINEL_CTI_FEED_URLS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    enableDemoIndicators: (process.env.SENTINEL_CTI_DEMO ?? 'true') !== 'false',
    timeoutMs: Number(process.env.SENTINEL_CTI_TIMEOUT_MS ?? 8000),
  },

  /**
   * 대역외(OOB) 능동 확정 (설계 §4.5 active) — Burp Collaborator 방식의 콜백 기반 blind 취약점 확정.
   * 페이로드에 콜라보레이터 URL 을 심어, 대상이 대역외로 콜백하면 blind SSRF 등을 확정한다(비파괴 — 콜백 신호만).
   * collaboratorBase 가 비어 있으면 OOB 확정은 비활성(콜백 수신 불가). 운영에서는 대상이 도달 가능한 공개 도메인/IP 로 설정.
   * waitMs: 페이로드 발신 후 콜백 수신을 기다리는 시간. aggressive+active(4-eyes) 게이트에서만 동작.
   */
  oob: {
    collaboratorBase: (process.env.SENTINEL_OOB_BASE ?? '').replace(/\/$/, ''),
    waitMs: Number(process.env.SENTINEL_OOB_WAIT_MS ?? 3500),
  },
} as const;
