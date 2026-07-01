/**
 * LLM 제공자 추상화 (설계 §5.3).
 * Anthropic Messages API / OpenAI 호환 Chat Completions 를 단일 인터페이스로 감싼다.
 * provider='local' 은 사내/로컬 GPU 의 OpenAI 호환 엔드포인트(Ollama·vLLM·LM Studio 등)를 가리키며,
 * 벤더 키 없이 동일 인터페이스로 붙는다(탈옥 불필요 — 오케스트레이터는 계획·분석만 하므로 검열해제 모델이 필요 없다).
 *
 * 안전 원칙:
 *  - 이 호출은 점검 대상이 아니라 LLM 엔드포인트(벤더 또는 로컬)로 나가므로 EgressGuard(대상 allowlist)를 거치지 않는다.
 *    대신 호출자(fingerprint/planner)가 PII·시크릿을 마스킹·제거한 데이터만 전달해야 한다.
 *  - 키 미설정·네트워크 오류·파싱 실패는 절대 throw 하지 않고 null 을 돌려준다(점검 무중단, graceful degradation).
 *  - 모델은 "계획·분석"만 생성한다(로컬이든 벤더든 동일). 실제 HTTP 발신은 기존 엔진이 게이트·EgressGuard 를 통해서만 수행한다.
 */
import { config } from '../../config.js';

export interface AiCallOpts { system: string; user: string; maxTokens?: number; temperature?: number }

export function isAiConfigured(): boolean {
  // 로컬 provider 는 로컬 엔드포인트라 벤더 키 없이도 활성(엔드포인트 부재 시 호출이 null 을 반환해 무중단).
  return config.ai.local || !!config.ai.apiKey;
}

export function aiStatus(): { configured: boolean; provider: string; model: string; baseUrl: string; local: boolean } {
  return { configured: isAiConfigured(), provider: config.ai.provider, model: config.ai.model, baseUrl: config.ai.baseUrl, local: config.ai.local };
}

/** 모델 호출 → 텍스트. 미구성/오류 시 null. */
export async function aiComplete(opts: AiCallOpts): Promise<string | null> {
  if (!isAiConfigured()) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), config.ai.timeoutMs);
  try {
    // anthropic 만 Messages API. openai·local 은 OpenAI 호환 Chat Completions 를 공유한다.
    return config.ai.provider === 'anthropic'
      ? await callAnthropic(opts, ctrl.signal)
      : await callOpenAi(opts, ctrl.signal);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** 모델에 JSON 응답을 요청하고 파싱. 코드펜스/잡텍스트를 견고하게 벗겨낸다. 실패 시 null. */
export async function aiJson<T = unknown>(opts: AiCallOpts): Promise<T | null> {
  const raw = await aiComplete({ ...opts, system: opts.system + '\n\n반드시 유효한 JSON 만 출력하라. 설명·마크다운·코드펜스 금지.' });
  if (!raw) return null;
  return extractJson<T>(raw);
}

export function extractJson<T>(raw: string): T | null {
  const s = raw.trim();
  // 1) 그대로 파싱 시도(가장 흔한 정상 케이스)
  try { return JSON.parse(s) as T; } catch { /* fall through */ }
  // 2) ```json ... ``` 펜스 안쪽 시도
  const fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(s);
  if (fence && fence[1]) { try { return JSON.parse(fence[1].trim()) as T; } catch { /* fall through */ } }
  // 3) 첫 여는 괄호부터 깊이 추적으로 "첫 완전한 JSON 값"만 분리(뒤따르는 산문의 stray 괄호에 영향받지 않음).
  const candidate = sliceFirstJson(fence && fence[1] ? fence[1] : s);
  if (candidate) { try { return JSON.parse(candidate) as T; } catch { /* */ } }
  return null;
}

/** 문자열·이스케이프를 인지한 균형 괄호 스캔으로 첫 완전한 JSON 객체/배열을 잘라낸다. */
function sliceFirstJson(s: string): string | null {
  let start = -1; let open = '';
  for (let i = 0; i < s.length; i++) { const c = s[i]!; if (c === '{' || c === '[') { start = i; open = c; break; } }
  if (start === -1) return null;
  const close = open === '{' ? '}' : ']';
  let depth = 0; let inStr = false; let esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; continue; }
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return s.slice(start, i + 1); }
  }
  return null;
}

async function callAnthropic(opts: AiCallOpts, signal: AbortSignal): Promise<string | null> {
  const url = (config.ai.baseUrl || 'https://api.anthropic.com') + '/v1/messages';
  const res = await fetch(url, {
    method: 'POST', signal,
    headers: {
      'content-type': 'application/json',
      'x-api-key': config.ai.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.ai.model,
      max_tokens: opts.maxTokens ?? config.ai.maxTokens,
      temperature: opts.temperature ?? 0.2,
      system: opts.system,
      messages: [{ role: 'user', content: opts.user }],
    }),
  });
  if (!res.ok) return null;
  const data = await res.json() as { content?: { type: string; text?: string }[] };
  return (data.content ?? []).filter((c) => c.type === 'text').map((c) => c.text ?? '').join('').trim() || null;
}

async function callOpenAi(opts: AiCallOpts, signal: AbortSignal): Promise<string | null> {
  const url = (config.ai.baseUrl || 'https://api.openai.com') + '/v1/chat/completions';
  // 로컬 엔드포인트(Ollama 등)는 인증이 없다 — 키가 있을 때만 Authorization 헤더를 붙인다.
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (config.ai.apiKey) headers.authorization = `Bearer ${config.ai.apiKey}`;
  const res = await fetch(url, {
    method: 'POST', signal,
    headers,
    body: JSON.stringify({
      model: config.ai.model,
      max_tokens: opts.maxTokens ?? config.ai.maxTokens,
      temperature: opts.temperature ?? 0.2,
      messages: [{ role: 'system', content: opts.system }, { role: 'user', content: opts.user }],
    }),
  });
  if (!res.ok) return null;
  const data = await res.json() as { choices?: { message?: { content?: string } }[] };
  return (data.choices?.[0]?.message?.content ?? '').trim() || null;
}
