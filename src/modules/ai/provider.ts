/**
 * LLM 제공자 추상화 (설계 §5.3).
 * Anthropic Messages API / OpenAI 호환 Chat Completions 를 단일 인터페이스로 감싼다.
 *
 * 안전 원칙:
 *  - 이 호출은 점검 대상이 아니라 LLM 벤더로 나가므로 EgressGuard(대상 allowlist)를 거치지 않는다(인프라 호출).
 *    대신 호출자(fingerprint/planner)가 PII·시크릿을 마스킹·제거한 데이터만 전달해야 한다.
 *  - 키 미설정·네트워크 오류·파싱 실패는 절대 throw 하지 않고 null 을 돌려준다(점검 무중단, graceful degradation).
 *  - 모델은 "계획·분석"만 생성한다. 실제 HTTP 발신은 기존 비파괴 엔진이 GET/HEAD/OPTIONS 로만 수행한다.
 */
import { config } from '../../config.js';

export interface AiCallOpts { system: string; user: string; maxTokens?: number; temperature?: number }

export function isAiConfigured(): boolean {
  return !!config.ai.apiKey;
}

export function aiStatus(): { configured: boolean; provider: string; model: string } {
  return { configured: isAiConfigured(), provider: config.ai.provider, model: config.ai.model };
}

/** 모델 호출 → 텍스트. 미구성/오류 시 null. */
export async function aiComplete(opts: AiCallOpts): Promise<string | null> {
  if (!isAiConfigured()) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), config.ai.timeoutMs);
  try {
    return config.ai.provider === 'openai'
      ? await callOpenAi(opts, ctrl.signal)
      : await callAnthropic(opts, ctrl.signal);
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
  let s = raw.trim();
  // ```json ... ``` 펜스 제거
  const fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(s);
  if (fence && fence[1]) s = fence[1].trim();
  // 첫 { 또는 [ 부터 마지막 } 또는 ] 까지 슬라이스 (앞뒤 잡텍스트 제거)
  const first = Math.min(...['{', '['].map((c) => { const i = s.indexOf(c); return i === -1 ? Infinity : i; }));
  const lastObj = s.lastIndexOf('}'); const lastArr = s.lastIndexOf(']');
  const last = Math.max(lastObj, lastArr);
  if (Number.isFinite(first) && last > first) s = s.slice(first, last + 1);
  try { return JSON.parse(s) as T; } catch { return null; }
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
  const res = await fetch(url, {
    method: 'POST', signal,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${config.ai.apiKey}` },
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
