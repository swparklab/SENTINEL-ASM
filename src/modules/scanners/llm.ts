/**
 * OWASP Top 10 for LLM (2025) — 비파괴 클라이언트측 점검. 설계 §4.4 확장.
 * 대상이 LLM/AI 앱일 때 클라이언트에서 관측 가능한 표면을 정적/수동으로 탐지한다.
 * ctx.guard.httpGet(GET 전용)으로 루트 HTML + 동일출처 번들 JS + 잘 알려진 AI 설정 경로만 본다.
 * 능동 프롬프트 주입(POST)은 EgressGuard 가 구조적으로 차단하므로 애초에 시도하지 않는다(비파괴).
 *
 * dast.ts 가 호출. 모든 발견은 module='dast', 제목에 'LLM' 키워드를 포함하고 owasp/cwe 를 명시 부착한다.
 */
import type { Finding } from '../../types.js';
import type { ScanContext } from './types.js';
import { mk } from './asm.js';

type HttpResp = { ok: boolean; status: number; headers: Record<string, string>; body: string };
type Sev = Finding['severity'];
type Conf = Finding['confidence'];

const REF_LLM = ['https://genai.owasp.org/llm-top-10/', 'https://owasp.org/www-project-top-10-for-large-language-model-applications/'];

/**
 * 사이트가 LLM/AI 앱임을 시사하는 강한 신호(1개 이상일 때만 점검 진입 — 무관 사이트 오탐 억제).
 * 단독 일반명사(claude/gemini/mistral/cohere/assistant/embedding)는 제외하고, AI 특이 형태만 신호로 본다.
 */
const LLM_APP_SIGNALS = /\bopenai\b|\banthropic\b|\bllm\b|gpt-?[0-9]|chatgpt|claude-(?:[0-9]|opus|sonnet|haiku)|gemini-(?:pro|flash|[0-9.])|huggingface|langchain|llamaindex|\bchat ?completions?\b|system ?prompt|\bai[ -]?(?:assistant|chatbot|agent|copilot)\b|vector ?store|text-embedding|\bollama\b|mistral(?:ai|-[a-z0-9])|api\.(?:openai|anthropic|cohere)\.|"role"\s*:\s*"(?:system|assistant)"|\btool_calls\b|\bfunction_call\b/i;

/** placeholder/예시 키 — 오탐 억제. */
const PLACEHOLDER = /your[_-]?api|example|xxxx+|placeholder|<[^>]+>|sk-\.\.\.|dummy|test[_-]?key|0{8,}|abcdef0123|changeme|insert[_-]?key|my[_-]?secret/i;

function build(sev: Sev, title: string, target: string, desc: string, evidence: string, remediation: string, owasp: string, cwe: string, confidence: Conf): Finding {
  return { ...mk('dast', sev, title, target, desc, evidence, remediation), owasp, cwe, confidence, references: REF_LLM };
}

export async function runLlmScan(ctx: ScanContext, base: string, host: string, root: HttpResp, baseStatus: number, baseBody: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    // (1) 동일출처 번들 JS 수집(최대 8개, GET). 외부 출처는 allowlist 밖이라 try/catch 흡수.
    const jsBlobs: string[] = [];
    const scripts = [...root.body.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]!);
    let jsCount = 0;
    for (const s of scripts) {
      if (jsCount >= 8) break;
      const abs = sameOriginUrl(s, base, host);
      if (!abs) continue;
      jsCount++;
      try { const r = await ctx.guard.httpGet(abs, { timeoutMs: 7000 }); if (r && r.status === 200 && r.body) jsBlobs.push(r.body.slice(0, 200_000)); } catch { /* EgressViolation 등 흡수 */ }
    }
    const corpus = root.body + '\n' + jsBlobs.join('\n');

    // LLM-앱 신호 게이트
    if (!LLM_APP_SIGNALS.test(corpus)) { ctx.log('llm: LLM/AI 앱 신호 없음 — 점검 생략'); return findings; }
    ctx.log('llm: LLM/AI 앱 신호 감지 — OWASP LLM Top10 표면 점검');

    // ── LLM06: 모델 API 키 노출 (critical) ──
    const KEY_RES: { re: RegExp; provider: string }[] = [
      { re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g, provider: 'OpenAI' },
      { re: /\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}\b/g, provider: 'Anthropic' },
      { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, provider: 'Google AI' },
      { re: /\bhf_[A-Za-z0-9]{30,}\b/g, provider: 'HuggingFace' },
      { re: /\br8_[A-Za-z0-9]{30,}\b/g, provider: 'Replicate' },
    ];
    const keysFound: string[] = [];
    for (const k of KEY_RES) {
      for (const m of corpus.matchAll(k.re)) {
        const val = m[0];
        if (PLACEHOLDER.test(val) || lowEntropyKey(val)) continue;
        if (keysFound.some((x) => x.endsWith(val))) continue;
        keysFound.push(`${k.provider}:${val}`);
        findings.push(build('critical', `LLM 모델 API 키(시크릿) 클라이언트 노출: ${k.provider}`, host,
          `클라이언트 번들/HTML 에 ${k.provider} 모델 API 키가 노출됩니다. 누구나 추출해 과금·오남용할 수 있습니다(LLM06).`,
          `${k.provider} key: ${maskKey(val)} (클라이언트 corpus 에서 발견)`,
          '모델 API 키를 클라이언트에 두지 말고 서버측 프록시로 호출하십시오. 노출된 키는 즉시 폐기·재발급하고 사용 로그를 점검하십시오.',
          'A02:2021', 'CWE-312', 'firm'));
        break; // 제공자당 1건
      }
    }

    // ── LLM06: 시스템 프롬프트 누출 (가드레일 어구 있으면 firm, 없으면 tentative) ──
    const sysPrompt = /["'`]?(system[_-]?prompt|systemprompt|system_message|systemmessage)["'`]?\s*[:=]\s*["'`](You are|당신은|As an AI|Your role|역할은|You must|Do not reveal|System:)([^"'`]{20,})/i.exec(corpus)
      || /["']role["']?\s*:\s*["']system["']\s*,\s*["']?content["']?\s*:\s*["'`]([^"'`]{20,})/i.exec(corpus);
    if (sysPrompt) {
      const full = sysPrompt[0];
      const snippet = scrubSecrets((sysPrompt[sysPrompt.length - 1] || full).slice(0, 60)).replace(/\s+/g, ' ');
      const guardrail = /do not reveal|never reveal|do not disclose|절대|비밀|반드시|must not|confidential|ignore (?:all |previous )?instruction|시스템 지시/i.test(full);
      findings.push(build('medium', 'LLM 시스템 프롬프트 클라이언트 누출', host,
        '클라이언트 번들에 시스템 프롬프트/가드레일 지시문이 노출됩니다. 공격자가 가드레일을 분석해 프롬프트 인젝션 우회를 설계할 수 있습니다(LLM06).',
        `system prompt: "${snippet}…(truncated)"`,
        '시스템 프롬프트·가드레일을 클라이언트 번들에 두지 말고 서버에서만 주입하십시오.',
        'A05:2021', 'CWE-200', guardrail ? 'firm' : 'tentative'));
    }

    // ── LLM02: 안전하지 않은 출력 처리(XSS-via-LLM) — 새니타이저 감싸면 억제 ──
    const xssSink = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*[=(][^;\n]{0,80}(response|completion|message|content|answer|reply|delta|choices|assistant|markdown|aiText|llm|chat)/i.exec(corpus)
      || /dangerouslySetInnerHTML\s*[:=]\s*\{\{?\s*__html\s*:[^}]{0,80}(response|message|content|answer|markdown|ai|llm)/i.exec(corpus);
    if (xssSink) {
      const sinkStr = xssSink[0];
      const sanitized = /sanitize|dompurify|purify|escape[_-]?html|encode[_-]?html|textcontent|\.text\(|striptags/i.test(sinkStr);
      if (!sanitized) {
        // 직접 보간/연결(+, ${}) 또는 키워드 변수 직접 대입 = 위험(high/firm); 함수 래핑(미상 새니타이저 가능) = medium/tentative.
        const direct = /\$\{|\+/.test(sinkStr) || /[=(]\s*(response|completion|message|content|answer|reply|delta|assistant|aitext|llm|chat)\b/i.test(sinkStr);
        findings.push(build(direct ? 'high' : 'medium', 'LLM 안전하지 않은 출력 처리(XSS-via-LLM)', host,
          'LLM 응답을 innerHTML/dangerouslySetInnerHTML 등으로 렌더합니다. 모델 출력에 스크립트가 포함되면 XSS 로 실행될 수 있습니다(LLM02).',
          `sink: ${sinkStr.slice(0, 90).replace(/\s+/g, ' ')}${direct ? ' (직접 보간)' : ' (새니타이저 미확인)'}`,
          'LLM 출력을 신뢰하지 말고 렌더 전 HTML 새니타이즈(DOMPurify)하거나 textContent 로 출력하고, 마크다운은 raw HTML 비활성화 + CSP 강화하십시오.',
          'A03:2021', 'CWE-79', direct ? 'firm' : 'tentative'));
      }
    }

    // ── LLM07/08: 도구/함수 정의 노출 — OpenAI function-calling 스키마 구조를 요구(일반 객체 오탐 억제) ──
    const toolDef = /["'`]?type["'`]?\s*:\s*["']function["'][\s\S]{0,160}["'`]?function["'`]?\s*:\s*\{/i.test(corpus)
      || /["'`]?(tools|functions)["'`]?\s*:\s*\[[\s\S]{0,400}?["'`]?parameters["'`]?\s*:\s*\{/i.test(corpus);
    if (toolDef) {
      // 게이트(toolDef)가 이미 OpenAI 도구 스키마 구조를 확인했으므로, name 뒤 80자 내 parameters/description 동반 시 도구명으로 추출(따옴표 유무 무관).
      const toolNames = [...corpus.matchAll(/["'`]?name["'`]?\s*:\s*["'`]([a-z][a-z0-9_]{2,40})["'`][\s\S]{0,80}?["'`]?(?:parameters|description|arguments)["'`]?\s*:/gi)].map((m) => m[1]!).slice(0, 8);
      const sensitive = toolNames.filter((n) => /execute|run|shell|sql|delete|drop|admin|payment|transfer|file|email|deploy|exec|eval/i.test(n));
      findings.push(build(sensitive.length ? 'high' : 'medium', 'LLM 도구/함수 정의 클라이언트 노출', host,
        `LLM 도구/함수 호출 스키마가 클라이언트에 노출됩니다${sensitive.length ? `(민감 동작 도구 포함: ${sensitive.join(', ')})` : ''}. 과도한 권한 위임/도구 남용 표면입니다(LLM07/08).`,
        `tools: ${toolNames.join(', ') || '(이름 미추출)'}`,
        '도구/함수 스키마·권한을 서버에서 관리하고 최소권한·휴먼인더루프 승인을 적용하십시오. 민감 동작(파일·결제·실행) 도구는 클라이언트 정의에서 제거하십시오.',
        'A05:2021', 'CWE-749', sensitive.length ? 'firm' : 'tentative'));
    }

    // ── LLM01: 입력→프롬프트 직접 보간 단서 (info) ──
    const reflect = /(prompt|messages|content|input|query)\s*[:=]\s*[`"'][^`"']{0,40}\$\{[^}]*(input|userinput|query|message|text|value|\bq\b)\}/i.exec(corpus);
    if (reflect) {
      findings.push(build('info', 'LLM 프롬프트 인젝션 표면 — 사용자 입력 직접 보간', host,
        '클라이언트에서 사용자 입력을 프롬프트 문자열에 직접 보간합니다. 프롬프트 인젝션·역할 혼동 표면입니다(LLM01).',
        `pattern: ${reflect[0].slice(0, 80).replace(/\s+/g, ' ')}`,
        '사용자 입력을 시스템 프롬프트와 분리하고 구조화 메시지(role 분리)로 전달하며, 프롬프트 조립은 서버에서 검증 후 수행하십시오.',
        'A03:2021', 'CWE-77', 'tentative'));
    }

    // ── LLM01/LLM04/LLM10: 챗·완성 엔드포인트 존재 + 레이트리밋 부재 ──
    const epRe = /["'`]((?:https?:\/\/[^"'`]+)?\/(?:api\/)?(?:v\d\/)?(?:chat(?:\/completions)?|completions?|ask|generate|copilot|assistant|converse|inference|predict|llm))["'`?]/gi;
    const cand = [...new Set([...corpus.matchAll(epRe)].map((m) => stripToPath(m[1]!, host)))].filter(Boolean).slice(0, 4);
    for (const path of cand) {
      let r: HttpResp | null = null;
      try { r = await ctx.guard.httpGet(base + path, { timeoutMs: 6000 }); } catch { continue; }
      if (!r) continue;
      const exists = [200, 400, 401, 403, 405].includes(r.status) && !(baseStatus === 200 && r.status === 200 && r.body === baseBody);
      if (!exists) continue;
      findings.push(build('info', `LLM 추론 엔드포인트 노출(프롬프트 인젝션 표면): ${path}`, host + path,
        `LLM 챗/완성 추론 엔드포인트가 외부에서 식별됩니다(GET 존재확인, POST 미수행). 입력 검증·인증·레이트리밋 점검이 필요합니다(LLM01).`,
        `endpoint=${path} status=${r.status} (POST 미수행, 비파괴 GET 존재확인)`,
        'LLM 입력에 시스템/사용자 프롬프트 경계를 강제하고, 엔드포인트에 인증·레이트리밋·입력 검증을 적용하십시오.',
        'A03:2021', 'CWE-77', 'tentative'));
      const hk = Object.keys(r.headers).map((h) => h.toLowerCase());
      const hasRl = hk.some((h) => /^(x-)?ratelimit|^x-rate-limit|^retry-after$/i.test(h));
      if (!hasRl) {
        findings.push(build('low', `LLM 엔드포인트 레이트리밋 부재 단서: ${path}`, host + path,
          'LLM 추론 엔드포인트 응답에 레이트리밋 헤더가 없습니다. 토큰 예산·동시성 제한이 없으면 모델 DoS/무단 소비(비용 폭증) 위험이 있습니다(LLM04/LLM10).',
          `${path}: no ratelimit headers (x-ratelimit-*/retry-after 부재)`,
          'LLM 엔드포인트에 사용자/토큰별 레이트리밋과 토큰 예산(max_tokens·동시성 제한)을 적용하고 x-ratelimit-* 헤더로 한도를 노출하십시오.',
          'A05:2021', 'CWE-770', 'tentative'));
      }
    }

    // ── LLM 설정 매니페스트 노출 (low) — evidence 는 시크릿 스크럽 후 출력 ──
    const manifests: { path: string; sig: RegExp }[] = [
      { path: '/.well-known/ai-plugin.json', sig: /"schema_version"|"api"\s*:|"auth"\s*:|openapi/i },
      { path: '/ai-plugin.json', sig: /"schema_version"|"api"\s*:|"auth"\s*:/i },
      { path: '/.well-known/openapi.json', sig: /x-openai|"openapi"\s*:/i },
    ];
    for (const mf of manifests) {
      let r: HttpResp | null = null;
      try { r = await ctx.guard.httpGet(base + mf.path, { timeoutMs: 6000 }); } catch { continue; }
      if (r && r.status === 200 && r.body && r.body !== baseBody && mf.sig.test(r.body)) {
        findings.push(build('low', `LLM 플러그인/AI 매니페스트 노출: ${mf.path}`, host + mf.path,
          'AI 플러그인/OpenAPI 매니페스트가 공개되어 내부 엔드포인트·도구·인증 흐름이 드러납니다(LLM 설정 노출).',
          `${mf.path}: ${scrubSecrets(r.body.slice(0, 120)).replace(/\s+/g, ' ').slice(0, 80)}`,
          'AI 매니페스트·OpenAPI 에 내부 엔드포인트/비밀이 노출되지 않게 하고, isConsequential 도구는 사용자 승인을 강제하며, 불필요한 매니페스트는 비공개 처리하십시오.',
          'A05:2021', 'CWE-200', 'firm'));
        break;
      }
    }
  } catch (e) {
    ctx.log(`llm: 점검 오류 — ${(e as Error).message}`);
  }
  ctx.log(`llm: OWASP LLM Top10 발견 ${findings.length}건`);
  return findings;
}

/** 상대/동일출처 절대 URL 만 허용(외부 CDN·data:/blob: 등 다른 스킴/호스트는 null). */
function sameOriginUrl(src: string, base: string, host: string): string | null {
  if (!src) return null;
  if (/^https?:\/\//i.test(src)) {
    try { const u = new URL(src); return u.host === host ? src : null; } catch { return null; }
  }
  if (src.startsWith('//')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(src)) return null;   // data:/blob:/javascript: 등 비-http 스킴 제외
  if (src.startsWith('/')) return base.replace(/\/$/, '') + src;
  if (src.startsWith('./') || /^[a-z0-9_]/i.test(src)) return base.replace(/\/$/, '') + '/' + src.replace(/^\.\//, '');
  return null;
}

/** 매칭된 엔드포인트 URL 에서 동일출처 경로만 추출(외부 URL 은 빈문자열). */
function stripToPath(raw: string, host: string): string {
  if (/^https?:\/\//i.test(raw)) {
    try { const u = new URL(raw); return u.host === host ? u.pathname : ''; } catch { return ''; }
  }
  return raw.startsWith('/') ? raw.split('?')[0]! : '';
}

/** 저엔트로피 더미 키 판정(반복문자/문자종류 부족) — 'sk-aaaa…' 등 샘플 키 오탐 억제. */
function lowEntropyKey(k: string): boolean {
  const body = k.replace(/^(sk-(?:proj-|ant-(?:api03-)?)?|AIza|hf_|r8_)/i, '');
  if (new Set(body.toLowerCase()).size <= 6) return true;
  if (/(.)\1{7,}/.test(body)) return true;
  return false;
}

/** evidence 출력 전 시크릿/토큰을 마스킹(키 패턴 + auth/token/secret/key JSON 값). */
function scrubSecrets(s: string): string {
  return s
    .replace(/\b(sk-(?:proj-|ant-(?:api03-)?)?[A-Za-z0-9_-]{10,}|AIza[0-9A-Za-z_-]{10,}|hf_[A-Za-z0-9]{10,}|r8_[A-Za-z0-9]{10,})\b/g, '[key-redacted]')
    .replace(/("?(?:auth|token|secret|api[_-]?key|password|client[_-]?secret|verification[_-]?token)"?\s*[:=]\s*")[^"]{4,}"/gi, '$1[redacted]"');
}

function maskKey(k: string): string { return k.slice(0, 6) + '…' + k.slice(-2) + ' (redacted)'; }
