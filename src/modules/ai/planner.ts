/**
 * AI 적응형 점검 플래너 (설계 §5.3).
 * 사이트 핑거프린트를 보고 "이 사이트에 특화된" 비파괴 점검 후보를 모델이 제안한다.
 * 모델은 계획만 만든다 — 실제 발신은 verifier 가 EgressGuard 로 GET/HEAD/OPTIONS 만 수행한다.
 */
import { aiJson } from './provider.js';
import type { SiteFingerprint } from './fingerprint.js';

export interface AiProbe {
  path: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  category: string;
  rationale: string;
  expect: string;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
/** 경로/근거에 파괴적 의도가 드러나면 거부(이중 안전장치). */
const DESTRUCTIVE = /\b(delete|drop|truncate|shutdown|destroy|wipe|format|;rm|--|\bunion\b|sleep\(|benchmark\(|\bexec\b)\b/i;

const SYSTEM = `당신은 "권한이 검증된 대상"을 점검하는 SENTINEL-ASM 의 비파괴(non-destructive) 적응형 점검 플래너다.
주어진 사이트 핑거프린트(용도·기술스택·경로·폼·API 힌트)를 보고, 이 사이트의 실제 데이터 모델에 특화된
"읽기 전용 점검 후보"를 제안하라.

엄격한 규칙(위반 금지):
- 메서드는 GET / HEAD / OPTIONS 만. 쓰기·상태변경·익스플로잇·브루트포스·자격증명 추측·파괴적 페이로드 절대 금지.
- 경로는 동일 출처의 상대경로('/'로 시작)만. 전체 URL·외부 도메인 금지.
- 사이트 용도에서 데이터 모델을 추론해 "그 사이트라면 있을 법한" 비인가 데이터/PII API, 객체참조(BOLA/IDOR)
  엔드포인트, 관리/내부 영역, 설정·백업·명세 노출, 정보 누출 지점을 우선 제안하라.
  (예: 지원/심사/공모 플랫폼 → /api/applicants, /api/submissions, /api/evaluations/{id}, /api/admin/applicants)
- 추측은 근거(rationale)와 함께. 확인 신호(expect: 무엇이 관측되면 취약인지)를 명시하라.
- 핑거프린트에 이미 드러난 paths/apiHints 를 적극 활용하되, 중복·정적 자원·로그아웃 같은 무의미 경로는 제외.

출력: JSON 배열만. 각 항목 = {"path","method","category","rationale","expect"}.
category 예: "data-exposure" | "bola" | "access-control" | "misconfig" | "info-leak" | "auth".
최대 {N}개. 설명·마크다운 금지, JSON 만.`;

export async function proposeProbes(fp: SiteFingerprint, max: number): Promise<AiProbe[]> {
  const system = SYSTEM.replace('{N}', String(max));
  const arr = await aiJson<unknown>({ system, user: JSON.stringify(fp), maxTokens: 2048 });
  if (!Array.isArray(arr)) return [];
  const out: AiProbe[] = [];
  const seen = new Set<string>();
  for (const it of arr) {
    if (!it || typeof it !== 'object') continue;
    const o = it as Record<string, unknown>;
    const method = String(o['method'] ?? 'GET').toUpperCase();
    let path = String(o['path'] ?? '').trim();
    if (!SAFE_METHODS.has(method)) continue;
    if (!path.startsWith('/') || path.length > 120) continue;
    if (/^https?:/i.test(path)) continue;
    const rationale = String(o['rationale'] ?? '').slice(0, 240);
    if (DESTRUCTIVE.test(path) || DESTRUCTIVE.test(rationale)) continue;
    const key = method + ' ' + path.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      path, method: method as AiProbe['method'],
      category: String(o['category'] ?? 'recon').slice(0, 40),
      rationale,
      expect: String(o['expect'] ?? '').slice(0, 200),
    });
    if (out.length >= max) break;
  }
  return out;
}
