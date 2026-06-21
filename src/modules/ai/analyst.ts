/**
 * AI 발견사항 분석가 (설계 §5.3).
 * 점검이 끝난 뒤 전체 발견을 받아 경영진 요약·우선순위·공격경로·오탐 가능성·핵심 권고를 생성한다.
 * LLM 미구성 시 null (리포트는 기존 규칙기반 요약으로 동작). PII 가 섞이지 않도록 제목·메타데이터만 전송.
 */
import { aiJson } from './provider.js';
import { redact } from './fingerprint.js';
import type { Finding } from '../../types.js';

export interface AiAnalysis {
  executiveSummary: string;
  blastRadius: string;
  prioritized: { title: string; severity: string; businessImpact: string; falsePositiveRisk: string; attackPath: string; recommendation: string }[];
  topRecommendations: string[];
}

const SYSTEM = `당신은 SENTINEL-ASM 의 수석 보안 분석가다. 비파괴 점검으로 수집된 발견 목록을 받아
경영진과 실무자 모두가 행동할 수 있는 분석을 한국어로 작성하라.
- executiveSummary: 3~5문장. 전체 위험 상태와 가장 시급한 문제를 비전문가도 이해하게.
- blastRadius: 공격자가 이 약점들을 연계하면 어디까지 갈 수 있는지(피해 범위) 한 단락.
- prioritized: 위험이 큰 순서로 최대 8개. 각 {title, severity, businessImpact(사업 영향),
  falsePositiveRisk(오탐 가능성: 낮음/중간/높음과 근거), attackPath(악용 시나리오 1~2문장), recommendation(구체적 조치)}.
- topRecommendations: 즉시 적용할 핵심 권고 3~6개(짧은 명령형).
과장 금지. 근거가 약한 항목은 falsePositiveRisk 에 솔직히 표기. 출력은 JSON 객체만.`;

export async function analyzeFindings(findings: Finding[]): Promise<AiAnalysis | null> {
  if (!findings.length) return null;
  // 제목·메타데이터만(원시 evidence 제외, 추가로 마스킹) — 최소 전송.
  const slim = findings.slice(0, 120).map((f) => ({
    title: redact(f.title), severity: f.severity, module: f.module,
    cwe: f.cwe, owasp: f.owasp, confidence: f.confidence,
    target: redact(f.target),
  }));
  const counts = findings.reduce<Record<string, number>>((a, f) => { a[f.severity] = (a[f.severity] ?? 0) + 1; return a; }, {});
  const user = JSON.stringify({ severityCounts: counts, findings: slim });
  const res = await aiJson<AiAnalysis>({ system: SYSTEM, user, maxTokens: 3072 });
  if (!res || typeof res !== 'object' || !res.executiveSummary) return null;
  // 방어적 정규화
  res.prioritized = Array.isArray(res.prioritized) ? res.prioritized.slice(0, 8) : [];
  res.topRecommendations = Array.isArray(res.topRecommendations) ? res.topRecommendations.slice(0, 8) : [];
  return res;
}
