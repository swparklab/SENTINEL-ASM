/**
 * 위험 산정 (설계 §5.1).
 * 최종 우선순위 점수 = CVSS 기본점수 × 자산 중요도 가중 × 노출도 가중,
 * 여기에 EPSS(익스플로잇 확률)·KEV(실제 악용) 를 반영해 우선순위 큐를 산출한다.
 */
import type { Asset, Finding } from '../../types.js';
import { assignCvss } from './cvss.js';

const SEVERITY_BASE: Record<Finding['severity'], number> = {
  info: 1, low: 3, medium: 5.5, high: 8, critical: 9.5,
};

const CRITICALITY_WEIGHT: Record<Asset['businessCriticality'], number> = {
  low: 0.85, medium: 1.0, high: 1.2, critical: 1.4,
};

/** 노출도: 외부에서 직접 도달 가능한 표면일수록 가중 (설계 §5.1 exposure). */
function exposureWeight(f: Finding): number {
  if (f.module === 'asm' || f.module === 'dast' || f.module === 'access' || f.module === 'ai') return 1.15; // 외부 노출/동적·접근통제·AI 적응형 표면
  if (f.module === 'config') return 1.05;
  return 1.0;
}

/**
 * 고위험 신호 키워드 가중치 (Keyword Weighting).
 * 점검 결과 정규화 후 위험 산정 루프에서 발견사항 텍스트(제목·설명·대상·CWE/OWASP)를
 * 스캔하여, 치명적 침해로 직결되는 신호가 포함되면 우선순위를 상향한다.
 * "남들이 놓치는 한 건"이 묻히지 않도록 하는 가중 레이어.
 */
export const KEYWORD_WEIGHTS: { weight: number; terms: string[] }[] = [
  { weight: 1.50, terms: ['rce', '원격코드실행', 'remote code execution', 'shellshock', 'log4shell', 'spring4shell', 'text4shell'] },
  { weight: 1.45, terms: ['비밀키', 'private key', 'id_rsa', 'credential', '자격증명', 'secret', '.env', '.aws', 'aws_access', 'db_password', 'connectionstring', 'apikey', 'api key', '_authtoken'] },
  { weight: 1.40, terms: ['인증 우회', 'auth bypass', 'authentication bypass', '인가 우회', 'authorization bypass', 'sql 주입', 'sql injection', 'sqli'] },
  { weight: 1.38, terms: ['역직렬화', 'deserialization', 'insecure deserialization'] },
  { weight: 1.35, terms: ['ssrf', 'server-side request forgery', '서브도메인 탈취', 'takeover', 'rce', 'command injection', '명령 주입'] },
  { weight: 1.30, terms: ['프로토타입 오염', 'prototype pollution', '경로 우회', 'path traversal', 'lfi', 'rfi', '임의 파일'] },
  { weight: 1.22, terms: ['관리자', 'admin', 'actuator', 'jmx', 'jenkins', '백도어', 'backdoor'] },
  { weight: 1.18, terms: ['토큰', 'token', 'session', '세션', 'csrf', 'xss', '인젝션', 'injection'] },
  { weight: 1.12, terms: ['백업', 'backup', '.git', '.svn', '디렉터리 인덱싱', 'directory listing', 'graphql', 'swagger'] },
];

/** 발견사항에 매칭되는 최대 키워드 가중치를 반환 (없으면 1.0). */
export function keywordWeight(f: Finding): { weight: number; matched: string | null } {
  const hay = `${f.title} ${f.description} ${f.target} ${f.cwe ?? ''} ${f.owasp ?? ''} ${f.cve ?? ''}`.toLowerCase();
  let best = 1.0; let matched: string | null = null;
  for (const rule of KEYWORD_WEIGHTS) {
    for (const t of rule.terms) {
      if (hay.includes(t) && rule.weight > best) { best = rule.weight; matched = t; }
    }
  }
  return { weight: best, matched };
}

/** 단일 발견사항의 0–100 위험 점수 산출. */
export function scoreFinding(f: Finding, asset: Asset): number {
  const base = f.cvss ?? SEVERITY_BASE[f.severity];
  let score = base * CRITICALITY_WEIGHT[asset.businessCriticality] * exposureWeight(f);

  // EPSS: 익스플로잇 확률이 높을수록 가산 (최대 +25%)
  if (typeof f.epss === 'number') score *= 1 + f.epss * 0.25;
  // KEV: 실제 악용 중인 취약점은 강한 가산
  if (f.kev) score *= 1.3;
  // 고위험 신호 키워드 가중 (루프 연산 내 적용)
  const kw = keywordWeight(f);
  if (kw.weight > 1.0) {
    score *= kw.weight;
    f.evidence = f.evidence ? `${f.evidence}\n[가중 키워드: ${kw.matched} ×${kw.weight}]` : `[가중 키워드: ${kw.matched} ×${kw.weight}]`;
  }

  return Math.min(100, Math.round(score * 10));
}

/** 발견사항 배열에 위험 점수를 부여하고 우선순위 내림차순으로 정렬. CVE 가 아닌 발견에는 CVSS 3.1 을 자동 산정한다. */
export function prioritize(findings: Finding[], asset: Asset): Finding[] {
  for (const f of findings) {
    if (f.cvss === undefined) { const c = assignCvss(f); f.cvss = c.score; f.cvssVector = c.vector; }   // CVE 피드 점수 없으면 CWE/심각도 기반 CVSS 3.1 추정(벡터 보존)
    f.riskScore = scoreFinding(f, asset);
  }
  return findings.sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
}

export type RiskBand = 'critical' | 'high' | 'medium' | 'low' | 'info';

export function band(score: number): RiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
}

/** 자산/작업 단위 종합 위험도 (가장 높은 발견 + 누적 가중). */
export function aggregateRisk(findings: Finding[]): { score: number; band: RiskBand; counts: Record<string, number> } {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let max = 0;
  let sum = 0;
  for (const f of findings) {
    const s = f.riskScore ?? 0;
    max = Math.max(max, s);
    sum += s;
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  // 종합 점수: 최고 위험 70% + 누적 위험(로그 스케일) 30%
  const cumulative = findings.length ? Math.min(100, Math.log2(sum + 1) * 8) : 0;
  const score = Math.round(max * 0.7 + cumulative * 0.3);
  return { score, band: band(score), counts };
}
