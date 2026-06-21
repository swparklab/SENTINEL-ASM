/**
 * CVSS 3.1 자동 산정 (설계 §5.1) — CVE 가 아닌 발견에도 객관적 기준점수를 부여한다.
 * 발견의 CWE/카테고리로 표준 CVSS 3.1 벡터를 추정해 Base Score 를 계산하고, 심각도 밴드로 클램프한다.
 * (CVE 발견은 피드의 실제 CVSS 를 사용하므로 본 산정을 적용하지 않는다.)
 */
import type { Finding } from '../../types.js';

type Vec = { AV: 'N' | 'A' | 'L' | 'P'; AC: 'L' | 'H'; PR: 'N' | 'L' | 'H'; UI: 'N' | 'R'; S: 'U' | 'C'; C: 'N' | 'L' | 'H'; I: 'N' | 'L' | 'H'; A: 'N' | 'L' | 'H' };

const AVv = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ACv = { L: 0.77, H: 0.44 };
const UIv = { N: 0.85, R: 0.62 };
const PRu = { N: 0.85, L: 0.62, H: 0.27 };
const PRc = { N: 0.85, L: 0.68, H: 0.5 };
const CIA = { N: 0, L: 0.22, H: 0.56 };

/** CVSS 3.1 Base Score 계산. */
export function cvss31Base(v: Vec): number {
  const iss = 1 - (1 - CIA[v.C]) * (1 - CIA[v.I]) * (1 - CIA[v.A]);
  const impact = v.S === 'C' ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * AVv[v.AV] * ACv[v.AC] * (v.S === 'C' ? PRc : PRu)[v.PR] * UIv[v.UI];
  const raw = v.S === 'C' ? 1.08 * (impact + expl) : impact + expl;
  return roundUp(Math.min(raw, 10));
}
function roundUp(x: number): number { return Math.ceil(x * 10) / 10; }
export function cvssVector(v: Vec): string {
  return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
}

const BASE: Vec = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
const v = (o: Partial<Vec>): Vec => ({ ...BASE, ...o });

/** CWE → CVSS 3.1 벡터 추정(대표값). */
const CWE_VEC: Record<string, Vec> = {
  'CWE-89': v({ C: 'H', I: 'H', A: 'H' }),                         // SQLi 9.8
  'CWE-78': v({ C: 'H', I: 'H', A: 'H' }),                         // OS command injection 9.8
  'CWE-1336': v({ C: 'H', I: 'H', A: 'H' }),                       // SSTI 9.8
  'CWE-502': v({ C: 'H', I: 'H', A: 'H' }),                        // deserialization 9.8
  'CWE-94': v({ C: 'H', I: 'H', A: 'H' }),
  'CWE-79': v({ UI: 'R', S: 'C', C: 'L', I: 'L' }),                // XSS 6.1
  'CWE-22': v({ C: 'H' }),                                         // path traversal 7.5
  'CWE-918': v({ C: 'H' }),                                        // SSRF 7.5
  'CWE-611': v({ C: 'H' }),                                        // XXE 7.5
  'CWE-359': v({ C: 'H' }),                                        // PII exposure 7.5
  'CWE-200': v({ C: 'H' }),                                        // info exposure 7.5
  'CWE-532': v({ C: 'H' }),
  'CWE-540': v({ C: 'H' }),                                        // sourcemap/source exposure
  'CWE-530': v({ C: 'H' }),                                        // backup files
  'CWE-312': v({ C: 'H' }),                                        // cleartext secret 7.5
  'CWE-798': v({ C: 'H', I: 'L' }),                                // hardcoded creds
  'CWE-922': v({ C: 'H' }),                                        // insecure storage
  'CWE-639': v({ C: 'H' }),                                        // IDOR 7.5
  'CWE-284': v({ C: 'H' }),                                        // access control
  'CWE-285': v({ C: 'H' }),
  'CWE-862': v({ C: 'H' }),                                        // missing authorization
  'CWE-863': v({ C: 'H' }),
  'CWE-306': v({ C: 'H', I: 'H' }),                                // missing auth 9.1
  'CWE-287': v({ C: 'H', I: 'H' }),                                // auth bypass 9.1
  'CWE-290': v({ C: 'H', I: 'H' }),                                // auth bypass by spoof
  'CWE-347': v({ C: 'H', I: 'H' }),                                // JWT sig (alg none) 9.1
  'CWE-352': v({ UI: 'R', I: 'H' }),                              // CSRF 6.5
  'CWE-942': v({ C: 'H' }),                                        // CORS misconfig 7.5
  'CWE-319': v({ AC: 'H', C: 'H' }),                               // cleartext transport (MITM) 5.9
  'CWE-311': v({ AC: 'H', C: 'H' }),
  'CWE-327': v({ AC: 'H', C: 'H' }),                               // weak crypto 5.9
  'CWE-326': v({ AC: 'H', C: 'H' }),
  'CWE-295': v({ AC: 'H', C: 'H' }),                               // cert validation
  'CWE-350': v({ S: 'C', C: 'L', I: 'L' }),                       // subdomain takeover
  'CWE-1021': v({ UI: 'R', S: 'C', I: 'L' }),                     // clickjacking 4.7
  'CWE-770': v({ A: 'L' }),                                        // no rate limit (DoS surface)
  'CWE-400': v({ A: 'L' }),
  'CWE-693': v({ C: 'L' }),                                        // missing CSP/defense
  'CWE-1004': v({ C: 'L' }),                                       // missing HttpOnly
  'CWE-614': v({ C: 'L' }),
  'CWE-16': v({ C: 'L' }),                                         // misconfig
  'CWE-548': v({ C: 'L' }),                                        // directory listing
  'CWE-650': v({ I: 'L' }),                                        // dangerous method
  'CWE-113': v({ I: 'L', S: 'C' }),
  'CWE-601': v({ UI: 'R', C: 'L', I: 'L' }),                      // open redirect
  'CWE-489': v({ C: 'L', I: 'L' }),                               // debug mode
  'CWE-506': v({ C: 'L', I: 'L' }),                                // threat-intel/IoC match
  'CWE-213': v({ C: 'L' }),                                        // excessive exposure
  'CWE-732': v({ C: 'H' }),                                        // incorrect permission (public bucket) 7.5
  'CWE-1357': v({ C: 'L', I: 'L' }),                               // IaC misconfig
};

const SEV_FALLBACK: Record<Finding['severity'], Vec> = {
  critical: v({ C: 'H', I: 'H' }),
  high: v({ C: 'H' }),
  medium: v({ C: 'L', I: 'L' }),
  low: v({ C: 'L' }),
  info: v({ }),
};

/** CWE 벡터 산정값을 우선 신뢰하되, severity 와의 극단적 괴리만 느슨히 보정(밴드 경계로 하드 스냅하지 않음). */
const LOOSE: Record<Finding['severity'], [number, number]> = {
  critical: [7.0, 10.0], high: [4.0, 10.0], medium: [0.1, 8.9], low: [0.1, 6.9], info: [0.0, 0.0],
};

/** 발견에 CVSS 3.1 Base Score 추정값과 벡터를 산정. cvss 가 이미 있으면(CVE 피드) 호출하지 않는다. */
export function assignCvss(f: Finding): { score: number; vector: string } {
  const vec = (f.cwe && CWE_VEC[f.cwe]) ? CWE_VEC[f.cwe]! : SEV_FALLBACK[f.severity];
  let score = cvss31Base(vec);
  if (f.severity === 'info') score = 0;
  else { const [lo, hi] = LOOSE[f.severity]; score = Math.min(Math.max(score, lo), hi); }
  return { score: Math.round(score * 10) / 10, vector: cvssVector(vec) };
}
