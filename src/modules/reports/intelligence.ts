/**
 * AI Pentest Report 인텔리전스 (설계 §5.3) — 발견을 "공격 시나리오 기반 위험"으로 합성한다.
 *  - MITRE ATT&CK 매핑(114): CWE/카테고리 → 전술·기법(TTP).
 *  - 예상 피해금액(116): FAIR 기반 손실 추정(규제 과징금 + 사고 대응/배상). 휴리스틱·참고용.
 *  - Attack Path(117): 발견을 킬체인 단계로 묶어 대표 공격 경로 생성(분석 — 실제 실행 아님).
 *  - 재현 절차(118): 발견의 대상/근거에서 비파괴 재현 단계를 생성.
 * 모두 후처리 분석으로, 대상에 추가 발신하지 않는다.
 */
import type { Finding } from '../../types.js';

export interface AttackTechnique { id: string; name: string; tactic: string }
export interface AttackPath { name: string; severity: Finding['severity']; stages: { phase: string; finding: string; technique?: string }[]; narrative: string }
export interface LossEstimate { currency: 'KRW'; min: number; likely: number; max: number; regulatory: number; breakdown: string[]; basis: string }
export interface Intelligence { attack: { id: string; name: string; tactic: string; count: number }[]; paths: AttackPath[]; loss: LossEstimate; repro: { title: string; steps: string[] }[] }

// ── MITRE ATT&CK 매핑(CWE 우선, 제목 키워드 보조) ──
const ATT: { test: (f: Finding) => boolean; techs: AttackTechnique[] }[] = [
  { test: (f) => /CWE-(89|78|94|1336|502|77|611)/.test(f.cwe || '') || /인젝션|injection|SSTI|역직렬화/i.test(f.title), techs: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }, { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' }] },
  { test: (f) => /CWE-79/.test(f.cwe || '') || /xss|반사|스크립트/i.test(f.title), techs: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }, { id: 'T1059.007', name: 'JavaScript', tactic: 'Execution' }] },
  { test: (f) => /CWE-(287|290|306|347|384)/.test(f.cwe || '') || /인증 우회|auth bypass|JWT|인가 누락|로그인 우회/i.test(f.title), techs: [{ id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' }, { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }] },
  { test: (f) => /CWE-(639|284|285|862|863|566)/.test(f.cwe || '') || /IDOR|BOLA|접근통제|권한 상승|객체 수준 인가/i.test(f.title), techs: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }, { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' }] },
  { test: (f) => /CWE-(312|798|522|200|540|530|532|359)/.test(f.cwe || '') || /시크릿|API 키|개인키|소스|민감|개인정보|노출/i.test(f.title), techs: [{ id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access' }, { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' }] },
  { test: (f) => /CWE-359/.test(f.cwe || '') || /개인정보|PII|회원 목록/i.test(f.title), techs: [{ id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' }, { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' }] },
  { test: (f) => /CWE-918/.test(f.cwe || '') || /SSRF|메타데이터/i.test(f.title), techs: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }, { id: 'T1552.005', name: 'Cloud Instance Metadata API', tactic: 'Credential Access' }] },
  { test: (f) => /CWE-732/.test(f.cwe || '') || /S3|버킷|Blob|클라우드|Firebase/i.test(f.title), techs: [{ id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection' }] },
  { test: (f) => /CWE-350/.test(f.cwe || '') || /서브도메인 탈취|takeover/i.test(f.title), techs: [{ id: 'T1584', name: 'Compromise Infrastructure', tactic: 'Resource Development' }] },
  { test: (f) => f.module === 'asm' && /포트|오픈 포트|서비스|노출|Redis|Elasticsearch|Docker|kubelet/i.test(f.title), techs: [{ id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' }] },
  { test: (f) => /CWE-506/.test(f.cwe || '') || /위협 인텔|IoC/i.test(f.title), techs: [{ id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' }] },
  { test: (f) => /CWE-(319|327|326|295|311)/.test(f.cwe || '') || /TLS|인증서|암호|평문/i.test(f.title), techs: [{ id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'Credential Access' }] },
  { test: (f) => /CWE-(434|530)/.test(f.cwe || '') || /업로드|웹쉘|backup|백업/i.test(f.title), techs: [{ id: 'T1505.003', name: 'Web Shell', tactic: 'Persistence' }] },
];

export function attackTechniques(f: Finding): AttackTechnique[] {
  const out: AttackTechnique[] = [];
  for (const a of ATT) if (a.test(f)) for (const t of a.techs) if (!out.some((x) => x.id === t.id)) out.push(t);
  return out;
}

// ── FAIR 기반 예상 피해금액(₩, 휴리스틱·참고용) ──
const SEV_LOSS: Record<Finding['severity'], number> = { critical: 500_000_000, high: 120_000_000, medium: 25_000_000, low: 5_000_000, info: 0 };
const CRIT_MULT: Record<string, number> = { critical: 1.6, high: 1.3, medium: 1.0, low: 0.7 };

export function estimateLoss(findings: Finding[], businessCriticality = 'high'): LossEstimate {
  const breakdown: string[] = [];
  const mult = CRIT_MULT[businessCriticality] ?? 1.0;
  // 사고 대응/복구/배상 추정: 심각도별 단일 손실 × (1 + 신뢰도 가중) — 중복 카테고리는 체감 합산.
  const byCat = new Map<string, number>();
  for (const f of findings) {
    const conf = f.confidence === 'confirmed' ? 1.0 : f.confidence === 'firm' ? 0.8 : 0.5;
    const v = SEV_LOSS[f.severity] * conf;
    const cat = (f.owasp || f.cwe || f.module).split(' ')[0]!;
    byCat.set(cat, Math.max(byCat.get(cat) ?? 0, v)); // 카테고리당 최댓값(중복 합산 방지)
  }
  let incident = [...byCat.values()].reduce((s, v) => s + v, 0) * mult;

  // 규제 과징금: 개인정보 노출 발견이 있으면 개인정보보호법/GDPR 과징금 추정 가산.
  const piiFindings = findings.filter((f) => /개인정보|PII|주민|회원 목록|이메일|휴대전화|CWE-359/i.test(f.title + (f.cwe || '')));
  let regulatory = 0;
  if (piiFindings.length) {
    const sev = piiFindings.some((f) => f.severity === 'critical') ? 'critical' : 'high';
    regulatory = sev === 'critical' ? 1_000_000_000 : 300_000_000; // 개인정보보호법 과징금(매출 3%)·배상 추정 레인지
    breakdown.push(`개인정보 노출 ${piiFindings.length}건 → 규제 과징금·정보주체 배상 시나리오 가정 ${won(regulatory)} (개인정보보호법 §64-2 / GDPR Art.83 — 실 과징금은 매출·정보주체 수·관할에 따라 산정되며 본 수치는 가정 레인지)`);
  }
  const critN = findings.filter((f) => f.severity === 'critical').length;
  const highN = findings.filter((f) => f.severity === 'high').length;
  breakdown.push(`사고 대응·복구·평판 손실 추정 ≈ ${won(incident)} (critical ${critN} · high ${highN}, 자산 중요도 ${businessCriticality})`);

  const likely = incident + regulatory;
  return { currency: 'KRW', min: Math.round(likely * 0.4), likely: Math.round(likely), max: Math.round(likely * 2.2), regulatory, breakdown,
    basis: 'FAIR 기반 휴리스틱 추정(단일손실×빈도/신뢰도 가중 + 규제 과징금). 실제 손실은 데이터 규모·계약·관할에 따라 달라지며 참고용입니다.' };
}

// ── Attack Path 합성(킬체인 단계로 묶기) ──
const PHASES: { phase: string; test: (f: Finding) => boolean }[] = [
  { phase: '정찰(Recon)', test: (f) => f.module === 'asm' || /인벤토리|서브도메인|포트|robots|sitemap|버전|소스|SourceMap/i.test(f.title) },
  { phase: '초기 침투(Initial Access)', test: (f) => /인젝션|xss|SSTI|업로드|SSRF|인증 우회|로그인 우회|CWE-(89|79|78|434|918|287)/i.test(f.title + (f.cwe || '')) },
  { phase: '자격증명 접근(Credential Access)', test: (f) => /시크릿|API 키|개인키|토큰|JWT|TLS|평문|CWE-(312|798|522|319)/i.test(f.title + (f.cwe || '')) },
  { phase: '권한 상승/접근통제(Privilege/Access)', test: (f) => /IDOR|BOLA|접근통제|권한|관리자|인가|CWE-(639|284|862|285)/i.test(f.title + (f.cwe || '')) },
  { phase: '수집·유출(Collection/Exfil)', test: (f) => /개인정보|PII|회원 목록|버킷|클라우드|대량|과다 노출|CWE-(359|732|213)/i.test(f.title + (f.cwe || '')) },
];

export function attackPaths(findings: Finding[]): AttackPath[] {
  const real = findings.filter((f) => f.confidence !== 'tentative' && f.severity !== 'info');
  const stages: AttackPath['stages'] = [];
  const used = new Set<string>();   // 한 발견은 한 단계에만(중복 배치 방지)
  for (const ph of PHASES) {
    const hit = real.filter((f) => ph.test(f) && !used.has(f.id)).sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0))[0];
    if (hit) { used.add(hit.id); const t = attackTechniques(hit)[0]; stages.push({ phase: ph.phase, finding: hit.title, technique: t ? `${t.id} ${t.name}` : undefined }); }
  }
  if (stages.length < 2) return [];
  const worst = real.sort((a, b) => sev(b.severity) - sev(a.severity))[0]?.severity ?? 'medium';
  const narrative = `공격자는 ${stages.map((s) => s.phase.split('(')[0]).join(' → ')} 순으로 연계해, "${stages[0]!.finding}"에서 시작하여 최종적으로 "${stages[stages.length - 1]!.finding}"까지 도달할 수 있습니다(분석 — 실제 실행 미수행).`;
  return [{ name: '대표 공격 경로(킬체인)', severity: worst, stages, narrative }];
}

// ── 재현 절차 생성(비파괴) ──
export function reproSteps(f: Finding): string[] {
  const steps: string[] = [];
  const ev = (f.evidence || '').split('\n')[0] || '';
  steps.push(`대상: ${f.target}`);
  if (/요청:\s*(GET|HEAD|OPTIONS)\s+(\S+)/.test(f.evidence || '')) steps.push(`요청 재현: ${(f.evidence!.match(/요청:\s*\S+\s+\S+/) || [])[0]}`);
  else steps.push(`1) ${f.target} 에 비파괴 GET 요청 전송`);
  steps.push(`2) 응답에서 관측: ${ev.slice(0, 120)}`);
  steps.push(`3) 판정 근거: ${f.title} (신뢰도 ${f.confidence || 'tentative'}${f.cwe ? `, ${f.cwe}` : ''})`);
  steps.push('※ 모든 절차는 비파괴(읽기전용)이며 데이터 변경·익스플로잇을 포함하지 않습니다.');
  return steps;
}

/** 발견 집합에 대한 종합 인텔리전스. 미확정(tentative)·정보성(info)은 일괄 제외해 수치 부풀림/불일치를 막는다. */
export function buildIntelligence(findings: Finding[], businessCriticality = 'high'): Intelligence {
  const real = findings.filter((f) => f.confidence !== 'tentative' && f.severity !== 'info');
  const attackMap = new Map<string, { id: string; name: string; tactic: string; count: number }>();
  for (const f of real) for (const t of attackTechniques(f)) {
    const e = attackMap.get(t.id) ?? { id: t.id, name: t.name, tactic: t.tactic, count: 0 };
    e.count++; attackMap.set(t.id, e);
  }
  const top = [...real].filter((f) => f.severity === 'critical' || f.severity === 'high').sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0)).slice(0, 5);
  return {
    attack: [...attackMap.values()].sort((a, b) => b.count - a.count),
    paths: attackPaths(real),
    loss: estimateLoss(real, businessCriticality),
    repro: top.map((f) => ({ title: f.title, steps: reproSteps(f) })),
  };
}

function won(n: number): string { return n >= 100_000_000 ? `약 ${(n / 100_000_000).toFixed(1)}억원` : n >= 10_000 ? `약 ${Math.round(n / 10_000).toLocaleString()}만원` : `${n.toLocaleString()}원`; }
function sev(s: Finding['severity']): number { return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s]; }
