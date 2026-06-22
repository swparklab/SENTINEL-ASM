/**
 * 리포트 엔진 (설계 §5.3).
 * 경영진 요약(Executive Summary) + 기술 상세(재현 절차·증거·조치 가이드) 를 생성하고,
 * 재점검 시 직전 점검 대비 변동 추이(delta)를 제공한다.
 * 웹 인터랙티브(JSON) + 마크다운/HTML 출력을 지원한다(PDF·DOCX 변환의 소스).
 */
import { repos } from '../../db/store.js';
import type { Finding, ScanJob } from '../../types.js';
import { aggregateRisk } from '../risk/scoring.js';
import { complianceSummary, categorySummary } from '../compliance/mapping.js';
import { buildIntelligence, type Intelligence } from './intelligence.js';

const METHODOLOGY = [
  'OWASP Top 10 (2021) 및 OWASP ASVS 검증 항목 기반 비파괴(non-destructive) 점검',
  'CWE 약점 분류 및 NVD/CISA KEV/EPSS 위협 인텔리전스 연계 우선순위 산정',
  '공격표면관리(ASM): 서브도메인·노출 포트·TLS·이메일/DNS 인증(SPF·DMARC·CAA)',
  '구성 점검: 보안 헤더·CORS·HTTP 메서드·쿠키·민감 경로(콘텐츠 검증 + soft-404 오탐 제거)',
  'SBOM 기반 알려진 취약점 대조 및 컴플라이언스 자동 증빙',
];

const COVERAGE = [
  'A01 접근통제 · A02 암호화 · A03 인젝션 · A05 보안설정 · A06 취약 컴포넌트 · A07 인증',
  '이메일 스푸핑 방지(SPF/DMARC/DKIM/CAA), 전송계층(TLS 버전·인증서)',
  'CORS·HTTP 메서드·보안 헤더·쿠키·정보 노출·민감 경로',
];

export interface ScanReport {
  jobId: string;
  asset: { id: string; value: string; criticality: string };
  depth: string;
  generatedAt: string;
  methodology: string[];
  coverage: string[];
  executive: {
    overallScore: number;
    band: string;
    severityCounts: Record<string, number>;
    topRisks: { title: string; target: string; riskScore: number; cve?: string; kev?: boolean }[];
    headline: string;
  };
  compliance: Record<string, { controls: string[]; findings: number }>;
  categories: { owasp: Record<string, number>; cwe: Record<string, number> };
  remediationRoadmap: { priority: string; window: string; items: { title: string; target: string; action: string }[] }[];
  technical: Finding[];
  delta?: ReportDelta;
  /** AI Pentest Report 인텔리전스 (MITRE ATT&CK·예상 피해(FAIR)·Attack Path·재현) */
  intelligence?: Intelligence;
}

export interface ReportDelta {
  comparedToJob: string;
  resolved: number;
  introduced: number;
  unchanged: number;
  scoreChange: number;
}

function findingKey(f: Finding): string {
  return `${f.module}:${f.title}:${f.target}`;
}

/** 직전 완료 점검과 비교한 delta 계산 (설계 §5.3 변동 추이). */
function computeDelta(job: ScanJob): ReportDelta | undefined {
  const prior = repos.scanJobs.list(job.tenantId)
    .filter((j) => j.assetId === job.assetId && j.id !== job.id && j.status === 'completed')
    .filter((j) => Date.parse(j.finishedAt ?? j.queuedAt) < Date.parse(job.finishedAt ?? job.queuedAt))
    .sort((a, b) => Date.parse(b.finishedAt ?? b.queuedAt) - Date.parse(a.finishedAt ?? a.queuedAt))[0];
  if (!prior) return undefined;

  const prevKeys = new Set(prior.findings.map(findingKey));
  const curKeys = new Set(job.findings.map(findingKey));
  const resolved = [...prevKeys].filter((k) => !curKeys.has(k)).length;
  const introduced = [...curKeys].filter((k) => !prevKeys.has(k)).length;
  const unchanged = [...curKeys].filter((k) => prevKeys.has(k)).length;
  return {
    comparedToJob: prior.id,
    resolved, introduced, unchanged,
    scoreChange: aggregateRisk(job.findings).score - aggregateRisk(prior.findings).score,
  };
}

export function buildReport(job: ScanJob): ScanReport {
  const asset = repos.assets.get(job.assetId);
  const agg = aggregateRisk(job.findings);
  const topRisks = job.findings.slice(0, 5).map((f) => ({
    title: f.title, target: f.target, riskScore: f.riskScore ?? 0, cve: f.cve, kev: f.kev,
  }));

  const crit = agg.counts.critical ?? 0;
  const high = agg.counts.high ?? 0;
  const headline = crit > 0
    ? `즉시 조치가 필요한 치명적 위험 ${crit}건이 식별되었습니다.`
    : high > 0
      ? `높은 위험 ${high}건에 대한 우선 조치가 권고됩니다.`
      : job.findings.length === 0
        ? '식별된 주요 위험이 없습니다. 정기 재점검을 권장합니다.'
        : '중·저위험 항목 위주로 개선 권고가 도출되었습니다.';

  return {
    jobId: job.id,
    asset: { id: asset?.id ?? job.assetId, value: asset?.value ?? '?', criticality: asset?.businessCriticality ?? '?' },
    depth: job.depth === 'deep' ? '심층(정밀·전수)' : '간단',
    generatedAt: new Date().toISOString(),
    methodology: METHODOLOGY,
    coverage: COVERAGE,
    executive: {
      overallScore: agg.score, band: agg.band, severityCounts: agg.counts, topRisks, headline,
    },
    compliance: complianceSummary(job.findings),
    categories: categorySummary(job.findings),
    remediationRoadmap: buildRoadmap(job.findings),
    technical: job.findings,
    delta: computeDelta(job),
    intelligence: buildIntelligence(job.findings, asset?.businessCriticality ?? 'high'),
  };
}

/** 심각도→처리 기한 기반 조치 로드맵 (경영진/실무 공통). */
function buildRoadmap(findings: Finding[]): ScanReport['remediationRoadmap'] {
  const tiers: { key: Finding['severity'][]; priority: string; window: string }[] = [
    { key: ['critical'], priority: 'P0 — 즉시', window: '24~72시간 내' },
    { key: ['high'], priority: 'P1 — 긴급', window: '1주 내' },
    { key: ['medium'], priority: 'P2 — 단기', window: '1개월 내' },
    { key: ['low', 'info'], priority: 'P3 — 계획', window: '분기 내' },
  ];
  return tiers.map((t) => ({
    priority: t.priority, window: t.window,
    items: findings.filter((f) => t.key.includes(f.severity)).map((f) => ({
      title: f.title, target: f.target, action: f.remediation ?? '조치 검토',
    })),
  })).filter((t) => t.items.length);
}

function wonText(n: number): string {
  if (n >= 100_000_000) return `약 ${(n / 100_000_000).toFixed(1)}억원`;
  if (n >= 10_000) return `약 ${Math.round(n / 10_000).toLocaleString()}만원`;
  return `${(n || 0).toLocaleString()}원`;
}

/** 마크다운 리포트 (PDF/DOCX 변환 소스). */
export function reportToMarkdown(r: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# SENTINEL-ASM 보안 점검 보고서`);
  lines.push(`- 대상: **${r.asset.value}** (자산 중요도: ${r.asset.criticality})`);
  lines.push(`- 작업 ID: ${r.jobId}`);
  lines.push(`- 생성 일시: ${r.generatedAt}`);
  lines.push(`- 점검 깊이: **${r.depth}**`);
  lines.push(`- 점검 방식: 비파괴(non-destructive) · 사전 권한 검증 기반\n`);

  lines.push(`## 1. 경영진 요약 (Executive Summary)`);
  lines.push(`- 종합 위험도: **${r.executive.overallScore}/100 (${r.executive.band.toUpperCase()})**`);
  lines.push(`- ${r.executive.headline}`);
  const c = r.executive.severityCounts;
  lines.push(`- 심각도 분포: 치명적 ${c.critical ?? 0} / 심각 ${c.high ?? 0} / 주의 ${c.medium ?? 0} / 경미 ${c.low ?? 0} / 정보 ${c.info ?? 0}`);
  if (r.delta) {
    lines.push(`- 직전 점검 대비: 해소 ${r.delta.resolved} · 신규 ${r.delta.introduced} · 유지 ${r.delta.unchanged} (점수 변화 ${r.delta.scoreChange >= 0 ? '+' : ''}${r.delta.scoreChange})`);
  }

  lines.push(`\n## 2. 점검 방법론 및 범위 (Methodology & Scope)`);
  r.methodology.forEach((m) => lines.push(`- ${m}`));
  lines.push(`- 점검 범위: ${r.coverage.join(' · ')}`);

  lines.push(`\n## 3. 표준 커버리지 (OWASP Top 10 / CWE)`);
  const ow = Object.entries(r.categories.owasp);
  if (ow.length) ow.forEach(([k, n]) => lines.push(`- ${k} — ${n}건`));
  else lines.push('- 해당 없음');
  const cwe = Object.entries(r.categories.cwe);
  if (cwe.length) lines.push(`- CWE: ${cwe.map(([k, n]) => `${k}(${n})`).join(', ')}`);

  lines.push(`\n## 4. 컴플라이언스 매핑`);
  for (const [fw, v] of Object.entries(r.compliance)) {
    lines.push(`- **${fw}**: 관련 통제 ${v.controls.length}개 — ${v.controls.join(', ')}`);
  }
  if (!Object.keys(r.compliance).length) lines.push(`- 매핑된 통제 항목 없음`);

  lines.push(`\n## 5. 조치 로드맵 (Remediation Roadmap)`);
  if (r.remediationRoadmap.length) {
    for (const t of r.remediationRoadmap) {
      lines.push(`\n### ${t.priority} (${t.window}) — ${t.items.length}건`);
      t.items.forEach((it) => lines.push(`- ${it.title} → ${it.action}`));
    }
  } else lines.push('- 조치 대상 없음');

  if (r.intelligence) {
    const it = r.intelligence;
    lines.push(`\n## 6. 공격 시나리오 인텔리전스 (AI Pentest)`);
    if (it.pii && it.pii.endpoints > 0) {
      lines.push(`\n### 6.0 유출 영향 정량화 (개인정보 노출 규모)`);
      lines.push(`- 노출 규모: **${it.pii.surfaceOnly ? '스키마 PII 필드 노출(실제 레코드 미수집)' : it.pii.enumerable ? '전체 사용자 열거 가능' : `최대 ${it.pii.records.toLocaleString()}건`}** (영향 엔드포인트 ${it.pii.endpoints}개)`);
      lines.push(`- 노출 PII 유형: ${it.pii.categories.join(' · ') || '민감필드'}${it.pii.sensitive ? ' · ⚠ 고위험 민감정보(주민·카드 등) 포함' : ''}`);
      if (!it.pii.surfaceOnly) lines.push(`- 추정 피해 인원: ${it.pii.affectedEstimate.toLocaleString()}명${it.pii.enumerable ? '+ (순차 열거 시 전체 사용자)' : ''}`);
    }
    if (it.loss && it.loss.likely > 0) {
      lines.push(`\n### 6.1 예상 피해금액 (FAIR 기반 추정 · 참고용)`);
      lines.push(`- 추정 손실: **${wonText(it.loss.likely)}** (레인지 ${wonText(it.loss.min)} ~ ${wonText(it.loss.max)})`);
      it.loss.breakdown.forEach((b) => lines.push(`- ${b}`));
      lines.push(`- 산정 근거: ${it.loss.basis}`);
    }
    if (it.paths.length) {
      lines.push(`\n### 6.2 공격 경로 (Attack Path · 킬체인 분석)`);
      for (const p of it.paths) {
        lines.push(`- **${p.name}** [${p.severity.toUpperCase()}]: ${p.stages.map((s) => s.phase.split('(')[0] + (s.technique ? `(${s.technique.split(' ')[0]})` : '')).join(' → ')}`);
        lines.push(`  - ${p.narrative}`);
      }
    }
    if (it.attack.length) {
      lines.push(`\n### 6.3 MITRE ATT&CK 기법 매핑`);
      it.attack.forEach((a) => lines.push(`- ${a.id} ${a.name} (${a.tactic})${a.count > 1 ? ` ×${a.count}` : ''}`));
    }
    if (it.repro.length) {
      lines.push(`\n### 6.4 재현 절차 (비파괴)`);
      it.repro.forEach((rp) => { lines.push(`\n**${rp.title}**`); rp.steps.forEach((st) => lines.push(`- ${st}`)); });
    }
  }

  lines.push(`\n## 7. 기술 상세 (Technical Findings)`);
  r.technical.forEach((f, i) => {
    lines.push(`\n### ${i + 1}. [${(f.severity).toUpperCase()} · 위험 ${f.riskScore ?? 0}] ${f.title}`);
    lines.push(`- 대상: ${f.target}`);
    const cls = [f.owasp, f.cwe].filter(Boolean).join(' · ');
    if (cls) lines.push(`- 분류: ${cls}${f.confidence ? ` · 신뢰도 ${f.confidence}` : ''}`);
    if (f.cve) lines.push(`- CVE: ${f.cve}${f.kev ? ' (CISA KEV 등재)' : ''}${typeof f.epss === 'number' ? ` · EPSS ${(f.epss * 100).toFixed(1)}%` : ''}${f.cvss != null ? ` · CVSS ${f.cvss}` : ''}`);
    lines.push(`- 설명: ${f.description}`);
    if (f.evidence) lines.push(`- 증거:\n\`\`\`\n${f.evidence}\n\`\`\``);
    if (f.remediation) lines.push(`- 조치: ${f.remediation}`);
    if (f.compliance?.length) lines.push(`- 컴플라이언스: ${f.compliance.map((m) => `${m.framework} ${m.control}`).join('; ')}`);
    if (f.references?.length) lines.push(`- 참고: ${f.references.join(' , ')}`);
  });
  if (!r.technical.length) lines.push(`- 발견된 항목이 없습니다.`);

  lines.push(`\n---`);
  lines.push(`_본 보고서는 SENTINEL-ASM 이 권한이 검증된 자산에 한해 비파괴 점검으로 생성했습니다._`);
  return lines.join('\n');
}

// ───────────────────────── 인쇄용(PDF) HTML 리포트 ─────────────────────────
const SEV_META: Record<string, [string, string, string]> = {
  critical: ['치명적', '#dc2626', '#fde8e8'],
  high: ['심각', '#ea580c', '#fde5d8'],
  medium: ['주의', '#a16207', '#fbf2d4'],
  low: ['경미', '#16a34a', '#e3f5e8'],
  info: ['정보', '#2563eb', '#eef4ff'],
};
function esc(s: unknown): string {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function bandColor(band: string): string {
  return (SEV_META[band] ?? SEV_META.info!)[1];
}

/** A4 인쇄 최적화 전문 보고서 (브라우저 인쇄 → PDF 저장). */
export function reportToHtml(r: ScanReport): string {
  const c = r.executive.severityCounts;
  const total = (['critical', 'high', 'medium', 'low', 'info'] as const).reduce((s, k) => s + (c[k] ?? 0), 0) || 1;
  const distBar = (['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => {
    const n = c[k] ?? 0; const w = (n / total) * 100;
    return n ? `<span style="display:inline-block;width:${w}%;background:${SEV_META[k]![1]}" title="${SEV_META[k]![0]} ${n}"></span>` : '';
  }).join('');
  const dateStr = new Date(r.generatedAt).toLocaleString('ko-KR', { hour12: false });

  const findingsHtml = r.technical.map((f, i) => {
    const m = SEV_META[f.severity] ?? SEV_META.info!;
    const meta = [
      f.owasp ? esc(f.owasp) : '', f.cwe ? esc(f.cwe) : '',
      f.cvss != null ? `CVSS ${f.cvss}` : '', typeof f.epss === 'number' ? `EPSS ${(f.epss * 100).toFixed(0)}%` : '',
      f.kev ? 'CISA KEV' : '', f.confidence ? `신뢰도 ${f.confidence}` : '',
    ].filter(Boolean).map((x) => `<span class="tag">${x}</span>`).join('');
    return `<div class="finding">
      <div class="f-head"><span class="sev" style="background:${m[2]};color:${m[1]}">${m[0]}</span>
        <span class="f-no">#${i + 1}</span><span class="f-title">${esc(f.title)}</span><span class="f-risk">위험 ${f.riskScore ?? 0}/100</span></div>
      <div class="tags">${meta}</div>
      <div class="f-row"><b>대상</b> <span class="mono">${esc(f.target)}</span></div>
      <div class="f-row"><b>설명</b> ${esc(f.description)}</div>
      ${f.evidence ? `<div class="f-row"><b>증거</b> <span class="mono">${esc(f.evidence)}</span></div>` : ''}
      ${f.remediation ? `<div class="f-row remedy"><b>조치</b> ${esc(f.remediation)}</div>` : ''}
      ${f.compliance?.length ? `<div class="f-row small"><b>컴플라이언스</b> ${esc(f.compliance.map((x) => `${x.framework} ${x.control}`).join('; '))}</div>` : ''}
      ${f.references?.length ? `<div class="f-row small"><b>참고</b> ${f.references.map((u) => `<a href="${esc(u)}">${esc(u)}</a>`).join(' · ')}</div>` : ''}
    </div>`;
  }).join('');

  const owaspRows = Object.entries(r.categories.owasp).map(([k, n]) => `<tr><td>${esc(k)}</td><td>${n}건</td></tr>`).join('') || '<tr><td colspan="2">해당 없음</td></tr>';
  const compRows = Object.entries(r.compliance).map(([fw, v]) => `<tr><td><b>${esc(fw)}</b></td><td>${esc(v.controls.join(', '))}</td></tr>`).join('') || '<tr><td colspan="2">매핑 없음</td></tr>';
  const roadmapRows = r.remediationRoadmap.map((t) => `<tr><td><b>${esc(t.priority)}</b></td><td>${esc(t.window)}</td><td>${t.items.length}건</td><td>${esc(t.items.slice(0, 3).map((x) => x.title).join(' / '))}${t.items.length > 3 ? ' …' : ''}</td></tr>`).join('') || '<tr><td colspan="4">조치 대상 없음</td></tr>';
  const methodItems = r.methodology.map((m) => `<li>${esc(m)}</li>`).join('');

  const it = r.intelligence;
  const intelHtml = !it ? '' : `
    <div class="page-break"></div>
    <h2>6. 공격 시나리오 인텔리전스 (AI Pentest)</h2>
    ${it.pii && it.pii.endpoints > 0 ? `
    <div class="finding" style="border-left:3px solid #b91c1c">
      <div class="f-head"><span class="f-title">유출 영향 정량화 (개인정보 노출 규모)</span>
        <span class="f-risk" style="color:#b91c1c;font-weight:700">${it.pii.surfaceOnly ? '스키마 PII 필드 노출' : it.pii.enumerable ? '전체 사용자 열거 가능' : `최대 ${it.pii.records.toLocaleString()}건`}</span></div>
      <div class="f-row small">노출 PII 유형: ${esc(it.pii.categories.join(' · ') || '민감필드')}${it.pii.sensitive ? ' · ⚠ 고위험 민감정보(주민·카드 등) 포함' : ''}</div>
      <div class="f-row small">영향 엔드포인트 ${it.pii.endpoints}개 · ${it.pii.surfaceOnly ? '실제 레코드 미수집(스키마 표면 확인)' : `추정 피해 인원 ${it.pii.affectedEstimate.toLocaleString()}명${it.pii.enumerable ? '+ (전체 사용자 확대 가능)' : ''}`}</div>
    </div>` : ''}
    ${it.loss && it.loss.likely > 0 ? `
    <div class="finding" style="border-left:3px solid #dc2626">
      <div class="f-head"><span class="f-title">예상 피해금액 (FAIR 기반 추정 · 참고용)</span>
        <span class="f-risk" style="color:#dc2626;font-weight:700">${esc(wonText(it.loss.likely))}</span></div>
      <div class="f-row small">레인지 ${esc(wonText(it.loss.min))} ~ ${esc(wonText(it.loss.max))}${it.loss.regulatory > 0 ? ` · 규제 과징금 추정 ${esc(wonText(it.loss.regulatory))}` : ''}</div>
      ${it.loss.breakdown.map((b) => `<div class="f-row small">· ${esc(b)}</div>`).join('')}
      <div class="f-row small" style="color:#6b7484">${esc(it.loss.basis)}</div>
    </div>` : ''}
    ${it.paths.map((p) => `<div class="finding">
      <div class="f-head"><span class="sev" style="background:${(SEV_META[p.severity] ?? SEV_META.info!)[2]};color:${(SEV_META[p.severity] ?? SEV_META.info!)[1]}">${(SEV_META[p.severity] ?? SEV_META.info!)[0]}</span>
        <span class="f-title">${esc(p.name)}</span></div>
      <div class="f-row"><span class="mono">${p.stages.map((s) => esc(s.phase.split('(')[0]) + (s.technique ? ` <span class="tag">${esc(s.technique)}</span>` : '')).join(' → ')}</span></div>
      <div class="f-row small">${esc(p.narrative)}</div>
    </div>`).join('')}
    ${it.attack.length ? `<h3 style="font-size:13px;margin:12px 0 4px">MITRE ATT&CK 기법 매핑</h3>
    <div class="tags">${it.attack.map((a) => `<span class="tag" title="${esc(a.tactic)}">${esc(a.id)} ${esc(a.name)}${a.count > 1 ? ` ×${a.count}` : ''}</span>`).join('')}</div>` : ''}
    ${it.repro.length ? `<h3 style="font-size:13px;margin:12px 0 4px">재현 절차 (비파괴)</h3>
    ${it.repro.map((rp) => `<div class="finding"><div class="f-head"><span class="f-title">${esc(rp.title)}</span></div>
      <ol style="margin:4px 0;padding-left:20px;font-size:11px">${rp.steps.map((st) => `<li>${esc(st)}</li>`).join('')}</ol></div>`).join('')}` : ''}`;

  return `<!DOCTYPE html><html lang="ko"><head><meta charset="UTF-8"/>
<title>SENTINEL-ASM 보안 점검 보고서 — ${esc(r.asset.value)}</title>
<style>
  @page { size: A4; margin: 16mm 15mm; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system,"Segoe UI","Malgun Gothic",system-ui,sans-serif; color:#1a2233; font-size:12px; line-height:1.6; margin:0; }
  .toolbar { position:sticky; top:0; background:#11192b; color:#fff; padding:10px 16px; display:flex; gap:12px; align-items:center; }
  .toolbar button { background:#2563eb; color:#fff; border:none; padding:8px 16px; border-radius:8px; font-weight:600; cursor:pointer; }
  .toolbar .sp { flex:1; }
  .wrap { max-width:820px; margin:0 auto; padding:24px; }
  h1,h2,h3 { color:#11192b; }
  h2 { font-size:16px; border-bottom:2px solid #2563eb; padding-bottom:6px; margin:26px 0 12px; }
  .cover { text-align:center; padding:80px 0 50px; border-bottom:1px solid #e6e8ee; }
  .logo { width:72px; height:72px; border-radius:20px; background:linear-gradient(135deg,#2563eb,#4f46e5); display:inline-grid; place-items:center; font-size:38px; color:#fff; }
  .cover h1 { font-size:30px; margin:18px 0 4px; letter-spacing:-1px; }
  .cover .sub { color:#6b7484; font-size:13px; }
  .cover .target { font-size:18px; font-weight:700; margin-top:18px; }
  .classif { display:inline-block; margin-top:14px; padding:3px 12px; border:1px solid #dc2626; color:#dc2626; border-radius:999px; font-size:11px; font-weight:700; }
  .scorebox { display:inline-block; margin-top:22px; padding:16px 28px; border-radius:14px; background:#f6f8fb; }
  .scorebox .n { font-size:40px; font-weight:800; }
  .meta-tbl { width:100%; margin-top:22px; font-size:12px; }
  .meta-tbl td { padding:3px 6px; }
  .meta-tbl td:first-child { color:#6b7484; width:120px; }
  .dist { height:14px; border-radius:999px; overflow:hidden; background:#eef0f4; display:flex; margin:8px 0; }
  .legend span { display:inline-block; margin-right:10px; font-size:11px; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:2px; vertical-align:middle; margin-right:3px; }
  table { width:100%; border-collapse:collapse; font-size:11.5px; margin-top:6px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid #e6e8ee; vertical-align:top; }
  th { background:#f6f8fb; color:#6b7484; font-size:10.5px; text-transform:uppercase; }
  ul { margin:6px 0; padding-left:18px; }
  .finding { border:1px solid #e6e8ee; border-radius:10px; padding:12px 14px; margin:10px 0; page-break-inside:avoid; }
  .f-head { display:flex; align-items:center; gap:8px; }
  .sev { padding:2px 9px; border-radius:999px; font-size:10.5px; font-weight:700; }
  .f-no { color:#6b7484; font-size:11px; } .f-title { font-weight:700; flex:1; } .f-risk { color:#6b7484; font-size:11px; }
  .tags { margin:6px 0; } .tag { display:inline-block; background:#f0f2f6; border:1px solid #e6e8ee; border-radius:999px; padding:1px 8px; font-size:10.5px; color:#444; margin:2px 4px 0 0; }
  .f-row { margin:3px 0; } .f-row b { color:#6b7484; font-weight:600; display:inline-block; min-width:64px; }
  .f-row.remedy { color:#1d4ed8; } .f-row.small { font-size:10.5px; color:#6b7484; } .f-row.small a { color:#2563eb; }
  .mono { font-family:ui-monospace,Consolas,monospace; font-size:11px; word-break:break-all; }
  .footer { margin-top:30px; padding-top:12px; border-top:1px solid #e6e8ee; color:#6b7484; font-size:10.5px; text-align:center; }
  @media print { .toolbar { display:none; } .page-break { page-break-before:always; } body { font-size:11px; } }
</style></head>
<body>
  <div class="toolbar"><b>SENTINEL-ASM 보고서</b><span class="sp"></span>
    <span style="font-size:12px;opacity:.8">Ctrl+P → 대상을 'PDF로 저장' 선택</span>
    <button onclick="window.print()">🖨 PDF로 저장 / 인쇄</button></div>
  <div class="wrap">
    <div class="cover">
      <div class="logo">🛡</div>
      <h1>보안 점검 보고서</h1>
      <div class="sub">SENTINEL-ASM · 공격표면관리 · 취약점 점검 · 컴플라이언스</div>
      <div class="target">${esc(r.asset.value)}</div>
      <div class="classif">CONFIDENTIAL · 대외비</div>
      <div><div class="scorebox"><div class="n" style="color:${bandColor(r.executive.band)}">${r.executive.overallScore}<span style="font-size:16px;color:#6b7484">/100</span></div>
        <div style="color:${bandColor(r.executive.band)};font-weight:700">${(SEV_META[r.executive.band] ?? SEV_META.info!)[0]} 등급</div></div></div>
      <table class="meta-tbl" style="max-width:420px;margin:22px auto 0">
        <tr><td>대상 자산</td><td>${esc(r.asset.value)} (중요도 ${esc(r.asset.criticality)})</td></tr>
        <tr><td>작업 ID</td><td class="mono">${esc(r.jobId)}</td></tr>
        <tr><td>점검 깊이</td><td>${esc(r.depth)}</td></tr>
        <tr><td>생성 일시</td><td>${esc(dateStr)}</td></tr>
        <tr><td>점검 방식</td><td>비파괴(non-destructive) · 사전 권한 검증 기반</td></tr>
      </table>
    </div>

    <h2>1. 경영진 요약</h2>
    <p><b>${esc(r.executive.headline)}</b></p>
    <div class="dist">${distBar}</div>
    <div class="legend">
      ${(['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => `<span><i class="dot" style="background:${SEV_META[k]![1]}"></i>${SEV_META[k]![0]} ${c[k] ?? 0}</span>`).join('')}
    </div>
    ${r.delta ? `<p class="small">직전 점검 대비: 해소 ${r.delta.resolved} · 신규 ${r.delta.introduced} · 유지 ${r.delta.unchanged} (점수 변화 ${r.delta.scoreChange >= 0 ? '+' : ''}${r.delta.scoreChange})</p>` : ''}

    <h2>2. 점검 방법론 및 범위</h2>
    <ul>${methodItems}</ul>
    <p class="small" style="color:#6b7484">범위: ${esc(r.coverage.join(' · '))}</p>

    <h2>3. 표준 커버리지 (OWASP Top 10)</h2>
    <table><thead><tr><th>카테고리</th><th>발견</th></tr></thead><tbody>${owaspRows}</tbody></table>
    ${Object.keys(r.categories.cwe).length ? `<p class="small">CWE: ${esc(Object.entries(r.categories.cwe).map(([k, n]) => `${k}(${n})`).join(', '))}</p>` : ''}

    <h2>4. 컴플라이언스 매핑</h2>
    <table><thead><tr><th>프레임워크</th><th>관련 통제</th></tr></thead><tbody>${compRows}</tbody></table>

    <h2>5. 조치 로드맵</h2>
    <table><thead><tr><th>우선순위</th><th>기한</th><th>건수</th><th>대표 항목</th></tr></thead><tbody>${roadmapRows}</tbody></table>
    ${intelHtml}

    <div class="page-break"></div>
    <h2>7. 기술 상세 (위험 우선순위 순)</h2>
    ${findingsHtml || '<p>발견된 항목이 없습니다.</p>'}

    <div class="footer">SENTINEL-ASM 자동 생성 보고서 · 권한이 검증된 자산에 한해 비파괴 점검으로 작성 · ${esc(dateStr)}</div>
  </div>
</body></html>`;
}
