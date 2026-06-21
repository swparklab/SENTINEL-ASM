import React, { useState, useEffect, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import htm from 'htm';

const html = htm.bind(React.createElement);

// ───────────────────────── API 클라이언트 ─────────────────────────
const tokenStore = {
  get: () => localStorage.getItem('sentinel_token'),
  set: (t) => localStorage.setItem('sentinel_token', t),
  clear: () => localStorage.removeItem('sentinel_token'),
};

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  const t = tokenStore.get();
  if (t) headers['authorization'] = `Bearer ${t}`;
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let json; try { json = await res.json(); } catch { json = null; }
  if (res.status === 401) { tokenStore.clear(); location.hash = '#/login'; }
  return { status: res.status, ok: res.ok, json };
}

// ───────────────────────── 공용 UI ─────────────────────────
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_KO = { critical: '치명적', high: '심각', medium: '주의', low: '경미', info: '정보' };
const SEV_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a', info: '#2563eb' };
const fmt = (iso) => iso ? new Date(iso).toLocaleString('ko-KR', { hour12: false }) : '-';
const Sev = ({ s }) => html`<span class=${`badge sev-${s}`}>${SEV_KO[s] || s.toUpperCase()}</span>`;

// ───────── 용어 사전 (비전공자용 클릭 팝업) ─────────
const GLOSSARY = {
  CVE: { title: 'CVE (공개 취약점 번호)', desc: '전 세계 보안 전문가들이 공식 등록한 소프트웨어 결함 목록입니다. "CVE-2021-44228(Log4Shell)"처럼 번호로 관리됩니다. CVE 번호가 있다는 건 이미 해커들도 이 취약점을 알고 있다는 뜻입니다.' },
  CVSS: { title: 'CVSS (취약점 위험 점수)', desc: '취약점의 위험도를 0~10점으로 표시한 국제 표준 점수입니다. 7점 이상이면 심각, 9점 이상이면 치명적으로 분류됩니다.' },
  EPSS: { title: 'EPSS (실제 악용 가능성)', desc: '이 취약점이 향후 30일 안에 실제 사이버 공격에 사용될 확률입니다. 80%라면 10개 중 8개 공격에서 이 방법을 쓴다는 뜻입니다.' },
  KEV: { title: 'KEV (실제 악용 확인됨)', desc: '미국 사이버보안청(CISA)이 "이 취약점은 지금 실제 공격에 쓰이고 있다"고 공식 확인한 목록입니다. KEV 표시가 있으면 즉시 조치가 필요합니다.' },
  OWASP: { title: 'OWASP Top 10', desc: '전 세계 웹 보안 전문가 단체(OWASP)가 선정한 가장 위험한 웹 보안 문제 10가지입니다. 국제 보안 감사의 기준으로 사용됩니다.' },
  CWE: { title: 'CWE (소프트웨어 결함 분류)', desc: '코드에 생길 수 있는 보안 결함의 종류를 분류한 국제 표준 목록입니다. "CWE-89(SQL 인젝션)"처럼 번호와 이름으로 관리됩니다.' },
  TLS: { title: 'TLS/HTTPS (암호화 통신)', desc: '인터넷에서 데이터를 암호화해서 전송하는 기술입니다. 브라우저 주소창의 자물쇠(🔒)가 이것입니다. TLS 1.0/1.1은 구버전으로 보안 취약, 1.2 이상을 써야 합니다.' },
  HSTS: { title: 'HSTS (HTTPS 강제 설정)', desc: '브라우저에게 "이 사이트는 반드시 HTTPS로만 접속하라"고 알려주는 설정입니다. 없으면 평문 HTTP로 연결되어 도청 위험이 있습니다.' },
  CSP: { title: 'CSP (악성 스크립트 차단)', desc: '웹사이트에서 실행할 수 있는 스크립트의 출처를 제한하는 보안 설정입니다. 이게 없으면 해커가 악성 코드를 삽입해도 브라우저가 막지 못합니다.' },
  CORS: { title: 'CORS (다른 사이트 접근 제어)', desc: '다른 웹사이트에서 내 사이트 데이터에 접근하는 것을 제어하는 설정입니다. 잘못 설정하면 공격자 사이트에서 로그인된 내 계정으로 데이터를 빼갈 수 있습니다.' },
  SPF: { title: 'SPF (이메일 발신자 인증)', desc: '내 도메인(예: naver.com)에서 보낼 수 있는 메일 서버를 지정하는 설정입니다. 없으면 누구나 naver.com 주소로 위조 이메일을 보낼 수 있습니다.' },
  DMARC: { title: 'DMARC (이메일 위조 차단)', desc: 'SPF·DKIM 인증에 실패한 이메일을 어떻게 처리할지 정하는 정책입니다. "p=reject"면 위조 이메일을 완전히 차단합니다.' },
  DKIM: { title: 'DKIM (이메일 서명)', desc: '이메일에 디지털 서명을 달아 내용이 전송 중 변조되지 않았음을 증명하는 기술입니다.' },
  ASM: { title: 'ASM (외부 공격표면 관리)', desc: '외부에서 내 시스템에 접근 가능한 모든 진입점(서브도메인, 열린 포트, 공개 파일 등)을 찾아 목록화하는 과정입니다.' },
  DAST: { title: 'DAST (동적 웹 취약점 점검)', desc: '실제로 실행 중인 웹사이트에 안전한 테스트 요청을 보내 취약점을 찾는 방법입니다. 마치 윤리적 해커처럼 사이트를 두드려보는 것입니다.' },
  ACCESS: { title: 'ACCESS (접근통제·자동수집 차단 점검)', desc: '로그인 없이 관리자 페이지가 열리는지, 주소창의 경로·번호를 바꿔치기해 남의 데이터·기능에 접근되는지(허가되지 않은 경로 필터링·우회), AI 봇의 자동 데이터 수집이 제대로 차단되는지를 점검합니다. "수작업 해킹"에 대한 방어 상태를 확인합니다.' },
  SAST: { title: 'SAST (소스코드 정적 분석)', desc: '소스 코드를 실행하지 않고 분석해서 보안 결함(SQL인젝션, 하드코딩된 비밀번호 등)을 찾는 방법입니다.' },
  SBOM: { title: 'SBOM (소프트웨어 부품 목록)', desc: '내 소프트웨어가 사용하는 외부 라이브러리·패키지 목록입니다. 어느 부품에 취약점이 있는지 파악하기 위해 필요합니다.' },
  ISMS: { title: 'ISMS-P (정보보호 관리체계)', desc: '한국 정보보호 인증 기준입니다. 기업이 정보를 안전하게 관리하고 있는지 평가하는 국내 표준입니다.' },
  PCI: { title: 'PCI-DSS (카드 결제 보안)', desc: '신용카드 결제를 처리하는 모든 기업이 지켜야 하는 국제 보안 기준입니다.' },
  NIST: { title: 'NIST CSF (미국 국립 보안 프레임워크)', desc: '미국 국립표준기술연구소가 만든 사이버보안 관리 프레임워크입니다. 전 세계 기업이 보안 수준을 평가할 때 참고합니다.' },
};

function GlossaryTag({ term, children }) {
  const [open, setOpen] = useState(false);
  const info = GLOSSARY[term];
  if (!info) return html`<span>${children || term}</span>`;
  return html`
    <span style=${{ position: 'relative', display: 'inline-block' }}>
      <span class="glossary-tag" onClick=${(e) => { e.stopPropagation(); setOpen(!open); }}>
        ${children || term} <span class="glossary-q">?</span>
      </span>
      ${open && html`<div class="glossary-pop" onClick=${(e) => e.stopPropagation()}>
        <div class="glossary-title">${info.title}</div>
        <div class="glossary-desc">${info.desc}</div>
        <button class="glossary-close" onClick=${() => setOpen(false)}>닫기 ✕</button>
      </div>`}
    </span>`;
}

// ───────── 온보딩 가이드 (처음 사용자용) ─────────
function OnboardingBanner({ onDismiss }) {
  return html`
    <div class="onboard">
      <div class="onboard-header">
        <div>
          <div class="onboard-title">👋 처음 오셨나요? 3단계로 시작하세요</div>
          <div class="onboard-sub">보안 전문가가 아니어도 괜찮습니다 — 입력만 하면 시스템이 알아서 분석합니다</div>
        </div>
        <button class="onboard-close" onClick=${onDismiss}>✕</button>
      </div>
      <div class="onboard-steps">
        <div class="onboard-step">
          <div class="onboard-num">1</div>
          <div>
            <div class="onboard-step-title">🌐 도메인 입력</div>
            <div class="onboard-step-desc">내 웹사이트 주소(예: mycompany.com)를 넣으면 외부에서 보이는 보안 문제를 찾아드립니다</div>
          </div>
        </div>
        <div class="onboard-step">
          <div class="onboard-num">2</div>
          <div>
            <div class="onboard-step-title">📂 소프트웨어 분석</div>
            <div class="onboard-step-desc">개발팀에서 package.json, requirements.txt 파일을 받아 업로드하면 알려진 보안 취약점을 찾습니다</div>
          </div>
        </div>
        <div class="onboard-step">
          <div class="onboard-num">3</div>
          <div>
            <div class="onboard-step-title">🤖 AI가 수정</div>
            <div class="onboard-step-desc">결과 리포트를 AI 개발 도구(Cursor 등)에 붙여넣으면 자동으로 보안 코드를 수정합니다</div>
          </div>
        </div>
      </div>
      <div class="onboard-tip">💡 <b>지금 바로:</b> 상단 검색창에 도메인을 넣고 "점검 시작"을 누르세요!</div>
    </div>`;
}

// ───────── 결과 액션 카드 (비전공자용 "그래서 뭘 해야 하나?") ─────────
function ActionCard({ findings, onOpenReport }) {
  if (!findings?.length) return null;
  const crit = findings.filter(f => f.severity === 'critical');
  const high = findings.filter(f => f.severity === 'high');
  const med  = findings.filter(f => f.severity === 'medium');
  const hasUrgent = crit.length > 0 || high.length > 0;

  return html`<div class="action-card ${hasUrgent ? 'urgent' : 'ok'}">
    <div class="action-card-title">
      ${hasUrgent ? '🚨 지금 해야 할 일이 있습니다' : '✅ 심각한 문제는 없습니다'}
    </div>
    <div class="action-steps">
      ${crit.length > 0 && html`<div class="action-step crit">
        <span class="action-step-num">즉시</span>
        <div><b>치명적 문제 ${crit.length}건</b> — 오늘 안에 해결하세요
          <div class="action-step-list">${crit.slice(0,3).map(f=>html`<div key=${f.id}>• ${f.title.slice(0,55)}</div>`)}</div>
        </div>
      </div>`}
      ${high.length > 0 && html`<div class="action-step high">
        <span class="action-step-num">1주일</span>
        <div><b>심각 문제 ${high.length}건</b> — 이번 주 안에 개발팀에 전달하세요
          <div class="action-step-list">${high.slice(0,3).map(f=>html`<div key=${f.id}>• ${f.title.slice(0,55)}</div>`)}</div>
        </div>
      </div>`}
      ${med.length > 0 && html`<div class="action-step med">
        <span class="action-step-num">1개월</span>
        <div><b>주의 문제 ${med.length}건</b> — 다음 업데이트 때 반영하세요</div>
      </div>`}
      <div class="action-step next">
        <span class="action-step-num">다음</span>
        <div>
          <b>AI 자동 수정하기</b> — "AI 수정 명령서" 버튼을 눌러 파일을 다운받고,
          Cursor나 GitHub Copilot에 붙여넣으면 개발 AI가 코드를 직접 수정합니다
        </div>
      </div>
    </div>
  </div>`;
}
const Status = ({ s }) => html`<span class=${`st-${s}`}>${s}</span>`;

function useToast() {
  const [toast, setToast] = useState(null);
  const show = useCallback((msg, err = false) => {
    setToast({ msg, err });
    setTimeout(() => setToast(null), 3500);
  }, []);
  const node = toast ? html`<div class=${`toast ${toast.err ? 'err' : ''}`}>${toast.msg}</div>` : null;
  return [node, show];
}

// ───────────────────────── 로그인 ─────────────────────────
function Login({ onLogin }) {
  const [email, setEmail] = useState('admin@hanbit.example');
  const [password, setPassword] = useState('sentinel!admin');
  const [err, setErr] = useState('');
  const submit = async (e) => {
    e.preventDefault();
    const r = await api('POST', '/api/auth/login', { email, password });
    if (r.ok) { tokenStore.set(r.json.token); onLogin(r.json.user); location.hash = '#/'; }
    else setErr(r.json?.message || '로그인 실패');
  };
  const quick = (em, pw) => { setEmail(em); setPassword(pw); };
  return html`
    <div class="login-wrap">
      <form class="login-card" onSubmit=${submit}>
        <h1>🛡 SENTINEL-ASM</h1>
        <div class="sub">권한 검증 기반 공격표면관리 · 취약점 점검 · 컴플라이언스</div>
        <label>이메일</label>
        <input value=${email} onChange=${(e) => setEmail(e.target.value)} />
        <label>비밀번호</label>
        <input type="password" value=${password} onChange=${(e) => setPassword(e.target.value)} />
        ${err && html`<div class="no" style=${{ marginTop: 10 }}>${err}</div>`}
        <button class="primary" style=${{ width: '100%', marginTop: 18 }}>로그인</button>
        <div class="accounts">
          데모 계정 (클릭 시 자동 입력):<br/>
          <code onClick=${() => quick('admin@hanbit.example', 'sentinel!admin')}>admin@hanbit.example</code> · admin<br/>
          <code onClick=${() => quick('scanner@hanbit.example', 'sentinel!scan')}>scanner@hanbit.example</code> · scanner<br/>
          <code onClick=${() => quick('auditor@hanbit.example', 'sentinel!audit')}>auditor@hanbit.example</code> · auditor<br/>
          <code onClick=${() => quick('viewer@hanbit.example', 'sentinel!view')}>viewer@hanbit.example</code> · viewer
        </div>
      </form>
    </div>`;
}

// ───────────────────────── 대시보드 ─────────────────────────
function Dashboard() {
  const [d, setD] = useState(null);
  useEffect(() => { api('GET', '/api/dashboard').then((r) => setD(r.json)); }, []);
  if (!d) return html`<div class="muted">로딩 중…</div>`;
  const counts = d.risk.counts || {};
  return html`
    <div class="grid cards">
      <div class="card"><div class="k">등록 자산</div><div class="v">${d.assets.total}</div>
        <div class="muted">검증 ${d.assets.verified} · 미검증 ${d.assets.unverified}</div></div>
      <div class="card"><div class="k">점검 작업</div><div class="v">${d.scans.total}</div>
        <div class="muted">완료 ${d.scans.completed} · 진행 ${d.scans.queuedOrRunning} · 차단 ${d.scans.rejected}</div></div>
      <div class="card"><div class="k">종합 위험도</div><div class="v">${d.risk.score}<span class="muted" style=${{ fontSize: 14 }}>/100</span></div>
        <div class="bar" style=${{ marginTop: 8 }}><i style=${{ width: `${d.risk.score}%` }}></i></div></div>
      <div class="card"><div class="k">위험 분포</div>
        <div style=${{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          ${SEV_ORDER.map((s) => html`<span key=${s} class=${`badge sev-${s}`}>${(counts[s] || 0)} ${s[0].toUpperCase()}</span>`)}
        </div></div>
    </div>
    ${d.trend?.length > 1 && html`<div class="panel" style=${{ marginTop: 16 }}>
      <h3>위험도 추세 (최근 점검 ${d.trend.length}건)</h3>
      <${TrendChart} points=${d.trend} />
    </div>`}
    <div class="grid" style=${{ gridTemplateColumns: '1fr 1fr', marginTop: 16 }}>
      <div class="panel" style=${{ margin: 0 }}>
        <h3>자산별 위험도</h3>
        <table><thead><tr><th>자산</th><th>중요도</th><th>위험도</th><th>발견</th></tr></thead><tbody>
          ${(d.assetRisk || []).map((a) => html`<tr key=${a.asset}>
            <td><b>${a.asset}</b></td><td class="muted">${a.criticality}</td>
            <td><${Sev} s=${a.band} /> <span class="muted">${a.score}</span></td><td>${a.findings}</td></tr>`)}
          ${!d.assetRisk?.length && html`<tr><td colSpan="4" class="muted">완료된 점검 없음</td></tr>`}
        </tbody></table>
      </div>
      <div class="panel" style=${{ margin: 0 }}>
        <h3>전체 상위 위험</h3>
        <table><thead><tr><th>위험</th><th>등급</th><th>항목</th></tr></thead><tbody>
          ${(d.topFindings || []).map((f, i) => html`<tr key=${i}>
            <td><b>${f.riskScore}</b></td><td><${Sev} s=${f.severity} /></td>
            <td>${f.title}<div class="muted mono" style=${{ fontSize: 11 }}>${f.target}</div></td></tr>`)}
          ${!d.topFindings?.length && html`<tr><td colSpan="3" class="muted">발견 없음</td></tr>`}
        </tbody></table>
      </div>
    </div>
    <div class="panel" style=${{ marginTop: 16 }}>
      <h3>최근 점검 작업</h3>
      <table><thead><tr><th>작업</th><th>자산</th><th>강도</th><th>상태</th><th>발견</th><th>요청시각</th></tr></thead>
        <tbody>${d.recentJobs.map((j) => html`<tr key=${j.id}>
          <td class="mono">${j.id.slice(0, 12)}</td><td class="mono">${j.assetId.slice(0, 14)}</td>
          <td><span class="pill">${j.intensity}</span></td><td><${Status} s=${j.status} /></td>
          <td>${j.findings}</td><td class="muted">${fmt(j.queuedAt)}</td></tr>`)}
          ${!d.recentJobs.length && html`<tr><td colSpan="6" class="muted">작업 없음</td></tr>`}
        </tbody></table>
    </div>`;
}

// 위험도 추세 — 인라인 SVG 라인 차트
function TrendChart({ points }) {
  const W = 720, H = 120, P = 24;
  const xs = (i) => P + (i * (W - 2 * P)) / Math.max(1, points.length - 1);
  const ys = (v) => H - P - (v / 100) * (H - 2 * P);
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join(' ');
  return html`<svg viewBox=${`0 0 ${W} ${H}`} style=${{ width: '100%', height: 130 }}>
    ${[0, 25, 50, 75, 100].map((g) => html`<g key=${g}>
      <line x1=${P} y1=${ys(g)} x2=${W - P} y2=${ys(g)} stroke="var(--line)" stroke-width="1" />
      <text x=${4} y=${ys(g) + 3} fill="var(--muted)" font-size="9">${g}</text></g>`)}
    <path d=${path} fill="none" stroke="var(--accent)" stroke-width="2" />
    ${points.map((p, i) => html`<circle key=${i} cx=${xs(i)} cy=${ys(p.score)} r="3.5" fill=${SEV_COLOR[p.score >= 80 ? 'critical' : p.score >= 60 ? 'high' : p.score >= 35 ? 'medium' : p.score >= 15 ? 'low' : 'info']}>
      <title>${p.asset} · ${p.score}/100 · ${p.findings}건 · ${fmt(p.ts)}</title></circle>`)}
  </svg>`;
}

// ───────────────────────── 자산 + 소유권 게이트 ─────────────────────────
function Assets({ user, toast }) {
  const [assets, setAssets] = useState([]);
  const [form, setForm] = useState({ type: 'domain', value: '', label: '', businessCriticality: 'medium' });
  const [sel, setSel] = useState(null);
  const [challenge, setChallenge] = useState(null);
  const canWrite = ['admin', 'scanner'].includes(user.role);
  const load = () => api('GET', '/api/assets').then((r) => setAssets(r.json || []));
  useEffect(() => { load(); }, []);

  const create = async () => {
    const r = await api('POST', '/api/assets', form);
    if (r.ok) { toast('자산 등록 완료'); setForm({ ...form, value: '', label: '' }); load(); }
    else toast(r.json?.message || '실패', true);
  };
  const startChallenge = async (asset, method) => {
    const r = await api('POST', `/api/assets/${asset.id}/ownership/challenge`, { method });
    if (r.ok) { setSel(asset.id); setChallenge({ ...r.json, method }); toast('검증 토큰 발급'); load(); }
  };
  const verify = async (asset, extra = {}) => {
    const r = await api('POST', `/api/assets/${asset.id}/ownership/verify`, extra);
    if (r.ok) { toast(r.json.proof.status === 'verified' ? '✅ 소유권 검증 성공' : '검증 실패: ' + r.json.proof.detail, r.json.proof.status !== 'verified'); load(); setChallenge(null); }
  };

  return html`
    ${canWrite && html`<div class="panel">
      <h3>자산 등록</h3>
      <div class="row">
        <div><label>유형</label><select value=${form.type} onChange=${(e) => setForm({ ...form, type: e.target.value })}>
          <option value="domain">도메인</option><option value="host">호스트</option><option value="web">웹</option></select></div>
        <div style=${{ flex: 2 }}><label>값 (도메인/IP)</label><input value=${form.value} placeholder="example.com" onChange=${(e) => setForm({ ...form, value: e.target.value })} /></div>
        <div><label>라벨</label><input value=${form.label} onChange=${(e) => setForm({ ...form, label: e.target.value })} /></div>
        <div><label>중요도</label><select value=${form.businessCriticality} onChange=${(e) => setForm({ ...form, businessCriticality: e.target.value })}>
          <option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option></select></div>
        <div style=${{ flex: 0 }}><label>&nbsp;</label><button class="primary" onClick=${create}>등록</button></div>
      </div>
    </div>`}
    <div class="panel">
      <h3>자산 목록 · 소유권 검증 게이트</h3>
      <table><thead><tr><th>자산</th><th>유형</th><th>중요도</th><th>소유권</th><th>검증 방식</th><th>액션</th></tr></thead>
        <tbody>${assets.map((a) => html`<tr key=${a.id}>
          <td><b>${a.value}</b><div class="muted">${a.label || ''}</div></td>
          <td><span class="pill">${a.type}</span></td>
          <td>${a.businessCriticality}</td>
          <td>${a.ownership
            ? html`<span class=${a.ownership.status === 'verified' ? 'ok' : 'no'}>${a.ownership.status}</span>`
            : html`<span class="muted">unverified</span>`}</td>
          <td class="muted">${a.ownership?.method || '-'}</td>
          <td>${canWrite && html`<div style=${{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            ${a.ownership?.status === 'verified'
              ? html`<span class="ok">검증완료</span>`
              : html`
                <button onClick=${() => startChallenge(a, 'dns-txt')}>DNS</button>
                <button onClick=${() => startChallenge(a, 'file-upload')}>파일</button>
                <button onClick=${() => startChallenge(a, 'contract-esign')}>전자서명</button>
                ${a.ownership && a.ownership.method !== 'contract-esign' && html`<button class="primary" onClick=${() => verify(a)}>검증확인</button>`}
                ${a.ownership && a.ownership.method === 'contract-esign' && html`<button class="primary" onClick=${() => verify(a, { contractSignatureHash: 'sig_' + Math.random().toString(16).slice(2), businessRegistryVerified: true })}>서명검증</button>`}
              `}
          </div>`}</td></tr>`)}
        </tbody></table>
      ${challenge && html`<div class="panel" style=${{ marginTop: 14, background: 'var(--panel2)' }}>
        <h3>검증 안내 (${challenge.proof.method})</h3>
        <pre class="evidence">${challenge.instructions}</pre>
        <div class="muted">위 절차 수행 후 목록의 '검증확인' 버튼을 누르세요. (전자서명은 데모상 즉시 검증)</div>
      </div>`}
    </div>`;
}

// ───────────────────────── 동의·범위 ─────────────────────────
function Consents({ user, toast }) {
  const [consents, setConsents] = useState([]);
  const [assets, setAssets] = useState([]);
  const nowLocal = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const plus = (h) => new Date(Date.now() + h * 3600000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const [form, setForm] = useState({ assetId: '', allowedTargets: '', allowedPorts: '80,443', maxIntensity: 'standard', windowStart: nowLocal(), windowEnd: plus(24), aggressiveApprovedBy: '' });
  const canWrite = ['admin', 'scanner'].includes(user.role);
  const load = () => { api('GET', '/api/consents').then((r) => setConsents(r.json || [])); api('GET', '/api/assets').then((r) => setAssets(r.json || [])); };
  useEffect(() => { load(); }, []);

  const create = async () => {
    const body = {
      assetId: form.assetId,
      allowedTargets: form.allowedTargets.split(',').map((s) => s.trim()).filter(Boolean),
      allowedPorts: form.allowedPorts.split(',').map((s) => parseInt(s.trim(), 10)).filter(Boolean),
      maxIntensity: form.maxIntensity,
      windowStart: new Date(form.windowStart).toISOString(),
      windowEnd: new Date(form.windowEnd).toISOString(),
      aggressiveApprovedBy: form.aggressiveApprovedBy || undefined,
    };
    const r = await api('POST', '/api/consents', body);
    if (r.ok) { toast('동의·범위 등록 완료'); load(); } else toast(r.json?.message || '실패', true);
  };
  const revoke = async (c) => { const r = await api('POST', `/api/consents/${c.id}/revoke`); if (r.ok) { toast('동의 철회(kill-switch) 실행'); load(); } };
  const assetName = (id) => assets.find((a) => a.id === id)?.value || id;

  return html`
    ${canWrite && html`<div class="panel">
      <h3>동의·범위 등록 (점검 윈도우)</h3>
      <div class="row">
        <div><label>대상 자산</label><select value=${form.assetId} onChange=${(e) => setForm({ ...form, assetId: e.target.value })}>
          <option value="">선택…</option>${assets.map((a) => html`<option key=${a.id} value=${a.id}>${a.value}</option>`)}</select></div>
        <div><label>최대 강도</label><select value=${form.maxIntensity} onChange=${(e) => setForm({ ...form, maxIntensity: e.target.value })}>
          <option value="passive">passive</option><option value="standard">standard</option><option value="aggressive">aggressive</option></select></div>
      </div>
      <div class="row">
        <div style=${{ flex: 2 }}><label>허용 대상 (egress allowlist, 콤마)</label><input value=${form.allowedTargets} placeholder="example.com, 127.0.0.1" onChange=${(e) => setForm({ ...form, allowedTargets: e.target.value })} /></div>
        <div><label>허용 포트 (콤마)</label><input value=${form.allowedPorts} onChange=${(e) => setForm({ ...form, allowedPorts: e.target.value })} /></div>
      </div>
      <div class="row">
        <div><label>시작</label><input type="datetime-local" value=${form.windowStart} onChange=${(e) => setForm({ ...form, windowStart: e.target.value })} /></div>
        <div><label>종료</label><input type="datetime-local" value=${form.windowEnd} onChange=${(e) => setForm({ ...form, windowEnd: e.target.value })} /></div>
        <div><label>Aggressive 승인자(4-eyes)</label><input value=${form.aggressiveApprovedBy} placeholder="선택 (aggressive 시 필수)" onChange=${(e) => setForm({ ...form, aggressiveApprovedBy: e.target.value })} /></div>
        <div style=${{ flex: 0 }}><label>&nbsp;</label><button class="primary" onClick=${create} disabled=${!form.assetId}>등록</button></div>
      </div>
    </div>`}
    <div class="panel">
      <h3>동의 목록</h3>
      <table><thead><tr><th>자산</th><th>최대강도</th><th>허용대상</th><th>포트</th><th>윈도우</th><th>상태</th><th></th></tr></thead>
        <tbody>${consents.map((c) => html`<tr key=${c.id}>
          <td>${assetName(c.assetId)}</td><td><span class="pill">${c.scope.maxIntensity}</span></td>
          <td class="mono">${c.scope.allowedTargets.join(', ') || '-'}</td>
          <td class="mono">${c.scope.allowedPorts.join(',') || '표준'}</td>
          <td class="muted">${fmt(c.windowStart)}<br/>~ ${fmt(c.windowEnd)}</td>
          <td><span class=${c.status === 'active' ? 'ok' : 'no'}>${c.status}</span></td>
          <td>${canWrite && c.status === 'active' && html`<button class="danger" onClick=${() => revoke(c)}>철회</button>`}</td></tr>`)}
          ${!consents.length && html`<tr><td colSpan="7" class="muted">동의 없음</td></tr>`}
        </tbody></table>
    </div>`;
}

// ───────────────────────── 점검 작업 ─────────────────────────
function Scans({ user, toast, onOpenReport }) {
  const [jobs, setJobs] = useState([]);
  const [assets, setAssets] = useState([]);
  const [form, setForm] = useState({ assetId: '', modules: ['asm', 'config', 'cve', 'access'], intensity: 'standard', active: false });
  const canScan = ['admin', 'scanner'].includes(user.role);
  const load = () => { api('GET', '/api/scans').then((r) => setJobs(r.json || [])); api('GET', '/api/assets').then((r) => setAssets(r.json || [])); };
  useEffect(() => { load(); const t = setInterval(load, 2500); return () => clearInterval(t); }, []);

  const toggleMod = (m) => setForm((f) => ({ ...f, modules: f.modules.includes(m) ? f.modules.filter((x) => x !== m) : [...f.modules, m] }));
  const run = async () => {
    const r = await api('POST', '/api/scans', form);
    if (r.status === 202) toast('게이트 통과 → 점검 큐 진입');
    else if (r.status === 422) toast('🚫 게이트 차단: ' + (r.json.gateDecision?.reason || ''), true);
    else toast(r.json?.message || '실패', true);
    load();
  };
  const assetName = (id) => assets.find((a) => a.id === id)?.value || id;

  return html`
    ${canScan && html`<div class="panel">
      <h3>점검 실행</h3>
      <div class="row">
        <div><label>대상 자산</label><select value=${form.assetId} onChange=${(e) => setForm({ ...form, assetId: e.target.value })}>
          <option value="">선택…</option>${assets.map((a) => html`<option key=${a.id} value=${a.id}>${a.value} ${a.ownership?.status === 'verified' ? '✓' : '(미검증)'}</option>`)}</select></div>
        <div><label>강도 프로파일</label><select value=${form.intensity} onChange=${(e) => setForm({ ...form, intensity: e.target.value })}>
          <option value="passive">passive (소유권만)</option><option value="standard">standard (소유권+동의)</option><option value="aggressive">aggressive (+추가승인)</option></select></div>
        <div style=${{ flex: 2 }}><label>점검 모듈</label>
          <div style=${{ display: 'flex', gap: 6 }}>
            ${['asm', 'config', 'cve', 'dast', 'access', 'ai'].map((m) => html`<button key=${m} class=${form.modules.includes(m) ? 'primary' : ''} onClick=${() => toggleMod(m)}>${m.toUpperCase()}</button>`)}
          </div></div>
        <div style=${{ flex: 0 }}><label>&nbsp;</label><button class="primary" onClick=${run} disabled=${!form.assetId || !form.modules.length}>점검 시작</button></div>
      </div>
      <label class="attest" style=${{ marginTop: 10, borderColor: form.active ? '#dc2626' : undefined }}>
        <input type="checkbox" checked=${form.active} onChange=${(e) => setForm((f) => ({ ...f, active: e.target.checked, intensity: e.target.checked ? 'aggressive' : f.intensity, modules: e.target.checked && !f.modules.includes('dast') ? [...f.modules, 'dast'] : f.modules }))} />
        <span><b>🔴 활성(침투) 검증 모드</b> — 취약점을 실제 트리거해 확정합니다(Boolean SQLi 차분 · XSS 컨텍스트 이스케이프 · IDOR 무인증 열람). <b>aggressive 강도 + 4-eyes 서면승인</b> 동의가 있어야만 게이트를 통과합니다. <span class="muted">비파괴 한정 — 데이터 변경·삭제, DoS, 무차별 대입, 실 악성 페이로드는 수행하지 않습니다. (dast 모듈에서 동작)</span></span>
      </label>
      <div class="muted" style=${{ marginTop: 8 }}>※ 검증되지 않은 자산·범위 밖 대상·윈도우 밖 요청은 게이트가 차단합니다.</div>
    </div>`}
    <div class="panel">
      <h3>점검 작업 목록</h3>
      <table><thead><tr><th>작업</th><th>자산</th><th>모듈</th><th>강도</th><th>상태</th><th>발견</th><th>사유/시각</th><th></th></tr></thead>
        <tbody>${jobs.map((j) => html`<tr key=${j.id}>
          <td class="mono">${j.id.slice(0, 12)}</td><td>${assetName(j.assetId)}</td>
          <td class="muted">${j.modules.join(',')}</td><td><span class="pill">${j.intensity}</span></td>
          <td><${Status} s=${j.status} /></td><td>${j.findings.length}</td>
          <td class="muted" style=${{ maxWidth: 240 }}>${j.status === 'rejected' || j.status === 'aborted' ? (j.gateDecision?.reason || j.error) : fmt(j.finishedAt || j.queuedAt)}</td>
          <td>${j.status === 'completed' && html`<button onClick=${() => onOpenReport(j.id)}>리포트</button>`}</td></tr>`)}
          ${!jobs.length && html`<tr><td colSpan="8" class="muted">작업 없음</td></tr>`}
        </tbody></table>
    </div>`;
}

// ───────────────────────── 리포트 ─────────────────────────
function Report({ jobId, onBack }) {
  const [r, setR] = useState(null);
  useEffect(() => { api('GET', `/api/scans/${jobId}/report`).then((x) => setR(x.json)); }, [jobId]);
  if (!r) return html`<div class="muted">리포트 로딩 중…</div>`;
  const e = r.executive;
  return html`
    <div style=${{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
      <button onClick=${onBack}>← 목록</button>
      <button class="primary" onClick=${() => openAuthedDoc(`/api/scans/${jobId}/report.html`, 'text/html')}>🖨 PDF 리포트</button>
      <${FixPromptButton} findings=${r.technical} target=${r.asset.value} />
      <button onClick=${() => openAuthedDoc(`/api/scans/${jobId}/report.md`, 'text/markdown')}>리포트 마크다운(.md)</button>
    </div>
    <div class="panel" style=${{ marginTop: 14 }}>
      <h3>경영진 요약 — ${r.asset.value}</h3>
      <div class="grid cards">
        <div class="card"><div class="k">종합 위험도</div><div class="v">${e.overallScore}<span class="muted">/100</span></div>
          <div><${Sev} s=${e.band} /></div></div>
        <div class="card"><div class="k">발견 항목</div><div class="v">${r.technical.length}</div></div>
        <div class="card" style=${{ gridColumn: 'span 2' }}><div class="k">핵심 메시지</div><div style=${{ marginTop: 8 }}>${e.headline}</div>
          ${r.delta && html`<div class="muted" style=${{ marginTop: 8 }}>직전 대비: 해소 ${r.delta.resolved} · 신규 ${r.delta.introduced} · 점수변화 ${r.delta.scoreChange >= 0 ? '+' : ''}${r.delta.scoreChange}</div>`}</div>
      </div>
    </div>
    <div class="panel">
      <h3>점검 방법론 및 범위</h3>
      <ul style=${{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
        ${(r.methodology || []).map((m, i) => html`<li key=${i} class="muted">${m}</li>`)}
      </ul>
      ${r.coverage?.length && html`<div class="muted" style=${{ marginTop: 8, fontSize: 12 }}>범위: ${r.coverage.join(' · ')}</div>`}
    </div>
    ${r.categories && (Object.keys(r.categories.owasp).length > 0) && html`<div class="panel">
      <h3>표준 커버리지 — <${GlossaryTag} term="OWASP">OWASP Top 10<//> · <${GlossaryTag} term="CWE">CWE<//></h3>
      <div class="muted" style=${{ fontSize: 12, marginBottom: 8 }}>발견된 취약점이 국제 보안 표준의 어느 항목에 해당하는지 분류한 것입니다.</div>
      <div style=${{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        ${Object.entries(r.categories.owasp).map(([k, n]) => html`<span key=${k} class="pill">${k} · ${n}건</span>`)}
      </div>
      <div style=${{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
        ${Object.entries(r.categories.cwe).map(([k, n]) => html`<span key=${k} class="pill">${k} (${n})</span>`)}
      </div>
    </div>`}
    ${r.remediationRoadmap?.length && html`<div class="panel">
      <h3>조치 로드맵 (우선순위 · 기한)</h3>
      <table><thead><tr><th>우선순위</th><th>기한</th><th>항목 수</th><th>대표 항목</th></tr></thead><tbody>
        ${r.remediationRoadmap.map((t, i) => html`<tr key=${i}>
          <td><b>${t.priority}</b></td><td class="muted">${t.window}</td><td>${t.items.length}</td>
          <td class="muted">${t.items.slice(0, 2).map((it) => it.title).join(' / ')}${t.items.length > 2 ? ' …' : ''}</td></tr>`)}
      </tbody></table>
    </div>`}
    <div class="panel">
      <h3>컴플라이언스 매핑</h3>
      <table><thead><tr><th>프레임워크</th><th>관련 통제</th></tr></thead><tbody>
        ${Object.entries(r.compliance).map(([fw, v]) => html`<tr key=${fw}><td><b>${fw}</b></td><td class="muted">${v.controls.join(', ')}</td></tr>`)}
        ${!Object.keys(r.compliance).length && html`<tr><td colSpan="2" class="muted">매핑 없음</td></tr>`}
      </tbody></table>
    </div>
    <div class="panel">
      <h3>기술 상세 (위험 우선순위 순)</h3>
      ${r.technical.map((f) => html`<div key=${f.id} style=${{ borderBottom: '1px solid var(--line)', padding: '12px 0' }}>
        <div style=${{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <${Sev} s=${f.severity} /><b>${f.title}</b>
          <span class="pill">위험 ${f.riskScore}</span>
          ${f.owasp && html`<${GlossaryTag} term="OWASP"><span class="pill">${f.owasp.split(' ')[0]}</span><//>`}
          ${f.cwe && html`<${GlossaryTag} term="CWE"><span class="pill">${f.cwe}</span><//>`}
          ${f.cve && html`<${GlossaryTag} term="CVE"><span class="pill">${f.cve}</span><//>`}
          ${f.kev && html`<${GlossaryTag} term="KEV"><span class="badge sev-critical">KEV ⚠</span><//>`}
          ${typeof f.epss === 'number' && html`<${GlossaryTag} term="EPSS"><span class="pill">악용 확률 ${(f.epss * 100).toFixed(0)}%</span><//>`}
        </div>
        <div class="muted" style=${{ margin: '6px 0' }}>${f.description}</div>
        <div class="mono muted" style=${{ fontSize: 12 }}>📍 위치: ${f.target}</div>
        ${f.evidence && html`<pre class="evidence">${f.evidence}</pre>`}
        ${f.remediation && html`<div style=${{ marginTop: 6, padding: '8px 10px', background:'var(--bg-soft)', borderRadius:8, fontSize:13 }}>🔧 <b>해결 방법</b> ${f.remediation}</div>`}
        ${f.compliance?.length && html`<div class="muted" style=${{ marginTop: 6, fontSize: 11 }}>📋 관련 규정: ${f.compliance.map((m) => `${m.framework} ${m.control}`).join(' · ')}</div>`}
      </div>`)}
      ${!r.technical.length && html`<div class="muted">발견 항목 없음</div>`}
    </div>`;
}

// ───────────────────────── 감사로그 ─────────────────────────
function Audit() {
  const [events, setEvents] = useState([]);
  const [chain, setChain] = useState(null);
  useEffect(() => { api('GET', '/api/audit?limit=300').then((r) => setEvents(r.json || [])); api('GET', '/api/audit/verify').then((r) => setChain(r.json)); }, []);
  return html`
    <div class="panel">
      <h3>감사로그 무결성 (해시 체인)</h3>
      ${chain && html`<div>레코드 ${chain.count}건 · 체인 검증: <span class=${chain.valid ? 'ok' : 'no'}>${chain.valid ? '무결성 정상 (변조 없음)' : '⚠ 변조 탐지 @ ' + chain.brokenAt}</span></div>`}
    </div>
    <div class="panel">
      <h3>감사 추적 (append-only)</h3>
      <table><thead><tr><th>시각</th><th>행위자</th><th>액션</th><th>대상</th><th>결과</th><th>사유</th></tr></thead>
        <tbody>${events.map((ev) => html`<tr key=${ev.id}>
          <td class="muted mono">${fmt(ev.ts)}</td><td>${ev.actor || '-'}</td>
          <td class="mono">${ev.action}</td><td class="mono">${ev.target || '-'}</td>
          <td><span class=${ev.outcome === 'deny' || ev.outcome === 'error' ? 'no' : 'ok'}>${ev.outcome}</span></td>
          <td class="muted" style=${{ maxWidth: 320 }}>${ev.reason || ''}</td></tr>`)}
        </tbody></table>
    </div>`;
}

// ───────────────────────── 셸 / 라우팅 ─────────────────────────
// 발견 유형별 5단 설명: [무엇이 노출] → [왜 위험] → [공격자] → [비즈니스 피해] → [조치]
function explainFinding(f) {
  const t = (f.title || '').toLowerCase();
  const has = (...k) => k.some((x) => t.includes(x));
  const tgt = f.target || '대상';
  const pathOnly = (tgt.match(/\/[^\s]*/) || [tgt])[0];

  let e = {
    exposed: f.description || '보안 취약점 또는 설정 오류가 확인되었습니다.',
    why: '공격자가 추가 공격의 발판으로 삼을 수 있는 약점입니다.',
    attacker: '정찰·침투·권한 상승의 출발점으로 악용될 수 있습니다.',
    business: '정보 유출·서비스 영향·대외 신뢰도 하락으로 이어질 수 있습니다.',
    action: f.remediation || '해당 항목을 점검·차단하고 재검증하십시오.',
  };

  if (f.cve || f.module === 'cve') {
    e = {
      exposed: `${tgt} 구성요소가 알려진 취약점(${f.cve || 'CVE'})에 영향을 받는 구버전입니다.`,
      why: '인터넷에 익스플로잇 코드가 공개되어 있을 수 있어, 별도 정찰 없이도 자동화 도구로 즉시 공격당할 수 있습니다.',
      attacker: '원격 코드 실행·인증 우회·데이터 탈취 등 취약점 유형에 따른 직접 침해가 가능합니다.',
      business: f.kev
        ? '실제 악용이 확인된(KEV) 취약점으로, 침해 시 대규모 정보 유출·서비스 중단·규제 제재로 직결될 수 있습니다.'
        : '침해 시 고객정보 유출·서비스 중단·복구 비용이 발생할 수 있습니다.',
      action: f.remediation || '취약 구성요소를 패치 버전으로 즉시 업그레이드하십시오.',
    };
  } else if (has('.git', '.env', 'server-status', '민감 경로', '정보 노출')) {
    e = {
      exposed: `외부에서 ${pathOnly} 접근 가능성이 확인되었습니다.`,
      why: '.env·.git·server-status 등에는 DB 계정, API Key, 토큰, 클라우드 접근키, 소스코드 같은 핵심 비밀정보가 담길 수 있습니다.',
      attacker: '유출 시 내부 시스템 접속, 데이터 조회, 관리자 권한 탈취, 서비스 변조로 이어질 수 있습니다.',
      business: '고객정보 유출, 서비스 중단, 대외 신뢰도 하락, 규제 대응 비용이 발생할 수 있습니다.',
      action: '즉시 외부 접근 차단, 노출 파일 제거, 노출된 비밀키 전면 교체, 접근 로그 확인이 필요합니다.',
    };
  } else if (has('admin', '관리', 'wp-admin', 'manager', 'phpmyadmin')) {
    e = {
      exposed: `관리자/운영 인터페이스(${pathOnly})가 외부에서 접근 가능합니다.`,
      why: '관리 콘솔은 기본 자격증명·무차별 대입(brute force)·해당 패널의 알려진 취약점의 표적이 됩니다.',
      attacker: '관리 권한을 탈취해 계정 조작, 데이터 전체 조회·삭제, 백도어 설치가 가능합니다.',
      business: '전체 시스템 통제권 상실, 대규모 정보 유출, 서비스 마비로 이어질 수 있습니다.',
      action: '관리 경로를 IP 허용목록/VPN 뒤로 이동, 기본 경로 변경, 다중인증(MFA) 적용.',
    };
  } else if (has('hsts')) {
    e = {
      exposed: 'HTTPS 강제(HSTS) 정책이 적용되어 있지 않습니다.',
      why: '중간자 공격자가 HTTPS 연결을 평문 HTTP로 강등(SSL stripping)시킬 수 있습니다.',
      attacker: '로그인 세션·비밀번호·쿠키를 평문으로 가로채 계정을 탈취할 수 있습니다.',
      business: '계정 도용·개인정보 유출에 따른 피해 보상과 신뢰도 하락이 발생합니다.',
      action: 'Strict-Transport-Security: max-age=31536000; includeSubDomains 적용.',
    };
  } else if (has('csp')) {
    e = {
      exposed: '콘텐츠 보안 정책(CSP)이 설정되어 있지 않습니다.',
      why: 'XSS가 발생하면 악성 스크립트 실행을 차단할 마지막 방어선이 없습니다.',
      attacker: '세션 쿠키 탈취, 피싱 페이지 삽입, 악성코드 배포가 가능합니다.',
      business: '대량 계정 탈취·악성코드 유포 사고로 번질 수 있습니다.',
      action: 'Content-Security-Policy로 스크립트/리소스 출처를 제한.',
    };
  } else if (has('x-frame', '클릭재킹')) {
    e = {
      exposed: '클릭재킹 방지 헤더(X-Frame-Options / CSP frame-ancestors)가 없습니다.',
      why: '공격자가 사이트를 투명 iframe으로 덧씌워 사용자의 클릭을 가로챌 수 있습니다.',
      attacker: '사용자가 모르는 사이 송금·권한 변경·동의 같은 민감 동작을 실행시킬 수 있습니다.',
      business: '부정거래·권한 오남용에 따른 분쟁과 보상 비용이 발생합니다.',
      action: 'X-Frame-Options: DENY 또는 CSP frame-ancestors 적용.',
    };
  } else if (has('x-content-type', 'mime')) {
    e = {
      exposed: 'MIME 스니핑 방지(X-Content-Type-Options) 헤더가 없습니다.',
      why: '브라우저가 파일 타입을 추측해, 업로드 파일이 실행 스크립트로 해석될 수 있습니다.',
      attacker: '악성 파일을 스크립트로 실행시켜 XSS·악성코드 유포가 가능합니다.',
      business: '방문자 단말 감염·브랜드 신뢰도 하락으로 이어질 수 있습니다.',
      action: 'X-Content-Type-Options: nosniff 적용.',
    };
  } else if (has('referrer')) {
    e = {
      exposed: 'Referrer 정책이 설정되어 있지 않습니다.',
      why: '페이지의 전체 URL(토큰·내부 경로 포함)이 외부 사이트로 전달될 수 있습니다.',
      attacker: '세션 토큰·내부 구조 정보를 수집해 후속 공격에 활용합니다.',
      business: '민감정보 유출 경로가 되어 규제 위반 소지가 있습니다.',
      action: 'Referrer-Policy: strict-origin-when-cross-origin 적용.',
    };
  } else if (has('쿠키', 'cookie', 'secure', 'httponly', 'samesite')) {
    e = {
      exposed: '세션 쿠키에 보안 플래그(Secure / HttpOnly / SameSite)가 누락되었습니다.',
      why: '평문 전송·자바스크립트 접근·교차사이트 전송이 허용됩니다.',
      attacker: '세션 쿠키를 탈취하거나 CSRF로 사용자 권한을 도용할 수 있습니다.',
      business: '계정 탈취·부정거래에 따른 보상·신뢰도 하락이 발생합니다.',
      action: '쿠키에 Secure; HttpOnly; SameSite=Lax|Strict 적용.',
    };
  } else if (has('서버 정보', 'server', 'x-powered')) {
    e = {
      exposed: '응답 헤더로 서버 제품·버전 정보가 노출됩니다.',
      why: '공격자가 해당 버전에 맞는 알려진 취약점을 즉시 선별할 수 있습니다.',
      attacker: '버전 특화 익스플로잇으로 정밀 타격을 시도합니다.',
      business: '공격 성공률이 높아져 침해 위험이 커집니다.',
      action: 'Server·X-Powered-By 등 식별 헤더 제거/일반화.',
    };
  } else if (has('tls', '인증서', 'https')) {
    e = {
      exposed: '전송 구간 암호화(TLS/인증서) 구성에 문제가 확인되었습니다.',
      why: '만료·약한 구성은 중간자 공격과 보안 경고 무시를 유발합니다.',
      attacker: '통신을 도청·변조하거나 가짜 사이트로 유도할 수 있습니다.',
      business: '통신 기밀성 상실·사용자 이탈·신뢰도 하락이 발생합니다.',
      action: '인증서 갱신 및 자동 갱신(ACME) 구성, 강한 암호 스위트 적용.',
    };
  } else if (has('포트', 'port', '서비스')) {
    e = {
      exposed: `민감 서비스 포트(${tgt})가 인터넷에 직접 노출되어 있습니다.`,
      why: 'DB·원격관리·파일공유 서비스는 인증 취약점·무차별 대입의 표적입니다.',
      attacker: '서비스에 직접 접속해 데이터 탈취·내부 횡적 이동을 시도합니다.',
      business: '데이터베이스 유출·랜섬웨어 침투의 진입점이 됩니다.',
      action: '불필요 포트 방화벽 차단, 관리 포트는 VPN/허용목록 뒤로 이동.',
    };
  } else if (has('디렉터리', '인덱싱')) {
    e = {
      exposed: '디렉터리 자동 목록(인덱싱)이 활성화되어 있습니다.',
      why: '내부 파일 구조·백업·설정 파일이 그대로 드러납니다.',
      attacker: '노출된 파일에서 비밀정보·소스를 수집해 공격을 정교화합니다.',
      business: '정보 유출 및 후속 침해 위험이 커집니다.',
      action: '웹서버 자동 디렉터리 인덱싱 비활성화.',
    };
  } else if (has('반사', 'xss')) {
    e = {
      exposed: '입력값이 응답에 그대로 반사되는 지점이 확인되었습니다.',
      why: '반사형/저장형 XSS로 이어질 수 있는 표면입니다.',
      attacker: '방문자 브라우저에서 악성 스크립트를 실행해 세션 탈취·피싱을 수행합니다.',
      business: '대량 계정 탈취·브랜드 피싱 악용 피해가 발생할 수 있습니다.',
      action: '출력 인코딩·입력 검증 적용, CSP 강화.',
    };
  }
  return e;
}

// 인증 토큰을 실어 문서를 받아 새 탭(Blob)으로 연다 — Bearer 인증 엔드포인트용
async function openAuthedDoc(path, type) {
  const res = await fetch(path, { headers: { authorization: `Bearer ${tokenStore.get()}` } });
  if (!res.ok) { alert('문서를 불러오지 못했습니다 (' + res.status + ')'); return; }
  const text = await res.text();
  const url = URL.createObjectURL(new Blob([text], { type }));
  window.open(url, '_blank');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// 텍스트를 .md 파일로 다운로드
function downloadMd(filename, text) {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// 점검 결과 → AI 코딩 어시스턴트에 그대로 붙여넣는 "수정 명령서" 마크다운 생성
// 발견 여부와 무관하게 항상 적용해야 하는 기본 보안 하드닝 기준선
const BASELINE_HARDENING = [
  ['전송 구간 암호화', '평문 통신은 도청·변조에 취약합니다.', '모든 HTTP 요청을 HTTPS 로 301 리다이렉트하고, HSTS(max-age=31536000; includeSubDomains; preload)와 TLS 1.2 이상만 허용하도록 설정합니다.'],
  ['보안 응답 헤더 전체 적용', '브라우저 보호 기능이 꺼져 있으면 XSS·클릭재킹·MIME 공격에 노출됩니다.', "CSP(default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none', 가능하면 nonce 기반으로 unsafe-inline 제거), X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy(불필요 기능 차단), X-Frame-Options: DENY 를 모든 응답에 추가합니다."],
  ['쿠키·세션 보안', '플래그 없는 세션 쿠키는 탈취·CSRF 에 취약합니다.', '세션 쿠키에 Secure; HttpOnly; SameSite=Lax(또는 Strict) 를 적용하고, 로그인 시 세션 ID 를 재발급(세션 고정 방지)하며 적절한 만료를 둡니다. 가능하면 __Host- 접두를 사용합니다.'],
  ['비밀정보 관리', '코드·프론트엔드 번들·저장소에 노출된 키는 즉시 악용됩니다.', '모든 API 키·토큰·DB 자격증명을 코드에서 제거하고 환경변수 또는 시크릿 매니저로 옮깁니다. .env 와 키 파일은 .gitignore 에 추가하고, 이미 노출된 비밀은 반드시 폐기 후 재발급합니다. 프론트엔드 번들에는 어떤 비밀도 두지 않습니다.'],
  ['의존성·패치 관리', '구버전 라이브러리는 공개된 익스플로잇으로 즉시 침해됩니다.', '취약 의존성을 안전한 최소 버전으로 올리고, lockfile 을 커밋하며, 자동 취약점 점검(npm audit / pip-audit / Dependabot 등)을 CI 에 연결합니다. 미사용 의존성은 제거합니다.'],
  ['입력 검증·출력 인코딩', '검증되지 않은 입력은 인젝션·XSS 의 통로입니다.', 'DB 접근은 파라미터화 쿼리(Prepared Statement)만 사용하고, 사용자 입력을 화면에 출력할 때 컨텍스트에 맞게 인코딩하며, 파일 업로드는 타입·크기·경로를 검증합니다.'],
  ['인증·인가', '서버측 인가 누락은 권한 상승으로 이어집니다.', '모든 보호 리소스에 서버측 인가 검사를 두고, 관리자/디버그 인터페이스는 인증·IP 제한 뒤에 둡니다. 토큰은 만료를 두고 서명 알고리즘을 고정 검증하며, 가능하면 다중인증(MFA)을 적용합니다.'],
  ['CORS 정책', '느슨한 CORS 는 교차 출처 데이터 탈취를 허용합니다.', '와일드카드(*)와 자격증명(credentials) 조합을 금지하고, 허용 출처는 정확 일치로 검증하며 null origin 을 허용하지 않습니다.'],
  ['남용 방지', '무차별 대입·자동화 공격은 인증·민감 엔드포인트를 노립니다.', '로그인·비밀번호 재설정·결제 등 민감 엔드포인트에 레이트리밋과 계정 잠금/캡차를 적용합니다.'],
  ['정보 노출 최소화', '상세 오류·버전·내부 파일 노출은 정찰을 돕습니다.', '운영 환경에서 상세 스택트레이스를 숨기고, 서버 버전 헤더(Server, X-Powered-By)를 제거하며, 디렉터리 인덱싱을 끄고 .git·.env·백업 파일에 대한 외부 접근을 차단합니다.'],
  ['로깅·모니터링·백업', '탐지·복구 체계가 없으면 사고가 장기화됩니다.', '인증 실패·권한 변경 등 보안 이벤트를 로깅(민감정보는 마스킹)하고, 정기 백업과 복구 테스트로 랜섬웨어·데이터 손실에 대비합니다.'],
];

function buildFixPrompt(findings, target) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => (order[a.severity] - order[b.severity]) || ((b.riskScore || 0) - (a.riskScore || 0)));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let max = 0, sum = 0;
  for (const f of findings) { counts[f.severity]++; max = Math.max(max, f.riskScore || 0); sum += f.riskScore || 0; }
  const score = findings.length ? Math.round(max * 0.7 + Math.min(100, Math.log2(sum + 1) * 8) * 0.3) : 0;

  const L = [];
  L.push('# 🤖 보안 개선 명령서 (AI 코딩 도구용)', '');
  L.push('> **사용법 — 보안을 잘 몰라도 됩니다.** 이 문서를 그대로 복사해, 이 코드를 만들 때 쓴 AI 코딩 도구');
  L.push('> (Cursor · Copilot 등)에 붙여넣고 다음과 같이 요청하세요:');
  L.push('> *"이 보안 개선 명령서대로, 우선순위에 따라 코드와 설정을 수정해줘. 기존 기능은 깨지 않게 최소 변경으로 하고,');
  L.push('> 바꾼 파일과 그 이유, 그리고 각 항목을 어떻게 검증하는지 알려줘."*', '');
  L.push('> 그러면 AI 가 아래 ① 기본 보안 기준선과 ② 발견된 문제를 함께 수정하여 보안 수준을 끌어올립니다.', '');

  L.push('## 0. 역할과 원칙 (AI 에게)');
  L.push('당신은 시니어 애플리케이션 보안 엔지니어입니다. 아래를 준수하여 이 프로젝트의 보안을 **엄격하게** 상향하세요.');
  L.push('1. **치명적 → 심각 → 주의** 순으로 처리하고, 각 변경마다 *무엇을 왜* 바꾸는지 한 줄로 설명합니다.');
  L.push('2. 기존 기능을 깨뜨리지 않도록 **최소 변경**으로 수정하고, 변경 파일 경로와 diff(또는 전체 코드)를 제시합니다.');
  L.push('3. 프로젝트가 실제로 쓰는 언어/프레임워크/서버(예: Express · Next.js · Spring · Django · nginx)를 **먼저 파악한 뒤** 그에 맞는 구체적 코드·설정으로 작성합니다. 아래 예시는 참고용이며 스택에 맞게 변환하세요.');
  L.push('4. 비밀정보(.env · 키 · 토큰)가 노출된 경우, 코드에서 제거하는 것에 더해 **해당 키를 즉시 폐기하고 재발급**하도록 사용자에게 명확히 지시합니다.');
  L.push('5. 의존성 취약점은 **안전한 최소 상향 버전**을 명시하고, 호환성에 영향이 있으면 주의사항을 덧붙입니다.');
  L.push('6. 수정 후 각 항목의 해결 여부를 확인하는 **구체적 검증 방법**(명령·요청 예시)을 제시합니다.', '');

  L.push('## 1. 점검 개요');
  L.push(`- 대상: ${target || '-'}`);
  L.push(`- 종합 위험도: **${score}/100**`);
  L.push(`- 발견: 총 ${findings.length}건 (치명적 ${counts.critical} · 심각 ${counts.high} · 주의 ${counts.medium} · 경미 ${counts.low} · 정보 ${counts.info})`, '');

  L.push('## 2. 기본 보안 기준선 (필수 — 발견 여부와 무관하게 모두 적용)');
  L.push('아래 항목은 강력한 기본 방어선입니다. 이미 적용된 것은 확인만 하고, 빠진 것은 모두 적용하세요.', '');
  BASELINE_HARDENING.forEach(([title, why, how], i) => {
    L.push(`**${i + 1}. ${title}**`);
    L.push(`- 왜: ${why}`);
    L.push(`- 어떻게: ${how}`, '');
  });
  L.push('### 참고 예시 (스택에 맞게 변환하여 적용)');
  L.push('```nginx');
  L.push('# nginx — HTTPS 강제 + 보안 헤더');
  L.push('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;');
  L.push('add_header X-Content-Type-Options "nosniff" always;');
  L.push('add_header X-Frame-Options "DENY" always;');
  L.push('add_header Referrer-Policy "strict-origin-when-cross-origin" always;');
  L.push("add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\" always;");
  L.push('```');
  L.push('```js');
  L.push('// Node/Express — helmet 로 보안 헤더 일괄 적용 + 쿠키 플래그');
  L.push("const helmet = require('helmet'); app.use(helmet());");
  L.push("res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax' });");
  L.push('```', '');

  L.push('## 3. 이번 점검에서 발견된 문제와 해결책 (우선순위 순)');
  if (!sorted.length) {
    L.push('- 발견된 개별 취약점은 없습니다. 위 2장의 기본 기준선을 점검·적용하세요.', '');
  }
  sorted.forEach((f, i) => {
    const e = explainFinding(f);
    L.push('', `### ${i + 1}. [${SEV_KO[f.severity] || f.severity}] ${f.title}`);
    L.push(`- **위치/대상**: \`${f.target}\``);
    if (f.owasp || f.cwe) L.push(`- **표준 분류**: ${[f.owasp, f.cwe].filter(Boolean).join(' · ')}`);
    if (f.cve) L.push(`- **CVE**: ${f.cve}${f.kev ? ' (실제 악용 확인 · KEV)' : ''}${typeof f.epss === 'number' ? ` · EPSS ${(f.epss * 100).toFixed(0)}%` : ''}${f.cvss != null ? ` · CVSS ${f.cvss}` : ''}`);
    L.push(`- **무엇이 노출되었는가**: ${e.exposed}`);
    L.push(`- **왜 위험한가**: ${e.why}`);
    L.push(`- **공격 시나리오**: ${e.attacker}`);
    L.push(`- **비즈니스 피해**: ${e.business}`);
    L.push(`- **해결책 (이렇게 고치세요)**: ${e.action}`);
    if (f.references?.length) L.push(`- **참고 표준**: ${f.references.join(' , ')}`);
    L.push('- **완료 기준**: 위 수정 적용 후 재점검 시 본 항목이 더 이상 탐지되지 않아야 합니다.');
  });
  L.push('');

  L.push('## 4. 결정적 실행 순서 (이 순서대로 해결하세요)');
  L.push('1. **즉시(치명적·KEV)** — 노출된 비밀키 폐기·재발급, 알려진 악용 취약점(KEV) 패치, 외부 노출된 민감 파일/경로 차단.');
  L.push('2. **긴급(심각)** — 인증·인가·접근통제 결함, 원격코드실행·인젝션 표면, 관리 인터페이스 노출 제거.');
  L.push('3. **기준선 전면 적용** — 위 2장의 기본 보안 기준선(전송 암호화·보안 헤더·쿠키·CORS·의존성)을 일괄 반영.');
  L.push('4. **재점검(검증)** — 동일 대상을 다시 점검하여 각 항목이 더 이상 탐지되지 않는지(차분=해소) 확인.');
  L.push('5. **정기화** — 위 과정을 배포 파이프라인에 통합하여 새 취약점이 누적되지 않도록 지속 관리.', '');

  L.push('## 5. 완료 후 보고 (AI 가 작성)');
  L.push('- 항목별로 (1) 적용한 수정 (2) 변경 파일 (3) 검증 방법을 표로 정리하세요.');
  L.push('- 기본 기준선 중 적용/이미충족/미적용 항목을 구분해 알려주세요.');
  L.push('- 수정으로 영향받을 수 있는 기능과 회귀 테스트 포인트를 알려주세요.', '');
  L.push('---');
  L.push('_SENTINEL-ASM 자동 생성 · 권한이 검증된 본인 자산에 한해 수정·점검하세요. 비밀키가 노출되었다면 코드 수정만으로 끝내지 말고 반드시 키를 재발급하세요._');
  return L.join('\n');
}

// "AI 수정 명령서(.md)" 다운로드 버튼
function FixPromptButton({ findings, target }) {
  if (!findings?.length) return null;
  const fn = `sentinel-fix-${String(target || 'scan').replace(/[^\w.-]/g, '_').slice(0, 40)}.md`;
  return html`<button class="primary" onClick=${() => downloadMd(fn, buildFixPrompt(findings, target))} title="AI에게 그대로 붙여넣어 코드를 수정시키는 명령서">🤖 AI 수정 명령서 (.md)</button>`;
}

// 게이트 차단 메시지를 비전공자가 이해할 수 있게 변환
function friendlyGateReason(raw) {
  if (!raw) return '';
  if (raw.includes('소유권')) return '이 사이트의 소유자임을 먼저 확인해야 합니다. → 자산 메뉴에서 소유권을 검증하세요.';
  if (raw.includes('동의') || raw.includes('consent')) return '이 사이트를 점검해도 된다는 사전 동의가 없습니다. → 동의·범위 메뉴에서 등록하세요.';
  if (raw.includes('범위') || raw.includes('scope')) return '이 주소는 허용된 점검 범위를 벗어났습니다. → 동의·범위에서 허용 대상을 추가하세요.';
  if (raw.includes('윈도우') || raw.includes('window')) return '점검 허용 시간이 아닙니다. → 동의·범위에서 허용 시간 범위를 확인하세요.';
  if (raw.includes('강도') || raw.includes('intensity')) return '요청한 점검 강도가 허용 범위를 초과했습니다.';
  return raw;
}

// ───────────────────────── 발견사항 목록 (공용) ─────────────────────────
// 구조: 제목/등급 → [피해 시나리오](점수보다 먼저) → 위험 지표 → 조치. 호버 시 5단 상세.
function FindingList({ findings }) {
  if (!findings?.length) return html`<div class="muted">발견된 취약점이 없습니다. ✅</div>`;
  return html`<div>${findings.map((f) => {
    const e = explainFinding(f);
    const color = SEV_COLOR[f.severity] || '#dc2626';
    return html`
    <div key=${f.id} class="finding">
      <div style=${{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <${Sev} s=${f.severity} /><b>${f.title}</b>
        ${f.cve && html`<span class="pill">${f.cve}</span>`}
        <span class="hint">ⓘ 마우스를 올리면 상세 분석</span>
      </div>
      <div class="muted" style=${{ margin: '5px 0' }}>${e.exposed}</div>

      <div class="scenario" style=${{ borderLeftColor: color }}>
        <div class="scenario-h" style=${{ color }}>🎯 이대로 두면 — 피해 시나리오</div>
        <div><b>공격자</b> ${e.attacker}</div>
        <div style=${{ marginTop: 3 }}><b>비즈니스</b> ${e.business}</div>
      </div>

      <div class="metrics">
        <span class="pill">우선순위 위험 ${f.riskScore}/100</span>
        ${f.owasp && html`<span class="pill">${f.owasp.split(' ')[0]}</span>`}
        ${f.cwe && html`<span class="pill">${f.cwe}</span>`}
        ${f.cvss != null && html`<span class="pill">CVSS ${f.cvss}</span>`}
        ${typeof f.epss === 'number' && html`<span class="pill">EPSS ${(f.epss * 100).toFixed(0)}%</span>`}
        ${f.kev && html`<span class="badge sev-critical">KEV · 실제 악용중</span>`}
        ${f.confidence && html`<span class="pill">신뢰도 ${f.confidence}</span>`}
        <span class="pill mono">${f.target}</span>
      </div>

      <div class="evidence-box">
        <div class="evidence-h">🔬 관측 근거 — 왜 이렇게 판단했나 (검증 가능)</div>
        <div class="evidence-row"><span class="evidence-k">점검 대상</span><span class="mono">${f.target}</span></div>
        ${f.evidence
          ? html`<div class="evidence-row"><span class="evidence-k">관측값</span><pre class="evidence">${f.evidence}</pre></div>`
          : html`<div class="evidence-row"><span class="evidence-k">관측값</span><span class="muted" style=${{ fontSize: 12 }}>이 항목은 휴리스틱/부재 단서로, 별도 관측 문자열이 없습니다(신뢰도 ${f.confidence || 'tentative'}).</span></div>`}
        ${(f.owasp || f.cwe || f.confidence) && html`<div class="evidence-row"><span class="evidence-k">분류·신뢰도</span><span style=${{ fontSize: 12 }}>${[f.owasp, f.cwe, f.confidence && `신뢰도 ${f.confidence}`].filter(Boolean).join(' · ')}</span></div>`}
        ${f.references?.length && html`<div class="evidence-row"><span class="evidence-k">참고 표준</span><span style=${{ fontSize: 11, wordBreak: 'break-all' }}>${f.references.map((u, i) => html`<a key=${i} href=${u} target="_blank" rel="noreferrer" class="evidence-ref">${u}</a>`)}</span></div>`}
      </div>

      <div class="action">🔧 <b>조치</b> ${e.action}</div>

      <div class="why-pop">
        <div class="arrow"></div>
        <h5>${f.title}</h5>
        <div class="sec"><div class="lbl">무엇이 노출되었는가</div>${e.exposed}</div>
        <div class="sec"><div class="lbl">왜 위험한가</div>${e.why}</div>
        <div class="sec"><div class="lbl">공격자가 무엇을 할 수 있는가</div>${e.attacker}</div>
        <div class="sec"><div class="lbl">비즈니스 피해</div>${e.business}</div>
        ${(f.cvss != null || f.epss != null || f.kev) && html`<div class="sec"><div class="lbl">위험 지표</div>
          ${f.cvss != null && html`<span class="metric">CVSS ${f.cvss} (0–10)</span>`}
          ${f.epss != null && html`<span class="metric">EPSS ${(f.epss * 100).toFixed(0)}% · 30일 내 악용 확률</span>`}
          ${f.kev && html`<span class="metric">KEV · 실제 악용 확인됨</span>`}
        </div>`}
        ${(f.owasp || f.cwe) && html`<div class="sec"><div class="lbl">표준 분류</div>
          ${f.owasp && html`<span class="metric">${f.owasp}</span>`}
          ${f.cwe && html`<span class="metric">${f.cwe}</span>`}
          ${f.confidence && html`<span class="metric">신뢰도 ${f.confidence}</span>`}
        </div>`}
        <div class="sec"><div class="lbl">조치</div>${e.action}</div>
        ${f.references?.length && html`<div class="sec"><div class="lbl">참고 표준</div>${f.references.map((u, i) => html`<div key=${i} style=${{ fontSize: 11, color: '#8fa3c8', wordBreak: 'break-all' }}>${u}</div>`)}</div>`}
      </div>
    </div>`;
  })}</div>`;
}

function aggScore(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let max = 0, sum = 0;
  for (const f of findings) { counts[f.severity]++; max = Math.max(max, f.riskScore || 0); sum += f.riskScore || 0; }
  const score = findings.length ? Math.round(max * 0.7 + Math.min(100, Math.log2(sum + 1) * 8) * 0.3) : 0;
  const band = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : score >= 15 ? 'low' : 'info';
  return { score, band, counts };
}

function ScoreBadge({ findings }) {
  const { score, band, counts } = aggScore(findings);
  return html`<div style=${{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
    <span class="v" style=${{ fontSize: 22, fontWeight: 700 }}>${score}<span class="muted" style=${{ fontSize: 13 }}>/100</span></span>
    <${Sev} s=${band} />
    ${SEV_ORDER.map((s) => html`<span key=${s} class=${`badge sev-${s}`}>${counts[s]} ${s[0].toUpperCase()}</span>`)}
  </div>`;
}

// AI 보안 분석 — 사이트 맞춤 적응형 점검 결과의 경영진 요약·우선순위·공격경로·오탐 분석
function AiInsights({ jobId }) {
  const [status, setStatus] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  useEffect(() => { api('GET', '/api/ai/status').then((x) => setStatus(x.json)).catch(() => {}); }, []);
  const run = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api('POST', '/api/ai/analyze', { jobId });
      if (r.ok && r.json?.analysis) setAnalysis(r.json.analysis);
      else setErr(r.json?.message || 'AI 분석을 받지 못했습니다.');
    } finally { setBusy(false); }
  };
  if (!status) return null;
  return html`<div class="ai-insights">
    <div class="ai-head">
      <span class="ai-badge">🤖 AI 보안 분석 ${status.configured
        ? html`<span class="ai-on">${status.model}</span>`
        : html`<span class="ai-off">비활성</span>`}</span>
      ${status.configured
        ? html`<button class="primary" onClick=${run} disabled=${busy}>${busy ? '🤖 AI 분석 중…' : (analysis ? '↻ 다시 분석' : '🤖 AI 종합 분석')}</button>`
        : html`<span class="muted" style=${{ fontSize: 12 }}>SENTINEL_AI_API_KEY(또는 ANTHROPIC_API_KEY) 환경변수 설정 시 활성화</span>`}
    </div>
    ${err && html`<div class="no" style=${{ fontSize: 13, marginTop: 8 }}>${err}</div>`}
    ${analysis && html`<div class="ai-body">
      <div class="ai-summary">${analysis.executiveSummary}</div>
      ${analysis.blastRadius && html`<div class="ai-blast"><b>🔥 피해 범위</b><div>${analysis.blastRadius}</div></div>`}
      ${analysis.prioritized?.length > 0 && html`<div class="ai-prio">
        ${analysis.prioritized.map((p, i) => html`<div key=${i} class="ai-prio-item">
          <div class="ai-prio-t">${p.severity && html`<${Sev} s=${p.severity} />`} <b>${p.title}</b></div>
          ${p.businessImpact && html`<div class="ai-line"><span class="ai-k">사업영향</span> ${p.businessImpact}</div>`}
          ${p.attackPath && html`<div class="ai-line"><span class="ai-k">공격경로</span> ${p.attackPath}</div>`}
          ${p.falsePositiveRisk && html`<div class="ai-line"><span class="ai-k">오탐가능성</span> ${p.falsePositiveRisk}</div>`}
          ${p.recommendation && html`<div class="ai-line"><span class="ai-k">조치</span> ${p.recommendation}</div>`}
        </div>`)}
      </div>`}
      ${analysis.topRecommendations?.length > 0 && html`<div class="ai-recs"><b>✅ 핵심 권고</b><ul>${analysis.topRecommendations.map((r, i) => html`<li key=${i}>${r}</li>`)}</ul></div>`}
      <div class="ai-foot muted">AI 는 점검 발견의 메타데이터만 분석합니다(대상 무발신·개인정보 마스킹). 결과는 참고용이며 전문가 검증을 권장합니다.</div>
    </div>`}
  </div>`;
}

// 발견사항 패널 — 심각도 필터 칩 + 검색 + 정렬 (UX)
function FindingsPanel({ findings }) {
  const [active, setActive] = useState(new Set());      // 빈 set = 전체
  const [q, setQ] = useState('');
  const [sort, setSort] = useState('risk');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const toggle = (s) => setActive((prev) => {
    const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n;
  });
  let list = findings.filter((f) => (active.size === 0 || active.has(f.severity)));
  if (q.trim()) {
    const k = q.trim().toLowerCase();
    list = list.filter((f) => `${f.title} ${f.target} ${f.cve || ''} ${f.cwe || ''} ${f.owasp || ''}`.toLowerCase().includes(k));
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  list = list.slice().sort((a, b) => sort === 'risk'
    ? (b.riskScore || 0) - (a.riskScore || 0)
    : (rank[a.severity] - rank[b.severity]) || ((b.riskScore || 0) - (a.riskScore || 0)));

  return html`
    <div class="filterbar">
      <div class="chips">
        ${SEV_ORDER.map((s) => counts[s] > 0 && html`<button key=${s} class=${`chip sev-${s} ${active.has(s) ? 'on' : ''}`} onClick=${() => toggle(s)}>${SEV_KO[s]} ${counts[s]}</button>`)}
        ${active.size > 0 && html`<button class="chip" onClick=${() => setActive(new Set())}>전체</button>`}
      </div>
      <div class="ftools">
        <input class="search" placeholder="검색(제목·대상·CVE·CWE)" value=${q} onChange=${(e) => setQ(e.target.value)} />
        <select value=${sort} onChange=${(e) => setSort(e.target.value)} style=${{ width: 'auto' }}>
          <option value="risk">위험순</option><option value="severity">심각도순</option>
        </select>
      </div>
    </div>
    <div class="muted" style=${{ fontSize: 12, margin: '4px 0 8px' }}>${list.length} / ${findings.length}건 표시</div>
    <${FindingList} findings=${list} />`;
}

// 진행률 바 — 경과/예상 잔여 시간과 % 표시
function ProgressBar({ pct, label, eta }) {
  return html`<div class="progress-wrap">
    <div class="progress"><i style=${{ width: Math.max(2, Math.min(100, pct)) + '%' }}></i></div>
    <div class="progress-meta"><span>${label}</span><span><b>${Math.round(pct)}%</b>${eta != null ? ` · 예상 잔여 ~${eta}초` : ''}</span></div>
  </div>`;
}

// ───────────────────────── 빠른 점검 (Quick Scan) ─────────────────────────
function Quick({ user, toast, onOpenReport }) {
  const [tab, setTab] = useState('domain');
  const canScan = ['admin', 'scanner'].includes(user.role);

  // 소프트웨어 프로젝트(폴더/다중 파일)
  const [projectFiles, setProjectFiles] = useState([]);   // [{ filename, content }]
  const [projectName, setProjectName] = useState('');
  const [fileJob, setFileJob] = useState(null);
  const [fileMeta, setFileMeta] = useState(null);   // { fileResults, totalFindings }
  const [busy, setBusy] = useState(false);
  const [filename, setFilename] = useState('');    // 텍스트 붙여넣기용
  const [content, setContent] = useState('');

  // ── SAST 상태 ──
  const [sastCode, setSastCode] = useState('');
  const [sastFilename, setSastFilename] = useState('app.js');
  const [sastResult, setSastResult] = useState(null);
  const [sastBusy, setSastBusy] = useState(false);
  const scanSast = async () => {
    if (!sastCode.trim()) return toast('소스코드를 붙여넣거나 파일을 선택하세요.', true);
    setSastBusy(true); setSastResult(null);
    const r = await api('POST', '/api/quick/sast', { filename: sastFilename, content: sastCode });
    setSastBusy(false);
    if (r.status === 200) { setSastResult(r.json); toast(`SAST 완료 — ${r.json.count}건 탐지`); }
    else toast(r.json?.message || 'SAST 실패', true);
  };
  const onSastFile = async (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    setSastFilename(f.name); setSastCode(await f.text());
  };

  // ── 인증 세션 상태 ──
  const [authedTarget, setAuthedTarget] = useState('');
  const [authedCookie, setAuthedCookie] = useState('');
  const [authedHeader, setAuthedHeader] = useState('');
  const [authedAttested, setAuthedAttested] = useState(false);
  const [authedJob, setAuthedJob] = useState(null);
  const [authedBusy, setAuthedBusy] = useState(false);
  const scanAuthed = async () => {
    if (!authedTarget.trim()) return toast('도메인 또는 URL 을 입력하세요.', true);
    if (!authedAttested) return toast('점검 권한 보유 확인이 필요합니다.', true);
    setAuthedBusy(true); setAuthedJob(null);
    const headers = authedHeader ? { Authorization: authedHeader } : undefined;
    const r = await api('POST', '/api/quick/authed', { target: authedTarget, attested: authedAttested, sessionCookie: authedCookie || undefined, headers, modules: ['config', 'dast', 'access'] });
    if (r.status !== 202) { setAuthedBusy(false); return toast(r.json?.message || '차단됨', true); }
    let job = r.json;
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      await new Promise(res => setTimeout(res, 700));
      const jr = await api('GET', `/api/scans/${job.id}`);
      if (jr.json?.id) job = jr.json;
      if (['completed','failed','aborted','rejected'].includes(job.status)) break;
    }
    setAuthedBusy(false); setAuthedJob(job);
    toast(job.status === 'completed' ? `인증 점검 완료 — ${job.findings.length}건` : `상태: ${job.status}`, job.status !== 'completed');
  };

  // ── 위협 인텔 상태 ──
  const [intelDomain, setIntelDomain] = useState('');
  const [intelResult, setIntelResult] = useState(null);
  const [intelBusy, setIntelBusy] = useState(false);
  const checkIntel = async () => {
    if (!intelDomain.trim()) return toast('도메인을 입력하세요.', true);
    setIntelBusy(true); setIntelResult(null);
    const r = await api('POST', '/api/quick/threatintel', { domain: intelDomain });
    setIntelBusy(false);
    if (r.status === 200) { setIntelResult(r.json); toast(r.json.breached ? `⚠ ${r.json.count}건 유출 이력` : '유출 이력 없음'); }
    else toast(r.json?.message || '조회 실패', true);
  };

  // ── 수동 점검(Pentest) 상태 ──
  const [ptTarget, setPtTarget] = useState('');
  const [ptAttested, setPtAttested] = useState(false);
  const [ptMode, setPtMode] = useState('repeater');     // 'repeater' | 'playbook'
  // Repeater
  const [ptMethod, setPtMethod] = useState('GET');
  const [ptPath, setPtPath] = useState('/');
  const [ptHeaders, setPtHeaders] = useState('');
  const [ptBody, setPtBody] = useState('');
  const [ptActive, setPtActive] = useState(false);
  const [ptResp, setPtResp] = useState(null);
  const [ptBusy, setPtBusy] = useState(false);
  // Playbook
  const [playbooks, setPlaybooks] = useState([]);
  const [pbId, setPbId] = useState('path-fuzz');
  const [pbPath, setPbPath] = useState('');
  const [pbParam, setPbParam] = useState('');
  const [pbResult, setPbResult] = useState(null);
  const [pbBusy, setPbBusy] = useState(false);
  useEffect(() => { api('GET', '/api/pentest/playbooks').then((r) => setPlaybooks(r.json?.playbooks || [])); }, []);

  const statusClass = (s) => s >= 500 ? 'sev-critical' : (s === 401 || s === 403) ? 'sev-medium' : s >= 400 ? 'sev-high' : s >= 300 ? 'sev-low' : 'sev-info';
  const parseHeaders = (txt) => { const h = {}; (txt || '').split('\n').forEach((l) => { const i = l.indexOf(':'); if (i > 0) h[l.slice(0, i).trim()] = l.slice(i + 1).trim(); }); return h; };
  const curPb = () => playbooks.find((p) => p.id === pbId);
  const sendRepeater = async () => {
    if (!ptTarget.trim()) return toast('대상을 입력하세요.', true);
    if (!ptAttested) return toast('점검 권한 보유 확인이 필요합니다.', true);
    setPtBusy(true); setPtResp(null);
    const r = await api('POST', '/api/pentest/probe', { target: ptTarget, attested: ptAttested, method: ptMethod, path: ptPath, headers: parseHeaders(ptHeaders), body: ptBody || undefined, active: ptActive });
    setPtBusy(false);
    if (r.status === 200) { setPtResp(r.json); toast(r.json.blocked ? '⛔ ' + r.json.blocked : `응답 ${r.json.response?.status ?? '-'}`, !!r.json.blocked); }
    else toast(r.json?.message || '요청 실패', true);
  };
  const execPlaybook = async () => {
    if (!ptTarget.trim()) return toast('대상을 입력하세요.', true);
    if (!ptAttested) return toast('점검 권한 보유 확인이 필요합니다.', true);
    const need = curPb()?.needs || [];
    if (need.includes('path') && !pbPath.trim()) return toast('이 Playbook 은 경로(path)가 필요합니다.', true);
    if (need.includes('param') && !pbParam.trim()) return toast('이 Playbook 은 파라미터(param)가 필요합니다.', true);
    setPbBusy(true); setPbResult(null);
    const r = await api('POST', '/api/pentest/run', { target: ptTarget, attested: ptAttested, playbook: pbId, path: pbPath || undefined, param: pbParam || undefined });
    setPbBusy(false);
    if (r.status === 200) { setPbResult(r.json); toast(`Playbook 완료 — ${r.json.findings?.length || 0}건`); }
    else toast(r.json?.message || '실행 실패', true);
  };

  // 분석 가치가 있는 파일 필터
  const isRelevant = (name) => {
    const n = name.toLowerCase().replace(/^.*[\\/]/, '');
    return /^(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|pipfile\.lock|poetry\.lock|gemfile\.lock|cargo\.lock|composer\.lock|composer\.json|pom\.xml|build\.gradle|build\.gradle\.kts|go\.mod|go\.sum|dockerfile|docker-compose\.ya?ml|\.gitlab-ci\.yml|.*\.csproj|packages\.config|.*\.tf|.*\.tfvars)$/i.test(n) ||
           /\.(github|gitlab|workflows|ci)\//i.test(name);
  };

  const onFolderSelect = async (e) => {
    const all = Array.from(e.target.files || []);
    const relevant = all.filter((f) => isRelevant(f.webkitRelativePath || f.name));
    if (!relevant.length) { toast('분석 가능한 파일(package.json·requirements.txt·Dockerfile 등)이 없습니다.', true); return; }
    const loaded = await Promise.all(relevant.map(async (f) => ({ filename: f.webkitRelativePath || f.name, content: await f.text().catch(() => '') })));
    setProjectFiles(loaded.filter((f) => f.content));
    const root = (relevant[0].webkitRelativePath || '').split('/')[0] || '프로젝트';
    setProjectName(root);
    toast(`${loaded.length}개 파일 인식 (총 ${all.length}개 중 관련 파일만)`);
  };

  const onMultiFile = async (e) => {
    const all = Array.from(e.target.files || []);
    const loaded = await Promise.all(all.map(async (f) => ({ filename: f.name, content: await f.text().catch(() => '') })));
    setProjectFiles((prev) => {
      const map = new Map(prev.map((p) => [p.filename, p]));
      loaded.forEach((l) => map.set(l.filename, l));
      return [...map.values()];
    });
    toast(`파일 ${loaded.length}개 추가됨`);
  };

  const removeFile = (fn) => setProjectFiles((prev) => prev.filter((f) => f.filename !== fn));

  const scanProject = async () => {
    // 텍스트 붙여넣기도 포함
    const files = [...projectFiles];
    if (content.trim()) files.push({ filename: filename || 'manifest', content });
    if (!files.length) return toast('폴더를 선택하거나 파일 내용을 붙여넣으세요.', true);
    setBusy(true); setFileJob(null); setFileMeta(null);
    const r = await api('POST', '/api/quick/sbom/project', { projectName: projectName || undefined, files });
    setBusy(false);
    if (r.status === 201) {
      setFileJob(r.json.job);
      setFileMeta({ fileResults: r.json.fileResults, totalFindings: r.json.totalFindings });
      toast(`프로젝트 분석 완료 — ${files.length}개 파일, ${r.json.totalFindings}건 발견`);
    } else toast(r.json?.message || '분석 실패', true);
  };

  // 도메인/URL
  const [target, setTarget] = useState('');
  const [normHint, setNormHint] = useState(null);   // { host, changed, note }
  const normTimer = useRef(null);

  // 입력 변경 시 정규화 힌트를 즉시 계산 (API 없이 프런트에서)
  const normalizeLocal = (raw) => {
    const t = raw.trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/[/?#].*$/, '')
      .replace(/:.*/, '')
      .replace(/\.$/, '');
    return t;
  };
  const onTargetChange = (val) => {
    setTarget(val);
    if (!val.trim()) { setNormHint(null); return; }
    const host = normalizeLocal(val);
    const original = val.trim();
    const changed = host !== original.toLowerCase();
    const notes = [];
    if (/^https?:\/\//i.test(original)) notes.push('스킴 제거');
    if (/[/?#]/.test(original.replace(/^https?:\/\//, ''))) notes.push('경로 제거');
    if (/:\d+/.test(original.replace(/^https?:\/\//, '').split(/[/?#]/)[0] ?? '')) notes.push('포트 제거');
    setNormHint({ host, changed, note: notes.join(' · ') });
  };
  const [attested, setAttested] = useState(false);
  const [domainJob, setDomainJob] = useState(null);
  const [bulk, setBulk] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [deep, setDeep] = useState(false);
  const [prog, setProg] = useState({ pct: 0, label: '', eta: null });
  const [live, setLive] = useState(null);       // 진행 중 작업(모듈 단계 표시용)
  const cancelRef = useRef(false);
  const curJobRef = useRef(null);

  const cancelScan = async () => {
    cancelRef.current = true;
    if (curJobRef.current) await api('POST', `/api/scans/${curJobRef.current}/cancel`);
    setScanning(false); setLive(null);
    setProg({ pct: 0, label: '', eta: null });
    toast('점검을 취소했습니다.', false);
  };

  // 여러 대상(콤마/공백/줄바꿈 구분) 일괄 점검
  const scanBulk = async (targets) => {
    setScanning(true); setDomainJob(null); setBulk(null);
    setProg({ pct: 2, label: `${targets.length}개 대상 ${deep ? '심층' : '간단'} 일괄 점검 시작…`, eta: null });
    const r = await api('POST', '/api/quick/bulk', { targets, attested, deep });
    if (r.status !== 202) { toast(r.json?.message || '일괄 점검 실패', true); setScanning(false); return; }
    const rows = r.json.jobs.map((j) => ({ ...j, status: j.jobId ? 'queued' : 'error' }));
    setBulk([...rows]);
    const isDone = (x) => !x.jobId || ['completed', 'failed', 'aborted', 'rejected', 'error'].includes(x.status);
    const deadline = Date.now() + (deep ? 360 : 120) * 1000;
    while (Date.now() < deadline && !rows.every(isDone)) {
      await new Promise((res) => setTimeout(res, 600));
      for (const row of rows) {
        if (isDone(row)) continue;
        const job = (await api('GET', `/api/scans/${row.jobId}`)).json;
        if (job && job.id) row.status = job.status;
        if (job?.status === 'completed') { const a = aggScore(job.findings); row.score = a.score; row.band = a.band; row.findings = job.findings.length; }
      }
      const done = rows.filter(isDone).length;
      setProg({ pct: Math.round((done / rows.length) * 100), label: `${done}/${rows.length} 대상 완료`, eta: null });
      setBulk([...rows]);
    }
    setScanning(false);
    const completed = rows.filter((x) => x.status === 'completed').length;
    toast(`일괄 점검 종료 — ${completed}/${rows.length} 완료`);
  };

  const scanDomain = async () => {
    if (!target.trim()) return toast('도메인 또는 URL 을 입력하세요.', true);
    if (!attested) return toast('점검 권한 보유 확인에 체크해야 합니다. (법적 필수)', true);
    // 쉼표·공백으로 구분된 여러 대상 지원 (각각 정규화)
    const parts = target.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (parts.length > 1) return scanBulk(parts);  // 이미 scanBulk 내부에서 정규화됨
    setScanning(true); setDomainJob(null); setBulk(null); setLive(null);
    cancelRef.current = false; curJobRef.current = null;
    const start = Date.now();
    setProg({ pct: 2, label: `${deep ? '심층' : '간단'} 점검 작업 생성 중…`, eta: null });
    try {
      const r = await api('POST', '/api/quick/domain', { target, attested, deep });
      if (r.status !== 202) { toast('🚫 ' + (r.json.gateDecision?.reason || r.json?.message || '차단됨'), true); return; }
      let job = r.json;
      curJobRef.current = job.id;
      const isTerminal = (s) => ['completed', 'failed', 'aborted', 'rejected'].includes(s);
      const deadline = Date.now() + (deep ? 300 : 90) * 1000;
      while (Date.now() < deadline) {
        if (cancelRef.current) return;        // 사용자 취소
        await new Promise((res) => setTimeout(res, 600));
        const jr = await api('GET', `/api/scans/${job.id}`);
        if (jr.json && jr.json.id) job = jr.json;
        // 실제 진행률·단계 반영
        const el = ((Date.now() - start) / 1000).toFixed(0);
        setLive(job);
        setProg({
          pct: typeof job.progress === 'number' ? job.progress : (job.status === 'queued' ? 4 : 8),
          label: `${job.stage || (job.status === 'queued' ? '큐 대기 중' : '점검 진행 중')} · ${el}초 경과`,
          eta: null,
        });
        if (isTerminal(job.status)) break;
      }
      if (cancelRef.current) return;
      const total = ((Date.now() - start) / 1000).toFixed(0);
      if (job.status === 'completed') {
        setProg({ pct: 100, label: `완료 · 총 ${total}초 소요`, eta: 0 });
        setDomainJob(job); setLive(null);
        // 정규화 힌트 업데이트 (서버가 실제로 사용한 호스트 표시)
        if (job.normalizedHost && job.normalizedHost !== normHint?.host) {
          setNormHint({ host: job.normalizedHost, changed: false, note: '실제 점검 완료' });
        }
        toast(`점검 완료 — ${job.findings.length}건 발견`);
      } else if (isTerminal(job.status)) {
        setProg({ pct: 100, label: `상태: ${job.status}`, eta: 0 });
        setDomainJob(job); setLive(null);
        toast(`상태: ${job.status}`, true);
      } else {
        setProg({ pct: Math.min(96, job.progress || 90), label: `예상보다 오래 걸립니다 · ${total}초 (백그라운드 계속 진행)`, eta: null });
        setDomainJob(job); setLive(null);
        toast('점검이 계속 진행 중입니다. 잠시 후 다시 시도하거나 "점검" 목록에서 확인하세요.', false);
      }
    } finally {
      setScanning(false);
    }
  };

  const onKey = (e) => { if (e.key === 'Enter' && attested && !scanning) scanDomain(); };

  if (!canScan) return html`<div class="panel"><div class="muted">빠른 점검은 admin·scanner 역할만 실행할 수 있습니다.</div></div>`;

  return html`
    <div class="hero">
      <div class="wordmark">
        <div class="logo">🛡</div>
        <h1>SENTINEL <span class="sub">ASM</span></h1>
      </div>
      <div class="tagline">권한이 검증된 대상을 비파괴로 점검하는 엔터프라이즈 보안 플랫폼</div>

      <div class="seg">
        <button class=${tab === 'domain' ? 'on' : ''} onClick=${() => setTab('domain')}>🔗 도메인 · URL</button>
        <button class=${tab === 'file' ? 'on' : ''} onClick=${() => setTab('file')}>📂 소프트웨어 프로젝트</button>
        <button class=${tab === 'sast' ? 'on' : ''} onClick=${() => setTab('sast')}>🔬 소스코드 SAST</button>
        <button class=${tab === 'authed' ? 'on' : ''} onClick=${() => setTab('authed')}>🔐 인증 세션 점검</button>
        <button class=${tab === 'pentest' ? 'on' : ''} onClick=${() => setTab('pentest')}>🧪 수동 점검</button>
        <button class=${tab === 'intel' ? 'on' : ''} onClick=${() => setTab('intel')}>🕵️ 위협 인텔</button>
      </div>

      ${tab === 'domain' && html`
        <div>
          <div class="searchbox">
            <span class="icon">🔍</span>
            <input value=${target}
              placeholder="naver.com / www.naver.com / naver.com/sw / https://s.naver.com — 어떤 형식이든 OK"
              onChange=${(e) => onTargetChange(e.target.value)}
              onKeyDown=${onKey} autoFocus />
            <button class="primary" onClick=${scanDomain} disabled=${scanning || !attested}>${scanning ? '점검 중…' : '점검 시작'}</button>
          </div>
          ${normHint && html`<div class="norm-hint">
            ${normHint.changed
              ? html`<span class="norm-arrow">→</span> <b class="norm-host">${normHint.host}</b> <span class="norm-note">(${normHint.note})</span>`
              : html`<span class="norm-ok">✓</span> <b class="norm-host">${normHint.host}</b>`}
          </div>`}
          <div class="depth-sel">
            <button class=${!deep ? 'on' : ''} onClick=${() => setDeep(false)}>
              <div class="d-t">⚡ 간단 점검</div><div class="d-d">핵심·고신호 항목 · 빠름(~30초)</div></button>
            <button class=${deep ? 'on' : ''} onClick=${() => setDeep(true)}>
              <div class="d-t">🔬 심층 점검</div><div class="d-d">확장 포트·정밀 항목 전수 · 토시 하나까지(시간 소요)</div></button>
          </div>
          <label class="attest">
            <input type="checkbox" checked=${attested} onChange=${(e) => setAttested(e.target.checked)} />
            <span>본인이 <b>소유</b>했거나 <b>점검 권한(위탁계약·서면 동의)</b>을 보유한 대상입니다. 무권한 점검은 법으로 금지되며 시스템이 차단·기록합니다. <span class="muted">(설계 §0/§3 · 생략 불가)</span></span>
          </label>
          ${(scanning || prog.pct === 100) && html`<div>
            <${ProgressBar} pct=${prog.pct} label=${prog.label} eta=${scanning ? prog.eta : null} />
            ${live?.moduleStatus?.length && html`<div class="steps">
              ${live.moduleStatus.map((m) => html`<span key=${m.module} class=${`step ${m.status}`}>
                ${m.status === 'done' ? '✓' : m.status === 'running' ? '⏳' : m.status === 'error' ? '⚠' : m.status === 'skipped' ? '–' : '·'} ${m.module.toUpperCase()}${m.status === 'done' ? ` (${m.findings})` : ''}</span>`)}
            </div>`}
            ${scanning && html`<div style=${{ textAlign: 'center', marginTop: 10 }}><button class="danger" onClick=${cancelScan}>점검 취소</button></div>`}
          </div>`}
        </div>`}

      ${tab === 'file' && html`
        <div class="filebox">
          <div class="proj-upload">
            <label class="proj-btn primary-upload">
              <input type="file" style=${{ display:'none' }} webkitdirectory="" onChange=${onFolderSelect} />
              📂 프로젝트 폴더 선택
            </label>
            <label class="proj-btn">
              <input type="file" style=${{ display:'none' }} multiple onChange=${onMultiFile} />
              ➕ 파일 추가
            </label>
            <div class="muted" style=${{ fontSize:12, alignSelf:'center' }}>package.json · *.lock · requirements.txt · Dockerfile · *.yml ···</div>
          </div>

          ${projectFiles.length > 0 && html`<div class="file-list">
            <div class="file-list-head">인식된 파일 <span class="muted">(${projectFiles.length}개)</span></div>
            ${projectFiles.map((f) => html`<div key=${f.filename} class="file-list-item">
              <span class="mono">${f.filename.replace(/^[^/]+\//, '')}</span>
              <button class="file-rm" onClick=${() => removeFile(f.filename)} title="제거">✕</button>
            </div>`)}
          </div>`}

          <div class="proj-sep"><span>또는 파일 내용 직접 붙여넣기</span></div>
          <textarea rows="5" class="mono" value=${content} placeholder=${'# 예) package.json, requirements.txt 내용을 여기에 붙여넣기\n{\n  "dependencies": { "lodash": "4.17.20" }\n}'} onChange=${(e) => setContent(e.target.value)}></textarea>
          <div style=${{ marginTop: 12, textAlign: 'center' }}>
            <button class="primary" onClick=${scanProject} disabled=${busy} style=${{ minWidth: 160 }}>
              ${busy ? '분석 중…' : (projectFiles.length > 0 ? `프로젝트 분석 (${projectFiles.length}개 파일)` : '분석 시작')}
            </button>
          </div>
          ${busy && html`<div class="progress-wrap"><div class="progress indet"><i></i></div><div class="progress-meta"><span>전체 파일 분석 중…</span><span></span></div></div>`}
          <div class="muted" style=${{ marginTop: 8, fontSize: 12, textAlign: 'center' }}>원격 트래픽 없음 · 권한 절차 불필요 · 모든 생태계(npm·PyPI·Maven·Cargo·Go·Ruby·PHP·.NET) 동시 분석</div>
        </div>`}

      ${tab === 'file' && fileJob && html`<div class="panel result-card">
        <div style=${{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
          <div><b>프로젝트 분석 결과</b> <span class="muted">· ${fileMeta?.fileResults?.length || 0}개 파일 · ${fileJob.findings.length}건 발견</span></div>
          <div style=${{ display: 'flex', gap: 8 }}>
            <${FixPromptButton} findings=${fileJob.findings} target=${projectName || 'project'} />
            <button onClick=${() => onOpenReport(fileJob.id)}>전체 리포트 →</button>
          </div>
        </div>
        ${fileMeta?.fileResults?.length > 0 && html`<div class="file-breakdown">
          ${fileMeta.fileResults.filter((r) => r.findingCount > 0 || r.componentCount > 0).map((r) => html`<div key=${r.filename} class="file-br-row">
            <span class="mono">${r.filename.replace(/^[^/]+\//, '')}</span>
            <span class="pill">${r.format}</span>
            ${r.componentCount > 0 && html`<span class="muted">${r.componentCount}개 구성요소</span>`}
            ${r.findingCount > 0 && html`<span class="badge sev-high">${r.findingCount}건</span>`}
          </div>`)}
        </div>`}
        <div style=${{ margin: '12px 0' }}><${ScoreBadge} findings=${fileJob.findings} /></div>
        <${ActionCard} findings=${fileJob.findings} />
        <${FindingsPanel} findings=${fileJob.findings} />
      </div>`}

      ${tab === 'domain' && bulk && html`<div class="panel result-card" style=${{ maxWidth: 860 }}>
        <div style=${{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
          <div><b>일괄 점검 결과</b> <span class="depth-badge">${deep ? '🔬 심층' : '⚡ 간단'}</span> <span class="muted">· ${bulk.length}개 대상</span></div>
        </div>
        <table><thead><tr><th>대상</th><th>상태</th><th>위험도</th><th>발견</th><th></th></tr></thead><tbody>
          ${bulk.map((row) => html`<tr key=${row.target}>
            <td><b>${row.target}</b></td>
            <td><${Status} s=${row.status} /></td>
            <td>${row.band ? html`<${Sev} s=${row.band} /> <span class="muted">${row.score}/100</span>` : html`<span class="muted">—</span>`}</td>
            <td>${row.findings != null ? row.findings : '—'}</td>
            <td>${row.status === 'completed' && html`<button onClick=${() => onOpenReport(row.jobId)}>리포트 →</button>`}
                ${(row.status === 'rejected' || row.status === 'error') && html`<span class="no" style=${{ fontSize: 11 }}>${row.reason || ''}</span>`}</td>
          </tr>`)}
        </tbody></table>
      </div>`}

      ${tab === 'domain' && domainJob && !bulk && html`<div class="panel result-card">
        ${domainJob.status === 'completed' ? html`
          <div style=${{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <b>점검 결과</b>
              <span class="depth-badge">${domainJob.depth === 'deep' ? '🔬 심층' : '⚡ 간단'}</span>
              <span class="muted">· ${domainJob.normalizedHost || domainJob.assetId} · ${domainJob.findings.length}건 발견</span>
            </div>
            <div style=${{ display: 'flex', gap: 8 }}>
              <button onClick=${scanDomain} disabled=${scanning} title="동일 설정으로 다시 점검(폐루프)">↻ 재점검</button>
              <${FixPromptButton} findings=${domainJob.findings} target=${target} />
              <button onClick=${() => onOpenReport(domainJob.id)}>전체 리포트 →</button>
            </div>
          </div>
          <div style=${{ margin: '12px 0' }}><${ScoreBadge} findings=${domainJob.findings} /></div>
          <${ActionCard} findings=${domainJob.findings} onOpenReport=${() => onOpenReport(domainJob.id)} />
          <${AiInsights} jobId=${domainJob.id} />
          <${FindingsPanel} findings=${domainJob.findings} />`
        : html`<div class=${domainJob.status === 'rejected' ? 'no' : 'muted'}>
            ${domainJob.status === 'rejected' ? '🚫 이 대상은 점검할 수 없습니다.' : ''}
            ${domainJob.gateDecision?.reason ? html`<div class="muted" style=${{ marginTop: 4, fontSize: 13 }}>${friendlyGateReason(domainJob.gateDecision.reason)}</div>` : ''}
          </div>`}
      </div>`}

      ${tab === 'sast' && html`
        <div class="filebox">
          <h3 style=${{ margin:'0 0 10px' }}>🔬 소스코드 SAST — 정적 보안 분석</h3>
          <div class="muted" style=${{ marginBottom:10, fontSize:13 }}>JS/TS·Python·PHP·Java·Go·Ruby 등 소스 파일을 붙여넣거나 업로드하면 SQL 인젝션·XSS·명령 인젝션·역직렬화·하드코딩 시크릿 등 <b>23개 룰</b>로 즉시 분석합니다.</div>
          <div class="row">
            <div style=${{ flex:0 }}><label>파일명(언어 감지용)</label><input value=${sastFilename} onChange=${e=>setSastFilename(e.target.value)} placeholder="app.js" /></div>
            <div style=${{ flex:0 }}><label>파일 업로드</label><input type="file" onChange=${onSastFile} /></div>
          </div>
          <label>소스코드 붙여넣기</label>
          <textarea rows="10" class="mono" value=${sastCode} placeholder="// 취약한 코드를 붙여넣으세요\nconst r = db.query('SELECT * FROM users WHERE id=' + req.params.id);" onChange=${e=>setSastCode(e.target.value)}></textarea>
          <div style=${{ marginTop:10, textAlign:'center' }}><button class="primary" onClick=${scanSast} disabled=${sastBusy}>${sastBusy ? '분석 중…' : '🔍 SAST 분석'}</button></div>
        </div>
        ${sastResult && html`<div class="panel result-card" style=${{ marginTop:14 }}>
          <div style=${{ display:'flex', justifyContent:'space-between', flexWrap:'wrap', gap:8 }}>
            <b>SAST 결과</b> <span class="muted">· ${sastResult.filename} · ${sastResult.count}건 탐지</span>
            <${FixPromptButton} findings=${sastResult.findings} target=${sastResult.filename} />
          </div>
          <div style=${{ margin:'10px 0' }}><${ScoreBadge} findings=${sastResult.findings} /></div>
          <${FindingsPanel} findings=${sastResult.findings} />
        </div>`}
      `}

      ${tab === 'authed' && html`
        <div class="filebox">
          <h3 style=${{ margin:'0 0 10px' }}>🔐 인증 세션 점검 — 로그인 후 영역 분석</h3>
          <div class="muted" style=${{ marginBottom:10, fontSize:13 }}>세션 쿠키 또는 Bearer 토큰을 입력하면 로그인 후 영역(인증이 필요한 페이지)의 보안 헤더·CORS·인증 설정을 점검합니다.</div>
          <label>도메인 / URL</label>
          <input value=${authedTarget} placeholder="https://app.example.com" onChange=${e=>setAuthedTarget(e.target.value)} />
          <label>세션 쿠키 (선택)</label>
          <input value=${authedCookie} placeholder="sessionid=abc123; csrftoken=xyz" onChange=${e=>setAuthedCookie(e.target.value)} class="mono" />
          <label>Authorization 헤더 값 (선택)</label>
          <input value=${authedHeader} placeholder="Bearer eyJhbGciOi..." onChange=${e=>setAuthedHeader(e.target.value)} class="mono" />
          <label class="attest" style=${{ marginTop:12 }}>
            <input type="checkbox" checked=${authedAttested} onChange=${e=>setAuthedAttested(e.target.checked)} />
            <span>본인이 소유하거나 점검 권한을 보유한 대상입니다. (필수)</span>
          </label>
          <div style=${{ marginTop:10, textAlign:'center' }}><button class="primary" onClick=${scanAuthed} disabled=${authedBusy || !authedAttested}>${authedBusy ? '점검 중…' : '🔐 인증 점검 시작'}</button></div>
          <div class="muted" style=${{ fontSize:12, marginTop:6, textAlign:'center' }}>현재 버전: 비인증 점검 수행 (인증 세션 워커 주입은 v2 예정)</div>
        </div>
        ${authedJob?.status === 'completed' && html`<div class="panel result-card" style=${{ marginTop:14 }}>
          <b>인증 점검 결과</b> <span class="muted">· ${authedJob.findings.length}건</span>
          <div style=${{ margin:'10px 0' }}><${ScoreBadge} findings=${authedJob.findings} /></div>
          <${FindingsPanel} findings=${authedJob.findings} />
        </div>`}
      `}

      ${tab === 'pentest' && html`
        <div class="filebox">
          <h3 style=${{ margin: '0 0 6px' }}>🧪 수동 점검 (Pentest) — 해킹 테스터 직접 테스트</h3>
          <div class="muted" style=${{ marginBottom: 10, fontSize: 13 }}>
            권한 보유가 확인된(attested) 대상에 한해, 범위 밖 호스트로는 패킷이 나가지 않으며(egress 하드 차단) 모든 요청이 감사로그에 기록됩니다.
            비파괴 원칙(GET·안전 마커)을 따르며, 상태변경 메서드(POST/PUT/PATCH/DELETE)는 별도 active 승인이 필요합니다.
          </div>
          <label>대상 (도메인 / URL / IP[:포트])</label>
          <input value=${ptTarget} placeholder="https://app.example.com  또는  127.0.0.1:8080" onChange=${e => setPtTarget(e.target.value)} class="mono" />
          <label class="attest" style=${{ marginTop: 10 }}>
            <input type="checkbox" checked=${ptAttested} onChange=${e => setPtAttested(e.target.checked)} />
            <span>본인이 소유하거나 점검 권한을 보유한 대상입니다. (필수)</span>
          </label>
          <div class="seg" style=${{ marginTop: 12 }}>
            <button class=${ptMode === 'repeater' ? 'on' : ''} onClick=${() => setPtMode('repeater')}>📡 요청 워크벤치 (Repeater)</button>
            <button class=${ptMode === 'playbook' ? 'on' : ''} onClick=${() => setPtMode('playbook')}>🎯 유도 공격 (Playbook)</button>
          </div>

          ${ptMode === 'repeater' && html`<div style=${{ marginTop: 12 }}>
            <div class="row" style=${{ gap: 8 }}>
              <div style=${{ flex: 0, minWidth: 120 }}><label>메서드</label>
                <select value=${ptMethod} onChange=${e => setPtMethod(e.target.value)}>
                  ${['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => html`<option key=${m} value=${m}>${m}</option>`)}
                </select></div>
              <div style=${{ flex: 2 }}><label>경로 + 쿼리</label>
                <input value=${ptPath} placeholder="/admin?id=1" onChange=${e => setPtPath(e.target.value)} class="mono" /></div>
            </div>
            <label>요청 헤더 (한 줄에 하나, "이름: 값")</label>
            <textarea rows="3" value=${ptHeaders} placeholder=${'Authorization: Bearer ...\nX-Original-URL: /admin'} onChange=${e => setPtHeaders(e.target.value)} class="mono"></textarea>
            ${['POST', 'PUT', 'PATCH', 'DELETE'].includes(ptMethod) && html`<div>
              <label>요청 바디</label>
              <textarea rows="3" value=${ptBody} onChange=${e => setPtBody(e.target.value)} class="mono"></textarea>
              <label class="attest" style=${{ marginTop: 8 }}>
                <input type="checkbox" checked=${ptActive} onChange=${e => setPtActive(e.target.checked)} />
                <span>상태변경 메서드(${ptMethod}) 전송을 승인합니다. (active)</span>
              </label>
            </div>`}
            <div style=${{ marginTop: 10, textAlign: 'center' }}>
              <button class="primary" onClick=${sendRepeater} disabled=${ptBusy || !ptAttested}>${ptBusy ? '전송 중…' : '📡 요청 전송'}</button>
            </div>
            ${ptResp && html`<div class="panel" style=${{ marginTop: 12 }}>
              ${ptResp.blocked
        ? html`<div style=${{ fontWeight: 700, color: 'var(--crit)' }}>⛔ 차단됨</div><div class="muted" style=${{ marginTop: 4 }}>${ptResp.blocked}</div>`
        : html`
                  <div style=${{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span class="pill">${ptResp.request.method}</span>
                    <span class="mono" style=${{ fontSize: 12 }}>${ptResp.request.url}</span>
                    ${ptResp.response && html`<span class=${'badge ' + statusClass(ptResp.response.status)}>${ptResp.response.status} ${ptResp.response.statusText}</span>`}
                    ${ptResp.response && html`<span class="muted" style=${{ fontSize: 12 }}>${ptResp.response.bytes.toLocaleString()}B · ${ptResp.response.timeMs}ms</span>`}
                  </div>
                  ${(ptResp.notes || []).length > 0 && html`<ul style=${{ margin: '8px 0', paddingLeft: 18, fontSize: 13 }}>${ptResp.notes.map((n, i) => html`<li key=${i}>${n}</li>`)}</ul>`}
                  ${ptResp.response && html`<details style=${{ marginTop: 6 }}><summary class="muted">응답 헤더</summary><pre class="mono" style=${{ whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 160, overflow: 'auto' }}>${Object.entries(ptResp.response.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}</pre></details>`}
                  ${ptResp.response && html`<details open style=${{ marginTop: 6 }}><summary class="muted">응답 본문${ptResp.response.truncated ? ' (앞 20KB)' : ''}</summary><pre class="mono" style=${{ whiteSpace: 'pre-wrap', fontSize: 12, maxHeight: 300, overflow: 'auto', background: 'var(--bg-soft)', padding: 8, borderRadius: 6 }}>${ptResp.response.body}</pre></details>`}
                `}
            </div>`}
          </div>`}

          ${ptMode === 'playbook' && html`<div style=${{ marginTop: 12 }}>
            <label>Playbook</label>
            <select value=${pbId} onChange=${e => { setPbId(e.target.value); setPbResult(null); }}>
              ${playbooks.map(p => html`<option key=${p.id} value=${p.id}>${p.name}${p.active ? ' ⚠' : ''}</option>`)}
            </select>
            <div class="muted" style=${{ fontSize: 13, margin: '6px 0' }}>${curPb()?.desc || ''}${curPb()?.active ? ' · 안전 마커 페이로드를 전송합니다(비파괴).' : ''}</div>
            ${(curPb()?.needs || []).includes('path') && html`<div><label>경로 (path)</label><input value=${pbPath} placeholder="/admin  또는  /users/123" onChange=${e => setPbPath(e.target.value)} class="mono" /></div>`}
            ${(curPb()?.needs || []).includes('param') && html`<div><label>파라미터 (param)</label><input value=${pbParam} placeholder="id" onChange=${e => setPbParam(e.target.value)} class="mono" /></div>`}
            <div style=${{ marginTop: 10, textAlign: 'center' }}>
              <button class="primary" onClick=${execPlaybook} disabled=${pbBusy || !ptAttested}>${pbBusy ? '실행 중…' : '🎯 Playbook 실행'}</button>
            </div>
            ${pbResult && html`<div class="panel result-card" style=${{ marginTop: 12 }}>
              <b>Playbook 결과</b> <span class="muted">· ${pbResult.host} · ${pbResult.findings.length}건</span>
              <div style=${{ margin: '10px 0' }}><${ScoreBadge} findings=${pbResult.findings} /></div>
              <${FindingsPanel} findings=${pbResult.findings} />
            </div>`}
          </div>`}
        </div>
      `}

      ${tab === 'intel' && html`
        <div class="filebox">
          <h3 style=${{ margin:'0 0 10px' }}>🕵️ 위협 인텔 — 유출 이력 확인</h3>
          <div class="muted" style=${{ marginBottom:10, fontSize:13 }}>HIBP(Have I Been Pwned) 공개 API로 해당 도메인의 이메일 계정 유출 이력을 조회합니다. (무료 공개 API)</div>
          <label>도메인</label>
          <div class="searchbox">
            <span class="icon">🕵️</span>
            <input value=${intelDomain} placeholder="example.com" onChange=${e=>setIntelDomain(e.target.value)} onKeyDown=${e=>e.key==='Enter'&&checkIntel()} />
            <button class="primary" onClick=${checkIntel} disabled=${intelBusy}>${intelBusy ? '조회 중…' : '유출 조회'}</button>
          </div>
          ${intelResult && html`<div style=${{ marginTop:14 }}>
            ${intelResult.breached
              ? html`<div class="panel" style=${{ borderLeft:'4px solid var(--crit)' }}>
                  <div class="no" style=${{ fontWeight:700, fontSize:16, marginBottom:8 }}>
                    ⚠ 데이터 침해 사고 ${intelResult.count}건 확인
                  </div>
                  <div style=${{ marginBottom:12 }}>
                    <b>${intelResult.domain}</b> 에서 총 <b>${(intelResult.totalPwned||0).toLocaleString()}</b>개 계정이
                    공개 데이터 침해에 포함된 것으로 확인됩니다.
                  </div>
                  ${(intelResult.breaches||[]).map((b) => html`
                    <div key=${b.Name} style=${{ borderBottom:'1px solid var(--line)', padding:'10px 0', marginBottom:8 }}>
                      <div style=${{ display:'flex', gap:10, flexWrap:'wrap', alignItems:'center', marginBottom:4 }}>
                        <b>${b.Title}</b>
                        <span class="pill">${b.BreachDate}</span>
                        <span class="badge sev-critical">${(b.PwnCount||0).toLocaleString()} 계정</span>
                        ${!b.IsVerified && html`<span class="pill">미검증</span>`}
                      </div>
                      <div class="muted" style=${{ fontSize:12 }}>유출 정보: ${(b.DataClasses||[]).slice(0,5).join(', ')}</div>
                    </div>
                  `)}
                  <div style=${{ marginTop:8, padding:'10px', background:'var(--bg-soft)', borderRadius:8, fontSize:13 }}>
                    🔧 <b>권고 조치</b>: 해당 도메인 사용자 전원에게 비밀번호 즉시 변경 안내,
                    MFA 강제 적용, 유출된 데이터 유형에 따라 추가 보호 조치(카드 재발급 등)를 시행하십시오.
                  </div>
                </div>`
              : html`<div class="panel" style=${{ borderLeft:'4px solid var(--low)' }}>
                  <div class="ok" style=${{ fontWeight:700, fontSize:15 }}>✅ 공개 침해 이력 없음</div>
                  <div class="muted" style=${{ marginTop:6 }}>
                    HIBP(Have I Been Pwned) 공개 데이터베이스에 <b>${intelResult.domain}</b> 의 침해 사고 기록이 없습니다.
                    단, 비공개·미공개 침해는 포함되지 않을 수 있습니다.
                  </div>
                </div>`}
          </div>`}
        </div>
      `}

      ${!domainJob && !fileJob && !bulk && tab === 'domain' && html`<div class="coverage">
        <div class="cov-title">엔터프라이즈 점검 커버리지</div>
        <div class="cov-grid">
          ${COVERAGE_CARDS.map((c) => html`<div key=${c.t} class="cov-card">
            <div class="cov-ic">${c.ic}</div><div class="cov-h">${c.t}</div><div class="cov-d">${c.d}</div>
          </div>`)}
        </div>
        <div class="cov-foot">표준 매핑: OWASP Top 10 · CWE · OWASP ASVS · ISMS-P · ISO/IEC 27001 · PCI-DSS · NIST CSF · 개인정보보호법/GDPR · 전자금융감독규정</div>
      </div>`}
    </div>`;
}

const COVERAGE_CARDS = [
  { ic: '🌐', t: '외부 노출 자산 탐색', d: '숨겨진 서브도메인·열린 포트·관리되지 않는 서버를 외부에서 찾아냅니다' },
  { ic: '📧', t: '이메일 위조 방지 설정', d: '내 도메인 명의로 위조 이메일을 보낼 수 없도록 SPF·DMARC·DKIM 설정을 점검합니다' },
  { ic: '🔐', t: 'HTTPS 암호화 통신', d: '최신 암호화 방식을 쓰는지, 인증서 만료 여부, 약한 암호 사용 여부를 점검합니다' },
  { ic: '🧱', t: '브라우저 보안 설정', d: '악성 스크립트 차단(CSP)·도청 방지(HSTS)·클릭재킹 방지 등 브라우저 보호 설정을 점검합니다' },
  { ic: '🔁', t: '데이터 접근 제어', d: '다른 사이트에서 내 데이터에 무단 접근하는 것을 막는 CORS 설정을 점검합니다' },
  { ic: '🍪', t: '로그인 세션 보안', d: '세션 쿠키가 탈취·도용되지 않도록 보안 속성이 올바르게 설정되었는지 점검합니다' },
  { ic: '📂', t: '유출 파일 탐지', d: '설정 파일(.env)·소스코드(.git)·백업 파일 등이 외부에 노출되지 않았는지 점검합니다' },
  { ic: '📦', t: '소프트웨어 취약점', d: '사용 중인 라이브러리·패키지에 알려진 보안 결함이 있는지 11개 언어 생태계에서 점검합니다' },
  { ic: '📊', t: '위험도 측정 & 법적 기준', d: '발견된 문제를 위험도 순으로 정렬하고, ISMS-P·개인정보보호법·PCI-DSS 등 8개 규정에 매핑합니다' },
];

const NAV = [
  { path: '#/', label: '⚡ 빠른 점검', roles: ['admin', 'scanner'] },
  { path: '#/dashboard', label: '대시보드', roles: ['admin', 'scanner', 'auditor', 'viewer'] },
  { path: '#/assets', label: '자산 · 게이트', roles: ['admin', 'scanner', 'auditor', 'viewer'] },
  { path: '#/consents', label: '동의 · 범위', roles: ['admin', 'scanner', 'auditor', 'viewer'] },
  { path: '#/scans', label: '점검', roles: ['admin', 'scanner', 'auditor', 'viewer'] },
  { path: '#/audit', label: '감사로그', roles: ['admin', 'auditor'] },
];

function App() {
  const [showOnboard, setShowOnboard] = useState(() => !localStorage.getItem('sentinel_onboard_done'));
  const [user, setUser] = useState(null);
  const [route, setRoute] = useState(location.hash || '#/');
  const [reportJob, setReportJob] = useState(null);
  const [toastNode, toast] = useToast();

  useEffect(() => {
    const onHash = () => setRoute(location.hash || '#/');
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    if (tokenStore.get()) api('GET', '/api/me').then((r) => { if (r.ok) setUser(r.json); else location.hash = '#/login'; });
  }, []);

  if (!user || route === '#/login') return html`<${Login} onLogin=${setUser} />`;

  const logout = () => { tokenStore.clear(); setUser(null); location.hash = '#/login'; };
  const navTitle = NAV.find((n) => n.path === route && n.roles.includes(user.role))?.label;
  const title = reportJob ? '리포트' : (navTitle || (['admin', 'scanner'].includes(user.role) ? '⚡ 빠른 점검' : '대시보드'));

  const canScan = ['admin', 'scanner'].includes(user.role);
  let page;
  if (reportJob) page = html`<${Report} jobId=${reportJob} onBack=${() => setReportJob(null)} />`;
  else if (route === '#/assets') page = html`<${Assets} user=${user} toast=${toast} />`;
  else if (route === '#/consents') page = html`<${Consents} user=${user} toast=${toast} />`;
  else if (route === '#/scans') page = html`<${Scans} user=${user} toast=${toast} onOpenReport=${setReportJob} />`;
  else if (route === '#/audit') page = html`<${Audit} />`;
  else if (route === '#/dashboard') page = html`<${Dashboard} />`;
  else page = canScan
    ? html`<${Quick} user=${user} toast=${toast} onOpenReport=${setReportJob} />`
    : html`<${Dashboard} />`;

  const isHero = !reportJob && route === '#/' && canScan;
  const goMain = (e) => { if (e) e.preventDefault(); setReportJob(null); location.hash = '#/'; };

  return html`
    <div>
      <header class="appbar">
        <a class="brand" href="#/" title="메인으로" onClick=${goMain}>
          <span class="logo">🛡</span>SENTINEL<small>ASM</small>
        </a>
        <nav>
          ${NAV.filter((n) => n.roles.includes(user.role)).map((n) => html`
            <a key=${n.path} href=${n.path} class=${route === n.path && !reportJob ? 'active' : ''} onClick=${() => setReportJob(null)}>${n.label}</a>`)}
        </nav>
        <div class="who">
          <span><b>${user.displayName || user.email}</b> <span class="role-badge">${user.role}</span></span>
          <span class="muted">${user.tenantName || user.tenantId}</span>
          <a href="#" onClick=${logout}>로그아웃</a>
        </div>
      </header>
      ${isHero
        ? html`<div class="container" style=${{ paddingTop: 0 }}>
            ${showOnboard && html`<div style=${{ padding: '20px 0 0' }}>
              <${OnboardingBanner} onDismiss=${() => { localStorage.setItem('sentinel_onboard_done','1'); setShowOnboard(false); }} />
            </div>`}
            ${page}
          </div>`
        : html`<div class="container">
            <div class="page-title">${title}</div>
            ${page}
          </div>`}
    </div>
    ${toastNode}`;
}

createRoot(document.getElementById('root')).render(html`<${App} />`);
