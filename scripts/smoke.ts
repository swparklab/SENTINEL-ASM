/**
 * 종단간 스모크 테스트.
 * 게이트 차단 → 소유권 검증 → 동의 등록 → 점검 실행 → 리포트 → kill-switch →
 * 감사체인 검증 → RBAC 차단 까지 핵심 흐름을 자동 검증한다.
 * 사용: 서버 기동 후 `npm run smoke` (BASE 환경변수로 주소 변경 가능).
 */
export {};
const BASE = process.env.BASE ?? 'http://localhost:8787';
let pass = 0, fail = 0;

function ok(cond: boolean, label: string, detail = '') {
  if (cond) { pass++; console.log(`  ✅ ${label}`); }
  else { fail++; console.log(`  ❌ ${label} ${detail}`); }
}

async function api(method: string, path: string, token?: string, body?: unknown) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json: any; try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json };
}

async function login(email: string, password: string) {
  const r = await api('POST', '/api/auth/login', undefined, { email, password });
  return r.json.token as string;
}

async function main() {
  console.log(`\n▶ SENTINEL-ASM 스모크 테스트 (${BASE})\n`);

  // 1) 인증
  const admin = await login('admin@hanbit.example', 'sentinel!admin');
  ok(!!admin, '관리자 로그인 + JWT 발급');
  const viewer = await login('viewer@hanbit.example', 'sentinel!view');
  ok(!!viewer, '조회자 로그인');

  // 2) 자산 생성
  const created = await api('POST', '/api/assets', admin, { type: 'host', value: '127.0.0.1', label: '스모크 대상', businessCriticality: 'high' });
  ok(created.status === 201, '자산 생성', `(status=${created.status})`);
  const assetId = created.json.id;

  // 3) 게이트 차단: 소유권 미검증 자산 점검 시도 → rejected
  const rejected = await api('POST', '/api/scans', admin, { assetId, modules: ['asm', 'config', 'cve'], intensity: 'standard' });
  ok(rejected.status === 422 && rejected.json.status === 'rejected', '소유권 미검증 → 게이트 차단', `(${rejected.json.gateDecision?.reason})`);

  // 4) 소유권 검증 (전자서명 위탁계약 — 결정적 경로)
  await api('POST', `/api/assets/${assetId}/ownership/challenge`, admin, { method: 'contract-esign' });
  const verified = await api('POST', `/api/assets/${assetId}/ownership/verify`, admin, { contractSignatureHash: 'sig_demo_0xABCDEF123456', businessRegistryVerified: true });
  ok(verified.json.proof?.status === 'verified', '소유권 검증(전자서명) 통과');

  // 5) 동의·범위 등록 (점검 윈도우 = 지금 ±1h)
  const start = new Date(Date.now() - 3600_000).toISOString();
  const end = new Date(Date.now() + 3600_000).toISOString();
  const consent = await api('POST', '/api/consents', admin, {
    assetId, allowedTargets: ['127.0.0.1'], allowedPorts: [8787, 22, 80], maxIntensity: 'standard', windowStart: start, windowEnd: end,
  });
  ok(consent.status === 201, '동의·범위 등록');
  const consentId = consent.json.id;

  // 6) 점검 실행 → 큐 진입
  const scan = await api('POST', '/api/scans', admin, { assetId, modules: ['asm', 'config', 'cve'], intensity: 'standard' });
  ok(scan.status === 202 && scan.json.status === 'queued', '게이트 통과 → 점검 큐 진입');
  const jobId = scan.json.id;

  // 7) 완료 대기
  let job: any;
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 400));
    job = (await api('GET', `/api/scans/${jobId}`, admin)).json;
    if (job.status === 'completed' || job.status === 'failed') break;
  }
  ok(job?.status === 'completed', '점검 완료', `(status=${job?.status})`);
  ok(Array.isArray(job?.findings) && job.findings.some((f: any) => f.module === 'asm'), 'ASM 모듈 발견사항 존재(오픈 포트 8787)');
  ok(job?.findings.every((f: any) => typeof f.riskScore === 'number'), '모든 발견에 위험점수 산정');

  // 8) 리포트
  const report = await api('GET', `/api/scans/${jobId}/report`, admin);
  ok(report.status === 200 && typeof report.json.executive?.overallScore === 'number', '리포트 생성(경영진 요약)');

  // 9) 범위 밖 자산은 egress 로 차단됨을 간접 확인: example.com 자산 점검 시도(동의 없음 → 게이트 차단)
  const ex = await api('POST', '/api/scans', admin, { assetId: 'ast_example_com', modules: ['asm'], intensity: 'standard' });
  ok(ex.status === 422, '동의 없는 타 자산 → 게이트 차단');

  // 10) kill-switch: 동의 철회
  const revoke = await api('POST', `/api/consents/${consentId}/revoke`, admin);
  ok(revoke.status === 200, '동의 철회(kill-switch)', `(cid=${consentId} status=${revoke.status} body=${JSON.stringify(revoke.json).slice(0, 120)})`);
  const afterRevoke = await api('POST', '/api/scans', admin, { assetId, modules: ['asm'], intensity: 'standard' });
  ok(afterRevoke.status === 422, '철회 후 점검 시도 → 게이트 차단', `(status=${afterRevoke.status} reason=${afterRevoke.json.gateDecision?.reason})`);

  // 11) RBAC: viewer 는 자산 생성 불가
  const forbidden = await api('POST', '/api/assets', viewer, { type: 'domain', value: 'x.example', businessCriticality: 'low' });
  ok(forbidden.status === 403, 'RBAC: viewer 자산 생성 차단(403)');

  // 12) 감사 체인 무결성 (auditor)
  const auditor = await login('auditor@hanbit.example', 'sentinel!audit');
  const chain = await api('GET', '/api/audit/verify', auditor);
  ok(chain.json?.valid === true, '감사로그 해시체인 무결성 검증', `(count=${chain.json?.count})`);
  const viewerAudit = await api('GET', '/api/audit', viewer);
  ok(viewerAudit.status === 403, 'RBAC: viewer 감사로그 접근 차단(403)');

  console.log(`\n결과: ${pass} 통과 / ${fail} 실패\n`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
