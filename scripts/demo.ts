/** 라이브 시연: 실제 API 를 순서대로 호출하고 결과를 사람이 읽기 좋게 출력. */
export {};
const BASE = process.env.BASE ?? 'http://localhost:8787';
const log = (...a: unknown[]) => console.log(...a);
const hr = () => log('─'.repeat(72));

async function api(method: string, path: string, token?: string, body?: unknown) {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers['authorization'] = `Bearer ${token}`;
  const res = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let json: any; try { json = await res.json(); } catch { json = null; }
  return { status: res.status, json };
}

async function main() {
  hr(); log('🛡  SENTINEL-ASM 라이브 시연  ·', BASE); hr();

  // 1) 로그인
  const login = await api('POST', '/api/auth/login', undefined, { email: 'admin@hanbit.example', password: 'sentinel!admin' });
  const token = login.json.token as string;
  log(`\n[1] 로그인  → ${login.status}  사용자=${login.json.user.displayName} 역할=${login.json.user.role} 테넌트=${login.json.user.tenantId}`);

  // 2) 자산 등록 (우리 콘솔 서버 자신을 대상으로 — 권한 보유)
  const asset = await api('POST', '/api/assets', token, { type: 'host', value: '127.0.0.1:8787', label: '데모 콘솔(자체)', businessCriticality: 'high' });
  const assetId = asset.json.id;
  log(`[2] 자산 등록 → ${asset.status}  ${asset.json.value} (중요도=${asset.json.businessCriticality})`);

  // 3) 게이트 차단 시연 (소유권 미검증)
  const blocked = await api('POST', '/api/scans', token, { assetId, modules: ['config'], intensity: 'standard' });
  log(`[3] 미검증 상태 점검 시도 → ${blocked.status} (${blocked.json.status})  🚫 ${blocked.json.gateDecision?.reason}`);

  // 4) 소유권 검증 (전자서명 위탁계약)
  await api('POST', `/api/assets/${assetId}/ownership/challenge`, token, { method: 'contract-esign' });
  const verified = await api('POST', `/api/assets/${assetId}/ownership/verify`, token, { contractSignatureHash: 'sig_live_demo_0xA1B2C3', businessRegistryVerified: true });
  log(`[4] 소유권 검증(전자서명) → ${verified.json.proof.status}  (${verified.json.proof.detail})`);

  // 5) 동의·범위 등록 (egress allowlist = 127.0.0.1, 포트 8787 포함, 윈도우 ±1h)
  const consent = await api('POST', '/api/consents', token, {
    assetId, allowedTargets: ['127.0.0.1'], allowedPorts: [8787, 80, 443, 22],
    maxIntensity: 'standard',
    windowStart: new Date(Date.now() - 3600_000).toISOString(),
    windowEnd: new Date(Date.now() + 3600_000).toISOString(),
  });
  log(`[5] 동의·범위 등록 → ${consent.status}  허용대상=${consent.json.scope.allowedTargets.join(',')} 포트=${consent.json.scope.allowedPorts.join(',')} 최대강도=${consent.json.scope.maxIntensity}`);

  // 6) 게이트 통과 점검 실행
  const scan = await api('POST', '/api/scans', token, { assetId, modules: ['asm', 'config', 'cve', 'dast'], intensity: 'standard' });
  const jobId = scan.json.id;
  log(`[6] 점검 실행 → ${scan.status} (${scan.json.status})  ✅ ${scan.json.gateDecision?.reason}  egress=${scan.json.egressAllowlist.join(',')}`);

  // 7) 완료 대기
  let job: any;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 300));
    job = (await api('GET', `/api/scans/${jobId}`, token)).json;
    if (['completed', 'failed', 'aborted'].includes(job.status)) break;
  }
  log(`[7] 점검 완료 → ${job.status}  발견 ${job.findings.length}건`);

  // 8) 발견사항 (위험 우선순위 순)
  hr(); log('발견사항 (위험점수 내림차순)'); hr();
  for (const f of job.findings) {
    log(` [${f.severity.toUpperCase().padEnd(8)}] 위험 ${String(f.riskScore).padStart(3)} · ${f.module.toUpperCase().padEnd(6)} · ${f.title}`);
    if (f.cve) log(`            └ ${f.cve}${f.kev ? ' (KEV)' : ''}${typeof f.epss === 'number' ? ` EPSS ${(f.epss * 100).toFixed(0)}%` : ''}`);
  }
  if (!job.findings.length) log(' (없음)');

  // 9) 리포트 요약
  const report = (await api('GET', `/api/scans/${jobId}/report`, token)).json;
  hr(); log('리포트 — 경영진 요약'); hr();
  log(` 종합 위험도 : ${report.executive.overallScore}/100 (${report.executive.band.toUpperCase()})`);
  log(` 핵심 메시지 : ${report.executive.headline}`);
  log(` 컴플라이언스: ${Object.keys(report.compliance).join(', ') || '없음'}`);
  for (const [fw, v] of Object.entries<any>(report.compliance)) {
    log(`   - ${fw}: ${v.controls.slice(0, 3).join(' / ')}${v.controls.length > 3 ? ' …' : ''}`);
  }

  // 10) kill-switch + 게이트 재차단
  const cid = consent.json.id;
  await api('POST', `/api/consents/${cid}/revoke`, token);
  const afterKill = await api('POST', '/api/scans', token, { assetId, modules: ['config'], intensity: 'standard' });
  log(`\n[10] 동의 철회(kill-switch) 후 재점검 → ${afterKill.status}  🚫 ${afterKill.json.gateDecision?.reason}`);

  // 11) 감사 체인 무결성
  const chain = (await api('GET', '/api/audit/verify', token)).json;
  log(`[11] 감사로그 해시체인 → ${chain.valid ? '무결성 정상 ✅' : '변조 탐지 ⚠'} (레코드 ${chain.count}건)`);

  hr(); log('시연 완료 — 콘솔: ' + BASE); hr();
}

main().catch((e) => { console.error(e); process.exit(1); });
