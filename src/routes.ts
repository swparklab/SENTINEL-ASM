/**
 * HTTP API 라우트 (설계 §2.1 API 게이트웨이 / §6.3 REST API).
 * 모든 보호된 엔드포인트는 인증(requireAuth) + 인가(requirePermission) + 테넌트 격리를 강제한다.
 */
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { repos } from './db/store.js';
import { audit, queryAudit, verifyAuditChain } from './db/audit.js';
import { id, now } from './util.js';
import {
  authenticate, issueToken, requireAuth, requirePermission,
} from './auth/auth.js';
import { issueOwnershipChallenge, verifyOwnership } from './modules/authorizationGate/ownership.js';
import { revokeConsent, currentConsentStatus, computeEgressAllowlist } from './modules/authorizationGate/gate.js';
import { orchestrator } from './modules/orchestrator/orchestrator.js';
import { scanSoftware, scanSoftwareProject, scanDomainQuick, parseTarget } from './modules/quick/quick.js';
import { authorizeTarget, runProbe, runPlaybook, recordPentestJob, PLAYBOOKS, type PlaybookId } from './modules/pentest/pentest.js';
import { EgressViolation } from './modules/scanners/egress.js';
import { aiStatus, analyzeFindings } from './modules/ai/index.js';
import { runSast } from './modules/scanners/sast.js';
import { checkHibpDomain } from './modules/scanners/cloud.js';
import { buildReport, reportToMarkdown, reportToHtml } from './modules/reports/report.js';
import { aggregateRisk } from './modules/risk/scoring.js';
import type { Asset, Consent } from './types.js';

function validate<S extends z.ZodTypeAny>(schema: S, body: unknown): { ok: true; data: z.infer<S> } | { ok: false; error: string } {
  const r = schema.safeParse(body);
  if (r.success) return { ok: true, data: r.data };
  return { ok: false, error: r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join(', ') };
}

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  // ───────────── 인증 ─────────────
  app.post('/api/auth/login', async (req, reply) => {
    const v = validate(z.object({ email: z.string().email(), password: z.string().min(1) }), req.body);
    if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
    const user = authenticate(v.data.email, v.data.password);
    if (!user) {
      audit({ action: 'auth.login', target: v.data.email, outcome: 'deny', reason: '인증 실패' });
      return reply.code(401).send({ error: 'unauthorized', message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    }
    audit({ tenantId: user.tenantId, actor: user.email, action: 'auth.login', outcome: 'allow' });
    return reply.send({
      token: issueToken(user),
      user: { id: user.id, email: user.email, role: user.role, displayName: user.displayName, tenantId: user.tenantId },
    });
  });

  // 이하 모든 라우트는 인증 필요
  app.register(async (api) => {
    api.addHook('preHandler', requireAuth);

    api.get('/api/me', async (req) => {
      const tenant = repos.tenants.get(req.auth!.tenantId);
      return { ...req.auth, tenantName: tenant?.name };
    });

    // ───────────── 대시보드 (설계 §1.2 단일 콘솔) ─────────────
    api.get('/api/dashboard', { preHandler: requirePermission('asset:read') }, async (req) => {
      const t = req.auth!.tenantId;
      const assets = repos.assets.list(t);
      const jobs = repos.scanJobs.list(t);
      const completed = jobs.filter((j) => j.status === 'completed');
      const allFindings = completed.flatMap((j) => j.findings);
      const agg = aggregateRisk(allFindings);
      return {
        assets: {
          total: assets.length,
          verified: assets.filter((a) => a.ownership?.status === 'verified').length,
          unverified: assets.filter((a) => a.ownership?.status !== 'verified').length,
        },
        scans: {
          total: jobs.length,
          completed: completed.length,
          queuedOrRunning: jobs.filter((j) => j.status === 'queued' || j.status === 'running').length,
          rejected: jobs.filter((j) => j.status === 'rejected').length,
        },
        risk: agg,
        recentJobs: jobs.sort((a, b) => Date.parse(b.queuedAt) - Date.parse(a.queuedAt)).slice(0, 8)
          .map((j) => ({ id: j.id, assetId: j.assetId, status: j.status, intensity: j.intensity, queuedAt: j.queuedAt, findings: j.findings.length })),
        // 추세: 완료 점검의 시계열 위험도 (최근 20건, 오름차순)
        trend: completed
          .slice().sort((a, b) => Date.parse(a.finishedAt ?? a.queuedAt) - Date.parse(b.finishedAt ?? b.queuedAt))
          .slice(-20)
          .map((j) => ({ ts: j.finishedAt ?? j.queuedAt, score: aggregateRisk(j.findings).score, findings: j.findings.length, asset: assets.find((a) => a.id === j.assetId)?.value ?? j.assetId })),
        // 자산별 최신 위험도
        assetRisk: assets.map((a) => {
          const latest = completed.filter((j) => j.assetId === a.id)
            .sort((x, y) => Date.parse(y.finishedAt ?? y.queuedAt) - Date.parse(x.finishedAt ?? x.queuedAt))[0];
          if (!latest) return null;
          const ar = aggregateRisk(latest.findings);
          return { asset: a.value, criticality: a.businessCriticality, score: ar.score, band: ar.band, findings: latest.findings.length, jobId: latest.id, ts: latest.finishedAt };
        }).filter(Boolean).sort((a, b) => (b!.score) - (a!.score)),
        // 전체 상위 위험 발견
        topFindings: allFindings.slice().sort((x, y) => (y.riskScore ?? 0) - (x.riskScore ?? 0)).slice(0, 8)
          .map((f) => ({ title: f.title, target: f.target, severity: f.severity, riskScore: f.riskScore, cve: f.cve, owasp: f.owasp, cwe: f.cwe })),
      };
    });

    // ───────────── 자산 ─────────────
    api.get('/api/assets', { preHandler: requirePermission('asset:read') }, async (req) =>
      repos.assets.list(req.auth!.tenantId));

    api.get('/api/assets/:id', { preHandler: requirePermission('asset:read') }, async (req, reply) => {
      const asset = repos.assets.get((req.params as any).id, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found' });
      return asset;
    });

    api.post('/api/assets', { preHandler: requirePermission('asset:write') }, async (req, reply) => {
      const v = validate(z.object({
        type: z.enum(['domain', 'host', 'web']),
        value: z.string().min(1),
        label: z.string().optional(),
        businessCriticality: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const asset: Asset = {
        id: id('ast'), tenantId: req.auth!.tenantId, type: v.data.type, value: v.data.value.trim().toLowerCase(),
        label: v.data.label, businessCriticality: v.data.businessCriticality, ownership: null,
        createdAt: now(), createdBy: req.auth!.email,
      };
      repos.assets.insert(asset);
      audit({ tenantId: asset.tenantId, actor: req.auth!.email, action: 'asset.create', target: asset.value, outcome: 'info', meta: { assetId: asset.id } });
      return reply.code(201).send(asset);
    });

    // ───────────── 소유권 검증 게이트 (설계 §3.1) ─────────────
    api.post('/api/assets/:id/ownership/challenge', { preHandler: requirePermission('ownership:verify') }, async (req, reply) => {
      const asset = repos.assets.get((req.params as any).id, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found' });
      const v = validate(z.object({ method: z.enum(['dns-txt', 'file-upload', 'meta-tag', 'contract-esign']) }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const proof = issueOwnershipChallenge(asset, v.data.method);
      return reply.send({ proof, instructions: challengeInstructions(asset, proof.method, proof.token) });
    });

    api.post('/api/assets/:id/ownership/verify', { preHandler: requirePermission('ownership:verify') }, async (req, reply) => {
      const asset = repos.assets.get((req.params as any).id, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found' });
      const v = validate(z.object({
        contractSignatureHash: z.string().optional(),
        businessRegistryVerified: z.boolean().optional(),
      }), req.body ?? {});
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const proof = await verifyOwnership(asset, v.data);
      return reply.send({ proof });
    });

    // ───────────── 동의·범위 (설계 §3.2) ─────────────
    api.get('/api/consents', { preHandler: requirePermission('consent:read') }, async (req) =>
      repos.consents.list(req.auth!.tenantId).map((c) => ({ ...c, status: currentConsentStatus(c) })));

    api.post('/api/consents', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        assetId: z.string(),
        allowedTargets: z.array(z.string()).default([]),
        allowedPorts: z.array(z.number().int().min(1).max(65535)).default([]),
        maxIntensity: z.enum(['passive', 'standard', 'aggressive']).default('standard'),
        windowStart: z.string(),
        windowEnd: z.string(),
        aggressiveApprovedBy: z.string().optional(),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const asset = repos.assets.get(v.data.assetId, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found', message: '자산 없음' });
      const consent: Consent = {
        id: id('cns'), tenantId: req.auth!.tenantId, assetId: asset.id,
        scope: { allowedTargets: v.data.allowedTargets, allowedPorts: v.data.allowedPorts, maxIntensity: v.data.maxIntensity },
        windowStart: v.data.windowStart, windowEnd: v.data.windowEnd,
        aggressiveApprovedBy: v.data.aggressiveApprovedBy,
        status: 'active', signedBy: req.auth!.email, signedAt: now(),
      };
      repos.consents.insert(consent);
      audit({ tenantId: consent.tenantId, actor: req.auth!.email, action: 'consent.create', target: asset.value, outcome: 'info', meta: { consentId: consent.id, scope: consent.scope } });
      return reply.code(201).send(consent);
    });

    api.post('/api/consents/:id/revoke', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const consent = repos.consents.get((req.params as any).id, req.auth!.tenantId);
      if (!consent) return reply.code(404).send({ error: 'not_found' });
      revokeConsent(consent, req.auth!.email);
      return reply.send({ ...consent, status: 'revoked' });
    });

    // ───────────── 점검 작업 (설계 §4) ─────────────
    api.get('/api/scans', { preHandler: requirePermission('scan:read') }, async (req) =>
      repos.scanJobs.list(req.auth!.tenantId).sort((a, b) => Date.parse(b.queuedAt) - Date.parse(a.queuedAt)));

    api.get('/api/scans/:id', { preHandler: requirePermission('scan:read') }, async (req, reply) => {
      const job = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found' });
      return job;
    });

    api.post('/api/scans', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        assetId: z.string(),
        modules: z.array(z.enum(['asm', 'config', 'cve', 'dast', 'access', 'ai'])).min(1),
        intensity: z.enum(['passive', 'standard', 'aggressive']).default('standard'),
        /** 활성(침투) 검증 — 취약점 실제 확정. 게이트에서 aggressive + 4-eyes 서면승인 통과 시에만 동작(비파괴 한정). */
        active: z.boolean().default(false),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const asset = repos.assets.get(v.data.assetId, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found', message: '자산 없음' });
      const consent = repos.consents.list(req.auth!.tenantId)
        .find((c) => c.assetId === asset.id && currentConsentStatus(c) === 'active');
      const job = orchestrator.enqueue({
        tenantId: req.auth!.tenantId, asset, consent,
        modules: v.data.modules, intensity: v.data.intensity, active: v.data.active, actor: req.auth!.email,
      });
      // 게이트 거부도 정상 응답(작업 객체에 사유 포함) — 클라이언트가 사유를 표시
      return reply.code(job.status === 'rejected' ? 422 : 202).send(job);
    });

    // ───────────── 빠른 점검 (Quick Scan, 저마찰 진입점) ─────────────
    // 1a) 소프트웨어 단일 파일 정적 분석
    api.post('/api/quick/sbom', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        filename: z.string().default('manifest'),
        content: z.string().min(1, '파일 내용이 비어 있습니다.'),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const { job, format, componentCount } = scanSoftware(req.auth!.tenantId, req.auth!.email, v.data.filename, v.data.content);
      return reply.code(201).send({ job, format, componentCount });
    });

    // 1c) SAST — 소스 파일 정적 보안 분석 (단독 엔드포인트)
    api.post('/api/quick/sast', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        filename: z.string().min(1),
        content: z.string().min(1),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const findings = runSast(v.data.filename, v.data.content);
      audit({ tenantId: req.auth!.tenantId, actor: req.auth!.email, action: 'quick.sast', target: v.data.filename, outcome: 'info', reason: `${findings.length}건 탐지` });
      return reply.code(200).send({ filename: v.data.filename, findings, count: findings.length });
    });

    // 1d) 위협 인텔 — HIBP 도메인 유출 확인 (무료 API)
    api.post('/api/quick/threatintel', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({ domain: z.string().min(1) }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const result = await checkHibpDomain(v.data.domain);
      audit({ tenantId: req.auth!.tenantId, actor: req.auth!.email, action: 'quick.threatintel', target: v.data.domain, outcome: 'info', reason: result.breached ? `침해 사고 ${result.count}건, 유출 계정 ${result.totalPwned?.toLocaleString()}개` : '침해 이력 없음' });
      return reply.code(200).send({ domain: v.data.domain, ...result });
    });

    // 1b) 소프트웨어 프로젝트(폴더/다중 파일) 통합 정적 분석
    api.post('/api/quick/sbom/project', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        projectName: z.string().optional(),
        files: z.array(z.object({ filename: z.string(), content: z.string() })).min(1).max(200),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const result = scanSoftwareProject(req.auth!.tenantId, req.auth!.email, v.data.files, v.data.projectName);
      return reply.code(201).send(result);
    });

    // 2) 도메인/URL 빠른 점검 — 권한 보유 전자 확인(attestation) 필수
    api.post('/api/quick/domain', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        target: z.string().min(1),
        attested: z.boolean(),
        deep: z.boolean().default(false),
        modules: z.array(z.enum(['asm', 'config', 'cve', 'dast', 'access', 'ai'])).min(1).default(['asm', 'config', 'cve', 'dast', 'access', 'ai']),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      if (!v.data.attested) {
        return reply.code(403).send({ error: 'attestation_required', message: '점검 권한 보유 확인(attestation)이 필요합니다. (설계 §0/§3)' });
      }
      try {
        const { job, normalizedHost, originalInput } = scanDomainQuick(req.auth!.tenantId, req.auth!.email, v.data.target, v.data.attested, v.data.modules, v.data.deep);
        return reply.code(job.status === 'rejected' ? 422 : 202).send({ ...job, normalizedHost, originalInput });
      } catch (e) {
        return reply.code(400).send({ error: 'bad_request', message: String(e instanceof Error ? e.message : e) });
      }
    });

    // 2b) 인증 세션 점검 — 쿠키·헤더 주입으로 로그인 후 영역 점검
    api.post('/api/quick/authed', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        target: z.string().min(1),
        attested: z.boolean(),
        /** 세션 쿠키 (예: "sessionid=abc123; csrftoken=xyz") */
        sessionCookie: z.string().optional(),
        /** 추가 요청 헤더 (예: {"Authorization":"Bearer token"}) */
        headers: z.record(z.string()).optional(),
        modules: z.array(z.enum(['asm', 'config', 'cve', 'dast', 'access', 'ai'])).default(['config', 'dast', 'access', 'ai']),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      if (!v.data.attested) return reply.code(403).send({ error: 'attestation_required', message: '점검 권한 보유 확인이 필요합니다.' });
      try {
        // 인증 정보를 동의·자산에 메타로 저장하고 점검 큐잉
        const { job, asset } = scanDomainQuick(
          req.auth!.tenantId, req.auth!.email, v.data.target, v.data.attested, v.data.modules as any,
        );
        // 인증 헤더는 job 메타에만 기록(실제 워커 주입은 향후 확장)
        if (v.data.sessionCookie || v.data.headers) {
          repos.scanJobs.update(job.id, { error: `[인증 세션 점검] cookie=${v.data.sessionCookie ? '있음' : '없음'}, headers=${Object.keys(v.data.headers ?? {}).join(',')} — 현재 버전은 비인증 점검 수행(인증 세션 워커 주입은 v2 예정)` });
        }
        audit({ tenantId: req.auth!.tenantId, actor: req.auth!.email, action: 'quick.authed', target: v.data.target, outcome: 'allow', reason: '인증 세션 점검 요청' });
        return reply.code(job.status === 'rejected' ? 422 : 202).send(job);
      } catch (e) {
        return reply.code(400).send({ error: 'bad_request', message: String(e instanceof Error ? e.message : e) });
      }
    });

    // 3) 멀티 자산 일괄 점검 — 여러 대상을 한 번에 큐잉
    api.post('/api/quick/bulk', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        targets: z.array(z.string().min(1)).min(1).max(50),
        attested: z.boolean(),
        deep: z.boolean().default(false),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      if (!v.data.attested) return reply.code(403).send({ error: 'attestation_required', message: '점검 권한 보유 확인이 필요합니다.' });
      const seen = new Set<string>();
      const results = v.data.targets
        .map((t) => t.trim()).filter(Boolean)
        .filter((t) => (seen.has(t.toLowerCase()) ? false : seen.add(t.toLowerCase())))
        .map((t) => {
          try {
            const { job } = scanDomainQuick(req.auth!.tenantId, req.auth!.email, t, true, undefined, v.data.deep);
            return { target: t, jobId: job.id, status: job.status, reason: job.gateDecision?.reason };
          } catch (e) {
            return { target: t, jobId: null, status: 'error', reason: String(e instanceof Error ? e.message : e) };
          }
        });
      audit({ tenantId: req.auth!.tenantId, actor: req.auth!.email, action: 'quick.bulk', outcome: 'info', reason: `${results.length}개 대상 일괄 점검`, meta: { count: results.length } });
      return reply.code(202).send({ jobs: results });
    });

    // ───────────── 수동 침투 점검 (Pentest) — 해킹 테스터 직접 테스트 ─────────────
    // 사용 가능한 Playbook 목록 (읽기)
    api.get('/api/pentest/playbooks', { preHandler: requirePermission('scan:read') }, async () => ({ playbooks: PLAYBOOKS }));

    // Repeater — 인가된 대상에 단일 요청을 보내고 원시 응답을 관찰
    api.post('/api/pentest/probe', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        target: z.string().min(1),
        attested: z.boolean(),
        method: z.string().default('GET'),
        path: z.string().default('/'),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        active: z.boolean().default(false),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      if (!v.data.attested) return reply.code(403).send({ error: 'attestation_required', message: '점검 권한 보유 확인(attestation)이 필요합니다.' });
      try {
        const at = authorizeTarget(req.auth!.tenantId, req.auth!.email, v.data.target, v.data.attested);
        const result = await runProbe(at, v.data, { tenantId: req.auth!.tenantId, actor: req.auth!.email });
        return reply.code(200).send({ host: at.host, ...result });
      } catch (e) {
        if (e instanceof EgressViolation) return reply.code(403).send({ error: 'egress_blocked', message: e.message });
        return reply.code(400).send({ error: 'bad_request', message: String(e instanceof Error ? e.message : e) });
      }
    });

    // Playbook — 표적 유도 점검을 실행하고 결과를 점검 작업으로 기록
    api.post('/api/pentest/run', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const v = validate(z.object({
        target: z.string().min(1),
        attested: z.boolean(),
        playbook: z.enum(['path-fuzz', 'auth-bypass', 'idor', 'sqli-probe', 'xss-probe', 'traversal-probe', 'method-audit']),
        path: z.string().optional(),
        param: z.string().optional(),
      }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      if (!v.data.attested) return reply.code(403).send({ error: 'attestation_required', message: '점검 권한 보유 확인(attestation)이 필요합니다.' });
      try {
        const at = authorizeTarget(req.auth!.tenantId, req.auth!.email, v.data.target, v.data.attested);
        const findings = await runPlaybook(at, { playbook: v.data.playbook as PlaybookId, path: v.data.path, param: v.data.param }, { tenantId: req.auth!.tenantId, actor: req.auth!.email });
        const meta = PLAYBOOKS.find((p) => p.id === v.data.playbook);
        const job = recordPentestJob(at, meta?.name ?? v.data.playbook, findings, req.auth!.email);
        return reply.code(200).send({ host: at.host, playbook: v.data.playbook, jobId: job.id, findings: job.findings });
      } catch (e) {
        if (e instanceof EgressViolation) return reply.code(403).send({ error: 'egress_blocked', message: e.message });
        return reply.code(400).send({ error: 'bad_request', message: String(e instanceof Error ? e.message : e) });
      }
    });

    // ───────────── AI 보안 분석 엔진 ─────────────
    // AI 구성 상태 (키 설정 여부·모델). 키 미설정이어도 200 으로 비활성 상태를 알린다.
    api.get('/api/ai/status', { preHandler: requirePermission('scan:read') }, async () => aiStatus());

    // AI 종합 분석 — 완료된 점검 작업의 발견을 받아 경영진 요약·우선순위·공격경로·오탐가능성을 생성.
    // 대상으로 패킷을 보내지 않으며(발견 메타데이터만 분석), PII 는 전송 전 마스킹된다.
    api.post('/api/ai/analyze', { preHandler: requirePermission('scan:read') }, async (req, reply) => {
      const v = validate(z.object({ jobId: z.string().min(1) }), req.body);
      if (!v.ok) return reply.code(400).send({ error: 'bad_request', message: v.error });
      const job = repos.scanJobs.get(v.data.jobId, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found', message: '점검 작업 없음' });
      const status = aiStatus();
      if (!status.configured) return reply.code(503).send({ error: 'ai_unconfigured', message: 'AI 미구성 — SENTINEL_AI_API_KEY(또는 ANTHROPIC_API_KEY) 설정 후 사용 가능합니다.', status });
      try {
        const analysis = await analyzeFindings(job.findings ?? []);
        if (!analysis) return reply.code(502).send({ error: 'ai_no_response', message: 'AI 응답을 받지 못했습니다(모델 오류/타임아웃).' });
        audit({ tenantId: job.tenantId, actor: req.auth!.email, action: 'ai.analyze', target: job.assetId, outcome: 'info', meta: { jobId: job.id, findings: job.findings?.length ?? 0 } });
        return reply.send({ jobId: job.id, model: status.model, analysis });
      } catch (e) {
        return reply.code(500).send({ error: 'ai_error', message: String(e instanceof Error ? e.message : e) });
      }
    });

    // 점검 취소 (UI kill-switch) — 큐 대기/실행 중 작업 중단
    api.post('/api/scans/:id/cancel', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const job = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found' });
      if (job.status !== 'queued' && job.status !== 'running') {
        return reply.code(409).send({ error: 'not_cancellable', message: `상태: ${job.status}` });
      }
      repos.scanJobs.update(job.id, { status: 'aborted', stage: '사용자 취소', finishedAt: now(), error: '사용자 취소' });
      audit({ tenantId: job.tenantId, actor: req.auth!.email, action: 'scan.cancel', target: job.assetId, outcome: 'deny', reason: '사용자 취소', meta: { jobId: job.id } });
      return reply.send({ ...repos.scanJobs.get(job.id) });
    });

    // 재점검 (폐루프) — 동일 자산을 같은 설정으로 다시 큐잉, 직전 대비 delta 산출 기반
    api.post('/api/scans/:id/rescan', { preHandler: requirePermission('scan:create') }, async (req, reply) => {
      const prev = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!prev) return reply.code(404).send({ error: 'not_found' });
      const asset = repos.assets.get(prev.assetId, req.auth!.tenantId);
      if (!asset) return reply.code(404).send({ error: 'not_found', message: '자산 없음' });
      const consent = repos.consents.list(req.auth!.tenantId)
        .find((cn) => cn.assetId === asset.id && currentConsentStatus(cn) === 'active');
      const job = orchestrator.enqueue({
        tenantId: req.auth!.tenantId, asset, consent,
        modules: prev.modules, intensity: prev.intensity, deep: prev.depth === 'deep', active: prev.active === true, actor: req.auth!.email,
      });
      return reply.code(job.status === 'rejected' ? 422 : 202).send(job);
    });

    // ───────────── 리포트 (설계 §5.3) ─────────────
    api.get('/api/scans/:id/report', { preHandler: requirePermission('report:read') }, async (req, reply) => {
      const job = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found' });
      if (job.status !== 'completed') return reply.code(409).send({ error: 'not_ready', message: `작업 상태: ${job.status}` });
      audit({ tenantId: job.tenantId, actor: req.auth!.email, action: 'report.view', target: job.assetId, outcome: 'info', meta: { jobId: job.id } });
      return buildReport(job);
    });

    api.get('/api/scans/:id/report.md', { preHandler: requirePermission('report:read') }, async (req, reply) => {
      const job = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found' });
      if (job.status !== 'completed') return reply.code(409).send({ error: 'not_ready' });
      reply.header('content-type', 'text/markdown; charset=utf-8');
      return reportToMarkdown(buildReport(job));
    });

    // 인쇄용(PDF) HTML 리포트 — 브라우저 인쇄로 PDF 저장 (설계 §5.3 PDF 출력)
    api.get('/api/scans/:id/report.html', { preHandler: requirePermission('report:read') }, async (req, reply) => {
      const job = repos.scanJobs.get((req.params as any).id, req.auth!.tenantId);
      if (!job) return reply.code(404).send({ error: 'not_found' });
      if (job.status !== 'completed') return reply.code(409).send({ error: 'not_ready' });
      audit({ tenantId: job.tenantId, actor: req.auth!.email, action: 'report.export.pdf', target: job.assetId, outcome: 'info', meta: { jobId: job.id } });
      reply.header('content-type', 'text/html; charset=utf-8');
      return reportToHtml(buildReport(job));
    });

    // ───────────── 감사추적 (설계 §6.2) ─────────────
    api.get('/api/audit', { preHandler: requirePermission('audit:read') }, async (req) => {
      const q = req.query as any;
      return queryAudit({ tenantId: req.auth!.tenantId, limit: q.limit ? Number(q.limit) : 200, action: q.action });
    });

    api.get('/api/audit/verify', { preHandler: requirePermission('audit:read') }, async () => verifyAuditChain());
  });
}

function challengeInstructions(asset: Asset, method: string, token: string): string {
  switch (method) {
    case 'dns-txt':
      return `대상 도메인(${asset.value})의 DNS 에 TXT 레코드를 추가하세요:\n  ${asset.value}.  IN  TXT  "${token}"`;
    case 'file-upload':
      return `다음 경로에 토큰을 담은 파일을 배치하세요:\n  https://${asset.value}/.well-known/sentinel-verify.txt\n  내용: ${token}`;
    case 'meta-tag':
      return `홈페이지 <head> 에 메타태그를 삽입하세요:\n  <meta name="sentinel-site-verification" content="${token}">`;
    case 'contract-esign':
      return `위탁사 권한자 전자서명 + 사업자등록 검증 후, verify 요청에 contractSignatureHash 와 businessRegistryVerified=true 를 전달하세요.`;
    default:
      return '';
  }
}

export { computeEgressAllowlist };
