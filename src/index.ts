/**
 * SENTINEL-ASM 서버 부트스트랩 (설계 §2 시스템 아키텍처).
 * Fastify 기반 API 게이트웨이 + 정적 웹 콘솔 서빙 + 주기적 kill-switch 스윕.
 */
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import fs from 'node:fs';
import { config } from './config.js';
import { registerRoutes } from './routes.js';
import { sweepExpiredConsents } from './modules/orchestrator/orchestrator.js';
import { audit } from './db/audit.js';

async function main() {
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'info' }, bodyLimit: 2 * 1024 * 1024 });

  await app.register(cors, { origin: true });
  await registerRoutes(app);

  // 헬스체크 (설계 §8.1 가용성/관측)
  app.get('/healthz', async () => ({ status: 'ok', service: 'sentinel-asm', ts: new Date().toISOString() }));

  // 도메인 정규화 미리보기 — 인증 불필요, 읽기 전용
  app.get('/api/normalize', async (req) => {
    const { parseTarget } = await import('./modules/quick/quick.js');
    const raw = String((req.query as any).q ?? '');
    return raw ? parseTarget(raw) : { host: '', original: '', changed: false, note: '' };
  });

  // 대역외(OOB) 콜라보레이터 싱크 — 인증 불필요. 대상이 blind SSRF 등으로 콜백하면 토큰만 기록한다.
  // 상태 변경 없음(로깅 전용), 미발급 토큰은 무시. 활성 점검의 대역외 확정 상관관계에만 사용된다.
  {
    const { recordOobHit } = await import('./modules/scanners/oob.js');
    const collabHandler = (req: any, reply: any) => {
      recordOobHit(String(req.params?.token ?? ''), { path: String(req.raw?.url ?? '/'), method: req.method, ua: String(req.headers?.['user-agent'] ?? ''), remote: req.ip });
      reply.code(200).header('content-type', 'text/plain').send('ok');
    };
    app.route({ method: ['GET', 'HEAD', 'POST', 'OPTIONS'], url: '/collab/:token', handler: collabHandler });
    app.route({ method: ['GET', 'HEAD', 'POST', 'OPTIONS'], url: '/collab/:token/*', handler: collabHandler });
  }

  // 정적 웹 콘솔 (설계 §2.1 프레젠테이션 계층)
  if (fs.existsSync(config.publicDir)) {
    await app.register(fastifyStatic, { root: config.publicDir, prefix: '/' });
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith('/api') || req.url.startsWith('/healthz')) {
        return reply.code(404).send({ error: 'not_found' });
      }
      return reply.sendFile('index.html'); // SPA fallback
    });
  }

  // 주기적 kill-switch: 만료 동의/작업 정리 (설계 §3.2)
  const sweep = setInterval(() => {
    try { sweepExpiredConsents(); } catch { /* noop */ }
  }, 30_000);
  sweep.unref?.();

  await app.listen({ port: config.port, host: config.host });
  audit({ action: 'system.start', outcome: 'info', reason: `port=${config.port}` });
  app.log.info(`SENTINEL-ASM 콘솔: http://localhost:${config.port}`);
}

main().catch((e) => {
  console.error('부트스트랩 실패:', e);
  process.exit(1);
});
