/**
 * Egress allowlist 강제 (설계 §3.2 / §8.1 / §9).
 * 점검 워커의 모든 외부 발신은 반드시 이 가드를 통과해야 한다. allowlist 에 없는
 * 대상으로의 패킷 발송은 워커 단에서 하드 차단되며, 위반 시도는 감사로그에 남는다.
 * 이로써 게이트를 통과한 작업조차 승인 범위 밖으로 나갈 수 없다.
 */
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { audit } from '../../db/audit.js';
import { isInScope } from '../authorizationGate/gate.js';

export class EgressViolation extends Error {
  constructor(public readonly target: string) {
    super(`Egress 차단: '${target}' 은(는) 승인 범위(allowlist) 밖입니다.`);
    this.name = 'EgressViolation';
  }
}

export class EgressGuard {
  constructor(
    private readonly allowlist: string[],
    private readonly ctx: { tenantId: string; jobId: string },
  ) {}

  private assertAllowed(target: string): void {
    if (!isInScope(target, this.allowlist)) {
      audit({
        tenantId: this.ctx.tenantId, action: 'egress.block', target,
        outcome: 'deny', reason: 'allowlist 위반', meta: { jobId: this.ctx.jobId, allowlist: this.allowlist },
      });
      throw new EgressViolation(target);
    }
  }

  /** 비파괴 TCP 연결 시도(connect-only) — 포트 개방 여부만 확인 후 즉시 종료. */
  async tcpProbe(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let done = false;
      const finish = (open: boolean) => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve(open);
      };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => finish(true));
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
      socket.connect(port, host);
    });
  }

  /** 비파괴 TLS 핸드셰이크 — 인증서/프로토콜 정보만 수집 후 종료 (설계 §4.2). */
  async tlsInspect(host: string, port = 443, timeoutMs = 4000): Promise<{
    protocol: string | null; validTo: string | null; subject: string | null; daysToExpiry: number | null;
  } | null> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      let done = false;
      const finish = (v: any) => { if (!done) { done = true; socket.destroy(); resolve(v); } };
      const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert?.valid_to ?? null;
        const days = validTo ? Math.round((Date.parse(validTo) - Date.now()) / 86_400_000) : null;
        finish({
          protocol: socket.getProtocol(),
          validTo,
          subject: cert?.subject?.CN ?? null,
          daysToExpiry: days,
        });
      });
      socket.once('timeout', () => finish(null));
      socket.once('error', () => finish(null));
    });
  }

  async resolveDns(host: string): Promise<string[]> {
    this.assertAllowed(host);
    try {
      return await dns.resolve(host);
    } catch {
      return [];
    }
  }

  /** DNS TXT 조회 (SPF/DMARC/DKIM 점검용) — allowlist 강제. */
  async resolveTxt(host: string): Promise<string[]> {
    this.assertAllowed(host);
    try {
      return (await dns.resolveTxt(host)).map((r) => r.join(''));
    } catch {
      return [];
    }
  }

  async resolveMx(host: string): Promise<{ exchange: string; priority: number }[]> {
    this.assertAllowed(host);
    try {
      return await dns.resolveMx(host);
    } catch {
      return [];
    }
  }

  async resolveCaa(host: string): Promise<unknown[]> {
    this.assertAllowed(host);
    try {
      return await dns.resolveCaa(host);
    } catch {
      return [];
    }
  }

  async resolveCname(host: string): Promise<string[]> {
    this.assertAllowed(host);
    try {
      return await dns.resolveCname(host);
    } catch {
      return [];
    }
  }

  /** allowlist 검증을 거친 HTTP 요청 (비파괴, 기본 GET). */
  async httpGet(
    url: string,
    opts: { timeoutMs?: number; method?: string; headers?: Record<string, string> } = {},
  ): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string } | null> {
    this.assertAllowed(url);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 6000);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        method: opts.method ?? 'GET',
        redirect: 'manual',
        headers: { 'user-agent': 'SENTINEL-ASM/1.0 (+authorized-scan; non-destructive)', ...(opts.headers ?? {}) },
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      const body = (await res.text().catch(() => '')).slice(0, 128_000);
      return { ok: res.ok, status: res.status, headers, body };
    } catch {
      return null;
    } finally {
      clearTimeout(t);
    }
  }
}
