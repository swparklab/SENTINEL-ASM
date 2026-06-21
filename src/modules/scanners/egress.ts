/**
 * Egress allowlist 강제 (설계 §3.2 / §8.1 / §9).
 * 점검 워커의 모든 외부 발신은 반드시 이 가드를 통과해야 한다. allowlist 에 없는
 * 대상으로의 패킷 발송은 워커 단에서 하드 차단되며, 위반 시도는 감사로그에 남는다.
 * 이로써 게이트를 통과한 작업조차 승인 범위 밖으로 나갈 수 없다.
 */
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import { audit } from '../../db/audit.js';
import { isInScope } from '../authorizationGate/gate.js';

export class EgressViolation extends Error {
  constructor(public readonly target: string) {
    super(`Egress 차단: '${target}' 은(는) 승인 범위(allowlist) 밖입니다.`);
    this.name = 'EgressViolation';
  }
}

/** 자동 비파괴 점검에서 허용되는 읽기전용 메서드. 이외(쓰기/상태변경)는 가드가 하드 차단한다. */
const READONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

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

  /** 비파괴 TLS 핸드셰이크 — 인증서/프로토콜 상세 수집 후 종료 (설계 §4.2). */
  async tlsInspect(host: string, port = 443, timeoutMs = 4000): Promise<{
    protocol: string | null; validTo: string | null; validFrom: string | null;
    subject: string | null; issuer: string | null; daysToExpiry: number | null;
    san: string[]; bits: number | null; selfSigned: boolean; hostnameMismatch: boolean;
    sigalg: string | null; keyType: string | null; keyBits: number | null; validityDays: number | null;
    alpn: string | null; http2: boolean; ocspUrl: string | null; sctCount: number;
  } | null> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      let done = false;
      const finish = (v: any) => { if (!done) { done = true; socket.destroy(); resolve(v); } };
      const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert?.valid_to ?? null;
        const validFrom = cert?.valid_from ?? null;
        const days = validTo ? Math.round((Date.parse(validTo) - Date.now()) / 86_400_000) : null;
        const validityDays = (validTo && validFrom) ? Math.round((Date.parse(validTo) - Date.parse(validFrom)) / 86_400_000) : null;
        const san = (cert?.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/i, '')).filter(Boolean);
        const authErr = (socket as any).authorizationError as string | undefined;
        const selfSigned = authErr === 'DEPTH_ZERO_SELF_SIGNED_CERT' || authErr === 'SELF_SIGNED_CERT_IN_CHAIN';
        let hostnameMismatch = false;
        try { hostnameMismatch = !!(cert && Object.keys(cert).length && tls.checkServerIdentity(host, cert as any)); } catch { hostnameMismatch = true; }
        // 인증서 서명알고리즘·공개키 상세 (crypto.X509Certificate)
        let sigalg: string | null = null; let keyType: string | null = null; let keyBits: number | null = (cert as any)?.bits ?? null;
        try {
          const raw = (cert as any)?.raw;
          if (raw) {
            const x = new crypto.X509Certificate(raw);
            sigalg = (x as any).sigalg ?? null;
            const pk = x.publicKey as any;
            keyType = pk?.asymmetricKeyType ?? null;
            const det = pk?.asymmetricKeyDetails;
            if (det?.modulusLength) keyBits = det.modulusLength;
          }
        } catch { /* 런타임 미지원 시 bits 만 사용 */ }
        // ALPN·HTTP/2 탐지
        const alpnRaw: unknown = (socket as any).alpnProtocol;
        const alpnStr = alpnRaw && typeof alpnRaw === 'string' ? alpnRaw : null;
        // OCSP URL 추출 (인증서 AIA 확장)
        let ocspUrl: string | null = null;
        try {
          const ext = (cert as any)?.infoAccess?.['OCSP - URI'];
          if (ext) ocspUrl = Array.isArray(ext) ? (ext[0] ?? null) : ext;
        } catch { /* */ }
        // SCT(서명된 인증서 타임스탬프) 수 — CT 정책 준수 지표
        const sctCount: number = (() => {
          try { return (cert as any)?.extensions?.find((e: any) => e?.oid === '1.3.6.1.4.1.11129.2.4.2')?.value?.length ?? 0; } catch { return 0; }
        })();
        finish({
          protocol: socket.getProtocol(),
          validTo, validFrom,
          subject: cert?.subject?.CN ?? null, issuer: cert?.issuer?.CN ?? null,
          daysToExpiry: days, validityDays, san, bits: (cert as any)?.bits ?? null,
          selfSigned, hostnameMismatch, sigalg, keyType, keyBits,
          alpn: alpnStr, http2: alpnStr === 'h2', ocspUrl, sctCount,
        });
      });
      socket.once('timeout', () => finish(null));
      socket.once('error', () => finish(null));
    });
  }

  /** 비파괴 읽기전용 명령 프로브 — 1회 송신 후 응답 수신(예: Redis PING, Memcached version). */
  async cmdProbe(host: string, port: number, payload: string, timeoutMs = 2500): Promise<string | null> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let done = false; let buf = '';
      const finish = (v: string | null) => { if (!done) { done = true; socket.destroy(); resolve(v); } };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => { try { socket.write(payload); } catch { finish(null); } });
      socket.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 1024) finish(buf.slice(0, 1024)); });
      socket.once('timeout', () => finish(buf || null));
      socket.once('error', () => finish(null));
      socket.once('close', () => finish(buf || null));
      socket.connect(port, host);
    });
  }

  /** 역방향 DNS(PTR) — 리졸버 질의(대상 패킷 미발신). */
  async reverse(ip: string): Promise<string[]> {
    try { return await dns.reverse(ip); } catch { return []; }
  }

  /** 특정 TLS 버전 수용 여부 — 해당 버전만 허용하여 핸드셰이크 시도(비파괴). */
  async tlsVersionAccepted(host: string, version: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3', port = 443, timeoutMs = 3500): Promise<boolean> {
    this.assertAllowed(host);
    // 구버전(1.0/1.1)은 모던 OpenSSL 기본 seclevel 이 클라이언트단에서 막으므로 seclevel 우회로 서버 실제 수용을 관측
    const opts: tls.ConnectionOptions = { host, port, servername: host, minVersion: version, maxVersion: version, rejectUnauthorized: false, timeout: timeoutMs };
    if (version === 'TLSv1' || version === 'TLSv1.1') (opts as any).ciphers = 'DEFAULT@SECLEVEL=0';
    return new Promise((resolve) => {
      let done = false;
      const finish = (v: boolean) => { if (!done) { done = true; try { socket.destroy(); } catch { /* */ } resolve(v); } };
      let socket: tls.TLSSocket;
      try {
        socket = tls.connect(opts, () => finish(true));
      } catch { resolve(false); return; }
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
    });
  }

  /** 약한 암호스위트 수용 여부 — 지정 암호군만 제안하여 협상 시도(비파괴, TLS1.2 한정). */
  async tlsWeakCipherAccepted(host: string, ciphers: string, port = 443, timeoutMs = 3500): Promise<string | null> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      let done = false;
      const finish = (v: string | null) => { if (!done) { done = true; try { socket.destroy(); } catch { /* */ } resolve(v); } };
      let socket: tls.TLSSocket;
      try {
        socket = tls.connect({ host, port, servername: host, maxVersion: 'TLSv1.2', minVersion: 'TLSv1', ciphers, rejectUnauthorized: false, timeout: timeoutMs }, () => {
          const c = socket.getCipher();
          finish(c?.name ?? 'accepted');
        });
      } catch { resolve(null); return; }
      socket.once('timeout', () => finish(null));
      socket.once('error', () => finish(null));
    });
  }

  /** 비파괴 배너 그랩 — connect 후 서버가 자발적으로 보내는 배너만 수신(요청 미전송). */
  async tcpBanner(host: string, port: number, timeoutMs = 2500): Promise<string | null> {
    this.assertAllowed(host);
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let done = false; let buf = '';
      const finish = (v: string | null) => { if (!done) { done = true; socket.destroy(); resolve(v); } };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => { /* 요청을 보내지 않고 자발적 배너만 대기 */ });
      socket.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 512) finish(buf.slice(0, 512)); });
      socket.once('timeout', () => finish(buf || null));
      socket.once('error', () => finish(null));
      socket.once('close', () => finish(buf || null));
      socket.connect(port, host);
    });
  }

  async resolveSoa(host: string): Promise<{ nsname: string; hostmaster: string; refresh: number; retry: number; expire: number; minttl: number } | null> {
    try { return await dns.resolveSoa(host); } catch { return null; }
  }

  async resolveSrv(host: string): Promise<{ name: string; port: number; priority: number; weight: number }[]> {
    try { return await dns.resolveSrv(host); } catch { return []; }
  }

  // ───────────────────────────────────────────────────────────────
  // DNS 해석 메서드: 질의는 *리졸버* 로 전송되며 대상 호스트로 패킷을 보내지 않는다.
  // 따라서 egress allowlist(대상 패킷 발신 통제) 대상이 아니다. 이로써 in-scope 도메인의
  // NS/MX/CNAME/PTR 등 연관 인프라(외부 호스트명)도 해석해 위생 점검을 수행할 수 있다.
  // 실제 패킷을 대상에 보내는 tcpProbe/tlsInspect/httpGet/tcpBanner/cmdProbe 만 allowlist 로 차단한다.
  // ───────────────────────────────────────────────────────────────
  async resolveDns(host: string): Promise<string[]> {
    try { return await dns.resolve(host); } catch { return []; }
  }

  async resolveTxt(host: string): Promise<string[]> {
    try { return (await dns.resolveTxt(host)).map((r) => r.join('')); } catch { return []; }
  }

  async resolveMx(host: string): Promise<{ exchange: string; priority: number }[]> {
    try { return await dns.resolveMx(host); } catch { return []; }
  }

  async resolveCaa(host: string): Promise<unknown[]> {
    try { return await dns.resolveCaa(host); } catch { return []; }
  }

  async resolveCname(host: string): Promise<string[]> {
    try { return await dns.resolveCname(host); } catch { return []; }
  }

  async resolve6(host: string): Promise<string[]> {
    try { return await dns.resolve6(host); } catch { return []; }
  }

  async resolveNs(host: string): Promise<string[]> {
    try { return await dns.resolveNs(host); } catch { return []; }
  }

  /** allowlist 검증을 거친 HTTP 요청 (비파괴, 기본 GET). */
  async httpGet(
    url: string,
    opts: { timeoutMs?: number; method?: string; headers?: Record<string, string>; body?: string; allowStateChange?: boolean } = {},
  ): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string } | null> {
    this.assertAllowed(url);
    // 비파괴 불변식을 단일 egress 초크포인트에서 구조적으로 강제한다(방어심도).
    // 자동 스캐너는 allowStateChange 를 전달하지 않으므로 GET/HEAD/OPTIONS·무바디만 발신 가능하다.
    // 상태변경이 필요한 수동 점검(pentest)만 자체 승인(active) 후 명시적으로 allowStateChange:true 를 넘긴다.
    const method = (opts.method ?? 'GET').toUpperCase();
    if (!opts.allowStateChange && (!READONLY_METHODS.has(method) || opts.body !== undefined)) {
      audit({
        tenantId: this.ctx.tenantId, action: 'egress.method_block', target: url, outcome: 'deny',
        reason: `비파괴 위반 차단: method=${method}${opts.body !== undefined ? '+body' : ''}`,
        meta: { jobId: this.ctx.jobId, method },
      });
      throw new EgressViolation(url);
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 6000);
    try {
      const res = await fetch(url, {
        signal: ctrl.signal,
        method: opts.method ?? 'GET',
        redirect: 'manual',
        body: opts.body,
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
