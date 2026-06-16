/**
 * 감사추적 (설계 §6.2).
 * 모든 점검 요청·게이트 판정·실행·조회 행위를 append-only JSONL 로 기록한다.
 * 각 레코드는 직전 레코드 해시를 포함하는 해시 체인으로 묶여, 사후 변조 시
 * 체인 검증이 깨지므로 "변조 불가(append-only)" 요건을 기술적으로 충족한다.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from '../config.js';
import type { AuditEvent } from '../types.js';

const GENESIS = '0'.repeat(64);

function ensureDir() {
  const dir = path.dirname(config.audit.file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readAll(): AuditEvent[] {
  ensureDir();
  if (!fs.existsSync(config.audit.file)) return [];
  return fs.readFileSync(config.audit.file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as AuditEvent);
}

let lastHash: string = (() => {
  const all = readAll();
  return all.length ? all[all.length - 1]!.hash : GENESIS;
})();

let seq = readAll().length;

function digest(e: Omit<AuditEvent, 'hash'>): string {
  const canonical = JSON.stringify({
    id: e.id, ts: e.ts, tenantId: e.tenantId, actor: e.actor,
    action: e.action, target: e.target, outcome: e.outcome,
    reason: e.reason, meta: e.meta, prevHash: e.prevHash,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

/** 감사로그 전체 초기화 — 시드/리셋 시에만 사용. 운영 중에는 절대 호출 금지. */
export function resetAudit(): void {
  ensureDir();
  fs.writeFileSync(config.audit.file, '', 'utf8');
  lastHash = GENESIS;
  seq = 0;
}

export interface AuditInput {
  tenantId?: string | null;
  actor?: string | null;
  action: string;
  target?: string;
  outcome: AuditEvent['outcome'];
  reason?: string;
  meta?: Record<string, unknown>;
}

/** 불변 감사 이벤트를 1건 기록한다. 절대 기존 레코드를 수정/삭제하지 않는다. */
export function audit(input: AuditInput): AuditEvent {
  ensureDir();
  const ts = new Date().toISOString();
  const base: Omit<AuditEvent, 'hash'> = {
    id: `evt_${ts.replace(/[-:.TZ]/g, '')}_${seq++}`,
    ts,
    tenantId: input.tenantId ?? null,
    actor: input.actor ?? null,
    action: input.action,
    target: input.target,
    outcome: input.outcome,
    reason: input.reason,
    meta: input.meta,
    prevHash: lastHash,
  };
  const hash = digest(base);
  const event: AuditEvent = { ...base, hash };
  fs.appendFileSync(config.audit.file, JSON.stringify(event) + '\n', 'utf8');
  lastHash = hash;
  return event;
}

/** 감사로그 조회 (감사자/관리자 전용 — 설계 §6.1 RBAC). */
export function queryAudit(opts: { tenantId?: string; limit?: number; action?: string } = {}): AuditEvent[] {
  let all = readAll();
  if (opts.tenantId) all = all.filter((e) => e.tenantId === opts.tenantId);
  if (opts.action) all = all.filter((e) => e.action === opts.action);
  all.reverse(); // 최신순
  return opts.limit ? all.slice(0, opts.limit) : all;
}

/** 해시 체인 무결성 검증 — 변조 탐지. */
export function verifyAuditChain(): { valid: boolean; brokenAt?: string; count: number } {
  const all = readAll();
  let prev = GENESIS;
  for (const e of all) {
    if (e.prevHash !== prev) return { valid: false, brokenAt: e.id, count: all.length };
    const expected = digest({ ...e });
    if (expected !== e.hash) return { valid: false, brokenAt: e.id, count: all.length };
    prev = e.hash;
  }
  return { valid: true, count: all.length };
}
