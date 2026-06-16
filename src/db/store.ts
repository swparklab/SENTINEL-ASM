/**
 * 데이터 계층 (설계 §2.1).
 * 운영 환경의 PostgreSQL/OpenSearch/Object Store 를 단일 노드에서 대체하는
 * 파일 기반 컬렉션 스토어. 리포지토리 인터페이스를 통해 접근하므로
 * 추후 실 DB 어댑터로 무중단 교체가 가능하다.
 */
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';
import type {
  Tenant, User, Asset, Consent, ScanJob, AuditEvent,
} from '../types.js';

interface DbShape {
  tenants: Tenant[];
  users: User[];
  assets: Asset[];
  consents: Consent[];
  scanJobs: ScanJob[];
}

const EMPTY: DbShape = {
  tenants: [], users: [], assets: [], consents: [], scanJobs: [],
};

const dbFile = path.join(config.dataDir, 'db.json');

function ensureDir() {
  if (!fs.existsSync(config.dataDir)) fs.mkdirSync(config.dataDir, { recursive: true });
}

function load(): DbShape {
  ensureDir();
  if (!fs.existsSync(dbFile)) return structuredClone(EMPTY);
  try {
    const raw = fs.readFileSync(dbFile, 'utf8');
    return { ...structuredClone(EMPTY), ...JSON.parse(raw) };
  } catch {
    return structuredClone(EMPTY);
  }
}

let db: DbShape = load();
let flushTimer: NodeJS.Timeout | null = null;

/** 디바운스 영속화 — 동시성 환경에서 과도한 디스크 IO 방지 */
function persist() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    ensureDir();
    fs.writeFileSync(dbFile, JSON.stringify(db, null, 2), 'utf8');
  }, 50);
}

export function flushNow() {
  if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
  ensureDir();
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2), 'utf8');
}

export function resetDb() {
  db = structuredClone(EMPTY);
  flushNow();
}

/**
 * 단순 컬렉션 리포지토리. 모든 조회는 tenantId 스코프를 강제할 수 있어
 * 멀티테넌시 데이터 격리(설계 §6.1)를 리포지토리 레벨에서 보장한다.
 */
class Repository<T extends { id: string; tenantId?: string }> {
  constructor(private readonly key: keyof DbShape) {}

  private all(): T[] {
    return db[this.key] as unknown as T[];
  }

  list(tenantId?: string): T[] {
    const items = this.all();
    return tenantId ? items.filter((i) => i.tenantId === tenantId) : items.slice();
  }

  find(predicate: (item: T) => boolean): T | undefined {
    return this.all().find(predicate);
  }

  get(id: string, tenantId?: string): T | undefined {
    const item = this.all().find((i) => i.id === id);
    if (!item) return undefined;
    if (tenantId && item.tenantId !== tenantId) return undefined; // 교차 테넌트 접근 차단
    return item;
  }

  insert(item: T): T {
    this.all().push(item);
    persist();
    return item;
  }

  update(id: string, patch: Partial<T>): T | undefined {
    const item = this.all().find((i) => i.id === id);
    if (!item) return undefined;
    Object.assign(item, patch);
    persist();
    return item;
  }

  remove(id: string): boolean {
    const arr = this.all();
    const idx = arr.findIndex((i) => i.id === id);
    if (idx < 0) return false;
    arr.splice(idx, 1);
    persist();
    return true;
  }
}

export const repos = {
  tenants: new Repository<Tenant>('tenants'),
  users: new Repository<User>('users'),
  assets: new Repository<Asset>('assets'),
  consents: new Repository<Consent>('consents'),
  scanJobs: new Repository<ScanJob>('scanJobs'),
};

export type { AuditEvent };
