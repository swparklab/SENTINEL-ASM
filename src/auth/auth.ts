/**
 * 인증·인가 (설계 §2.1 API 게이트웨이 / §6.1 RBAC).
 * - JWT 발급/검증
 * - 역할 기반 접근통제: admin / scanner / auditor / viewer (최소권한 원칙)
 * - 모든 인증 컨텍스트는 tenantId 를 포함하여 멀티테넌시 격리를 강제
 */
import jwt from 'jsonwebtoken';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import { repos } from '../db/store.js';
import { verifyPassword } from '../util.js';
import type { Role, User } from '../types.js';

export interface AuthContext {
  userId: string;
  tenantId: string;
  role: Role;
  email: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

export function issueToken(user: User): string {
  const payload: AuthContext = {
    userId: user.id, tenantId: user.tenantId, role: user.role, email: user.email,
  };
  return jwt.sign(payload, config.jwtSecret, { expiresIn: config.jwtExpiresIn as any });
}

export function authenticate(email: string, password: string): User | null {
  const user = repos.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return null;
  if (!verifyPassword(password, user.passwordSalt, user.passwordHash)) return null;
  return user;
}

/** 최소권한 정책 — 각 역할이 수행 가능한 행위 (설계 §6.1). */
const PERMISSIONS: Record<Role, string[]> = {
  admin: ['*'],
  scanner: ['asset:read', 'asset:write', 'ownership:verify', 'consent:read', 'scan:create', 'scan:read', 'report:read'],
  auditor: ['asset:read', 'consent:read', 'scan:read', 'report:read', 'audit:read'],
  viewer: ['asset:read', 'scan:read', 'report:read'],
};

export function can(role: Role, permission: string): boolean {
  const perms = PERMISSIONS[role];
  return perms.includes('*') || perms.includes(permission);
}

/** 인증 미들웨어 — Bearer 토큰 검증 후 req.auth 주입. */
export async function requireAuth(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    reply.code(401).send({ error: 'unauthorized', message: '인증 토큰이 필요합니다.' });
    return;
  }
  try {
    const decoded = jwt.verify(header.slice(7), config.jwtSecret) as AuthContext;
    req.auth = decoded;
  } catch {
    reply.code(401).send({ error: 'unauthorized', message: '유효하지 않은 토큰입니다.' });
  }
}

/** 인가 미들웨어 팩토리 — 특정 권한 요구. */
export function requirePermission(permission: string) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!req.auth) {
      reply.code(401).send({ error: 'unauthorized' });
      return;
    }
    if (!can(req.auth.role, permission)) {
      reply.code(403).send({
        error: 'forbidden',
        message: `'${req.auth.role}' 역할에는 '${permission}' 권한이 없습니다.`,
      });
    }
  };
}
