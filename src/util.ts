import crypto from 'node:crypto';

export function id(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(9).toString('base64url')}`;
}

export function now(): string {
  return new Date().toISOString();
}

/** 데모용 패스워드 해시 (운영은 Vault 연동 Argon2id 권장 — 설계 §7 Vault). */
export function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const s = salt ?? crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, s, 32).toString('hex');
  return { hash, salt: s };
}

export function verifyPassword(password: string, salt: string, expected: string): boolean {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
}

/** 소유권 검증 토큰 생성 (설계 §3.1). */
export function verificationToken(): string {
  return `sentinel-verify=${crypto.randomBytes(16).toString('hex')}`;
}
