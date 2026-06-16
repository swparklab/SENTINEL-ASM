/**
 * 시드 데이터 — 데모/개발용 초기 테넌트·RBAC 사용자·자산.
 * 멀티테넌시(설계 §6.1)를 보이기 위해 2개 테넌트를 생성한다.
 */
import { repos, resetDb, flushNow } from './db/store.js';
import { audit, resetAudit } from './db/audit.js';
import { hashPassword, id, now } from './util.js';
import type { Role, User } from './types.js';

function mkUser(tenantId: string, email: string, password: string, role: Role, displayName: string): User {
  const { hash, salt } = hashPassword(password);
  return { id: id('usr'), tenantId, email, passwordHash: hash, passwordSalt: salt, role, displayName, createdAt: now() };
}

export function seed() {
  resetDb();
  resetAudit(); // 시드는 깨끗한 해시체인으로 시작 (설계 §6.2)

  // 테넌트 1: 금융 그룹사
  const t1 = repos.tenants.insert({ id: 'tnt_finance', name: '한빛금융그룹', createdAt: now() });
  // 테넌트 2: 공공기관
  const t2 = repos.tenants.insert({ id: 'tnt_public', name: '국가전자정부센터', createdAt: now() });

  // RBAC 4역할 (설계 §6.1) — 테넌트1
  repos.users.insert(mkUser(t1.id, 'admin@hanbit.example', 'sentinel!admin', 'admin', '관리자 김보안'));
  repos.users.insert(mkUser(t1.id, 'scanner@hanbit.example', 'sentinel!scan', 'scanner', '점검자 이점검'));
  repos.users.insert(mkUser(t1.id, 'auditor@hanbit.example', 'sentinel!audit', 'auditor', '감사자 박감사'));
  repos.users.insert(mkUser(t1.id, 'viewer@hanbit.example', 'sentinel!view', 'viewer', '조회자 최열람'));
  // 테넌트2 관리자
  repos.users.insert(mkUser(t2.id, 'admin@egov.example', 'sentinel!admin', 'admin', '공공 관리자'));

  // 예시 자산 (소유권 미검증 상태 — 게이트 차단 시연용)
  repos.assets.insert({
    id: 'ast_demo_local', tenantId: t1.id, type: 'host', value: '127.0.0.1',
    label: '내부 데모 호스트(로컬)', businessCriticality: 'medium', ownership: null,
    createdAt: now(), createdBy: 'admin@hanbit.example',
  });
  repos.assets.insert({
    id: 'ast_example_com', tenantId: t1.id, type: 'domain', value: 'example.com',
    label: '공개 테스트 도메인', businessCriticality: 'high', ownership: null,
    createdAt: now(), createdBy: 'admin@hanbit.example',
  });

  flushNow();
  audit({ action: 'system.seed', outcome: 'info', reason: '시드 데이터 생성' });

  console.log('✅ 시드 완료');
  console.log('테넌트: 한빛금융그룹(tnt_finance), 국가전자정부센터(tnt_public)');
  console.log('로그인 계정 (비밀번호):');
  console.log('  admin@hanbit.example   / sentinel!admin   (admin)');
  console.log('  scanner@hanbit.example / sentinel!scan    (scanner)');
  console.log('  auditor@hanbit.example / sentinel!audit   (auditor)');
  console.log('  viewer@hanbit.example  / sentinel!view    (viewer)');
}

seed();
