/**
 * 소유권 증명 검증기 (설계 §3.1).
 * 4가지 방식(DNS TXT · 파일 업로드 · 메타태그 · 전자서명 위탁계약)을 통해
 * 점검 대상 자산의 소유권/운영권한을 시스템 차원에서 verified 상태로 만든다.
 *
 * 검증 행위 자체는 표준 소유권 증명 절차(예: 검색엔진 사이트 등록)와 동일한
 * 비파괴·읽기 동작이며, 이 단계를 통과하지 못한 자산은 능동 스캔 큐에 진입할 수 없다.
 */
import dns from 'node:dns/promises';
import { repos } from '../../db/store.js';
import { audit } from '../../db/audit.js';
import { now, verificationToken } from '../../util.js';
import type { Asset, OwnershipMethod, OwnershipProof } from '../../types.js';

const FETCH_TIMEOUT_MS = 5000;

async function httpGet(url: string): Promise<{ ok: boolean; status: number; body: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: 'manual',
      headers: { 'user-agent': 'SENTINEL-ASM/1.0 (+ownership-verification)' },
    });
    const body = await res.text().catch(() => '');
    return { ok: res.ok, status: res.status, body: body.slice(0, 64_000) };
  } catch (e) {
    return { ok: false, status: 0, body: String(e) };
  } finally {
    clearTimeout(t);
  }
}

/** 자산에 소유권 검증 토큰을 발급하고 pending 상태로 전환 (검증 절차 시작). */
export function issueOwnershipChallenge(asset: Asset, method: OwnershipMethod): OwnershipProof {
  const proof: OwnershipProof = {
    method,
    token: method === 'contract-esign' ? '' : verificationToken(),
    status: 'pending',
    issuedAt: now(),
  };
  repos.assets.update(asset.id, { ownership: proof });
  audit({
    tenantId: asset.tenantId, action: 'ownership.challenge.issued', target: asset.value,
    outcome: 'info', reason: `method=${method}`, meta: { assetId: asset.id, token: proof.token },
  });
  return proof;
}

/** 발급된 토큰이 실제로 대상에 배치되었는지 확인하여 소유권을 검증한다. */
export async function verifyOwnership(
  asset: Asset,
  opts: { contractSignatureHash?: string; businessRegistryVerified?: boolean } = {},
): Promise<OwnershipProof> {
  const proof = asset.ownership;
  if (!proof) throw new Error('소유권 검증 챌린지가 발급되지 않았습니다.');

  let verified = false;
  let detail = '';

  switch (proof.method) {
    case 'dns-txt': {
      try {
        const records = await dns.resolveTxt(asset.value);
        const flat = records.map((r) => r.join('')).join(' | ');
        verified = records.some((r) => r.join('').includes(proof.token));
        detail = verified ? `DNS TXT 토큰 확인됨` : `TXT 레코드에서 토큰 미발견: [${flat.slice(0, 200)}]`;
      } catch (e) {
        detail = `DNS 조회 실패: ${String(e)}`;
      }
      break;
    }
    case 'file-upload': {
      const base = asset.type === 'domain' ? `https://${asset.value}` : asset.value;
      const url = `${base.replace(/\/$/, '')}/.well-known/sentinel-verify.txt`;
      const res = await httpGet(url);
      verified = res.ok && res.body.includes(proof.token);
      detail = verified ? `검증 파일 확인됨 (${url})` : `파일 검증 실패 status=${res.status} (${url})`;
      break;
    }
    case 'meta-tag': {
      const base = asset.type === 'domain' ? `https://${asset.value}` : asset.value;
      const res = await httpGet(base.replace(/\/$/, '') + '/');
      const re = new RegExp(`<meta[^>]+name=["']sentinel-site-verification["'][^>]+content=["'][^"']*${escapeRe(proof.token)}`, 'i');
      verified = res.ok && re.test(res.body);
      detail = verified ? `메타태그 확인됨` : `메타태그 미발견 status=${res.status}`;
      break;
    }
    case 'contract-esign': {
      // 대규모/공공 계약: 위탁사 권한자 전자서명 + 사업자 검증 (설계 §3.1)
      verified = Boolean(opts.contractSignatureHash) && opts.businessRegistryVerified === true;
      detail = verified
        ? `전자서명 위탁계약 검증 완료 (sigHash=${opts.contractSignatureHash!.slice(0, 12)}…)`
        : `전자서명/사업자 검증 미완료`;
      break;
    }
  }

  const updated: OwnershipProof = {
    ...proof,
    status: verified ? 'verified' : 'failed',
    lastCheckedAt: now(),
    verifiedAt: verified ? now() : proof.verifiedAt,
    detail,
  };
  repos.assets.update(asset.id, { ownership: updated });
  audit({
    tenantId: asset.tenantId,
    action: 'ownership.verify',
    target: asset.value,
    outcome: verified ? 'allow' : 'deny',
    reason: detail,
    meta: { assetId: asset.id, method: proof.method },
  });
  return updated;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
