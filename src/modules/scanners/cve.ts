/**
 * 취약점 매칭 (CVE / SBOM) — 설계 §4.3.
 * 탐지된 기술 스택·버전을 SBOM 으로 구성하여 알려진 CVE 피드와 대조한다.
 * EPSS(익스플로잇 확률)·KEV(실제 악용) 메타를 발견사항에 부착하여 위험 산정에 반영한다.
 */
import type { Finding } from '../../types.js';
import type { Scanner, ScanContext } from './types.js';
import { mk } from './asm.js';
import { CVE_FEED, lessThan } from './feed.js';

interface Component { product: string; version: string; source: string; }

/** 응답 헤더/본문에서 제품·버전을 식별하여 SBOM 컴포넌트를 추출. */
function fingerprint(headers: Record<string, string>, body: string): Component[] {
  const comps: Component[] = [];
  const add = (product: string, version: string, source: string) => {
    if (version) comps.push({ product: product.toLowerCase(), version, source });
  };

  const server = headers['server'] ?? '';
  // 예: "nginx/1.18.0", "Apache/2.4.29 (Ubuntu)", "Microsoft-IIS/10.0"
  for (const m of server.matchAll(/([A-Za-z\-]+)\/(\d[\w.]*)/g)) {
    const name = m[1]!.toLowerCase().replace('microsoft-iis', 'iis');
    add(name, m[2]!, `Server: ${server}`);
  }
  const powered = headers['x-powered-by'] ?? '';
  for (const m of powered.matchAll(/([A-Za-z\-]+)\/(\d[\w.]*)/g)) {
    add(m[1]!, m[2]!, `X-Powered-By: ${powered}`);
  }
  // 본문 generator 메타 (CMS 등)
  const gen = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) {
    const gm = gen[1]!.match(/([A-Za-z\-]+)\s+(\d[\w.]*)/);
    if (gm) add(gm[1]!, gm[2]!, `generator: ${gen[1]}`);
  }
  return comps;
}

export const cveScanner: Scanner = {
  module: 'cve',
  minIntensity: 'passive',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const base = ctx.asset.type === 'host' ? `http://${ctx.asset.value}` : `https://${ctx.asset.value}`;
    const res = await ctx.guard.httpGet(base + '/');
    if (!res) {
      ctx.log('cve: 핑거프린팅 대상 응답 없음');
      return findings;
    }

    const sbom = fingerprint(res.headers, res.body);
    if (!sbom.length) {
      ctx.log('cve: 식별 가능한 버전 정보 없음 (SBOM 비어있음)');
      return findings;
    }
    ctx.log(`cve: SBOM ${sbom.length}개 컴포넌트 식별`);

    for (const comp of sbom) {
      for (const entry of CVE_FEED) {
        if (entry.product === comp.product && lessThan(comp.version, entry.vulnerableBelow)) {
          const sev: Finding['severity'] =
            entry.cvss >= 9 ? 'critical' : entry.cvss >= 7 ? 'high' : entry.cvss >= 4 ? 'medium' : 'low';
          findings.push({
            ...mk('cve', sev, `${entry.cve}: ${entry.title}`, ctx.asset.value,
              `${comp.product} ${comp.version} 은(는) ${entry.vulnerableBelow} 미만으로 취약합니다.`,
              `${comp.source} → SBOM(${comp.product}@${comp.version})`, entry.remediation),
            cvss: entry.cvss, epss: entry.epss, kev: entry.kev, cve: entry.cve,
          });
        }
      }
    }
    return findings;
  },
};
