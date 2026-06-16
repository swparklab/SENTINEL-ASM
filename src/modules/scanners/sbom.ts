/**
 * 소프트웨어 구성요소(SBOM) 정적 취약점 분석 (설계 §4.3 SBOM/CVE 대조).
 * 사용자가 제공한 의존성 매니페스트를 파싱하여 컴포넌트 목록을 만들고, 내장 CVE 피드와
 * 대조한다. **원격 대상에 어떤 트래픽도 발생시키지 않는 순수 정적 분석**이므로 소유권
 * 검증 게이트(§3)의 대상이 아니며, 권한 절차 없이 즉시 수행 가능하다.
 */
import { id } from '../../util.js';
import type { Finding } from '../../types.js';
import { CVE_FEED, lessThan } from './feed.js';

export interface SbomComponent { name: string; version: string; ecosystem?: string; }

const cleanVer = (v: string): string =>
  (v || '').trim().replace(/^[v^~>=<\s]+/, '').replace(/\s.*$/, '').replace(/[,;].*$/, '');

const clean = (s: string): string => (s || '').trim().toLowerCase();

/** 매니페스트 종류를 자동 감지하여 컴포넌트 목록으로 파싱. */
export function parseManifest(filename: string, content: string): { components: SbomComponent[]; format: string } {
  const fn = (filename || '').toLowerCase();
  const text = content || '';

  // 1) JSON 계열 (package.json / package-lock.json / CycloneDX SBOM)
  if (/^\s*[{[]/.test(text)) {
    try {
      const json = JSON.parse(text);
      // CycloneDX
      if (json.bomFormat === 'CycloneDX' || Array.isArray(json.components)) {
        return {
          format: 'CycloneDX SBOM',
          components: (json.components || []).map((c: any) => ({
            name: clean(c.name), version: cleanVer(String(c.version ?? '')),
            ecosystem: c.purl?.split(':')[1]?.split('/')[0],
          })).filter((c: SbomComponent) => c.name && c.version),
        };
      }
      // package-lock.json (v2/v3: packages, v1: dependencies)
      if (json.lockfileVersion || json.packages || (json.dependencies && fn.includes('lock'))) {
        const out: SbomComponent[] = [];
        const pkgs = json.packages || {};
        for (const [pathKey, meta] of Object.entries<any>(pkgs)) {
          if (!pathKey || !meta?.version) continue;
          const name = pathKey.replace(/^.*node_modules\//, '');
          if (name) out.push({ name: clean(name), version: cleanVer(meta.version), ecosystem: 'npm' });
        }
        for (const [name, meta] of Object.entries<any>(json.dependencies || {})) {
          if (meta?.version) out.push({ name: clean(name), version: cleanVer(meta.version), ecosystem: 'npm' });
        }
        return { format: 'npm lockfile', components: dedupe(out) };
      }
      // package.json
      const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
      const out = Object.entries<string>(deps).map(([name, ver]) => ({ name: clean(name), version: cleanVer(ver), ecosystem: 'npm' }));
      return { format: 'package.json', components: out.filter((c) => c.name && c.version) };
    } catch { /* JSON 아님 → 텍스트 파서로 폴백 */ }
  }

  // 2) pom.xml (Maven)
  if (fn.endsWith('.xml') || /<dependency>/.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g)) {
      out.push({ name: clean(m[1]!), version: cleanVer(m[2]!), ecosystem: 'maven' });
    }
    if (out.length) return { format: 'Maven pom.xml', components: out };
  }

  // 3) go.mod
  if (fn.endsWith('go.mod') || /^\s*module\s+/m.test(text)) {
    const out: SbomComponent[] = [];
    for (const m of text.matchAll(/^\s*([\w./-]+)\s+v(\d[\w.\-+]*)/gm)) {
      const name = m[1]!.split('/').pop()!;
      out.push({ name: clean(name), version: cleanVer(m[2]!), ecosystem: 'go' });
    }
    if (out.length) return { format: 'go.mod', components: out };
  }

  // 4) requirements.txt / 일반 목록 (name==ver, name@ver, name ver)
  const out: SbomComponent[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    let m = line.match(/^([A-Za-z0-9._\-@/]+)\s*(?:==|>=|~=|@|\s)\s*v?(\d[\w.\-+]*)/);
    if (m) {
      const name = m[1]!.replace(/^@[^/]+\//, (s) => s); // scoped npm 유지
      out.push({ name: clean(name), version: cleanVer(m[2]!) });
    }
  }
  return { format: out.length ? 'requirements/목록' : '미인식', components: out };
}

function dedupe(comps: SbomComponent[]): SbomComponent[] {
  const seen = new Set<string>();
  return comps.filter((c) => { const k = `${c.name}@${c.version}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/** 컴포넌트 이름이 피드 제품과 매칭되는지 (정확/접두/부분 일치). */
function matches(compName: string, product: string): boolean {
  const n = compName.replace(/^@[^/]+\//, '');
  return n === product || n.startsWith(product + '-') || n.startsWith(product + '.') || n === product.replace(/-/g, '');
}

/** SBOM 컴포넌트를 CVE 피드와 대조하여 발견사항 생성. */
export function matchSbom(components: SbomComponent[]): Finding[] {
  const findings: Finding[] = [];
  for (const comp of components) {
    if (!comp.version) continue;
    for (const entry of CVE_FEED) {
      if (entry.ecosystem && entry.ecosystem !== 'service' && matches(comp.name, entry.product) && lessThan(comp.version, entry.vulnerableBelow)) {
        const sev: Finding['severity'] =
          entry.cvss >= 9 ? 'critical' : entry.cvss >= 7 ? 'high' : entry.cvss >= 4 ? 'medium' : 'low';
        findings.push({
          id: id('fnd'), module: 'cve', severity: sev,
          title: `${entry.cve}: ${entry.title}`,
          target: `${comp.name}@${comp.version}`,
          description: `${comp.name} ${comp.version} 은(는) ${entry.vulnerableBelow} 미만으로 알려진 취약점에 노출됩니다.`,
          evidence: `SBOM(${comp.ecosystem ?? entry.ecosystem}): ${comp.name}@${comp.version}`,
          remediation: entry.remediation,
          cvss: entry.cvss, epss: entry.epss, kev: entry.kev, cve: entry.cve,
        });
      }
    }
  }
  return findings;
}
