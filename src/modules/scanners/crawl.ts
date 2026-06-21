/**
 * 비파괴 공격표면 크롤러 (전수 스크리닝) — 설계 §4.4 확장.
 * 홈페이지만 보던 한계를 넘어, 동일 출처 앱을 BFS 로 크롤링해 "모든" 페이지·쿼리 파라미터·폼·API
 * 엔드포인트를 발견한다. 발견된 표면 전체에 동적 점검을 일괄 적용해 커버리지를 극대화한다.
 *
 * 비파괴 엄수: GET 만(EgressGuard 가 강제), 페이지/요청 상한으로 플러딩 방지, 동일 출처만, 정적 자원 제외.
 */
import type { ScanContext } from './types.js';

export interface ParamTarget { path: string; param: string; value: string; query: Record<string, string> }
export interface CrawlResult {
  pages: string[];
  params: ParamTarget[];
  forms: { path: string; action: string; method: string; inputs: string[] }[];
  apiPaths: string[];
}

const STATIC_RE = /\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webm|webp|pdf|zip|map|avif)(\?|$)/i;

export async function crawlSurface(ctx: ScanContext, base: string, host: string, rootBody: string, opts: { maxPages: number }): Promise<CrawlResult> {
  const origin = base.replace(/\/$/, '');
  const pages: string[] = [];
  const seen = new Set<string>(['/']);
  const params = new Map<string, ParamTarget>();
  const forms: CrawlResult['forms'] = [];
  const apiPaths = new Set<string>();
  const queue: string[] = ['/'];
  let processed = 0;   // 발신 GET 시도 수(루트 포함) — maxPages 상한의 일관된 의미.

  // sitemap.xml 시드 — 링크로 연결되지 않은 페이지까지 발견(전수 커버리지).
  for (const sp of ['/sitemap.xml', '/sitemap_index.xml']) {
    try {
      const sm = await ctx.guard.httpGet(origin + sp, { timeoutMs: 6000 });
      if (!sm || sm.status !== 200 || !/<urlset|<sitemapindex|<loc>/i.test(sm.body)) continue;
      for (const m of sm.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
        const norm = toPath(m[1]!, origin, host);
        if (!norm) continue;
        const p = norm.split('?')[0]!;
        if (!seen.has(p) && !STATIC_RE.test(p) && queue.length < opts.maxPages) { seen.add(p); queue.push(p); }  // sitemap 시드는 maxPages 내로 캡(링크 BFS 공간 확보)
      }
    } catch { /* */ }
  }

  while (queue.length && processed < opts.maxPages) {
    const path = queue.shift()!;
    processed++;
    let body: string;
    if (path === '/') { body = rootBody; }
    else {
      let r: { status: number; headers: Record<string, string>; body: string } | null = null;
      try { r = await ctx.guard.httpGet(origin + path, { timeoutMs: 6000 }); } catch { continue; }
      if (!r || r.status >= 400 || !r.body) continue;
      const ct = (r.headers['content-type'] || '').toLowerCase();
      const looksHtml = /<html|<!doctype|<body|<a\s|<div/i.test(r.body.slice(0, 1024));
      if (ct && !/text\/html|application\/xhtml/i.test(ct)) continue;     // 명시적 비-HTML 헤더면 스킵
      if (!ct && !looksHtml) continue;                                    // 헤더 부재 시 본문 토큰으로 보강 판정
      body = r.body;
    }
    pages.push(path);

    // 링크/리소스 → 동일 출처 경로 큐잉 + 쿼리 파라미터 수집
    for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']/gi)) {
      const norm = toPath(m[1]!, origin, host);
      if (!norm) continue;
      const [p, qs] = splitQuery(norm);
      if (qs) addParams(params, p, parseQueryMap(qs));
      if (!seen.has(p) && !STATIC_RE.test(p) && pages.length + queue.length < opts.maxPages * 2) { seen.add(p); queue.push(p); }
    }
    // 폼
    for (const fm of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
      if (forms.length >= 30) break;
      const attrs = fm[1] || '';
      const aMatch = attrs.match(/action\s*=\s*["']([^"']*)["']/i)?.[1];
      const action = aMatch && aMatch.length ? aMatch : path;          // action="" → 현재 URL
      const method = (attrs.match(/method\s*=\s*["']([^"']+)["']/i)?.[1] ?? 'GET').toUpperCase();
      const inputs = [...(fm[2] || '').matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']{1,40})["']/gi)].map((x) => x[1]!).slice(0, 15);
      forms.push({ path, action, method, inputs });
      // GET 폼 입력은 파라미터 표적으로 흡수(형제 입력을 함께 query 로 보존)
      if (method === 'GET' && inputs.length) {
        const ap = (toPath(action, origin, host) || path).split('?')[0]!;
        const qmap: Record<string, string> = {};
        for (const inp of inputs) qmap[inp] = '1';
        addParams(params, ap, qmap);
      }
    }
    // API 엔드포인트(HTML 내 문자열)
    for (const m of body.matchAll(/["'`](\/(?:api|rest|graphql|internal|v\d{1,2})\/[A-Za-z0-9_\-./]{1,64})["'`]/g)) apiPaths.add(m[1]!.replace(/\/+$/, ''));
  }

  ctx.log(`crawl: 페이지 ${pages.length} · 파라미터 ${params.size} · 폼 ${forms.length} · API ${apiPaths.size}`);
  return { pages, params: [...params.values()], forms, apiPaths: [...apiPaths].slice(0, 40) };
}

/** 표적 URL 빌더 — 대상 파라미터만 payload(이미 인코딩됨)로 치환하고 형제 파라미터는 원값 유지. */
export function buildParamUrl(origin: string, t: ParamTarget, encodedPayload: string): string {
  const o = origin.replace(/\/$/, '');
  const entries = Object.entries(t.query && Object.keys(t.query).length ? t.query : { [t.param]: t.value });
  const qs = entries.map(([k, v]) => `${encodeURIComponent(k)}=${k === t.param ? encodedPayload : encodeURIComponent(v)}`).join('&');
  return `${o}${t.path}?${qs}`;
}

function addParams(params: Map<string, ParamTarget>, path: string, qmap: Record<string, string>) {
  for (const param of Object.keys(qmap)) {
    const key = path + '?' + param;
    if (params.has(key) || params.size >= 200) continue;
    params.set(key, { path, param, value: qmap[param] ?? '', query: qmap });
  }
}
/** 상대/절대 URL → 동일 출처 경로(쿼리 포함). 외부/비-http/정적 앵커는 null. */
function toPath(raw0: string, origin: string, host: string): string | null {
  let raw = (raw0 || '').replace(/\\/g, '/').trim();    // 백슬래시 → 슬래시(브라우저 정규화)
  if (!raw || raw.startsWith('#') || raw.startsWith('//')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) {
    if (!/^https?:/i.test(raw)) return null;            // mailto:/javascript:/data: 등 제외
    try { const u = new URL(raw); return u.host === host ? u.pathname + u.search : null; } catch { return null; }
  }
  if (raw.startsWith('/')) return raw;
  return '/' + raw.replace(/^\.\//, '');                 // 상대경로
}
function splitQuery(p: string): [string, string] { const i = p.indexOf('?'); return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)]; }
function parseQueryMap(qs: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const kv of qs.split('&')) {
    const i = kv.indexOf('=');
    const k = safeDecode(i < 0 ? kv : kv.slice(0, i));   // 등호 없는 플래그형(?debug) 포함
    if (!k || k.length > 40) continue;
    const v = i < 0 ? '' : safeDecode(kv.slice(i + 1));
    if (v.length <= 60) out[k] = v;
  }
  return out;
}
function safeDecode(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }
