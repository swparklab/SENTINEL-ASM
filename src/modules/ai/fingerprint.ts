/**
 * 사이트 핑거프린트 (LLM 입력용) — 설계 §5.3.
 * 외부 LLM 벤더로 나가기 전에 PII·시크릿을 제거/마스킹한 "안전한 사이트 요약"을 만든다.
 * 모델은 이 요약만 보고 사이트의 용도·기술스택을 추론해 사이트 맞춤 점검을 제안한다.
 */
type Headers = Record<string, string>;
export interface SiteFingerprint {
  host: string; scheme: string; status: number; title: string;
  server: string; poweredBy: string; metaGenerator: string;
  tech: string[];
  securityHeaders: { present: string[]; missing: string[] };
  cookieNames: string[];
  forms: { action: string; method: string; inputs: string[] }[];
  paths: string[];
  apiHints: string[];
  capabilities: string[];
  purposeHints: string[];
  note: string;
}

/** 텍스트에서 PII/시크릿을 마스킹 (LLM 전송 전 필수). */
export function redact(s: string): string {
  return s
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]')
    .replace(/\b01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}\b/g, '[phone]')
    .replace(/\b\d{6}-?[1-4]\d{6}\b/g, '[rrn]')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[card]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g, '[jwt]')
    .replace(/\b(?:sk|pk|ghp|gho|xox[baprs]|AKIA|ASIA)[-_A-Za-z0-9]{8,}\b/g, '[secret]')
    .replace(/\b[A-Fa-f0-9]{32,}\b/g, '[hash]');
}

const TECH_SIGS: { re: RegExp; name: string }[] = [
  { re: /react|__REACT|data-reactroot/i, name: 'React' },
  { re: /vue(\.js)?|__vue__|data-v-/i, name: 'Vue' },
  { re: /angular|ng-version/i, name: 'Angular' },
  { re: /next\.js|__NEXT_DATA__|_next\//i, name: 'Next.js' },
  { re: /nuxt|__nuxt/i, name: 'Nuxt' },
  { re: /svelte/i, name: 'Svelte' },
  { re: /wordpress|wp-content|wp-includes/i, name: 'WordPress' },
  { re: /drupal/i, name: 'Drupal' },
  { re: /jquery/i, name: 'jQuery' },
  { re: /bootstrap/i, name: 'Bootstrap' },
  { re: /laravel|laravel_session/i, name: 'Laravel' },
  { re: /django|csrftoken/i, name: 'Django' },
  { re: /express|x-powered-by:\s*express/i, name: 'Express' },
  { re: /spring|jsessionid/i, name: 'Spring/Java' },
  { re: /asp\.net|__viewstate|aspxauth/i, name: 'ASP.NET' },
  { re: /php|phpsessid/i, name: 'PHP' },
  { re: /shopify/i, name: 'Shopify' },
  { re: /cloudflare/i, name: 'Cloudflare' },
];

const SEC_HEADERS: { key: string; label: string }[] = [
  { key: 'content-security-policy', label: 'CSP' },
  { key: 'strict-transport-security', label: 'HSTS' },
  { key: 'x-frame-options', label: 'X-Frame-Options' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { key: 'referrer-policy', label: 'Referrer-Policy' },
  { key: 'permissions-policy', label: 'Permissions-Policy' },
];

export function buildFingerprint(input: {
  host: string; scheme: string; status: number; headers: Headers; body: string; extraPaths?: string[];
}): SiteFingerprint {
  const { host, scheme, status, headers, body } = input;
  const hj = JSON.stringify(headers).toLowerCase();
  const title = redact((body.match(/<title[^>]*>([^<]{1,120})<\/title>/i)?.[1] ?? '').trim());
  const metaGenerator = redact((body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,80})["']/i)?.[1] ?? '').trim());

  const tech = [...new Set(TECH_SIGS.filter((t) => t.re.test(body.slice(0, 60_000)) || t.re.test(hj)).map((t) => t.name))];
  const present: string[] = []; const missing: string[] = [];
  for (const h of SEC_HEADERS) (headers[h.key] ? present : missing).push(h.label);

  const cookieNames = (headers['set-cookie'] || '').split(/,(?=[^;]+?=)/)
    .map((c) => (c.split('=')[0] || '').trim()).filter(Boolean).slice(0, 8);

  // 폼: action + method + 입력 이름(값 제외)
  const forms: SiteFingerprint['forms'] = [];
  for (const fm of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    if (forms.length >= 6) break;
    const attrs = fm[1] || ''; const inner = fm[2] || '';
    const action = (attrs.match(/action\s*=\s*["']([^"']{0,80})["']/i)?.[1] ?? '').trim();
    const method = (attrs.match(/method\s*=\s*["']([^"']+)["']/i)?.[1] ?? 'get').toUpperCase();
    const inputs = [...inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']{1,40})["']/gi)]
      .map((m) => m[1]!).slice(0, 12);
    forms.push({ action: redact(action), method, inputs: inputs.map(redact) });
  }

  // 동일 출처 경로 수집(href/src/action)
  const paths = new Set<string>();
  for (const m of body.matchAll(/(?:href|src|action)\s*=\s*["'](\/[A-Za-z0-9_\-./]{1,60})["']/g)) {
    const p = m[1]!;
    if (/\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|map)$/i.test(p)) continue;
    paths.add(p.replace(/\/+$/, '') || '/');
    if (paths.size >= 40) break;
  }
  for (const p of input.extraPaths ?? []) paths.add(p);

  const apiHints = [...new Set([...body.matchAll(/["'`](\/(?:api|rest|graphql|v\d{1,2})\/[A-Za-z0-9_\-./]{1,48})["'`]/g)].map((m) => m[1]!))].slice(0, 24);

  const capabilities: string[] = [];
  if (/type\s*=\s*["']password["']|로그인|sign\s?in|log\s?in/i.test(body)) capabilities.push('login');
  if (/회원가입|sign\s?up|register|가입/i.test(body)) capabilities.push('signup');
  if (/type\s*=\s*["']file["']|multipart\/form-data|업로드|upload/i.test(body)) capabilities.push('upload');
  if (/type\s*=\s*["']search["']|검색|search/i.test(body)) capabilities.push('search');
  if (/admin|관리자|대시보드|dashboard|console/i.test(body)) capabilities.push('admin-ui');
  if (/결제|payment|checkout|장바구니|cart/i.test(body)) capabilities.push('payment');
  if (apiHints.length) capabilities.push('json-api');

  // 사이트 용도 추론 힌트(가시 텍스트 키워드, 마스킹). 모델이 "지원/심사/회원" 같은 도메인 데이터 모델을 추론하게 한다.
  const visible = redact(body.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ')).slice(0, 1200);
  const PURPOSE_KW = ['지원', '신청', '심사', '평가', '선정', '합격', '회원', '가입', '공모', '모집', '접수', '제출', '대회', '경진', '창업', '투자', '채용', '예약', '주문', '결제', '게시판', '커뮤니티', '설문', '문의', '상담', '교육', '강의', '병원', '진료', '계좌', '대출', '보험'];
  const purposeHints = [...new Set(PURPOSE_KW.filter((k) => visible.includes(k)))].slice(0, 12);

  return {
    host, scheme, status, title,
    server: redact((headers['server'] || '').slice(0, 60)),
    poweredBy: redact((headers['x-powered-by'] || '').slice(0, 60)),
    metaGenerator,
    tech,
    securityHeaders: { present, missing },
    cookieNames: cookieNames.map(redact),
    forms,
    paths: [...paths].slice(0, 30).map(redact),
    apiHints: apiHints.map(redact),
    capabilities: [...new Set(capabilities)],
    purposeHints,
    note: 'PII/secrets redacted before transmission',
  };
}
