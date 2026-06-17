/**
 * SAST — 소스 파일 정적 보안 분석.
 * 소스코드 파일을 업로드하면 위험 패턴(SQL 주입·XSS·평문 암호·취약 함수·
 * 하드코딩 자격증명·안전하지 않은 난수·경로 조작 등)을 탐지한다.
 * Semgrep 같은 외부 바이너리 없이 Node 표준으로 구현.
 */
import { id } from '../../util.js';
import type { Finding } from '../../types.js';

export interface SastRule {
  id: string;
  title: string;
  severity: Finding['severity'];
  cwe: string;
  owasp: string;
  pattern: RegExp;
  remediation: string;
  lang?: string[];   // 해당 언어(없으면 전체)
}

export const SAST_RULES: SastRule[] = [
  // ── SQL 인젝션 ──────────────────────────────────────────────────
  { id: 'S001', title: 'SQL 쿼리 문자열 직접 연결(SQLi 위험)', severity: 'critical',
    cwe: 'CWE-89', owasp: 'A03:2021',
    pattern: /(?:query|execute|exec)\s*\(\s*(?:`|['"])[^'"`;]*\$\{|(?:query|execute|exec)\s*\(\s*[^)]*\+\s*(?:req\.|request\.|params\.|body\.)/i,
    remediation: '파라미터화 쿼리(Prepared Statement) 또는 ORM 을 사용하십시오.', lang: ['js','ts','py','php','java'] },
  { id: 'S002', title: 'Raw SQL with string format (SQLi)', severity: 'critical',
    cwe: 'CWE-89', owasp: 'A03:2021',
    pattern: /f['"]{1}.*SELECT.*\{|%s.*SELECT|\.format\(.*SELECT|sprintf.*SELECT/i,
    remediation: '파라미터화 쿼리를 사용하십시오.', lang: ['py','php'] },

  // ── XSS ─────────────────────────────────────────────────────────
  { id: 'S003', title: 'innerHTML 직접 할당(DOM XSS)', severity: 'high',
    cwe: 'CWE-79', owasp: 'A03:2021',
    pattern: /\.innerHTML\s*=\s*(?!['"`]<(?:span|div)[^>]*>[^<]*<\/(?:span|div)>['"`])[^;{]+/,
    remediation: 'textContent 를 사용하거나 DOMPurify 로 sanitize 하십시오.', lang: ['js','ts'] },
  { id: 'S004', title: 'eval() 사용(코드 인젝션)', severity: 'high',
    cwe: 'CWE-95', owasp: 'A03:2021',
    pattern: /\beval\s*\((?!['"`][^'"`,;)]+['"`]\))/,
    remediation: 'eval 사용을 제거하고 JSON.parse 또는 명시적 로직으로 대체하십시오.', lang: ['js','ts','py'] },
  { id: 'S005', title: 'document.write() 사용', severity: 'medium',
    cwe: 'CWE-79', owasp: 'A03:2021',
    pattern: /document\.write\s*\(/,
    remediation: 'document.write 대신 DOM API 를 사용하십시오.', lang: ['js','ts'] },

  // ── 하드코딩 자격증명 ────────────────────────────────────────────
  { id: 'S006', title: '하드코딩 패스워드/시크릿 (소스)', severity: 'critical',
    cwe: 'CWE-798', owasp: 'A02:2021',
    pattern: /(?:password|passwd|secret|api_key|apikey|api_secret|access_key|private_key|token)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    remediation: '비밀정보를 환경변수 또는 시크릿 매니저로 이전하십시오.' },

  // ── 안전하지 않은 난수 ───────────────────────────────────────────
  { id: 'S007', title: 'Math.random() 보안 컨텍스트 사용', severity: 'medium',
    cwe: 'CWE-338', owasp: 'A02:2021',
    pattern: /Math\.random\(\).*(?:token|secret|key|password|session|nonce|csrf)/i,
    remediation: 'crypto.randomBytes() 또는 crypto.getRandomValues() 를 사용하십시오.', lang: ['js','ts'] },
  { id: 'S008', title: 'random.random() 보안 컨텍스트 사용', severity: 'medium',
    cwe: 'CWE-338', owasp: 'A02:2021',
    pattern: /random\.random\(\).*(?:token|secret|key|password|session)/i,
    remediation: 'secrets.token_hex() 를 사용하십시오.', lang: ['py'] },

  // ── 경로 조작 ────────────────────────────────────────────────────
  { id: 'S009', title: '경로 조작 가능성 (Path Traversal)', severity: 'high',
    cwe: 'CWE-22', owasp: 'A01:2021',
    pattern: /(?:readFile|readFileSync|createReadStream|open)\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)/i,
    remediation: 'path.basename() 으로 정규화하고 허용 디렉터리 밖 접근을 차단하십시오.', lang: ['js','ts'] },

  // ── 안전하지 않은 역직렬화 ──────────────────────────────────────
  { id: 'S010', title: 'pickle.loads() 역직렬화 — RCE 위험', severity: 'critical',
    cwe: 'CWE-502', owasp: 'A08:2021',
    pattern: /pickle\.loads?\s*\(/,
    remediation: 'pickle 대신 json.loads() 를 사용하거나 신뢰하지 않는 데이터에 적용을 금지하십시오.', lang: ['py'] },
  { id: 'S011', title: 'unserialize() 역직렬화 — RCE 위험', severity: 'critical',
    cwe: 'CWE-502', owasp: 'A08:2021',
    pattern: /unserialize\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|user|input)/i,
    remediation: 'unserialize 에 사용자 입력을 허용하지 마십시오.', lang: ['php'] },
  { id: 'S012', title: 'ObjectInputStream 역직렬화 — RCE 위험', severity: 'critical',
    cwe: 'CWE-502', owasp: 'A08:2021',
    pattern: /new\s+ObjectInputStream/,
    remediation: '신뢰하지 않는 스트림에 ObjectInputStream 사용을 금지하십시오.', lang: ['java'] },

  // ── SSRF ────────────────────────────────────────────────────────
  { id: 'S013', title: 'SSRF — 외부 URL 사용자 입력 직접 사용', severity: 'high',
    cwe: 'CWE-918', owasp: 'A10:2021',
    pattern: /fetch\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.)|\$_(?:GET|POST|REQUEST)\[['"]url|urllib.*open\s*\(\s*(?:request\.|req\.)/i,
    remediation: 'URL 을 화이트리스트로 검증하고 내부 대역 접근을 차단하십시오.' },

  // ── 명령 인젝션 ──────────────────────────────────────────────────
  { id: 'S014', title: '쉘 명령 인젝션 위험', severity: 'critical',
    cwe: 'CWE-78', owasp: 'A03:2021',
    pattern: /(?:exec|execSync|spawn|system|popen|os\.system|subprocess\.call)\s*\([^)]*(?:\$\{|req\.|request\.|params\.|body\.)/i,
    remediation: 'execFile 과 인자 배열을 사용하고 사용자 입력을 shell 에 직접 전달하지 마십시오.' },

  // ── 암호화 약점 ──────────────────────────────────────────────────
  { id: 'S015', title: 'MD5/SHA1 패스워드 해시 사용', severity: 'high',
    cwe: 'CWE-327', owasp: 'A02:2021',
    pattern: /(?:md5|sha1)\s*\(\s*\$?password|hashlib\.(?:md5|sha1)\(\s*password/i,
    remediation: 'bcrypt, argon2, scrypt 같은 패스워드 해시 함수를 사용하십시오.' },
  { id: 'S016', title: 'ECB 모드 암호화 사용', severity: 'high',
    cwe: 'CWE-327', owasp: 'A02:2021',
    pattern: /(?:AES|DES)\/ECB|Cipher\.getInstance\s*\(\s*['"]AES\/ECB|createCipheriv\s*\(\s*['"]aes-\d+-ecb/i,
    remediation: 'GCM 또는 CBC 모드를 사용하십시오.', lang: ['java','js','ts'] },

  // ── 인증·세션 ────────────────────────────────────────────────────
  { id: 'S017', title: 'JWT 검증 알고리즘 미고정', severity: 'high',
    cwe: 'CWE-347', owasp: 'A02:2021',
    pattern: /jwt\.verify\s*\([^,]+,[^,]+\)(?!\s*,\s*\{[^}]*algorithms)/,
    remediation: 'algorithms 옵션으로 허용 알고리즘을 명시적으로 지정하십시오.', lang: ['js','ts'] },
  { id: 'S018', title: 'DEBUG=True 운영 노출 위험', severity: 'medium',
    cwe: 'CWE-489', owasp: 'A05:2021',
    pattern: /DEBUG\s*=\s*True/,
    remediation: '운영 환경에서 DEBUG=False 로 설정하십시오.', lang: ['py'] },

  // ── 보안 설정 ────────────────────────────────────────────────────
  { id: 'S019', title: 'SSL 인증서 검증 비활성화', severity: 'high',
    cwe: 'CWE-295', owasp: 'A02:2021',
    pattern: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context/i,
    remediation: 'SSL 인증서 검증을 활성화하십시오.' },
  { id: 'S020', title: 'CORS AllowAll origin 설정', severity: 'medium',
    cwe: 'CWE-942', owasp: 'A05:2021',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/i,
    remediation: '허용 출처를 구체적으로 지정하십시오.', lang: ['js','ts'] },
  { id: 'S021', title: 'CSRF 보호 비활성화', severity: 'high',
    cwe: 'CWE-352', owasp: 'A01:2021',
    pattern: /csrf_exempt|@csrf_protect\s*$|csrfProtection\s*=\s*false/i,
    remediation: 'CSRF 보호를 활성화하십시오.' },

  // ── 정보 노출 ────────────────────────────────────────────────────
  { id: 'S022', title: 'console.log 민감 정보 출력 가능성', severity: 'low',
    cwe: 'CWE-532', owasp: 'A09:2021',
    pattern: /console\.(?:log|debug|info)\s*\([^)]*(?:password|token|secret|key|credential)/i,
    remediation: '민감 정보를 로그에 출력하지 마십시오.', lang: ['js','ts'] },
  { id: 'S023', title: 'Stack trace 직접 응답 전송', severity: 'medium',
    cwe: 'CWE-209', owasp: 'A05:2021',
    pattern: /res\.(?:send|json)\s*\([^)]*(?:err\.stack|error\.stack|e\.stack)/i,
    remediation: '운영 환경에서 스택트레이스를 응답에 포함하지 마십시오.', lang: ['js','ts'] },
];

const LANG_EXT: Record<string, string> = {
  js: 'js', ts: 'ts', py: 'py', php: 'php', java: 'java', rb: 'rubygems',
  go: 'go', cs: 'csharp', cpp: 'cpp', c: 'c', rs: 'rust',
};

function detectLang(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  return LANG_EXT[ext] ?? ext;
}

/** 소스 파일에서 SAST 룰 매칭하여 발견사항 생성. */
export function runSast(filename: string, content: string): Finding[] {
  const lang = detectLang(filename);
  const out: Finding[] = [];
  const lines = content.split('\n');

  for (const rule of SAST_RULES) {
    if (rule.lang && !rule.lang.includes(lang)) continue;
    const hits: { line: number; text: string }[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? '';
      if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('*')) continue;
      if (rule.pattern.test(line)) hits.push({ line: i + 1, text: line.trim().slice(0, 80) });
      if (hits.length >= 5) break;
    }
    if (hits.length) {
      out.push({
        id: id('fnd'), module: 'cve', severity: rule.severity,
        title: `[SAST ${rule.id}] ${rule.title}`,
        target: `${filename}:${hits.map(h => h.line).join(',')}`,
        description: `정적 분석으로 ${filename} 에서 취약 패턴(${rule.id})을 탐지했습니다.`,
        evidence: hits.map(h => `L${h.line}: ${h.text}`).join('\n'),
        remediation: rule.remediation,
        cwe: rule.cwe, owasp: rule.owasp, confidence: 'firm',
      });
    }
  }
  return out;
}
