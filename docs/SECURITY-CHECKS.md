# SENTINEL-ASM 보안 점검 커버리지 매트릭스

상태 범례: **✅ 구현됨**(DNS·HTTP·TLS 비파괴, 심층 모드) · **🔌 외부 피드 필요**(유료 API/데이터셋 연동 시 가능) · **⚠ 연구/위험 영역**(능동·고위험 기법으로 별도 승인·환경 필요, 현재 보류)

> **v2 확장(전문가 갭분석 반영)**: 비파괴·Node 표준만으로 구현 가능한 누락 항목 다수를 심층 점검에 추가했습니다 —
> TLS 전수(버전 매트릭스·약한 암호군·PFS·인증서 SAN/자가서명/짧은키/약한서명/유효기간), 인증서 SAN 마이닝, 와일드카드 DNS 보정,
> 공개 DNS 사설IP 노출, dangling NS·SOA·SRV·CNAME·PTR·MX 위생, SPF 중복/ptr/pct, 배너 그랩→서비스 CVE,
> Redis/Memcached/ES/Kibana/CouchDB 무인증 단서, robots/sitemap 역노출, 오류 스택트레이스·SQL 오류·디렉터리 트래버설·PII(주민/카드/전화),
> JWT 구조 약점·CSRF 폼·로그인 평문·OIDC discovery·OpenAPI 파싱·CORS preflight·GraphQL 배칭/GET·WebSocket 노출,
> 디버그/추적 헤더·COEP·Permissions/Referrer 품질·캐시 공유·.well-known 전수·백업/임시·에디터/IDE/인프라 파일·런타임 설정,
> 그리고 소프트웨어 파일: yarn/pnpm/Gemfile/Cargo/Pipfile/poetry/composer/gradle/.csproj 파서, 업로드 시크릿,
> Dockerfile/IaC(compose·k8s·terraform)/CI 하드닝 린트, EOL 런타임, 설치 훅·비고정 의존성.

> 본 엔진은 **비파괴(non-destructive)** 원칙과 **egress allowlist** 를 지키며, 외부 데이터에 의존하지 않고 자체 관측 가능한 항목만 ✅ 로 구현했습니다. 🔌/⚠ 항목은 "되는 척" 하지 않고 명시적으로 미구현으로 둡니다.

## 1. 인프라·자산 상관분석 (OSINT 심화)
| 항목 | 상태 | 비고 |
|---|---|---|
| 인증서 투명성(CT) 로그 마이닝 | 🔌 | crt.sh / Censys API 연동 필요 |
| Passive DNS 히스토리 | 🔌 | SecurityTrails / Farsight 등 |
| ASN/BGP 자산 귀속 | 🔌 | RIR·BGP 데이터셋 |
| favicon 해시 상관 | 🟡 | 해시 산출은 가능, **클러스터링은 Shodan API 필요** |
| JARM/JA3(S) TLS 핑거프린팅 | ⚠ | 능동 JARM 프로빙 — 별도 구현 |
| HTTP 응답 해시 클러스터링 | 🔌 | 다자산 코퍼스 필요 |
| 클라우드 자산 귀속(SOA/MX/NS) | ✅ | NS/MX 프로파일 + SPOF 탐지 구현 |
| 역방향 WHOIS | 🔌 | WHOIS API |

## 2. 메일·DNS 프로토콜 정밀 (RFC 수준) — **대부분 ✅**
| 항목 | 상태 |
|---|---|
| SPF +all/?all 과허용 | ✅ |
| SPF DNS 룩업 10회 초과(PermError) | ✅ |
| DMARC 정렬(aspf/adkim relaxed) | ✅ |
| DMARC sp=(서브도메인 정책) 부재 | ✅ |
| DMARC rua 부재 | ✅ |
| DKIM 셀렉터 열거 / t=y 테스트모드 / rsa-sha1 | ✅ |
| MTA-STS 모드(none/testing/enforce) | ✅ |
| TLS-RPT 수신 여부 | ✅ |
| CAA 부재 | ✅ |
| 개방형 리졸버 / 캐시 스누핑 | ⚠ |
| NSEC/NSEC3 walking | ⚠ (DNSKEY/NSEC 질의 — Node dns 한계) |
| DNS rebinding 응답 패턴 | ⚠ |

## 3. 웹 플랫폼·헤더 심층 — **대부분 ✅**
| 항목 | 상태 |
|---|---|
| CSP 정적 분석(unsafe-inline/eval, base-uri/object-src/frame-ancestors 누락) | ✅ |
| Trusted Types 미적용 | ✅ |
| HSTS preload/includeSubDomains 누락 | ✅ |
| Cache 오구성(인증 응답 캐싱) | ✅ |
| Vary 헤더 부재 | ✅ |
| 이중 클릭재킹(XFO+frame-ancestors 부재) | ✅ |
| CORS null origin / 반사+credentials / 정규식 결함 | ✅ |
| 버전·기술 스택 누출(Server/X-Powered-By/쿠키 명명) | ✅ |
| CSP 화이트리스트 내 JSONP 가젯 우회 | 🟡 (가젯 DB 확장 필요) |

## 4. 인증·세션·토큰 (외부 관찰 범위)
| 항목 | 상태 |
|---|---|
| 세션 쿠키 Secure/HttpOnly/SameSite | ✅ |
| `__Host-`/`__Secure-` 프리픽스 규칙 | ✅ |
| 도메인 과범위 쿠키 | ✅ |
| JWT 구조(alg:none/exp 부재/노출) | 🟡 (응답에 토큰 노출 시 부분 가능) |
| OAuth/OIDC(redirect_uri·PKCE·state) | ⚠ (인증 플로우 능동 점검 필요) |
| SAML XSW 시그널 | ⚠ |

## 5. API·현대 아키텍처 — **부분 ✅**
| 항목 | 상태 |
|---|---|
| GraphQL introspection | ✅ |
| GraphQL field suggestion 누출 | ✅ |
| REST 버전 병존(/v1 잔존) | ✅ |
| 레이트리밋 헤더 노출/부재 | ✅ |
| GraphQL 별칭 배치/깊이 제한 | 🟡 |
| gRPC-Web server reflection | ⚠ |
| WebSocket origin 검증(CSWSH) | ⚠ |

## 6. 공급망·코드 노출 — **대부분 ✅**
| 항목 | 상태 |
|---|---|
| 소스맵(.map) → 소스 복원 | ✅ |
| 프론트엔드 번들 시크릿(AWS/Stripe/Slack/GCP/GitHub/PrivateKey) | ✅ |
| SRI(integrity) 미적용 외부 스크립트 | ✅ |
| 빌드/버전 메타(/version.json·humans.txt·.well-known) | ✅ |
| CI/CD 누출(.gitlab-ci.yml·Dockerfile·docker-compose) | ✅ (심층 민감경로) |
| 의존성 confusion 표면 | 🟡 (내부 패키지명 추출 후 레지스트리 대조 필요) |
| 타입스쿼팅 의존 로딩 | 🔌 |

## 7. 비즈니스 로직·정보 노출 (비파괴 관찰)
| 항목 | 상태 |
|---|---|
| 에러 메시지 정보량(스택트레이스/SQL/경로) | 🟡 (시그니처 확대 예정) |
| 디렉터리 리스팅 | ✅ |
| robots/sitemap 민감 경로 역노출 | 🟡 |
| 사용자 열거(타이밍 차이) | ⚠ (통계적·능동) |
| 문서 메타데이터(EXIF/문서 속성) | 🔌 (문서 수집·파싱) |

## 7-A. 접근통제·자동수집 차단 (access 모듈, OWASP A01·A04) — **신규 ✅**
> "수작업 기반 해킹"에 대한 방어 상태를 비파괴(GET/HEAD/OPTIONS)로 점검한다. 익스플로잇·로그인·쓰기를 수행하지 않으며, 발견은 모두 "취약 가능성의 안전 지표"다. soft-404 베이스라이닝으로 SPA 오탐을 억제한다.

| 항목 | 상태 |
|---|---|
| 허가되지 않은 경로 필터링(관리/내부/디버그 경로가 인증 없이 200) | ✅ (CWE-862) |
| 접근통제 우회 — 경로 표기 변형(대문자/슬래시/`..;/`/`/./`) | ✅ (CWE-639) |
| 접근통제 우회 — 헤더 변조(X-Original-URL/X-Rewrite-URL/X-Forwarded-For 등) | ✅ 심층 (CWE-290) |
| 순차 객체참조(IDOR) — 주소창 번호 ±1 열람 단서 | ✅ 심층 (CWE-639, tentative) |
| 권한 파라미터 변조(`?admin=true`/`role=admin`) 반응 | ✅ 심층 (CWE-639, tentative) |
| 디버그 파라미터(`?debug=true`) 정보 노출 | ✅ 심층 (→ A03 매핑) |
| AI 크롤러 차단 여부(robots.txt: GPTBot/ClaudeBot/CCBot/Google-Extended 등) | ✅ (RFC 9309) |
| 봇 User-Agent 필터링 능동 확인(GPTBot/ClaudeBot/python-requests/Scrapy) | ✅ |
| 봇 매니지먼트·레이트리밋 부재 단서(Cloudflare/DataDome/PerimeterX 등) | ✅ 심층 |

## 7-A2. 비인가 API 개인정보·과다 노출 (apiexposure, OWASP API1/API3 · A01) — **신규 ✅**
> 실제 유출 사고 클래스("API 요청 시 개인정보를 무분별하게 제공하는 구조") 대응. 관리자 페이지가 아니라 **인증 없이 호출되는 데이터 API 가 PII 를 그대로 반환**하는 표면을 발견·분석한다. 비파괴(GET/HEAD/OPTIONS, 식별자 2~3개 표본, 브루트포스 금지). PII 가 본문에서 실제 검증된 경우에만 firm/confirmed 로 승격한다.

| 항목 | 상태 |
|---|---|
| API 엔드포인트 발견 — 컬렉션 워드리스트(users/members/applicants/submissions/evaluations…) | ✅ |
| API 엔드포인트 발견 — OpenAPI/Swagger 명세 파싱(공개 명세 노출 + 실제 경로 인벤토리) | ✅ (CWE-200) |
| API 엔드포인트 발견 — 홈/번들 JS 내 `/api/..` 마이닝 | ✅ 심층 |
| 응답 본문 JSON PII 워킹 — 이메일·휴대전화·주민번호(체크섬)·카드(Luhn) | ✅ (CWE-359) |
| 한국형 민감 필드명 — 이메일·연락처·이름·주소·생년월일·점수·평가·심사평·등급·합격·선정·지원자/회원 | ✅ |
| **인증 없이 개인정보 대량 노출** — 비인가 API 가 PII 반환 | ✅ critical (CWE-359, firm) → 개인정보보호법/GDPR 매핑 |
| 인증 미강제 차분 — 익명 vs 무효 토큰 동일 PII 반환 확증 | ✅ |
| 과다 노출(Excessive Data Exposure) — 인증 없이 민감 필드/대량 레코드 반환 | ✅ (CWE-213) |
| **객체 수준 인가(BOLA)** — `{id}` 인접값으로 타인 개인정보 열람 | ✅ 심층 critical (CWE-639, firm) |
| 정상 보호 확인(401/403 응답 데이터 API) — 긍정 신호 로깅 | ✅ |
| 무해 사이트 무오탐(`/api/config` 등 공개 비-PII) | ✅ (검증됨) |

## 7-A3. AI 보안 분석 엔진 (ai 모듈, 설계 §5.3) — **신규 ✅**
> 사이트에 맞춘 적응형 점검. **LLM 은 "계획·분석"만** 하고, 실제 발신은 기존 비파괴 엔진(EgressGuard, GET/HEAD/OPTIONS)이 수행한다 — "AI 가 제안했다"는 사실만으로는 발견이 아니며, 응답에서 구체 신호가 관측될 때만 Finding 을 만든다. 키(`SENTINEL_AI_API_KEY`/`ANTHROPIC_API_KEY`) 미설정 시 전체 플랫폼은 그대로 동작하고 AI 만 비활성(graceful degradation). 외부 LLM 으로 나가는 데이터는 fingerprint 단계에서 PII·시크릿을 마스킹·제거한다.

| 항목 | 상태 |
|---|---|
| 사이트 핑거프린트(용도·기술·경로·폼·API 힌트) — **PII/시크릿 마스킹 후 전송** | ✅ |
| LLM 기반 사이트 특화 점검 제안(데이터 모델 추론 → 워드리스트에 없는 경로 발굴) | ✅ |
| 안전 필터 — GET/HEAD/OPTIONS·동일출처·파괴적 의도 거부(이중 안전장치) | ✅ |
| 비파괴 검증 — AI 제안 경로를 가드로 호출, PII/인가누락/정보노출 **구체 신호 관측 시에만** 발견 | ✅ |
| 인증 없이 개인정보 노출(사이트 특화 API) | ✅ critical (CWE-359) |
| 비인가 관리/내부 영역, 디렉터리 인덱싱, 민감 파일/설정 노출 | ✅ (CWE-862/200/548) |
| AI 종합 분석 — 경영진 요약·우선순위·공격경로·오탐 가능성·핵심 권고(`POST /api/ai/analyze`) | ✅ |
| 제공자 — Anthropic Messages / OpenAI 호환(`SENTINEL_AI_PROVIDER`·`SENTINEL_AI_MODEL`) | ✅ |
| 키 미설정 시 무중단·무오탐(graceful) | ✅ (검증됨) |

## 7-A4. 활성(침투) 검증 모드 (active, 설계 §4.5 aggressive) — **신규 ✅**
> "마커만 관측"을 넘어 취약점을 **실제로 트리거해 확정**한다. **비파괴 한계는 유지** — 데이터 변경·삭제, DoS/플러딩, 무차별 대입, 실 악성 페이로드는 수행하지 않으며, 확정은 모두 읽기전용 차분/반사/소량 열거다(기법당 요청 수 제한, 브루트포스 아님). **게이트: `active` 는 `aggressive` 강도 + 4-eyes 서면승인(`aggressiveApprovedBy`)을 통과한 경우에만 동작** — 자기확인(self-attested) 빠른점검 경로로는 절대 켤 수 없다.

| 항목 | 상태 |
|---|---|
| Boolean 기반 SQLi 확정 — `AND 1=1`(참) vs `AND 1=2`(거짓) 응답 차분(데이터 추출·변경 없음) | ✅ firm (CWE-89) |
| 반사형 XSS 확정 — HTML/속성 컨텍스트 이스케이프(안전 토큰, 실행 유도 없음) | ✅ firm (CWE-79) |
| IDOR/BOLA 확정 — 객체참조 자원의 인접 식별자 소량(≤4) 읽기전용 열람 | ✅ firm (CWE-639) |
| 권한 게이트 — active ⟹ aggressive ⟹ 4-eyes 강제(미충족 시 거부) | ✅ (검증됨) |
| active=false 시 활성 확정 완전 차단 | ✅ (검증됨) |
| **제외(옵션으로도 미구현)**: 데이터 변경·삭제 · DoS · 무차별 대입 · 실 악성 페이로드 | ⛔ 안전·법적 한계 |

## 7-B. 수동 침투 점검 (Pentest 모듈) — **신규 ✅**
> 해킹 테스터가 직접 대상을 테스트해 취약점을 찾는 기능. 안전장치는 그대로 강제된다 — (1) attestation 으로 검증된 자산·활성 동의 범위 내에서만, (2) egress allowlist 하드 차단(범위 밖 호스트로 패킷 미발신), (3) 전 요청 감사로그 기록. `scan:create` 권한 필요(viewer 차단). 엔드포인트: `GET /api/pentest/playbooks`, `POST /api/pentest/probe`, `POST /api/pentest/run`.

| 기능 | 상태 |
|---|---|
| Repeater(요청 워크벤치) — 메서드·경로·헤더·바디 직접 구성, 원시 응답 관찰 | ✅ |
| 포트·스킴 보존(`IP:포트`, `http(s)://`) | ✅ |
| 상태변경 메서드(POST/PUT/PATCH/DELETE) 명시 active 승인 게이트 | ✅ |
| 자동 관찰 노트(반사·보안헤더 누락·서버지문·오류 시그니처) | ✅ |
| Playbook: 관리/민감 경로 탐색(path-fuzz) | ✅ |
| Playbook: 접근통제 우회(auth-bypass, 경로·헤더 변형) | ✅ (soft-404 오탐 억제) |
| Playbook: 순차 객체참조(idor) 스윕 | ✅ |
| Playbook: SQL 오류 인젝션 표면(sqli-probe, 단일따옴표) | ✅ (비파괴) |
| Playbook: 반사형 XSS 표면(xss-probe, 안전 마커) | ✅ (비파괴) |
| Playbook: 경로 트래버설/LFI(traversal-probe) | ✅ (비파괴) |
| Playbook: 허용 HTTP 메서드 감사(method-audit) | ✅ |
| 결과를 점검 작업으로 기록(위험산정·컴플라이언스 매핑·리포트 연동) | ✅ |

## 8. 평판·유출·외부 그림자 — **전부 🔌 (외부 데이터 필수)**
| 항목 | 상태 |
|---|---|
| 자격증명 유출(브리치/스틸러 로그) | 🔌 HIBP·유출 DB |
| 시크릿 스캐닝(GitHub/Pastebin/Postman) | 🔌 |
| 타이포스쿼팅/IDN homograph 모니터링 | 🔌 |
| 딥/다크웹·랜섬웨어 유출 등재 | 🔌 |
| 모바일 앱(APK/IPA) 하드코딩 시크릿 | 🔌 |
| RBL/위협 인텔 평판 | 🔌 |

## 9. 고급·연구급 표면
| 항목 | 상태 |
|---|---|
| IPv6 그림자 자산(AAAA 비대칭) | ✅ |
| CDN/WAF 핑거프린팅 | ✅ |
| DNS·메일·웹 정책 일관성(비대칭) | 🟡 (서브도메인별 비교 확대 예정) |
| HTTP request smuggling(CL.TE/TE.CL) | ⚠ (오탐·부작용 위험 → 별도 승인 환경) |
| HTTP/2 h2c smuggling | ⚠ |
| web cache poisoning(unkeyed input) | ⚠ |
| 타이밍 사이드채널 | ⚠ |
| TLS 0-RTT/세션티켓/ECH | 🟡 (Node TLS 노출 한계) |
| 양자내성(PQC) 준비도 | 🟡 |

## 10. 거버넌스·메타 신호 — **대부분 ✅**
| 항목 | 상태 |
|---|---|
| security.txt(RFC 9116) 부재 | ✅ |
| 인증서·도메인 만료 임박 | ✅ |
| 3rd-party SPOF(단일 NS/CDN/CA) | ✅ (NS SPOF 구현) |
| 버그바운티/VDP 존재 | 🟡 (security.txt Policy 파싱 확대 예정) |
| 컴플라이언스 통제 상충·중복 | 🟡 (현재 매핑까지 구현) |

---

## 외부 피드 연동(🔌) 설계 메모
🔌 항목들은 다음 어댑터 인터페이스로 연동 가능하도록 설계 여지를 둔다(현재 미연동):

```ts
interface ExternalIntelProvider {
  name: string;                       // 'crtsh' | 'shodan' | 'hibp' | 'securitytrails' ...
  enrich(asset: Asset): Promise<Finding[]>;  // API 키 설정 시에만 동작, 미설정이면 빈 배열
}
```

> 연동 시에도 **권한 검증 게이트 통과 자산에 한해** 호출하며, 외부 조회 사실을 감사로그에 기록한다.
