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
