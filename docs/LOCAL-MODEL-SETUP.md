# 로컬모델로 SENTINEL-ASM 고도화하기

AI 오케스트레이터(사이트 특화 점검 계획·분석)를 **사내/로컬 GPU**에서 구동하는 방법과, 그 위에서
세부 페이지 **토큰 검증**·상태변경(파괴형) 점검을 **인가 게이트 뒤에서** 안전하게 수행하는 방법을 정리한다.

> 적용 범위: **본인 소유·사내 자산 전용.** 소유권 미검증 대상은 어떤 경로로도 능동 점검 큐에 진입하지 못한다
> (`authorizationGate`). 로컬모델 도입은 이 게이트나 비파괴 초크포인트(`EgressGuard`)를 **완화하지 않는다.**

---

## 1. 왜 "탈옥/검열해제 모델"이 필요 없는가

핵심 아키텍처 결정: **LLM 은 계획·분석만 하고, 실제 요청은 결정론적 엔진이 게이트를 거쳐 실행한다.**

```
[로컬모델]  ──계획/해석(텍스트·JSON)──▶  [SENTINEL 엔진]
 (오케스트레이터)                         │  authorizationGate  : 소유권·동의·범위·윈도우 검증
                                          │  EgressGuard        : 대상 allowlist + 메서드 게이트(allowStateChange)
                                          ▼
                                    승인 범위 내 대상에만 발신
```

- 모델은 익스플로잇을 **창작·발신하지 않는다.** 어떤 경로를 점검할지 제안하고, 응답을 해석할 뿐이다.
- 그래서 "무엇이든 답하는" 검열해제 모델이 주는 **추가 능력은 없다.** 탈옥이 바꾸는 건 안전장치의 유무이지 성능이 아니며,
  대상 오배정 하나로 무관한 제3자 시스템을 건드릴 위험만 커진다.
- 실제 상태변경(파괴형) 점검은 **모델이 아니라 테스터가** 결정론적으로 지시하며(§5), 게이트·감사로그로 통제된다.

결론: 로컬모델은 **일반 지시수행·도구호출·구조화 출력이 강한 모델**이면 충분하다. 아래 추천은 그 기준이다.

---

## 2. 로컬모델 추천

오케스트레이션(계획 JSON 생성 + 응답 해석)에는 tool/구조화 출력과 보안 도메인 추론이 균형 잡힌 모델이 좋다.

| 모델 | 파라미터 | VRAM(4bit 기준) | 강점 | 비고 |
|---|---|---|---|---|
| **Qwen2.5‑Coder 32B Instruct** ⭐ | 32B | ~20–24GB | 구조화 출력·코드/보안 추론·JSON 준수 | 기본 추천. 단일 24GB GPU(4090/A5000)에서 구동 |
| Qwen2.5 14B / 7B Instruct | 14B/7B | ~10GB/~6GB | 가볍고 빠름 | VRAM 제약 시. 계획 품질은 32B 대비 하락 |
| Llama 3.3 70B Instruct | 70B | ~40–48GB(2x GPU) | 범용 추론 최상위 | 멀티 GPU/48GB급 필요 |
| DeepSeek‑R1 Distill (Qwen 32B) | 32B | ~20–24GB | 다단계 추론 강함 | 사고사슬이 길어 지연↑, timeout 상향 권장 |

- **처음이라면 Qwen2.5‑Coder 32B + Ollama** 로 시작. 처리량이 필요해지면 같은 모델을 vLLM 으로 올린다.
- "보안 특화" 명목의 파인튜닝/abliterated 모델은 이 시스템 설계상 **불필요**하다(모델은 발신하지 않으므로).
  검열해제로 얻는 이점이 없고, 게이트·EgressGuard 가 실제 통제선이다.

---

## 3. Ollama 로 5분 세팅 (프로토타이핑)

```bash
# 1) 설치: https://ollama.com/download  (Windows/macOS/Linux)
# 2) 모델 받기
ollama pull qwen2.5-coder:32b
# 3) 서버 확인(기본 포트 11434, OpenAI 호환 엔드포인트 /v1)
curl http://127.0.0.1:11434/v1/models
```

SENTINEL 환경변수 (PowerShell):

```powershell
$env:SENTINEL_AI_PROVIDER = "local"
$env:SENTINEL_AI_MODEL    = "qwen2.5-coder:32b"   # 생략 시 이 값이 기본
# baseUrl 생략 시 http://127.0.0.1:11434 (Ollama 기본). 키 불필요.
npm start
```

bash/zsh:

```bash
export SENTINEL_AI_PROVIDER=local
export SENTINEL_AI_MODEL=qwen2.5-coder:32b
npm start
```

`GET /api/ai/status` 로 확인:

```json
{ "configured": true, "provider": "local", "model": "qwen2.5-coder:32b", "baseUrl": "http://127.0.0.1:11434", "local": true }
```

---

## 4. vLLM 로 세팅 (처리량·동시성)

```bash
pip install vllm
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-Coder-32B-Instruct \
  --host 127.0.0.1 --port 8000 \
  --max-model-len 16384
```

```powershell
$env:SENTINEL_AI_PROVIDER = "local"
$env:SENTINEL_AI_BASE_URL = "http://127.0.0.1:8000"          # vLLM 포트
$env:SENTINEL_AI_MODEL    = "Qwen/Qwen2.5-Coder-32B-Instruct"
# vLLM 에 API 키를 걸었다면:  $env:SENTINEL_AI_API_KEY = "your-key"
npm start
```

> `baseUrl` 은 `/v1` **앞의 호스트만** 넣는다(엔진이 `/v1/chat/completions` 를 붙임).

### 환경변수 요약

| 변수 | 기본값(local) | 설명 |
|---|---|---|
| `SENTINEL_AI_PROVIDER` | `anthropic` | `local` 로 설정 시 로컬 OpenAI 호환 엔드포인트 사용 |
| `SENTINEL_AI_BASE_URL` | `http://127.0.0.1:11434` | 로컬 엔드포인트 호스트(`/v1` 제외) |
| `SENTINEL_AI_MODEL` | `qwen2.5-coder:32b` | 모델 태그/이름 |
| `SENTINEL_AI_API_KEY` | (없음) | 로컬은 불필요. vLLM 에 인증 걸었을 때만 |
| `SENTINEL_AI_TIMEOUT_MS` | `120000`(local) | 로컬 추론이 느릴 수 있어 상향. R1 계열은 더 늘리기 |
| `SENTINEL_AI_MAX_PROBES` | `18` | 모델이 제안하는 점검 후보 수 상한 |

미설정/엔드포인트 다운 시 AI 점검만 조용히 비활성(무중단·무오탐)되고 나머지 플랫폼은 그대로 동작한다.

---

## 5. 세부 페이지 토큰 검증 · 상태변경(파괴형) 점검 — 게이트 뒤에서

로컬모델과 별개로, 아래 두 경로가 실제 "세부 페이지 토큰 검증 / 파괴형" 점검을 **인가·감사 하에** 수행한다.
모두 소유권 검증(`attested`)된 본인 자산에서만, `EgressGuard` allowlist 안으로만 나간다.

### 5.1 세션 토큰 검증 Playbook (`token-audit`) — 읽기전용

보호된 상세 페이지에서 서버가 토큰을 **실제로 검증**하는지 점검한다. 본인 계정의 유효 토큰을 넣으면,
그 토큰을 변형해 각 1회씩 GET 으로 확인한다(데이터 변경·브루트포스 없음):

- 토큰 제거 → 보호 콘텐츠가 그대로 나오면 인증 미강제 (`CWE-306`)
- 서명 변조 → 수용되면 서명 미검증 (`CWE-345`)
- **JWT `alg=none` 위조** → 수용되면 알고리즘 혼동 서명 우회 (`CWE-347`)
- 임의 토큰 → 수용되면 토큰 검증 부재 (`CWE-287`)

공개 페이지 오탐을 막기 위해 "유효 토큰이 있어야만 200 이 나오는 페이지"인지 먼저 확인한 뒤에만 우회로 판정한다.

```bash
curl -X POST http://localhost:8787/api/pentest/run \
  -H "authorization: Bearer <SENTINEL_JWT>" -H "content-type: application/json" \
  -d '{
    "target": "https://app.내소유도메인.example",
    "attested": true,
    "playbook": "token-audit",
    "path": "/account/orders/1042",
    "token": "eyJhbGciOiJIUzI1Ni', ... 본인 계정의 유효 토큰"
  }'
```

### 5.2 상태변경(파괴형) 요청 — Repeater `active`

POST/PUT/PATCH/DELETE 등 상태변경 요청은 Repeater 에서 `active:true` 를 명시할 때만 나간다.
`EgressGuard` 는 이 플래그가 없으면 GET/HEAD/OPTIONS·무바디만 통과시킨다(비파괴 초크포인트).

```bash
curl -X POST http://localhost:8787/api/pentest/probe \
  -H "authorization: Bearer <SENTINEL_JWT>" -H "content-type: application/json" \
  -d '{
    "target": "https://staging.내소유도메인.example",
    "attested": true,
    "method": "DELETE",
    "path": "/api/carts/self/items/9",
    "headers": { "authorization": "Bearer <본인 토큰>" },
    "active": true
  }'
```

> 파괴형 시험은 **스테이징/복구 가능한 환경**에서 수행하고, 프로덕션 데이터에는 되돌릴 수 있는 대상만 지정하라.
> 모든 요청은 `audit.log.jsonl` 에 행위자·대상·결과와 함께 남는다.

---

## 6. 안전 모델 요약 (깨지 않는 불변식)

1. **소유권 게이트**: 검증되지 않은 자산은 능동 점검 불가. (`authorizationGate`)
2. **Egress allowlist**: 통과한 작업도 승인 범위 밖 호스트로는 패킷이 나가지 않는다. (`EgressGuard`)
3. **메서드 게이트**: 상태변경은 명시적 `active` 승인(수동 pentest)에서만. 자동 스캐너는 영원히 읽기전용.
4. **모델은 발신하지 않는다**: 로컬이든 벤더든 계획·분석만. 검열해제 모델을 도입할 이유가 없다.
5. **감사·무중단**: 모든 결정/차단은 감사로그. AI 미구성/다운은 조용히 비활성(무오탐).

로컬모델은 (1)~(5)를 **바꾸지 않고**, 오케스트레이션을 사내에서 돌려 데이터가 외부 벤더로 나가지 않게 하는 것이 목적이다.
