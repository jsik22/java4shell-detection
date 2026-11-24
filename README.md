# java4shell-detection

Java4Shell(CVE-2026-114938) 네트워크 탐지 룰(Snort 3·Suricata)과 그 회귀 시험만 다루는 저장소입니다.
Snort 3 and Suricata network detection rules for Java4Shell (CVE-2026-114938), with a synthetic-pcap regression test. Rules only — no exploit code.

> **주의 / Disclaimer**
> 이 룰은 [CyberTissue](https://github.com/jsik22/cybertissue)가 공개된 기술 정보와 공개 PoC의 요청 모양을 바탕으로 직접 만들고 직접 시험한 것으로, **계속 업데이트 중입니다.** 제3자 검증과 실제 운영 트래픽 오탐 확인은 거치지 않았으니 차단(drop) 대신 탐지(alert) 모드로 먼저 돌려 보세요. Emerging Threats·Talos 공식 룰과의 비교는 [공식 룰과 비교](#공식-룰과-비교)에 있고, 두 룰은 함께 쓸 수 있습니다.
> These rules are self-made, self-tested, and continuously updated. They have not been validated by third parties or against production traffic, so run them in alert mode first. A comparison with the official Emerging Threats and Talos rules is in the section below; both rule sets can be used together.

## 취약점 요약

- OpenJDK HotSpot의 x86-64 Base64 디코딩 최적화 코드(AVX-512 VBMI)가 입력 끝의 '=' 패딩을 처리하다 출력 길이를 잘못 계산해, 디코딩 결과 배열 끝 너머로 62바이트를 덮어쓴다. 발견·명명: [Calif](https://calif.io/java4shell/).
- 영향: Java 17(17.0.6 이상)·21·25·27 계열, AVX-512 VBMI를 지원하는 x86-64 CPU(인텔 Xeon Ice Lake 이후, AMD Zen 4 이후). ARM은 해당 없음.
- 수정: 2026-11-17 오라클·OpenJDK 보안 릴리스(17.0.21, 21.0.13, 25.0.5, 27.0.1 뒤에 ".1"이 붙은 빌드)와 각 배포판의 해당 빌드. [Oracle CSPU Nov 2026](https://www.oracle.com/security-alerts/cspunov2026.html) · [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- 해설: [CyberTissue 노트](https://jsik22.github.io/cybertissue-notes/2026/11/17/java-cve-2026-114938/)

## 룰

| 파일 | 엔진 | sid |
|---|---|---|
| [`rules/snort3/java4shell.rules`](rules/snort3/java4shell.rules) | Snort 3 | 9114938(Authorization Basic), 9114939(Authorization Bearer), 9114940(URL 쿼리), 9114941(요청 본문, HUNT), 9114942(그 밖의 헤더, HUNT), 9114943(Cookie, HUNT), 9114944(Basic 안쪽 이중 인코딩, HUNT), 9114945(Priority 헤더 바이너리 항목), 9114946(Authorization 그 밖의 스킴), 9114947(URL 경로 조각, HUNT), 9114948(헤더 RFC 2047 인코딩 단어), 9114949(서버 안 스크립트의 트리거 구성), 9114950(Elasticsearch 스크립트의 허용 목록 밖 Java 이름, HUNT) |
| [`rules/suricata/java4shell.rules`](rules/suricata/java4shell.rules) | Suricata 7 | 9114938(Authorization Basic·Bearer), 9114940(URL 쿼리), 9114941(요청 본문, HUNT), 9114942(그 밖의 헤더, HUNT), 9114943(Cookie, HUNT), 9114944(Basic 안쪽 이중 인코딩, HUNT), 9114945(Priority 헤더 바이너리 항목), 9114946(Authorization 그 밖의 스킴), 9114947(URL 경로 조각, HUNT), 9114948(헤더 RFC 2047 인코딩 단어), 9114949(서버 안 스크립트의 트리거 구성), 9114950(Elasticsearch 스크립트의 허용 목록 밖 Java 이름, HUNT) |

탐지 대상: 32자 이상의 Base64 값이 정상 패딩이 아닌 '='로 끝나는 요청(`=`, `==`, `===`, `X=`, `X==`, `XY=` 꼬리). URL-safe 문자(`-`, `_`)와 URL 인코딩(`%2B`, `%2F`, `%3D`)도 본다.

- 9114938·9114939: Authorization 헤더(Basic·Bearer). JWT처럼 점(.)으로 나뉜 토큰은 각 조각을 따로 본다.
- 9114940: URL 쿼리 파라미터 값(인코딩 전 원문을 본다). 값 안의 `접두어=` 뒤 트리거도 본다.
- 9114941(HUNT): 요청 본문(텍스트·폼·JSON). 정상 데이터에서 오탐이 날 여지가 가장 커서 사냥용으로 이름을 붙였다. 탐지 모드에서 먼저 돌려 본다.
- 9114942(HUNT): Authorization과 표준 헤더(Host, User-Agent, Accept 계열, Content-Type, Referer, Origin, Sec-Fetch·Sec-Ch 계열 등)를 뺀 나머지 요청 헤더(예: X-Auth-Token, X-Api-Key). 직접 만든 인증 헤더로 Base64를 받는 애플리케이션을 겨냥한다.
- 9114943(HUNT): Cookie 값.
- 9114945: `Priority` 헤더(RFC 9218 구조화 필드) 안 바이너리 항목(`:값:`). 정상 `Priority` 값(`u=`, `i`)에는 바이너리 항목이 없다. Talos 공식 룰 설명을 보고 v0.8.0에 더했다.
- 9114946: Authorization 헤더의 Basic·Bearer가 아닌 스킴(예: ApiKey).
- 9114947(HUNT): URL 경로 조각('?' 앞 경로에서 '/' 뒤 값).
- 9114948: 요청 헤더 안 RFC 2047 인코딩 단어(`=?UTF-8?B?값?=`, 예: multipart boundary). 본문 안 인코딩 단어(multipart 이름 등)는 9114941(HUNT)이 본다.
- 9114949: 트리거 값을 요청에 싣지 않고 서버 안 스크립트(Elasticsearch Painless 등)에서 만드는 요청. 본문에 `Base64.getDecoder()`·`decode`와 함께 '=' byte(`(byte) 61`·`0x3D`·`'='`)나 트리거 모양 문자열 리터럴이 있을 때다. 경로를 가리지 않아 `_execute`·`_search`·`_update_by_query` 등 스크립트를 받는 곳을 모두 본다. 첫 무기화 공개 PoC(Elasticsearch 7.17.28·7.17.29, 2026-11-24)가 이 모양이다.
- 9114950(HUNT): Elasticsearch API 경로(`/_`)로 보낸 스크립트에 Painless 허용 목록 밖 Java 이름(MethodHandles·defineClass·Class.forName·ClassLoader)이 있을 때. 정상 Painless는 이 이름으로 컴파일되지 않는다. 공개 PoC가 트리거 뒤 체인에서 쓰며, 트리거를 숨긴 변형을 사냥할 때 쓴다.
- 러프하게 "Base64처럼 생긴 값이 있으면 모두 탐지"하는 방식은 시험에서 정상 요청의 92%에 경보가 나 쓰지 않는다. 인증, 웹소켓 키, HTTP 서명, Digest, CSRF 토큰, 요청·추적 ID가 모두 Base64 문자로만 이루어져 있어 디코딩 없이는 구분할 수 없다. 그래서 모든 룰이 트리거의 핵심 특징(32자 이상 + 정상 패딩이 아닌 '=' 꼬리)만 본다.

공격 **시도**를 잡을 뿐 성공 여부는 알려 주지 않는다. sid는 지역 룰 범위로 임의로 붙인 값이니 환경에 맞게 바꾼다.

### 알려진 공백

[`tests/known_gaps.json`](tests/known_gaps.json)에 있는 케이스는 현재 판이 놓친다.

- 32자 미만 값. 표준 헤더로 분류해 뺀 헤더(Referer, Origin 등) 안의 값.
- multipart 업로드 안의 파일 내용, 압축(gzip 등)된 요청 본문, 엔진의 본문 검사 한도를 넘는 큰 본문.
- 암호화된 HTTPS: TLS를 복호화하는 프록시·WAF·IDS 뒤에 둬야 보인다.
- 서버 안 스크립트에서 '='를 계산식(예: `60 + 1`)이나 JSON 유니코드 이스케이프(`\u003d`)로 숨기면 9114949를 피한다. 9114950(HUNT)이 체인의 Java 이름으로 일부 메운다.
- 네트워크 룰로 못 보는 경로는 JVM 쪽에서 메운다: `java.util.Base64$Decoder`의 IllegalArgumentException 폭증, `hs_err_pid*.log` 크래시 파일, 원인 모를 재시작.

## 회귀 시험

```
bash tests/run.sh RESULTS.md
```

- [`tests/fixtures.py`](tests/fixtures.py)가 합성 pcap을 만든다(문서용 주소, 네트워크 전송 없음). 묶음:
  - `synthetic`: 공개 트리거 모양과 변형, 정상 인증·본문·쿼리, 범위 밖 참고 케이스
  - `poc-shape`: 공개 PoC 저장소의 소스를 읽어 **요청 모양만** 옮긴 케이스(PoC는 실행하지 않는다)
  - `benign-bulk`: 무작위 정상 Basic·Bearer 300건(오탐 측정)
  - `talos-shape`: Talos 공식 룰이 다루는 요청 위치(값은 공개 트리거 모양만)
  - `es-benign`: 정상 Elasticsearch 스크립트 요청(산술, 필드 디코딩, byte 배열, 인코딩, `_update`, ingest, 정렬)
- Suricata(`jasonish/suricata:7.0`)와 Snort 3(`ciscotalos/snort3`) 컨테이너를 `--network none`으로 돌려 문법 검사와 pcap 실행을 하고, [`tests/score.py`](tests/score.py)가 채점한다.
- 통과 기준: 공격형 케이스를 모두 잡고(알려진 공백 제외) 정상 케이스 오탐 0. 알려진 공백을 새로 잡으면 종료 코드 2로 알린다.
- 룰 파일 첫 줄 주석의 판 번호(`# java4shell-detection vX.Y.Z`)가 CHANGELOG 최신 판과 같은지 먼저 본다. 릴리스 첨부 파일과 저장소 파일은 같은 내용이다.
- 최근 결과: [`RESULTS.md`](RESULTS.md). GitHub Actions가 push마다 같은 시험을 돈다.

## 공식 룰과 비교

Emerging Threats Open에 2026-11-18자로 Java4Shell 룰 6개(sid 2072829~2072834)가 올라왔고, 2026-11-19자 갱신에서 사냥용 룰의 길이 조건과 User-Agent 룰 등급이 바뀌었다. 갱신판을 같은 시험 pcap으로 Suricata 7.0에 돌려 비교했다(2026-11-20, 주소 변수만 `any`로 바꿈. 공식 룰 원문은 이 저장소에 넣지 않는다).

Talos 공식 룰 13개(2026-11-19, 1:67502~67513, Snort 3 전용 1:301754)는 무료 Snort Community 룰 묶음에도 들어 있다. 같은 시험 pcap을 Snort 3.10에 돌려 비교했다(2026-11-20, 원문은 이 저장소에 넣지 않는다).

| 룰 묶음 | 공격형 61건 | 정상 365건 오탐 |
|---|---|---|
| 이 저장소 v0.10.0(Snort 3·Suricata) | 61 | 0 |
| Talos 13개(Snort 3) | 23 | 0 |
| ET 기본 활성 3개(11-19 갱신판, Suricata) | 27 | 0 |
| ET 6개 전부(주석 처리된 사냥용 3개 포함) | 33 | 1 |

2026-11-24에 Elasticsearch Painless 케이스 16건(공격형 8, 정상 8)을 더해 세 묶음을 다시 돌린 결과다.

- Talos 룰은 대부분 제품별 요청 위치(SAML 아티팩트, 커넥터 인증 헤더, 콘솔 주석 헤더, CSP 보고 경로, 브랜치 페이지 토큰, Authorization의 Basic·ApiKey·Other 스킴, multipart 인코딩 단어, HTTP2-Settings, Priority 헤더, Elasticsearch Painless 스크립트)를 경로와 함께 좁게 본다. 기본 활성은 67507·67508·67512·67513 네 개다.
- 64자 이상 Base64 뒤 비정상 '=' 꼬리만 본다. 그래서 32·35·49자 같은 짧은 값, `===` 꼬리, Bearer·JWT 조각, 일반 쿼리·본문·쿠키·사용자 정의 헤더, Basic 안쪽 이중 인코딩은 보지 않는다.
- 이 저장소는 v0.9.0에서 Talos가 다루는 위치 중 놓치던 곳(Authorization의 다른 스킴, URL 경로 조각, 쿼리 값 안 `접두어=` 뒤, multipart boundary·이름의 인코딩 단어)을 보강했다. 이 위치의 시험 케이스 11건은 Talos 룰을 보고 만들어 Talos 쪽에 유리하고, 나머지 케이스는 이 저장소 룰과 함께 만들어 이 저장소 쪽에 유리하다. 운영 트래픽 기준 비교는 아니다.
- ET 기본 활성 룰은 공개 PoC의 고정 문자열(`A` 반복 뒤 `=`)과 PoC 도구 User-Agent(11-19 갱신에서 사냥용으로 내려감)를 찾는다. Painless 케이스는 스크립트 안 문자열 리터럴로 `A` 반복을 쓴 1건만 잡는다. 다른 글자로 된 값, `B=`·`BC=`처럼 꼬리 글자가 붙은 모양, 64자가 아닌 길이, JWT 조각, Basic 안쪽 이중 인코딩, Priority 헤더를 놓친다.
- ET의 주석 처리된 사냥용 3개는 11-19 갱신에서 4글자 묶음 단위로 길이를 세도록 바뀌어, 이전 판에서 정상 패딩 헤더·본문에 나던 오탐(이전 시험 56건)이 사라졌다. 남은 오탐 1건은 URL 경로의 정상 패딩(`==`) 값이다. 64자 미만 값과 `===` 꼬리는 보지 않는다.
- 1:67513은 Elasticsearch `/_search` 요청 본문 안 Painless 스크립트가 정해진 문자열(65바이트 배열과 그 예외 처리 구문)을 모두 갖출 때만 울린다. 첫 무기화 공개 PoC는 `/_scripts/painless/_execute`로 보내고 문자열도 달라, 실제 PoC 본문으로 만든 요청에서 67513은 울리지 않았다(2026-11-24, Snort 3.10 실행). 이 저장소는 v0.10.0부터 9114949·9114950이 같은 경로를 넓게 본다.

## 보강 방식

CyberTissue가 공개 PoC·보고서·공식 룰을 계속 모니터링한다. 새 요청 모양이 나오면 `poc-shape` 케이스로 옮기고, 룰을 고쳐 회귀 시험을 통과하면 반영하고 릴리스 태그를 붙인다. 바뀐 내용은 [CHANGELOG](CHANGELOG.md)와 CyberTissue 노트에 적는다.

이 저장소에는 룰, 합성 시험 데이터 생성기, 채점기만 둔다. 익스플로잇 코드·페이로드·PoC 사본은 두지 않는다.

## 출처

- Calif, [Java4Shell: Write once, RCE everywhere](https://calif.io/java4shell/) (2026-11-17)
- Oracle, [Critical Security Patch Update Advisory - November 2026](https://www.oracle.com/security-alerts/cspunov2026.html)
- OpenJDK, [Vulnerability Advisory 2026/11/17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- Upwind, [Java4Shell: What We Know Now and What Comes Next](https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next) (탐지 단서)
- Proofpoint Emerging Threats, [ET Open 룰셋](https://rules.emergingthreats.net/open/) (sid 2072829~2072834, 2026-11-18)

## License

MIT
