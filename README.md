# java4shell-detection

Java4Shell(CVE-2026-114938) 네트워크 탐지 룰(Snort 3·Suricata)과 그 회귀 시험만 다루는 저장소입니다.
Snort 3 and Suricata network detection rules for Java4Shell (CVE-2026-114938), with a synthetic-pcap regression test. Rules only — no exploit code.

> **주의 / Disclaimer**
> 이 룰은 [CyberTissue](https://github.com/jsik22/cybertissue)가 공개된 기술 정보를 바탕으로 직접 만들고 직접 시험한 것입니다. 제3자 검증을 거치지 않았고 실제 운영 트래픽에서 오탐을 확인하지 않았으므로 **미완성일 수 있습니다.** 차단(drop) 대신 탐지(alert) 모드로 먼저 돌려 보고, Talos·Emerging Threats 공식 룰이 나오면 비교해 교체를 검토하세요.
> These rules are self-made and self-tested only. They may be incomplete. Run them in alert mode first and compare with official Talos / Emerging Threats rules when available.

## 취약점 요약

- OpenJDK HotSpot의 x86-64 Base64 디코딩 최적화 코드(AVX-512 VBMI)가 입력 끝의 '=' 패딩을 처리하다 출력 길이를 잘못 계산해, 디코딩 결과 배열 끝 너머로 62바이트를 덮어쓴다. 발견·명명: [Calif](https://calif.io/java4shell/).
- 영향: Java 17(17.0.6 이상)·21·25·27 계열, AVX-512 VBMI를 지원하는 x86-64 CPU(인텔 Xeon Ice Lake 이후, AMD Zen 4 이후). ARM은 해당 없음.
- 수정: 2026-11-17 오라클·OpenJDK 보안 릴리스(17.0.21, 21.0.13, 25.0.5, 27.0.1 뒤에 ".1"이 붙은 빌드)와 각 배포판의 해당 빌드. [Oracle CSPU Nov 2026](https://www.oracle.com/security-alerts/cspunov2026.html) · [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- 해설: [CyberTissue 노트](https://jsik22.github.io/cybertissue-notes/2026/11/17/java-cve-2026-114938/)

## 룰

| 파일 | 엔진 | sid |
|---|---|---|
| [`rules/snort3/java4shell.rules`](rules/snort3/java4shell.rules) | Snort 3 | 9114938(헤더 Basic), 9114939(헤더 Bearer), 9114940(URL 쿼리), 9114941(요청 본문, HUNT) |
| [`rules/suricata/java4shell.rules`](rules/suricata/java4shell.rules) | Suricata 7 | 9114938(헤더 Basic·Bearer), 9114940(URL 쿼리), 9114941(요청 본문, HUNT) |

탐지 대상: 32자 이상의 Base64 값이 정상 패딩이 아닌 '='로 끝나는 요청(`=`, `==`, `===`, `X=`, `X==`, `XY=` 꼬리). URL-safe 문자(`-`, `_`)와 URL 인코딩(`%2B`, `%2F`, `%3D`)도 본다.

- 9114938·9114939: Authorization 헤더(Basic·Bearer).
- 9114940: URL 쿼리 파라미터 값(인코딩 전 원문을 본다).
- 9114941(HUNT): 요청 본문(텍스트·폼·JSON). 정상 데이터에서 오탐이 날 여지가 가장 커서 사냥용으로 이름을 붙였다. 탐지 모드에서 먼저 돌려 본다.

공격 **시도**를 잡을 뿐 성공 여부는 알려 주지 않는다. sid는 지역 룰 범위로 임의로 붙인 값이니 환경에 맞게 바꾼다.

### 알려진 공백

[`tests/known_gaps.json`](tests/known_gaps.json)에 있는 케이스는 현재 판이 놓친다.

- Cookie·사용자 정의 헤더(예: X-Auth-Token)로 들어오는 Base64, 32자 미만 값.
- multipart 업로드 안의 파일 내용, 압축(gzip 등)된 요청 본문, 엔진의 본문 검사 한도를 넘는 큰 본문.
- 암호화된 HTTPS: TLS를 복호화하는 프록시·WAF·IDS 뒤에 둬야 보인다.
- 네트워크 룰로 못 보는 경로는 JVM 쪽에서 메운다: `java.util.Base64$Decoder`의 IllegalArgumentException 폭증, `hs_err_pid*.log` 크래시 파일, 원인 모를 재시작.

## 회귀 시험

```
bash tests/run.sh RESULTS.md
```

- [`tests/fixtures.py`](tests/fixtures.py)가 합성 pcap을 만든다(문서용 주소, 네트워크 전송 없음). 묶음:
  - `synthetic`: 공개 트리거 모양과 변형, 정상 인증·본문·쿼리, 범위 밖 참고 케이스
  - `poc-shape`: 공개 PoC 저장소의 소스를 읽어 **요청 모양만** 옮긴 케이스(PoC는 실행하지 않는다)
  - `benign-bulk`: 무작위 정상 Basic·Bearer 300건(오탐 측정)
- Suricata(`jasonish/suricata:7.0`)와 Snort 3(`ciscotalos/snort3`) 컨테이너를 `--network none`으로 돌려 문법 검사와 pcap 실행을 하고, [`tests/score.py`](tests/score.py)가 채점한다.
- 통과 기준: 공격형 케이스를 모두 잡고(알려진 공백 제외) 정상 케이스 오탐 0. 알려진 공백을 새로 잡으면 종료 코드 2로 알린다.
- 최근 결과: [`RESULTS.md`](RESULTS.md). GitHub Actions가 push마다 같은 시험을 돈다.

## 보강 방식

CyberTissue가 공개 PoC·보고서·공식 룰을 계속 모니터링한다. 새 요청 모양이 나오면 `poc-shape` 케이스로 옮기고, 룰을 고쳐 회귀 시험을 통과하면 반영하고 릴리스 태그를 붙인다. 바뀐 내용은 [CHANGELOG](CHANGELOG.md)와 CyberTissue 노트에 적는다.

이 저장소에는 룰, 합성 시험 데이터 생성기, 채점기만 둔다. 익스플로잇 코드·페이로드·PoC 사본은 두지 않는다.

## 출처

- Calif, [Java4Shell: Write once, RCE everywhere](https://calif.io/java4shell/) (2026-11-17)
- Oracle, [Critical Security Patch Update Advisory - November 2026](https://www.oracle.com/security-alerts/cspunov2026.html)
- OpenJDK, [Vulnerability Advisory 2026/11/17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- Upwind, [Java4Shell: What We Know Now and What Comes Next](https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next) (탐지 단서)

## License

MIT
