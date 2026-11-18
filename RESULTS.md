# 회귀 시험 결과

- 실행: 2026-11-18T01:16Z
- 엔진: Suricata version 7.0.17, Snort++ 3.10.0.0

**suricata**: 공격형 21/21 탐지(알려진 공백 0) · 정상 321/321 조용(오탐 0)

| 케이스 | 묶음 | 기대 | 결과 | 설명 |
|---|---|---|---|---|
| S-P01 | synthetic | True | 탐지 9114938 | Basic A*64+'=' (칼리프 트리거) |
| S-P02 | synthetic | True | 탐지 9114938 | Basic A*128+'=' (구 17 트리거) |
| S-P03 | synthetic | True | 탐지 9114938 | Basic A*64+'B=' |
| S-P04 | synthetic | True | 탐지 9114938 | Basic A*64+'BC=' |
| S-P05 | synthetic | True | 탐지 9114938 | Basic A*64+'B==' |
| S-P06 | synthetic | True | 탐지 9114938 | Basic A*64+'==' |
| S-P07 | synthetic | True | 탐지 9114938 | Basic A*64+'===' |
| S-P08 | synthetic | True | 탐지 9114938 | Bearer A*64+'=' |
| S-P09 | synthetic | True | 탐지 9114938 | 소문자 헤더명·스킴 |
| S-P10 | synthetic | True | 탐지 9114938 | 최소 길이 A*32+'=' |
| S-P11 | synthetic | True | 탐지 9114938 | 무작위 Base64 96자+'=' |
| S-P12 | synthetic | True | 탐지 9114938 | 스킴 뒤 공백 두 칸 |
| S-P13 | synthetic | True | 탐지 9114938 | URL-safe 문자 섞인 Bearer+'=' |
| S-N01 | synthetic | False | - | 정상 패딩 'XY==' |
| S-N02 | synthetic | False | - | 정상 패딩 'XYZ=' |
| S-N03 | synthetic | False | - | 패딩 없음 A*64 |
| S-N04 | synthetic | False | - | 짧은 Basic 정상 계정 |
| S-N05 | synthetic | False | - | 긴 Basic 정상 계정 |
| S-N06 | synthetic | False | - | JWT Bearer |
| S-N07 | synthetic | False | - | 불투명 Bearer 40자 |
| S-N08 | synthetic | False | - | Digest 인증 |
| S-N09 | synthetic | False | - | 정상 Base64 폼 본문 |
| S-N10 | synthetic | False | - | 정상 Base64 JSON 본문 |
| S-N11 | synthetic | False | - | 정상 Base64 쿼리 |
| S-Q01 | synthetic | True | 탐지 9114940 | 쿼리 ?b=A*64+'=' (리터럴 '=') |
| S-Q02 | synthetic | True | 탐지 9114940 | 쿼리 ?x=1&b=A*64+'%3D' (인코딩) |
| S-J01 | synthetic | True | 탐지 9114941 | JSON 본문 {"file": A*64+'='} |
| S-F01 | synthetic | True | 탐지 9114941 | 폼 본문 data=A*64+'%3D'&x=1 |
| S-N12 | synthetic | False | - | SAMLResponse 폼(정상 패딩, URL 인코딩) |
| S-N13 | synthetic | False | - | data URI 이미지 JSON(정상 패딩) |
| S-N14 | synthetic | False | - | 로그인 폼(짧은 값) |
| S-N15 | synthetic | False | - | 서명 쿼리(16진수, '=' 꼬리 없음) |
| S-N16 | synthetic | False | - | 긴 경로·쿼리(Base64 아님) |
| S-N17 | synthetic | False | - | ViewState 폼(정상 패딩 1개) |
| S-N18 | synthetic | False | - | JSON에 JWT·UUID |
| S-G01 | synthetic | None | - | 짧은 꼬리 A*28+'=' (8그룹 미만) |
| S-G02 | synthetic | None | - | Cookie 헤더의 트리거 |
| S-G03 | synthetic | None | - | 사용자 정의 헤더의 트리거 |
| R-auth-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack auth control |
| R-query-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack query control |
| R-body-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack form body control |
| R-auth-padded | poc-shape | True | 탐지 9114938 | r3dvei1/java4shell RemoteAttack auth padded |
| R-query-padded | poc-shape | True | 탐지 9114940 | r3dvei1/java4shell RemoteAttack query padded |
| R-body-padded | poc-shape | True | 탐지 9114941 | r3dvei1/java4shell RemoteAttack form body padded |
| R-auth-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack auth badtail |
| R-query-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack query badtail |
| R-body-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack form body badtail |
| P-text-body | poc-shape | True | 탐지 9114941 | Pwned-test/cve-2026-114938-java17-PoC POST text/plain A*128+'=' |

**snort**: 공격형 21/21 탐지(알려진 공백 0) · 정상 321/321 조용(오탐 0)

| 케이스 | 묶음 | 기대 | 결과 | 설명 |
|---|---|---|---|---|
| S-P01 | synthetic | True | 탐지 9114938 | Basic A*64+'=' (칼리프 트리거) |
| S-P02 | synthetic | True | 탐지 9114938 | Basic A*128+'=' (구 17 트리거) |
| S-P03 | synthetic | True | 탐지 9114938 | Basic A*64+'B=' |
| S-P04 | synthetic | True | 탐지 9114938 | Basic A*64+'BC=' |
| S-P05 | synthetic | True | 탐지 9114938 | Basic A*64+'B==' |
| S-P06 | synthetic | True | 탐지 9114938 | Basic A*64+'==' |
| S-P07 | synthetic | True | 탐지 9114938 | Basic A*64+'===' |
| S-P08 | synthetic | True | 탐지 9114939 | Bearer A*64+'=' |
| S-P09 | synthetic | True | 탐지 9114938 | 소문자 헤더명·스킴 |
| S-P10 | synthetic | True | 탐지 9114938 | 최소 길이 A*32+'=' |
| S-P11 | synthetic | True | 탐지 9114938 | 무작위 Base64 96자+'=' |
| S-P12 | synthetic | True | 탐지 9114938 | 스킴 뒤 공백 두 칸 |
| S-P13 | synthetic | True | 탐지 9114939 | URL-safe 문자 섞인 Bearer+'=' |
| S-N01 | synthetic | False | - | 정상 패딩 'XY==' |
| S-N02 | synthetic | False | - | 정상 패딩 'XYZ=' |
| S-N03 | synthetic | False | - | 패딩 없음 A*64 |
| S-N04 | synthetic | False | - | 짧은 Basic 정상 계정 |
| S-N05 | synthetic | False | - | 긴 Basic 정상 계정 |
| S-N06 | synthetic | False | - | JWT Bearer |
| S-N07 | synthetic | False | - | 불투명 Bearer 40자 |
| S-N08 | synthetic | False | - | Digest 인증 |
| S-N09 | synthetic | False | - | 정상 Base64 폼 본문 |
| S-N10 | synthetic | False | - | 정상 Base64 JSON 본문 |
| S-N11 | synthetic | False | - | 정상 Base64 쿼리 |
| S-Q01 | synthetic | True | 탐지 9114940 | 쿼리 ?b=A*64+'=' (리터럴 '=') |
| S-Q02 | synthetic | True | 탐지 9114940 | 쿼리 ?x=1&b=A*64+'%3D' (인코딩) |
| S-J01 | synthetic | True | 탐지 9114941 | JSON 본문 {"file": A*64+'='} |
| S-F01 | synthetic | True | 탐지 9114941 | 폼 본문 data=A*64+'%3D'&x=1 |
| S-N12 | synthetic | False | - | SAMLResponse 폼(정상 패딩, URL 인코딩) |
| S-N13 | synthetic | False | - | data URI 이미지 JSON(정상 패딩) |
| S-N14 | synthetic | False | - | 로그인 폼(짧은 값) |
| S-N15 | synthetic | False | - | 서명 쿼리(16진수, '=' 꼬리 없음) |
| S-N16 | synthetic | False | - | 긴 경로·쿼리(Base64 아님) |
| S-N17 | synthetic | False | - | ViewState 폼(정상 패딩 1개) |
| S-N18 | synthetic | False | - | JSON에 JWT·UUID |
| S-G01 | synthetic | None | - | 짧은 꼬리 A*28+'=' (8그룹 미만) |
| S-G02 | synthetic | None | - | Cookie 헤더의 트리거 |
| S-G03 | synthetic | None | - | 사용자 정의 헤더의 트리거 |
| R-auth-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack auth control |
| R-query-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack query control |
| R-body-control | poc-shape | False | - | r3dvei1/java4shell RemoteAttack form body control |
| R-auth-padded | poc-shape | True | 탐지 9114938 | r3dvei1/java4shell RemoteAttack auth padded |
| R-query-padded | poc-shape | True | 탐지 9114940 | r3dvei1/java4shell RemoteAttack query padded |
| R-body-padded | poc-shape | True | 탐지 9114941 | r3dvei1/java4shell RemoteAttack form body padded |
| R-auth-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack auth badtail |
| R-query-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack query badtail |
| R-body-badtail | poc-shape | None | - | r3dvei1/java4shell RemoteAttack form body badtail |
| P-text-body | poc-shape | True | 탐지 9114941 | Pwned-test/cve-2026-114938-java17-PoC POST text/plain A*128+'=' |

