# 회귀 시험 결과

- 실행: 2026-11-19T14:29Z
- 엔진: Suricata version 7.0.17, Snort++ 3.10.0.0

**suricata**: 공격형 42/42 탐지(알려진 공백 0) · 정상 347/347 조용(오탐 0)

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
| S-G02 | synthetic | True | 탐지 9114943 | Cookie 헤더의 트리거 |
| S-G03 | synthetic | True | 탐지 9114942 | 사용자 정의 헤더의 트리거 |
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
| G-auth-35 | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Basic A*34+'=' (35자) |
| G-auth-49 | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Basic A*48+'=' (49자) |
| G-bearer-jwt-seg | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Bearer 가짜 JWT 가운데 조각에 트리거 |
| G-bearer-concat | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Bearer JWT 머리 뒤에 트리거를 이어 붙임 |
| G-spray-32 | poc-shape | None | - | Ghost-Bx1/java-exploits exploit.py 힙 분사 Basic A*32(정상 틀, 트리거 아님) |
| G-spel-junk | poc-shape | None | - | Ghost-Bx1/java-exploits exploit.py Basic 값 앞에 Base64 아닌 문자열 + 트리거(디코더가 앞에서 멈춰 트리거 불성립 추정) |
| S-N19 | synthetic | False | - | 정상 JWT 세 조각(서명 URL-safe) |
| S-basic-nested | poc-shape | True | 탐지 9114944 | sam00/Java4Shell-CVE-2026-114938-PoC payloads.py Basic password_literal: Base64('warmup:'+A*64+'=') — 바깥 값은 정상 Base64(이중 인코딩). 앱이 비밀번호를 다시 디코딩할 때만 트리거(9114944 HUNT) |
| S-json-token | poc-shape | True | 탐지 9114941 | sam00/Java4Shell-CVE-2026-114938-PoC payloads.py JSON token·password 필드에 A*64+'=' 리터럴 |
| H-cookie-jsess | real-headers | False | - | 현실 정상 헤더 H-cookie-jsess |
| H-cookie-b64 | real-headers | False | - | 현실 정상 헤더 H-cookie-b64 |
| H-cookie-b64pad | real-headers | False | - | 현실 정상 헤더 H-cookie-b64pad |
| H-cookie-uuid | real-headers | False | - | 현실 정상 헤더 H-cookie-uuid |
| H-cookie-jwt | real-headers | False | - | 현실 정상 헤더 H-cookie-jwt |
| H-ws-key | real-headers | False | - | 현실 정상 헤더 H-ws-key |
| H-req-id | real-headers | False | - | 현실 정상 헤더 H-req-id |
| H-traceparent | real-headers | False | - | 현실 정상 헤더 H-traceparent |
| H-etag | real-headers | False | - | 현실 정상 헤더 H-etag |
| H-csrf | real-headers | False | - | 현실 정상 헤더 H-csrf |
| H-sig | real-headers | False | - | 현실 정상 헤더 H-sig |
| H-digest | real-headers | False | - | 현실 정상 헤더 H-digest |
| H-amz | real-headers | False | - | 현실 정상 헤더 H-amz |
| H-apikey | real-headers | False | - | 현실 정상 헤더 H-apikey |
| H-cookie-emptyname | real-headers | False | - | 이름이 긴 빈 값 쿠키(팝업 닫기 등, 이름=UUID 포함) |
| H-cookie-emptyname-mid | real-headers | False | - | 이름이 긴 빈 값 쿠키가 중간 |
| S-N20 | synthetic | False | - | 폼 본문 끝의 이름이 긴 빈 값 필드 |
| H-kv-emptyname | real-headers | False | - | 사용자 정의 헤더 안 key=value 목록 끝의 이름이 긴 빈 값 |
| H-att-scheme | real-headers | True | 탐지 9114942 | 사용자 정의 헤더 '스킴 값' 형태의 트리거 |
| H-att-cookie | real-headers | True | 탐지 9114943 | Cookie 값의 트리거(다른 쿠키 뒤) |
| H-att-api | real-headers | True | 탐지 9114942 | X-Api-Key 트리거 A*128+'=' |
| H-att-kv | real-headers | True | 탐지 9114942 | 사용자 정의 헤더 안 key=트리거 |
| H-att-token-url | real-headers | True | 탐지 9114942 | X-Token URL-safe 값+'XY=' |
| D-P01 | synthetic | True | 탐지 9114944 | Basic 안쪽 비밀번호 A*128+'=' |
| D-P02 | synthetic | True | 탐지 9114944 | Basic 안쪽 비밀번호 무작위 64자+'Bc=' |
| D-P03 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 뒤에 다른 헤더 |
| D-P04 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 바깥 값에 정상 패딩 '=' |
| D-P05 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 바깥 값에 정상 패딩 '==' |
| D-N01 | synthetic | False | - | Basic 안쪽 비밀번호가 정상 Base64 64자(패딩 없음) |
| D-N02 | synthetic | False | - | Basic 안쪽 비밀번호가 정상 Base64 68자('==' 패딩) |
| D-N03 | synthetic | False | - | Basic 안쪽 긴 영숫자 비밀번호 48자 |
| D-N04 | synthetic | False | - | Basic 안쪽 '='가 든 짧은 비밀번호 |
| D-G01 | synthetic | None | - | Basic 안쪽 짧은 꼬리 A*28+'=' (8그룹 미만) |
| PR-P01 | synthetic | True | 탐지 9114945 | Priority 사전 멤버 바이너리 :A*64+'=:' |
| PR-P02 | synthetic | True | 탐지 9114945 | Priority 바이너리 항목만 :A*128+'=:' |
| PR-P03 | synthetic | True | 탐지 9114945 | Priority 소문자 헤더명, 무작위 64자+'Bc=' |
| PR-N01 | synthetic | False | - | 정상 Priority u=0, i |
| PR-N02 | synthetic | False | - | Priority 정상 바이너리 64자(패딩 없음) |
| PR-N03 | synthetic | False | - | Priority 정상 바이너리 68자('==' 패딩) |

**snort**: 공격형 42/42 탐지(알려진 공백 0) · 정상 347/347 조용(오탐 0)

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
| S-G02 | synthetic | True | 탐지 9114943 | Cookie 헤더의 트리거 |
| S-G03 | synthetic | True | 탐지 9114942 | 사용자 정의 헤더의 트리거 |
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
| G-auth-35 | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Basic A*34+'=' (35자) |
| G-auth-49 | poc-shape | True | 탐지 9114938 | Ghost-Bx1/java-exploits poc.py Basic A*48+'=' (49자) |
| G-bearer-jwt-seg | poc-shape | True | 탐지 9114939 | Ghost-Bx1/java-exploits poc.py Bearer 가짜 JWT 가운데 조각에 트리거 |
| G-bearer-concat | poc-shape | True | 탐지 9114939 | Ghost-Bx1/java-exploits poc.py Bearer JWT 머리 뒤에 트리거를 이어 붙임 |
| G-spray-32 | poc-shape | None | - | Ghost-Bx1/java-exploits exploit.py 힙 분사 Basic A*32(정상 틀, 트리거 아님) |
| G-spel-junk | poc-shape | None | - | Ghost-Bx1/java-exploits exploit.py Basic 값 앞에 Base64 아닌 문자열 + 트리거(디코더가 앞에서 멈춰 트리거 불성립 추정) |
| S-N19 | synthetic | False | - | 정상 JWT 세 조각(서명 URL-safe) |
| S-basic-nested | poc-shape | True | 탐지 9114944 | sam00/Java4Shell-CVE-2026-114938-PoC payloads.py Basic password_literal: Base64('warmup:'+A*64+'=') — 바깥 값은 정상 Base64(이중 인코딩). 앱이 비밀번호를 다시 디코딩할 때만 트리거(9114944 HUNT) |
| S-json-token | poc-shape | True | 탐지 9114941 | sam00/Java4Shell-CVE-2026-114938-PoC payloads.py JSON token·password 필드에 A*64+'=' 리터럴 |
| H-cookie-jsess | real-headers | False | - | 현실 정상 헤더 H-cookie-jsess |
| H-cookie-b64 | real-headers | False | - | 현실 정상 헤더 H-cookie-b64 |
| H-cookie-b64pad | real-headers | False | - | 현실 정상 헤더 H-cookie-b64pad |
| H-cookie-uuid | real-headers | False | - | 현실 정상 헤더 H-cookie-uuid |
| H-cookie-jwt | real-headers | False | - | 현실 정상 헤더 H-cookie-jwt |
| H-ws-key | real-headers | False | - | 현실 정상 헤더 H-ws-key |
| H-req-id | real-headers | False | - | 현실 정상 헤더 H-req-id |
| H-traceparent | real-headers | False | - | 현실 정상 헤더 H-traceparent |
| H-etag | real-headers | False | - | 현실 정상 헤더 H-etag |
| H-csrf | real-headers | False | - | 현실 정상 헤더 H-csrf |
| H-sig | real-headers | False | - | 현실 정상 헤더 H-sig |
| H-digest | real-headers | False | - | 현실 정상 헤더 H-digest |
| H-amz | real-headers | False | - | 현실 정상 헤더 H-amz |
| H-apikey | real-headers | False | - | 현실 정상 헤더 H-apikey |
| H-cookie-emptyname | real-headers | False | - | 이름이 긴 빈 값 쿠키(팝업 닫기 등, 이름=UUID 포함) |
| H-cookie-emptyname-mid | real-headers | False | - | 이름이 긴 빈 값 쿠키가 중간 |
| S-N20 | synthetic | False | - | 폼 본문 끝의 이름이 긴 빈 값 필드 |
| H-kv-emptyname | real-headers | False | - | 사용자 정의 헤더 안 key=value 목록 끝의 이름이 긴 빈 값 |
| H-att-scheme | real-headers | True | 탐지 9114942 | 사용자 정의 헤더 '스킴 값' 형태의 트리거 |
| H-att-cookie | real-headers | True | 탐지 9114943 | Cookie 값의 트리거(다른 쿠키 뒤) |
| H-att-api | real-headers | True | 탐지 9114942 | X-Api-Key 트리거 A*128+'=' |
| H-att-kv | real-headers | True | 탐지 9114942 | 사용자 정의 헤더 안 key=트리거 |
| H-att-token-url | real-headers | True | 탐지 9114942 | X-Token URL-safe 값+'XY=' |
| D-P01 | synthetic | True | 탐지 9114944 | Basic 안쪽 비밀번호 A*128+'=' |
| D-P02 | synthetic | True | 탐지 9114944 | Basic 안쪽 비밀번호 무작위 64자+'Bc=' |
| D-P03 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 뒤에 다른 헤더 |
| D-P04 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 바깥 값에 정상 패딩 '=' |
| D-P05 | synthetic | True | 탐지 9114944 | Basic 안쪽 트리거, 바깥 값에 정상 패딩 '==' |
| D-N01 | synthetic | False | - | Basic 안쪽 비밀번호가 정상 Base64 64자(패딩 없음) |
| D-N02 | synthetic | False | - | Basic 안쪽 비밀번호가 정상 Base64 68자('==' 패딩) |
| D-N03 | synthetic | False | - | Basic 안쪽 긴 영숫자 비밀번호 48자 |
| D-N04 | synthetic | False | - | Basic 안쪽 '='가 든 짧은 비밀번호 |
| D-G01 | synthetic | None | - | Basic 안쪽 짧은 꼬리 A*28+'=' (8그룹 미만) |
| PR-P01 | synthetic | True | 탐지 9114945 | Priority 사전 멤버 바이너리 :A*64+'=:' |
| PR-P02 | synthetic | True | 탐지 9114945 | Priority 바이너리 항목만 :A*128+'=:' |
| PR-P03 | synthetic | True | 탐지 9114945 | Priority 소문자 헤더명, 무작위 64자+'Bc=' |
| PR-N01 | synthetic | False | - | 정상 Priority u=0, i |
| PR-N02 | synthetic | False | - | Priority 정상 바이너리 64자(패딩 없음) |
| PR-N03 | synthetic | False | - | Priority 정상 바이너리 68자('==' 패딩) |

