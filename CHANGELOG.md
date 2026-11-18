# CHANGELOG

## v0.4.0 — 2026-11-18

- 헤더 룰(Snort 3 9114939 rev2, Suricata 9114938 rev3)이 JWT처럼 점으로 나뉜 토큰의 가운데 조각에 든 트리거도 잡는다. 공개 저장소의 '공격 도구'가 가짜 JWT 가운데 조각에 트리거를 넣어 보내는 모양을 v0.3.0이 놓쳤다.
- 시험 케이스 추가: 새 공개 도구의 요청 모양 6건(Basic 35·49자, JWT 가운데 조각, JWT 머리 뒤 이어 붙임, 힙 분사용 정상 틀 값, Base64가 아닌 문자열 뒤 트리거)과 정상 JWT 대조.
- 결과: 두 엔진 모두 공격형 25건 전부 탐지, 정상 322건 오탐 0.

## v0.3.0 — 2026-11-18

- 9114940(URL 쿼리)·9114941(요청 본문, HUNT) 추가. URL 인코딩(`%2B`, `%2F`, `%3D`)을 한 글자로 센다. Snort 3·Suricata 모두.
- 시험 케이스 추가: 쿼리 리터럴·인코딩 꼬리, JSON·폼 본문 트리거, 정상 SAMLResponse·ViewState·data URI·로그인 폼·서명 쿼리·JWT JSON.
- 결과: 두 엔진 모두 공격형 21건 전부 탐지(공개 PoC의 쿼리·폼 본문·텍스트 본문 경로 포함), 정상 321건 오탐 0. 알려진 공백 0건(범위 밖: Cookie·사용자 정의 헤더, 32자 미만).

## v0.2.0 — 2026-11-18

- 첫 공개. CyberTissue 노트에 실었던 룰 2판(Snort 3: Basic·Bearer 분리 + fast_pattern, Suricata: Authorization 헤더 하나)을 옮겼다. URL-safe 문자(`-`, `_`)를 본다.
- 회귀 시험 추가: 합성 pcap 337세션(공개 트리거 변형, 공개 PoC 요청 모양, 정상 314건), Suricata 7.0.17·Snort 3.10 컨테이너, GitHub Actions.
- 결과: 두 엔진 모두 공격형 17건 중 14건 탐지, 정상 314건 오탐 0. 알려진 공백 3건(공개 PoC의 URL 쿼리·폼 본문·텍스트 본문 경로).

## v0.1.0 — 2026-11-18 (노트에만 게시)

- Authorization 헤더(Basic·Bearer)의 비정상 '=' 꼬리를 보는 첫 시안. Snort 3에서 fast pattern 경고, URL-safe Bearer 미탐.
