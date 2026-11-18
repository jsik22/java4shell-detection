# CHANGELOG

## v0.2.0 — 2026-11-18

- 첫 공개. CyberTissue 노트에 실었던 룰 2판(Snort 3: Basic·Bearer 분리 + fast_pattern, Suricata: Authorization 헤더 하나)을 옮겼다. URL-safe 문자(`-`, `_`)를 본다.
- 회귀 시험 추가: 합성 pcap 337세션(공개 트리거 변형, 공개 PoC 요청 모양, 정상 314건), Suricata 7.0.17·Snort 3.10 컨테이너, GitHub Actions.
- 결과: 두 엔진 모두 공격형 17건 중 14건 탐지, 정상 314건 오탐 0. 알려진 공백 3건(공개 PoC의 URL 쿼리·폼 본문·텍스트 본문 경로).

## v0.1.0 — 2026-11-18 (노트에만 게시)

- Authorization 헤더(Basic·Bearer)의 비정상 '=' 꼬리를 보는 첫 시안. Snort 3에서 fast pattern 경고, URL-safe Bearer 미탐.
