"""Java4Shell(CVE-2026-114938) 탐지 룰 회귀 시험용 합성 pcap 생성기. 파이썬 표준 라이브러리만 쓴다.

- 케이스마다 TCP 세션 하나(handshake → HTTP 요청 → 200 응답 → FIN). 출발 포트로 케이스를 구분한다.
- 주소는 문서용 대역(192.0.2.10 → 198.51.100.20:80)만 쓴다. 네트워크로 아무것도 보내지 않는다.
- 공격형 값은 공개된 트리거 모양(Base64 뒤 비정상 '=' 꼬리)뿐이다. 익스플로잇 코드·페이로드는 없다.
- poc-shape 케이스는 공개 PoC 저장소의 소스를 읽어 요청 모양만 옮긴 것이다(PoC는 실행하지 않는다).

expect: True = 탐지해야 함, False = 탐지하면 안 됨(오탐 측정), None = 트리거 모양이 아니거나 범위 밖(참고용).

사용: python3 tests/fixtures.py OUT.pcap OUT-index.json
"""
import base64
import json
import random
import struct
import sys
from urllib.parse import quote

random.seed(114938)
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
A = "A"


def rnd(n, alpha=B64):
    return "".join(random.choice(alpha) for _ in range(n))


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def req(method, path, headers, body=""):
    r = f"{method} {path} HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: fixtures/1.0\r\nAccept: */*\r\n"
    for k, v in headers:
        r += f"{k}: {v}\r\n"
    if body:
        r += f"Content-Length: {len(body.encode())}\r\n"
    return (r + "\r\n" + body).encode()


def auth(v, path="/api/v1/resource"):
    return req("GET", path, [("Authorization", v)])


JWT = ".".join([b64url(b'{"alg":"HS256","typ":"JWT"}'),
                b64url(json.dumps({"sub": "user-1234", "name": "Test User", "iat": 1763424000}).encode()),
                b64url(bytes(random.getrandbits(8) for _ in range(32)))])

# (id, 묶음, expect, 설명, 요청 바이트)
CASES = [
    # --- 합성: 탐지해야 함(칼리프·업윈드가 밝힌 비정상 '=' 꼬리) ---
    ("S-P01", "synthetic", True, "Basic A*64+'=' (칼리프 트리거)", auth("Basic " + A * 64 + "=")),
    ("S-P02", "synthetic", True, "Basic A*128+'=' (구 17 트리거)", auth("Basic " + A * 128 + "=")),
    ("S-P03", "synthetic", True, "Basic A*64+'B='", auth("Basic " + A * 64 + "B=")),
    ("S-P04", "synthetic", True, "Basic A*64+'BC='", auth("Basic " + A * 64 + "BC=")),
    ("S-P05", "synthetic", True, "Basic A*64+'B=='", auth("Basic " + A * 64 + "B==")),
    ("S-P06", "synthetic", True, "Basic A*64+'=='", auth("Basic " + A * 64 + "==")),
    ("S-P07", "synthetic", True, "Basic A*64+'==='", auth("Basic " + A * 64 + "===")),
    ("S-P08", "synthetic", True, "Bearer A*64+'='", auth("Bearer " + A * 64 + "=")),
    ("S-P09", "synthetic", True, "소문자 헤더명·스킴", req("GET", "/", [("authorization", "basic " + A * 64 + "=")])),
    ("S-P10", "synthetic", True, "최소 길이 A*32+'='", auth("Basic " + A * 32 + "=")),
    ("S-P11", "synthetic", True, "무작위 Base64 96자+'='", auth("Basic " + rnd(96) + "=")),
    ("S-P12", "synthetic", True, "스킴 뒤 공백 두 칸", auth("Basic  " + A * 64 + "=")),
    ("S-P13", "synthetic", True, "URL-safe 문자 섞인 Bearer+'='", auth("Bearer " + rnd(64, B64[:62] + "-_") + "-=")),
    # --- 합성: 탐지하면 안 됨 ---
    ("S-N01", "synthetic", False, "정상 패딩 'XY=='", auth("Basic " + A * 64 + "BC==")),
    ("S-N02", "synthetic", False, "정상 패딩 'XYZ='", auth("Basic " + A * 64 + "BCD=")),
    ("S-N03", "synthetic", False, "패딩 없음 A*64", auth("Basic " + A * 64)),
    ("S-N04", "synthetic", False, "짧은 Basic 정상 계정", auth("Basic " + base64.b64encode(b"user:pass").decode())),
    ("S-N05", "synthetic", False, "긴 Basic 정상 계정", auth("Basic " + base64.b64encode(b"service-account@example.test:Very-Long-Passw0rd-2026!!").decode())),
    ("S-N06", "synthetic", False, "JWT Bearer", auth("Bearer " + JWT)),
    ("S-N07", "synthetic", False, "불투명 Bearer 40자", auth("Bearer " + rnd(40, B64[:62]))),
    ("S-N08", "synthetic", False, "Digest 인증", auth('Digest username="u", realm="r", nonce="' + rnd(48, B64[:62]) + '=", uri="/", response="' + rnd(32, "0123456789abcdef") + '"')),
    ("S-N09", "synthetic", False, "정상 Base64 폼 본문", req("POST", "/upload", [("Content-Type", "application/x-www-form-urlencoded")], "f=" + quote(base64.b64encode(bytes(range(200))).decode(), safe=""))),
    ("S-N10", "synthetic", False, "정상 Base64 JSON 본문", req("POST", "/api", [("Content-Type", "application/json")], json.dumps({"file": base64.b64encode(bytes(range(150))).decode()}))),
    ("S-N11", "synthetic", False, "정상 Base64 쿼리", req("GET", "/d?b=" + quote(base64.b64encode(bytes(range(97))).decode(), safe=""), [])),
    # --- 합성: 쿼리·본문 경로(공개 PoC가 쓰는 경로) ---
    ("S-Q01", "synthetic", True, "쿼리 ?b=A*64+'=' (리터럴 '=')", req("GET", "/d?b=" + A * 64 + "=", [])),
    ("S-Q02", "synthetic", True, "쿼리 ?x=1&b=A*64+'%3D' (인코딩)", req("GET", "/d?x=1&b=" + A * 64 + "%3D", [])),
    ("S-J01", "synthetic", True, "JSON 본문 {\"file\": A*64+'='}", req("POST", "/api", [("Content-Type", "application/json")], json.dumps({"file": A * 64 + "="}))),
    ("S-F01", "synthetic", True, "폼 본문 data=A*64+'%3D'&x=1", req("POST", "/f", [("Content-Type", "application/x-www-form-urlencoded")], "data=" + A * 64 + "%3D&x=1")),
    # --- 합성: 쿼리·본문 정상(오탐 측정) ---
    ("S-N12", "synthetic", False, "SAMLResponse 폼(정상 패딩, URL 인코딩)", req("POST", "/sso/acs", [("Content-Type", "application/x-www-form-urlencoded")], "SAMLResponse=" + quote(base64.b64encode(bytes(random.getrandbits(8) for _ in range(301))).decode(), safe="") + "&RelayState=%2Fhome")),
    ("S-N13", "synthetic", False, "data URI 이미지 JSON(정상 패딩)", req("POST", "/api/avatar", [("Content-Type", "application/json")], json.dumps({"img": "data:image/png;base64," + base64.b64encode(bytes(random.getrandbits(8) for _ in range(500))).decode()}))),
    ("S-N14", "synthetic", False, "로그인 폼(짧은 값)", req("POST", "/login", [("Content-Type", "application/x-www-form-urlencoded")], "username=alice&password=S3cr3t%3D%3D&remember=1")),
    ("S-N15", "synthetic", False, "서명 쿼리(16진수, '=' 꼬리 없음)", req("GET", "/file?X-Amz-Signature=" + rnd(64, "0123456789abcdef") + "&X-Amz-Expires=300", [])),
    ("S-N16", "synthetic", False, "긴 경로·쿼리(Base64 아님)", req("GET", "/static/js/app.min.js?v=" + rnd(40, "0123456789abcdef") + "&lang=ko", [])),
    ("S-N17", "synthetic", False, "ViewState 폼(정상 패딩 1개)", req("POST", "/page.aspx", [("Content-Type", "application/x-www-form-urlencoded")], "__VIEWSTATE=" + quote(base64.b64encode(bytes(random.getrandbits(8) for _ in range(149))).decode(), safe="") + "&btn=OK")),
    ("S-N18", "synthetic", False, "JSON에 JWT·UUID", req("POST", "/api/refresh", [("Content-Type", "application/json")], json.dumps({"token": JWT, "id": "00000000-0000-4000-8000-0000000a4b2f"}))),
    # --- 합성: 범위 밖·참고(현재 판이 못 잡아도 실패로 보지 않음) ---
    ("S-G01", "synthetic", None, "짧은 꼬리 A*28+'=' (8그룹 미만)", auth("Basic " + A * 28 + "=")),
    ("S-G02", "synthetic", True, "Cookie 헤더의 트리거", req("GET", "/", [("Cookie", "session=" + A * 64 + "=")])),
    ("S-G03", "synthetic", True, "사용자 정의 헤더의 트리거", req("GET", "/", [("X-Auth-Token", A * 64 + "=")])),
]

# --- 공개 PoC 요청 모양(소스에서 옮김, 실행하지 않음) ---
CTRL = base64.b64encode(b"probe").decode()
SLASH130 = "/" * 128 + "=="       # 130자, %4=2
SLASH128 = "/" * 126 + "=="       # 128자, %4=0(정상 틀) — 도구 주석과 달리 트리거 모양 아님
for label, val, expect in [("control", CTRL, False), ("padded", SLASH130, True), ("badtail", SLASH128, None)]:
    src = "r3dvei1/java4shell RemoteAttack"
    CASES.append((f"R-auth-{label}", "poc-shape", expect, f"{src} auth {label}",
                  req("GET", "/d", [("Authorization", "Basic " + val)])))
    CASES.append((f"R-query-{label}", "poc-shape", expect, f"{src} query {label}",
                  req("GET", "/d?b=" + quote(val, safe=""), [])))
    CASES.append((f"R-body-{label}", "poc-shape", expect, f"{src} form body {label}",
                  req("POST", "/d", [("Content-Type", "application/x-www-form-urlencoded")], "b=" + quote(val, safe=""))))
CASES.append(("P-text-body", "poc-shape", True, "Pwned-test/cve-2026-114938-java17-PoC POST text/plain A*128+'='",
              req("POST", "/probe", [("Content-Type", "text/plain")], A * 128 + "=")))

# Ghost-Bx1/java-exploits cve-2026-114938/poc.py·exploit.py(2026-11-18, '공격 도구'를 자처, 실제 동작 미확인)에서 요청 모양만 옮김
SRC_G = "Ghost-Bx1/java-exploits"
CASES.append(("G-auth-35", "poc-shape", True, f"{SRC_G} poc.py Basic A*34+'=' (35자)", req("GET", "/", [("Authorization", "Basic " + A * 34 + "=")])))
CASES.append(("G-auth-49", "poc-shape", True, f"{SRC_G} poc.py Basic A*48+'=' (49자)", req("GET", "/", [("Authorization", "Basic " + A * 48 + "=")])))
CASES.append(("G-bearer-jwt-seg", "poc-shape", True, f"{SRC_G} poc.py Bearer 가짜 JWT 가운데 조각에 트리거",
              req("GET", "/api/v1/", [("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9." + A * 32 + "=.fakesig")])))
CASES.append(("G-bearer-concat", "poc-shape", True, f"{SRC_G} poc.py Bearer JWT 머리 뒤에 트리거를 이어 붙임",
              req("GET", "/api/", [("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + A * 34 + "=")])))
CASES.append(("G-spray-32", "poc-shape", None, f"{SRC_G} exploit.py 힙 분사 Basic A*32(정상 틀, 트리거 아님)", req("GET", "/", [("Authorization", "Basic " + A * 32)])))
CASES.append(("G-spel-junk", "poc-shape", None, f"{SRC_G} exploit.py Basic 값 앞에 Base64 아닌 문자열 + 트리거(디코더가 앞에서 멈춰 트리거 불성립 추정)",
              req("GET", "/", [("Authorization", "Basic dXNlcjoke{T(x)}" + A * 32 + "=")])))
CASES.append(("S-N19", "synthetic", False, "정상 JWT 세 조각(서명 URL-safe)", auth("Bearer " + JWT)))
SRC_S = "sam00/Java4Shell-CVE-2026-114938-PoC"
CASES.append(("S-basic-nested", "poc-shape", True, f"{SRC_S} payloads.py Basic password_literal: Base64('warmup:'+A*64+'=') — 바깥 값은 정상 Base64(이중 인코딩). 앱이 비밀번호를 다시 디코딩할 때만 트리거(9114944 HUNT)",
              auth("Basic " + base64.b64encode(("warmup:" + A * 64 + "=").encode()).decode())))
CASES.append(("S-json-token", "poc-shape", True, f"{SRC_S} payloads.py JSON token·password 필드에 A*64+'=' 리터럴",
              req("POST", "/api/login", [("Content-Type", "application/json")], json.dumps({"token": A * 64 + "=", "password": A * 64 + "="}))))

# --- 헤더 전역·쿠키 룰용: 현실적인 정상 헤더와 헤더형 공격 ---
REAL = [
    ("H-cookie-jsess", [("Cookie", "JSESSIONID=" + rnd(32, "0123456789ABCDEF") + "; lang=ko")]),
    ("H-cookie-b64", [("Cookie", "session=" + base64.b64encode(bytes(range(48))).decode() + "; theme=dark")]),
    ("H-cookie-b64pad", [("Cookie", "state=" + base64.b64encode(bytes(range(50))).decode() + "; a=1")]),
    ("H-cookie-uuid", [("Cookie", "00000000-0000-4000-8000-0000000a4b2f=11111111-2222-4333-8444-555555555555; SESSIONID=" + rnd(32, "0123456789ABCDEF"))]),
    ("H-cookie-jwt", [("Cookie", "id_token=" + JWT)]),
    ("H-ws-key", [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Key", base64.b64encode(bytes(range(16))).decode()), ("Sec-WebSocket-Version", "13")]),
    ("H-req-id", [("X-Request-ID", "7f1c2a4e-9b3d-4e8a-a1f0-3c5d6e7f8a9b")]),
    ("H-traceparent", [("traceparent", "00-" + rnd(32, "0123456789abcdef") + "-" + rnd(16, "0123456789abcdef") + "-01")]),
    ("H-etag", [("If-None-Match", 'W/"' + rnd(40, "0123456789abcdef") + '"')]),
    ("H-csrf", [("X-CSRF-Token", rnd(43, B64[:62] + "-_"))]),
    ("H-sig", [("Signature", "sig1=:" + base64.b64encode(bytes(range(64))).decode() + ":"), ("Signature-Input", 'sig1=("@authority");created=1700000000;keyid="' + rnd(43, B64[:62] + "-_") + '";tag="web-bot-auth"')]),
    ("H-digest", [("Digest", "sha-256=" + base64.b64encode(bytes(range(32))).decode())]),
    ("H-amz", [("X-Amz-Security-Token", base64.b64encode(bytes(range(200))).decode())]),
    ("H-apikey", [("X-Api-Key", base64.b64encode(bytes(range(33))).decode())]),
]
for cid, hs in REAL:
    CASES.append((cid, "real-headers", False, "현실 정상 헤더 " + cid, req("GET", "/", hs)))
CASES.append(("H-cookie-emptyname", "real-headers", False, "이름이 긴 빈 값 쿠키(팝업 닫기 등, 이름=UUID 포함)",
              req("GET", "/", [("Cookie", "lang=ko; refreshToken=" + JWT + "; popup_today_close_00000000-0000-4000-8000-000000000000=")])))
CASES.append(("H-cookie-emptyname-mid", "real-headers", False, "이름이 긴 빈 값 쿠키가 중간",
              req("GET", "/", [("Cookie", "popup_today_close_00000000-0000-4000-8000-000000000000=; lang=ko")])))
CASES.append(("S-N20", "synthetic", False, "폼 본문 끝의 이름이 긴 빈 값 필드",
              req("POST", "/f", [("Content-Type", "application/x-www-form-urlencoded")], "a=1&popup_today_close_00000000-0000-4000-8000-000000000000=")))
CASES.append(("H-kv-emptyname", "real-headers", False, "사용자 정의 헤더 안 key=value 목록 끝의 이름이 긴 빈 값",
              req("GET", "/", [("X-Prefs", "theme=dark; popup_today_close_00000000-0000-4000-8000-000000000000=")])))
CASES.append(("H-att-scheme", "real-headers", True, "사용자 정의 헤더 '스킴 값' 형태의 트리거",
              req("GET", "/", [("X-Auth", "Token " + A * 64 + "=")])))
CASES.append(("H-att-cookie", "real-headers", True, "Cookie 값의 트리거(다른 쿠키 뒤)", req("GET", "/", [("Cookie", "lang=ko; session=" + A * 64 + "=; theme=dark")])))
CASES.append(("H-att-api", "real-headers", True, "X-Api-Key 트리거 A*128+'='", req("GET", "/", [("X-Api-Key", A * 128 + "=")])))
CASES.append(("H-att-kv", "real-headers", True, "사용자 정의 헤더 안 key=트리거", req("GET", "/", [("X-Session", "v=1; data=" + A * 64 + "=")])))
CASES.append(("H-att-token-url", "real-headers", True, "X-Token URL-safe 값+'XY='", req("GET", "/", [("X-Token", rnd(64, B64[:62] + "-_") + "Ab=")])))

# --- 정상 대량(오탐 측정) ---
for i in range(300):
    raw = bytes(random.getrandbits(8) for _ in range(random.randint(8, 180)))
    val = ("Bearer " + b64url(raw)) if i % 3 == 0 else ("Basic " + base64.b64encode(raw).decode())
    CASES.append((f"B{i:03d}", "benign-bulk", False, "정상 대량", auth(val)))


# --- Basic 이중 인코딩(9114944, HUNT): 비밀번호 칸 안의 트리거. 정상 대량 뒤에 둬 난수 순서를 바꾸지 않는다 ---
def basic_up(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


ALNUM = B64[:62]
CASES += [
    ("D-P01", "synthetic", True, "Basic 안쪽 비밀번호 A*128+'='", auth(basic_up("admin", A * 128 + "="))),
    ("D-P02", "synthetic", True, "Basic 안쪽 비밀번호 무작위 64자+'Bc='", auth(basic_up("u", rnd(64) + "Bc="))),
    ("D-P03", "synthetic", True, "Basic 안쪽 트리거, 뒤에 다른 헤더", req("GET", "/", [("Authorization", basic_up("svc", A * 64 + "=")), ("X-Request-Id", rnd(16, "0123456789abcdef"))])),
    ("D-P04", "synthetic", True, "Basic 안쪽 트리거, 바깥 값에 정상 패딩 '='", auth(basic_up("ab", A * 64 + "="))),
    ("D-P05", "synthetic", True, "Basic 안쪽 트리거, 바깥 값에 정상 패딩 '=='", auth(basic_up("abcd", A * 64 + "="))),
    ("D-N01", "synthetic", False, "Basic 안쪽 비밀번호가 정상 Base64 64자(패딩 없음)", auth(basic_up("svc", base64.b64encode(bytes(range(48))).decode()))),
    ("D-N02", "synthetic", False, "Basic 안쪽 비밀번호가 정상 Base64 68자('==' 패딩)", auth(basic_up("svc", base64.b64encode(bytes(range(50))).decode()))),
    ("D-N03", "synthetic", False, "Basic 안쪽 긴 영숫자 비밀번호 48자", auth(basic_up("deploy", rnd(48, ALNUM)))),
    ("D-N04", "synthetic", False, "Basic 안쪽 '='가 든 짧은 비밀번호", auth(basic_up("user", "p@ss=word=="))),
    ("D-G01", "synthetic", None, "Basic 안쪽 짧은 꼬리 A*28+'=' (8그룹 미만)", auth(basic_up("u", A * 28 + "="))),
]

# --- Priority 헤더 바이너리 항목(9114945). Talos 2026-11-19 공식 룰 1:301754 설명("parsed Priority header"의 바이너리 값)을 보고 더함. 정상 대량 뒤에 둔다 ---
CASES += [
    ("PR-P01", "synthetic", True, "Priority 사전 멤버 바이너리 :A*64+'=:'", req("GET", "/", [("Priority", "u=3, x=:" + A * 64 + "=:")])),
    ("PR-P02", "synthetic", True, "Priority 바이너리 항목만 :A*128+'=:'", req("GET", "/", [("Priority", ":" + A * 128 + "=:")])),
    ("PR-P03", "synthetic", True, "Priority 소문자 헤더명, 무작위 64자+'Bc='", req("GET", "/", [("priority", "i, y=:" + rnd(64) + "Bc=:")])),
    ("PR-N01", "synthetic", False, "정상 Priority u=0, i", req("GET", "/", [("Priority", "u=0, i")])),
    ("PR-N02", "synthetic", False, "Priority 정상 바이너리 64자(패딩 없음)", req("GET", "/", [("Priority", "u=3, x=:" + base64.b64encode(bytes(range(48))).decode() + ":")])),
    ("PR-N03", "synthetic", False, "Priority 정상 바이너리 68자('==' 패딩)", req("GET", "/", [("Priority", "u=1, x=:" + base64.b64encode(bytes(range(50))).decode() + ":")])),
]

# --- Talos 공식 룰(2026-11-19, Snort Community 룰에 공개)이 다루는 요청 위치. 값은 공개 트리거 모양만 쓴다. 정상 대량 뒤에 둔다 ---
T = A * 64 + "="
MP = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
def mp_body(name):
    return f"--{MP}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\nvalue\r\n--{MP}--\r\n"
CASES += [
    ("T-apikey", "talos-shape", True, "Talos 67507 위치: Authorization ApiKey 스킴", auth("ApiKey " + T)),
    ("T-other", "talos-shape", True, "Talos 67508 위치: Authorization Other 스킴", auth("Other " + T)),
    ("T-samlart", "talos-shape", True, "Talos 67502 위치: SAML 쿼리 SAMLart", req("GET", "/realms/demo/protocol/saml?SAMLart=" + T, [])),
    ("T-xconnect", "talos-shape", True, "Talos 67503 위치: X-Connect-Authorization 헤더", req("POST", "/connectors/c1/fence", [("X-Connect-Authorization", T)])),
    ("T-csp-path", "talos-shape", True, "Talos 67504 위치: URL 경로 조각 뒤 ':'", req("POST", "/content-security-policy-reporting-endpoint/" + T + ":ctx", [("Content-Type", "application/csp-report")], "{}")),
    ("T-console", "talos-shape", True, "Talos 67505 위치: X-ConsoleAnnotator 헤더", req("POST", "/job/demo/1/logText/progressiveHtml", [("X-ConsoleAnnotator", T)])),
    ("T-pagetoken", "talos-shape", True, "Talos 67506 위치: 쿼리 값 안 '접두어=' 뒤", req("GET", "/rest/api/branches/?next-page-token=v1=" + T, [])),
    ("T-mp-boundary", "talos-shape", True, "Talos 67509 위치: multipart boundary의 RFC 2047 인코딩 단어",
     req("POST", "/upload", [("Content-Type", "multipart/form-data; boundary=\"=?UTF-8?B?" + T + "?=\"")], "x")),
    ("T-mp-name", "talos-shape", True, "Talos 67510 위치: multipart 본문 name의 RFC 2047 인코딩 단어",
     req("POST", "/upload", [("Content-Type", "multipart/form-data; boundary=" + MP)], mp_body("=?UTF-8?B?" + T + "?="))),
    ("T-h2settings", "talos-shape", True, "Talos 67511 위치: HTTP2-Settings 헤더(h2c 업그레이드)",
     req("GET", "/", [("Connection", "Upgrade, HTTP2-Settings"), ("Upgrade", "h2c"), ("HTTP2-Settings", T)])),
    ("T-priority", "talos-shape", True, "Talos 301754 위치: Priority 사전 멤버 바이너리", req("GET", "/", [("Priority", "u=3, x=:" + T + ":")])),
    ("TN-apikey", "talos-shape", False, "정상 ApiKey(정상 패딩 Base64)", auth("ApiKey " + base64.b64encode(bytes(range(44))).decode())),
    ("TN-negotiate", "talos-shape", False, "정상 Negotiate 토큰", auth("Negotiate " + base64.b64encode(bytes(range(120))).decode())),
    ("TN-aws4", "talos-shape", False, "정상 AWS4-HMAC-SHA256 서명", auth("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261119/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=" + rnd(64, "0123456789abcdef"))),
    ("TN-digest", "talos-shape", False, "정상 Digest", auth('Digest username="svc", realm="api", nonce="' + base64.b64encode(bytes(range(33))).decode() + '", uri="/", response="' + rnd(32, "0123456789abcdef") + '"')),
    ("TN-sharedkey", "talos-shape", False, "정상 SharedKey(계정:서명)", auth("SharedKey account1:" + base64.b64encode(bytes(range(32))).decode())),
    ("TN-mp", "talos-shape", False, "정상 multipart와 RFC 2047 이름(정상 Base64)",
     req("POST", "/upload", [("Content-Type", "multipart/form-data; boundary=" + MP)], mp_body("=?UTF-8?B?" + base64.b64encode("보고서-2026-11-최종본-첨부.txt".encode()).decode() + "?="))),
    ("TN-h2settings", "talos-shape", False, "정상 HTTP2-Settings", req("GET", "/", [("Connection", "Upgrade, HTTP2-Settings"), ("Upgrade", "h2c"), ("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")])),
    ("TN-csp-path", "talos-shape", False, "정상 경로 조각(URL-safe 64자)", req("POST", "/content-security-policy-reporting-endpoint/" + b64url(bytes(range(48))) + ":ctx", [], "{}")),
    ("TN-path-pad", "talos-shape", False, "정상 경로 조각(정상 패딩 '==')", req("GET", "/files/" + base64.urlsafe_b64encode(bytes(range(50))).decode() + "/meta", [])),
    ("TN-pagetoken", "talos-shape", False, "정상 next-page-token(정상 Base64 64자)", req("GET", "/rest/api/branches/?next-page-token=" + base64.b64encode(bytes(range(48))).decode(), [])),
]


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(ip):
    return bytes(int(x) for x in ip.split("."))


def _pkt(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, 20 + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp + payload)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), random.getrandbits(16), 0x4000, 64, 6, 0, _ip(src), _ip(dst))
    iph = iph[:10] + struct.pack("!H", _csum(iph)) + iph[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + iph + tcp + payload


def main(out_pcap, out_index):
    cli, srv = "192.0.2.10", "198.51.100.20"
    t = 1763424000.0
    frames, index = [], {}
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    for n, (cid, group, expect, desc, request) in enumerate(CASES):
        sport = 20000 + n
        index[sport] = {"id": cid, "group": group, "expect": expect, "desc": desc}
        cs, ss, q = 1000, 5000, len(request)
        for s in [
            (cli, srv, sport, 80, cs, 0, 0x02, b""),
            (srv, cli, 80, sport, ss, cs + 1, 0x12, b""),
            (cli, srv, sport, 80, cs + 1, ss + 1, 0x10, b""),
            (cli, srv, sport, 80, cs + 1, ss + 1, 0x18, request),
            (srv, cli, 80, sport, ss + 1, cs + 1 + q, 0x10, b""),
            (srv, cli, 80, sport, ss + 1, cs + 1 + q, 0x18, resp),
            (cli, srv, sport, 80, cs + 1 + q, ss + 1 + len(resp), 0x10, b""),
            (cli, srv, sport, 80, cs + 1 + q, ss + 1 + len(resp), 0x11, b""),
            (srv, cli, 80, sport, ss + 1 + len(resp), cs + 2 + q, 0x11, b""),
            (cli, srv, sport, 80, cs + 2 + q, ss + 2 + len(resp), 0x10, b""),
        ]:
            t += 0.001
            frames.append((t, _pkt(*s)))
    with open(out_pcap, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)
    with open(out_index, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)
    print(f"cases={len(CASES)} frames={len(frames)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
