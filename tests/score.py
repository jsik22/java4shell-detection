"""엔진 경보를 케이스 기대값과 비교한다. 회귀 기준: expect=True 케이스를 모두 잡고(known_gaps 제외), expect=False 케이스에서 오탐 0.

사용: python3 tests/score.py INDEX.json {suricata|snort} ALERTS KNOWN_GAPS.json [결과.md]
  ALERTS: suricata는 eve.json, snort는 -A alert_json 표준 출력.
종료 코드: 0 통과, 1 실패(놓침 또는 오탐), 2 known_gaps에 있던 케이스를 이제 잡음(known_gaps 갱신 필요).
"""
import json
import sys
from collections import defaultdict

LOCAL_SIDS = {9114938, 9114939, 9114940, 9114941, 9114942, 9114943, 9114944, 9114945, 9114946, 9114947, 9114948, 9114949, 9114950}


def load_hits(engine, path):
    hit = defaultdict(set)
    for line in open(path, errors="replace"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        e = json.loads(line)
        if engine == "suricata":
            if e.get("event_type") == "alert" and e["alert"]["signature_id"] in LOCAL_SIDS and e.get("src_ip") == "192.0.2.10":
                hit[e["src_port"]].add(e["alert"]["signature_id"])
        elif "rule" in e and e.get("dir") == "C2S":
            sid = int(e["rule"].split(":")[1])
            if sid in LOCAL_SIDS:
                hit[int(e["src_ap"].rsplit(":", 1)[1])].add(sid)
    return hit


def main():
    index = {int(k): v for k, v in json.load(open(sys.argv[1], encoding="utf-8")).items()}
    engine, alerts = sys.argv[2], sys.argv[3]
    gaps = set(json.load(open(sys.argv[4], encoding="utf-8")).get(engine, []))
    hit = load_hits(engine, alerts)
    tp = fn = fp = tn = 0
    missed, falsepos, newly = [], [], []
    rows = []
    for port, c in sorted(index.items()):
        got = bool(hit.get(port))
        sids = ",".join(map(str, sorted(hit.get(port, []))))
        if c["expect"] is True:
            if got:
                tp += 1
                if c["id"] in gaps:
                    newly.append(c["id"])
            else:
                fn += 1
                if c["id"] not in gaps:
                    missed.append(c["id"])
        elif c["expect"] is False:
            fp += got
            tn += not got
            if got:
                falsepos.append(c["id"])
        if c["group"] != "benign-bulk" or got:
            state = ("탐지 " + sids) if got else ("놓침(알려진 공백)" if c["id"] in gaps else ("놓침" if c["expect"] is True else "-"))
            rows.append(f"| {c['id']} | {c['group']} | {c['expect']} | {state} | {c['desc']} |")
    head = f"**{engine}**: 공격형 {tp}/{tp + fn} 탐지(알려진 공백 {len(gaps)}) · 정상 {tn}/{tn + fp} 조용(오탐 {fp})"
    print(head)
    if len(sys.argv) > 5:
        with open(sys.argv[5], "a", encoding="utf-8") as f:
            f.write(head + "\n\n| 케이스 | 묶음 | 기대 | 결과 | 설명 |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n")
    if missed or falsepos:
        print("실패: 놓침", missed, "오탐", falsepos)
        return 1
    if newly:
        print("알려진 공백이 이제 탐지됨(tests/known_gaps.json 갱신):", newly)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
