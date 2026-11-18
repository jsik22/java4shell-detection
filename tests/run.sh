#!/usr/bin/env bash
# 룰 회귀 시험: 합성 pcap 생성 → Suricata·Snort 3 문법 검사와 pcap 실행(컨테이너, --network none) → 채점.
# 볼륨 마운트 대신 docker cp를 써서 colima·원격 Docker에서도 같은 방식으로 돈다.
# 사용: bash tests/run.sh [결과.md]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
SURICATA_IMAGE=${SURICATA_IMAGE:-jasonish/suricata:7.0}
SNORT_IMAGE=${SNORT_IMAGE:-ciscotalos/snort3:latest}
REPORT=${1:-}

mkdir -p "$WORK/t"
cp -R "$ROOT/rules" "$WORK/t/"
python3 -I "$ROOT/tests/fixtures.py" "$WORK/t/fixtures.pcap" "$WORK/index.json"

in_container() {  # in_container IMAGE DEST SCRIPT OUTFILE
  local cid
  cid=$(docker create --network none --entrypoint sh "$1" -c "$3")
  docker cp "$WORK/t/." "$cid:$2" >/dev/null
  docker start -a "$cid" > "$4" 2>&1 || true
  docker rm "$cid" >/dev/null
}

S=/home/snorty/snort3
in_container "$SURICATA_IMAGE" /t "suricata -V; mkdir -p /t/o && suricata -T -S /t/rules/suricata/java4shell.rules -l /t/o 2>&1 | tail -1" "$WORK/suricata-check.txt"
in_container "$SURICATA_IMAGE" /t "mkdir -p /t/o && suricata -r /t/fixtures.pcap -S /t/rules/suricata/java4shell.rules -k none -l /t/o >/dev/null 2>&1; cat /t/o/eve.json" "$WORK/suricata-eve.json"
in_container "$SNORT_IMAGE" /home/snorty/t "$S/bin/snort -c $S/etc/snort/snort.lua -R /home/snorty/t/rules/snort3/java4shell.rules --warn-all -T 2>&1 | grep -E -i '9114|error|validated|Snort\+\+'" "$WORK/snort-check.txt"
in_container "$SNORT_IMAGE" /home/snorty/t "$S/bin/snort -c $S/etc/snort/snort.lua -R /home/snorty/t/rules/snort3/java4shell.rules -r /home/snorty/t/fixtures.pcap -k none -A alert_json -q" "$WORK/snort-alerts.json"

echo "== 문법 검사"; cat "$WORK/suricata-check.txt" "$WORK/snort-check.txt"
grep -q "successfully loaded" "$WORK/suricata-check.txt" || { echo "Suricata 문법 검사 실패"; exit 1; }
grep -q "successfully validated" "$WORK/snort-check.txt" || { echo "Snort 문법 검사 실패"; exit 1; }
if grep -E -i "warn.*9114" "$WORK/snort-check.txt"; then echo "Snort가 로컬 룰에 경고를 냈다"; exit 1; fi

if [ -n "$REPORT" ]; then
  { echo "# 회귀 시험 결과"; echo; echo "- 실행: $(date -u +%Y-%m-%dT%H:%MZ)"; echo "- 엔진: $(head -1 "$WORK/suricata-check.txt" | sed 's/This is //; s/ RELEASE//'), $(grep -o 'Snort++ [0-9.]*' "$WORK/snort-check.txt" | head -1)"; echo; } > "$REPORT"
fi
rc=0
echo "== 채점"
for engine in suricata snort; do
  alerts="$WORK/suricata-eve.json"; [ "$engine" = snort ] && alerts="$WORK/snort-alerts.json"
  r=0; python3 -I "$ROOT/tests/score.py" "$WORK/index.json" "$engine" "$alerts" "$ROOT/tests/known_gaps.json" ${REPORT:+"$REPORT"} || r=$?
  # 1(실패)이 2(공백 갱신 필요)보다 우선
  if [ "$r" = 1 ] || { [ "$r" = 2 ] && [ "$rc" = 0 ]; }; then rc=$r; fi
done
exit $rc
