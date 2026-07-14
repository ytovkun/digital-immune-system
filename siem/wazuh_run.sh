#!/usr/bin/env bash
# Оркестратор Wazuh-порівняння (Docker single manager).
# Цифрова імунна система — siem/wazuh_run.sh
#
# Запускає Wazuh manager у Docker, моніторить reports/siem/access.log, реплеїть
# розмічений набір (siem_capture.py), збирає alerts.json і рахує порівняння з ЦІС.
#
# Передумови: Docker працює; Helios на :8001; .venv з requirements.
# Запуск:   bash siem/wazuh_run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PY:-.venv/bin/python}"
IMG="${WAZUH_IMG:-wazuh/wazuh-manager:4.9.2}"
NAME="wazuh-cmp"
SIEM_DIR="reports/siem"
ALOG="$SIEM_DIR/access.log"

mkdir -p "$SIEM_DIR"
echo "==> 1/6 Готую чистий access.log"
: > "$ALOG"                                   # спорожнюємо (Wazuh тейлитиме нові рядки)

echo "==> 2/6 Стартую Wazuh manager ($IMG) у Docker"
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  docker rm -f "$NAME" >/dev/null
fi
docker run -d --name "$NAME" -v "$ROOT/$SIEM_DIR:/siemdata" "$IMG" >/dev/null
echo "    очікую готовності wazuh-manager (~60с)..."
for i in $(seq 1 60); do
  if docker exec "$NAME" test -f /var/ossec/logs/alerts/alerts.json 2>/dev/null \
     || docker exec "$NAME" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q running; then
    break
  fi
  sleep 2
done

echo "==> 3/6 Вмикаю моніторинг access.log + рестарт аналізу"
docker exec "$NAME" bash -c '
  grep -q "/siemdata/access.log" /var/ossec/etc/ossec.conf || \
  sed -i "s#</ossec_config>#  <localfile>\n    <log_format>apache</log_format>\n    <location>/siemdata/access.log</location>\n  </localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf
  /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
'
sleep 15

echo "==> 4/6 Реплей розміченого набору (пише access.log)"
"$PY" siem/siem_capture.py

echo "==> 5/6 Очікую обробки Wazuh (~30с) і збираю alerts.json"
sleep 30
docker exec "$NAME" cat /var/ossec/logs/alerts/alerts.json > "$SIEM_DIR/wazuh_alerts.json" 2>/dev/null || true
LINES=$(wc -l < "$SIEM_DIR/wazuh_alerts.json" 2>/dev/null || echo 0)
echo "    зібрано alerts.json: $LINES рядків"

echo "==> 6/6 Порівняння Wazuh vs ЦІС"
"$PY" siem/siem_compare.py "$SIEM_DIR/wazuh_alerts.json"

echo ""
echo "Готово. Контейнер '$NAME' лишається (докладно: docker logs $NAME)."
echo "Зупинити:  docker rm -f $NAME"
