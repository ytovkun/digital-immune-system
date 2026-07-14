# SIEM-порівняння: Wazuh vs ЦІС

Емпіричне head-to-head сигнатурного/rule-based SIEM (**Wazuh**) та ЦІС на **тому
самому** розміченому наборі, що й `benchmark.py`. Показує, де класичний SIEM
програє (поведінкові APT, prompt-injection, held-out новизна) — тобто перевагу
ШІ-ядра ЦІС (міркування про намір, а не звіряння зі списком правил).

> **Wazuh** — практичне порівняння (host-based SIEM, аналізує лог веб-доступу).
> **Splunk / QRadar / ArcSight** — у теоретичному огляді (типові показники з
> літератури: latency/MTTR/FP, у `metrics_summary.py → COMPARISON`).
> Код винесено в окрему теку — це зовнішній інструмент, не частина ЦІС.
> Результати → `reports/siem/`, дашборд показує їх у вкладці «Метрики vs SIEM».

## Файли
| Файл | Роль |
|---|---|
| `siem_capture.py` | реплей набору → пише `reports/siem/access.log` (для Wazuh) + шле HTTP; маркер `_bid` для кореляції |
| `siem_compare.py` | парсинг Wazuh `alerts.json` (або Suricata `eve.json`) → метрики SIEM + порівняння з ЦІС |
| `wazuh_run.sh` | **оркестратор**: піднімає Wazuh у Docker, моніторить access.log, збирає alerts, рахує порівняння |

---

## Практичне порівняння — Wazuh (Docker)

### Передумови
- **Docker Desktop** запущений (`docker ps` працює);
- **Helios** на :8001 (ціль реплею);
- `.venv` з `requirements.txt`.

### Один крок (рекомендовано)
```bash
bash siem/wazuh_run.sh
```
Скрипт: спорожнює access.log → піднімає `wazuh/wazuh-manager` у Docker → вмикає
моніторинг access.log → реплеїть набір → збирає `alerts.json` → рахує порівняння.
Результат: таблиця + `reports/siem/siem_comparison_*.json/.txt`. Дашборд (`R`)
покаже виміряне порівняння + перелік атак, які Wazuh пропустив.

### Вручну (якщо треба контроль)
```bash
mkdir -p reports/siem && : > reports/siem/access.log
docker run -d --name wazuh-cmp -v "$PWD/reports/siem:/siemdata" wazuh/wazuh-manager:4.9.2
# додати моніторинг access.log:
docker exec wazuh-cmp bash -c 'sed -i "s#</ossec_config>#  <localfile><log_format>apache</log_format><location>/siemdata/access.log</location></localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf; /var/ossec/bin/wazuh-control restart'
sleep 15
python siem/siem_capture.py                       # дописує access.log → Wazuh тейлить
sleep 30
docker exec wazuh-cmp cat /var/ossec/logs/alerts/alerts.json > reports/siem/wazuh_alerts.json
python siem/siem_compare.py reports/siem/wazuh_alerts.json
docker rm -f wazuh-cmp                             # прибрати контейнер
```

### Налаштування
- ціль реплею: env `SIEM_TARGET=http://localhost:PORT` (типово `:8001`);
- версія образу: env `WAZUH_IMG=wazuh/wazuh-manager:X.Y.Z`;
- поріг детекції Wazuh: `WAZUH_MIN_LEVEL` у `siem_compare.py` (типово 6 — реальні
  атаки; нижчі рівні — інформаційний шум веб-доступу).

---

## Що очікувати (і чому це сильно)

Wazuh (rule-based) **ловить** відомі payload — SQLi/XSS/traversal (правила web-attack,
rule id 31100+). Але **пропускає**:
- поведінкові **APT** (немає правила на траєкторію recon→дія);
- **prompt-injection** проти ШІ-судді;
- held-out новизну й граничні кейси.

Таблиця 3.E: `Wazuh: R частковий, APT 0/3` vs `ЦІС: R=1.0, APT 3/3`. Це
**емпірично** доводить перевагу ШІ-ядра — замість «цифр із літератури».

