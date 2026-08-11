# Цифрова імунна система розумної е-держави на основі GenAI

Дисертаційний програмний комплекс: **генерація кіберзагроз через GenAI** +
**inline-захист у реальному часі на основі ШІ** для сервісу електронного
голосування Helios.

> Тема: *«Цифрова імунна система розумної електронної держави на основі
> GenAI-моделювання кіберзагроз»* (Розділ 3).

---

## Архітектура

```
┌─────────────────── ГЕНЕРАЦІЯ АТАК (offensive GenAI) ───────────────────┐
│  attack_generator → red_team_agent → adaptive_generator → attack_chain  │
│   (STRIDE/MITRE/    (HTTP-виконання)  (мутація під блок:    (APT-ланцюги) │
│    LINDDUN)                            escalate/refine/bypass)            │
└─────────────────────────────────────────────────────────────────────────┘
                                   ↓
┌─────────────────── ЗАХИСТ (defensive GenAI, inline) ───────────────────┐
│   Атакувальник → :8000 ImmuneProxy → :8001 Helios                       │
│                       ↓                                                  │
│   L1 FastReflex (~0.05ms): rate, concurrency, сигнатури, payload-блок,   │
│        вивчені сигнатури, детермінований hard-payload/admin/verb-блок     │
│   L2 AIAnalyst (Claude): adaptive thinking + structured outputs —        │
│        міркує про НАМІР і ПОВЕДІНКОВУ ТРАЄКТОРІЮ; повертає threat_score    │
│   Навчання L1 ← L2: ШІ синтезує сигнатуру → L1 ловить повторні за 0мс     │
│   Payload-бэкстоп: детермінований override — ШІ не обдурити (тіло 64КБ)   │
│   Fingerprint-антиген, анти-ексфільтрація, session circuit-breaker        │
│   Імунна памʼять (LRU + SQLite): антитіла переживають перезапуск          │
└─────────────────────────────────────────────────────────────────────────┘
                                   ↓
        logs/immune_blocks.jsonl  (кожне inline-блокування)
                                   ↓
   immune_response_engine (offline SOC) + risk_scorer + defense_report +
   benchmark (P/R/F1/ROC) + coevolution_report (щит vs меч) + metrics_summary
```

**Цикл цифрового імунітету:** Detect → Classify → Respond → Learn.

### Два взаємодоповнювальні режими імунітету

| Режим | Модуль | Аналогія | Роль |
|---|---|---|---|
| **INLINE** (реальний час) | `immune_system/immune_proxy.py` | імунітет «на кордоні» | **превенція**: блокує атаку до Helios, пише `logs/immune_blocks.jsonl` |
| **OFFLINE** (постфактум) | `core/immune_response_engine.py` | лімфовузол / SOC | **агрегація**: інгестує inline-блоки + репорти червоної команди, класифікує (STRIDE/MITRE/LINDDUN), радить патч, веде памʼять |

Звʼязок: inline-проксі **відвертає** атаку та емітує інцидент →
`ThreatDetector.detect_from_immune_blocks()` його **інгестує** в offline-двигун.

---

## Структура `reports/`

Звіти розкладені по підпапках (без візуального шуму), читаються рекурсивно:

| Підпапка | Вміст |
|---|---|
| `attacks/baseline/` | атаки проти СИРОГО Helios (без захисту) |
| `attacks/defended/` | ті самі атаки ЧЕРЕЗ ЦІС (із захистом) |
| `benchmark/` | labeled-бенчмарк (P/R/F1, ROC, гранична вибірка, APT) |
| `defense/` | ефективність захисту (`--scope baseline` / `defended`) |
| `coevolution/` | динаміка поколінь «щит vs меч» |
| `risk/` | кількісна оцінка ризиків (CIA + LINDDUN + MITRE) |
| `ire/` | offline-класифікація інцидентів |
| `security/` | результати тестів стійкості ЦІС (FPR, узагальнення, інʼєкції, DoS) |
| `metrics/` | зведені метрики (vs SIEM) |
| `run_manifest.{json,txt}` | **єдиний запис прогону**: git-commit + модель + зведення всіх метрик |

> Адаптивні репорти позначені в назві `ATK-..._adaptive_report.json` і несуть у
> JSON `adaptation_mode` (escalate/refine/bypass). `defense_report` міряє БАЗОВИЙ
> набір (adaptive виключено), а `coevolution_report` — обидва покоління окремо.

---

## Структура проєкту

| Тека / файл | Призначення |
|---|---|
| `core/attack_generator.py` | LLM-генератор атак (STRIDE + MITRE + LINDDUN) |
| `core/red_team_agent.py` | Виконавець атак (HTTP; ціль — env `HELIOS_BASE_URL`) |
| `core/adaptive_generator.py` | Мутація сценаріїв під блокування (escalate/refine/bypass) |
| `core/attack_chain.py` | APT-ланцюжки з передачею контексту між фазами |
| `core/attack_flow.py` | Kill chain / `attack_flow.json` (візуалізація blocked/leaked/allowed) |
| `core/risk_scorer.py` | Кількісна оцінка ризиків (CIA + LINDDUN + MITRE) |
| `core/immune_response_engine.py` | **Offline SOC-двигун** (інгестує inline-блоки, SQLite-памʼять) |
| `immune_system/immune_proxy.py` | **Inline reverse-proxy ЦІС** (порт 8000) |
| `immune_system/fast_reflex.py` | Уровень 1 — швидкі рефлекси |
| `immune_system/ai_analyst.py` | Уровень 2 — ШІ-аналітик (Claude) |
| `immune_system/threat_patterns.py` | Спільний каталог сигнатур (єдине джерело L1+L2) |
| `immune_system/benchmark.py` | Labeled-бенчмарк (P/R/F1 + ДІ Вілсона, ROC, **гранична вибірка**, APT) |
| `immune_system/defense_report.py` | Ефективність захисту (baseline vs defended) |
| `immune_system/coevolution_report.py` | **Метрика ко-еволюції** (щит vs меч поколіннями) |
| `immune_system/metrics_summary.py` | Зведені метрики (vs SIEM); читає `reports/security/` |
| `immune_system/*_test.py` | Security-тести для живого сервера (пишуть `reports/security/*.json`) |
| `immune_system/redetection_test.py` | Re-detection через імунну пам'ять (adaptive→innate, розділ 5.1) |
| `immune_system/_sec_result.py` | Хелпер збереження результату security-тесту в JSON |
| `siem/` | **Порівняння з реальним SIEM** (Wazuh/Suricata) — див. `siem/README.md` |
| `run_all.py` | Оркестратор пайплайну (пресети нижче) |
| `dashboard.py` | **Streamlit-дашборд** (9 вкладок) |
| `utils/run_manifest.py` | Run-маніфест для відтворюваності |
| `utils/cleaner.py` | Очистка артефактів |
| `tests/` | Автоматичні unit-тести (pytest, **147 шт.**) |
| `config.json` | Єдина конфігурація (секрети — у `config.local.json`, поза git) |
| `LICENSE` / `NOTICE` | Apache 2.0 + атрибуція Helios |

---

## Встановлення

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`.env` із ключем Anthropic (для GenAI-частини):
```
ANTHROPIC_API_KEY=sk-ant-...
```

`config.local.json` із даними тестової виборки (паролі, `election_uuid`,
`voter_uuids`) — НЕ комітяться:
```bash
cp config.local.json.example config.local.json   # потім впиши реальні значення
```
> `.env` і `config.local.json` — у `.gitignore`; локальні значення перекривають
> `config.json` (deep-merge у `env_loader.load_config`).

---

## Схема портів

| Порт | Що крутиться | Хто туди б'є |
|---|---|---|
| **8001** | **Helios** (реальний сервер голосування) | атаки в СИРИЙ Helios (baseline) |
| **8000** | **ImmuneProxy** (ЦІС) — стоїть ПЕРЕД Helios | атаки крізь захист (defended) |

Прокси :8000 фільтрує запит і форвардить на Helios :8001. Маркер запущеного коду —
у `GET /__immune__/stats` (поле `build`); Prometheus-метрики — `GET /__immune__/metrics`.

---

## Запуск

Для дисертації потрібен контраст: атаки проти СИРОГО Helios проходять («до»),
а через ЦІС — блокуються («після»). Різниця — доказ роботи імунної системи.

### Головний сценарій — пресети `run_all.py`

```bash
# ПОВНИЙ звіт «без захисту vs із захистом» ОДНІЄЮ командою (наповнює весь дашборд).
# Helios :8001 підніми заздалегідь; проксі :8000 підіймається САМ:
python run_all.py campaign
#
# ⚠️ --skip-generate ПРОПУСКАЄ генерацію сценаріїв (Claude) і ПЕРЕВИКОРИСТОВУЄ вже
#    наявні у scenarios/. Додавай ЛИШЕ якщо ти вже генерував їх раніше — на чистій
#    системі scenarios/ порожня (у .gitignore), тож виконувати буде нічого → порожній
#    дашборд. Для першого/повного прогону запускай БЕЗ цього прапора.

# Ко-еволюційний цикл: мутувати атаки під блокування ЦІС → виконати → метрика поколінь
# (передумова: вже є defended-звіти з campaign):
python run_all.py coevolve

# Лише тести стійкості самої ЦІС (FPR, узагальнення, інʼєкції, DoS):
python run_all.py security

# Аналіз НАЯВНИХ даних без серверів/ключа:
python run_all.py analyze

# Unit-тести:
python run_all.py test

# Точкові кроки (пресет ігнорується):
python run_all.py --score --ire --metrics
```

**Пресети:**

| Пресет | Кроки | Потрібен проксі? |
|---|---|---|
| `campaign` | generate → атаки baseline+defended → risk → ire → benchmark → 4×security → звіти → ко-еволюція → metrics → **manifest** | так (авто) |
| `coevolve` | adapt (мутація) → execute_defended → defense → coevolution | так (авто) |
| `security` | 4 security-тести → metrics | так (авто) |
| `offense` | generate → execute(:8001) → score → ire | ні |
| `defense` | benchmark → demo → defense_report → metrics | так |
| `analyze` | score → ire → metrics (лише reports/) | ні |
| `test` | pytest | ні |

**Флаги:** `--with-defense` (підняти проксі у фоні) · `--skip-generate`
(пропустити генерацію Claude, ПЕРЕВИКОРИСТАТИ наявні scenarios/ — потребує вже
згенерованих сценаріїв) · `--skip-execute` · `--clean` · `--keep-going`.

### Фінальний атомарний прогін (для розділу 3)

```bash
lsof -ti:8000 | xargs kill 2>/dev/null                    # звільнити порт
python utils/cleaner.py --yes                             # повністю чистий reports/ + scenarios/
python run_all.py campaign                                # генерація + весь дашборд (gen-0)
python run_all.py coevolve                                # gen-1 (мутовані атаки)
python run_all.py --score --ire --metrics                # перерахунок із gen-1
python utils/run_manifest.py                              # єдиний маніфест прогону
```

> `run_manifest.txt` фіксує git-commit, модель і зведення всіх метрик — кожне
> число розділу 3 привʼязане до конкретного коміту й прогону.

### Ручний прогін (розкрито)

```bash
# Термінал 1 — Helios на :8001
cd ~/helios-server && .venv/bin/python manage.py runserver 8001
# Термінал 2 — ЦІС на :8000 (з ключем ШІ)
python immune_system/immune_proxy.py
# Термінал 3 — метрики
python immune_system/benchmark.py                # P/R/F1 + ROC + гранична вибірка + APT
python immune_system/defense_report.py --scope defended
python immune_system/coevolution_report.py --scope defended
```

### Дашборд (Streamlit) — 9 вкладок

```bash
python -m streamlit run dashboard.py
```
Вкладки: **Ризики** · **Бенчмарк+ROC** (осн. + комбінований граничний ROC) ·
**IRE-класифікація** · **Ефективність захисту** (baseline→defended) ·
**Ко-еволюція** (щит vs меч) · **Kill Chain** (граф blocked/leaked/allowed) ·
**Attack Surface** · **Метрики vs SIEM** (Wazuh vs ЦІС + re-detection) ·
**Live** (метрики проксі :8000).

---

## Ключові концепти дисертації

- **Гібридний детермінізм + ШІ.** Однозначне (payload, admin/verb, hard-token) ловить
  детермінований L1 за ~0.05мс; неоднозначне (намір голосу, новизна, темп) ескалює на
  ШІ, який міркує про НАМІР і ПОВЕДІНКОВУ ТРАЄКТОРІЮ.
- **Ко-еволюція «щит vs меч».** GenAI мутує заблоковані атаки (escalate/refine/**bypass**),
  зберігаючи злонамірену ціль (крит-операцію), але змінюючи техніку обходу. Метрика
  **held** = частка атак, де ЖОДНА небезпечна операція не дійшла до Helios. Стійке
  утримання крізь покоління = захист **генералізує намір**, а не запамʼятовує сигнатури.
- **Гранична («сіра») стрес-вибірка.** Неоднозначні кейси (легіт з підозрілими ознаками
  + тонкі атаки без явного payload) дають ГРАДУЙОВАНИЙ threat_score → реалістичний
  комбінований ROC. Мета — строгіший ЧЕСНИЙ тест дискримінації, не заниження AUC.
- **adaptive→innate immunity.** ШІ синтезує сигнатуру нового патерну → L1 блокує
  повторні миттєво (0мс). Re-detection міряє прискорення (×1000+): 1-ша зустріч —
  ШІ (~секунди), повторна — рефлекс L1 (~мс).
- **Kill chain.** Кожна атака візуалізується як ланцюг Cyber Kill Chain з вердиктом
  захисту на кожному кроці (🟩 заблоковано / 🟦 безпечний крок / 🟥 крит-витік / ⬜
  симуляція). У defended-прогоні 🟥 = 0 — жодна небезпечна операція не дійшла до Helios.
- **Порівняння з SIEM.** Практичне — з реальним **Wazuh** (host-based SIEM) на тому
  самому наборі (`siem/README.md`); Wazuh/Splunk як клас — у теоретичному огляді.

---

## Тести

```bash
pytest            # 147 unit-тестів (без серверів/ключа); testpaths=tests
```
Покривають: L1 FastReflex, L2 AIAnalyst, hardening проксі (payload-бэкстоп, fingerprint,
анти-ексфільтрація, circuit-breaker, XFF), спільний каталог сигнатур, персистентну
памʼять, розділення звітів (scope), логіку `core/`, offline-двигун, метрику held,
граничну вибірку, `decide_adaptation_mode`.

**Security-тести** (потрібен живий проксі + ключ) пишуть `reports/security/*.json`,
які читає `metrics_summary` (без хардкоду цифр):
```bash
python run_all.py security        # усі 4 разом (проксі підіймається сам)
```

---

## Ключові результати

| Метрика | Значення |
|---|---|
| Небезпечних операцій заблоковано (defended) | **16/16 (100%)**, витоків 0 |
| Precision / Recall / F1 (labeled-бенчмарк) | **1.00 / 1.00 / 1.00** |
| ROC-AUC (основний / комбінований граничний) | **1.00 / 0.977** |
| False-positive rate (реальний виборець) | **0%** |
| Багатокрокові APT (поведінкова траєкторія) | **3/3** |
| Ко-еволюція: gen-0 → gen-1 (утримано) | **100% → 100%** (крит-блок 22/22) |
| Узагальнення / prompt injection / DoS на ШІ | 5/5 / 5/5 / 20/20 |
| Час реагування L1 / кеш / ШІ | ~0.05ms / 0ms / ~3с |

> Точні числа кожного прогону — у `reports/run_manifest.txt`.

---

## Обмеження (чесно)

- **Відтворюваність ШІ.** Детермінований L1 і payload-бэкстоп дають ідентичний
  результат за будь-якого прогону. Рішення L2 (Claude) для граничних/багатокрокових
  випадків (APT, гранична вибірка) можуть варіюватися в межах ±ε між прогонами — це
  властивість LLM-систем. Кожен фінальний прогін фіксується у `run_manifest.json`,
  сирі рішення — у `logs/immune_blocks.jsonl`.
- **Зовнішня валідність.** Експерименти — на одному тестовому екземплярі Helios із
  синтетичними даними; вибірки скінченні (101 запит бенчмарку, 12 граничних, 3 APT,
  22 класи атак у 2 поколіннях). Наведено 95% довірчі інтервали Вілсона. Інші платформи
  / реальний трафік потребують окремої валідації.
- **Production WSGI** (waitress); для бойового — TLS-термінація + кластер.
- **Клієнтські атаки** помʼякшено security-заголовками (CSP/X-Frame-Options/nosniff);
  device-JS/MITB частково. **Timing-деанон** помʼякшено (rate-limit + огрублення `cast_at`);
  ISP-рівнева кореляція — поза серверним периметром. **Людське примушення** — поза
  областю серверного захисту.
- **Залежність від LLM**: при відмові ШІ діє fail-closed на критичних endpoint;
  L1-сигнатури ловлять відомі патерни й без ШІ.

---

## Безпека за дизайном

- **GenAI-ядро L2**: adaptive thinking + structured outputs; авто-fallback на базовий режим
- **Поведінкова траєкторія**: ШІ аналізує послідовність і темп запитів актора (recon→дія)
- **Нелюдський темп → ескалація на ШІ** (не хард-блок): у e-voting хибний блок = позбавлення
  голосу, тож рішення виносить ШІ за траєкторією (recon-sweep → BLOCK; voter-flow → ALLOW)
- **Payload-бэкстоп**: детермінований override — ШІ не обдурити prompt-injection у бік
  пропуску явного payload (скан тіла до 64КБ)
- **Fingerprint-антиген**: кореляція за відбитком клієнта проти ротації IP (сигнал ШІ)
- **Анти-ексфільтрація**: детекція аномального дампу `/voters/`, `/ballots/`
- **Навчання L1 ← L2** (adaptive→innate): миттєвий блок повторних (0мс)
- **Fail-closed** на критичних операціях; **rate-cap** проти cache-busting флуду ШІ
- **Session circuit-breaker**: не амплифікує навантаження на Helios під флудом сесій
- **XFF-межа довіри**: проксі перезаписує X-Forwarded-For на реальний client IP до Helios
- **verbose-blocks** (config): у проді 403 без деталей детекції (не підказувати атакувальнику)
- **Приватність журналу**: voter_uuid/ballot_hash маскуються; ротація журналів за розміром
- **SOC-спостережуваність**: `/__immune__/metrics` (Prometheus) + порогові алерти
- **ROC/AUC**: неперервний threat_score (`X-Immune-Score`) → ROC-крива та AUC
- **Відтворюваність**: 147 unit-тестів (`pytest`), без серверів/мережі/ключа

---

## Ліцензія та атрибуція

Проєкт ліцензовано під **Apache License 2.0** (`LICENSE`).

Робота **не містить і не розповсюджує** код Helios — вона працює як окремий
застосунок проти локально розгорнутого тестового екземпляра Helios. Атрибуція — у `NOTICE`:
- **Helios Voting** (Ben Adida та контрибутори) — Apache 2.0 — github.com/benadida/helios-server
- **Anthropic Claude SDK** — MIT

Усі звернення до endpoint-ів і задокументованих вразливостей Helios — виключно
для академічного дослідження безпеки в межах дисертації.
