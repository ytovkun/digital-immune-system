# Методологія оцінки ризиків та покриття загроз

> Обґрунтування методики скорингу ризиків (чому **OWASP Risk Rating**, а не CVSS)
> та явне покриття **STRIDE** і **OWASP Top 10 (2021)** набором атак. Матеріал для
> теоретичної частини (розділи моделювання загроз та оцінки ризиків).

---

## 1. Методологія оцінки ризиків (OWASP Risk Rating)

### 1.1. Формула
Скоринг реалізовано в `core/risk_scorer.py`:

```
Risk = (CIA×0.35 + LINDDUN×0.25 + MITRE×0.15 + Execution×0.25) × Severity × 10
```

де кожен фактор ∈ [0,1], підсумковий **composite_score ∈ [0,10]**, а рівень
(`risk_level`) — Critical/High/Medium/Low за порогами.

### 1.2. Які фактори враховуються і чому

| Фактор | Вага | Що моделює | Джерело значення |
|---|---|---|---|
| **CIA** | 0.35 | Технічний вплив на тріаду безпеки (Confidentiality/Integrity/Availability) | `affected_cia` + `CIA_WEIGHTS`, оцінка Low/Med/High/Critical |
| **LINDDUN** | 0.25 | **Приватнісний** вплив (деанонімізація виборця, зв'язуваність, розкриття) | `linddun_category` + `LINDDUN_WEIGHTS` |
| **MITRE** | 0.15 | Здійсненність/зрілість техніки за ATT&CK | прив'язка `mitre_technique_id` |
| **Execution** | 0.25 | **Спостережувана** успішність атаки в реальних прогонах | `weighted_success_rate` / `http_success_rate` |
| **Severity** | множник | Категорійна серйозність (Low..Critical) | `SEVERITY_MAP` |

### 1.3. Чому OWASP Risk Rating, а не CVSS

Наша формула — це, по суті, канонічний **OWASP Risk Rating Methodology**:
**`Risk = Likelihood × Impact`**, де:
- **Impact** = технічний (**CIA**) + приватнісний (**LINDDUN**) вплив;
- **Likelihood** = **Execution** (чи спрацювала атака у прогонах) × **MITRE**
  (зрілість техніки);
- **Severity** — категорійне зважування, узгоджене з бізнес-контекстом e-voting.

**Чому саме OWASP Risk Rating (а не CVSS):**

| Критерій | OWASP Risk Rating ✅ | CVSS ✗ (для нашого завдання) |
|---|---|---|
| Що оцінює | **Ризик реалізованого сценарію атаки** в контексті системи | **Серйозність окремої вразливості** (статичний бал) |
| Врахування успішності | Так — `Likelihood` включає **спостережувану** успішність у прогонах | Ні — бал не залежить від того, чи атака вдалась у нас |
| Приватність (виборця) | Так — прямо через **LINDDUN** як Impact-складову | Слабко — CVSS зосереджений на CIA, приватність поза базовими метриками |
| Контекст/бізнес-вага | Так — гнучкі ваги під критичність e-voting | Environmental-метрики є, але громіздкі й vuln-центричні |
| Придатність | Скоринг **атак-сценаріїв** (наш об'єкт) | Скоринг **вразливостей** (наш `VULN-xx` рівень) |

**Висновок:** CVSS доречний для оцінки **окремих вразливостей** Helios (ми
посилаємось на них як `VULN-11: SECRET_KEY='replaceme'` тощо — це CVSS-рівень),
а для оцінки **ризику атак-сценаріїв** (пріоритезація загроз із урахуванням
успішності й приватності) методологічно правильний саме **OWASP Risk Rating**.
CVSS-подібну **severity** ми при цьому використовуємо як один із входів (множник).

> Альтернатива **DREAD** (Damage/Reproducibility/Exploitability/Affected/
> Discoverability) також розглядалась, але відкинута: суб'єктивні шкали DREAD
> гірше відтворювані, тоді як OWASP Risk Rating дозволяє прив'язати Likelihood до
> **виміряної** успішності атак — що й даємо через `Execution`.

---

## 2. Покриття STRIDE

Набір із 11 класів атак покриває **всі 6 категорій STRIDE** у двох площинах
(системна + на виборця):

| STRIDE | Клас(и) атаки |
|---|---|
| **S**poofing | session_forgery, voter_phishing_credential, voter_social_engineering |
| **T**ampering | ballot_stuffing, csrf_trustee_takeover, tally_manipulation, voter_device_js |
| **R**epudiation | voter_coercion_receipt, voter_device_js_injection |
| **I**nformation Disclosure | voter_timing_deanonymization |
| **D**enial of Service | dos_zk_flood, voter_suppression_targeted |
| **E**levation of Privilege | csrf_trustee_takeover |

**Висновок:** STRIDE покрито повністю (6/6).

---

## 3. Покриття OWASP Top 10 (2021)

Мапимо класи атак (+ payload-рівень із benchmark: SQLi/XSS/SSTI/traversal) на
категорії OWASP Top 10 2021:

| OWASP Top 10 (2021) | Покрито? | Чим саме |
|---|---|---|
| **A01 Broken Access Control** | ✅ | csrf_trustee_takeover, tally_manipulation, admin-lifecycle (delete/archive/keygen), path traversal |
| **A02 Cryptographic Failures** | ✅ | session_forgery (SECRET_KEY='replaceme'), voter_timing_deanonymization (сайд-канал) |
| **A03 Injection** | ✅ | SQLi, XSS, SSTI, prompt-injection (payload-набір benchmark) |
| **A04 Insecure Design** | ✅ | ballot_stuffing (TOCTOU race), voter_suppression, voter_coercion_receipt (протокол) |
| **A05 Security Misconfiguration** | 🟡 частково | devlogin без пароля, дефолтні секрети/налаштування Helios |
| **A06 Vulnerable & Outdated Components** | ✗ поза scope | інфраструктурний рівень (версії залежностей), не логіка застосунку — свідомо поза межами дослідження |
| **A07 Identification & Auth Failures** | ✅ | session_forgery, voter_phishing_credential, неавтент. вкидання голосів |
| **A08 Software & Data Integrity Failures** | ✅ | tally_manipulation, voter_device_js_injection, цілісність бюлетеня |
| **A09 Security Logging & Monitoring Failures** | 🟡 захисно | ЦІС **додає** логування/алерти/Prometheus (закриває цю категорію з боку захисту) |
| **A10 SSRF** | 🟡 захисно | ЦІС **захищає** від SSRF (`_safe_backend_url`: заборона `..`/абс.URL/host-check) |

**Підсумок покриття:**
- **Прямими атаками**: A01, A02, A03, A04, A07, A08 (**6/10**);
- **Частково/захисно**: A05, A09, A10 (**3/10**);
- **Свідомо поза scope**: A06 (**1/10**) — інфраструктурний, з обґрунтуванням.

**Формулювання для тексту:** «Набір атак покриває 6 із 10 категорій OWASP Top 10
2021 прямими сценаріями та ще 3 — частково або з боку захисту (ЦІС сама закриває
A09/A10); поза межами лишено лише A06 (застарілі компоненти) як інфраструктурний
рівень, що не стосується логіки застосунку голосування. Разом зі STRIDE (6/6) це
доводить репрезентативність набору загроз.»
