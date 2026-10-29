# PLAN — صفحه Runbook (Governed Action Ledger)

- **تاریخ**: 2026-10-27 15:01
- **وضعیت**: 🟢 تصمیم‌های D1–D4 تأیید و اعمال شد — منتظر تأیید نهایی برای شروع کدنویسی
- **دامنه v1**: Governance (فاز ۰) + Runbook Execution (فاز ۱) + Runbook Page (فاز ۲)
- **خارج از دامنه v1**: Automation Rules، Runbook Editor بصری، اجرای واقعی SOAR روی vendor

---

## 1. Goal

ساخت یک صفحه‌ی **Runbook** که برای هر موجودیت (Alert / Case / Incident) نشان دهد:
**چه کاری انجام شد، توسط چه کسی یا چه سرویسی، با چه شرطی مجاز بود، و با چه نتیجه‌ای.**

سه خروجی مشخص:

1. **Governance layer** — کاتالوگ Actions، قراردادها (audit / data-safety / failure / cost)، و policy مؤثر per-tenant؛ به‌گونه‌ای که هر Action قبل از اجرا مجوز بگیرد.
2. **Execution ledger** — جدول append-only `runbook_events` که تمام گام‌های واقعی روی یک موجودیت را ثبت می‌کند (شامل گام‌های داده‌ای مثل «Splunk در حالت simple اجرا شد»).
3. **صفحه/پنل «What we did»** — همان چیزی که الان در Case Overview هست، اما برای هر Alert و **از روی داده‌ی واقعی ledger**، نه استنتاج از فیلدها.

به‌علاوه در همین فاز: **Splunk Simple Query Mode** + ساخت `llm_payload` سمت کد، برای instances با حجم notable بالا (خطای memory در pipeline سنگین).

---

## 2. Files / Services Discovered

### آنچه الان وجود دارد (و باید روی آن سوار شویم)

| مسیر | نقش فعلی | ارتباط با Runbook |
|---|---|---|
| `services/api/app/services/case_investigation_brief.py` | سازنده‌ی «What we did» برای Case (`GET /cases/{id}/brief`) | **الگوی UI/شکل داده**؛ اما محتوا استنتاج heuristic است، نه ledger |
| `apps/web/src/components/cases/CaseInvestigationBriefPanel.tsx` | رندر پنل Investigation brief (سه ستون + outcome) | همان مارک‌آپی که شما فرستادید از `BriefColumn` می‌آید |
| `services/api/app/services/alert_rail.py` → `build_mini_timeline` | timeline کوچک Alert از `CaseTimeline` + `AuditLog` (حداکثر ۶ رکورد) | داده‌ی خامِ «گذشته» را دارد، اما ungoverned و فقط ۶ رکورد |
| `services/api/app/models/audit.py` (`audit_log`) | audit قانونی، hash-chain (`prev_hash`/`entry_hash`) | باید بماند؛ Runbook باید به آن **ارجاع** بدهد نه اینکه جایگزینش شود |
| `services/api/app/models/case.py` (`CaseTimeline`) | timeline سطح Case (`event_type`, `metadata`, `is_automated`) | دقیقاً همان الگوی event-store، اما Case-only |
| `services/api/app/api/v1/endpoints/alerts.py:1031` (`get_alert`) + `_build_alert_detail:960` | جزئیات Alert + rail envelope | نقطه‌ی افزودن endpoint/فیلد Runbook |
| `apps/web/src/components/alerts/AlertDetailView.tsx:1085,1249` | تب‌های overview / timeline / raw / llm | تب timeline **فعلاً جعلی است** (پایین توضیح داده شده) |
| `services/api/app/models/alert.py` | `llm_payload JSONB` (migration 061)، `raw_event`, `narrative`, `funnel_stage` | `llm_payload` از قبل ستون درجه‌یک است |
| `services/fusion/app/services/promoter.py:113` (`_llm_payload`) | `llm_payload` را از envelope بیرون می‌کشد؛ هم **dict** و هم **JSON string** را می‌پذیرد (`_as_mapping`) | یعنی ساخت payload سمت Python بدون تغییر ingest/fusion کار می‌کند |
| `services/connectors/app/connectors/splunk.py:61` (`_MISSION_CONTROL_PIPELINE`) | pipeline سنگین (فقط همان که شما فرستادید) | منشأ خطای memory روی instances پرنوتیفیکیشن |
| `splunk.py:711` (`_fetch_rows`) | اولویت: `custom_search` → saved search → Mission Control | نقطه‌ی تزریق «simple mode» |
| `splunk.py:977` (`normalize`) | هرگز `llm_payload` تولید نمی‌کند (به ستون SPL تکیه دارد) | نقطه‌ی ساخت payload سمت کد |
| `services/api/app/api/v1/endpoints/approvals.py` + `models/responder.py::AgentApproval` | approval موجود با `alert_id`, `case_id`, `action`, `risk_level`, `status` | **دوباره‌سازی نکنیم**؛ Runbook به همین ارجاع می‌دهد |
| `services/agents/app/policy/guardrails.py` | مدل سه‌لایه autonomy (defaults → site YAML → tenant DB) با `auto/review/escalate/reject` | **همان مدل، نه مدل جدید** |
| `services/api/migrations/` | شماره‌گذاری تا `061` | migration جدید = `062` |
| `docs/operations/*.md` (`live-demo-runbook.md`, …) | «runbook» در اینجا یعنی **سند رویه** | تفکیک نام: doc = procedure، صفحه = execution record |

### سه یافته‌ی مهم که طراحی را تعیین می‌کند

**(الف) «What we did» فعلی Case واقعاً ledger نیست.**
`build_brief_from_rows()` در `case_investigation_brief.py` آیتم‌ها را از فیلدهای Case می‌سازد:
`"Case opened"` از `len(alerts)`، `"Auto / analyst triage applied"` از `Counter(disposition)`، و notes از `aisoc_case_comments WHERE is_system = TRUE`.
یعنی خروجی شما «تاریخِ اتفاقات» نیست، «خلاصه‌ی وضعیتِ فعلی» است. اگر عیناً برای Alert تکرار شود، همان مشکل تکرار می‌شود: چیزی که اتفاق نیفتاده ممکن است نمایش داده شود یا ترتیب زمانی از دست برود.

**(ب) تب Timeline در Alert صفحه‌ی جعلی دارد — این یک باگ است.**
`AlertDetailView.tsx:1249` دو رکورد **hardcoded** می‌سازد:
```tsx
{ time: alert.createdAt, type: 'alert_created', title: 'Alert Created', desc: `Alert ingested from ${alert.source}` },
{ time: alert.updatedAt, type: 'status_change', title: 'Status Updated', desc: `Status changed to ${alert.status}` },
```
این نه ingest واقعی را نشان می‌دهد نه تغییر وضعیت‌های تاریخی را (فقط `updatedAt` آخر). طبق قواعد پروژه (mock data به‌عنوان داده واقعی = باگ) این باید در همین کار اصلاح شود.

**(ج) Splunk simple mode بدون دست‌زدن به ingest/fusion امکان‌پذیر است.**
`promoter._llm_payload()` با `_as_mapping()` هم `Mapping` و هم string با `{` ابتدایی را می‌پذیرد و داخل `raw_data` هم قدم می‌زند. پس اگر `splunk.py::normalize()` یک `llm_payload` (dict) داخل `raw_event` بگذارد، بدون تغییر OCSF mapper یا fusion به ستون `alerts.llm_payload` می‌رسد. **این ریسک بزرگ‌ترین بخش کار را حذف می‌کند.**

---

## 3. طراحی

### 3.1 تفکیک مفاهیم (نام‌گذاری)

| مفهوم | معنا | محل |
|---|---|---|
| **Operational Runbook doc** | «چه کاری *باید* انجام شود» | `docs/operations/*.md`, `apps/docs/docs/operations/*` (بی‌تغییر) |
| **Playbook** | SOAR قابل اجرا با گام‌های از پیش تعریف‌شده | `services/agents/app/playbook/` (بی‌تغییر) |
| **RunbookEvent** | «چه کاری *انجام شد*، چرا مجاز بود، نتیجه چه شد» | **جدید** — `runbook_events` |
| **ActionDefinition / ActionPolicy** | «چه کاری *مجاز است* و با چه شرطی» | **جدید** — governance catalog |

### 3.2 مدل داده (migration `062_runbook.sql`)

**`action_definitions`** — کاتالوگ، source of truth در گیت (`action_catalog.py`) و mirror در DB برای override و UI:

```
slug            varchar(64) PK          -- e.g. "splunk.simple_query", "alert.close", "host.isolate"
label           text
category        varchar(32)             -- ingest|enrich|triage|investigate|respond|itsm|data
risk_class      varchar(16)             -- low|medium|high|critical
blast_radius    varchar(16)             -- none|entity|host|tenant|external
default_auto    numeric(3,2)            -- آستانه‌ها، هم‌معنی guardrails
default_review  numeric(3,2)
default_escalate numeric(3,2)
requires_approval_above numeric(3,2) NULL
evidence_required jsonb DEFAULT '[]'    -- فیلدهایی که باید موجود باشند تا مجاز شود
data_contract   jsonb                   -- DataSafetyContract: allowed_fields, pii_policy, redaction
failure_contract jsonb                  -- FailureContract: max_attempts, backoff_s, timeout_s, on_failure
cost_budget     jsonb                   -- CostBudget: max_usd_per_run, max_tokens, max_wall_ms
dry_run_default boolean DEFAULT true
schema_version  int DEFAULT 1
is_active       boolean DEFAULT true
```

**`runbook_events`** — ledger، append-only (trigger مثل `audit_log`):

```
id             uuid PK
tenant_id      uuid NOT NULL
subject_type   varchar(16) NOT NULL     -- alert|case|incident
subject_id     uuid NOT NULL
seq            bigint NOT NULL          -- monotonically increasing per subject
occurred_at    timestamptz NOT NULL
stage          varchar(32)              -- ingest|enrich|triage|investigate|funnel|respond|itsm|close
kind           varchar(32)              -- query_mode|llm_payload|enrichment|triage|investigation|finding|policy|approval|action|state_change
action_slug    varchar(64) NULL         -- FK-ish به action_definitions
actor_type     varchar(16)              -- system|agent|analyst|connector
actor_id       text NULL
actor_label    text NULL                -- "TriageAgent", "analyst@corp", "splunk-connector"
summary        text NOT NULL            -- خط «What we did»
detail         text NULL                -- متن بازشده
status         varchar(16) NOT NULL     -- recorded|allowed|denied|executed|simulated|failed|skipped
policy         jsonb NULL               -- {decision, autonomy_level, layer, thresholds, reason}
approval_id    uuid NULL                -- → agent_approvals.id
input          jsonb NULL
output         jsonb NULL
cost           jsonb NULL               -- {usd, tokens, model}
error          text NULL                -- sanitized inline
duration_ms    int NULL
audit_log_id   uuid NULL                -- پل به audit قانونی
idempotency_key varchar(128) NULL
created_at     timestamptz NOT NULL DEFAULT now()

UNIQUE (tenant_id, subject_type, subject_id, seq)
INDEX  (tenant_id, subject_type, subject_id, occurred_at DESC)
INDEX  (tenant_id, stage, created_at DESC)
UNIQUE (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
```

**`tenant_action_overrides`** — همان `TenantActionOptIn` + override آستانه:

```
id uuid PK, tenant_id uuid, action_slug varchar(64)
enabled boolean DEFAULT true            -- opt-in/opt-out
autonomy_level varchar(2) NULL          -- L0..L4 (سقف مؤثر)
thresholds jsonb NULL                   -- {auto, review, escalate} جایگزین defaults
approval_required boolean NULL
updated_by uuid NULL, updated_at timestamptz
UNIQUE (tenant_id, action_slug)
```

> **تصمیم:** برای approval جدول جدید نمی‌سازیم. `agent_approvals` موجود است و `alert_id`/`case_id`/`action`/`risk_level` دارد. `runbook_events.approval_id` به آن ارجاع می‌دهد.

### 3.3 قراردادها (فاز ۰) — به‌صورت کد، نه فقط جدول

`services/api/app/services/runbook/contracts.py`:

- **`AuditContract`** — هر Action پس از اجرا باید یک `runbook_events` بنویسد + در صورت `risk_class >= high` یک `audit_log` هم بنویسد. نگاشت `action_slug → audit.action` در همین فایل.
- **`DataSafetyContract`** — قبل از نوشتن `input`/`output`، فیلدهای حساس حذف/redact شوند. از `app/privacy/redactor` (موجود در agents) و `llm_safety.py` الگو بگیرد: keys در allowlist می‌مانند، بقیه `"[redacted]"`. `data_contract.allowed_fields` مرجع است.
- **`FailureContract`** — `on_failure ∈ {abort, continue, escalate}`, `max_attempts`, `backoff_s`, `timeout_s`. اجرای action از این‌ها تبعیت می‌کند و نتیجه در `status` ثبت می‌شود (`failed` هرگز به `executed` تبدیل نمی‌شود).
- **`CostBudget`** — سقف per-run؛ عبور از سقف → `status='denied'` با `policy.reason='cost_budget_exceeded'`.

### 3.4 لایه‌ی مجوز (فاز ۱)

`services/api/app/services/runbook/gate.py`:

```python
async def evaluate(db, *, action_slug, tenant_id, confidence, subject) -> GateDecision
```
ترتیب حل (همان سه‌لایه‌ی `guardrails.py`، بدون مدل جدید):
`action_definitions` defaults → site YAML (`AISOC_AUTONOMY_POLICY`) → `tenant_action_overrides`.

```python
@dataclass(frozen=True)
class GateDecision:
    decision: str          # allow | review | deny | require_approval
    autonomy_level: str    # L0..L4
    layer: str             # defaults | site_yaml | tenant
    thresholds: dict
    reason: str
    approval_required: bool
```

هر فراخوانی **یک ردیف `kind='policy'`** ثبت می‌کند — یعنی «چرا مجاز بود» همیشه قابل استناد است.

### 3.5 مسیرهای نوشتن در ledger (مهم‌ترین تصمیم معماری)

دو مسیر، بدون اینکه connectors به DB دسترسی پیدا کنند:

**مسیر A — in-band provenance (connectors → ingest → alert):**
Connector داخل `raw_event` یک بلوک `runbook_provenance` می‌گذارد:
```json
{"query_mode":"simple","notable_volume":24310,"threshold":20000,
 "reason":"volume_above_threshold","llm_payload_source":"code",
 "caveats":["macros_not_expanded"]}
```
سرویس API هنگام **اولین خواندن** Alert این بلوک را به‌صورت lazy به `runbook_events` materialize می‌کند (`stage='ingest'`, `kind='query_mode'|'llm_payload'`) — دقیقاً همان الگوی lazy-fill که `_build_alert_detail()` برای `narrative` دارد.

**مسیر B — out-of-band ledger (api / agents / fusion):**
سرویس‌هایی که از قبل به Postgres می‌نویسند (`fusion/services/alert_sink.py`, `agents/app/workers/case_promoter.py`, `api/services/agentic_funnel.py`, `api/api/v1/endpoints/cases.py`) در نقاط تغییر وضعیت یک ردیف ثبت می‌کنند.

> **چرا نه HTTP؟** نوشتن از طریق endpoint /events یعنی یک round-trip شبکه در hot path تریاژ + نیاز به service-token. fusion و agents الان هم مستقیم DB می‌نویسند؛ همان الگو ادامه می‌یابد.

`recorder.py` یک helper مشترک است (vendored pattern مثل `cors.py`):
```python
async def record(db, *, tenant_id, subject_type, subject_id, stage, kind,
                 summary, status="recorded", **fields) -> uuid.UUID
```
با `idempotency_key` تا retry پلیس‌ها ردیف تکراری نسازد. تخصیص `seq` با `INSERT ... SELECT COALESCE(MAX(seq),0)+1` داخل همان تراکنش + retry روی unique-violation.

### 3.6 فاز ۱ — Splunk Simple Query Mode + llm_payload builder

**فیلدهای جدید در `schema()` connector:**

| field | default | معنی |
|---|---|---|
| `query_mode` | `pipeline` | `pipeline` (پیش‌فرض، رفتار فعلی) \| `simple` \| `auto` |
| `pipeline_max_notables` | `20000` | سقف فقط در حالت `auto` |
| `fallback_to_simple_on_failure` | `false` | در خطای memory/timeout به simple سوییچ کند یا نه |
| `enable_rule_enrichment` | `true` | دو REST call برای rule SPL + macros |

> **پیش‌فرض `pipeline` است** — هیچ instance موجودی رفتارش بدون اقدام ادمین تغییر نمی‌کند. حالت `auto` و fallback هر دو opt-in هستند تا هیچ تغییری در داده‌ی ingest‌شده بی‌اطلاع رخ ندهد.

**کوئری ساده** (همان که فرستادید، به‌عنوان ثابت `_SIMPLE_NOTABLE_SPL`):
```
search index=notable | table _time source search_name severity host dvc dest_port
       source_guid source_event_id _cd _raw
```

**انتخاب حالت در `_fetch_rows()`:**
1. `custom_search` غیرخالی → همان رفتار فعلی (هیچ‌وقت بازنویسی نمی‌شود).
2. `query_mode == 'simple'` → `_SIMPLE_NOTABLE_SPL`.
3. `query_mode == 'pipeline'` (پیش‌فرض) → Mission Control کامل، دقیقاً مثل امروز.
4. `query_mode == 'auto'` (opt-in) → **preflight** با یک oneshot ارزان: `search index=notable [filters] | stats count`. اگر `count > pipeline_max_notables` → simple. (preflight خودش سبک است و مشکل memory نمی‌سازد.)
5. اگر `fallback_to_simple_on_failure=true` و job با memory/timeout شکست خورد → **fallback به simple** و ثبت `reason='pipeline_failed'` در provenance (خطا هم لاگ می‌شود؛ silent-success ممنوع).

**پیامد آگاهانه:** با پیش‌فرض `pipeline` + `fallback=false`، یک instance پرحجم در صورت memory error هیچ alertی نمی‌آورد (رفتار امروز). راه‌حل توصیه‌شده برای آن instance: یا `query_mode=simple` دستی، یا `auto` تا خودکار تصمیم بگیرد.

**`_build_llm_payload(row)` سمت Python** — بازسازی شکل همان payload نمونه‌ی شما:
```
rule{ title, title_template, description, spl, spl_caveat, macro_definitions }
annotations{ mitre_attack, analytic_story, kill_chain_phases, cis20, nist, data_source, cve, type_list }
alert_fields ← همه‌ی فیلدهای غیرمتادیتای ردیف (همان regex exclusion اما در Python)
time_window{earliest, latest, search_time} ← از info_min_time/info_max_time اگر موجود، وگرنه null
                                              + source="declared_window" هرگز ساختگی ساخته نشود
event_time_source{first_event|alert_time_fallback}
date_context, entity, entity_type, risk_score, severity, finding_count, investigation_hint
_meta{ provider:"splunk", mode:"simple", caveats:["macros_not_expanded"] }
```
اگر `enable_rule_enrichment` روشن باشد: دو call کوچک (`/saved/searches/<name>` و `/configs/conf-macros`) تا `rule.spl` و `macro_definitions` پر شود — همان داده‌ای که pipeline با `| rest` می‌آورد، اما بدون memory blow-up.

**قاعده‌ی صداقت:** اگر payload از حالت simple ساخته شد، `rule.spl` ممکن است `null` باشد و `_meta.caveats` پر است. UI باید «Simple mode — macroها expand نشده‌اند» را نشان دهد، نه اینکه آن را معادل pipeline جا بزند.

### 3.7 فاز ۲ — صفحه و پنل

**الف) پنل قابل جاسازی (برای Alert Overview):**
`apps/web/src/components/runbook/RunbookPanel.tsx` — props: `{ subjectType, subjectId }`
ساختار (همان سه‌ستون آشنای شما + دو بخش جدید):

```
┌ Investigation brief ────────────────────────────────── [Outcome chip] ┐
│ Runbook · 9 events · window 11:10–12:20 · mode: live (L2)              │
├───────────────┬───────────────────────┬────────────────────────────────┤
│ What we did   │ Data acquisition      │ Governance                     │
│ (ledger,      │ (query mode، حجم      │ (layer، threshold، approval)   │
│  زمان‌دار)     │  notable، payload src)│                                │
└───────────────┴───────────────────────┴────────────────────────────────┘
```
هر ردیف What-we-did: `summary` + چیپ `actor` (agent/analyst/system) + چیپ `status` (executed/simulated/failed/denied) + `duration` + expand برای `input`/`output` + لینک به approval.
**Empty state صریح**: «هیچ event ثبت نشده» — هیچ ردیفی از فیلدها ساخته نمی‌شود.

**ب) صفحه‌ی مستقل:** `apps/web/src/app/(app)/runbook/page.tsx`
- فیلتر: subject type، stage، status، actor، بازه‌ی زمانی
- جدول + drawer جزئیات (همان الگوی `InvestigationRail`)
- دکمه‌ی Export Markdown

**ج) رفع باگ تب Timeline — تصمیم نهایی: دو سطح، نه دو تکرار.**
دو سطح نمایش، هر کدام یک نقش، بدون تکرار داده:

| سطح | محل | نقش | منبع |
|---|---|---|---|
| **خلاصه** | پنل در تب Overview | «چه کاری کردیم» — گروه‌بندی‌شده بر اساس stage | `runbook_events` (مرتب بر اساس stage) |
| **خط زمانی کامل** | تب `timeline` → تغییر نام به `runbook` | ثبت کامل گام‌به‌گام با دکمه/سیاست/نتیجه | `runbook_events` (مرتب بر اساس `occurred_at`) |

دلیل: حذف کامل تب timeline انتظار تحلیل‌گر را می‌شکند، و دو تب جدا با یک داده غیرحرفه‌ای است. یک منبع، دو نما.

پیاده‌سازی:
- `AlertDetailView.tsx:1085` → `'timeline'` به `'runbook'` تغییر نام و لیبل «Runbook».
- `AlertDetailView.tsx:1249` → بدنه‌ی hardcoded حذف؛ رندر از `runbookApi.list('alert', id)`.
- اگر ledger خالی ولی `audit_log` داده دارد → نمایش fallback با برچسب صریح `source: audit`.
- اگر هر دو خالی → empty state: «هیچ رویدادی ثبت نشده» (نه ردیف ساختگی).

### 3.8 API

`services/api/app/api/v1/endpoints/runbook.py` (router prefix `/runbook`):

| متد | مسیر | کار |
|---|---|---|
| GET | `/runbook/actions` | کاتالوگ + policy مؤثر tenant |
| PATCH | `/runbook/actions/{slug}` | override per-tenant (`runbook:admin`) |
| GET | `/runbook/events` | ledger با فیلتر `subject_type`, `subject_id`, `stage`, `status`, cursor |
| GET | `/runbook/subjects/{type}/{id}` | view-model آماده‌ی پنل (header + what_we_did + governance + data_acquisition) |

در `alerts.py`:
| GET | `/alerts/{id}/runbook` | همان view-model برای Alert |
| GET | `/alerts/{id}/runbook.md` | خروجی Markdown (الگوی `GET /cases/{id}/report.md`) |

فرم‌ها: `RunbookEventOut`, `RunbookSubjectView`, `ActionDefinitionOut`, `ActionOverridePatch`.
مجوزها: خواندن `alerts:read`/`cases:read`، نوشتن override `runbook:admin`.
Tenant isolation: `WHERE tenant_id = :tid` در همه‌ی queryها (نه فقط RLS).

### 3.9 نقاط emission (فاز ۱) — حداقل مجموعه‌ی ارزشمند

| نقطه | فایل | event |
|---|---|---|
| ingest alert | `fusion/app/services/alert_sink.py` | `stage=ingest`, `kind=query_mode`/`llm_payload` (از provenance) |
| triage | `api/services/agentic_funnel.py` + `agents` triage | `stage=triage`, `kind=triage`, status از verdict |
| escalate/full pipeline | همان مسیر triage | `kind=policy`، `summary="Escalating: confidence 0.72 < 0.85"` |
| case promote | `agents/app/workers/case_promoter.py` | `stage=funnel`, `kind=state_change` |
| ITSM push | `api/api/v1/endpoints/inbox_itsm.py` | `stage=itsm`, `kind=action` |
| analyst disposition / status | `api/api/v1/endpoints/alerts.py::update_alert` | `kind=state_change`, `actor_type=analyst` |
| containment (playbook/actions) | `services/actions/*` | `kind=action`, `status=executed|simulated` |

**قاعده:** اگر action واقعی اجرا نشد و خروجی `simulated` بود، `status='simulated'` — هرگز `executed`.

---

## 4. Step-by-Step Plan

### فاز ۰ — Governance

| # | کار | فایل‌ها | وضعیت |
|---|---|---|---|
| 0.0 | فلگ `AISOC_RUNBOOK_ENABLED` (پیش‌فرض: روشن در dev، خاموش در prod) + `runbook_enabled()` dependency | `services/api/app/core/config.py` | [ ] pending |
| 0.1 | migration `062_runbook.sql`: سه جدول + trigger append-only + ایندکس‌ها | `services/api/migrations/062_runbook.sql` | [ ] pending |
| 0.2 | کاتالوگ Actions (منبع حقیقت در گیت) + seed | `services/api/app/services/runbook/action_catalog.py` | [ ] pending |
| 0.3 | قراردادها: Audit/DataSafety/Failure/Cost | `services/api/app/services/runbook/contracts.py` | [ ] pending |
| 0.4 | `evaluate()` سه‌لایه، بازاستفاده از semantics `guardrails.py` | `services/api/app/services/runbook/gate.py` | [ ] pending |
| 0.5 | تست gate: defaults / site YAML / tenant override / reject | `services/api/tests/test_runbook_gate.py` | [ ] pending |

### فاز ۱ — Execution ledger

| # | کار | فایل‌ها | وضعیت |
|---|---|---|---|
| 1.1 | `record()` idempotent + تخصیص `seq` + sanitize | `services/api/app/services/runbook/recorder.py` | [ ] pending |
| 1.2 | تست append-only + seq + tenant isolation | `services/api/tests/test_runbook_events.py` | [ ] pending |
| 1.3 | Splunk: `query_mode` / `pipeline_max_notables` / `enable_rule_enrichment` در `schema()` | `connectors/splunk.py` | [ ] pending |
| 1.4 | `_preflight_count()` + انتخاب حالت + fallback با ثبت دلیل | `connectors/splunk.py` | [ ] pending |
| 1.5 | `_build_llm_payload()` سمت Python + `_meta.caveats` | `connectors/splunk.py` | [ ] pending |
| 1.6 | `runbook_provenance` داخل `raw_event` | `connectors/splunk.py::normalize` | [ ] pending |
| 1.7 | تست: threshold، fallback، fidelity payload | `connectors/tests/test_splunk_simple_mode.py` | [ ] pending |
| 1.8 | materialize provenance → `runbook_events` (lazy، الگوی narrative) | `api/services/runbook/materialize.py` | [ ] pending |
| 1.9 | emission در چوک‌پوینت‌ها (بند ۳.۹) | `fusion/alert_sink.py`, `agents/case_promoter.py`, `api/agentic_funnel.py`, `api/inbox_itsm.py`, `api/alerts.py` | [ ] pending |
| 1.10 | تست emission: هر نقطه حداقل یک تست | همان سرویس‌ها | [ ] pending |

### فاز ۲ — API + صفحه

| # | کار | فایل‌ها | وضعیت |
|---|---|---|---|
| 2.1 | endpointهای `/runbook/*` + `/alerts/{id}/runbook(.md)` | `api/api/v1/endpoints/runbook.py`, `alerts.py` | [ ] pending |
| 2.2 | ثبت router در `api.py` + تایپ‌های پاسخ | `api/api/v1/api.py` | [ ] pending |
| 2.3 | `runbookApi` + تایپ‌ها | `apps/web/src/lib/api.ts` | [ ] pending |
| 2.4 | پنل: `RunbookPanel` + `RunbookEventRow` + چیپ‌ها | `apps/web/src/components/runbook/` | [ ] pending |
| 2.5 | جاسازی پنل خلاصه در Alert Overview | `apps/web/src/components/alerts/AlertDetailView.tsx` | [ ] pending |
| 2.6 | تب `timeline` → `runbook`، حذف رکوردهای hardcoded، رندر از ledger | `AlertDetailView.tsx:1085,1249` | [ ] pending |
| 2.7 | صفحه‌ی `/runbook` با فیلتر و drawer | `apps/web/src/app/(app)/runbook/page.tsx` | [ ] pending |
| 2.8 | تست کامپوننت (empty state + rendering) | `apps/web/src/components/runbook/RunbookPanel.test.tsx` | [ ] pending |

### مستندسازی و گیت‌ها

| # | کار | فایل‌ها | وضعیت |
|---|---|---|---|
| 3.1 | سند کاربر: runbook چیست و با operations doc چه تفاوتی دارد | `apps/docs/docs/console/runbook.md` | [ ] pending |
| 3.2 | ایندکس در sidebar | `apps/docs/sidebars.ts` | [ ] pending |
| 3.3 | `CHANGELOG.md` → `[Unreleased]` | `CHANGELOG.md` | [ ] pending |
| 3.4 | به‌روزرسانی `docs/openapi.yaml` (گیت OpenAPI) | `docs/openapi.yaml` | [ ] pending |
| 3.5 | اجرای گیت‌ها: `pnpm type-check`، `pytest` سه سرویس، `ruff`، CodeQL | — | [ ] pending |

---

## 5. Modified Files Log

(با پیشرفت کار به‌روزرسانی می‌شود — طبق `copilot-instructions.md`)

| فایل | تغییر | وضعیت |
|---|---|---|
| `docs/plans/PLAN-20261027-1501-runbook-page.md` | ایجاد سند پلن + ثبت تصمیم‌های D1–D4 | ✅ انجام شد |

**تغییر موجود در workspace که مال این کار نیست:** `services/connectors/app/connectors/splunk.py` یک diff یک‌خطی uncommitted دارد: حذف `count|punct|linecount|drilldown_.*` از regex استثنای `foreach *` در `_MISSION_CONTROL_PIPELINE`. این یعنی آن فیلدها الان وارد `rule_specific_json` می‌شوند. قبل از دست‌زدن به همان فایل باید تعیین تکلیف شود (متعلق به کار Runbook نیست).

---

## 6. Risks & Dependencies

### ریسک‌های اصلی

| # | ریسک | شدت | کاهش |
|---|---|---|---|
| R1 | **مسیر اجرای دوم** — اگر Runbook خودش action اجرا کند، موازی با playbook engine می‌شود و دو حقیقت متفاوت می‌سازد | بالا | v1 فقط **ledger + gate**؛ اجرا دست سرویس‌های موجود می‌ماند |
| R2 | **یکپارچگی داده** — append-only واقعی نباشد و بعداً UPDATE شود | بالا | trigger در DB (مثل `audit_log`) + تست منفی |
| R3 | **نوشتن در hot path** — هر گام تریاژ یک INSERT | متوسط | فقط eventهای معنادار؛ batch برای مراحل پرتکرار؛ `seq` در همان تراکنش |
| R4 | **فریب ظاهری** — پنل پر شود از استنتاج فیلدها مثل `case_investigation_brief` | بالا | rule صریح: هیچ ردیف از فیلد ساخته نمی‌شود؛ empty state واقعی |
| R5 | **کاهش دقت simple mode** — `rule.spl` و macroها ممکن است نباشند | متوسط | `_meta.caveats` + نمایش در UI + `enable_rule_enrichment` برای جبران |
| R6 | **خطای memory در preflight** — اگر `| stats count` هم روی بازه‌ی بزرگ شکست بخورد | کم | preflight با `earliest=-1h` و `head` محافظت‌شده؛ در خطا → simple |
| R7 | **حجم `raw_event`** — افزودن provenance حجم ردیف را بالا می‌برد | کم | بلوک provenance < 500 بایت، بدون تکرار payload |
| R8 | **migration 062 روی Fly** | متوسط | الگوی retry موجود در `run_migrations.py`؛ migration idempotent |
| R9 | **CodeQL** — لاگ‌های جدید با ورودی خارجی | متوسط | sanitize inline دقیقاً طبق الگوی `waitlist.py` |
| R10 | **نام‌گذاری** — تداخل «runbook» با اسناد رویه | کم | تفکیک مستند ۳.۱ |

### تصمیم‌های تأییدشده (۲۰۲۶-۱۰-۲۷)

| # | تصمیم | نتیجه |
|---|---|---|
| D1 | دامنه Governance در v1 | **حداقلی داخل v1** — چهار قرارداد به‌صورت jsonb + gate سه‌لایه؛ بدون UI کامل مدیریت policy |
| D2 | تب Timeline | **یک منبع، دو نما** — خلاصه در Overview، خط زمانی کامل در تب `runbook`؛ رکوردهای hardcoded حذف |
| D3 | پیش‌فرض Splunk | **`pipeline`** — بدون تغییر رفتار instanceهای موجود؛ `simple`/`auto`/`fallback` همه opt-in |
| D4 | فعال‌سازی | **پشت `AISOC_RUNBOOK_ENABLED`** — پیش‌فرض روشن در dev، خاموش در prod تا تأیید |

### تصمیم‌های فرعی که خودم گرفتم (قابل تغییر)

- **Approval**: استفاده‌ی مجدد از `agent_approvals` — جدول جدید ساخته نمی‌شود.
- **`fallback_to_simple_on_failure`**: پیش‌فرض `false` تا هیچ datasetی بی‌اطلاع تغییر نکند.
- **`count|punct|linecount` در diff موجود**: به کار Runbook مربوط نیست؛ دست نمی‌زنم و تعیین تکلیفش را به شما می‌سپارم.

### پیش‌نیازها / وابستگی‌ها

- migration `061` تنها ستون لازم برای `llm_payload` را دارد — بدون تغییر ingest/fusion.
- `guardrails.py` semantics منبع autonomy است؛ در صورت تغییر آن، gate باید هم‌زمان به‌روز شود.
- گیت‌های CI که این کار لمس می‌کند: OpenAPI check، CodeQL، `pnpm type-check`، pytest سه سرویس، claim-to-gate matrix (اگر ادعای новый در README/داکس اضافه شود → باید gate داشته باشد).

---

## 7. ترتیب اجرا (پیشنهاد)

```
0.0 → 0.1 → 0.2 → 0.3 → 0.4 → 0.5  (فلگ + Governance، بدون UI)
        ↓
1.1 → 1.2                           (ledger پایه)
        ↓
1.3 → 1.4 → 1.5 → 1.6 → 1.7        (Splunk simple mode — مستقل و قابل تست)
        ↓
1.8 → 1.9 → 1.10                    (materialize + emission)
        ↓
2.1 → 2.2 → 2.3                     (API)
        ↓
2.4 → 2.5 → 2.6 → 2.7 → 2.8        (UI)
        ↓
3.1 … 3.5                           (docs + گیت‌ها)
```

هر مرحله یک commit مستقل؛ گام‌های ۱.۳–۱.۷ را می‌توان موازی با ۰.x پیش برد چون به ledger وابسته نیستند (فقط provenance در `raw_event`).
