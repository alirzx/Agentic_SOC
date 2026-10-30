
---

# معماری جامع و تاییدشده — AiSOC

**وضعیت:** تاییدشده بر اساس کد (Code-verified) در تاریخ ۲۰۲۶-۱۰-۳۰. هر فلش در نمودارهای زیر قابل ردیابی به یک فایل و یک تابع در سورس کد است. مراحلی که در پیاده‌سازی **وجود ندارند** با رنگ قرمز (`absent`) مشخص شده‌اند تا از توهمات معماری جلوگیری شود.

**این سند چیست:** منبع واحد حقیقت (Single Source of Truth) برای کل معماری پلتفرم. این سند شامل نمودار کلی چرخه حیات و سپس زوم عمیق روی هر زیرسیستم است.

---

## بخش ۱ — چرخه حیات اصلی (تاییدشده بر اساس کد)

این نمودار فازهای ۱ تا ۶ (از دریافت داده تا ارسال به Jira) را پوشش می‌دهد. فلش‌های ممتد مسیرهای کدی هستند که اجرا می‌شوند. فلش‌های نقطه‌چین با برچسب "نوشته نمی‌شود" نشان می‌دهند که در آن مرحله، هیچ رکوردی در دفتر ثبت (`runbook_events`) درج نمی‌شود.

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef human    fill:#d97706,stroke:#b45309,stroke-width:3px,color:#fff
    classDef ledger   fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef stage    fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3

    subgraph P1["1 · Ingest and Fusion — nothing is written to the ledger here"]
        direction TB
        SRC["Connectors<br/>Splunk · EDR · Cloud · IAM · SaaS"]:::auto
        ING["services/ingest<br/>OCSF normalization"]:::auto
        RAW[("Kafka raw_events")]:::infra
        FUS["services/fusion<br/>dedup · correlation<br/>trust · narrative"]:::auto
        PG[("Postgres alerts<br/>AlertSink insert<br/>idempotent on dedup_hash")]:::infra
        TOP[("Kafka aisoc.alerts.fused")]:::infra
        FS0["alerts.funnel_stage = ingested"]:::stage
        N1["No row written to runbook_events<br/>for alert creation"]:::absent

        SRC -->|"POST /v1/ingest/batch · X-Tenant-ID"| ING --> RAW --> FUS
        FUS --> PG
        FUS --> TOP
        PG --> FS0
        FS0 -.->|"nothing written"| N1
    end

    subgraph P2["2 · Automated triage — services/agents fused_alert_consumer.py"]
        direction TB
        TRI["Automated triage<br/>run_auto_triage<br/>deterministic fallback run_triage"]:::auto
        V{"Verdict + confidence"}:::decision
        ACO["Auto-close<br/>false_positive · benign<br/>benign_true_positive"]:::auto
        INV{"passes_investigation_gate<br/>TP · escalate · likely_tp<br/>needs_review at high severity<br/>or medium 0.70+"}:::decision
        ILG[("Investigation Ledger<br/>investigation_runs<br/>investigation_events<br/>kind = triage_verdict")]:::ledger
        MR[("runbook_tasks<br/>task_type = manual_review")]:::human
        WS[("Kafka aisoc.runbook.task_updates<br/>→ realtime /ws/runbook")]:::infra
        FS1["alerts.funnel_stage = suppressed"]:::stage
        FS2["alerts.funnel_stage = triaged"]:::stage
        FS3["alerts.funnel_stage = investigating"]:::stage
        N2["No row in runbook_events<br/>for the result"]:::absent

        TOP --> TRI --> V
        TRI --> ILG
        ILG -.->|"read by Runbook at render time"| N2
        V -->|"auto-closeable"| ACO --> FS1
        V -->|"needs review"| MR --> WS
        V -->|"escalate"| INV
        INV -->|"no"| FS2
        INV -->|"yes"| FS3
    end

    subgraph P3["3 · Promotion to Case — services/agents case_promoter.py"]
        direction TB
        CP["promote_to_case<br/>create Case · link family alerts<br/>tasks · comments"]:::auto
        CASES[("aisoc_cases · aisoc_case_tasks")]:::infra
        RJ{"passes_ready_for_jira_stage<br/>Case + disposition + evidence threshold"}:::decision
        FS4["alerts.funnel_stage = cased"]:::stage
        FS5["alerts.funnel_stage = ready_for_jira"]:::stage
        N3["No row in runbook_events<br/>the promoting agent does not write 'Case opened'"]:::absent

        FS3 --> CP --> CASES
        CP --> RJ
        RJ -->|"threshold not met"| FS4
        RJ -->|"threshold met"| FS5
        CP -.->|"nothing written"| N3
    end

    subgraph P4["4 · Ledger writers — the only code that writes runbook_events"]
        direction TB
        GETD["GET /api/v1/alerts/id<br/>lazy provenance promotion"]:::auto
        PATCH["PATCH /api/v1/alerts/id"]:::auto
        ESC["POST /api/v1/alerts/id/escalate"]:::auto
        EVAL["Rule evaluator worker<br/>claims alerts with automation_rules_evaluated_at IS NULL"]:::auto
        RULES["Automation rules<br/>alert.created via evaluator<br/>alert.updated via PATCH"]:::auto
        GATE{"Governance gate<br/>gate.evaluate + rule authority cap"}:::decision
        PB["Start linked playbook<br/>POST agents /api/v1/playbooks/id/run"]:::auto
        PLR[("playbook_runs<br/>status = pending_approval")]:::infra
        BF["POST /api/v1/soc/funnel/backfill"]:::auto
        WH["POST /api/v1/inbox/itsm/tenant_token/instance<br/>inbound webhook from Jira or ServiceNow"]:::auto

        RE[("runbook_events<br/>append-only<br/>triggers block UPDATE and DELETE")]:::ledger
        TASKS[("runbook_tasks<br/>task_type = approval_gate")]:::human
        RUN["GET /api/v1/runbook/subject_type/subject_id<br/>procedure + ledger + triage union"]:::auto

        GETD -->|"stage=ingest kind=query_mode<br/>stage=enrich kind=llm_payload"| RE
        PATCH -->|"one row per changed field<br/>stage=triage or funnel"| RE
        ESC -->|"stage=triage kind=state_change"| RE
        EVAL -->|"alert.created"| GATE
        RULES --> GATE
        PATCH -->|"alert.updated · fire-and-forget"| GATE
        GATE -->|"allowed · denied · simulated · executed"| RE
        GATE -->|"Containment or Case action blocked"| TASKS
        GATE -->|"allowed and playbook_ref set"| PB
        PB -->|"kind=action action_name=playbook.run"| RE
        PB -->|"pauses at an approval step"| PLR
        PLR -->|"one open gate task per run"| TASKS
        BF -->|"Case opened from N alert(s)"| RE
        WH -->|"case-scoped stage=itsm"| RE
        RE --> RUN
        ILG -.->|"read-only union, never copied"| RUN
    end

    subgraph P5["5 · Analyst decision — Action Plan"]
        direction TB
        COMP["POST /api/v1/runbook/tasks/id/complete"]:::human
        RES{"playbook_run_id exists?"}:::decision
        RS["POST agents /api/v1/playbooks/runs/id/resume<br/>approve · reject"]:::auto
        FB["POST /api/v1/outcomes/feedback<br/>outcome prior updated"]:::auto
        PLRS[("playbook_runs<br/>running · completed · cancelled")]:::infra
        TROW[("runbook_tasks<br/>resolution · feedback_applied<br/>resume_applied")]:::infra
        N5["No row in runbook_events<br/>the human decision is not a ledger event"]:::absent

        TASKS --> COMP --> RES
        MR --> COMP
        RES -->|"yes · playbooks:approve"| RS --> PLRS
        RES -->|"no"| FB
        RS --> FB
        COMP --> TROW
        COMP -.->|"nothing written"| N5
    end

    subgraph P6["6 · Jira and outbound delivery — optional, via connector"]
        direction TB
        PUSH["POST /api/v1/soc/funnel/push-itsm<br/>or POST /api/v1/cases with connector_ids"]:::auto
        JG{"passes_jira_gate"}:::decision
        FAN["case_fanout.fanout_create_case<br/>best effort, sequential per connector"]:::auto
        REFS[("case_external_refs")]:::infra
        FS6["alerts.funnel_stage = jira_pushed"]:::stage
        SKIP["Returned as skipped / error<br/>in ticket_refs"]:::absent
        N6["No row in runbook_events<br/>for outbound delivery"]:::absent

        FS5 --> PUSH --> JG
        JG -->|"blocked"| SKIP
        JG -->|"passed"| FAN
        FAN -->|"at least one successful send"| REFS
        REFS --> FS6
        FAN -->|"any error"| SKIP
        FAN -.->|"nothing written"| N6
    end

    subgraph LEGEND["Legend"]
        direction LR
        L1["Automated step"]:::auto
        L2["Human queue or task"]:::human
        L3["Ledger table"]:::ledger
        L4["Decision point"]:::decision
        L5["Funnel stage label"]:::stage
        L6["Infrastructure"]:::infra
        L7["Not written"]:::absent
    end
```

</div>

---

## بخش ۲ — زیرسیستم‌های عمیق و تاییدشده

### ۲.۱ خط لوله تفصیلی Fusion

*   **UEBA Boost واقعی است اما اختیاری.** اگر کش Redis وجود داشته باشد، بسته به سطح ریسک یک افزایش (Additive) اعمال می‌کند.
*   **Vuln Boost واقعی و وابسته به کانفیگ است.**
*   **Neo4j یک مخزن هشدار نیست.** Fusion فقط در جدول `alerts` در Postgres می‌نویسد. گراف Neo4j توسط یک مسیر جداگانه در زمان Ingest نوشته می‌شود.

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef boost    fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef narr     fill:#059669,stroke:#047857,stroke-width:2px,color:#fff

    INPUT[("Kafka raw_events<br/>normalized OCSF alert")]:::infra
    DEDUP["Deduplicator<br/>Redis SET NX + fingerprint<br/>duplicate? → early return"]:::auto
    DEDUP_DUP["Duplicate<br/>no further processing"]:::absent
    CORR["Correlator<br/>Redis + durable store<br/>time-window grouping"]:::auto
    ML["MLScorer<br/>IsolationForest anomaly_score<br/>LightGBM priority_score"]:::auto
    ENRICH["AlertEnricher<br/>extract IOCs → POST /enrich/bulk<br/>fill fused.enrichments"]:::auto
    ENRICH_SKIP["No IOCs → skipped<br/>scorer keeps 'no TI match'"]:::absent
    CONF["ConfidenceScorer<br/>7 weighted factors + memory change<br/>HIGH≥0.70 / MEDIUM / LOW &lt;0.40"]:::auto
    VULN{"vuln_boost_enabled?"}:::decision
    VULN_ON["VulnBoost<br/>exploited vulnerability found?<br/>exploit_in_wild = True<br/>trust +0.15"]:::boost
    VULN_OFF["Skipped"]:::absent
    UEBA_CACHE{"_ueba_cache available?"}:::decision
    UEBA_LOOKUP["UebaSignalCache.lookup<br/>highest anomaly in<br/>username / hostname / srcIP / dstIP"]:::auto
    UEBA_BOOST["apply_ueba_boost<br/>trust change +0.0–0.20<br/>anomaly_score raised to ≥ UEBA score"]:::boost
    UEBA_OFF["Skipped — no behavioral merge"]:::absent
    RBA{"_entity_risk enabled?"}:::decision
    RBA_ON["EntityRiskEngine.observe<br/>collect score per entity"]:::auto
    RBA_OFF["Skipped"]:::absent
    NARR["build_narrative<br/>deterministic, light Markdown<br/>summary / reason / correlation / action"]:::narr
    SINK["AlertSink.persist<br/>asyncpg INSERT … WHERE NOT EXISTS dedup_hash<br/>INSERTED / DUPLICATE / UNAVAILABLE / FAILED"]:::auto
    PG[("Postgres alerts")]:::infra
    TOP[("Kafka aisoc.alerts.fused")]:::infra
    N_NEO4J["Neo4j 'Incident Store'<br/>not written here"]:::absent

    INPUT --> DEDUP
    DEDUP -->|"duplicate"| DEDUP_DUP
    DEDUP -->|"unique"| CORR --> ML
    ML --> ENRICH
    ENRICH -->|"has IOCs"| ENRICH_SKIP -.->|"no-op enriches"| CONF
    ENRICH -->|"no IOCs"| CONF
    CONF --> VULN
    VULN -->|"yes"| VULN_ON -.->|"does not write Neo4j"| N_NEO4J
    VULN -->|"no"| UEBA_CACHE
    VULN_ON --> UEBA_CACHE
    UEBA_CACHE -->|"cache available"| UEBA_LOOKUP --> UEBA_BOOST
    UEBA_CACHE -->|"no (no cache / miss)"| UEBA_OFF -.->|"no-op"| RBA
    RBA --> NARR --> SINK
    SINK --> PG
    SINK --> TOP

    style INPUT fill:#475569,color:#fff
    style PG fill:#475569,color:#fff
    style TOP fill:#475569,color:#fff
    style DEDUP_DUP fill:#7f1d1d,color:#fff
    style ENRICH_SKIP fill:#7f1d1d,color:#fff
    style VULN_OFF fill:#7f1d1d,color:#fff
    style UEBA_OFF fill:#7f1d1d,color:#fff
    style RBA_OFF fill:#7f1d1d,color:#fff
    style N_NEO4J fill:#7f1d1d,color:#fff
```

</div>

---

### ۲.۲ درخت تصمیم‌گیری تریاژ خودکار

*   **Business context یک موتور قوانین کدی است، نه یک خواندن از Redis.**
*   **Memory و override دو مرحله جداگانه هستند.**
*   **تصمیم Cost governor انتخاب‌کننده لایه (Tier) است.**
*   **آستانه بستن خودکار `AISOC_AUTO_CLOSE_THRESHOLD` (پیش‌فرض 0.85) است.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef human    fill:#d97706,stroke:#b45309,stroke-width:3px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef ledger   fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef stage    fill:#059669,stroke:#047857,stroke-width:2px,color:#fff

    TOP[("Kafka aisoc.alerts.fused")]:::infra
    BC["BusinessContextApplier.apply<br/>phase B4 — rules file + environment flag<br/>suppress: drop (no triage cost)"]:::auto
    BC_SUPP["suppressed<br/>record_business_context_suppression<br/>disposition=benign, funnel_stage=suppressed"]:::auto
    ENRICH["_enrich_asset_context<br/>Asset/CMDB fail-soft<br/>add asset_context to raw_alert"]:::auto
    MEM_SUPP{"AISOC_AGENT_MEMORY_SUPPRESSION?"}:::decision
    MEM_LOOKUP["lookup_prior(signature)<br/>valid benign/FP history?"]:::auto
    MEM_RESOLVE["Auto-resolved from memory<br/>result from history, confidence 0.9<br/>tier=memory"]:::auto
    OVERRIDE_SUPP{"override enabled?"}:::decision
    OVERRIDE_LOOKUP["lookup_human_override<br/>coarse signature match?"]:::auto
    OVERRIDE_RESOLVE["Auto-resolved from analyst override<br/>verdict=corrected_verdict<br/>confidence 0.95<br/>tier=override"]:::auto
    GOVERNOR["get_governor().check<br/>evidence fingerprint → Decision"]:::auto
    TIER{"Tier selection"}:::decision
    TIER_CACHED["DEDUPLICATED + cached result<br/>reuse result, no LLM"]:::auto
    TIER_DETR["Deterministic<br/>run_triage(state)"]:::auto
    TIER_LLM["run_auto_triage(state)<br/>LLM, with tenant BYOK override<br/>falls back to deterministic on error"]:::auto
    VERDICT["state.verdict + state.confidence<br/>guarded: empty verdict → needs_review"]:::auto
    PERSIST["persist_auto_triage<br/>one transaction:<br/>investigation_runs<br/>investigation_events<br/>alerts: disposition, ai_score, funnel_stage"]:::ledger
    NEEDS_REVIEW{"verdict == needs_review?"}:::decision
    TASK["create_task_for_needs_review<br/>runbook_tasks (task_type=manual_review)<br/>Kafka aisoc.runbook.task_updates"]:::human
    COMPLETED{"state.status is COMPLETED?"}:::decision
    INV_GATE["passes_investigation_gate<br/>TP/escalate/likely_tp → yes<br/>needs_review at high severity → yes"]:::decision
    SET_INV["_set_funnel_stage<br/>UPDATE alerts SET funnel_stage=investigating"]:::auto
    ESCALATE["_maybe_escalate<br/>run_escalation(state)"]:::auto
    PROMOTE["_maybe_promote_case<br/>case_promoter.promote_to_case"]:::auto
    AUTO_CLOSE{"verdict in AUTO_CLOSEABLE?"}:::decision
    FP_TAG["tag_false_positive<br/>tags += false_positive<br/>funnel_stage=suppressed"]:::auto
    SUPPRESSED["funnel_stage = suppressed"]:::stage
    TRIAGED["funnel_stage = triaged"]:::stage
    INVESTIGATING["funnel_stage = investigating"]:::stage

    TOP --> BC
    BC -->|"suppressed"| BC_SUPP --> SUPPRESSED
    BC -->|"continue"| ENRICH
    ENRICH --> MEM_SUPP
    MEM_SUPP -->|"yes"| MEM_LOOKUP
    MEM_LOOKUP -->|"suppress"| MEM_RESOLVE --> SUPPRESSED
    MEM_LOOKUP -->|"no suppress"| OVERRIDE_SUPP
    MEM_SUPP -->|"no"| OVERRIDE_SUPP
    OVERRIDE_SUPP -->|"yes"| OVERRIDE_LOOKUP
    OVERRIDE_LOOKUP -->|"suppress"| OVERRIDE_RESOLVE --> SUPPRESSED
    OVERRIDE_LOOKUP -->|"no suppress"| GOVERNOR
    OVERRIDE_SUPP -->|"no"| GOVERNOR
    GOVERNOR --> TIER
    TIER -->|"DEDUPLICATED"| TIER_CACHED
    TIER -->|"deterministic"| TIER_DETR
    TIER -->|"LLM available"| TIER_LLM
    TIER_CACHED --> VERDICT
    TIER_DETR --> VERDICT
    TIER_LLM --> VERDICT
    VERDICT --> PERSIST
    PERSIST --> NEEDS_REVIEW
    NEEDS_REVIEW -->|"yes"| TASK
    NEEDS_REVIEW -->|"no"| COMPLETED
    TASK --> COMPLETED
    COMPLETED -->|"yes (auto-closed)"| AUTO_CLOSE
    COMPLETED -->|"no"| INV_GATE
    AUTO_CLOSE -->|"yes"| FP_TAG --> SUPPRESSED
    AUTO_CLOSE -->|"no"| TRIAGED
    INV_GATE -->|"no"| TRIAGED
    INV_GATE -->|"yes"| SET_INV --> ESCALATE --> PROMOTE --> INVESTIGATING

    style TOP fill:#475569,color:#fff
    style BC_SUPP fill:#2563eb,color:#fff
    style MEM_RESOLVE fill:#2563eb,color:#fff
    style OVERRIDE_RESOLVE fill:#2563eb,color:#fff
    style TIER_CACHED fill:#2563eb,color:#fff
    style TIER_DETR fill:#2563eb,color:#fff
    style TIER_LLM fill:#2563eb,color:#fff
    style TASK fill:#d97706,color:#fff
    style FP_TAG fill:#2563eb,color:#fff
    style SUPPRESSED fill:#059669,color:#fff
    style TRIAGED fill:#059669,color:#fff
    style INVESTIGATING fill:#059669,color:#fff
```

</div>

---

### ۲.۳ تحقیق و ارتقا به Case

*   **جستجوی Case موجود با شباهت عنوان وجود ندارد.**
*   **پنجره ۴۸ ساعته فقط برای لینک کردن هم‌خانواده‌هاست.**
*   **آستانه شواهد برای ready_for_jira در کد ≥۸۰ کاراکتر است.**
*   **کد تا ۱۲ تسک پویا تولید می‌کند.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef stage    fill:#059669,stroke:#047857,stroke-width:2px,color:#fff

    START["Triaged alert<br/>funnel_stage=TRIAGED"]:::stage
    PROMOTE_CHECK{"should_promote<br/>(case_promoter.promote_to_case)"}:::decision
    NO_PROMOTE["Returns None<br/>stays in triaged"]:::absent
    POOL{"get_pool() available?"}:::decision
    NO_POOL["Returns None<br/>fail-soft"]:::absent
    EXISTING_CASE{"alert.case_id exists?"}:::decision
    RETURN_EXISTING["Returns existing case_id<br/>no new write"]:::auto
    FUSION_CASE{"fusion_incident_id &amp;<br/>case_id linked?"}:::decision
    REUSE_FUSION["Reuse case linked by Fusion"]:::auto
    ENTITIES["campaign_entities(alert, raw)<br/>host/IP/user clusters"]:::auto
    THEME["infer_attack_theme<br/>title + mitre_tactics + mitre_techniques"]:::auto
    TITLE["campaign_case_title<br/>theme + entities → Case title"]:::auto
    DESCRIPTION["Build description (max 8000 chars)"]:::auto
    TASKS["_build_tasks(state, alert)<br/>up to 12 investigation checklist rows"]:::auto
    CREATE_CASE["INSERT aisoc_cases<br/>created_by='SYSTEM'"]:::auto
    CREATE_TASKS["INSERT aisoc_case_tasks"]:::auto
    CREATE_COMMENT["INSERT aisoc_case_comments"]:::auto
    LINK_CASE["UPDATE alerts<br/>SET case_id = :cid, funnel_stage = cased"]:::auto
    FIND_SIBLINGS["Find family alerts<br/>48-hour lookback"]:::auto
    LINK_SIBLINGS["Link family alerts → same case_id"]:::auto
    TAG["Tag alert<br/>tags += agentic-promoted, reportable"]:::auto
    READY_CHECK{"passes_ready_for_jira_stage"}:::decision
    READY_EVIDENCE["Evidence threshold (any one):<br/>• severity high/critical<br/>• findings text ≥80 chars<br/>• medium + conf ≥0.70 + mitre_techniques"]:::auto
    SET_CASED["funnel_stage = cased"]:::stage
    SET_READY["funnel_stage = ready_for_jira"]:::stage

    START --> PROMOTE_CHECK
    PROMOTE_CHECK -->|"no"| NO_PROMOTE
    PROMOTE_CHECK -->|"yes"| POOL
    POOL -->|"no"| NO_POOL
    POOL -->|"yes"| EXISTING_CASE
    EXISTING_CASE -->|"yes"| RETURN_EXISTING
    EXISTING_CASE -->|"no"| FUSION_CASE
    FUSION_CASE -->|"reuse"| REUSE_FUSION
    FUSION_CASE -->|"no case in Fusion"| ENTITIES --> THEME --> TITLE --> DESCRIPTION --> TASKS
    REUSE_FUSION -.-> CREATE_CASE
    CREATE_CASE --> CREATE_TASKS --> CREATE_COMMENT
    CREATE_CASE --> LINK_CASE
    LINK_CASE --> FIND_SIBLINGS --> LINK_SIBLINGS --> TAG
    TAG --> READY_CHECK
    READY_CHECK -->|"no"| SET_CASED
    READY_CHECK -->|"yes"| READY_EVIDENCE --> SET_READY

    style START fill:#059669,color:#fff
    style NO_PROMOTE fill:#7f1d1d,color:#fff
    style NO_POOL fill:#7f1d1d,color:#fff
    style RETURN_EXISTING fill:#2563eb,color:#fff
    style REUSE_FUSION fill:#2563eb,color:#fff
    style SET_CASED fill:#059669,color:#fff
    style SET_READY fill:#059669,color:#fff
```

</div>

---

### ۲.۴ اجرای پلی‌بوک و دروازه‌های تایید

*   **محافظ SSRF کامل است.**
*   **رفتار دروازه به `AISOC_PLAYBOOK_RESUME` بستگی دارد.**
*   **Resume از `next_step_index` ادامه می‌یابد.**
*   **جدول `playbook_approvals` فقط طرح‌واره است.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef human    fill:#d97706,stroke:#b45309,stroke-width:3px,color:#fff
    classDef gate     fill:#b45309,stroke:#78350f,stroke-width:2px,color:#fff

    TRIGGER["POST agents /api/v1/playbooks/id/run"]:::auto
    LOAD["Load playbook definition"]:::auto
    CREATE_RUN["INSERT playbook_runs<br/>status='running'"]:::infra
    STEP_LOOP{"step_index &lt; step_count?"}:::decision
    NO_MORE["status='completed'<br/>return step_results"]:::auto
    STEP["Current step"]:::auto
    CONDITIONAL{"has_condition?"}:::decision
    COND_FALSE["Skip step"]:::auto
    COND_TRUE["Continue"]:::auto
    APPROVAL_LEVEL{"approval_level?"}:::decision
    APPROVAL_NONE["none → run directly"]:::auto
    APPROVAL_MANDATORY["mandatory"]:::gate
    APPROVAL_CRITICAL["critical"]:::gate
    PLAYBOOK_RESUME{"AISOC_PLAYBOOK_RESUME?"}:::decision
    RESUME_ON["Create approval_gate task<br/>playbook_runs: status='pending_approval'<br/>→ paused until resume"]:::human
    RESUME_OFF["Step blocked<br/>no task created, no resume possible"]:::absent
    APPROVAL_DONE{"resume called?"}:::decision
    APPROVE["Continue from next_step_index"]:::auto
    REJECT["Cancel run<br/>status='cancelled'"]:::auto
    SSRF{"http/notify step?<br/>validate_outbound_url"}:::decision
    SSRF_FAIL["SSRFError → step failed"]:::absent
    SSRF_PASS["Safe → continue"]:::auto
    EXEC_MODE{"Execution mode?<br/>dry_run / real"}:::decision
    EXEC_REAL["Real handler"]:::auto
    EXEC_SIM["Simulated result"]:::auto
    RECORD_RESULT["step_results[id] recorded<br/>step_index++"]:::infra

    TRIGGER --> LOAD --> CREATE_RUN --> STEP_LOOP
    STEP_LOOP -->|"yes"| STEP --> CONDITIONAL
    CONDITIONAL -->|"no"| COND_FALSE --> RECORD_RESULT
    CONDITIONAL -->|"yes"| APPROVAL_LEVEL
    APPROVAL_LEVEL -->|"none"| APPROVAL_NONE --> SSRF
    APPROVAL_LEVEL -->|"mandatory/critical"| PLAYBOOK_RESUME
    PLAYBOOK_RESUME -->|"on"| RESUME_ON --> APPROVAL_DONE
    APPROVAL_DONE -->|"approve"| APPROVE --> SSRF
    APPROVE --> RECORD_RESULT
    APPROVAL_DONE -->|"reject"| REJECT --> NO_MORE
    PLAYBOOK_RESUME -->|"off"| RESUME_OFF
    SSRF -->|"blocked"| SSRF_FAIL --> RECORD_RESULT
    SSRF -->|"pass"| EXEC_MODE
    EXEC_MODE -->|"real"| EXEC_REAL --> RECORD_RESULT
    EXEC_MODE -->|"simulated"| EXEC_SIM --> RECORD_RESULT
    RECORD_RESULT --> STEP_LOOP
    STEP_LOOP -->|"no"| NO_MORE

    style TRIGGER fill:#2563eb,color:#fff
    style RESUME_ON fill:#d97706,color:#fff
    style REJECT fill:#d97706,color:#fff
    style SSRF_FAIL fill:#7f1d1d,color:#fff
    style RESUME_OFF fill:#7f1d1d,color:#fff
    style NO_MORE fill:#059669,color:#fff
```

</div>

---

### ۲.۵ یکپارچه‌سازی Jira و چرخه حیات تیکت

*   **همگام‌سازی دوره‌ای وجود ندارد.**
*   **ارسال خروجی ترتیبی است، نه موازی.**
*   **وب‌هوک ورودی تنها نویسنده دفتر ثبت ITSM است.**
*   **مراجع خارجی در `case_external_refs` هستند.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef ledger   fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef stage    fill:#059669,stroke:#047857,stroke-width:2px,color:#fff

    subgraph OUTBOUND["Outbound delivery (optional, via connector)"]
        direction TB
        TRIGGER_PUSH["POST /api/v1/soc/funnel/push-itsm"]:::auto
        JIRA_GATE{"passes_jira_gate"}:::decision
        GATE_BLOCKED["Return results as skipped"]:::absent
        SERIALIZE["_serialize_case_for_push"]:::auto
        ENRICH_REPORT["_enrich_case_description_with_report"]:::auto
        FOR_EACH["For each connector (sequential)"]:::auto
        PUSH_OK["2xx → upsert case_external_refs"]:::auto
        PUSH_FAIL["Error → FanoutResult(status=error)"]:::absent
        ANY_OK{"At least one successful send?"}:::decision
        STAGE_BUMP["UPDATE alerts SET funnel_stage = 'jira_pushed'"]:::auto
        NO_STAGE["No stage change"]:::absent
        RETURN["Return ticket_refs"]:::auto

        TRIGGER_PUSH --> JIRA_GATE
        JIRA_GATE -->|"blocked"| GATE_BLOCKED
        JIRA_GATE -->|"passed"| SERIALIZE --> ENRICH_REPORT --> FOR_EACH
        FOR_EACH --> PUSH_OK
        FOR_EACH --> PUSH_FAIL
        PUSH_OK --> ANY_OK
        PUSH_FAIL --> ANY_OK
        ANY_OK -->|"yes"| STAGE_BUMP
        ANY_OK -->|"no"| NO_STAGE
        STAGE_BUMP --> RETURN
        NO_STAGE --> RETURN
    end

    subgraph INBOUND["Inbound webhook (the only ITSM ledger writer)"]
        direction TB
        WEBHOOK["POST /api/v1/inbox/itsm/"]:::auto
        AUTH{"Authentication"}:::decision
        TOKEN["Resolve tenant_token"]:::auto
        CONNECTOR["Resolve connector_instance_id"]:::auto
        HMAC{"hmac_secret configured?"}:::decision
        HMAC_OK["Verify X-AiSOC-Signature"]:::auto
        PARSE{"Parse payload"}:::decision
        PARSE_JIRA["Jira: issue.key + status.name"]:::auto
        PARSE_SNOW["ServiceNow: sys_id + state"]:::auto
        PARSE_FAIL["Malformed → 200, status_changed=False"]:::absent
        LOOKUP_REF{"case_external_refs"}:::decision
        NO_REF["No linked Case"]:::absent
        MAP_STATUS{"Inbound mapping → AiSOC status"}:::decision
        MAP_JIRA["_JIRA_INBOUND_STATUS"]:::auto
        MAP_SNOW["_SNOW_INBOUND_STATUS"]:::auto
        NO_MAP["Not mapped → only last_synced_at"]:::absent
        SAME_STATUS{"new status == current?"}:::decision
        BUMP_ONLY["UPDATE case_external_refs"]:::auto
        APPLY["_apply_status_to_case (one transaction)"]:::auto
        LEDGER_WRITE["emit_itsm_status_change<br/>runbook_events row"]:::ledger
        RETURN_INBOUND["Return InboundResult"]:::auto

        WEBHOOK --> AUTH
        AUTH --> TOKEN --> CONNECTOR
        AUTH --> HMAC -->|"yes"| HMAC_OK --> PARSE
        HMAC -->|"no"| PARSE
        PARSE -->|"jira"| PARSE_JIRA
        PARSE -->|"servicenow"| PARSE_SNOW
        PARSE -->|"malformed"| PARSE_FAIL
        PARSE_JIRA --> LOOKUP_REF
        PARSE_SNOW --> LOOKUP_REF
        PARSE_FAIL --> RETURN_INBOUND
        LOOKUP_REF -->|"no reference"| NO_REF --> RETURN_INBOUND
        LOOKUP_REF -->|"found"| MAP_STATUS
        MAP_STATUS -->|"jira"| MAP_JIRA
        MAP_STATUS -->|"servicenow"| MAP_SNOW
        MAP_JIRA --> SAME_STATUS
        MAP_SNOW --> SAME_STATUS
        SAME_STATUS -->|"yes"| BUMP_ONLY --> RETURN_INBOUND
        SAME_STATUS -->|"no"| APPLY --> LEDGER_WRITE --> RETURN_INBOUND
        NO_MAP -.-> BUMP_ONLY
    end

    style TRIGGER_PUSH fill:#2563eb,color:#fff
    style GATE_BLOCKED fill:#7f1d1d,color:#fff
    style PUSH_FAIL fill:#7f1d1d,color:#fff
    style NO_STAGE fill:#7f1d1d,color:#fff
    style PARSE_FAIL fill:#7f1d1d,color:#fff
    style NO_REF fill:#7f1d1d,color:#fff
    style NO_MAP fill:#7f1d1d,color:#fff
    style STAGE_BUMP fill:#059669,color:#fff
    style LEDGER_WRITE fill:#7c3aed,color:#fff
```

</div>

---

### ۲.۶ معماری پایگاه داده و ذخیره‌سازی

*   جدول `triage_ledger` و `case_findings` وجود ندارند. جدول اصلی `runbook_events` است.
*   `playbook_approvals` فقط طرح‌واره است.
*   Neo4j توسط Fusion نوشته نمی‌شود.

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart LR
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef postgres fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef kafka    fill:#d97706,stroke:#b45309,stroke-width:2px,color:#fff
    classDef redis    fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef clickhouse fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef neo4j    fill:#1d4ed8,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef qdrant   fill:#0d9488,stroke:#0f766e,stroke-width:2px,color:#fff
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3

    subgraph PG["PostgreSQL (primary)"]
        direction TB
        ALERTS[("alerts<br/>id, tenant_id, title, description,<br/>severity, status, priority,<br/>mitre_tactics, mitre_techniques, iocs,<br/>entities, raw_event, dedup_hash,<br/>confidence, confidence_label,<br/>confidence_rationale, narrative,<br/>anomaly_score, event_time, first_seen,<br/>last_seen, created_at, updated_at,<br/>ai_recommendations, tags,<br/>enrichment_data, affected_ips,<br/>affected_users, affected_assets,<br/>child_alert_ids, is_merged,<br/>connector_id, connector_type,<br/>source_event_ids, ocsf_class_uid,<br/>rule_id, rule_name, affected_hosts,<br/>llm_payload, funnel_stage,<br/>automation_rules_evaluated_at,<br/>case_id, disposition, ai_summary, ai_score")]:::postgres
        CASES[("aisoc_cases<br/>id, tenant_id, case_number, title,<br/>description, severity, status,<br/>assignee, tags, mitre_techniques,<br/>mitre_tactics, created_by,<br/>created_at, updated_at,<br/>triaged_at, resolved_at, closed_at,<br/>observable_graph, evidence_chain,<br/>case_type, external_ticket_url,<br/>external_ticket_id, external_status")]:::postgres
        CASE_TASKS[("aisoc_case_tasks<br/>id, case_id, title, description,<br/>status, order_index,<br/>created_at, completed_at,<br/>completed_by, notes")]:::postgres
        RUNBOOK_EVENTS[("runbook_events<br/>id, tenant_id, subject_type,<br/>subject_id, seq, occurred_at,<br/>stage, kind, action_name,<br/>actor_type, actor_id, actor_label,<br/>summary, detail, status, policy,<br/>approval_id, run_id, input, output,<br/>cost, error, duration_ms,<br/>audit_log_id, idempotency_key,<br/>created_at<br/>— append-only")]:::postgres
        RUNBOOK_TASKS[("runbook_tasks<br/>id, tenant_id, alert_id, task_type,<br/>title, description, status,<br/>created_by, created_at,<br/>assigned_to, assigned_at,<br/>completed_at, completed_by,<br/>resolution, feedback_applied,<br/>resume_applied, playbook_run_id,<br/>signature, gate_id")]:::postgres
        PLAYBOOK_RUNS[("playbook_runs<br/>id, playbook_id, tenant_id,<br/>status, trigger, trigger_meta,<br/>started_at, completed_at,<br/>step_index, next_step_index,<br/>gate_step_id, gate_step_name,<br/>error, summary, created_by,<br/>approval_decision, approved_by,<br/>rejected_by")]:::postgres
        PLAYBOOK_STEP_RESULTS[("playbook_step_results<br/>id, run_id, step_id, step_index,<br/>status, output, error,<br/>duration_ms, created_at")]:::postgres
        PLAYBOOK_APPROVALS[("playbook_approvals<br/>— schema only (migration 072)<br/>no writer, no reader")]:::absent
        CASE_EXTERNAL_REFS[("case_external_refs<br/>id, case_id, connector_instance_id,<br/>vendor, external_id, external_url,<br/>external_status, pushed_by,<br/>last_synced_at, created_at, updated_at")]:::postgres
        TENANT_INBOX_TOKENS[("tenant_inbox_tokens<br/>id, tenant_id, token, template_id,<br/>hmac_secret, last_used_at,<br/>created_at, revoked_at")]:::postgres
        AUTOMATION_RULES[("automation_rules<br/>id, tenant_id, rule_name,<br/>rule_type, trigger_type,<br/>condition, action, action_type,<br/>action_config, autonomy_level,<br/>dry_run, description,<br/>required_connector_type,<br/>created_at, updated_at,<br/>enabled, installed_from_pack")]:::postgres
        CONNECTORS[("connectors<br/>id, tenant_id, name, connector_type,<br/>connector_config, auth_config,<br/>is_enabled, poll_interval_seconds,<br/>last_poll_at, next_poll_at,<br/>fusion_persist_failed,<br/>created_at, updated_at")]:::postgres
        USERS[("users<br/>id, tenant_id, email, name,<br/>role, created_at, updated_at")]:::postgres
        AUDIT_LOG[("audit_log<br/>id, tenant_id, actor_type, actor_id,<br/>action, resource_type, resource_id,<br/>before, after, occurred_at,<br/>source_ip, user_agent")]:::postgres
    end

    subgraph KAFKA["Kafka (Redpanda-compatible)"]
        TOPIC1[("raw_events")]:::kafka
        TOPIC2[("aisoc.alerts.fused")]:::kafka
        TOPIC3[("aisoc.runbook.task_updates")]:::kafka
        TOPIC4[("ueba.anomalies")]:::kafka
        DLQ[("aisoc.alerts.fused.dlq")]:::kafka
    end

    subgraph REDIS["Redis"]
        R1[("aisoc:fusion:correlation:*")]:::redis
        R2[("aisoc:fusion:incident:*")]:::redis
        R3[("ueba:anom:*")]:::redis
        R4[("cost_governor:*")]:::redis
        R5[("memory:*")]:::redis
    end

    subgraph CLICKHOUSE["ClickHouse (event lake)"]
        CH1[("aisoc.raw_events")]:::clickhouse
        CH2[("aisoc.alert_metrics")]:::clickhouse
        CH3[("aisoc.ioc_enrichments")]:::clickhouse
    end

    subgraph NEO4J["Neo4j (entity graph)"]
        NG[("User / Asset / Process / IP / Domain /<br/>Alert nodes")]:::neo4j
    end

    subgraph QDRANT["Qdrant (vector store)"]
        QD[("IOC embeddings + actor profiles")]:::qdrant
    end

    style PG fill:#e1f5ff
    style KAFKA fill:#fff3e0
    style REDIS fill:#f3e5f5
    style CLICKHOUSE fill:#e0f2f1
    style NEO4J fill:#fff9c4
    style QDRANT fill:#ffccbc
```

</div>

---

### ۲.۷ لایه‌های جداسازی مستاجر (Tenant Isolation)

*   **"پارتیشن‌بندی Kafka با tenant_id" دقیق نیست.**
*   **جداسازی دریاچه ClickHouse یک لایه هفتم است.**
*   **کلیدهای Redis ساده‌سازی شده‌اند.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff

    REQUEST["API request<br/>GET /alerts"]:::auto
    LAYER1["Layer 1: JWT<br/>token must carry tenant_id claim"]:::auto
    LAYER2["Layer 2: Postgres RLS<br/>SET app.current_tenant_id"]:::auto
    LAYER3["Layer 3: WHERE in query layer<br/>every query filters explicitly<br/>WHERE tenant_id = :tid"]:::auto
    LAYER4["Layer 4: Kafka<br/>X-Tenant-ID header<br/>downstream filtering"]:::auto
    LAYER5["Layer 5: Neo4j<br/>tenant_id node property"]:::auto
    LAYER6["Layer 6: Redis<br/>per-tenant key prefix"]:::auto
    CLICKHOUSE["Layer 7 (bonus): ClickHouse lake<br/>rewrite_for_tenant()<br/>tenant_id injected into every SELECT"]:::auto
    RESPONSE["Response<br/>only data for the current tenant"]:::auto
    AUDIT["Audit trail<br/>audit_log"]:::absent

    REQUEST --> LAYER1 --> LAYER2 --> LAYER3 --> LAYER4
    LAYER3 --> LAYER5
    LAYER3 --> LAYER6
    LAYER3 --> CLICKHOUSE
    LAYER4 --> RESPONSE
    LAYER5 --> RESPONSE
    LAYER6 --> RESPONSE
    CLICKHOUSE --> RESPONSE
    RESPONSE --> AUDIT

    style REQUEST fill:#e1f5ff
    style RESPONSE fill:#c8e6c9
    style AUDIT fill:#7f1d1d
```

</div>

---

### ۲.۸ یکپارچه‌سازی UEBA

*   **"UEBA Boost: 1.15×" اشتباه است.** افزایشی و وابسته به ریسک است.
*   **آستانه Z-score > 1.5σ اشتباه است.** آستانه ترکیبی RSS برابر `anomaly_threshold` (پیش‌فرض ۳.۰).
*   **UEBA در Fusion اختیاری است.**
*   **سرویس UEBA مستقل است.**

<div style="background:#f1f5f9; padding:16px; border-radius:8px;">

```mermaid
%%{init: {"theme": "default", "htmlLabels": false, "themeVariables": {"background": "#f1f5f9", "fontFamily": "Consolas, 'Courier New', monospace", "fontSize": "15px", "clusterBkg": "#e2e8f0", "clusterBorder": "#94a3b8", "edgeLabelBackground": "#ffffff"}, "flowchart": {"htmlLabels": false, "useMaxWidth": true, "padding": 24, "nodeSpacing": 40, "rankSpacing": 56, "wrappingWidth": 600, "curve": "basis"}}}%%
flowchart TD
    classDef auto     fill:#2563eb,stroke:#1e40af,stroke-width:2px,color:#fff
    classDef infra    fill:#475569,stroke:#334155,stroke-width:2px,color:#fff,stroke-dasharray:4 4
    classDef absent   fill:#7f1d1d,stroke:#b91c1c,stroke-width:2px,color:#fff,stroke-dasharray:6 3
    classDef decision fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff
    classDef boost    fill:#7c3aed,stroke:#5b21b6,stroke-width:2px,color:#fff
    classDef narr     fill:#059669,stroke:#047857,stroke-width:2px,color:#fff

    subgraph UEBA_SERVICE["services/ueba (standalone service)"]
        direction TB
        CONSUMER["UEBAKafkaConsumer<br/>subscribed to security.events"]:::auto
        SCORER["ScoringService.score_event<br/>1. BaselineService.score_features<br/>2. _composite_score (RSS)<br/>3. PeerGroupService.deviation_score<br/>4. if composite &lt; anomaly_threshold → None<br/>5. ELSE → CREATE UEBAAnomaly<br/>6. publish to ueba.anomalies"]:::auto
        BASELINE_TABLE[("EntityBaseline")]:::infra
        ANOMALY_TABLE[("UEBAAnomaly")]:::infra
        CONSUMER --> SCORER
        SCORER --> BASELINE_TABLE
        SCORER --> ANOMALY_TABLE
        SCORER --> |"(publish)"| TOPIC_UEBA[("Kafka ueba.anomalies")]:::infra
    end

    subgraph FUSION_CONSUMER["services/fusion (optional)"]
        direction TB
        CACHE_SUB["UebaSignalCache subscribed to<br/>ueba.anomalies → record()"]:::auto
        REDIS_CACHE[("Redis: ueba:anom:*")]:::infra
        FUSION_ENGINE["FusionEngine.process<br/>(only if _ueba_cache is not None)"]:::auto
        BOOST["apply_ueba_boost<br/>→ ConfidenceFactor<br/>→ if risk critical/high/medium:<br/>  boost = _RISK_BOOST[risk]"]:::boost
        NO_UEBA{"_ueba_cache is None?"}:::decision
        NO_UEBA_RESULT["No UEBA boost<br/>no-op"]:::absent
        CACHE_SUB --> REDIS_CACHE
        REDIS_CACHE --> FUSION_ENGINE
        FUSION_ENGINE --> NO_UEBA
        NO_UEBA -->|"yes"| NO_UEBA_RESULT
        NO_UEBA -->|"no"| BOOST
    end

    style UEBA_SERVICE fill:#e1f5ff
    style FUSION_CONSUMER fill:#f3e5f5
    style TOPIC_UEBA fill:#fff3e0
    style REDIS_CACHE fill:#f3e5f5
    style NO_UEBA_RESULT fill:#7f1d1d
```

</div>

---

## بخش ۳ — ماتریس "بدون نوشتن" (No-Write Matrix)

| نقطه در چرخه حیات | چرا ردیفی نیست | مرجع کد |
|---|---|---|
| دریافت خام، ادغام، ساخت هشدار | Ingest مسیر داغ (hot path) است؛ sink ادغام فقط در `alerts` می‌نویسد. | `services/fusion/app/services/alert_sink.py` |
| Claim هشدار توسط ارزیاب قوانین | Claim یک عملیات DB روی `alerts` است. نوشتن‌های دفتر ثبت *پس از* claim رخ می‌دهند. | `services/api/app/workers/rule_evaluator.py` |
| نتیجه تریاژ خودکار | متعلق به `investigation_events` است؛ Runbook آن را بازمی‌خواند تا کپی نکند. | `services/agents/app/investigator/ledger.py` |
| بستن خودکار / کاهش FP | یک تگ روی ردیف هشدار (`false_positive`). | `services/agents/app/workers/case_promoter.py` |
| سرکوب زمینه تجاری | `disposition=benign`، `funnel_stage=suppressed` را تنظیم می‌کند. | `services/agents/app/workers/case_promoter.py` |
| انتقال‌های مرحله فانل | `alerts.funnel_stage` منبع حقیقت است. | `services/api/app/services/funnel_stages.py` |
| ارتقا به Case توسط ایجنت (`case_promoter`) | `aisoc_cases` / تسک‌ها / کامنت‌ها را می‌نویسد، بدون نویسنده Runbook. | `services/agents/app/workers/case_promoter.py` |
| ساخت Case از طریق `POST /api/v1/cases` | هیچ emitter در آن مسیر فراخوانی نمی‌شود. | `services/api/app/api/v1/endpoints/cases.py` |
| ساخت Case توسط لینک حادثه Fusion | از Case موجود استفاده مجدد می‌کند. | `services/agents/app/workers/case_promoter.py` |
| تکمیل تسک Runbook (هر نوع) | در `runbook_tasks` نوشته می‌شود. | `services/api/app/api/v1/endpoints/runbook.py` |
| ارسال خروجی Jira / ServiceNow | دفتر ثبت پاسخ فروشنده را ثبت می‌کند، نه درخواست ما را. | `services/api/app/services/case_fanout.py` |
| عملیات انبوه فانل | در سطح مستاجر → `audit_log`، نه `runbook_events`. | `services/api/app/services/agentic_funnel.py` |
| اجرای گام پلی‌بوک | در `playbook_step_results` و `playbook_runs` ذخیره می‌شود. | `services/agents/app/playbook/engine.py` |
| تکمیل / لغو پلی‌بوک | در `playbook_runs.status` ذخیره می‌شود. | `services/agents/app/playbook/engine.py` |
| تایید/رد انسان در دروازه پلی‌بوک | در `runbook_tasks.resolution` + `resume_applied` ذخیره می‌شود. | `services/api/app/api/v1/endpoints/runbook.py` |
| سرکوب حافظه / سرکوب override | `investigation_runs` + `investigation_events` را می‌نویسد، اما بدون `runbook_events`. | `services/agents/app/workers/fused_alert_consumer.py` |
| همگام‌سازی دوره‌ای وضعیت Jira/ServiceNow | وجود ندارد — وضعیت فقط از طریق وب‌هوک وارد می‌شود. | (تایید شده که غایب است) |
| جستجوی Case با شباهت عنوان | وجود ندارد — فقط `case_id` و لینک حادثه بررسی می‌شود. | `services/agents/app/workers/case_promoter.py` |
| نوشتن در جدول `playbook_approvals` | فقط طرح‌واره. بدون نویسنده، بدون خواننده. | `services/agents/app/models/playbook_approval.py` |
| نوشتن هشدار در Neo4j از Fusion | Neo4j توسط نویسنده گراف جداگانه در زمان Ingest نوشته می‌شود. | `services/fusion/app/services/alert_sink.py` |

---

## ضمیمه — تایید شده بر اساس

- `services/fusion/app/services/fusion_engine.py`
- `services/fusion/app/services/alert_sink.py`
- `services/fusion/app/services/confidence.py`
- `services/fusion/app/services/vuln_boost.py`
- `services/fusion/app/services/ueba_signal.py`
- `services/fusion/app/services/alert_enricher.py`
- `services/fusion/app/services/correlator.py`
- `services/fusion/app/services/narrative.py`
- `services/agents/app/workers/fused_alert_consumer.py`
- `services/agents/app/funnel/stages.py`
- `services/agents/app/workers/case_promoter.py`
- `services/agents/app/investigator/ledger.py`
- `services/agents/app/playbook/engine.py`
- `services/agents/app/playbook/ssrf_guard.py`
- `services/agents/app/playbook/approvals.py`
- `services/agents/app/playbook/resume.py`
- `services/api/app/workers/rule_evaluator.py`
- `services/api/app/services/runbook/rule_executor.py`
- `services/api/app/services/runbook/recorder.py`
- `services/api/app/services/runbook/emitters.py`
- `services/api/app/services/funnel_stages.py`
- `services/api/app/services/case_fanout.py`
- `services/api/app/api/v1/endpoints/inbox_itsm.py`
- `services/api/app/db/rls.py`
- `services/api/app/services/lake_sql.py`
- `services/ueba/app/services/scoring.py`
- `services/ueba/app/services/baseline.py`
- `services/ueba/app/services/kafka_consumer.py`
- `services/ueba/app/core/config.py`
- Migrations: 062, 064, 065, 066, 067, 068, 069, 070, 072, 073.