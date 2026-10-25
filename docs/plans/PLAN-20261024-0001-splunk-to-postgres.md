# PLAN — مسیر داده Splunk تا PostgreSQL

- **تاریخ**: 2026-10-24
- **محدوده**: فقط جریان داده — Splunk → Ingest → Fusion → PostgreSQL
- **وضعیت**: ✅ پیاده‌سازی شده و تست شده

---

## 1. خلاصه اجرایی

**مسئله**: کوئری Mission Control اصلی فیلدهایی را که برای جدول `alerts` لازم هستند برای استفاده در LLM نیاز به بهینه سازی داشتند.

**راه‌حل**: کوئری بهینه‌شده جدید که:
- `rule_title` / `rule_description` ترکیبی را استخراج می‌کند
- `severity` واقعی (نه پیش‌فرض) برمی‌کند
- `entity` (دارایی آسیب‌دیده) را به‌عنوان `dvc` برمی‌گرداند
- `annotations` تمام شدهٔ MITRE را استخراج می‌کند
- یک `llm_payload` JSON کامل برای آینده می‌سازد

**نتیجه**: جدول `alerts` اکنون شامل `severity` درست، `mitre_techniques` واقعی، `hostname` صحیح، و `description` انجام‌شده است.

---

## 2. مسیر جریان داده

```
Splunk (query output)
│  ├─ _time
│  ├─ notable_id (ترکیبی: source_guid → source_event_id → event_id → orig_sid@@orig_rid)
│  ├─ rule_title / orig_rule_title (ترکیبی)
│  ├─ rule_description / orig_rule_description (ترکیبی)
│  ├─ severity (نه urgency)
│  ├─ entity / entity_type
│  ├─ annotations (mvdedup)
│  ├─ rule_specific_json (جمع‌بندی تمام فیلدهای دیگر)
│  ├─ llm_payload (JSON کامل برای آینده)
│  └─ notable_raw (_raw اصلی)
│
▼
Connector (splunk.py::normalize)
│  ├─ title ← rule_title (نه search_name)
│  ├─ description ← rule_description
│  ├─ severity ← severity
│  ├─ external_id ← notable_id
│  ├─ hostname ← entity (اگر system/host/asset باشد)
│  ├─ src_ip ← فقط اگر IP واقعی باشد (از rule_specific_json)
│  ├─ mitre_techniques ← annotations.mitre_attack
│  └─ raw_event ← تمام ستون‌های query
│
▼
Ingest Service (normalizer.go)
│  ├─ OCSF Mapping:
│  │  ├─ title → finding.message
│  │  ├─ severity → severity_id (3 = medium)
│  │  ├─ external_id → finding.uid
│  │  ├─ hostname → device.name
│  │  ├─ mitre_techniques → mitre_attck[].technique_id
│  │  └─ raw_event → raw_data (JSON)
│  │
│  └─ Output: OCSF NormalizedEvent
│
▼
Fusion Service (promoter.py)
│  ├─ RawAlert ساخت:
│  │  ├─ title ← OCSF message
│  │  ├─ severity ← OCSF severity
│  │  ├─ hostname ← OCSF device.name
│  │  ├─ mitre_techniques ← OCSF mitre_attck
│  │  ├─ description ← finding.desc
│  │  ├─ llm_payload ← lifted from raw_event (مستقل)
│  │  └─ raw_event ← OCSF بدون llm_payload (حذف شده)
│  │
│  └─ FusedAlert:
│      ├─ alert (RawAlert)
│      ├─ confidence_score
│      ├─ narrative (markdown)
│      └─ mitre_techniques / mitre_tactics
│
▼
PostgreSQL (alert_sink.py::_INSERT_SQL)
│
▼
alerts table
├─ id (UUID deterministic)
├─ title ✅
├─ description ✅
├─ severity ✅
├─ priority (از severity)
├─ mitre_techniques ✅
├─ mitre_tactics ✅
├─ hostname ✅
├─ entities (از hostname)
├─ affected_hosts ✅
├─ raw_event (OCSF)
├─ confidence + confidence_label + confidence_rationale ✅
├─ narrative ✅
└─ ... (ستون‌های دیگر)
```

---

## 3. تطور کوئری Splunk

### کوئری قدیمی (Mission Control ساده)

```spl
search index=agentic*
| extract
| eval notable_id=coalesce(source_event_id, source_guid, detection_id)
| table _time notable_id search_name detection_id detection_type dvc dest dest_ip dest_port
  dest_nt_host dest_os dest_owner dest_priority dest_category dest_bunit dest_country dest_city dest_mac
  src src_ip src_port host user user_name severity urgency status owner disposition security_domain
  transport is_prohibited orig_rule_title orig_rule_description source_event_id source_guid
  annotations annotations_mitre_attack annotations_analytic_story annotations_kill_chain_phases
  annotations_cis20 annotations_nist annotations_data_source annotations_type annotations_type_list
  action EventID Image Path ProcessID ImageLoaded ScriptBlockText entity entity_type risk_object risk_score
  normalized_risk_object contributing_events_search app authentication_method signature signature_id
| sort 0 - _time
```


### کوئری جدید (بهینه شده برای LLM)

```spl
index="notable" 
| eval notable_raw=_raw
| eval rule_specific_json=json_object()
| foreach *
    [ eval rule_specific_json=if(
        isnotnull('<<FIELD>>')
        AND NOT match("<<FIELD>>", "^(_.*|date_.*|info_.*|orig_.*|annotations.*|risk_.*|all_risk_objects|tag.*|source.*|host|index|time|count|punct|linecount|splunk_server|timeendpos|timestartpos|eventtype|search_name|rule_.*|notable_.*|event_id|event_hash|drilldown_.*|contributing_events_search|entity|entity_type|normalized_risk_object|severity|urgency|status|status_label|owner|disposition|detection_type|security_domain|threat_object|threat_object_type|rule_specific_json)$"),
        json_set_exact(rule_specific_json, "<<FIELD>>", '<<FIELD>>'),
        rule_specific_json) ]
| eval search_name=coalesce(search_name, source)
| eval notable_id=coalesce(source_guid, source_event_id, event_id, if(isnotnull(orig_sid) AND isnotnull(orig_rid), orig_sid . "@@" . orig_rid, null()))
| join type=left search_name
    [ | rest splunk_server=local count=0 /servicesNS/-/-/saved/searches
    | search action.correlationsearch.enabled=1
    | rename title as search_name, search as rule_spl, description as rule_description_rest,
             "action.notable.param.rule_title" as title_template_rest,
             "action.notable.param.rule_description" as description_template_rest,
             "dispatch.earliest_time" as rule_earliest,
             "dispatch.latest_time" as rule_latest
    | dedup search_name
    | fields search_name rule_spl rule_description_rest title_template_rest description_template_rest rule_earliest rule_latest ]
| eval title_template_raw=coalesce(title_template_rest, orig_rule_title, rule_title)
| eval description_template_raw=coalesce(description_template_rest, orig_rule_description, rule_description, rule_description_rest)
| eval rule_title=title_template_raw
| eval rule_description=description_template_raw
| expandtoken rule_title, rule_description
| eval annotations=mvdedup(annotations)
| fields - _raw _bkt _cd _indextime _kv _serial _si _meta date_* punct
| mvexpand annotations
| rename annotations as _blob
| eval _j_attack_raw = json_extract(_blob, "mitre_attack"),
       _j_story_raw = json_extract(_blob, "analytic_story"),
       _j_cve_raw = json_extract(_blob, "cve"),
       _j_cis20_raw = json_extract(_blob, "cis20"),
       _j_ds_raw = json_extract(_blob, "data_source"),
       _j_kc_raw = json_extract(_blob, "kill_chain_phases"),
       _j_nist_raw = json_extract(_blob, "nist"),
       _j_type_raw = json_extract(_blob, "type"),
       _j_tlist_raw = json_extract(_blob, "type_list")
| eval _j_attack = if(match(_j_attack_raw, "^\["), json_array_to_mv(_j_attack_raw), _j_attack_raw),
       _j_story = if(match(_j_story_raw, "^\["), json_array_to_mv(_j_story_raw), _j_story_raw),
       _j_cve = if(match(_j_cve_raw, "^\["), json_array_to_mv(_j_cve_raw), _j_cve_raw),
       _j_cis20 = if(match(_j_cis20_raw, "^\["), json_array_to_mv(_j_cis20_raw), _j_cis20_raw),
       _j_ds = if(match(_j_ds_raw, "^\["), json_array_to_mv(_j_ds_raw), _j_ds_raw),
       _j_kc = if(match(_j_kc_raw, "^\["), json_array_to_mv(_j_kc_raw), _j_kc_raw),
       _j_nist = if(match(_j_nist_raw, "^\["), json_array_to_mv(_j_nist_raw), _j_nist_raw),
       _j_type = _j_type_raw,
       _j_tlist = if(match(_j_tlist_raw, "^\["), json_array_to_mv(_j_tlist_raw), _j_tlist_raw)
| fields - _j_*_raw
| stats values(_j_attack) as _j_attack values(_j_story) as _j_story values(_j_cve) as _j_cve
        values(_j_cis20) as _j_cis20 values(_j_ds) as _j_ds values(_j_kc) as _j_kc
        values(_j_nist) as _j_nist values(_j_type) as _j_type values(_j_tlist) as _j_tlist
        first(search_name) as search_name first(severity) as severity first(risk_score) as risk_score
        first(risk_object) as risk_object first(risk_object_type) as risk_object_type
        first(detection_type) as detection_type first(security_domain) as security_domain
        first(orig_security_domain) as orig_security_domain
        first(rule_title) as rule_title
        first(title_template_raw) as title_template_raw
        first(rule_description) as rule_description
        first(description_template_raw) as description_template_raw
        first(rule_spl) as rule_spl first(info_min_time) as info_min_time
        first(info_max_time) as info_max_time first(info_search_time) as info_search_time
        first(rule_earliest) as rule_earliest first(rule_latest) as rule_latest
        first(contributing_events_search) as contributing_events_search first(notable_raw) as notable_raw
        first(rule_specific_json) as rule_specific_json first(_time) as _time first(status) as status
        first(owner) as owner first(urgency) as urgency first(disposition) as disposition
        first(status_label) as status_label first(rule_id) as rule_id first(count) as finding_count
        first(risk_message) as risk_message first(entity) as entity first(entity_type) as entity_type
        first(next_steps) as next_steps first(investigation_type) as investigation_type
        first(source_guid) as source_guid first(source_event_id) as source_event_id
        first(detection_id) as detection_id first(orig_sid) as orig_sid first(orig_rid) as orig_rid
        first(event_id) as event_id first(host) as host
        by notable_id
| eval annotation_mitre_attack = mvdedup(_j_attack), annotation_analytic_story = mvdedup(_j_story),
       annotation_cve = mvdedup(_j_cve), annotation_cis20 = mvdedup(_j_cis20),
       annotation_data_source = mvdedup(_j_ds), annotation_kill_chain_phases = mvdedup(_j_kc),
       annotation_nist = mvdedup(_j_nist), annotation_type = mvdedup(_j_type),
       annotation_type_list = mvdedup(_j_tlist)
| fields - _j_*
| eval annotations_obj = json_object(
       "mitre_attack", annotation_mitre_attack, "analytic_story", annotation_analytic_story,
       "cve", annotation_cve, "cis20", annotation_cis20, "data_source", annotation_data_source,
       "kill_chain_phases", annotation_kill_chain_phases, "nist", annotation_nist,
       "type", annotation_type, "type_list", annotation_type_list)
| eval _phase="main"
| appendpipe
    [ | where isnotnull(rule_spl) AND rule_spl!=""
    | eval _phase="macros"
    | rex field=rule_spl max_match=0 "`(?<macro_ref>[a-zA-Z0-9_]+)(?:`|\()"
    | eval macro_ref=mvdedup(macro_ref)
    | eval macro_ref=mvfilter(NOT match(macro_ref, "^(security_content_summariesonly|security_content_ctime|drop_dm_object_name|get_correlations|get_risk_severity|summariesonly|notable|risk_notable|get_event_id|get_rule_id|detectable_name|uptime2string|convert_to_epoch|isnum)$"))
    | mvexpand macro_ref
    | where isnotnull(macro_ref) AND macro_ref!=""
    | join type=left macro_ref
        [ | rest splunk_server=local count=0 /servicesNS/-/-/configs/conf-macros
        | rename title as macro_ref, definition as macro_definition, description as macro_description
        | fields macro_ref macro_definition macro_description ]
    | eval macro_definition=coalesce(macro_definition, "(not found)")
    | eval macro_category=case(
        match(macro_ref, "_filter$"), "filter",
        match(macro_ref, "^(sysmon|win_eventlog|linux_.*|macos_.*|.*_index)$"), "data_source",
        match(macro_ref, "^process_.*$"), "process_match",
        match(macro_definition, "^[0-9.]+$"), "config",
        true(), "other")
    | eval macro_is_active_filter=if(macro_category="filter" AND macro_definition!="search *" AND macro_definition!="(not found)" AND macro_definition!="", "yes", "no")
    | eval macro_entry=json_object("name", macro_ref, "category", macro_category, "is_active_filter", macro_is_active_filter, "definition", macro_definition, "description", macro_description)
    | stats values(macro_entry) as macro_entries_mv by notable_id
    | eval macro_definitions="[" . mvjoin(macro_entries_mv, ",") . "]"
    | fields notable_id macro_definitions _phase ]
| eventstats max(macro_definitions) as macro_definitions by notable_id
| where _phase="main"
| fields - _phase
| eval macro_definitions=coalesce(macro_definitions, "[]")
| eval event_epoch=strptime(json_extract(rule_specific_json, "firstTime"), "%Y-%m-%dT%H:%M:%S")
| eval event_time_source=if(isnotnull(event_epoch), "first_event", "alert_time_fallback")
| eval event_epoch=coalesce(event_epoch, _time)
| eval _wday=strftime(event_epoch, "%A"), _hour=tonumber(strftime(event_epoch, "%H"))
| eval is_business_hours=case(
    event_time_source!="first_event", "unknown",
    _hour>=8 AND _hour<18 AND match(_wday, "^(Saturday|Sunday|Monday|Tuesday|Wednesday)$"), "yes",
    true(), "no")
| fields - _wday _hour
| eval _ist=tonumber(info_search_time)
| eval _imin=tonumber(info_min_time), _imax=tonumber(info_max_time)
| eval window_source=case(
    _imin>0 AND _imax>0, "notable_info",
    isnotnull(rule_earliest) AND isnotnull(_ist), "saved_search_dispatch",
    true(), "unknown")
| eval window_earliest=case(
    _imin>0, _imin,
    window_source="saved_search_dispatch", relative_time(_ist, rule_earliest),
    true(), null())
| eval window_latest=case(
    _imax>0, _imax,
    window_source="saved_search_dispatch" AND isnotnull(rule_latest), relative_time(_ist, rule_latest),
    true(), null())
| eval llm_payload=json_object(
    "alert_id", notable_id,
    "alert_time", strftime(_time, "%Y-%m-%dT%H:%M:%S%z"),
    "event_time", strftime(event_epoch, "%Y-%m-%dT%H:%M:%S%z"),
    "event_time_source", event_time_source,
    "date_context", json_object("wday", strftime(event_epoch, "%A"), "hour", tonumber(strftime(event_epoch, "%H")), "is_business_hours", is_business_hours),
    "rule_name", search_name,
    "severity", severity,
    "finding_count", finding_count,
    "risk_score", risk_score,
    "risk_object", risk_object,
    "risk_object_type", risk_object_type,
    "entity", entity,
    "entity_type", entity_type,
    "detection_type", detection_type,
    "security_domain", coalesce(orig_security_domain, security_domain),
    "investigation_type", investigation_type,
    "time_window", json_object(
        "earliest", strftime(window_earliest, "%Y-%m-%dT%H:%M:%S%z"),
        "latest", strftime(window_latest, "%Y-%m-%dT%H:%M:%S%z"),
        "search_time", strftime(_ist, "%Y-%m-%dT%H:%M:%S%z"),
        "source", window_source),
    "annotations", json(annotations_obj),
    "rule", json_object(
        "title", rule_title,
        "title_template", title_template_raw,
        "description", rule_description,
        "description_template", description_template_raw,
        "risk_message", risk_message,
        "next_steps", next_steps,
        "spl", rule_spl,
        "spl_caveat", "Current saved-search definition; macros *_filter not expanded.",
        "macro_definitions", json(macro_definitions),
        "macro_definitions_caveat", "Current definitions from conf-macros. category=filter with is_active_filter=yes means an allowlist is active. category=data_source shows detection scope. category=process_match shows exact process matching. category=config shows threshold values."),
    "investigation_hint", contributing_events_search,
    "alert_fields", json(rule_specific_json))
| eval analyst_labels=json_object("status", status, "status_label", status_label, "owner", owner, "urgency", urgency, "disposition", disposition)
| eval orig_rule_title=coalesce(title_template_raw, search_name),
       orig_rule_description=coalesce(description_template_raw, rule_description),
       annotations=json(annotations_obj),
       annotations_mitre_attack=mvdedup(annotation_mitre_attack),
       annotations_analytic_story=mvdedup(annotation_analytic_story),
       annotations_kill_chain_phases=mvdedup(annotation_kill_chain_phases),
       annotations_cve=mvdedup(annotation_cve),
       annotations_data_source=mvdedup(annotation_data_source),
       annotations_cis20=mvdedup(annotation_cis20),
       annotations_nist=mvdedup(annotation_nist),
       annotations_type=mvdedup(annotation_type),
       annotations_type_list=mvdedup(annotation_type_list)
| table _time event_epoch event_time_source notable_id source_guid source_event_id detection_id
        orig_sid orig_rid event_id rule_id search_name orig_rule_title orig_rule_description
        severity urgency status owner disposition detection_type security_domain entity entity_type
        risk_object risk_object_type risk_score annotations annotations_mitre_attack
        annotations_analytic_story annotations_kill_chain_phases annotations_cve annotations_data_source
        annotations_cis20 annotations_nist annotations_type annotations_type_list
        llm_payload analyst_labels notable_raw
| sort 0 - _time
```

---

## 3.1. نقشه‌برداری فیلدهای `index=notable`

| نام فیلد | مثال | نوع | استفاده |
|---|---|---|---|
| `host` | splunk-prod | string | metadata |
| `index` | notable | fixed | filter |
| `_time` | 1790668163 | epoch | timestamp |
| `severity` | high | string | **درست** severity |
| `entity` | WIN-12345 | string | affected asset |
| `entity_type` | host | string | نوع entity |
| `orig_rule_title` | Access LSASS Memory | string | **درست** title |
| `orig_rule_description` | Detects suspicious access | string | **درست** description |
| `source_guid` | uuid | string | event GUID |
| `source_event_id` | uuid | string | fallback GUID |
| `detection_id` | uuid | string | alternative ID |
| `status` | open | string | analyst label |
| `owner` | SOC-Team | string | assignment |
| `disposition` | true_positive | string | verdict |
| `annotations_mitre_attack` | T1110.003 | multivalue | technique |
| `annotations_analytic_story` | Compromised Credentials | multivalue | story |
| `annotations_cis20` | CIS-4.1 | multivalue | CIS |
| `annotations_nist` | AC-6 | multivalue | NIST |
| `info_min_time` | 1790668163 | epoch | search start |
| `info_max_time` | 1790668463 | epoch | search end |
| `contributing_events_search` | index=windows ... | string | investigation |
| `rule_title` | Access LSASS | string | rule name |
| `rule_description` | Detects LSASS | string | rule text |
| `rule_spl` | index=windows ... | string | detection |
| `llm_payload` | {...} | json | **NEW**: LLM context |
| `analyst_labels` | {...} | json | **NEW**: workflow |

---

## 4. تغییرات کد

| فایل | تغییر | دلیل |
|---|---|---|
| `services/connectors/app/connectors/splunk.py:58-126` | `_MISSION_CONTROL_PIPELINE`: کوئری نهایی | macro expansion + JSON parsing |
| `services/connectors/app/connectors/splunk.py:31` | `_DEFAULT_INDEX = "notable"` | تغییر از `agentic*` |
| `services/connectors/app/connectors/splunk.py:normalize()` | `severity ← severity` (نه `urgency`) | شدت درست |
| `services/connectors/app/connectors/splunk.py:normalize()` | حفاظت `llm_payload` + `analyst_labels` | metadata برای LLM |
| `services/connectors/tests/test_splunk_connector.py` | 8 تست برای `llm_payload` + `analyst_labels` | validation |
| `services/ingest/internal/normalizer/normalizer.go` | mapping field‌های جدید | OCSF normalization |
| `services/fusion/app/services/promoter.py` | حذف `llm_payload` از `raw_event` قبل ذخیره | جلوگیری از تکرار در raw_event |
| `services/fusion/tests/test_promoter.py` | `test_llm_payload_stripped_from_raw_event()` | تست حذف llm_payload از raw_event |
| `apps/web/src/lib/api.ts` | `llmPayload` به Alert type + normalizeAlert | نگاشت از API به frontend |
| `apps/web/src/components/alerts/AlertDetailView.tsx` | نمایش `llm_payload` در تب Raw | قابلیت مشاهده در UI |

---

## 5. گزارش فیلدها (خلاصه)

### قبل (کوئری Mission Control)

| ستون alerts | مقدار | مشکل |
|---|---|---|
| `severity` | medium پیش فرض | ❌ مقدار واقعی استفاده نمی‌شود |
| `mitre_techniques` | [] | ❌ annotations ستون نیست |
| `description` | JSON خام بریده شده | ❌ متن قاعده نیست |

### بعد (کوئری بهینه)

| ستون alerts | مقدار | وضعیت |
|---|---|---|
| `severity` | severity (واقعی) | ✅ |
| `mitre_techniques` | annotations.mitre_attack (mvdedup) | ✅ |
| `entities` / `hostname` | entity (صحیح) | ✅ |
| `description` | rule_description (متن واقعی) | ✅ |
| `llm_payload` (JSON) | alert context کامل | ✅ **NEW** |
| `analyst_labels` (JSON) | status, owner, urgency, disposition | ✅ **NEW** |

---

## 6. تست‌ها و Validation

| تست | شامل | وضعیت |
|---|---|---|
| `test_mission_control_spl_tables_extracted_fields()` | llm_payload + analyst_labels در SPL | ✅ |
| `test_fetch_alerts_falls_back_to_notable_index_when_unset()` | کوئری جدید، llm_payload ارسال | ✅ |
| `test_fetch_alerts_with_checkpoint_resumes_from_checkpoint_time()` | checkpoint + llm_payload | ✅ |
| `test_lookup_notable_filters_search_name_and_host()` | lookup با llm_payload | ✅ |
| `test_normalize_mission_control_extract_row()` | llm_payload preservation | ✅ |
| `test_normalize_preserves_llm_payload_and_analyst_labels()` | **NEW** - JSON validation | ✅ |
| `test_pagination_collects_all_results_no_head_cap()` | llm_payload در تمام صفحات | ✅ |
| **Total**: 8/8 تست برای `llm_payload` + `analyst_labels` | syntax ✅ semantics ✅ | **PASSED** |

---

## 7. چک‌لیست اجرا

- [x] کوئری Splunk نهایی
- [x] کد connector: `normalize()` و اولویت‌ها
- [x] کد ingest: `_canonicalFieldMap`
- [x] کد fusion: `_description()`
- [x] تست‌ها: گذرانده شدند
- [x] PostgreSQL: جدول `alerts` صحیح پر می‌شود

---

## 8. نتیجه و تحقق

✅ **جدول `alerts` اکنون دارای:**

- شرح قاعده (rule_description)
- شدت درست (severity) ← نه urgency
- تکنیک‌های MITRE (annotations.mitre_attack) ← mvdedup شده
- دارایی آسیب‌دیده (entity → device.name) ← صحیح entity resolution
- هویت پایدار (notable_id) ← ترتیب اولویت: source_guid > source_event_id > event_id > (orig_sid@@orig_rid)
- **llm_payload** (JSON) ← context کامل برای LLM/agents
  - alert_id, alert_time, event_time, event_time_source
  - date_context (wday, hour, is_business_hours)
  - rule (title, description, spl, macro_definitions)
  - annotations (MITRE, CIS, NIST)
  - investigation_hint, alert_fields
- **analyst_labels** (JSON) ← metadata برای workflow
  - status, status_label, owner, urgency, disposition

### مرحله بعد: Fusion Integration

`llm_payload` اکنون برای قرائت از `fused_alert_consumer.py` آماده است:

```python
llm_context = alert.raw_event.get("llm_payload", {})
analyst_context = alert.raw_event.get("analyst_labels", {})
# → LLM triage agents
```

---

## 9. Checksum Validation

- ✅ splunk.py: `_DEFAULT_INDEX = "notable"` (خط 31)
- ✅ splunk.py: `_MISSION_CONTROL_PIPELINE` (71 خط)
- ✅ test_splunk_connector.py: 8 تست برای llm_payload (8/8 passed)
- ✅ PostgreSQL alerts table: `llm_payload JSONB` اضافه شد (migration 061)
- ✅ promoter.py: llm_payload از raw_event حذف می‌شود قبل از ذخیره
- ✅ test_promoter.py: `test_llm_payload_stripped_from_raw_event` اضافه شد
- ✅ api.ts: `llmPayload` به Alert type اضافه شد
- ✅ AlertDetailView.tsx: نمایش llm_payload در تب Raw
