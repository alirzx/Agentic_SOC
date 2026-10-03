# Soorin Agentic SOC — الزامات داده‌ای مرحله Triage

## سند جامع فنی بر اساس داده‌های واقعی Splunk

---

## ۱) هدف سند

این سند مشخص می‌کند:

- حداقل و حداکثر اطلاعاتی که باید از Splunk دریافت شود تا **Triage Agent** بتواند کار خود را انجام دهد.
- مرز دقیق بین Triage و Investigation.
- چه اطلاعاتی زاید است و باید حذف شود.
- شکاف‌های موجود در پیاده‌سازی فعلی Splunk و راه‌حل حداقلی.
- تنظیمات Splunk که باید اصلاح شوند.

---

## ۲) مرز Triage و Investigation

طبق داکیومنت Soorin (بخش ۱۱.۱ و ۱۲)، مرز مسئولیت‌ها این است:

| نیاز | Triage Agent | Investigation Agent |
|---|---|---|
| Classification و Severity | ✅ | |
| Analytic Story و MITRE (از rule) | ✅ | |
| Host / User درگیر (نام سطح بالا) | ✅ | |
| Asset Criticality (تخمینی) | ✅ | |
| User Privilege (فقط boolean) | ✅ | |
| تصمیم به Investigation | ✅ | |
| Command Line / Process Tree | | ✅ |
| Network Correlation (src_ip/dest_ip) | | ✅ |
| تاریخچه Alert روی همان host | | ✅ |
| Baseline رفتاری | | ✅ |
| بررسی Auth Logs | | ✅ |
| Lateral Movement | | ✅ |
| Correlation با Alertهای خواهر | | ✅ |
| بازسازی Attack Chain | | ✅ |
| Enrichment عمیق TI | | ✅ |

**اصل حاکم:** Triage تصمیم می‌گیرد «آیا Investigation ارزش دارد؟» — خودِ مسئله را حل نمی‌کند. تحمیل وظایف Investigation به Triage، هم MVP را پیچیده می‌کند و هم با فازبندی اسپرینت‌های داکیومنت Soorin همخوان نیست.

---

## ۳) حداقل مطلق برای عبور از Normalization

چهار فیلد اجباری که Splunk ES برای Notable Event تعریف کرده:

| فیلد | توضیح |
|---|---|
| `signature` | نوع alert (مثلاً "Brute Force Detected") |
| `src` | موجودیتی که alert برای آن رخ داده (host, user, IP) |
| `vendor_severity` | شدت از دید vendor اصلی |
| `severity_id` | شدت نرمال‌شده به عدد ۱ تا ۶ |

این چهار فیلد **شرط لازم** برای ورود به pipeline هستند، اما **شرط کافی برای Triage نیستند**. با این چهار فیلد، Triage فقط می‌تواند یک برچسب اولیه بزند.

---

## ۴) حداقل معنادار برای Triage

Triage Agent طبق داکیومنت Soorin باید این کارها را انجام دهد:

- Alert classification
- Severity estimation
- False-positive likelihood
- Asset criticality awareness
- User privilege awareness
- Initial hypothesis

برای این کارها، به فیلدهای زیر نیاز دارید:

### الف) هویت و زمینه رخداد (Base & Entity Context)

| دسته | فیلدهای کلیدی | کاربرد در Triage |
|---|---|---|
| زمان | `_time`, `info_min_time`, `info_max_time` | تشخیص بازه حمله |
| منبع داده | `sourcetype`, `source`, `host` | شناسایی نوع telemetry |
| موجودیت مقصد | `dest`, `dest_ip` | شناسایی هدف |
| کاربر | `user`, `src_user` | بررسی privilege |

### ب) متادیتای قانون تشخیص (Detection Rule Metadata)

| فیلد | چرا مهم است؟ |
|---|---|
| `rule_id` | شناسایی منطق تشخیص |
| `rule_name` | زمینه‌سازی برای LLM |
| `rule_description` | کمک به classification |
| `security_domain` | مسیردهی به Agent مناسب |
| `analytic_story` | **حیاتی** — بخشی از چه سناریویی است |
| `mitre_technique_id` | افزایش دقت Triage |
| `risk_score` | ورودی deterministic برای Risk Engine |

فیلد `analytic_story` به Triage Agent می‌گوید این alert **تنها یک رخداد نیست، بلکه بخشی از یک سناریوی بزرگ‌تر** است.

### ج) فیلدهای اختصاصی Notable Events در Splunk ES

```text
event_id, event_hash, host, risk_object, risk_object_type, risk_score,
rule_description, rule_id, rule_name, search_name, source, splunk_server, urgency
```

مستندات Splunk صریحاً می‌گوید Notable Eventها باید شامل `risk_object`, `event_id`, `info_min_time`, `info_max_time` باشند.

---

## ۵) حداکثر اطلاعات مفید

داکیومنت Soorin بخش ۷۹:

> «۱۰۰۰۰ رویداد خام نباید مستقیماً وارد LLM شود. اول aggregation، filter، top results و statistics.»

### مواردی که باید بفرستید:
- خلاصه آماری: تعداد رویدادها، بازه زمانی، منابع یکتا
- Top entities: ۵ source IP برتر، ۳ user درگیر
- فیلدهای CIM نرمال‌شده (نه raw log)
- متادیتای Analytic Story
- زمینه asset/user (criticality, privilege) از enrichment

### مواردی که **نباید** بفرستید:
- کل raw log
- تمام ۱۰۰۰+ رویداد خام
- فیلدهای تکراری یا بی‌ربط
- داده‌های tenant دیگر
- secrets, tokens

---

## ۶) نگاشت فیلدهای Splunk به AgentContext

| نیاز Triage Agent | فیلد(های) Splunk |
|---|---|
| `alert.title` | `rule_name` یا `signature` |
| `alert.description` | `rule_description` |
| `alert.severity` | `urgency` یا `severity_id` |
| `alert.source` | `sourcetype`, `source`, `splunk_server` |
| `alert.time` | `_time`, `info_min_time`, `info_max_time` |
| `entities.dest` | `dest`, `dest_ip` |
| `entities.user` | `user`, `src_user` |
| `detection.rule_id` | `rule_id` |
| `detection.analytic_story` | `analytic_story` |
| `detection.mitre` | `mitre_technique_id` |
| `risk.object` | `risk_object`, `risk_object_type` |
| `risk.score` | `risk_score` |

---

## ۷) تحلیل داده واقعی — Alert نمونه از Splunk

### الف) آنچه Analytic Story `Windows Audit Policy Tampering` فراهم می‌کند

| فیلد | مقدار | کاربرد در Triage |
|---|---|---|
| `analytic_story` | Windows Audit Policy Tampering | ✅ حیاتی — hypothesis اولیه |
| `mitre_attack` | T1562.001, T1562.002, T1547.014 | ✅ نگاشت تکنیک |
| `kill_chain` | Exploitation, Installation | ✅ مرحله حمله |
| `nist` | DE.CM, DE.AE | ✅ انطباق |
| `cis20` | CIS 10 | ✅ انطباق |
| `references` | Solorigate, Prometei | ✅ زمینه |
| ۱۱ Correlation Search خواهر | شامل همین Alert | ✅ **ارزش Correlation** |

**نکته استراتژیک:** Analytic Story به Triage Agent می‌گوید این Alert **تنها یک رخداد نیست، بلکه بخشی از یک سناریوی ۱۱-Rule است**.

### ب) آنچه Correlation Search فراهم می‌کند

- Detection ID: `1bf500e5-1226-41d9-af5d-ed1f577929f2`
- Security domain: **Endpoint**
- Output type: **Finding**
- Severity: Medium
- Risk score: **60**
- Risk entity: `dest`
- Risk message: `Important audit policy "$SubCategory$" of category "$Category$" was disabled on $dest$`
- ۲ Drill-down Search (results و risk events 7 روز)

### ج) شکاف بحرانی در SPL

SPL فعلی:

```spl
| stats min(_time) as _time values(host) as dest 
        by AuditPolicyChanges SubcategoryGuid, process_id
```

**مشکل:** چون `stats ... by` دارد، فیلدهای زیر در Finding **زنده نمی‌مانند**:

| فیلد | آیا می‌ماند؟ |
|---|---|
| `user` / `src_user` | ❌ گم می‌شود |
| `src_user_role` | ❌ گم می‌شود |
| `process_name` (`auditpol.exe`) | ❌ گم می‌شود |
| `command_line` | ❌ گم می‌شود |
| `src_ip` | ❌ گم می‌شود |

**نتیجه:** Triage می‌داند **کدام host** تغییر کرده، ولی نمی‌داند **چه کسی**. با اینکه Extractionها در Splunk ES تعریف شده‌اند، SPL آن‌ها را دور می‌ریزد.

### د) فیلدهای زاید در Alert فعلی

حدود **۶۰٪ اطلاعات تکراری یا بی‌ارزش**:

| فیلد زاید | چرا |
|---|---|
| `raw data` در بخش Notable | تکرار Description |
| `external_id`, `source_event_id`, `source_guid`, `Source Ref`, `finding.uid` | همه یک مقدار |
| `device`, `metadata`, `connector` | تکراری |
| `category uid`, `class uid`, `class name`, `activity id` | ECS بی‌ارزش |
| تکرار `tenant uid` و `severity` | ۳ بار |
| `raw_event` تودرتو | تکرار سطح بالا |

### ه) مشکلات ساختاری Alert

| مشکل | راه‌حل |
|---|---|
| `Description` یک **String JSON** است | پارس و ذخیره در ستون‌های جدا |
| باگ Confidence: `1900%` به‌جای `19%` | رفع ضرب اشتباه در ۱۰۰ |
| سه زمان مختلف بدون برچسب | `eventTime`, `ingestTime`, `alertTime` |
| `src_ip: null` | استخراج از raw_event |

---

## ۸) اصلاح حداقلی SPL (فقط دو فیلد)

```spl
| eval user=coalesce(SubjectUserName, user),
       subject_is_admin=if(match(SubjectUserName, "(?i)admin|administrator"), "true", "false")
| stats min(_time) as _time 
        values(host) as dest
        values(user) as user
        values(subject_is_admin) as subject_is_admin
        values(EventCode) as event_code
        by AuditPolicyChanges SubcategoryGuid, process_id
```

فقط **دو فیلد** اضافه شد: `user` و `subject_is_admin`. همین برای Triage کافی است — بدون اینکه Command Line، Process Tree و Network Info که وظیفه Investigation است، به Triage تحمیل شوند.

---

## ۹) تنظیمات Splunk که باید اصلاح شوند

| تنظیم | فعلی | پیشنهاد |
|---|---|---|
| Status | Off | On |
| Schedule | `0 * * * *` | متناسب با حجم (`*/15 * * * *`) |
| Earliest | `-15y@year` | `-1h` |
| Latest | `-6y@year` | `now` |
| Throttling window | 0 | 15 minutes |
| Throttling group-by | خالی | `dest`, `AuditPolicyChanges`, `SubcategoryGuid` |
| Adaptive response | خالی | Webhook به Agentic SOC |

بازه `-15y` تا `-6y` غیرمنطقی است و باعث duplicate alerts و مصرف منابع می‌شود.

---

## ۱۰) Schema پیشنهادی NormalizedAlert

```json
{
  "alertId": "uuid",
  "tenantId": "uuid",
  
  "title": "ESCU - Windows Important Audit Policy Disabled - Rule",
  "description": "The following analytic detects...",
  "severity": "medium",
  "severityId": 3,
  "status": "new",
  "riskScore": 60,
  
  "eventTime": "2026-09-29T07:26:41Z",
  "ingestTime": "2026-09-29T10:35:27Z",
  
  "source": {
    "vendor": "splunk",
    "searchName": "ESCU - Windows Important Audit Policy Disabled - Rule",
    "sourceRef": "f71c8f2e-..."
  },
  
  "detection": {
    "detectionId": "1bf500e5-1226-41d9-af5d-ed1f577929f2",
    "securityDomain": "endpoint",
    "mitreTechniqueIds": ["T1562.001"],
    "eventCode": 4719
  },
  
  "analyticStory": {
    "name": "Windows Audit Policy Tampering",
    "killChain": ["Exploitation"],
    "nist": ["DE.CM"],
    "cis20": ["CIS 10"]
  },
  
  "entities": {
    "host": "IT40",
    "user": null,
    "subjectIsAdmin": null
  },
  
  "risk": {
    "object": "IT40",
    "objectType": "system",
    "score": 60,
    "message": "Important audit policy was disabled on IT40"
  },
  
  "auditPolicy": {
    "changes": "Success removed",
    "category": "Logon/Logoff",
    "subCategory": "Logon"
  }
}
```

---

## ۱۱) Analytic Story به عنوان Entity مستقل

در Agentic SOC، Analytic Story باید به‌عنوان یک **Entity مستقل** مدل شود. این اجازه می‌دهد:

- **Correlation Agent** بتواند Alertهای خواهر را در همان Story پیدا کند — بدون query اضافی.
- **Investigation Agent** بداند این Alert بخشی از یک سناریوی بزرگ‌تر است.
- **Risk Engine** بتواند Multi-Stage بودن حمله را در نظر بگیرد.
- **Report Agent** بتواند Attack Story را از پیش ساخته پیدا کند.

این مدل‌سازی، هزینه query را کاهش می‌دهد و دقت Correlation را بالا می‌برد.

---

## ۱۲) جمع‌بندی سه سطحی

| سطح | فیلدها | کاربرد |
|---|---|---|
| **حداقل مطلق** | `signature`, `src`, `vendor_severity`, `severity_id` | عبور از Normalization |
| **حداقل معنادار** | + `_time`, `user`, `rule_id`, `rule_name`, `analytic_story`, `security_domain` | ساخت hypothesis و classification |
| **حداکثر مفید** | + `mitre_technique_id`, `risk_object`, `risk_score`, `dest_ip`, `subject_is_admin`, `urgency` | Triage دقیق و Evidence-backed |
| **نباید بفرستید** | raw log، ۱۰۰۰+ رویداد خام، command line، process tree، network correlation، secrets | جلوگیری از Token explosion و نشت داده |

---

## ۱۳) چک‌لیست پیاده‌سازی

### اولویت اول — اصلاح SPL
- [ ] افزودن `user` و `subject_is_admin` به `stats by`
- [ ] حفظ `EventCode` برای تأیید

### اولویت دوم — اصلاح تنظیمات Splunk
- [ ] فعال‌سازی Detection (Status = On)
- [ ] اصلاح Schedule و بازه زمانی (`-1h` تا `now`)
- [ ] تنظیم Throttling روی `dest`, `AuditPolicyChanges`, `SubcategoryGuid`
- [ ] افزودن Adaptive Response webhook به Agentic SOC

### اولویت سوم — در سمت Agentic SOC
- [ ] ساخت Schema استاندارد `NormalizedAlert`
- [ ] حذف فیلدهای زاید قبل از ذخیره
- [ ] پارس کردن `Description` از String JSON
- [ ] تعریف hypothesis template برای هر Analytic Story
- [ ] مدل‌سازی Analytic Story به عنوان Entity مستقل
- [ ] اتصال Asset Criticality از Asset Inventory

---

## ۱۴) نتیجه نهایی

Triage Agent برای این نوع Alert **فقط به دو چیز اضافه** نیاز دارد:

1. **Asset Criticality** (از Asset Inventory، نه Splunk)
2. **boolean admin بودن کاربر** (از lookup ساده SPL)

تمام اطلاعات دیگر — command line، process tree، network correlation، تاریخچه، baseline و بازسازی attack chain — **وظیفه Investigation Agent** است، نه Triage.

**اصل حاکم:**

```text
Triage تصمیم می‌گیرد
Investigation حل می‌کند
Correlation می‌بیند
Risk می‌سنجد
Human تأیید می‌کند
```

اگر این ساختار پیاده شود، Triage Agent هم **دقیق** خواهد بود و هم **قابل Audit و Replay**، چون هر تصمیمش به فیلدهای مشخصی از Splunk متصل است.