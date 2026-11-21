#!/usr/bin/env python3
"""
تحلیل: Deduplicated Alerts چه تأثیری بر LLM Calls دارند؟

سناریوهای مختلف:
1. Auto-Triage (fused_alert_consumer)
2. Investigation (deep-dive agent)
3. Narrative Building
4. Cost & Token Usage
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Config
DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://aisoc:aisoc_dev_secret@192.168.220.131:5433/aisoc"
)
DEMO_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


async def main():
    engine = create_async_engine(DB_URL, echo=False, pool_pre_ping=True)
    
    async with AsyncSession(engine) as session:
        print("=" * 90)
        print("تحلیل: Deduplicated Alerts و تأثیر بر LLM")
        print("=" * 90)
        
        since = datetime.now(timezone.utc) - timedelta(hours=3)
        
        # ۱. Cost Governor: Fingerprint Deduplication
        print("\n[۱] Cost Governor - Fingerprint Deduplication:")
        print("   " + "─" * 85)
        
        result = await session.execute(
            text("""
                SELECT 
                    COUNT(*) as total_alerts,
                    COUNT(DISTINCT 
                        CASE WHEN funnel_stage = 'deduplicated' THEN NULL 
                             ELSE md5(title || severity || COALESCE(disposition, '')) 
                        END
                    ) as unique_fingerprints_canonical,
                    COUNT(DISTINCT 
                        md5(title || severity || COALESCE(disposition, ''))
                    ) as total_unique_fingerprints,
                    SUM(CASE WHEN funnel_stage = 'deduplicated' THEN 1 ELSE 0 END) as deduplicated_count
                FROM alerts
                WHERE tenant_id = :tid AND created_at >= :since
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        row = result.fetchone()
        
        print(f"""
   📊 Fingerprint Status:
      • Total Alerts: {row[0]:,}
      • Unique Fingerprints (Canonical Only): {row[1]:,}
      • Total Unique Fingerprints (All): {row[2]:,}
      • Deduplicated Count: {row[3]:,}
      
   💰 Cost Impact:
      ✅ فقط {row[1]:,} alert باید LLM تریج شوند (canonical)
      ❌ بدون cost governor: {row[0]:,} LLM call!
      💵 Savings: {row[0] - row[1]:,} unnecessary LLM calls ≈ ${(row[0] - row[1]) * 0.001:.2f} USD*
         (*فرض: $0.001 per triage call)
        """)
        
        # ۲. Auto-Triage Decision
        print("\n[۲] Auto-Triage Decision Flow:")
        print("   " + "─" * 85)
        
        # Get alerts with their triage status
        triage_result = await session.execute(
            text("""
                SELECT 
                    CASE WHEN funnel_stage = 'deduplicated' THEN 'Deduplicated' ELSE 'Canonical' END as alert_type,
                    COUNT(*) as count,
                    COUNT(CASE WHEN disposition IS NOT NULL THEN 1 END) as with_disposition,
                    COUNT(CASE WHEN disposition IS NULL THEN 1 END) as null_disposition
                FROM alerts
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY alert_type
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        
        triage_data = triage_result.fetchall()
        
        for row in triage_data:
            alert_type = row[0]
            count = row[1]
            with_disp = row[2]
            null_disp = row[3]
            
            print(f"""
   {alert_type}:
      • Count: {count:,}
      • With Disposition: {with_disp:,} ({100*with_disp/count:.1f}%)
      • Null Disposition: {null_disp:,} ({100*null_disp/count:.1f}%)""")
        
        print("""
   
   فلو تریج:
   
   Canonical Alert (e.g., Alert_1):
      1. FusedAlertConsumer checks: cost_governor.check(fingerprint)
      2. Result: Decision.NOT_DEDUPLICATED → use_llm=True
      3. ✅ LLM CALLED → triage_agent.run_auto_triage(state)
      4. verdict='true_positive', confidence=0.85
      5. Persisted to DB
      6. case_promoter.promote_to_case() → creates Case_A
   
   Deduplicated Alert (e.g., Alert_2...10):
      1. FusedAlertConsumer checks: cost_governor.check(fingerprint)
      2. Result: Decision.DEDUPLICATED → use_llm=False
      3. ❌ LLM SKIPPED!
      4. cached_verdict={'verdict': 'true_positive', 'confidence': 0.85} used
      5. Triage costs $0
      6. case_promoter.promote_to_case() → returns None (guard added!)
        """)
        
        # ۳. Investigation Mode
        print("\n[۳] Investigation Mode (Deep-Dive):")
        print("   " + "─" * 85)
        
        # Check for investigation runs
        inv_result = await session.execute(
            text("""
                SELECT 
                    COUNT(*) as total_runs,
                    COUNT(DISTINCT alert_summary) as unique_alerts_investigated,
                    AVG(total_tokens) as avg_tokens_per_run,
                    SUM(total_cost_usd) as total_cost_usd
                FROM investigation_runs
                WHERE tenant_id = :tid 
                  AND started_at >= :since
                  AND status = 'completed'
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        
        inv_data = inv_result.fetchone()
        
        print(f"""
   🔬 Investigation Status:
      • Total Investigation Runs: {inv_data[0] if inv_data and inv_data[0] else 0}
      • Unique Alerts Investigated: {inv_data[1] if inv_data and inv_data[1] else 0}
      • Avg Tokens/Run: {int(inv_data[2]) if inv_data and inv_data[2] else 0}
      • Total Cost: ${inv_data[3] if inv_data and inv_data[3] else 0:.2f}
      
   ⚠️  تأثیر Deduplicated:
      • اگر deduplicated alert باز شود (manually)
      • سیستم تریج را دوباره نمی‌کند
      • از cached disposition استفاده می‌کند
      • هیچ investigation run ایجاد نمی‌شود
      • توضیحات ممکن است generic باشند
        """)
        
        # ۴. Narrative Generation
        print("\n[۴] Narrative Generation:")
        print("   " + "─" * 85)
        
        print("""
   📝 Narrative Flow:
   
   Canonical Alert:
      ✅ Full deterministic narrative generated (no LLM)
      ✅ Evidence bundles linked
      ✅ Custom summary based on verdict + evidence
   
   Deduplicated Alert:
      ⚠️  Same narrative as canonical
      ⚠️  Tags show: ["deduplicated_into:<canonical_id>"]
      ❌ No independent narrative
      ❌ No LLM-generated investigation notes
      💰 Cost saved on narrative generation
        """)
        
        # ۵. Cost Comparison
        print("\n[۵] Cost Comparison - Full Workflow:")
        print("   " + "─" * 85)
        
        canonical_count = sum(row[1] for row in triage_data if row[0] == 'Canonical')
        deduplicated_count = sum(row[1] for row in triage_data if row[0] == 'Deduplicated')
        
        # Estimations
        triage_cost_per_call = 0.001  # $0.001 per LLM call
        investigation_cost = 0.003    # $0.003 per investigation
        tokens_per_triage = 256       # avg tokens
        tokens_per_investigation = 1024
        
        print(f"""
   Scenario: {canonical_count:,} Canonical + {deduplicated_count:,} Deduplicated
   
   WITHOUT Deduplication (process all individually):
      • Triage LLM Calls: {canonical_count + deduplicated_count:,}
      • Cost: ${(canonical_count + deduplicated_count) * triage_cost_per_call:.2f}
      • Tokens: {(canonical_count + deduplicated_count) * tokens_per_triage:,}
      • Cases Created: {canonical_count + deduplicated_count:,} (duplicates!)
      
   WITH Deduplication (canonical only):
      • Triage LLM Calls: {canonical_count:,}
      • Cost: ${canonical_count * triage_cost_per_call:.2f}
      • Tokens: {canonical_count * tokens_per_triage:,}
      • Cases Created: {canonical_count:,} (correct!)
      
   💰 SAVINGS:
      • LLM Calls Eliminated: {deduplicated_count:,}
      • Cost Saved: ${deduplicated_count * triage_cost_per_call:.2f}
      • Tokens Saved: {deduplicated_count * tokens_per_triage:,}
      • Case Duplication Eliminated: {deduplicated_count:,}
        """)
        
        # ۶. سناریوهای خاص
        print("\n[۶] سناریوهای خاص:")
        print("   " + "─" * 85)
        
        print("""
   🔴 Scenario A: User Opens Deduplicated Alert in Console
      ├─ Alert detail loads: disposition is cached ✅
      ├─ Investigation rail loads but NO deep-dive
      ├─ AI Summary: from cached narrative
      └─ Cost: $0 (no new LLM calls)
   
   🟡 Scenario B: Multiple Investigations on Deduplicated
      ├─ User clicks "Investigate" on deduplicated alert
      ├─ Opens investigation panel
      ├─ System could re-run investigation (wastes cost!)
      ├─ Or reuse investigation from canonical
      └─ Cost: Depends on implementation
   
   🟢 Scenario C: Hunt Query Returns Deduplicated Alerts
      ├─ Hunt NL→KQL translation
      ├─ Results include deduplicated alerts
      ├─ Investigation agent processes results
      ├─ No LLM re-triage (cached verdict used)
      └─ Cost: Minimal (no new triage)
        """)
        
        # ۷. Recommendations
        print("\n[۷] توصیه‌ها:")
        print("   " + "─" * 85)
        
        print("""
   ✅ GOOD PRACTICES:
      1. Never re-triage deduplicated alerts
         → Use cached verdict from canonical
         → Cost savings: 100% on triage
      
      2. Link investigation results to canonical
         → If user investigates deduplicated
         → Show canonical's investigation
         → Avoid duplicate investigation cost
      
      3. Share narrative across duplicates
         → One narrative from canonical
         → All losers reference it
         → Narrative generation cost: 1 instead of N
      
      4. Case linking for losers
         → If canonical has case
         → Link all losers to same case
         → No duplicate cases (fixed by guard!)
      
      5. Monitor cost_governor effectiveness
         → Track Decision.DEDUPLICATED rates
         → Calculate actual savings
         → Alert on unusual patterns
   
   ❌ AVOID:
      1. Re-running LLM triage on deduplicated
         → Wastes cost
         → Results are identical anyway
      
      2. Creating separate investigations per duplicate
         → Massive cost multiplication
         → Redundant work
      
      3. Separate cases per duplicate
         → Already fixed with guard!
         → But monitor for regressions
        """)
        
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
