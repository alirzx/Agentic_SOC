#!/usr/bin/env python3
"""Diagnostic script to check why agentic_funnel cases are not being created.

Run this against the live database to diagnose:
1. Alert promotion eligibility
2. Atomic ownership claim status  
3. Case creation success/failure reasons
"""

import asyncio
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import text

TENANT_ID = "00000000-0000-0000-0000-000000000001"
DB_URL = "postgresql+asyncpg://aisoc:aisoc_dev_secret@192.168.220.131:5433/aisoc"


async def check_recent_alerts(db: AsyncSession):
    """Analyze recent alerts for promotion eligibility."""
    print("\n" + "="*80)
    print("1. RECENT ALERTS — Promotion Eligibility Check")
    print("="*80 + "\n")
    
    result = await db.execute(text("""
        SELECT 
            id,
            title,
            disposition,
            severity,
            confidence,
            correlation_owner,
            correlation_state,
            case_id,
            funnel_stage,
            created_at
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= now() - interval '4 hours'
        ORDER BY created_at DESC
        LIMIT 30
    """).bindparams(tid=TENANT_ID))
    
    rows = result.fetchall()
    print(f"Total alerts in last 4 hours: {len(rows)}\n")
    
    if not rows:
        print("⚠️  No alerts found. Check if connector is polling.")
        return
    
    # Analyze each alert
    eligible_for_promotion = []
    owned_by_legacy = []
    owned_by_graph = []
    already_cased = []
    disposition_blocks = []
    
    for row in rows[:10]:  # Show first 10
        alert_id = row[0]
        disposition = row[2]
        severity = row[3]
        confidence = row[4]
        correlation_owner = row[5]
        correlation_state = row[6]
        case_id = row[7]
        
        # Check promotion criteria
        auto_closeable = disposition in {'false_positive', 'benign', 'benign_true_positive'}
        is_tp_or_escalate = disposition in {'true_positive', 'likely_tp', 'escalate', 'needs_review'}
        sev_ok = severity in {'high', 'critical'} or (severity == 'medium' and confidence >= 0.70)
        can_promote = is_tp_or_escalate and (not auto_closeable) and sev_ok
        
        print(f"Alert: {str(alert_id)[:8]}... | {row[1][:40]}")
        print(f"  Disposition: {disposition} | Severity: {severity} | Confidence: {confidence:.2f}")
        print(f"  Promotion eligible: {'✅ YES' if can_promote else '❌ NO'}")
        print(f"  Reason: {_explain_promotion(disposition, severity, confidence, auto_closeable, is_tp_or_escalate, sev_ok)}")
        print(f"  Owner: {correlation_owner} | State: {correlation_state} | Cased: {case_id is not None}")
        print()
        
        if can_promote:
            eligible_for_promotion.append(alert_id)
        
        if correlation_owner == 'legacy':
            owned_by_legacy.append(alert_id)
        elif correlation_owner == 'graph_engine':
            owned_by_graph.append(alert_id)
        
        if case_id:
            already_cased.append(alert_id)
        
        if auto_closeable:
            disposition_blocks.append(alert_id)
    
    # Summary
    print(f"\n📊 SUMMARY (last 10 alerts):")
    print(f"  Eligible for promotion: {len(eligible_for_promotion)}")
    print(f"  Owned by legacy: {len(owned_by_legacy)}")
    print(f"  Owned by graph_engine: {len(owned_by_graph)}")
    print(f"  Already cased: {len(already_cased)}")
    print(f"  Disposition blocks: {len(disposition_blocks)}")
    
    return eligible_for_promotion


def _explain_promotion(disposition, severity, confidence, auto_closeable, is_tp_or_escalate, sev_ok):
    """Explain why alert can or cannot promote."""
    if auto_closeable:
        return f"AUTO_CLOSEABLE disposition ({disposition})"
    if not is_tp_or_escalate:
        return f"Disposition ({disposition}) not in promotion list"
    if not sev_ok:
        return f"Severity gate failed: {severity} + confidence {confidence:.2f} < 0.70"
    return "✅ All criteria met"


async def check_case_creation_status(db: AsyncSession):
    """Check which Caseهای agentic_funnel آند ایجاد شدند."""
    print("\n" + "="*80)
    print("2. CASE CREATION STATUS by creation_method")
    print("="*80 + "\n")
    
    result = await db.execute(text("""
        SELECT 
            creation_method,
            COUNT(*) as case_count,
            MIN(opened_at) as oldest,
            MAX(opened_at) as newest
        FROM aisoc_cases
        WHERE tenant_id = CAST(:tid AS uuid)
          AND opened_at >= now() - interval '24 hours'
        GROUP BY creation_method
        ORDER BY case_count DESC
    """).bindparams(tid=TENANT_ID))
    
    rows = result.fetchall()
    if not rows:
        print("⚠️  No cases created in last 24 hours.")
        return
    
    for row in rows:
        method = row[0] or 'NULL'
        count = row[1]
        oldest = row[2]
        newest = row[3]
        print(f"{method:20} | Count: {count:3d} | Oldest: {oldest} | Newest: {newest}")
    
    # Specific query for agentic_funnel
    result = await db.execute(text("""
        SELECT id, title, created_by, opened_at, array_length(alert_ids, 1) as alert_count
        FROM aisoc_cases
        WHERE tenant_id = CAST(:tid AS uuid)
          AND creation_method = 'agentic_funnel'
          AND opened_at >= now() - interval '24 hours'
        ORDER BY opened_at DESC
        LIMIT 5
    """).bindparams(tid=TENANT_ID))
    
    agentic_rows = result.fetchall()
    print(f"\n✅ Recent agentic_funnel Cases ({len(agentic_rows)}):")
    for row in agentic_rows:
        print(f"  {row[1][:50]} | {row[3]} | {row[4]} alerts")


async def check_ownership_distribution(db: AsyncSession):
    """Check alerts by correlation_owner and correlation_state."""
    print("\n" + "="*80)
    print("3. ALERT OWNERSHIP & CORRELATION STATE Distribution")
    print("="*80 + "\n")
    
    result = await db.execute(text("""
        SELECT 
            COALESCE(correlation_owner, 'NULL') as owner,
            COALESCE(correlation_state, 'NULL') as state,
            COUNT(*) as count
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND created_at >= now() - interval '4 hours'
        GROUP BY correlation_owner, correlation_state
        ORDER BY count DESC
    """).bindparams(tid=TENANT_ID))
    
    rows = result.fetchall()
    for row in rows:
        owner = row[0]
        state = row[1]
        count = row[2]
        status = "✅" if owner in {'legacy', 'graph_engine'} else "❌"
        print(f"{status} Owner: {owner:15} | State: {state:20} | Count: {count}")


async def check_correlation_engine_health(db: AsyncSession):
    """Check if graph_engine is actively claiming alerts."""
    print("\n" + "="*80)
    print("4. GRAPH ENGINE Activity Check")
    print("="*80 + "\n")
    
    result = await db.execute(text("""
        SELECT 
            COUNT(*) as total_claimed,
            COUNT(CASE WHEN correlation_state = 'claimed' THEN 1 END) as still_claimed,
            COUNT(CASE WHEN correlation_state = 'cased' THEN 1 END) as cased,
            COUNT(CASE WHEN correlation_state = 'no_case' THEN 1 END) as no_case,
            COUNT(CASE WHEN correlation_state = 'deduplicated_into_case' THEN 1 END) as dedup
        FROM alerts
        WHERE tenant_id = CAST(:tid AS uuid)
          AND correlation_owner = 'graph_engine'
          AND created_at >= now() - interval '4 hours'
    """).bindparams(tid=TENANT_ID))
    
    row = result.fetchone()
    if row[0] == 0:
        print("⚠️  Graph engine has NOT claimed any alerts in last 4 hours.")
        print("    This could mean:")
        print("    1. Graph engine service is not running")
        print("    2. Worker is still waiting for next poll cycle (default 60s)")
        print("    3. All alerts are already owned by legacy")
        return
    
    print(f"Graph Engine Claims (last 4 hours):")
    print(f"  Total claimed: {row[0]}")
    print(f"  Still claiming: {row[1]}")
    print(f"  Converted to cased: {row[2]}")
    print(f"  Marked no_case: {row[3]}")
    print(f"  Dedup into case: {row[4]}")
    
    if row[2] > 0:
        print("\n✅ Graph engine IS successfully creating cases")
        
        # Show graph_correlation cases
        result = await db.execute(text("""
            SELECT title, opened_at, array_length(alert_ids, 1) as alert_count
            FROM aisoc_cases
            WHERE tenant_id = CAST(:tid AS uuid)
              AND creation_method = 'graph_correlation'
              AND opened_at >= now() - interval '4 hours'
            ORDER BY opened_at DESC
            LIMIT 5
        """).bindparams(tid=TENANT_ID))
        
        cases = result.fetchall()
        print(f"\n  Recent graph_correlation cases ({len(cases)}):")
        for case in cases:
            print(f"    - {case[0][:60]} | {case[1]} | {case[2]} alerts")


async def main():
    """Run all diagnostics."""
    print("\n🔍 AiSOC Case Creation Diagnostic Report")
    print(f"   Tenant: {TENANT_ID}")
    print(f"   Time: {__import__('datetime').datetime.now()}\n")
    
    engine = create_async_engine(DB_URL)
    async with AsyncSession(engine) as db:
        async with db.begin():
            await check_recent_alerts(db)
            await check_case_creation_status(db)
            await check_ownership_distribution(db)
            await check_correlation_engine_health(db)
    
    await engine.dispose()
    
    print("\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("""
1. If graph_engine is claiming alerts but NO graph_correlation cases:
   → Check /services/correlation logs for errors
   → Verify Neo4j connection (AISOC_GRAPH_ENABLED=true)
   
2. If legacy is claiming alerts but NO agentic_funnel cases:
   → Check disposition values — are they TRUE_POSITIVE / ESCALATE?
   → Check severity/confidence combination meets gate
   → Check agents service logs for "case_promoter" errors
   
3. If NO alerts are claimed (all correlation_owner = NULL):
   → Services may not have started yet
   → Wait 60+ seconds (default poll cycle)
   → Check both agent services are running
   
4. To force legacy-only mode (disable graph_engine):
   → Set AISOC_GRAPH_ENABLED=false in correlation service
   → Or don't start correlation service: .\start-dev-local.ps1 -All -SkipCorrelation
""")


if __name__ == "__main__":
    asyncio.run(main())
