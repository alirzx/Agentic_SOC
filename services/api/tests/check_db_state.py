#!/usr/bin/env python3
"""Check database schema and alert state for case creation debugging."""

import asyncio
import asyncpg
import json

async def check_db():
    conn = await asyncpg.connect('postgresql://aisoc:aisoc_dev_secret@192.168.220.131:5433/aisoc')
    
    print("=" * 80)
    print("DATABASE SCHEMA CHECK")
    print("=" * 80)
    
    # Check if migration 074 exists (correlation_owner column)
    result = await conn.fetch("""
        SELECT column_name, data_type
        FROM information_schema.columns 
        WHERE table_name = 'alerts' 
          AND column_name IN ('correlation_owner', 'correlation_state', 'correlation_claimed_at')
        ORDER BY column_name
    """)
    
    if not result:
        print("\n❌ CRITICAL: correlation_owner columns DO NOT EXIST")
        print("   Migration 074 has NOT been applied!")
        print("\n   To apply migrations run:")
        print("   cd services/api && poetry run python app/scripts/run_migrations.py")
    else:
        print("\n✅ Correlation ownership columns exist:")
        for row in result:
            print(f"  - {row['column_name']}: {row['data_type']}")
    
    print("\n" + "=" * 80)
    print("RECENT ALERTS STATE")
    print("=" * 80)
    
    # Check recent alerts
    recent = await conn.fetch("""
        SELECT 
            id, title, disposition, severity, confidence,
            correlation_owner, correlation_state, case_id, 
            funnel_stage, created_at
        FROM alerts
        WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
          AND created_at >= now() - interval '60 minutes'
        ORDER BY created_at DESC
        LIMIT 10
    """)
    
    print(f"\nFound {len(recent)} alerts in last 60 minutes")
    
    ownership_stats = {
        'NULL': 0,
        'legacy': 0,
        'graph_engine': 0,
        'other': 0
    }
    
    promotable = 0
    
    for row in recent:
        owner = row['correlation_owner'] or 'NULL'
        ownership_stats[owner if owner in ownership_stats else 'other'] += 1
        
        # Check if promotable
        disposition = row['disposition']
        severity = row['severity']
        confidence = row['confidence']
        
        is_tp_or_escalate = disposition in {'true_positive', 'likely_tp', 'escalate', 'needs_review'}
        auto_closeable = disposition in {'false_positive', 'benign', 'benign_true_positive'}
        sev_ok = severity in {'high', 'critical'} or (severity == 'medium' and confidence >= 0.70)
        can_promote = is_tp_or_escalate and not auto_closeable and sev_ok
        
        if can_promote:
            promotable += 1
        
        print(f"\n  Alert: {str(row['id'])[:8]}...")
        print(f"    Created: {row['created_at']}")
        print(f"    Title: {row['title'][:60]}")
        print(f"    Disposition: {row['disposition']} | Severity: {severity} | Conf: {confidence:.2f}")
        print(f"    Promotable: {'✅ YES' if can_promote else '❌ NO'}")
        print(f"    correlation_owner: {row['correlation_owner']}")
        print(f"    correlation_state: {row['correlation_state']}")
        print(f"    case_id: {row['case_id']}")
        print(f"    funnel_stage: {row['funnel_stage']}")
    
    print("\n" + "=" * 80)
    print("STATISTICS")
    print("=" * 80)
    print(f"  Total alerts: {len(recent)}")
    print(f"  Promotable (disposition + severity OK): {promotable}")
    print(f"  Ownership distribution:")
    for owner, count in ownership_stats.items():
        if count > 0:
            print(f"    {owner}: {count}")
    
    # Check if any cases were created
    print("\n" + "=" * 80)
    print("CASE CREATION STATUS")
    print("=" * 80)
    
    cases = await conn.fetch("""
        SELECT 
            creation_method,
            COUNT(*) as case_count,
            MAX(opened_at) as newest
        FROM aisoc_cases
        WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
          AND opened_at >= now() - interval '60 minutes'
        GROUP BY creation_method
        ORDER BY case_count DESC
    """)
    
    if not cases:
        print("\n❌ NO CASES created in last 60 minutes!")
    else:
        print(f"\nCases created ({len(cases)} types):")
        for row in cases:
            print(f"  {row['creation_method']:20} | Count: {row['case_count']:3d} | Newest: {row['newest']}")
    
    # Final diagnosis
    print("\n" + "=" * 80)
    print("DIAGNOSIS")
    print("=" * 80)
    
    if not result:
        print("\n🔴 PROBLEM: Migration 074 not applied!")
        print("   FIX: Run migrations: cd services/api && poetry run python app/scripts/run_migrations.py")
    elif promotable == 0:
        print("\n🔴 PROBLEM: No promotable alerts (all have wrong disposition/severity)!")
        print("   FIX: Check LLM triage - dispositions might be false_positive/benign")
    elif ownership_stats['NULL'] == 0 and ownership_stats['legacy'] == 0:
        print("\n🔴 PROBLEM: All alerts already claimed by other engine!")
        print("   FIX: This shouldn't happen in -SkipCorrelation mode. Check if correlation is really disabled.")
    elif ownership_stats['legacy'] > 0 and not cases:
        print("\n🔴 PROBLEM: Legacy claimed alerts but no cases created!")
        print("   FIX: Check agents service logs for case_promoter errors")
        print("        Look for: 'case_promoter.failed' or 'should_promote' messages")
    elif not cases:
        print("\n🟡 WARNING: No cases yet - this is normal if alerts just arrived.")
        print("   NEXT: Wait 30+ seconds for agents to process, then retry query")
    else:
        print("\n✅ Cases ARE being created!")
        print("   Everything appears normal")
    
    await conn.close()

asyncio.run(check_db())
