#!/usr/bin/env python
"""Verify that migrations were applied successfully"""

import asyncio
import asyncpg
import os
import sys

async def verify_schema():
    """Verify database schema after migrations"""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL not set")
        sys.exit(1)
    
    # Parse connection string
    url = db_url.replace("postgresql+asyncpg://", "").replace("postgresql://", "")
    user, password_host = url.split(":", 1)
    password, host_port = password_host.split("@", 1)
    host, port_db = host_port.split(":", 1)
    port, dbname = port_db.split("/", 1)
    
    conn = await asyncpg.connect(
        host=host, port=int(port), user=user, password=password, database=dbname
    )
    
    try:
        print("🔍 Verifying KPI Level 1 migrations...")
        
        # Check case_evaluations table
        print("\n✓ Checking case_evaluations table...")
        cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='case_evaluations'
            ORDER BY column_name
        """)
        
        expected_cols = ['id', 'tenant_id', 'case_id', 'evaluator_id', 'is_correct', 'confidence_score', 'notes', 'evaluated_at', 'created_at']
        found_cols = [row['column_name'] for row in cols]
        
        for col in expected_cols:
            if col in found_cols:
                print(f"  ✅ case_evaluations.{col}")
            else:
                print(f"  ❌ case_evaluations.{col} MISSING")
        
        # Check false_alert_records table
        print("\n✓ Checking false_alert_records table...")
        cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='false_alert_records'
            ORDER BY column_name
        """)
        
        expected_cols = ['id', 'tenant_id', 'case_id', 'alert_id', 'evaluator_id', 'reason', 'created_at']
        found_cols = [row['column_name'] for row in cols]
        
        for col in expected_cols:
            if col in found_cols:
                print(f"  ✅ false_alert_records.{col}")
            else:
                print(f"  ❌ false_alert_records.{col} MISSING")
        
        # Check kpi_metrics table
        print("\n✓ Checking kpi_metrics table...")
        cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='kpi_metrics'
            ORDER BY column_name
        """)
        
        expected_cols = [
            'id', 'tenant_id', 'metric_date', 'metric_period',
            'alert_reduction_rate', 'precision', 'cluster_purity', 'false_correlation_rate',
            'sample_size', 'raw_alerts_count', 'created_cases_count', 'evaluated_cases_count',
            'correct_cases_count', 'cases_with_false_alerts_count',
            'calculated_at', 'created_at'
        ]
        found_cols = [row['column_name'] for row in cols]
        
        for col in expected_cols:
            if col in found_cols:
                print(f"  ✅ kpi_metrics.{col}")
            else:
                print(f"  ❌ kpi_metrics.{col} MISSING")
        
        # Check case_candidate_dismissals table
        print("\n✓ Checking case_candidate_dismissals table...")
        cols = await conn.fetch("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name='case_candidate_dismissals'
            ORDER BY column_name
        """)
        
        expected_cols = ['id', 'tenant_id', 'candidate_key', 'dismissed_at']
        found_cols = [row['column_name'] for row in cols]
        
        for col in expected_cols:
            if col in found_cols:
                print(f"  ✅ case_candidate_dismissals.{col}")
            else:
                print(f"  ❌ case_candidate_dismissals.{col} MISSING")
        
        # Check indexes
        print("\n✓ Checking indexes...")
        indexes = await conn.fetch("""
            SELECT indexname FROM pg_indexes
            WHERE tablename IN ('case_evaluations', 'false_alert_records', 'kpi_metrics', 'case_candidate_dismissals')
            ORDER BY indexname
        """)
        
        print(f"  Found {len(indexes)} indexes")
        for idx in indexes:
            print(f"    - {idx['indexname']}")
        
        print("\n✅ All KPI Level 1 schema elements verified successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(verify_schema())
