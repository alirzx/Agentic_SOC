#!/usr/bin/env python3
"""
تست: بررسی اینکه deduplicated alerts برای case creation انتخاب نشده‌اند

سناریو:
  1. DB را بخوانیم
  2. deduplicated alerts را بررسی کنیم
  3. ببینیم آیا deduplicated alerts جزو cases هستند
  4. اگر جزو case هستند → BUG (باید skip شوند)
  5. اگر جزو case نیستند → GOOD ✅
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Config
DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://aisoc:aisoc_dev_secret@192.168.220.131:5433/aisoc"
)
DEMO_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
LOOKBACK_HOURS = 2


async def main():
    engine = create_async_engine(DB_URL, echo=False, pool_pre_ping=True)
    
    async with AsyncSession(engine) as session:
        print("=" * 80)
        print("تست: Deduplicated Alerts از Case Creation محفوظ؟")
        print("=" * 80)
        
        # ۱. تمام alerts در آخر 2 ساعت
        print("\n[۱] تمام alerts (آخر 2 ساعت):")
        since = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
        
        all_alerts = await session.execute(
            text("""
                SELECT 
                    id, title, funnel_stage, disposition, 
                    case_id, created_at, correlation_owner
                FROM alerts
                WHERE tenant_id = :tid
                  AND created_at >= :since
                ORDER BY created_at DESC
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        
        alerts = all_alerts.fetchall()
        print(f"    Total: {len(alerts)} alerts")
        
        # ۲. Statistics
        deduplicated = [a for a in alerts if a[2] == 'deduplicated']  # funnel_stage
        cased = [a for a in alerts if a[4] is not None]  # case_id
        promoted_by_legacy = [a for a in alerts if a[6] == 'legacy']  # correlation_owner
        
        print(f"    Deduplicated: {len(deduplicated)}")
        print(f"    With case_id: {len(cased)}")
        print(f"    Claimed by legacy: {len(promoted_by_legacy)}")
        
        # ۳. مشکل: deduplicated alerts که case_id دارند
        print("\n[۲] مشکل شناسایی:")
        deduplicated_with_case = [
            a for a in deduplicated 
            if a[4] is not None  # case_id
        ]
        
        if deduplicated_with_case:
            print(f"    ❌ {len(deduplicated_with_case)} deduplicated alerts که case_id دارند!")
            print("       (این باید صفر باشد! هر deduplicated alert باید از case creation رد شود)")
            for alert in deduplicated_with_case[:5]:
                print(f"       - Alert {str(alert[0])[:8]}... | case_id: {alert[4]} | disposition: {alert[3]}")
        else:
            print(f"    ✅ صفر deduplicated alerts با case_id (GOOD!)")
        
        # ۴. Canonical alerts (non-deduplicated cased)
        print("\n[۳] Canonical alerts (اصلی‌ها):")
        canonical_alerts = [
            a for a in alerts 
            if a[2] != 'deduplicated' and a[4] is not None
        ]
        print(f"    {len(canonical_alerts)} alerts که case_id دارند و deduplicated نیستند")
        
        # ۵. Cases تفصیل
        print("\n[۴] Cases تفصیل:")
        cases = await session.execute(
            text("""
                SELECT 
                    id, title, alert_ids, created_by, opened_at,
                    ARRAY_LENGTH(alert_ids, 1) as alert_count
                FROM aisoc_cases
                WHERE tenant_id = :tid
                  AND opened_at >= :since
                ORDER BY opened_at DESC
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        
        cases_data = cases.fetchall()
        print(f"    Total: {len(cases_data)} cases")
        
        legacy_cases = [c for c in cases_data if c[3] == 'agentic-funnel']
        print(f"    Legacy (agentic-funnel): {len(legacy_cases)}")
        
        # ۶. خطرناک: deduplicated alerts جزو cases
        print("\n[۵] خطرناک: Deduplicated alerts در case_ids:")
        
        deduplicated_ids = {str(a[0]) for a in deduplicated}
        
        risky_cases = []
        for case in cases_data:
            alert_ids = case[2] or []
            alert_ids_str = [str(aid) for aid in alert_ids]
            
            deduplicated_in_case = [
                aid for aid in alert_ids_str 
                if aid in deduplicated_ids
            ]
            
            if deduplicated_in_case:
                risky_cases.append({
                    'case_id': case[0],
                    'case_title': case[1],
                    'alert_count': case[5],
                    'deduplicated_in_case': len(deduplicated_in_case),
                    'created_by': case[3]
                })
        
        if risky_cases:
            print(f"    ⚠️  {len(risky_cases)} cases حاوی deduplicated alerts:")
            for rc in risky_cases[:3]:
                print(f"       - Case {str(rc['case_id'])[:8]}... | "
                      f"Total: {rc['alert_count']} | "
                      f"Deduplicated: {rc['deduplicated_in_case']} | "
                      f"By: {rc['created_by']}")
        else:
            print(f"    ✅ صفر case حاوی deduplicated alerts (GOOD!)")
        
        # ۷. Verdict distribution
        print("\n[۶] Disposition Distribution:")
        verdict_dist = await session.execute(
            text("""
                SELECT disposition, COUNT(*), funnel_stage
                FROM alerts
                WHERE tenant_id = :tid
                  AND created_at >= :since
                GROUP BY disposition, funnel_stage
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """).bindparams(tid=DEMO_TENANT, since=since)
        )
        
        verdicts = verdict_dist.fetchall()
        for disp, count, stage in verdicts:
            stage_str = f" [{stage}]" if stage != 'ingested' else ""
            print(f"    {disp or 'NULL'}: {count:4d}{stage_str}")
        
        # ۸. Summary
        print("\n" + "=" * 80)
        print("خلاصه:")
        print("=" * 80)
        
        if deduplicated_with_case:
            print(f"🔴 BUG تأیید شد: {len(deduplicated_with_case)} deduplicated alerts جزو cases هستند")
            print("   ← باید guard اضافی در case_promoter.promote_to_case() اضافه شود")
        else:
            print("✅ BUG وجود ندارد: deduplicated alerts از case creation رد شدند")
            print("   ← promotion gate صحیح کار می‌کند")
        
        if risky_cases:
            print(f"   → {len(risky_cases)} case حاوی deduplicated alerts")
        
        print(f"\nدر کل:")
        print(f"  • {len(alerts)} alerts")
        print(f"  • {len(deduplicated)} deduplicated")
        print(f"  • {len(cased)} cased")
        print(f"  • {len(cases_data)} cases")
        print(f"  • {len(legacy_cases)} legacy funnel cases")
        
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
