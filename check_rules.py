import asyncio
import asyncpg
import os

async def check_rules():
    dsn = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/aisoc')
    conn = await asyncpg.connect(dsn)
    
    # Check alerts
    alerts = await conn.fetch('SELECT id, tenant_id, title, severity FROM alerts LIMIT 10')
    print('=== ALERTS ===')
    print(f'Total alerts: {len(alerts)}')
    for row in alerts:
        print(f'  ID: {row["id"]}, Title: {row["title"]}, Severity: {row["severity"]}')
    
    # Check rules
    rules = await conn.fetch('SELECT id, name, trigger_type, conditions, enabled FROM automation_rules')
    print(f'\n=== AUTOMATION RULES ===')
    print(f'Total rules: {len(rules)}')
    for row in rules:
        print(f'  Rule: {row["name"]} | Trigger: {row["trigger_type"]} | Enabled: {row["enabled"]}')
        print(f'    Conditions: {row["conditions"]}')
    
    await conn.close()

asyncio.run(check_rules())
