#!/usr/bin/env python3
"""Debug script to check automation rules vs alerts."""
import asyncio
import json
import os
import asyncpg

async def main():
    dsn = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/aisoc')
    conn = await asyncpg.connect(dsn)
    
    print("\n" + "="*80)
    print("ALERTS IN DATABASE")
    print("="*80)
    alerts = await conn.fetch('''
        SELECT id, title, severity, confidence, source, category, connector_type
        FROM alerts
        LIMIT 10
    ''')
    
    for alert in alerts:
        print(f"\n📍 Alert: {alert['title']}")
        print(f"   ID: {alert['id']}")
        print(f"   Severity: {alert['severity']}")
        print(f"   Confidence: {alert['confidence']}")
        print(f"   Source: {alert['source']}")
        print(f"   Category: {alert['category']}")
        print(f"   Connector: {alert['connector_type']}")
    
    print("\n" + "="*80)
    print("AUTOMATION RULES IN DATABASE")
    print("="*80)
    
    rules = await conn.fetch('''
        SELECT id, name, trigger_type, conditions, enabled, priority
        FROM automation_rules
    ''')
    
    if not rules:
        print("\n❌ NO AUTOMATION RULES FOUND IN DATABASE!")
        print("\n⚠️  To seed default rules, call GET /api/v1/automation-rules endpoint")
        print("    This will create the default rules from DEFAULT_AUTOMATION_RULES")
    else:
        print(f"\n✅ Found {len(rules)} automation rules")
        for rule in rules:
            print(f"\n📋 Rule: {rule['name']}")
            print(f"   ID: {rule['id']}")
            print(f"   Trigger: {rule['trigger_type']}")
            print(f"   Enabled: {rule['enabled']}")
            print(f"   Priority: {rule['priority']}")
            print(f"   Conditions:")
            if rule['conditions']:
                for cond in rule['conditions']:
                    print(f"     - {cond.get('field')} {cond.get('op')} {cond.get('value')}")
            else:
                print(f"     (empty - matches all)")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80)
    
    if not rules:
        print("\n1. Start the API server (if not running)")
        print("2. Call GET /api/v1/automation-rules with your auth token")
        print("3. This will seed DEFAULT_AUTOMATION_RULES into your database")
        print("\nExample:")
        print('  curl -H "Cookie: aisoc.session=YOUR_TOKEN" \\')
        print('       http://localhost:8000/api/v1/automation-rules')
    else:
        print("\n✅ Rules exist. Check why they don't match your alerts:")
        for rule in rules:
            conditions = rule['conditions'] or []
            print(f"\n  Rule: {rule['name']}")
            print(f"  Trigger: {rule['trigger_type']}")
            if not conditions:
                print(f"  ✓ Will match all {rule['trigger_type']} alerts (no conditions)")
            else:
                print(f"  Checking conditions for {len(alerts)} alerts:")
                for alert in alerts:
                    matches = True
                    for cond in conditions:
                        field = cond.get('field')
                        op = cond.get('op')
                        value = cond.get('value')
                        
                        alert_value = alert.get(field)
                        
                        if op == 'eq':
                            matches = matches and (alert_value == value or 
                                                  (isinstance(alert_value, str) and 
                                                   alert_value.lower() == str(value).lower()))
                        elif op == 'in':
                            matches = matches and (alert_value in value or
                                                  (isinstance(alert_value, str) and
                                                   alert_value.lower() in [str(v).lower() for v in value]))
                        elif op == 'ge':
                            matches = matches and (alert_value is not None and alert_value >= value)
                        elif op == 'lt':
                            matches = matches and (alert_value is not None and alert_value < value)
                        elif op == 'contains':
                            matches = matches and (isinstance(alert_value, str) and 
                                                  value.lower() in alert_value.lower())
                        
                        if not matches:
                            break
                    
                    status = "✓ MATCH" if matches else "✗ NO MATCH"
                    print(f"    {status}: {alert['title']}")
    
    await conn.close()

if __name__ == '__main__':
    asyncio.run(main())
