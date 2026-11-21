#!/usr/bin/env python3
"""Diagnostic for agents service - check if fused_alert_consumer is running."""

import asyncio
import os
import sys

# Check environment
print("=" * 80)
print("AGENTS SERVICE CONFIGURATION")
print("=" * 80)

kafka_brokers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip()
kafka_disable = os.getenv("AISOC_AGENT_KAFKA_DISABLE", "").strip().lower()
auto_case = os.getenv("AISOC_AGENT_AUTO_CASE", "1").strip().lower()

print(f"\nKAFKA Configuration:")
print(f"  KAFKA_BOOTSTRAP_SERVERS: {kafka_brokers or '❌ NOT SET'}")
print(f"  AISOC_AGENT_KAFKA_DISABLE: {kafka_disable or '(default: false)'}")
print(f"  AISOC_AGENT_AUTO_CASE: {auto_case or '(default: 1)'}")

# Check if worker would be enabled
worker_enabled = kafka_disable not in {"1", "true", "yes", "on"} and bool(kafka_brokers)
print(f"\nWorker would be enabled: {'✅ YES' if worker_enabled else '❌ NO'}")

if not worker_enabled:
    if kafka_disable in {"1", "true", "yes", "on"}:
        print("  Reason: AISOC_AGENT_KAFKA_DISABLE is set to disable")
    else:
        print("  Reason: KAFKA_BOOTSTRAP_SERVERS is not configured")
    sys.exit(1)

# Try to import and check FusedAlertTriageWorker
print("\n" + "=" * 80)
print("FUSED ALERT CONSUMER CHECK")
print("=" * 80)

try:
    from app.workers.fused_alert_consumer import FusedAlertTriageWorker
    print("\n✅ FusedAlertTriageWorker imported successfully")
except Exception as e:
    print(f"\n❌ Failed to import FusedAlertTriageWorker: {e}")
    sys.exit(1)

# Try to create worker instance
print("\nAttempting to create FusedAlertTriageWorker instance...")

try:
    worker = FusedAlertTriageWorker(
        bootstrap_servers=kafka_brokers,
        topic=os.getenv("KAFKA_TOPIC_ALERTS_FUSED", "aisoc.alerts.fused"),
    )
    print("✅ Worker instance created successfully")
    print(f"   Bootstrap servers: {worker.bootstrap_servers}")
    print(f"   Topic: {worker.topic}")
except Exception as e:
    print(f"❌ Failed to create worker: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Try to connect to Kafka
print("\nAttempting Kafka connection test...")

async def test_kafka():
    try:
        import aiokafka
        from aiokafka.admin import AIOKafkaAdminClient
        
        admin_client = AIOKafkaAdminClient(
            bootstrap_servers=kafka_brokers.split(',')
        )
        
        await admin_client.start()
        print("✅ Kafka connection successful!")
        
        # List topics
        topics = await admin_client.list_topics()
        print(f"\n   Available topics ({len(topics)}):")
        for topic in sorted(topics.keys()):
            if 'alert' in topic.lower() or 'fused' in topic.lower():
                print(f"   - {topic} 📌 (RELEVANT)")
            else:
                print(f"   - {topic}")
        
        await admin_client.close()
        
    except Exception as e:
        print(f"❌ Kafka connection failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

try:
    asyncio.run(test_kafka())
except KeyboardInterrupt:
    print("Interrupted")
except Exception as e:
    print(f"❌ Async test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 80)
print("✅ ALL CHECKS PASSED - Agents service should work")
print("=" * 80)
