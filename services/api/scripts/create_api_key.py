#!/usr/bin/env python
"""Create API key for correlation engine with cases:write:correlation scope"""

import asyncio
import asyncpg
import os
import sys
import secrets
from datetime import datetime, timezone

async def create_api_key():
    """Create an API key for service-to-service authentication"""
    
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL not set")
        print("\nSet it with:")
        print("  export DATABASE_URL='postgresql+asyncpg://user:pass@host:port/dbname'")
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
        print("🔑 Creating API key for correlation engine...")
        
        # Generate secure random key
        api_key = secrets.token_urlsafe(32)
        key_hash = api_key  # In production, this should be bcrypt hashed
        
        # Get default tenant (first one)
        tenant_row = await conn.fetchrow("""
            SELECT id FROM tenants ORDER BY created_at ASC LIMIT 1
        """)
        
        if not tenant_row:
            print("❌ No tenant found. Please create a tenant first.")
            sys.exit(1)
        
        tenant_id = tenant_row['id']
        print(f"📌 Using tenant: {tenant_id}")
        
        # Create API key in api_keys table
        now = datetime.now(timezone.utc)
        
        try:
            # Try to insert into api_keys table
            result = await conn.fetchrow("""
                INSERT INTO api_keys (
                    tenant_id,
                    name,
                    key_hash,
                    scopes,
                    created_at,
                    last_used_at,
                    is_active
                )
                VALUES (
                    $1,
                    'correlation-engine',
                    $2,
                    ARRAY['cases:write:correlation', 'alerts:read'],
                    $3,
                    NULL,
                    true
                )
                RETURNING id
            """, tenant_id, key_hash, now)
            
            api_key_id = result['id']
            print(f"✅ API key created successfully!")
            print(f"\n📋 Details:")
            print(f"   ID: {api_key_id}")
            print(f"   Tenant: {tenant_id}")
            print(f"   Scopes: cases:write:correlation, alerts:read")
            print(f"   Active: true")
            
            print(f"\n🔐 API Key (save this securely - cannot be retrieved later):")
            print(f"   {api_key}")
            
            print(f"\n📌 Set this in worker environment:")
            print(f"   export AISOC_CORRELATION_ENGINE_API_KEY='{api_key}'")
            print(f"   export AISOC_CORRELATION_ENGINE_TENANT_ID='{tenant_id}'")
            
        except Exception as e:
            print(f"⚠️  api_keys table error: {e}")
            print("\nℹ️  Falling back to environment-based auth...")
            
            print(f"\n✅ API Key generated (store securely):")
            print(f"   {api_key}")
            print(f"\n📌 Set in worker environment:")
            print(f"   export AISOC_CORRELATION_ENGINE_API_KEY='{api_key}'")
            print(f"   export AISOC_CORRELATION_ENGINE_TENANT_ID='{tenant_id}'")
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        sys.exit(1)
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(create_api_key())
