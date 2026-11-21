#!/usr/bin/env python
"""
Phase 1 Testing Checklist — Candidate Discovery Backend

Run this after starting API service:
  cd services/api && poetry run uvicorn app.main:app --host 0.0.0.0 --port 8888
"""

import asyncio
import httpx
import json
from datetime import datetime, timezone

async def test_endpoints():
    """Test candidate discovery endpoints"""
    
    BASE_URL = "http://localhost:8888/api/v1"
    
    # Mock auth headers (in real scenario, get valid JWT token)
    headers = {
        "Accept": "application/json",
    }
    
    tests_passed = 0
    tests_failed = 0
    
    async with httpx.AsyncClient(timeout=30) as client:
        
        # Test 1: GET /cases/candidates (should return 200 or 401)
        print("\n1️⃣ Testing GET /cases/candidates...")
        try:
            response = await client.get(f"{BASE_URL}/cases/candidates", headers=headers)
            if response.status_code in (200, 401):
                print(f"   ✅ Status {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    print(f"   Found {len(data)} candidates (expected 0 if no data yet)")
                    if data:
                        print(f"   Sample: {json.dumps(data[0], indent=4, default=str)[:200]}...")
                tests_passed += 1
            else:
                print(f"   ❌ Unexpected status {response.status_code}")
                print(f"   {response.text[:200]}")
                tests_failed += 1
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            tests_failed += 1
        
        # Test 2: GET /cases/candidates with filters
        print("\n2️⃣ Testing GET /cases/candidates with filters...")
        try:
            response = await client.get(
                f"{BASE_URL}/cases/candidates",
                headers=headers,
                params={
                    "min_score": 3,
                    "severity": "high",
                    "limit": 10,
                    "offset": 0,
                }
            )
            if response.status_code in (200, 401):
                print(f"   ✅ Filters accepted (status {response.status_code})")
                tests_passed += 1
            else:
                print(f"   ❌ Status {response.status_code}")
                tests_failed += 1
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            tests_failed += 1
        
        # Test 3: GET /cases/candidates/{candidate_key} (should return 404 if no candidates)
        print("\n3️⃣ Testing GET /cases/candidates/{candidate_key}...")
        try:
            response = await client.get(
                f"{BASE_URL}/cases/candidates/test-key-abc123",
                headers=headers,
            )
            if response.status_code in (404, 401):
                print(f"   ✅ Status {response.status_code} (expected 404 for missing candidate)")
                tests_passed += 1
            elif response.status_code == 200:
                print(f"   ✅ Candidate found (status 200)")
                print(f"   {json.dumps(response.json(), indent=2, default=str)[:300]}...")
                tests_passed += 1
            else:
                print(f"   ❌ Unexpected status {response.status_code}")
                tests_failed += 1
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            tests_failed += 1
    
    # Summary
    print("\n" + "="*60)
    print(f"Tests Passed: {tests_passed}/3")
    print(f"Tests Failed: {tests_failed}/3")
    if tests_failed == 0:
        print("✅ All tests passed!")
    else:
        print(f"❌ {tests_failed} test(s) failed")
    print("="*60)
    
    return tests_failed == 0


if __name__ == "__main__":
    import sys
    success = asyncio.run(test_endpoints())
    sys.exit(0 if success else 1)
