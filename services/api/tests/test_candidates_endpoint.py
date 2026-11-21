#!/usr/bin/env python
"""Quick test: verify GET /cases/candidates endpoint responds"""

import asyncio
import httpx
import json

async def test_candidates():
    """Test the candidates endpoint"""
    
    api_url = "http://localhost:8888"
    
    # You would normally auth first, but we're just testing endpoint availability
    headers = {
        "Authorization": "Bearer demo_token",  # Would be real token
    }
    
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            # Test list candidates
            print("Testing GET /cases/candidates...")
            response = await client.get(
                f"{api_url}/api/v1/cases/candidates",
                headers=headers,
                params={"limit": 10}
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:500]}")
            
            if response.status_code == 200:
                print("✅ GET /cases/candidates works!")
                data = response.json()
                print(f"Found {len(data)} candidates")
                if data:
                    print(f"Sample: {json.dumps(data[0], indent=2, default=str)}")
            else:
                print(f"❌ Error: {response.status_code}")
                
        except Exception as e:
            print(f"Error: {e}")
            print("(This is expected if API is not running)")

if __name__ == "__main__":
    asyncio.run(test_candidates())
