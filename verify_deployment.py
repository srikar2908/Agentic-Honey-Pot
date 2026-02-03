"""
Verification script to check if OpenAPI schema fix is deployed
Run this after Render finishes deploying
"""
import requests
import json
import time

BASE_URL = "https://agentic-honey-pot-e7mc.onrender.com"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("="*60)
print("DEPLOYMENT VERIFICATION - OpenAPI Schema Fix")
print("="*60)

# Step 1: Wake up the service (Render free tier spins down)
print("\n🔄 Step 1: Waking up Render service...")
try:
    wake_response = requests.get(f"{BASE_URL}/health", timeout=60)
    print(f"   ✅ Service is awake (Status: {wake_response.status_code})")
except Exception as e:
    print(f"   ⚠️  Warning: {e}")
    print("   Waiting 10 seconds for service to start...")
    time.sleep(10)

# Step 2: Check OpenAPI schema
print("\n📋 Step 2: Checking OpenAPI schema...")
try:
    schema_response = requests.get(f"{BASE_URL}/openapi.json")
    schema = schema_response.json()
    
    # Check /honeypot POST endpoint schema
    post_schema = schema['paths']['/honeypot']['post']['responses']['200']['content']['application/json']['schema']
    
    print(f"   POST /honeypot response schema:")
    print(f"   {json.dumps(post_schema, indent=2)}")
    
    if post_schema == {}:
        print("\n   ❌ PROBLEM: Schema is still empty {}")
        print("   → Render might not have finished deploying yet")
        print("   → Wait 2-3 minutes and run this script again")
    elif '$ref' in post_schema or 'properties' in post_schema:
        print("\n   ✅ SUCCESS: Schema has proper structure!")
        print("   → GUVI tester should now accept the endpoint")
    else:
        print(f"\n   ⚠️  UNEXPECTED: Schema is {post_schema}")
        
except Exception as e:
    print(f"   ❌ Error: {e}")

# Step 3: Test GET endpoint
print("\n🔍 Step 3: Testing GET /honeypot...")
try:
    get_response = requests.get(
        f"{BASE_URL}/honeypot",
        headers={"x-api-key": API_KEY}
    )
    get_json = get_response.json()
    print(f"   Status: {get_response.status_code}")
    print(f"   Response: {get_json}")
    
    if get_json.get("status") == "success" and "reply" in get_json:
        print("   ✅ GET endpoint returns correct format")
    else:
        print("   ❌ GET endpoint response format issue")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Step 4: Test POST endpoint
print("\n🔍 Step 4: Testing POST /honeypot...")
try:
    post_response = requests.post(
        f"{BASE_URL}/honeypot",
        headers={
            "x-api-key": API_KEY,
            "Content-Type": "application/json"
        },
        json={
            "sessionId": "verify-test",
            "message": {
                "sender": "scammer",
                "text": "Test message"
            }
        }
    )
    post_json = post_response.json()
    print(f"   Status: {post_response.status_code}")
    print(f"   Response: {post_json}")
    
    if post_json.get("status") == "success" and "reply" in post_json and len(post_json) == 2:
        print("   ✅ POST endpoint returns correct format")
    else:
        print(f"   ❌ POST endpoint response issue (keys: {list(post_json.keys())})")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Final verdict
print("\n" + "="*60)
print("FINAL VERDICT")
print("="*60)
print("\n✅ If all checks passed, try the GUVI tester now!")
print("\n📝 GUVI Tester Settings:")
print(f"   URL: {BASE_URL}/honeypot")
print(f"   x-api-key: {API_KEY}")
print("\n⏰ If schema is still empty {}, wait 2-3 minutes for Render")
print("   to finish deploying, then run this script again.")
print("="*60)
