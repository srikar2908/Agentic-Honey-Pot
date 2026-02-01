"""
Emulate EXACTLY what the GUVI API Endpoint Tester might be doing.
The GUVI tester might be:
1. Sending a GET request first to validate the endpoint exists
2. Then sending POST requests with different payload structures
3. Checking response format compliance
"""
import requests
import json

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("GUVI API Endpoint Tester Emulation")
print("=" * 80)

# Test 1: GET request (validation check)
print("\n[TEST 1] GET /honeypot (endpoint validation)")
print("-" * 80)
try:
    resp = requests.get(
        API_URL,
        headers={"x-api-key": API_KEY},
        timeout=10
    )
    print(f"Status: {resp.status_code}")
    print(f"Response: {json.dumps(resp.json(), indent=2)}")
    
    # Check response format
    data = resp.json()
    if isinstance(data, dict) and "status" in data and "reply" in data:
        print("✅ Response format: VALID")
    else:
        print(f"❌ Response format: INVALID - got keys: {list(data.keys())}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 2: POST with minimal payload (might be what GUVI sends first)
print("\n[TEST 2] POST /honeypot (minimal payload)")
print("-" * 80)
minimal_payload = {
    "sessionId": "guvi-test-001",
    "message": {
        "sender": "scammer",
        "text": "Test message from GUVI"
    }
}
try:
    resp = requests.post(
        API_URL,
        json=minimal_payload,
        headers={
            "x-api-key": API_KEY,
            "Content-Type": "application/json"
        },
        timeout=10
    )
    print(f"Status: {resp.status_code}")
    print(f"Response: {json.dumps(resp.json(), indent=2)}")
    
    # Check response format
    data = resp.json()
    if isinstance(data, dict) and "status" in data and "reply" in data:
        print("✅ Response format: VALID")
        if len(data.keys()) == 2:
            print("✅ Response has EXACTLY 2 keys (status, reply)")
        else:
            print(f"⚠️ Response has extra keys: {set(data.keys()) - {'status', 'reply'}}")
    else:
        print(f"❌ Response format: INVALID - got keys: {list(data.keys())}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 3: POST with full GUVI spec payload
print("\n[TEST 3] POST /honeypot (full GUVI spec payload)")
print("-" * 80)
full_payload = {
    "sessionId": "guvi-test-002",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked today. Verify immediately.",
        "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}
try:
    resp = requests.post(
        API_URL,
        json=full_payload,
        headers={
            "x-api-key": API_KEY,
            "Content-Type": "application/json"
        },
        timeout=10
    )
    print(f"Status: {resp.status_code}")
    print(f"Response: {json.dumps(resp.json(), indent=2)}")
    
    # Check response format
    data = resp.json()
    if isinstance(data, dict) and "status" in data and "reply" in data:
        print("✅ Response format: VALID")
        if len(data.keys()) == 2:
            print("✅ Response has EXACTLY 2 keys (status, reply)")
        else:
            print(f"⚠️ Response has extra keys: {set(data.keys()) - {'status', 'reply'}}")
        
        # Check data types
        if isinstance(data.get("status"), str) and isinstance(data.get("reply"), str):
            print("✅ Both 'status' and 'reply' are strings")
        else:
            print(f"❌ Type mismatch - status: {type(data.get('status'))}, reply: {type(data.get('reply'))}")
            
    else:
        print(f"❌ Response format: INVALID - got keys: {list(data.keys())}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 4: Check Content-Type header
print("\n[TEST 4] Verify Content-Type header")
print("-" * 80)
try:
    resp = requests.post(
        API_URL,
        json=minimal_payload,
        headers={
            "x-api-key": API_KEY,
            "Content-Type": "application/json"
        },
        timeout=10
    )
    content_type = resp.headers.get("Content-Type", "")
    print(f"Content-Type: {content_type}")
    
    if "application/json" in content_type:
        print("✅ Content-Type is application/json")
    else:
        print(f"❌ Content-Type is NOT application/json")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 5: OPTIONS preflight (CORS)
print("\n[TEST 5] OPTIONS /honeypot (CORS preflight)")
print("-" * 80)
try:
    resp = requests.options(
        API_URL,
        headers={
            "Origin": "https://hackathon.guvi.in",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-api-key, content-type"
        },
        timeout=10
    )
    print(f"Status: {resp.status_code}")
    print(f"Allow: {resp.headers.get('Allow', 'Not set')}")
    print(f"Access-Control-Allow-Origin: {resp.headers.get('Access-Control-Allow-Origin', 'Not set')}")
    print(f"Access-Control-Allow-Methods: {resp.headers.get('Access-Control-Allow-Methods', 'Not set')}")
    print(f"Access-Control-Allow-Headers: {resp.headers.get('Access-Control-Allow-Headers', 'Not set')}")
    
    if resp.status_code == 200:
        print("✅ OPTIONS request successful")
    else:
        print(f"⚠️ OPTIONS request returned {resp.status_code}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 80)
print("Testing completed!")
print("\nIf all tests pass but GUVI tester still fails, the issue might be:")
print("1. GUVI tester uses a different API key format")
print("2. GUVI tester sends requests from a specific IP that needs whitelisting")
print("3. GUVI tester has additional validation logic we haven't replicated")
print("4. There's a timeout or latency issue with your Render deployment")
