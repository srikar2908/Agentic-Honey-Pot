"""
CRITICAL TEST: Check if the GUVI API Tester is actually a VALIDATOR service
that TESTS our API by sending requests to it.

Based on the requirements, the GUVI tester might be:
1. Sending test scam messages TO our API
2. Expecting our API to respond correctly
3. Then calling OUR callback (which we should NOT implement for the tester)

Let's verify the exact behavior.
"""
import requests
import json

print("=" * 80)
print("HYPOTHESIS: GUVI Tester sends requests TO our API and validates responses")
print("=" * 80)

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

# Simulate what WE THINK the GUVI tester does
print("\n[SIMULATION] GUVI Tester sends scam message to our API")
print("-" * 80)

test_message = {
    "sessionId": "guvi-automated-test-001",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked. Call 9876543210 immediately.",
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
    print(f"\n📤 Sending: {json.dumps(test_message, indent=2)}")
    
    response = requests.post(
        API_URL,
        json=test_message,
        headers={
            "x-api-key": API_KEY,
            "Content-Type": "application/json"
        },
        timeout=15
    )
    
    print(f"\n📥 Response:")
    print(f"  Status: {response.status_code}")
    print(f"  Body: {json.dumps(response.json(), indent=2)}")
    
    # Validate response format
    resp_json = response.json()
    
    checks = {
        "Has 'status' key": "status" in resp_json,
        "Has 'reply' key": "reply" in resp_json,
        "Status is 'success'": resp_json.get("status") == "success",
        "Reply is non-empty string": isinstance(resp_json.get("reply"), str) and len(resp_json.get("reply")) > 0,
        "No extra keys": set(resp_json.keys()) == {"status", "reply"},
        "Status code is 200": response.status_code == 200,
        "Content-Type is JSON": "application/json" in response.headers.get("Content-Type", "")
    }
    
    print(f"\n✅ Validation Checks:")
    all_passed = True
    for check, passed in checks.items():
        symbol = "✅" if passed else "❌"
        print(f"  {symbol} {check}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print(f"\n🎉 ALL CHECKS PASSED! Your API meets GUVI spec 100%")
        print(f"\nIf GUVI tester STILL shows 'INVALID_REQUEST_BODY', then:")
        print(f"  1. The GUVI tester has a BUG")
        print(f"  2. There's a network/timeout issue")
        print(f"  3. The API key in GUVI tester doesn't match Render env var")
        print(f"  4. The GUVI tester URL field has a typo")
    else:
        print(f"\n⚠️ SOME CHECKS FAILED - Review above")
        
except requests.exceptions.Timeout:
    print(f"\n❌ TIMEOUT! Your Render service might be 'cold' (spun down)")
    print(f"   Solution: Ping your API a few times to 'wake it up', then try GUVI tester")
except Exception as e:
    print(f"\n❌ ERROR: {e}")

print("\n" + "=" * 80)
