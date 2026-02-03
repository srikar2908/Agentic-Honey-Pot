"""Quick test to verify the fix works"""
import requests

# Test local server if running, otherwise test deployed
BASE_URL = "https://agentic-honey-pot-e7mc.onrender.com"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("Testing API responses...\n")

# Test GET
print("1. GET /honeypot")
response = requests.get(
    f"{BASE_URL}/honeypot",
    headers={"x-api-key": API_KEY}
)
print(f"   Status: {response.status_code}")
print(f"   Response: {response.json()}")

# Test POST
print("\n2. POST /honeypot with valid request")
response = requests.post(
    f"{BASE_URL}/honeypot",
    headers={
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    },
    json={
        "sessionId": "test-fix",
        "message": {
            "sender": "scammer", 
            "text": "Hello"
        }
    }
)
print(f"   Status: {response.status_code}")
resp_json = response.json()
print(f"   Response keys: {list(resp_json.keys())}")
print(f"   Response: {resp_json}")

# Verify response format
assert "status" in resp_json, "Missing 'status' key"
assert "reply" in resp_json, "Missing 'reply' key"
assert len(resp_json) == 2, f "Expected 2 keys, got {len(resp_json)}"

print("\n✅ All tests passed! Response format is correct.")
