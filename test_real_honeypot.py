"""
Debug what GUVI is actually sending when it does scam simulation
"""
import requests
import json

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("=" * 80)
print("TESTING REAL HONEYPOT REQUEST")
print("=" * 80)

# Test with a REAL honeypot request format
payload = {
    "sessionId": "test-session-001",
    "message": {
        "sender": "scammer",
        "text": "Your account is blocked. Share OTP now!"
    },
    "conversationHistory": []
}

print("\n📋 Sending real honeypot message...")
print(f"Payload: {json.dumps(payload, indent=2)}")

try:
    response = requests.post(
        API_URL,
        headers={"x-api-key": API_KEY},
        json=payload,
        timeout=15
    )
    print(f"\nStatus: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.json().get("reply") == "Honeypot endpoint validated successfully.":
        print("\n❌ BUG: Real honeypot request treated as validation!")
    else:
        print("\n✅ Correct: Got actual agent response")
        
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 80)
