"""
Test with GUVI's exact timestamp format (integer)
"""
import requests
import json
import time

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("=" * 80)
print("TESTING WITH INTEGER TIMESTAMPS (GUVI FORMAT)")
print("=" * 80)

# Use integer timestamp like GUVI does
payload = {
    "sessionId": "test-timestamp-001",
    "message": {
        "sender": "scammer",
        "text": "Your SBI account is blocked! Share OTP now!",
        "timestamp": int(time.time() * 1000)  # Integer milliseconds like GUVI
    },
    "conversationHistory": [
        {
            "sender": "scammer",
            "text": "Previous message",
            "timestamp": int(time.time() * 1000) - 5000
        }
    ]
}

print("\n📋 Payload with INTEGER timestamps:")
print(json.dumps(payload, indent=2))

try:
    response = requests.post(
        API_URL,
        headers={"x-api-key": API_KEY},
        json=payload,
        timeout=15
    )
    print(f"\nStatus: {response.status_code}")
    response_data = response.json()
    print(f"Response: {json.dumps(response_data, indent=2)}")
    
    if "validated" in response_data.get("reply", "").lower():
        print("\n❌ Still returning validation response - fix not deployed yet")
    else:
        print("\n✅ SUCCESS! Getting real AI response!")
        print(f"Agent said: {response_data.get('reply')}")
        
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 80)
