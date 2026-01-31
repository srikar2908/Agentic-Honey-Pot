"""
Test the improved intelligence extraction
"""
import requests
import json

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("=" * 80)
print("TESTING IMPROVED INTELLIGENCE EXTRACTION")
print("=" * 80)

# Realistic scam message with various intelligence
payload = {
    "sessionId": "test-extraction-001",
    "message": {
        "sender": "scammer",
        "text": "Your SBI account 1234567890123456 is blocked! Contact us at scammer.fraud@fakebank or call +91-9876543210. UPI: scammer@yesbank. Visit http://fake-bank.com",
        "timestamp": "2026-01-31T21:30:00Z"
    },
    "conversationHistory": []
}

print("\n📋 Test Message:")
print(payload["message"]["text"])
print("\n🔍 Expected Extraction:")
print("  - Bank Account: 1234567890123456")
print("  - Email: scammer.fraud@fakebank")
print("  - UPI: scammer@yesbank")
print("  - Phone: +91-9876543210")
print("  - URL: http://fake-bank.com")

try:
    response = requests.post(
        API_URL,
        headers={"x-api-key": API_KEY},
        json=payload,
        timeout=15
    )
    print(f"\n✅ Status: {response.status_code}")
    
    # Continue conversation to trigger final report
    for i in range(4):
        next_msg = {
            "sessionId": "test-extraction-001",
            "message": {
                "sender": "scammer",
                "text": f"More info: account 9876543210987654, call +91-8765432109",
                "timestamp": f"2026-01-31T21:3{i}:00Z"
            },
            "conversationHistory": []
        }
        requests.post(API_URL, headers={"x-api-key": API_KEY}, json=next_msg, timeout=15)
    
    print("\n📊 Check Render logs for final intelligence report!")
    print("It should show:")
    print("  bankAccounts: ['1234567890123456', '9876543210987654']")
    print("  emails: ['scammer.fraud@fakebank']")
    print("  upiIds: ['scammer@yesbank']")
    print("  phoneNumbers: ['+91-9876543210', '+91-8765432109']")
    
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 80)
