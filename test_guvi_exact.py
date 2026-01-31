"""
Test the exact payload GUVI tester sends
"""
import requests

API_URL = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
API_KEY = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("=" * 80)
print("TESTING GUVI TESTER EXACT PAYLOAD")
print("=" * 80)

# Test with the exact payload GUVI sends: {"name": "Add your name in the body"}
print("\n📋 Test: POST with GUVI validation payload...")
try:
    response = requests.post(
        API_URL,
        headers={"x-api-key": API_KEY},
        json={"name": "Add your name in the body"},
        timeout=15
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print(f"✅ SUCCESS! Response: {response.json()}")
        print("\n🎉 GUVI tester should work now!")
    elif response.status_code == 422:
        print(f"❌ Still 422! Response: {response.json()}")
    else:
        print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "=" * 80)
