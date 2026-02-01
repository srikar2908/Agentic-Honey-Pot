"""Check exact response headers that GUVI tester receives"""
import requests

url = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
api_key = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

payload = {
    "sessionId": "test-headers",
    "message": {
        "sender": "scammer",
        "text": "Test"
    },
    "conversationHistory": []
}

print("Sending request to honeypot endpoint...")
try:
    response = requests.post(
        url,
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json"
        },
        json=payload,
        timeout=15
    )
    
    print(f"\n✓ Status Code: {response.status_code}")
    print(f"\n✓ Response Headers:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    
    print(f"\n✓ Response Body:")
    print(f"  {response.text}")
    
    print(f"\n✓ Response JSON:")
    try:
        json_response = response.json()
        print(f"  {json_response}")
        
        # Check if it matches GUVI spec
        if "status" in json_response and "reply" in json_response:
            print("\n✅ Response matches GUVI spec: {status, reply}")
        else:
            print("\n❌ Response DOES NOT match GUVI spec!")
            print(f"  Expected keys: status, reply")
            print(f"  Got keys: {list(json_response.keys())}")
    except:
        print("  Could not parse as JSON!")
        
except Exception as e:
    print(f"\n❌ Error: {e}")
