"""Test what exact error GUVI tester might be getting"""
import requests
import json

url = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
api_key = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

# Test 1: Empty body (worst case)
print("="*80)
print("TEST 1: Empty JSON body (what tester might send)")
print("="*80)
try:
    response = requests.post(url, headers={"x-api-key": api_key, "Content-Type": "application/json"}, json={}, timeout=10)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"Error: {e}")

# Test 2: Minimal valid payload
print("\n" + "="*80)
print("TEST 2: Minimal valid payload")
print("="*80)
try:
    payload = {
        "sessionId": "test",
        "message": {
            "sender": "scammer",
            "text": "test"
        }
    }
    response = requests.post(url, headers={"x-api-key": api_key, "Content-Type": "application/json"}, json=payload, timeout=10)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"Error: {e}")

# Test 3: Check if /honeypot returns helpful error  
print("\n" + "="*80)
print("TEST 3: Invalid JSON to trigger validation error")
print("="*80)
try:
    response = requests.post(url, headers={"x-api-key": api_key, "Content-Type": "application/json"}, data='{"invalid": true}', timeout=10)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
