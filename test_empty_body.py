"""Test what happens when GUVI sends empty or minimal POST body"""
import requests

url = "https://agentic-honey-pot-e7mc.onrender.com/honeypot"
api_key = "UoxDHBe1m83w5zRtaAwz-FF70-8T94c4O6tZmHmjcu8"

print("=== Testing Different Body Scenarios ===\n")

# Test 1: Empty body (what GUVI tester might send for validation)
print("Test 1: POST with empty JSON body {}")
try:
    response = requests.post(
        url,
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json"
        },
        json={}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
except Exception as e:
    print(f"Error: {e}\n")

# Test 2: No body at all
print("Test 2: POST with no body")
try:
    response = requests.post(
        url,
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
except Exception as e:
    print(f"Error: {e}\n")

# Test 3: Only sessionId (minimal)
print("Test 3: POST with only sessionId")
try:
    response = requests.post(
        url,
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json"
        },
        json={"sessionId": "test"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
except Exception as e:
    print(f"Error: {e}\n")

# Test 4: Full valid request
print("Test 4: POST with full valid request")
try:
    response = requests.post(
        url,
        headers={
            "x-api-key": api_key,
            "Content-Type": "application/json"
        },
        json={
            "sessionId": "test-session",
            "message": {
                "sender": "scammer",
                "text": "Hello"
            }
        }
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
except Exception as e:
    print(f"Error: {e}\n")
