"""
Test script for Agentic Honey-Pot API
Run this to test your API locally or on Render
"""

import requests
import json
import time

# Configuration
API_URL = "http://localhost:5000"  # Change to your Render URL
API_KEY = "your-secret-api-key-here"  # Change to your API key

# Test scenarios
test_scenarios = [
    {
        "name": "Bank Account Scam",
        "sessionId": "test-session-001",
        "messages": [
            "Your bank account will be blocked today. Verify immediately.",
            "Share your account number to avoid suspension.",
            "Also provide your UPI ID for verification."
        ]
    },
    {
        "name": "UPI Fraud",
        "sessionId": "test-session-002",
        "messages": [
            "Congratulations! You won 50,000 rupees in lucky draw.",
            "Send your UPI ID to claim prize.",
            "Also share your phone number for verification."
        ]
    },
    {
        "name": "OTP Scam",
        "sessionId": "test-session-003",
        "messages": [
            "Your account shows suspicious activity.",
            "We need to verify. Please share the OTP we just sent.",
            "This is urgent to prevent account closure."
        ]
    }
]


def test_health_check():
    """Test health endpoint"""
    print("\n" + "="*60)
    print("🏥 Testing Health Check Endpoint")
    print("="*60)
    
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ Health check passed!")
            return True
        else:
            print("❌ Health check failed!")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_authentication():
    """Test API authentication"""
    print("\n" + "="*60)
    print("🔐 Testing API Authentication")
    print("="*60)
    
    # Test without API key
    print("\n1. Testing WITHOUT API key (should fail):")
    try:
        response = requests.post(
            f"{API_URL}/test",
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 401:
            print("✅ Correctly rejected unauthorized request!")
        else:
            print("⚠️  Warning: Should return 401 for missing API key")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test with API key
    print("\n2. Testing WITH API key (should pass):")
    try:
        response = requests.post(
            f"{API_URL}/test",
            headers={
                "x-api-key": API_KEY,
                "Content-Type": "application/json"
            },
            timeout=5
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print("✅ Authentication successful!")
            return True
        else:
            print("❌ Authentication failed!")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_honeypot_scenario(scenario):
    """Test a complete scam scenario"""
    print("\n" + "="*60)
    print(f"🍯 Testing Scenario: {scenario['name']}")
    print("="*60)
    
    session_id = scenario['sessionId']
    conversation_history = []
    
    for idx, message_text in enumerate(scenario['messages'], 1):
        print(f"\n--- Message {idx} ---")
        print(f"Scammer: {message_text}")
        
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": message_text,
                "timestamp": int(time.time() * 1000)
            },
            "conversationHistory": conversation_history,
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        try:
            response = requests.post(
                f"{API_URL}/honeypot",
                json=payload,
                headers={
                    "x-api-key": API_KEY,
                    "Content-Type": "application/json"
                },
                timeout=30  # Longer timeout for AI response
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Agent Reply: {result.get('reply', 'No reply')}")
                
                # Add to conversation history
                conversation_history.append({
                    "sender": "scammer",
                    "text": message_text,
                    "timestamp": int(time.time() * 1000)
                })
                conversation_history.append({
                    "sender": "user",
                    "text": result.get('reply', ''),
                    "timestamp": int(time.time() * 1000)
                })
                
                print("✅ Message processed successfully!")
            else:
                print(f"❌ Error: {response.text}")
                break
                
        except Exception as e:
            print(f"❌ Error: {e}")
            break
        
        # Wait a bit between messages
        time.sleep(2)
    
    print(f"\n✅ Completed scenario: {scenario['name']}")
    print(f"Total messages exchanged: {len(conversation_history)}")


def run_all_tests():
    """Run all test scenarios"""
    print("\n" + "="*60)
    print("🚀 AGENTIC HONEY-POT API TEST SUITE")
    print("="*60)
    print(f"API URL: {API_URL}")
    print(f"API Key: {API_KEY[:10]}...")
    
    # Test 1: Health Check
    if not test_health_check():
        print("\n❌ Health check failed. Please check if server is running.")
        return
    
    # Test 2: Authentication
    if not test_authentication():
        print("\n❌ Authentication failed. Please check your API key.")
        return
    
    # Test 3: Honeypot Scenarios
    print("\n" + "="*60)
    print("🧪 Running Honeypot Test Scenarios")
    print("="*60)
    
    for scenario in test_scenarios:
        test_honeypot_scenario(scenario)
        time.sleep(3)  # Wait between scenarios
    
    print("\n" + "="*60)
    print("✅ ALL TESTS COMPLETED!")
    print("="*60)
    print("\n📊 Summary:")
    print("- Health check: ✅")
    print("- Authentication: ✅")
    print(f"- Scenarios tested: {len(test_scenarios)}")
    print("\n💡 Next steps:")
    print("1. Check Render logs for intelligence extraction")
    print("2. Verify final callback was sent to GUVI endpoint")
    print("3. Review extracted intelligence in logs")


if __name__ == "__main__":
    print("⚠️  BEFORE RUNNING:")
    print("1. Update API_URL if testing on Render")
    print("2. Update API_KEY to match your environment variable")
    print("3. Make sure server is running (python main.py)")
    print("\nPress Enter to continue or Ctrl+C to cancel...")
    input()
    
    run_all_tests()