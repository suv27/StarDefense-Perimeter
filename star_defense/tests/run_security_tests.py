# star_defense/tests/run_security_suite.py

import json
import time
import requests
import star_defense.tests.security_scenarios as testcases

BASE_URL = "http://127.0.0.1:8000/login"

BOT_TESTS = [
    {
        "name": "Bot Check: Legit Browser",
        "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
        "payload": {"username": "user", "password": "pass"},
        "expect_status": 200
    },
    {
        "name": "Bot Check: No User Agent",
        "headers": {"Content-Type": "application/json"},
        "payload": {"username": "bot", "password": "bot"},
        "expect_status": 403
    },
    {
        "name": "Bot Check: Curl User Agent",
        "headers": {"User-Agent": "curl/7.68.0", "Content-Type": "application/json"},
        "payload": {"username": "bot", "password": "bot"},
        "expect_status": 403
    }
]

def print_result(name, response, expected_status):
    """Refined helper to validate security expectations"""
    try:
        data = response.json()
    except:
        data = {"message": response.text}

    actual_status = response.status_code
    # A test 'Passes' if the actual status matches what we expected (e.g., 403 for a bot)
    test_passed = (actual_status == expected_status)
    result_icon = "✅ PASS" if test_passed else "❌ FAIL"

    print(f"🔹 {name} -> {result_icon}")
    print(f"   Status: {actual_status} (Expected: {expected_status})")
    print(f"   Message: {data.get('message') or data.get('detail')}")
    
    if "waf" in data:
        waf = data["waf"]
        print(f"   WAF Rule: {waf.get('primary_rule', {}).get('rule_id')} (Confidence: {waf.get('confidence')})")
    print("-" * 50)

def run_security_suite():
    print("\n🛡️  StarDefense Combined Security Suite Starting...\n")
    
    print("=" * 50)
    print("STAGE 1: BOT PROTECTION")
    for test in BOT_TESTS:
        r = requests.post(BASE_URL, json=test["payload"], headers=test["headers"])
        print_result(test["name"], r, test["expect_status"])

    print("=" * 50)
    print("STAGE 2: WAF ATTACK TESTS")
    for test in testcases.TestCases.load_test_cases():
        # Determine expected status: Malicious cases should be 403, Legit should be 200
        # We look at the 'intent' if it exists, otherwise default to 403 for attacks
        expected = 200 if "Legit" in test["name"] else 403
        
        r = requests.post(BASE_URL, headers=test["headers"], data=json.dumps(test["payload"]))
        print_result(test["name"], r, expected)
        time.sleep(0.1)

    print("\n✅ All Security Tests Completed\n")

if __name__ == "__main__":
    run_security_suite()
