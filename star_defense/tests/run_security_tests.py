# star_defense/tests/run_security_suite.py

import json
import time
import requests
import star_defense.tests.test_cases as testcases

BASE_URL = "http://127.0.0.1:8000/login"

# 1. Defined Bot Test Cases
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

def print_result(name, response, expected=None):
    """Helper to format the output consistently"""
    try:
        data = response.json()
    except:
        data = {"message": response.text}

    # Determine status icon
    if response.status_code == 403:
        status_icon = "🚫 BLOCKED"
    elif response.status_code == 200:
        status_icon = "✅ ALLOWED"
    else:
        status_icon = f"❓ STATUS {response.status_code}"

    print(f"🔹 {name}")
    print(f"   Result:      {status_icon}")
    print(f"   Message:     {data.get('message') or data.get('detail')}")
    
    # If WAF info exists, show it
    if "waf" in data:
        waf = data["waf"]
        print(f"   WAF Score:   {waf.get('confidence')}")
        print(f"   Rule ID:     {waf.get('primary_rule', {}).get('rule_id')}")
    
    print("-" * 50)

def run_security_suite():
    print("\n🛡️  StarDefense Combined Security Suite Starting...\n")
    print("=" * 50)
    print("STAGE 1: BOT PROTECTION TESTS")
    print("=" * 50)

    for test in BOT_TESTS:
        try:
            r = requests.post(BASE_URL, json=test["payload"], headers=test["headers"], timeout=5)
            print_result(test["name"], r)
        except Exception as e:
            print(f"❌ Connection Error: {e}")

    print("\n" + "=" * 50)
    print("STAGE 2: WAF ATTACK TESTS (Loaded from test_cases.py)")
    print("=" * 50)

    for test in testcases.TestCases.load_test_cases():
        try:
            # We use json.dumps for the payload to match your previous WAF test style
            r = requests.post(BASE_URL, headers=test["headers"], data=json.dumps(test["payload"]), timeout=5)
            print_result(test["name"], r)
        except Exception as e:
            print(f"❌ Connection Error: {e}")
        time.sleep(0.3)

    print("\n✅ All Security Tests Completed\n")

if __name__ == "__main__":
    run_security_suite()