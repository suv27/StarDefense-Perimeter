import json
import time
import logging
import requests
import star_defense.tests.test_cases as testcases
# from star_defense.tests.test_cases import TestCases


logger = logging.getLogger("uvicorn.error")

BASE_URL = "http://127.0.0.1:8000/login"

def run_tests():
    logger.info("\n🛡️ StarDefense WAF Test Suite Starting...\n")

    # test_cases = TestCases.load_test_cases()

    for idx, test in enumerate(testcases.TestCases.load_test_cases(), start=1):
        print(f"🔹 Test {idx}: {test['name']}")

        try:
            response = requests.post(
                BASE_URL,
                headers=test["headers"],
                data=json.dumps(test["payload"]),
                timeout=5
            )

            try:
                data = response.json()
            except Exception:
                data = {"raw_response": response.text}

            waf_info = data.get("waf", {})
            action = waf_info.get("action", "UNKNOWN")

            if action == "BLOCK":
                status = "🚫 BLOCKED"
            elif action == "FLAG":
                status = "⚠️ FLAGGED"
            elif action == "ALLOW":
                status = "✅ ALLOWED"
            else:
                status = "❓ UNKNOWN"

            print(f"   Result: {status}")
            print(f"   HTTP Status: {response.status_code}")
            print(f"   WAF Score: {waf_info.get('confidence', {})}")
            print(f"   Severity: {waf_info.get('primary_rule', {}).get('severity')}")
            print(f"   Response: {json.loads(response.text)['message']}")

            if waf_info:
                print(f"   Rule Triggered: {waf_info.get('primary_rule', {}).get('rule_id')}")

        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")

        print("-" * 60)
        time.sleep(0.5)

    print("\n✅ WAF Test Suite Completed\n")


if __name__ == "__main__":
    run_tests()
