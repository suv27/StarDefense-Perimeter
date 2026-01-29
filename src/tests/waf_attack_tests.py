import requests
import json
import time
import logging
logger = logging.getLogger("uvicorn.error")

BASE_URL = "http://127.0.0.1:8000/login"

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0"
}

TEST_CASES = [
    {
        "name": "Legitimate Login",
        "payload": {"username": "john", "password": "Password123"},
        "headers": HEADERS
    },
    {
        "name": "SQL Injection - OR 1=1",
        "payload": {"username": "admin' OR 1=1 --", "password": "test"},
        "headers": HEADERS
    },
    {
        "name": "SQL Injection - UNION SELECT",
        "payload": {"username": "admin", "password": "UNION SELECT * FROM users"},
        "headers": HEADERS
    },
    {
        "name": "Cross Site Scripting (XSS) - Script Tag",
        "payload": {"username": "<script>alert(1)</script>", "password": "test"},
        "headers": HEADERS
    },
    {
        "name": "Cross Site Scripting (XSS) - IMG onerror",
        "payload": {"username": "<img src=x onerror=alert(1)>", "password": "test"},
        "headers": HEADERS
    },
    {
        "name": "Path Traversal in Username",
        "payload": {"username": "../../etc/passwd", "password": "test"},
        "headers": HEADERS
    },
    {
        "name": "Recon Tool - sqlmap UA",
        "payload": {"username": "test", "password": "test"},
        "headers": {
            **HEADERS,
            "User-Agent": "sqlmap/1.7.2"
        }
    },
    {
        "name": "Recon Tool - curl",
        "payload": {"username": "test", "password": "test"},
        "headers": {
            **HEADERS,
            "User-Agent": "curl/7.88.1"
        }
    },
    {
        "name": "Empty Body",
        "payload": {},
        "headers": HEADERS
    },
    {
        "name": "Oversized Payload",
        "payload": {"username": "A" * 5000, "password": "B" * 5000},
        "headers": HEADERS
    }
]


def run_tests():
    logger.info("\n🛡️ StarDefense WAF Test Suite Starting...\n")

    for idx, test in enumerate(TEST_CASES, start=1):
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
