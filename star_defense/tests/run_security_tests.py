# star_defense/tests/run_security_tests.py

import time
import requests
import star_defense.tests.security_scenarios as scenarios

BASE_URL = "http://127.0.0.1:8000/login"

# Terminal Colors for Professional Reporting
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_YELLOW = "\033[93m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

def print_result(name, response, expected_status):
    """
    Validates security expectations and prints a detailed, 
    color-coded summary of the WAF/BOT decision.
    """
    try:
        data = response.json()
    except:
        data = {"message": response.text}

    actual_status = response.status_code
    test_passed = (actual_status == expected_status)
    
    # Visual Logic: Icons change based on whether it was a block or an allow
    status_color = C_GREEN if test_passed else C_RED
    result_text = "PASS" if test_passed else "FAIL"
    icon = "🛡️" if actual_status == 403 else "✅" if actual_status == 200 else "⚠️"
    
    print(f"{status_color}{C_BOLD}{result_text} | {icon} {name:<35}{C_END}")
    
    # If the WAF blocked it, show the technical details
    if "waf" in data:
        waf_info = data["waf"]
        rule = waf_info.get("primary_rule", {})
        print(f"      {C_CYAN}↳ WAF Match: [{rule.get('rule_id')}] {rule.get('rule_name')}{C_END}")
        
        # This helps you understand the "Why" behind the regex match
        if "matched_value" in rule:
            snippet = rule.get('matched_value')[:60]
            print(f"      {C_CYAN}↳ Snippet: {C_YELLOW}{snippet}...{C_END}")
    
    if not test_passed:
        print(f"      {C_RED}↳ Status Mismatch: Got {actual_status}, Expected {expected_status}{C_END}")
        msg = data.get('message') or data.get('detail') or "No error message provided"
        print(f"      {C_RED}↳ Backend Message: {msg}{C_END}")
    
    return test_passed

def run_security_suite():
    print(f"\n{C_BOLD}🚀 StarDefense Perimeter Security Suite v1.2{C_END}")
    print(f"{C_BOLD}Target Endpoint: {BASE_URL}{C_END}\n")
    
    stats = {"total": 0, "passed": 0}
    loader = scenarios.TestCases()

    # --- STAGE 1: BOT PROTECTION ---
    print(f"{C_BOLD}{'='*65}{C_END}")
    print(f"{C_BOLD}STAGE 1: BOT & USER-AGENT PROTECTION{C_END}")
    print(f"{'='*65}")
    
    for test in loader.load_bot_test_cases():
        try:
            r = requests.post(BASE_URL, json=test["payload"], headers=test["headers"], timeout=5)
            if print_result(test["name"], r, test["expect_status"]):
                stats["passed"] += 1
            stats["total"] += 1
        except Exception as e:
            print(f"{C_RED}❌ Connection Error: {e}{C_END}")

    # --- STAGE 2: WAF ATTACK TESTS ---
    print(f"\n{C_BOLD}STAGE 2: OWASP TOP 10 (2025) ATTACK MITIGATION{C_END}")
    print(f"{'='*65}")
    
    for test in loader.load_waf_test_cases():
        # Logic: If 'Legit' is in name, we expect 200. Otherwise, we expect a 403.
        expected = 200 if "Legit" in test["name"] else 403
        
        try:
            r = requests.post(BASE_URL, headers=test["headers"], json=test["payload"], timeout=5)
            if print_result(test["name"], r, expected):
                stats["passed"] += 1
            stats["total"] += 1
        except Exception as e:
            print(f"{C_RED}❌ Connection Error: {e}{C_END}")
        time.sleep(0.05) # Minor delay for log readability

    # --- FINAL SECURITY SCORECARD ---
    score = (stats["passed"] / stats["total"]) * 100
    leaks = stats["total"] - stats["passed"]
    
    print(f"\n{C_BOLD}{'='*65}{C_END}")
    print(f"{C_BOLD}FINAL SECURITY SCORECARD{C_END}")
    print(f"{'='*65}")
    print(f"Total Scenarios Tested:  {stats['total']}")
    print(f"Threats Mitigated:      {C_GREEN}{stats['passed']}{C_END}")
    print(f"Critical Leaks:         {C_RED if leaks > 0 else C_GREEN}{leaks}{C_END}")
    
    # Grading Logic
    grade_color = C_GREEN if score == 100 else C_YELLOW if score > 80 else C_RED
    print(f"\n{C_BOLD}OVERALL GRADE: {grade_color}{score:.1f}%{C_END}")
    
    if score == 100:
        print(f"🏆 {C_GREEN}STATUS: MAXIMUM FORTRESS REACHED - PERIMETER HARDENED{C_END}")
    else:
        print(f"⚠️  {C_RED}STATUS: VULNERABLE - SIGNATURE DATABASE REQUIRES UPDATE{C_END}")
    print(f"{C_BOLD}{'='*65}{C_END}\n")

if __name__ == "__main__":
    run_security_suite()