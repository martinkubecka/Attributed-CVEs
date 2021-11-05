# Stored XSS in "Expense Management System" application by EGavilan Media

- Vendor Homepage: https://egavilanmedia.com/Expense-Management-System/
- Github: https://github.com/EGavilan-Media/Expense-Management-System
- Version 1.0

A stored Cross-Site Scripting (XSS) vulnerability exists in version 1.0 of the **Expense Management System** application by EGavilan Media that allows for arbitrary execution of JavaScript commands.

> A **Cross-Site Scripting** (XSS) attack is a type of malicious script injection on an otherwise harmless and trusted website. XSS attacks occur when an attacker uses a web application to send malicious code, on the browser side, to another end user. Stored XSS attacks are those where the injected script is permanently stored on the target servers. The victim later retrieves the malicious script from the server when it requests the stored information.

### Steps to reproduce

1. Download, install and run **Expense Management System** application.
2. Visit the following resource `localhost/index.php`.
3. Click on the **Add Expense** buttom and fill in the form.
  - Description: `<script>alert(document.cookie);</script>` 
  - Amount: _any number_
  - Date: _any date_

<p align="center">
<img src="https://github.com/martinkubecka/CVE-References/blob/main/images/XSS-1.png" alt="Add Expense">
</p>

5. Press the **Save** button and navigate to the page including our added expense. 
- The result is that the JavaScript command will runs in the description field.

<p align="center">
<img src="https://github.com/martinkubecka/CVE-References/blob/main/images/XSS-2.png" alt="Alert">
</p>


---
Discovered by Martin Kubecka, September 18, 2021.