# Authentication Bypass in "Resumes Management and Job Application Website" application by EGavilan Media

- Vendor Homepage: https://egavilanmedia.com/resumes-management-and-job-application-website/
- Github: https://github.com/EGavilan-Media/Resumes-Management-and-Job-Application-Website-with-PHP-Bootstrap-and-MySQL
- Version 1.0

SQL Injection vulnerability exists in the **Resumes Management and Job Application Website** application login form by EGavilan Media that allows Authentication Bypass. 

> SQL Injection attack consists of inserting an SQL query through the input data from the client into the application. Upon successful misuse, it is possible to retrieve detailed data from the database, edit database data such as inserting, updating or deleting data, work with administrative operations in the database, or in some situations run commands directly on the operating system.

### Steps to reproduce

1. Download, install and run **Resumes Management and Job Application Website** application.
2. Visit the following resource `localhost/login.html`.
3. Enter the below mentioned credentials in the vulnerable field:
  - username: `admin'-- -`
  - password: _anything_

<p align="center">
<img src="https://github.com/martinkubecka/CVE-References/blob/main/images/SQLi-1.png" alt="Vulnerable form">
</p>

5. Press the **Login** button, this will result in a successful Authentication Bypass.

<p align="center">
<img src="https://github.com/martinkubecka/CVE-References/blob/main/images/SQLi-2.png" alt="successful Authentication Bypass">
</p>



Discovered by Martin Kubecka, September 15, 2021.