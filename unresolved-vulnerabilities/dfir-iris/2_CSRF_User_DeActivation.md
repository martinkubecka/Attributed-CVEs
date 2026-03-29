# Cross-site Request Forgery Vulnerability in User Activation and Deactivation Endpoint

## Short Vulnerability Summary

A CSRF vulnerability in DFIR-IRIS v2.4.27 and before allows attackers to (de)activate any user account, leading to denial of service, disruption of operations, or unauthorized access of previously deactivated accounts.

## Vulnerability Summary

During security testing of the **IRIS** (Incident Response Investigation System) web application **v2.4.22**, a high-severity **Cross-Site Request Forgery** (CSRF) vulnerability was identified in the user **activation** (`/manage/users/activate/cur_id`) and **deactivation** (`/manage/users/deactivate/cur_id`) endpoints. This vulnerability allows a malicious actor to activate or deactivate any user account, including administrators. If exploited, it may lead to denial of service, disruption of operations, or unauthorized access of previously deactivated accounts. The exploit requires minimal user interaction, such as an authenticated administrator clicking a link while logged in.

### Technical Details

The `GET /manage/users/activate/cur_id` and `GET /manage/users/deactivate/cur_id` endpoints processes user activation and deactivation requests without requiring or validating a CSRF token. These requests are authenticated solely via the session cookie, which is automatically included in cross-origin requests by the browser if the victim is logged in.

The vulnerable code appears in the following locations within the application source:
- Activation endpoint - [iris-web/source/app/blueprints/rest/manage/manage_users.py](https://github.com/dfir-iris/iris-web/blob/a4bfedaae11033005d61ece9d82a5af677c43512/source/app/blueprints/rest/manage/manage_users.py#L330), line 330,
- Deactivation endpoint - [iris-web/source/app/blueprints/rest/manage/manage_users.py](https://github.com/dfir-iris/iris-web/blob/a4bfedaae11033005d61ece9d82a5af677c43512/source/app/blueprints/rest/manage/manage_users.py#L308), line 308.

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  | 7.3 (**High**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:H` |

## Proof of Concept (PoC) Exploit

The following proof of concept demonstrates how an attacker could exploit the CSRF vulnerability in the IRIS web application hosted at `https://localhost/`. In this scenario, an authenticated administrator (user administrator, ID 1) is tricked into deactivating another user (user tester, ID 3) without their knowledge. Note that the same approach applies to the activation endpoint, simply by modifying the target URL to `/manage/users/activate/cur_id`.

### Steps to Reproduce

1. The victim (user administrator) is logged into the IRIS web application with a valid session and the target (user tester) is active.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/user_access_active.png" alt="User Access Active">

2. The attacker crafts a malicious HTML page hosted on a separate domain. The following HTML demonstrates how an attacker could exploit this CSRF vulnerability.

```html
<html>
  <body>
    <form action="https://localhost/manage/users/deactivate/3">
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

3. When the administrator visits attacker’s page, their browser automatically includes the session cookie with the cross-origin request to `https://localhost/manage/users/deactivate/3`.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/user_deactivated.png" alt="User Deactivated">

4. The IRIS server processes the request and deactivates the user tester, without prompting the administrator for confirmation or CSRF validation.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/user_access_deactivated.png" alt="User Access Deactivated">

> *Note: A similar attack could be crafted to re-enable disabled accounts, creating risk of unauthorized access of previously deactivated accounts.*

## Recommended Mitigations

To mitigate this risk effectively, it is recommended to implement CSRF token validation on all state-changing endpoints, enforce appropriate request methods for sensitive operations (e.g., using POST instead of GET), and apply stricter cookie settings to prevent automatic inclusion in cross-origin requests.

## Vendor Response & Patch Information

TODO

## References

- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/preventing
- https://owasp.org/www-community/attacks/csrf

## Timeline

- **2025-06-27**: I disclosed the vulnerabilities to the DFIR-IRIS support team.  
- **2025-07-01**: IRIS support team responded that they will investigate, implement a fix, and publish it, stating they will look into it and address the issue as soon as possible.
- **2025-09-02**: I followed up with another email to the IRIS support team after conducting a retest of the newly published version v2.4.22. Since no further response was received, I reported that all vulnerabilities were still present in the latest version as of that date.
- **2026-03-29**: I requested a CVE ID from MITRE prior to public disclosure of the vulnerabilities.