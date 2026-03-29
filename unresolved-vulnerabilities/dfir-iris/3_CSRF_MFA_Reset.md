# Cross-site Request Forgery Vulnerability in MFA Reset Endpoint

## Short Vulnerability Summary

A CSRF vulnerability in DFIR-IRIS v2.4.27 and before allows attackers to reset MFA configuration for any user account.

## Vulnerability Summary

During security testing of the **IRIS** (Incident Response Investigation System) web application **v2.4.22**, a medium-severity **Cross-Site Request Forgery** (CSRF) vulnerability was identified in the **MFA reset endpoint** (`/manage/access-control/reset-mfa/cur_id`). This vulnerability allows a malicious actor to reset the Multi-Factor Authentication (MFA) configuration for any user account, including administrators. The exploit requires minimal user interaction, such as an authenticated administrator clicking a link while logged in.

### Technical Details

The `GET /manage/access-control/reset-mfa/cur_id` endpoint processes MFA reset requests without requiring or validating a CSRF token. These requests are authenticated solely via the session cookie, which is automatically included in cross-origin requests by the browser if the victim is logged in.

The vulnerable code appears in the following location within the application source:
[iris-web/source/app/blueprints/rest/manage/manage_access_control_routes.py](https://github.com/dfir-iris/iris-web/blob/a4bfedaae11033005d61ece9d82a5af677c43512/source/app/blueprints/rest/manage/manage_access_control_routes.py#L51), line 51.

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  |  6.3 (**Medium**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N` |

## Proof of Concept (PoC) Exploit

The following proof of concept demonstrates how an attacker could exploit the CSRF vulnerability in the IRIS web application hosted at `https://localhost/`. In this scenario, an authenticated administrator (user administrator, ID 1) is tricked into resetting the MFA setup for another user (user tester, ID 3) without their knowledge.

### Steps to Reproduce

1. The victim (user administrator) is logged into the IRIS web application with a valid session, MFA enforcement is enabled, and the target (user tester) has already completed MFA setup.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/global_settings_mfa.png" alt="Global Settings MFA">

2. The attacker crafts a malicious HTML page hosted on a separate domain under their control. The following HTML demonstrates how an attacker could exploit this CSRF vulnerability.

```html
<html>
  <body>
    <form action="https://localhost/manage/access-control/reset-mfa/3">
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

3. When the administrator visits the malicious page, their browser automatically includes the session cookie with the cross-origin request to `https://localhost/manage/access-control/reset-mfa/3`.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/mfa_reset.png" alt="MFA Reset">

4. The IRIS server processes the request and resets the MFA configuration for the user tester, without requiring CSRF validation or administrative confirmation. As a result, the next time the user tester logs in, they will be prompted to reconfigure their MFA device, unaware that their existing configuration was reset by an attacker.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/mfa_setup.png" alt="MFA Setup">

## Note on Severity Escalation

While the CSRF vulnerability in the MFA reset endpoint is rated Medium, its severity escalates to High in the following realistic attack scenario:
1. MFA is enforced on the IRIS instance.
2. The attacker has obtained the username and password of a legitimate user (e.g., via phishing, credential stuffing, etc.).
3. The attacker hosts a malicious HTML page that exploits CSRF vulnerability in the MFA reset endpoint.
4. The attacker tricks an authenticated administrator into visiting the malicious page, which triggers a CSRF request to reset the MFA configuration for the targeted user.
5. The server immediately invalidates the existing MFA configuration for the target account.
6. The attacker then logs in using the stolen credentials. Since the MFA has been reset, the system prompts them to register a new MFA device, which the attacker completes using their own authenticator device.
7. The attacker now has full access to the user’s account, including any elevated privileges they may have. The legitimate user is locked out, unaware that their MFA device has been replaced.

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  | 7.6  (**High**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L` |

## Recommended Mitigations

To mitigate this risk effectively, it is recommended to implement CSRF token validation on all state-changing endpoints, enforce appropriate request methods for sensitive operations (e.g., using POST instead of GET), and apply stricter cookie settings to prevent automatic inclusion in cross-origin requests.

## Vendor Response & Patch Information

TODO

## References

- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/preventing
- https://owasp.org/www-community/attacks/csrf

## Timeline

- **2025-06-30**: I disclosed the vulnerabilities to the DFIR-IRIS support team.  
- **2025-07-01**: IRIS support team responded that they will investigate, implement a fix, and publish it, stating they will look into it and address the issue as soon as possible.
- **2025-09-02**: I followed up with another email to the IRIS support team after conducting a retest of the newly published version v2.4.22. Since no further response was received, I reported that all vulnerabilities were still present in the latest version as of that date.
- **2026-03-29**: I requested a CVE ID from MITRE prior to public disclosure of the vulnerabilities.