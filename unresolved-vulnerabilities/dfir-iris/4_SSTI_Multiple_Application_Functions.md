# Severity Server-Side Template Injection in Multiple Application Functions
---
## Short Vulnerability Summary

A SSTI vulnerability in DFIR-IRIS v2.4.27 and before allows attackers with module management access to execute arbitrary code on the server, potentially leading to full system compromise.

## Vulnerability Summary

During security testing of the **IRIS** (Incident Response Investigation System) web application **v2.4.22**, a high-severity **Server-Side Template Injection** (SSTI) vulnerability was identified across multiple enrichment modules, including VirusTotal, MISP, and Seika. This vulnerability allows a malicious actor with access to the module management interface to inject arbitrary **Jinja2** template code into user-customizable report templates. When enrichment tasks are executed, the application renders these templates using insecure Jinja2 methods, resulting in execution of the injected code on the server. While this exploit requires authenticated access with module management permissions, it enables server-side code execution, potentially leading to full compromise of the host system.

### Technical Details

Functions responsible for generating reports for various enrichment services use Jinja2's Template class directly with unsanitized user input, without employing a secure sandbox environment. The following is a representative example, applicable across multiple vulnerable locations:

File: [iris_vt_module/vt_handler/vt_helper.py](https://github.com/dfir-iris/iris-vt-module/blob/3935df96b6c00e2a53ab2c9eec1dc33834810732/iris_vt_module/vt_handler/vt_helper.py#L122), line 122

```python
from jinja2 import Template
. . .
def gen_hash_report_from_template(html_template, vt_report) -> IrisInterfaceStatus:
    """
    Generates an HTML report for hash, displayed as an attribute in the IOC

    :param html_template: A string representing the HTML template
    :param vt_report: The JSON report fetched with VT API
    :return: IrisInterfaceStatus
    """
    template = Template(html_template)
    context = vt_report

    try:

        rendered = template.render(context)

    except Exception:
        print(traceback.format_exc())
        log.error(traceback.format_exc())
        return IrisInterfaceStatus.I2Error(traceback.format_exc())

    return IrisInterfaceStatus.I2Success(data=rendered)
```

In the code above, `Template(html_template)` directly accepts user-provided template strings without any sandboxing (`SandboxedEnvironment` not used) and the `render()` call executes the template in a fully privileged Jinja2 environment, exposing access to dangerous Python internals and OS modules.

SSTI vulnerability appears in the following locations within the application source:
- [iris_vt_module/vt_handler/vt_helper.py](https://github.com/dfir-iris/iris-vt-module/blob/3935df96b6c00e2a53ab2c9eec1dc33834810732/iris_vt_module/vt_handler/vt_helper.py#L41), line 41,
- [iris_vt_module/vt_handler/vt_helper.py](https://github.com/dfir-iris/iris-vt-module/blob/3935df96b6c00e2a53ab2c9eec1dc33834810732/iris_vt_module/vt_handler/vt_helper.py#L81), line 81,
- [iris_vt_module/vt_handler/vt_helper.py](https://github.com/dfir-iris/iris-vt-module/blob/3935df96b6c00e2a53ab2c9eec1dc33834810732/iris_vt_module/vt_handler/vt_helper.py#L122), line 122,
- [iris_misp_module/misp_handler/misp_handler.py](https://github.com/dfir-iris/iris-misp-module/blob/23bdc0aee6d4ff7d2a4ac653dc28b577eb9f2d1f/iris_misp_module/misp_handler/misp_handler.py#L90), line 90,
- [iris_seika_module/seika_handler/seika_helper.py](https://github.com/dfir-iris/iris-seika-module/blob/1941bebd88699dae5af9e74b096d3f3acfd23869/iris_seika_module/seika_handler/seika_helper.py#L43), line 43,
- [iris_seika_module/seika_handler/seika_helper.py](https://github.com/dfir-iris/iris-seika-module/blob/1941bebd88699dae5af9e74b096d3f3acfd23869/iris_seika_module/seika_handler/seika_helper.py#L83), line 83,
- [iris_seika_module/seika_handler/seika_helper.py](https://github.com/dfir-iris/iris-seika-module/blob/1941bebd88699dae5af9e74b096d3f3acfd23869/iris_seika_module/seika_handler/seika_helper.py#L106), line 106.

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  | 7.2 (**High**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

### Weakness Enumeration

| CWE ID | Description |
|--------|-------------|
| [CWE-XX]() | XXX |
| [CWE-XX]() | XXX |

## Proof of Concept (PoC) Exploit

The following proof of concept demonstrates how an attacker could exploit the SSTI vulnerability in the IRIS web application hosted at `https://localhost/`. This PoC demonstrates how a privileged user can exploit the SSTI vulnerability to read sensitive files on the host system.

### Steps to Reproduce

1. Log into the IRIS web UI with a user account that has module management permissions.
2. Navigate to Manage → Advanced → Modules → IrisVT.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/irisvt_module_information.png" alt="IrisVT Module Information">

3. Modify the value for parameter "Hash report template" field and insert the following payload.

```python
{{ self.__init__.__globals__.__builtins__.__import__("os").popen("cat /etc/passwd").read() }}
```

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/hash_report_template_modification.png" alt="Hash Report Template Modification">


4. Save the changes.
5. Open any available case, navigate to IoCs, and select or create a hash IoC.
6. In the IoC detail view, click the top-right menu and choose "Get VT Insight".
7. Once the enrichment task completes, click "VT Report" in the same view.

The rendered VirusTotal report includes the contents of the `/etc/passwd file`, confirming that arbitrary OS command execution was successfully achieved via the template injection vulnerability.

<img src="https://github.com/martinkubecka/Attributed-CVEs/blob/main/images/dfir_iris/arbitrary_command_execution.png" alt="Arbitrary Command Execution">

## Recommended Mitigations

To mitigate the risk of SSTI vulnerability, the following remediation strategies are recommended:
1. Use **SandboxedEnvironment** from `jinja2.sandbox`.
Instead of directly instantiating templates with `Template(...)`, use a sandboxed environment to safely parse and render templates. This restricts access to unsafe built-ins and helps prevent access to dangerous attributes or execution of arbitrary code, significantly reducing the risk of exploitation.

Example code:

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(html_template)
rendered = template.render(context)
```

2. Validate or sanitize user-defined templates.
When templates are user-provided or modifiable through the UI as in this case, additional security controls should be implemented:
- Disallow access to unsafe methods or attributes, such as `__globals__`, `__builtins__`, `import`, etc.
- Restrict template content by performing input validation or using allowlists for acceptable syntax.
- Consider using a safe subset of Jinja2 syntax or strip out unsupported tags and filters before rendering.

Implementing these controls ensures that only safe, intended operations are allowed when rendering templates.

## Vendor Response & Patch Information

TODO

## References

- https://portswigger.net/web-security/server-side-template-injection
- https://jinja.palletsprojects.com/en/stable/sandbox

## Timeline

- **2025-07-01**: I disclosed the vulnerabilities to the DFIR-IRIS support team.
- **2025-07-01**: No direct response was received from the IRIS support team regarding this disclosure.  
- **2025-09-02**: I followed up with another email to the IRIS support team after conducting a retest of the newly published version v2.4.22. Since no further response was received, I reported that all vulnerabilities were still present in the latest version as of that date.
- **2026-03-22**: I requested a CVE ID from MITRE prior to public disclosure of the vulnerabilities.