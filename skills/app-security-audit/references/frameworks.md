# Security frameworks used in the audit

Contents: OWASP Top 10:2025 (web) · OWASP API Security Top 10 (2023) · OWASP Mobile Top 10 (2024) · OWASP Top 10 for LLM Applications (2025) · ASVS, MASVS, CWE, CVSS · Keeping this current

Use the IDs below exactly as written. The Top 10:2025 is the backbone of every report; add the other lists when the detector says they apply.

## OWASP Top 10:2025 (web applications)

Final version published January 2026. It replaced the 2021 list. If you remember the 2021 numbering, note that it changed: server-side request forgery is now part of A01, misconfiguration moved up to A02, supply chain is broader and is A03, and A10 is new.

For each category: what it means, and the questions to answer during review.

**A01:2025 Broken Access Control** (includes SSRF)
Users acting outside their permissions.
- Does every entry point check sign-in, permission for the action, and ownership of the specific record?
- Can changing an ID in a URL, body or query return or modify someone else's data (IDOR)?
- Are admin functions protected on the server, or only hidden in the UI?
- Is authorization enforced only in client code or route guards that the server does not repeat?
- Can the user set fields they should not (role, owner ID, price, verified flag) through mass assignment?
- Does any handler fetch a URL the user supplies? Can it reach internal addresses or cloud metadata?
- Is CORS limited to known origins when credentials are allowed?
- Multi-tenant apps: is every query scoped to the tenant?

**A02:2025 Security Misconfiguration**
- Debug mode, verbose errors, stack traces, or development servers in production settings?
- Default credentials, sample apps, open admin consoles, exposed API docs or database studios?
- Missing security headers (Content-Security-Policy, HSTS, X-Content-Type-Options, frame protection)?
- Cookies without Secure, HttpOnly and SameSite?
- Cloud storage buckets, database rules or security groups open to everyone?
- Directory listing, source maps, `.git` or `.env` reachable from the web root?

**A03:2025 Software Supply Chain Failures**
- Known-vulnerable dependencies (run the audit tools)?
- Lockfile present and committed? Versions pinned?
- Packages that look typosquatted, abandoned, or that an AI assistant may have invented? Verify unfamiliar package names exist and are the intended ones.
- Install scripts, unpinned CI actions, `curl | sh` in build steps?
- Third-party scripts loaded from CDNs without integrity attributes?
- CI secrets exposed to pull requests from forks?

**A04:2025 Cryptographic Failures**
- Secrets, keys or tokens in source code, client bundles or git history?
- Passwords hashed with a slow, salted algorithm (argon2, bcrypt, scrypt), and not MD5, SHA-1, plain SHA-256 or reversible encryption?
- Sensitive data sent over plain HTTP or stored unencrypted where it should not be?
- Security tokens generated with a non-cryptographic random source?
- Hard-coded keys or IVs, ECB mode, home-made crypto, disabled certificate validation?
- JWTs: algorithm pinned, signature verified, secret strong, expiry enforced?

**A05:2025 Injection** (includes cross-site scripting)
- SQL or NoSQL queries built by string concatenation or interpolation?
- User input reaching shell commands, `eval`, template engines, file paths, LDAP or XPath?
- HTML output that bypasses escaping (raw HTML sinks) with user-influenced data?
- NoSQL operator injection through unvalidated JSON bodies?
- Is input validated against a schema on the server at every entry point?

**A06:2025 Insecure Design**
Missing or ineffective controls by design, not by coding slip.
- Rate limiting on login, signup, password reset, OTP, and any costly endpoint?
- Business logic the client can cheat: prices, quantities, discounts, balances computed or trusted from the client?
- Password reset and email change flows: tokens single-use, short-lived, unguessable, bound to the user?
- Multi-step flows that can be entered at a later step?
- Is anything security-relevant decided on the client?

**A07:2025 Authentication Failures**
- Home-made authentication where a maintained library or provider would do?
- Weak password policy, no protection against credential stuffing or brute force?
- Sessions: invalidated on logout and password change, rotated on login, expiring?
- Tokens in places scripts can read when a cookie would be safer? Long-lived tokens with no revocation?
- Account enumeration through different responses for existing and unknown users?
- OAuth: state parameter checked, redirect URIs exact, tokens validated?
- MFA available for sensitive apps, and not bypassable through an alternate endpoint?

**A08:2025 Software or Data Integrity Failures**
- Unsafe deserialization of untrusted data (pickle, unsafe YAML load, PHP unserialize, Java native serialization, Ruby Marshal)?
- Webhooks accepted without verifying the provider's signature?
- Auto-update or plugin loading without integrity checks?
- Client-supplied data trusted for integrity (signed cookies not verified, unsigned JWT accepted)?

**A09:2025 Security Logging and Alerting Failures**
- Are logins, failures, access-control denials and admin actions logged?
- Are passwords, tokens, card numbers or personal data written to logs?
- Would anyone be alerted to an attack in progress? Any monitoring or error tracking at all?
- Can users inject content into logs?

**A10:2025 Mishandling of Exceptional Conditions**
- Empty catch blocks or swallowed errors around security checks?
- Code that fails open: an error in the auth or permission check lets the request through?
- Error responses that leak stack traces, queries, paths or secrets to the client?
- Unhandled promise rejections, missing timeouts, unbounded input sizes that allow denial of service?
- Transactions left half-applied on failure (money debited, order not created)?

## OWASP API Security Top 10 (2023)

Apply when the app exposes an API, which includes almost every modern web and mobile backend.

| ID | Name | Core question |
|---|---|---|
| API1:2023 | Broken Object Level Authorization | Can I read or change another user's object by ID? |
| API2:2023 | Broken Authentication | Can tokens be forged, replayed, or brute-forced? |
| API3:2023 | Broken Object Property Level Authorization | Does the response return fields I should not see, or accept fields I should not set? |
| API4:2023 | Unrestricted Resource Consumption | Are there limits on rate, page size, upload size, query cost, and paid third-party calls? |
| API5:2023 | Broken Function Level Authorization | Can a normal user call admin endpoints? |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Can signup, purchase, or referral flows be automated and abused? |
| API7:2023 | Server Side Request Forgery | Does the API fetch user-supplied URLs? |
| API8:2023 | Security Misconfiguration | Same concerns as A02, at the API layer |
| API9:2023 | Improper Inventory Management | Old API versions, debug or undocumented endpoints still deployed? |
| API10:2023 | Unsafe Consumption of APIs | Is data from third-party APIs trusted without validation? |

## OWASP Mobile Top 10 (2024)

Apply when the project contains a mobile app. A mobile binary is in the attacker's hands: anything in it can be extracted.

| ID | Name | Core question |
|---|---|---|
| M1 | Improper Credential Usage | API keys or secrets bundled in the app? Credentials stored insecurely? |
| M2 | Inadequate Supply Chain Security | Vulnerable or untrusted SDKs and packages? |
| M3 | Insecure Authentication/Authorization | Is authorization enforced on the server, or only in the app? |
| M4 | Insufficient Input/Output Validation | Deep links, intents, WebView content and IPC inputs validated? |
| M5 | Insecure Communication | Cleartext traffic allowed? Certificate validation weakened? |
| M6 | Inadequate Privacy Controls | Excess personal data collected, logged, or sent to third parties? |
| M7 | Insufficient Binary Protections | Debuggable release builds? No obfuscation for sensitive logic? |
| M8 | Security Misconfiguration | Exported components, backup enabled, excessive permissions? |
| M9 | Insecure Data Storage | Tokens or personal data in plain preferences, files, or logs rather than the keystore or keychain? |
| M10 | Insufficient Cryptography | Weak algorithms, hard-coded keys? |

## OWASP Top 10 for LLM Applications (2025)

Apply when the app calls an LLM API or runs a model.

| ID | Name | Core question |
|---|---|---|
| LLM01:2025 | Prompt Injection | Can user or retrieved content override instructions and trigger actions? |
| LLM02:2025 | Sensitive Information Disclosure | Can the model reveal other users' data, secrets or internal context? |
| LLM03:2025 | Supply Chain | Are models, datasets and plugins from trusted sources? |
| LLM04:2025 | Data and Model Poisoning | Can users influence training, fine-tuning or retrieval data? |
| LLM05:2025 | Improper Output Handling | Is model output rendered as HTML, run as code or SQL, or passed to tools without validation? |
| LLM06:2025 | Excessive Agency | Do tools given to the model have more permission than the current user? |
| LLM07:2025 | System Prompt Leakage | Does the system prompt hold secrets or act as the only access control? |
| LLM08:2025 | Vector and Embedding Weaknesses | Is retrieval scoped per user or tenant? |
| LLM09:2025 | Misinformation | Are outputs used for decisions without verification where that matters? |
| LLM10:2025 | Unbounded Consumption | Per-user limits on tokens, requests and cost? Is the provider key server-side? |

The most common finding in practice: the LLM provider key shipped in client code, or an unauthenticated endpoint that proxies to the provider, letting anyone spend the owner's money.

## Supporting standards

**OWASP ASVS (Application Security Verification Standard), version 5.0.** A detailed catalogue of testable requirements in three assurance levels. Use it as the depth checklist when the user wants more rigor than the Top 10, or needs to demonstrate a level of assurance. Level 1 is a sensible target for most small apps; Level 2 for apps holding sensitive data. Cite requirement IDs only when sure of them, since numbering changed between versions 4 and 5.

**OWASP MASVS / MASTG.** The mobile counterpart of ASVS and its testing guide. Reference for mobile audits needing more depth than the Mobile Top 10.

**CWE (Common Weakness Enumeration).** Tag each finding with the most specific CWE you are confident of. Frequently used, well-established IDs:

| CWE | Weakness |
|---|---|
| CWE-22 | Path traversal |
| CWE-78 | OS command injection |
| CWE-79 | Cross-site scripting |
| CWE-89 | SQL injection |
| CWE-200 | Exposure of sensitive information |
| CWE-209 | Error message containing sensitive information |
| CWE-284 | Improper access control (general) |
| CWE-285 | Improper authorization |
| CWE-287 | Improper authentication |
| CWE-306 | Missing authentication for critical function |
| CWE-307 | Improper restriction of excessive authentication attempts |
| CWE-311 | Missing encryption of sensitive data |
| CWE-312 | Cleartext storage of sensitive information |
| CWE-319 | Cleartext transmission of sensitive information |
| CWE-327 | Broken or risky cryptographic algorithm |
| CWE-330 | Insufficiently random values |
| CWE-345 | Insufficient verification of data authenticity |
| CWE-352 | Cross-site request forgery |
| CWE-434 | Unrestricted upload of dangerous file type |
| CWE-502 | Deserialization of untrusted data |
| CWE-532 | Sensitive information in log file |
| CWE-601 | Open redirect |
| CWE-639 | Authorization bypass through user-controlled key (IDOR) |
| CWE-732 | Incorrect permission assignment for critical resource |
| CWE-770 | Allocation of resources without limits |
| CWE-798 | Hard-coded credentials |
| CWE-862 | Missing authorization |
| CWE-863 | Incorrect authorization |
| CWE-915 | Mass assignment |
| CWE-916 | Password hash with insufficient computational effort |
| CWE-918 | Server-side request forgery |
| CWE-942 | Permissive cross-domain policy |
| CWE-1104 | Use of unmaintained third-party components |

**CVSS.** Optional. Give a CVSS v3.1 or v4.0 vector and score when the user wants one or the report is for a compliance audience. The severity rubric in `report-format.md` is the default, since a contextual rating is more useful to a small team than a base score.

**Compliance mappings.** If the user mentions PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR or a local data protection law (for example NDPA in Nigeria), note which findings bear on it. Do not claim the app is or is not compliant; a code audit cannot establish that.

## Keeping this current

These lists are revised every few years. If web access is available and the audit is formal, check owasp.org for a newer edition before finalizing, and state in the report which editions were used.
