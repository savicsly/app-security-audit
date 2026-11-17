# Security Audit Report: {{App name}}

| | |
|---|---|
| **Date** | {{YYYY-MM-DD}} |
| **Prepared for** | {{Owner or team}} |
| **Code reviewed** | {{Repository or folder, commit hash or "files provided on <date>"}} |
| **Type of review** | Static source code security audit (AI-assisted) |
| **Standards applied** | OWASP Top 10:2025{{, OWASP API Security Top 10 (2023)}}{{, OWASP Mobile Top 10 (2024)}}{{, OWASP Top 10 for LLM Applications (2025)}}, CWE |
| **Report version** | 1.0 |

---

## 1. Executive summary

**Overall security posture: {{Critical risk | High risk | Moderate risk | Low risk}}** (within the scope reviewed; see section 8).

{{Two to four sentences in plain language: what the app is, the headline conclusion, and whether it is safe to launch or keep running as is.}}

| Severity | Open | Fixed |
|---|---|---|
| Critical | {{n}} | {{n}} |
| High | {{n}} | {{n}} |
| Medium | {{n}} | {{n}} |
| Low | {{n}} | {{n}} |
| Informational | {{n}} | {{n}} |

**The most important problems**

1. {{Plain-language statement of the top risk and its consequence for users or the business.}} (F-01)
2. {{...}} (F-02)
3. {{...}} (F-03)

**Actions required from you** {{omit this block if none}}

- {{Things only the owner can do: rotate a named key at a named provider, change a dashboard setting, make a design decision.}}

---

## 2. Scope and methodology

**Application.** {{One paragraph: purpose, users, sensitive data handled.}}

**Technology detected and coverage**

| Component | Technology | Coverage tier |
|---|---|---|
| {{Web frontend}} | {{Next.js 15, React 19}} | {{Full}} |
| {{Backend / API}} | {{...}} | {{Full / Generic}} |
| {{Database and auth}} | {{Supabase}} | {{Full / Rules not available}} |
| {{Mobile}} | {{...}} | {{...}} |

**Approach.** Stack detection; attack surface mapping ({{n}} entry points identified); automated checks; manual review of each OWASP category against the code; severity rating by exploitability and impact in this app's context.

**Automated checks**

| Check | Tool | Result |
|---|---|---|
| Pattern scan | Bundled `pattern_scan.py` | {{n leads, n confirmed}} |
| Dependency audit | {{npm audit / pip-audit / ...}} | {{n advisories / Not run: reason}} |
| Secret scan | {{Gitleaks / TruffleHog}} | {{n leads, n confirmed / Not run: reason}} |
| Static analysis | {{Semgrep / Bandit / ...}} | {{n leads, n confirmed / Not run: reason}} |

{{Include this block only if any tool did not run.}}
**Recommended follow-up scans.** These checks did not run in this audit, so the weaknesses they detect were not checked by a tool. Install them and run them, or ask for the audit to be rerun:

| Tool | What it would add | Install | Run |
|---|---|---|---|
| {{Gitleaks}} | {{Secrets across all git history}} | `{{brew install gitleaks}}` | `{{gitleaks detect --source . --redact}}` |

---

## 3. Findings summary

| ID | Finding | Severity | OWASP | Confidence | Status |
|---|---|---|---|---|---|
| F-01 | {{Title}} | Critical | A01:2025 | Confirmed | Open |
| F-02 | {{Title}} | High | {{...}} | {{...}} | {{...}} |

---

## 4. Detailed findings

### F-01: {{Specific title naming the flaw and where}}

**Severity:** {{...}} · **Confidence:** {{...}} · **OWASP:** {{A0X:2025 Name}} · **CWE:** {{CWE-nnn}} · **Status:** {{Open}}

**Location:** `{{path/to/file}}`, lines {{n to m}}

**What is wrong.** {{Two to four sentences specific to this code.}}

**Evidence.**
```{{lang}}
{{Relevant code, trimmed; secrets masked}}
```

**Impact.** {{What an attacker gains, in concrete terms for this app.}}

**How it could be abused.** {{Brief conceptual attack path.}}

**Fix.** {{Explanation, then corrected code; plus any non-code steps.}}
```{{lang}}
{{Corrected code}}
```

**How to verify.** {{One or two checks.}}

{{Repeat for each finding, in severity order.}}

---

## 5. OWASP Top 10:2025 coverage

| Category | Status | Notes |
|---|---|---|
| A01:2025 Broken Access Control | {{Findings / Reviewed, no issues found / Partially reviewed / Not applicable / Not assessed}} | {{Finding IDs, or what was checked}} |
| A02:2025 Security Misconfiguration | | |
| A03:2025 Software Supply Chain Failures | | |
| A04:2025 Cryptographic Failures | | |
| A05:2025 Injection | | |
| A06:2025 Insecure Design | | |
| A07:2025 Authentication Failures | | |
| A08:2025 Software or Data Integrity Failures | | |
| A09:2025 Security Logging and Alerting Failures | | |
| A10:2025 Mishandling of Exceptional Conditions | | |

{{Add equivalent tables for the API, Mobile and LLM lists only where they applied.}}

---

## 6. What is done well

- {{Specific positive observation, e.g. "Passwords are hashed with bcrypt at cost 12."}}
- {{...}}

---

## 7. Remediation roadmap

**Immediately (before launch, or today if live)**
- {{Critical findings and key rotations, with IDs.}}

**Within the next two weeks**
- {{High findings.}}

**Planned**
- {{Medium and Low findings; hardening.}}

**Ongoing practices**
- {{For example: dependency and secret scanning in CI, a security review before each major release, re-audit after significant changes.}}

---

## 8. Limitations

{{Written for this audit, per the guidance in report-format.md: static review only, coverage tiers, parts not reviewed, tools not run, sampling, the standing caveat that an audit reduces risk and does not prove the absence of vulnerabilities, and the recommendation of an independent penetration test for high-risk applications.}}

---

## Appendix A: Entry points reviewed

| Entry point | Method | Signed-in check | Permission check | Ownership check | Notes |
|---|---|---|---|---|---|
| {{/api/projects/[id]}} | {{GET}} | {{Yes}} | {{n/a}} | {{No (F-02)}} | |

## Appendix B: Files reviewed in depth

{{List or summary by directory.}}

## Appendix C: Document history

| Version | Date | Change |
|---|---|---|
| 1.0 | {{date}} | Initial audit |
