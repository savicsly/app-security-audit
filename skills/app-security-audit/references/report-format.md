# Report format

Contents: Audiences · Severity rubric · Confidence levels · Overall posture rating · Writing findings · Example finding · Coverage matrix statuses · Limitations wording · After fixes

## Audiences

The report has two readers. The owner reads the executive summary and the roadmap and decides what to do; assume no security background. The developer (often an AI coding assistant) reads the detailed findings and implements fixes; give exact locations and working code. Write each section for its reader.

Use the skeleton in `assets/report-template.md` and keep its section order.

## Severity rubric

Rate by what an attacker can realistically do to this app, combining how easy the attack is with how bad the result is.

| Severity | Meaning | Typical examples |
|---|---|---|
| **Critical** | Exploitable now by anyone on the internet with little skill; leads to full compromise or mass data exposure | Database open to the public key; service-role or admin credential in client code; unauthenticated admin endpoint; SQL injection on a public endpoint; remote code execution; payment webhook accepted without verification |
| **High** | Serious impact but needs an account, a specific condition, or some skill; or exposes one user at a time | IDOR between authenticated users; stored XSS; privilege escalation through mass assignment; weak password hashing; a live third-party secret in the repository; no rate limit on login with weak password rules |
| **Medium** | Meaningful weakness with limited impact or notable preconditions | Reflected XSS needing interaction; CSRF on a moderately sensitive action; permissive CORS without a demonstrated exploit path; verbose errors leaking internals; missing rate limits on non-auth endpoints; tokens in web storage |
| **Low** | Minor weakness or defence-in-depth gap | Missing security headers; outdated dependency with no reachable vulnerable path; overly long session lifetime; missing lockfile |
| **Informational** | Not a vulnerability; good practice or an observation | No security logging; no automated scanning in CI; hardening suggestions |

Adjust for context and say why when you do. The same IDOR is Critical if the records are medical or financial and exposed to anyone who can sign up freely. A debug flag is Critical if the deployment config shows it reaching production, Low if it is clearly local-only.

When several weaknesses combine into a worse attack (open signup plus "any authenticated user" rules), describe the chain in the more severe finding and cross-reference.

A CVSS vector and score may be added in the finding's metadata when the user wants it; it supplements this rating and does not replace it.

## Confidence levels

| Confidence | Use when |
|---|---|
| **Confirmed** | The code path was read end to end and the flaw is evident, or a tool result was verified in the code |
| **Likely** | The flaw is evident in the code reviewed, but a control might exist somewhere that could not be seen (a gateway, dashboard rules, middleware in another repository) |
| **Needs verification** | A reasonable suspicion that needs runtime testing or information you do not have; say exactly what would confirm it |

Do not rate Critical with "Needs verification" without explaining what you saw and why it warrants urgency anyway.

## Overall posture rating

One line in the executive summary, to orient the owner:

- **Critical risk:** at least one Critical finding. Do not launch, or act immediately if already live.
- **High risk:** no Critical, one or more High.
- **Moderate risk:** Medium findings at most.
- **Low risk:** only Low and Informational findings within what was reviewed.

Always follow it with the scope caveat: the rating reflects only what this audit covered.

## Writing findings

Each finding uses these fields, in this order.

- **ID and title.** `F-01`, numbered in severity order. The title names the flaw and where: "Any signed-in user can read every invoice (`/api/invoices/[id]`)". Avoid bare category names like "Broken Access Control".
- **Metadata line.** Severity · Confidence · OWASP category ID and name · CWE if confident · additional list IDs (API, Mobile, LLM) if relevant · Status (Open, Fixed, Accepted, Needs owner action).
- **Location.** File path and line or line range; list all affected locations when the flaw repeats.
- **What is wrong.** Two to four sentences, specific to this code.
- **Evidence.** The relevant code excerpt, trimmed to what matters, with any secret masked (first four characters, then asterisks).
- **Impact.** What an attacker gains, in concrete terms for this app: whose data, what action, what cost. One short paragraph a non-specialist can follow.
- **How it could be abused.** A brief conceptual description of the attack path, enough for the developer to understand and test the fix locally. Keep it to the shape of the request and the precondition. Do not write a ready-to-run exploit against the deployed app.
- **Fix.** The corrected code for this stack, minimal and idiomatic, plus any non-code steps (rotate the key, change a dashboard setting). If there are sound alternatives, name the recommended one.
- **How to verify.** One or two checks the developer can perform after fixing: a request that should now return 403 or 404, a test to add, a scan to rerun.

Keep findings distinct. Merge repeated instances of the same root cause into one finding with several locations; split findings that have different fixes.

## Example finding

> ### F-02: Any signed-in user can read and edit any project (`app/api/projects/[id]/route.ts`)
>
> **Severity:** High · **Confidence:** Confirmed · **OWASP:** A01:2025 Broken Access Control · **CWE:** CWE-639 · **API:** API1:2023 · **Status:** Open
>
> **Location:** `app/api/projects/[id]/route.ts`, lines 8 to 31 (GET and PATCH handlers)
>
> **What is wrong.** Both handlers confirm that a session exists, then load the project using only the ID from the URL. Nothing checks that the project belongs to the signed-in user.
>
> **Evidence.**
> ```ts
> const session = await auth();
> if (!session) return new Response("Unauthorized", { status: 401 });
> const project = await db.project.findUnique({ where: { id: params.id } });
> return Response.json(project);
> ```
>
> **Impact.** Anyone who creates a free account can view and change every customer's projects, including the client names and budgets stored in them, by requesting other project IDs. IDs are sequential integers, so all of them can be enumerated in minutes.
>
> **How it could be abused.** A signed-in user requests `/api/projects/<another id>` and receives a project they do not own. The same applies to PATCH.
>
> **Fix.** Scope the query to the owner in both handlers and return 404 when nothing matches.
> ```ts
> const project = await db.project.findFirst({
>   where: { id: params.id, ownerId: session.user.id },
> });
> if (!project) return new Response("Not found", { status: 404 });
> ```
> The same pattern is missing in `app/api/tasks/[id]/route.ts` (lines 10 to 24); fix it there too.
>
> **How to verify.** Sign in as user A, request a project ID belonging to user B, and confirm a 404. Add this case to the API tests.

## Coverage matrix statuses

The OWASP Top 10:2025 matrix lists all ten categories with one status each, so the reader sees what was examined and not only what failed.

| Status | Meaning |
|---|---|
| **Findings** | One or more findings; list their IDs |
| **Reviewed, no issues found** | Examined with the checks in the references; nothing found. Say briefly what was checked |
| **Partially reviewed** | Some of it could not be examined; say what and why |
| **Not applicable** | The category does not apply to this app; say why |
| **Not assessed** | Not examined; say why |

Add matrices for the API, Mobile and LLM lists only when they applied.

"Reviewed, no issues found" is a statement about this review, not a guarantee. Phrase it that way.

## Limitations wording

Write this section for the specific audit. Include whichever of these are true, in plain statements:

- This was a static review of source code at commit `<hash>` (or of the files provided on `<date>`). The running application was not tested.
- Coverage tier per stack, naming any stack that received generic-tier coverage.
- Parts not reviewed: for example backend code not provided, database rules held only in a provider dashboard, infrastructure and cloud configuration outside the repository, third-party services, git history when unavailable.
- Tools that could not be run, why, and what that leaves unchecked (for example: "No secret scanner ran, so git history was checked only by filename, not by content"). Point to the recommended follow-up scans table.
- Paths the bundled scripts excluded as the skill's own installed files (their `excluded_paths` output), if any.
- Large codebases: which areas were read in depth and which were sampled.
- An audit reduces risk and does not prove the absence of vulnerabilities. For applications handling payments, health data or large volumes of personal data, an independent penetration test by a qualified professional is recommended before launch and after major changes.
- The audit was AI-assisted; findings should be reviewed by the development team before changes are deployed.

Do not soften or omit limitations to make the report look more complete.

## After fixes

When fixes are applied, update the same report so it remains the single record:

- Change each finding's Status and add a "Resolution" line: what was changed, in which files.
- Update the summary counts to show open and fixed.
- Keep items needing owner action (key rotation, dashboard settings) visible at the top under "Actions required from you" until the user confirms they are done.
- Add a dated entry to the document history.
