---
name: app-security-audit
description: Run a full security audit of a web or mobile app codebase, write a professional findings report mapped to OWASP Top 10:2025 (plus OWASP API, Mobile and LLM Top 10, ASVS, CWE), and apply fixes on approval. Detects the stack automatically. Full coverage for Next.js, React, Vue/Nuxt, SvelteKit, Node (Express, NestJS, Fastify), Python (Django, Flask, FastAPI), Laravel, Rails, Supabase, Firebase, React Native/Expo, Flutter, native Android (Kotlin/Java) and iOS (Swift). Generic coverage for other stacks (Go, Spring, .NET and so on). Use this skill whenever the user asks for a security audit, security review, vulnerability scan, pentest-style code review, OWASP check, "is my app secure", "check my app before launch", or wants security holes found or fixed in a codebase, especially AI-generated or vibe-coded apps, even if they never say the word "audit".
---

# App Security Audit

Audit an application's source code for security weaknesses, report them professionally, and fix them with the owner's approval.

The typical user built an app quickly, often with AI assistance, and does not know what they do not know. They need three things: the real problems found, an explanation they can act on, and an honest statement of what was not checked. A report that misses a hole is bad; a report that buries three real holes under forty speculative ones is nearly as bad, because nobody acts on it. Aim for findings that are evidenced, ranked, and fixable.

## Ground rules

These apply throughout, and each exists for a reason.

- **Audit only what the user owns or is authorized to assess.** Work from the code and configuration they give you. Do not send traffic to deployed systems, third-party services, or production databases. If the user asks for live testing of a running app, confirm it is theirs and limit it to a local or staging instance they started for the purpose.
- **Never reproduce a live secret in full.** When a credential is found, show the first four characters and mask the rest. Reports get pasted into chats, tickets and emails, and a report that leaks the key it found makes things worse.
- **Evidence or it is not a finding.** Every finding cites a file and line and shows the relevant code. If you suspect a problem but could not confirm it, record it as "Needs verification" with what would confirm it.
- **The report is sensitive; keep it out of git.** It is a map of exploitable weaknesses. Save it only where git ignores it (Phase 5 gives the steps) and never commit, push or paste it anywhere public.
- **Read-only until told otherwise.** Phases 1 to 5 change nothing in the codebase. Fixes begin only after the user has seen the report and said which ones to apply.
- **Say what was not covered.** A static review cannot see runtime behavior, infrastructure outside the repository, or logic that lives in a third-party dashboard. The limitations section is part of the deliverable, because a reader who assumes full coverage will stop looking.

## Workflow

Six phases. Do them in order; each one feeds the next.

### Phase 1: Identify the app

The bundled scripts are in the `scripts/` folder beside this file. The working directory is usually the user's project, so call them by the full path of that folder (shown below as `<skill-dir>`). Use `python3`, or `python` where that is the Python 3 command. If Python is unavailable, do the detection by reading the manifests yourself and note that the pattern scan was not run.

Run the detector against the project root:

```bash
python3 <skill-dir>/scripts/detect_stack.py <project-root>
```

It prints JSON listing the stacks found, the evidence for each, a coverage tier (`full` or `generic`), which framework lists apply (web, API, mobile, LLM), the reference files to read, and notable files such as env files, security rules and CI configuration.

Then confirm it by reading: open the manifests it points to and look at the directory layout. The detector reads dependency files, so it can miss a stack in an unusual layout or report one that is installed but unused. If the project is a monorepo, treat each app in it as its own audit target and say so in the report.

Tell the user, in two or three sentences, what you detected and the coverage tier before continuing. If a stack is `generic` tier, say plainly that the audit will use framework-agnostic checks and will be less deep than for a fully covered stack.

If no code is available (the user only described the app or gave a URL), explain that this skill audits source code and ask for the repository or files.

### Phase 2: Map the attack surface

Before hunting for bugs, build a short map. Most serious flaws in quickly built apps are missing controls, and a missing control cannot be found by searching for a bad line; it is found by listing what should be protected and checking each item.

Record:

- **Entry points:** every route, API endpoint, server action, RPC function, webhook, deep link, exported mobile component, background job and file upload handler.
- **Trust boundaries:** what runs on the client (untrusted) and what runs on the server; which keys and clients are used on each side.
- **Authentication:** how identity is established, where sessions or tokens live, how they expire.
- **Authorization model:** roles, ownership rules, tenancy. Where is each rule enforced: middleware, per handler, database policy, or nowhere?
- **Data stores and sensitive data:** tables or collections, personal data, payment data, files, secrets.
- **Third parties:** payment, email, storage, auth providers, LLM APIs, analytics.

For a large codebase, list every entry point but read in depth by risk: authentication, anything touching money or personal data, admin functions, file handling, and anything that builds a query or a command.

### Phase 3: Automated checks

Tools find the mechanical problems cheaply, which frees attention for the logic flaws they cannot see. Read `references/tooling.md` for commands per stack.

1. Always run the bundled pattern scan. It needs only Python:

   ```bash
   python3 <skill-dir>/scripts/pattern_scan.py <project-root> --format json > <temp-dir>/pattern_leads.json
   ```

2. Check which tools are available before running any. From `references/tooling.md`, list the tools that apply to this project: a dependency audit for each package manager present, a secret scanner (Gitleaks or TruffleHog), a static analyzer (Semgrep, plus the stack-specific one if there is one), and Trivy or Checkov if there are container or IaC files. Check them all in one pass with `command -v`.

3. If any are missing, stop and tell the user before continuing. Do not skip a missing tool without saying so: a gap the user never heard about looks like full coverage. Give them a short table with each missing tool, what it would catch that this audit would otherwise miss, and the install command for their OS (from the install table in `references/tooling.md`). Then ask which of these they want:
   - **Install now:** you run the install commands, confirm each tool works, and continue. Do this only with the user's yes, because it changes their machine.
   - **They install them:** wait, then recheck with `command -v`.
   - **Continue without them:** proceed and record each one as not run.

   If you cannot ask (a non-interactive or headless run), do not install anything. Continue, and make the gap prominent in the report as described in step 5.

4. Run every tool that is now available.

5. For every applicable tool that did not run, the methodology table says "Not run" with the reason (not installed, user declined, no network) and the exact install and run command. The limitations section names the gap and what it leaves unchecked. If the secret scan or static analysis did not run, also add it to "Actions required from you" in the executive summary, so the owner knows to run it and how.

Treat every tool result as a lead to verify, never as a finding. Open the file, read the surrounding code, and decide whether it is reachable and exploitable. Discard false positives silently; keep a count for the methodology section.

### Phase 4: Manual review

This is where most of the value is. Read `references/frameworks.md` first, then the stack reference files that Phase 1 named. Read only those; the others are irrelevant to this project.

Work through every OWASP Top 10:2025 category against the attack surface map, using the stack reference for what each category looks like in this framework. Add the API, Mobile and LLM lists where Phase 1 says they apply.

Give the most time to access control. It is the top category for good reason and it is where generated code fails most often. For each entry point from Phase 2, answer three questions and write down the answer:

1. Does it check that the caller is signed in?
2. Does it check that the caller is allowed to perform this action (role or function level)?
3. Does it check that the caller may touch this specific record (object level)? Look for handlers that take an ID from the request and fetch by that ID alone.

An endpoint table with these three columns is a useful working document and makes a good appendix.

Then trace untrusted input to dangerous sinks (queries, shell commands, HTML output, file paths, outbound URLs, deserializers, LLM prompts and tool calls), and review the checks that only make sense as a whole: session handling, password reset and email verification flows, payment and webhook verification, rate limiting on expensive or sensitive actions, and error handling that fails open.

Also note what is done well. Positive observations belong in the report; they tell the owner what to keep and make the criticism more credible.

### Phase 5: Report

Read `references/report-format.md` and write the report from `assets/report-template.md`. Follow the template's section order; consistency lets readers compare one audit with the next.

Rate severity with the rubric in `references/report-format.md`, considering this app's context. The same flaw matters more in an app holding payment data than in a to-do list. State a confidence level for each finding.

Write the executive summary for a non-technical owner: what could happen to their users and business, in plain words, with no jargon left unexplained. Write the detailed findings for the developer (or the AI assistant) who will fix them: exact location, the vulnerable code, why it is exploitable, and corrected code for this stack.

The report describes exploitable weaknesses, so it must never reach version control. Never save it to the project root or anywhere git tracks. A report committed and pushed to a public or shared repository gives attackers a map of the app's holes. Before writing it:

1. Save it to `.security-audit/security-audit-report.md` under the project root (other formats go in the same folder), unless the user names another location outside the repository.
2. If the project is a git repository, add `.security-audit/` to `.git/info/exclude` unless it is already listed. That file is a local-only ignore list: it changes no tracked file, so the audit stays read-only. Do not edit `.gitignore` during the audit.
3. Verify it with `git check-ignore -q .security-audit/security-audit-report.md`. If this does not succeed (for example because a `.gitignore` rule re-includes the path), save the report outside the repository instead, such as `~/security-audits/<project-name>/`.
4. When you deliver the report, give its full path and say it is excluded from git on this machine only. Anyone who copies it elsewhere, or a teammate whose clone lacks the exclusion, must keep it out of the repository. Offer to add `.security-audit/` to `.gitignore` as part of Phase 6.

Also check that no earlier audit report is already tracked or sitting unignored in the repository (`git ls-files` and `git status --porcelain` for files such as `*security*audit*report*`). If one is, warn the user straight away; if it was ever pushed, treat its findings as public.

Default output is Markdown. If the user asks for Word or PDF, produce that format using the appropriate document skill if one is available, saved in the same protected folder.

Before delivering, check the report against itself: every finding has a location and evidence, no secret appears unmasked, counts in the summary match the findings, each OWASP category in the coverage matrix has a status, the limitations section reflects what actually happened in this audit, every tool that did not run is listed with its install command, and `git check-ignore` confirms the report file is ignored.

### Phase 6: Fix

Present the report, then ask which findings to fix. Recommend starting with Critical and High.

For each approved fix:

1. Make the smallest change that closes the hole. Do not refactor nearby code; a security patch that also restructures things is hard to review and easy to break.
2. Prefer the framework's built-in protection to a hand-rolled one (parameterized queries, the ORM, the framework's CSRF and escaping, the platform keystore).
3. Fix the class, not just the instance. If one handler lacked an ownership check, search for the same gap in its siblings.
4. Re-verify: rerun the relevant scan, run the project's tests if it has them, and reread the changed code as an attacker would.
5. Record the change in the report: mark the finding Fixed, with the files changed.

Some fixes cannot be done in code, and the user must be told exactly what to do:

- **Exposed secrets must be rotated at the provider.** Removing a key from the code does not un-leak it, and it remains in git history. Tell the user which key, where to rotate it, and to move the new one to server-side environment configuration.
- **Dashboard settings** (database rules deployed from a console, auth provider settings, storage bucket visibility, cloud IAM) need the user to change them; give step-by-step instructions.
- **Design-level problems** (no tenancy model, authorization done entirely in the client) need a decision. Lay out the options and their cost; do not quietly pick one.

Finish with an updated report showing the status of every finding and what remains open.

## Calibration

A few judgment calls come up in almost every audit.

- **Client-side keys that are meant to be public** (Supabase anon key, Firebase web config, Stripe publishable key, map keys) are not secrets. The finding, if any, is whatever protects the data behind them: row level security, Firebase rules, key restrictions. Reporting the public key itself as a leak is a common false positive that damages the report's credibility.
- **Test files, fixtures, seed scripts and examples** often contain fake credentials and deliberately unsafe code. Check whether the value is real and whether the code ships before reporting.
- **Framework defaults** protect a lot. Do not report missing output escaping in a React or Django template that escapes by default; report the places that opt out.
- **Dependency advisories** are worth a finding when the vulnerable function is reachable or the package is exposed to untrusted input. Group the rest into one Low or Informational finding with the upgrade command, and avoid one finding per advisory.
- **Do not inflate.** If the app is in decent shape, say so. A short report with two real findings is a good outcome.
- **Do not cite identifiers from memory you are not sure of.** Use the category IDs in `references/frameworks.md`. For CWE numbers and ASVS requirement IDs, cite only ones you are confident are correct; a wrong identifier in a professional report is worse than none.

## Reference files

| File | Read it when |
|---|---|
| `references/frameworks.md` | Always, at the start of Phase 4 |
| `references/tooling.md` | Phase 3 |
| `references/report-format.md` | Phase 5 |
| `references/stack-javascript.md` | Next.js, React, Vue/Nuxt, SvelteKit, Express, NestJS, Fastify |
| `references/stack-python.md` | Django, Flask, FastAPI |
| `references/stack-php-ruby.md` | Laravel, Rails |
| `references/stack-baas.md` | Supabase or Firebase is used |
| `references/stack-mobile.md` | React Native/Expo, Flutter, native Android, native iOS |
| `references/stack-generic.md` | Any stack at `generic` tier, and for infrastructure files (Docker, CI, IaC) |
| `assets/report-template.md` | Phase 5, as the report skeleton |
