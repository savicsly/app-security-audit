# App Security Audit

An AI agent skill that audits a web or mobile app's source code for security weaknesses, writes a professional report mapped to the OWASP Top 10:2025, and fixes the problems you approve.

It was built for apps made quickly, often with AI coding tools, where security was not part of the process. It works in Claude Code, Cursor, VS Code with GitHub Copilot, OpenAI Codex, Gemini CLI, Windsurf, OpenCode, and any other tool that supports the open Agent Skills format.

## Install

Pick one method. All of them install the same skill.

### Option 1: Skills CLI (any tool that supports Agent Skills)

Run this inside your project folder:

```bash
npx skills add savicsly/app-security-audit
```

The full GitHub URL works too:

```bash
npx skills add https://github.com/savicsly/app-security-audit
```

The [Skills CLI](https://github.com/vercel-labs/skills) asks which tools to install for (Claude Code, Cursor, Codex, Copilot and others) and whether to install for this project or globally. Add `-g` for all your projects, or `-a claude-code` to pick a tool without the prompt. The package is called `skills`, plural; `npx skill add` will not work.

### Option 2: Bundled installer (npx)

```bash
npx app-security-audit                       # from npm
npx github:savicsly/app-security-audit       # straight from GitHub, no npm needed
```

It asks which tool you use and where to install. Or skip the questions:

```bash
npx app-security-audit install --agent cursor            # this project, Cursor
npx app-security-audit install --agent vscode            # this project, VS Code (GitHub Copilot)
npx app-security-audit install --agent claude --global   # all your projects, Claude Code
npx app-security-audit install --all --yes               # every supported tool
```

| Tool | `--agent` | This project | All projects (`--global`) |
|---|---|---|---|
| Claude Code | `claude` | `.claude/skills/` | `~/.claude/skills/` |
| Cursor | `cursor` | `.cursor/skills/` | `~/.cursor/skills/` |
| VS Code (GitHub Copilot) | `vscode` | `.github/skills/` | `~/.copilot/skills/` |
| OpenAI Codex | `codex` | `.codex/skills/` | `~/.codex/skills/` |
| Gemini CLI | `gemini` | `.gemini/skills/` | `~/.gemini/skills/` |
| Windsurf | `windsurf` | `.windsurf/skills/` | `~/.codeium/windsurf/skills/` |
| OpenCode | `opencode` | `.opencode/skills/` | `~/.config/opencode/skills/` |
| Shared folder read by several tools | `agents` | `.agents/skills/` | `~/.agents/skills/` |

For any other tool, point the installer at its skills folder: `npx app-security-audit install --dir path/to/skills`.

Other commands: `status` shows where the skill is installed, `uninstall --agent <name>` removes it, and running `install` again updates it (use `npx app-security-audit@latest` to be sure you get the newest version).

The installer only copies files. It has no dependencies, makes no network requests, and collects nothing.

### Option 3: Claude Code plugin

Inside Claude Code:

```
/plugin marketplace add savicsly/app-security-audit
/plugin install app-security-audit@appsec-audit
```

Updates then arrive through `/plugin`.

### Option 4: Manual

Copy the `skills/app-security-audit` folder from this repository into your tool's skills folder (see the table above).

## Use

Restart or reload your tool after installing, open the app you want to check, and ask in plain words:

- "Run a security audit on this app."
- "Is my app safe to launch? Check it against the OWASP Top 10."
- "Find and fix the security holes in this codebase."

In Claude Code with the plugin installed you can also type `/app-security-audit:app-security-audit`.

You will get `security-audit-report.md`. Then tell the assistant which findings to fix. Nothing in your code is changed until you have seen the report and chosen.

For the best results:

- Open the whole repository, including backend code, database migrations and rules files.
- If you use Supabase or Firebase and your rules exist only in the dashboard, export them when asked. Those rules are your main protection and cannot be reviewed otherwise.
- Keep the git history if possible, so secrets committed in the past can be found.
- Use a capable model. The manual review depends on the model's reasoning, so results vary between tools and models.

## What it does

1. **Identifies your app.** Detects the languages, frameworks and services in the codebase.
2. **Maps the attack surface.** Lists every route, endpoint and entry point, and what data sits behind them.
3. **Runs automated checks.** A bundled pattern scan, plus dependency, secret and static analysis tools when they are available.
4. **Reviews the code manually.** Works through each security category against your code, concentrating on the flaws scanners cannot see, such as missing permission checks.
5. **Writes a report.** Plain-language summary for the owner; exact locations, evidence and corrected code for the developer.
6. **Fixes what you approve.** Applies minimal patches, re-checks them, and updates the report.

## Stacks covered

**Full coverage** means the skill has a dedicated checklist for that technology: its specific pitfalls, its configuration files, and fixes written in its idiom.

| Area | Full coverage |
|---|---|
| Web frontends and full-stack frameworks | Next.js, React (Vite, Create React App), Vue, Nuxt, Svelte, SvelteKit |
| Node.js backends | Express, NestJS, Fastify |
| Python backends | Django (including Django REST Framework), Flask, FastAPI |
| PHP | Laravel |
| Ruby | Ruby on Rails |
| Backend-as-a-service | Supabase (row level security, storage, edge functions), Firebase (Firestore, Realtime Database and Storage rules, Cloud Functions) |
| Cross-platform mobile | React Native, Expo, Flutter |
| Native mobile | Android (Kotlin, Java), iOS (Swift) |
| Data and auth libraries | Prisma, Drizzle, Mongoose, Sequelize, TypeORM, SQLAlchemy; NextAuth/Auth.js, Clerk, Auth0, Supabase Auth, Firebase Auth, custom JWT |
| Delivery and infrastructure files | Dockerfile, Docker Compose, GitHub Actions and other CI, Terraform, Kubernetes manifests, hosting config |

**Generic coverage** means the skill audits with a framework-agnostic checklist. It will still find many problems, with less depth than a fully covered stack, and the report says so.

| Generic coverage |
|---|
| Go, Java and Spring Boot, .NET and ASP.NET Core, Angular, Remix, Astro, Koa, Hono, plain PHP, plain Node.js or Python without a recognized framework, Rust, Elixir/Phoenix, and anything else |

The skill tells you which tier applies to your project before it starts the review.

**Not covered:** desktop applications, games, embedded firmware, smart contracts, and network or cloud-account penetration testing.

## Security standards applied

| Standard | Used for |
|---|---|
| OWASP Top 10:2025 | Every audit; the backbone of the report |
| OWASP API Security Top 10 (2023) | Apps with an API |
| OWASP Mobile Top 10 (2024) | Mobile apps |
| OWASP Top 10 for LLM Applications (2025) | Apps that call an AI model |
| OWASP ASVS 5.0 and MASVS | Deeper verification on request |
| CWE | Classifying each finding |
| CVSS | Optional scoring on request |

## What the report contains

- Executive summary with an overall risk rating and the top problems in plain language
- Scope, stack detected, coverage tier, and tools run
- Findings table, then each finding in detail: severity, confidence, OWASP category, location, evidence, impact, fix with code, and how to verify the fix
- OWASP Top 10:2025 coverage matrix showing what was examined in every category
- What the app already does well
- A prioritized remediation roadmap
- Limitations: what was not reviewed

## Limits you should know

- **It reviews code; it does not attack your running app.** Problems that only appear at runtime, or in infrastructure outside the repository, may not be found.
- **It reduces risk; it cannot prove an app is secure.** No audit can, automated or human.
- **It is not a compliance certification** (PCI DSS, SOC 2, ISO 27001, HIPAA, GDPR, NDPA), though findings can inform that work.
- **Some fixes need you.** Leaked keys must be rotated at the provider, and dashboard settings must be changed by the account owner. The report lists these separately.
- **Review changes before deploying them.** Test fixes as you would any other code change.
- For apps handling payments, health records, or large volumes of personal data, also commission an independent penetration test before launch.

Only use this skill on code you own or are authorized to assess.

## Requirements

- Node.js 18 or later, for the `npx` installers only
- Python 3, for the bundled scanner scripts (standard library only). Without it the audit still runs, minus the pattern scan.
- Optional tools that improve coverage when installed: Semgrep, Gitleaks, OSV-Scanner, and the audit command for your package manager (`npm audit`, `pip-audit`, `composer audit`, `bundle audit`)

## Repository layout

```
app-security-audit/
├── bin/cli.js                    npx installer
├── package.json
├── .claude-plugin/
│   ├── plugin.json               Claude Code plugin manifest
│   ├── marketplace.json          Lets Claude Code install from this repository
│   └── icon.png
└── skills/app-security-audit/
    ├── SKILL.md                  Workflow the assistant follows
    ├── scripts/
    │   ├── detect_stack.py       Identifies the stack and coverage tier
    │   └── pattern_scan.py       Sweep for secrets and risky patterns (values masked)
    ├── references/               OWASP lists, per-stack checklists, tooling, report guidance
    └── assets/report-template.md
```

## Releasing (maintainers)

1. Change the skill files under `skills/app-security-audit/`.
2. Raise the version in both `package.json` and `.claude-plugin/plugin.json`; Claude Code uses the plugin version to detect updates.
3. Check: `node bin/cli.js targets`, `claude plugin validate .`, `npm pack --dry-run`.
4. Commit and push to `main` (the Skills CLI and Claude Code plugin read from GitHub), then `npm publish`.

Keep the installer dependency-free and never add install scripts: people trust this package with their code.

## License

MIT
