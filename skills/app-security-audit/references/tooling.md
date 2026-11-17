# Automated tooling

Contents: Approach · Bundled scripts · Dependency audits · Secret scanning · Static analysis · Framework self-checks · Handling results

## Approach

Run what is available; do not block on what is not. Check with `command -v <tool>` before use. Installing a tool is fine when the environment allows it and it is quick; otherwise record it as "not run" in the report's methodology table. The bundled scripts need only Python 3 and always run.

Run tools from the project root. Send output to files under a temporary directory outside the project (shown as `/tmp` below; use the system temp folder on Windows) and read those, so large outputs do not flood the context. Never run a tool's auto-fix mode during the audit phases (`npm audit fix`, `--fix` flags): the audit is read-only.

## Bundled scripts

```bash
python3 <skill-dir>/scripts/detect_stack.py <root>                      # Phase 1: stack and coverage tier
python3 <skill-dir>/scripts/pattern_scan.py <root> --format json        # Phase 3: leads as JSON
python3 <skill-dir>/scripts/pattern_scan.py <root> --format text        # same, human-readable
python3 <skill-dir>/scripts/pattern_scan.py <root> --min-severity high  # filter
```

`pattern_scan.py` is a regex sweep for hard-coded secrets and well-known risky constructs across all supported stacks. It is deliberately broad. It knows nothing about data flow or context, so expect false positives, and expect it to miss every logic flaw. Its output masks secret values.

## Dependency audits (A03)

| Ecosystem | Detect by | Command |
|---|---|---|
| npm | `package-lock.json` | `npm audit --json` |
| pnpm | `pnpm-lock.yaml` | `pnpm audit --json` |
| Yarn | `yarn.lock` | `yarn npm audit --json` (v2+) or `yarn audit --json` (v1) |
| Python | `requirements*.txt`, `poetry.lock`, `uv.lock` | `pip-audit -r requirements.txt -f json` (install: `pip install pip-audit`) |
| PHP | `composer.lock` | `composer audit --format=json` |
| Ruby | `Gemfile.lock` | `bundle audit check --update` (gem `bundler-audit`) |
| Dart/Flutter | `pubspec.lock` | `dart pub outdated --json`; check advisories with OSV-Scanner |
| Go | `go.mod` | `govulncheck ./...` |
| Java | `pom.xml`, `build.gradle` | OWASP Dependency-Check, or OSV-Scanner |
| .NET | `*.csproj` | `dotnet list package --vulnerable --include-transitive` |
| Any | any lockfile | `osv-scanner scan source -r .` (one tool for most ecosystems) |

Audits that query an online advisory database need network access. If the network is blocked, record that the dependency audit could not run and recommend the user run the command themselves; do not guess at advisories from memory.

If there is no lockfile, the audit cannot be precise. Report the missing lockfile as a finding in its own right (Low) and audit against the manifest's ranges as best the tool allows.

## Secret scanning (A04)

| Tool | Command | Notes |
|---|---|---|
| Gitleaks | `gitleaks detect --source . --report-format json --report-path /tmp/gitleaks.json --redact` | Scans git history by default; add `--no-git` for a plain directory |
| TruffleHog | `trufflehog filesystem . --json` or `trufflehog git file://. --json` | Do not use the verification mode unless the user agrees, since it contacts providers with the found credentials |

Also check directly:

```bash
git ls-files | grep -Ei '(^|/)\.env|\.pem$|\.p12$|\.jks$|\.keystore$|id_rsa|service.?account.*\.json|\.tfstate$'
git log --all --diff-filter=A --name-only --format= | grep -Ei '\.env|\.pem$|service.?account' | sort -u   # ever committed
```

A secret found only in history is still a finding; it must be rotated.

## Static analysis

| Tool | Stacks | Command |
|---|---|---|
| Semgrep | Most languages | `semgrep scan --config auto --json -o /tmp/semgrep.json` (needs network for rules; or `--config p/owasp-top-ten`) |
| Bandit | Python | `bandit -r . -f json -o /tmp/bandit.json -x ./venv,./.venv,./tests` |
| Brakeman | Rails | `brakeman -f json -o /tmp/brakeman.json` |
| gosec | Go | `gosec -fmt=json -out=/tmp/gosec.json ./...` |
| ESLint security plugins | JS/TS | Only if the project already configures them |
| MobSF | Android/iOS | Heavy; suggest to the user for a deeper mobile assessment; do not install during an audit |
| Trivy | Containers, IaC, dependencies | `trivy fs --scanners vuln,secret,misconfig -f json -o /tmp/trivy.json .` |
| Checkov | Terraform, CloudFormation, Kubernetes | `checkov -d . -o json` |

Semgrep is the most valuable general addition when available.

## Framework self-checks

These need the project's dependencies installed and sometimes its environment; skip them if setup would be slow or would require real credentials.

- Django: `python manage.py check --deploy`
- Laravel: `php artisan route:list` (shows middleware per route)
- Rails: `bin/rails routes`
- Supabase and Firebase rule exports: see `stack-baas.md`

Do not start the application, run migrations, or connect to any real database or service during the audit unless the user has asked for that.

## Handling results

1. Merge leads from all tools and remove duplicates (same file and line).
2. For each lead, open the code and decide: confirmed, not exploitable, or needs verification. Check reachability: is the code shipped, is the input user-controlled, is there a control upstream?
3. Promote confirmed leads into findings with your own description and evidence. Tool output is supporting material for the appendix; it does not go into the findings as-is.
4. In the methodology section, give one line per tool: version if known, what it scanned, how many leads, how many confirmed, or why it was not run.
