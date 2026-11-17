# Generic checklist and infrastructure files

Contents: Using this file · Framework-agnostic review · Notes for common generic-tier stacks · Infrastructure and delivery files

## Using this file

Use it for any stack the detector marks `generic` (Go, Java/Spring, .NET, Elixir, Rust, plain PHP and others), and for the infrastructure files in any project. The checks are the same ideas as in the stack-specific files, stated without framework detail. Because you lack a tailored checklist, spend a few minutes first learning how this framework handles routing, authentication middleware, query building, output escaping and configuration, then apply the list.

State in the report that this stack received generic-tier coverage.

## Framework-agnostic review

**Access control (A01).** Enumerate routes from the router or controller annotations. For each: is authentication applied, is the role or permission checked, is the record scoped to the caller? Look for IDs taken from the request and used alone in a lookup. Look for request bodies bound directly to persistence models. Look for server-side fetches of user-supplied URLs.

**Configuration (A02).** Debug or development mode in production config; default credentials; permissive CORS with credentials; missing security headers; admin or actuator or metrics or profiling endpoints exposed; verbose errors.

**Supply chain (A03).** Run the ecosystem's audit tool (see `tooling.md`); lockfile committed; unpinned or unfamiliar dependencies.

**Cryptography and secrets (A04).** Secrets in source or config files; weak password hashing; non-cryptographic randomness for tokens; TLS verification disabled; JWT verification gaps.

**Injection (A05).** String-built SQL; shell execution with user input; template rendering of user-controlled templates; unescaped HTML output; path building from user input.

**Design (A06).** Rate limits on authentication and costly actions; server-side enforcement of prices, quotas and state transitions; sound reset and verification flows.

**Authentication (A07).** Library or home-made; session lifetime, rotation and invalidation; enumeration; brute-force protection.

**Integrity (A08).** Unsafe deserialization; unverified webhooks; unsigned updates.

**Logging (A09).** Security events logged; secrets and personal data kept out of logs.

**Error handling (A10).** Swallowed errors around security checks; fail-open logic; internal details returned to clients; missing timeouts and size limits.

## Notes for common generic-tier stacks

**Go.** `fmt.Sprintf` into `db.Query`/`Exec` (use placeholders). `text/template` used for HTML where `html/template` is needed. `exec.Command("sh", "-c", userInput)`. Ignored errors (`_ =`) on auth or crypto calls. `InsecureSkipVerify: true`. `math/rand` for tokens. HTTP servers without timeouts. Middleware not applied to every route group. Tool: `govulncheck`, `gosec`.

**Java / Spring Boot.** `SecurityFilterChain` with broad `permitAll()` or `csrf().disable()` on cookie-authenticated apps. Missing method security (`@PreAuthorize`) and ownership checks in services. Actuator endpoints exposed (`management.endpoints.web.exposure.include=*`), especially `env` and `heapdump`. JPQL or native queries built by concatenation. Entities bound directly from request bodies. Java native deserialization; XML parsers with external entities enabled. Secrets in `application.properties`/`application.yml`. H2 console enabled. Tool: OWASP Dependency-Check, SpotBugs with FindSecBugs.

**ASP.NET Core.** Controllers or minimal API endpoints missing `[Authorize]`, or `[AllowAnonymous]` applied broadly; no resource-based authorization. `FromSqlRaw`/`ExecuteSqlRaw` with interpolation built outside the safe interpolated overloads. Over-posting: binding entities directly from requests. `Html.Raw` with user data. Developer exception page in production. Secrets in `appsettings.json`. Permissive CORS policy. Antiforgery disabled. `BinaryFormatter` or other unsafe deserializers. Tool: `dotnet list package --vulnerable`.

**Plain PHP (no framework).** Often the highest-risk category: `mysqli_query` with concatenated input, `echo $_GET[...]` without `htmlspecialchars`, `include $_GET[...]`, uploads moved into the web root, `md5` passwords, no CSRF tokens, session fixation, `display_errors` on.

## Infrastructure and delivery files

Review these whenever present, in any project.

**Dockerfile and compose (A02, A04).**
- Secrets passed as `ARG`/`ENV` or copied in (`COPY .env`), which persist in image layers.
- Running as root (no `USER`). Base images on `latest` or long outdated.
- Compose files publishing database, cache or admin ports to all interfaces (`"5432:5432"`), default passwords, `privileged: true`, the Docker socket mounted into a container.
- No `.dockerignore`, so `.git` and env files enter the build context.

**CI/CD (`.github/workflows`, GitLab CI and others) (A03, A08).**
- Secrets written in plain text in workflow files, or echoed to logs.
- `pull_request_target` workflows that check out and run code from the pull request with access to secrets.
- Untrusted input (issue titles, branch names, PR bodies) interpolated directly into `run:` scripts.
- Third-party actions referenced by a mutable tag where a commit hash would be safer; rate Low unless the action has broad access.
- Overly broad `permissions:` or long-lived cloud keys where short-lived federated credentials are available.
- No dependency or secret scanning step: a recommendation, not a vulnerability.

**Infrastructure as code (Terraform, CloudFormation, Kubernetes manifests) (A02).**
- Storage buckets with public access; security groups open to `0.0.0.0/0` on database, SSH or admin ports.
- IAM policies with wildcard actions and resources.
- Unencrypted storage and databases; databases publicly accessible.
- Kubernetes: secrets in plain manifests, privileged containers, host mounts, no resource limits.
- State files (`terraform.tfstate`) committed; they contain secrets.

**Hosting config (`vercel.json`, `netlify.toml`, `nginx.conf`, `.htaccess`) (A02).** Security headers; redirects and rewrites that expose internal paths; directory listing; dotfiles served.

**Repository hygiene (A04, A03).**
- `.gitignore` missing entries for env files, keys, build outputs.
- Database dumps, backups, logs, key files (`.pem`, `.p12`, `.jks`, `id_rsa`) committed.
- If git history is available, a history-aware secret scan (see `tooling.md`), since a deleted secret is still exposed.
