#!/usr/bin/env python3
"""Detect the technology stack of an application codebase.

Usage:
    python detect_stack.py <project-root> [--pretty]

Prints JSON describing the stacks found, the evidence for each, the coverage
tier this skill offers ("full" or "generic"), which OWASP lists apply, which
reference files to read, and notable security-relevant files.

Read-only. Uses only the Python standard library.
"""

import json
import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__",
    ".next", ".nuxt", ".svelte-kit", "dist", "build", "out", "target", "Pods",
    ".gradle", ".dart_tool", ".expo", ".idea", ".vscode", "coverage",
    ".turbo", ".cache", "DerivedData", "bower_components", ".terraform",
    "site-packages",
}


SKILL_DIR = Path(__file__).resolve().parent.parent
EXCLUDED = []  # paths skipped as this skill's own files, reported in the output


def _is_own_skill_dir(path: Path) -> bool:
    """True only for the copy of this skill that is running this script.

    Its scripts and references contain the very patterns being searched for,
    so scanning them would only add noise. The match is on the resolved path
    of this script's own skill folder, never on a folder's name or contents,
    so a look-alike folder planted in the project is still scanned. Every
    skipped path is recorded in EXCLUDED and reported.
    """
    try:
        own = path.resolve() == SKILL_DIR
    except OSError:
        return False
    if own:
        EXCLUDED.append(str(path))
    return own


MAX_FILES = 60000

# (dependency name or prefix, stack id)
JS_DEPS = [
    ("next", "nextjs"), ("nuxt", "nuxt"), ("@sveltejs/kit", "sveltekit"),
    ("react-native", "react-native"), ("expo", "expo"),
    ("react", "react"), ("vue", "vue"), ("svelte", "svelte"),
    ("@angular/core", "angular"), ("@remix-run/react", "remix"),
    ("astro", "astro"),
    ("express", "express"), ("@nestjs/core", "nestjs"), ("fastify", "fastify"),
    ("koa", "koa"), ("hono", "hono"),
    ("@supabase/supabase-js", "supabase"), ("@supabase/ssr", "supabase"),
    ("firebase", "firebase"), ("firebase-admin", "firebase"),
    ("firebase-functions", "firebase"),
    ("@react-native-firebase/app", "firebase"),
]
PY_DEPS = [("django", "django"), ("djangorestframework", "django"),
           ("flask", "flask"), ("fastapi", "fastapi"),
           ("supabase", "supabase"), ("firebase-admin", "firebase")]
LLM_DEPS = {
    "openai", "@anthropic-ai/sdk", "anthropic", "langchain", "@langchain/core",
    "llamaindex", "llama-index", "ai", "@ai-sdk/openai", "@ai-sdk/anthropic",
    "@google/generative-ai", "google-generativeai", "google-genai", "cohere",
    "cohere-ai", "replicate", "ollama", "litellm", "mistralai",
    "@mistralai/mistralai", "groq-sdk", "groq", "transformers",
}
DATA_DEPS = {
    "prisma": "Prisma", "@prisma/client": "Prisma", "drizzle-orm": "Drizzle",
    "mongoose": "Mongoose/MongoDB", "mongodb": "MongoDB", "pg": "PostgreSQL (pg)",
    "mysql2": "MySQL", "sequelize": "Sequelize", "typeorm": "TypeORM",
    "knex": "Knex", "sqlalchemy": "SQLAlchemy", "psycopg2": "PostgreSQL",
    "psycopg2-binary": "PostgreSQL", "psycopg": "PostgreSQL",
    "pymongo": "MongoDB", "redis": "Redis", "ioredis": "Redis",
}
AUTH_DEPS = {
    "next-auth": "NextAuth/Auth.js", "@auth/core": "Auth.js",
    "@clerk/nextjs": "Clerk", "@clerk/clerk-expo": "Clerk",
    "@clerk/clerk-react": "Clerk", "@auth0/nextjs-auth0": "Auth0",
    "passport": "Passport", "jsonwebtoken": "jsonwebtoken (custom JWT)",
    "jose": "jose (JWT)", "better-auth": "Better Auth", "lucia": "Lucia",
    "bcrypt": "bcrypt", "bcryptjs": "bcryptjs", "argon2": "argon2",
    "pyjwt": "PyJWT (custom JWT)", "python-jose": "python-jose (custom JWT)",
    "django-allauth": "django-allauth", "flask-login": "Flask-Login",
    "passlib": "passlib", "fastapi-users": "FastAPI Users",
    "djangorestframework-simplejwt": "SimpleJWT",
}
PAYMENT_DEPS = {
    "stripe": "Stripe", "@stripe/stripe-js": "Stripe", "paystack": "Paystack",
    "react-paystack": "Paystack", "paystack-sdk": "Paystack",
    "flutterwave-node-v3": "Flutterwave", "flutterwave-react-v3": "Flutterwave",
    "@paypal/checkout-server-sdk": "PayPal", "razorpay": "Razorpay",
    "@lemonsqueezy/lemonsqueezy.js": "Lemon Squeezy",
}

STACKS = {
    # id: (display name, tier, kind, reference file)
    "nextjs": ("Next.js", "full", "web", "references/stack-javascript.md"),
    "react": ("React (SPA)", "full", "web", "references/stack-javascript.md"),
    "vue": ("Vue", "full", "web", "references/stack-javascript.md"),
    "nuxt": ("Nuxt", "full", "web", "references/stack-javascript.md"),
    "svelte": ("Svelte", "full", "web", "references/stack-javascript.md"),
    "sveltekit": ("SvelteKit", "full", "web", "references/stack-javascript.md"),
    "express": ("Express", "full", "api", "references/stack-javascript.md"),
    "nestjs": ("NestJS", "full", "api", "references/stack-javascript.md"),
    "fastify": ("Fastify", "full", "api", "references/stack-javascript.md"),
    "django": ("Django", "full", "web", "references/stack-python.md"),
    "flask": ("Flask", "full", "web", "references/stack-python.md"),
    "fastapi": ("FastAPI", "full", "api", "references/stack-python.md"),
    "laravel": ("Laravel", "full", "web", "references/stack-php-ruby.md"),
    "rails": ("Ruby on Rails", "full", "web", "references/stack-php-ruby.md"),
    "supabase": ("Supabase", "full", "baas", "references/stack-baas.md"),
    "firebase": ("Firebase", "full", "baas", "references/stack-baas.md"),
    "react-native": ("React Native", "full", "mobile", "references/stack-mobile.md"),
    "expo": ("Expo (React Native)", "full", "mobile", "references/stack-mobile.md"),
    "flutter": ("Flutter", "full", "mobile", "references/stack-mobile.md"),
    "android": ("Native Android (Kotlin/Java)", "full", "mobile", "references/stack-mobile.md"),
    "ios": ("Native iOS (Swift)", "full", "mobile", "references/stack-mobile.md"),
    # generic tier
    "angular": ("Angular", "generic", "web", "references/stack-generic.md"),
    "remix": ("Remix", "generic", "web", "references/stack-generic.md"),
    "astro": ("Astro", "generic", "web", "references/stack-generic.md"),
    "koa": ("Koa", "generic", "api", "references/stack-generic.md"),
    "hono": ("Hono", "generic", "api", "references/stack-generic.md"),
    "node": ("Node.js (no recognized framework)", "generic", "api", "references/stack-generic.md"),
    "python": ("Python (no recognized framework)", "generic", "api", "references/stack-generic.md"),
    "php": ("PHP (no recognized framework)", "generic", "web", "references/stack-generic.md"),
    "go": ("Go", "generic", "api", "references/stack-generic.md"),
    "spring": ("Java / Spring Boot", "generic", "api", "references/stack-generic.md"),
    "java": ("Java / Kotlin (JVM)", "generic", "api", "references/stack-generic.md"),
    "dotnet": (".NET / ASP.NET Core", "generic", "api", "references/stack-generic.md"),
    "rust": ("Rust", "generic", "api", "references/stack-generic.md"),
    "elixir": ("Elixir / Phoenix", "generic", "web", "references/stack-generic.md"),
    "ruby": ("Ruby (no Rails)", "generic", "web", "references/stack-generic.md"),
}


def walk(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not _is_own_skill_dir(Path(dirpath) / d)]
        for name in filenames:
            count += 1
            if count > MAX_FILES:
                return
            yield Path(dirpath) / name


def read(path: Path, limit: int = 400_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def norm_py(name: str) -> str:
    return re.split(r"[\s<>=!~\[;@(]", name.strip(), maxsplit=1)[0].lower().replace("_", "-")


def py_deps_from(path: Path) -> set:
    text = read(path)
    deps = set()
    if path.name.startswith("requirements") or path.suffix == ".txt":
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-")):
                deps.add(norm_py(line))
    else:  # pyproject.toml, Pipfile, setup.py, setup.cfg: loose token match
        for m in re.finditer(r"""["']?([A-Za-z0-9][A-Za-z0-9._-]+)["']?\s*(?:[<>=~!\[]|=\s*["'{])""", text):
            deps.add(norm_py(m.group(1)))
        for m in re.finditer(r"""["']([A-Za-z0-9][A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:[<>=~! ][^"']*)?["']""", text):
            deps.add(norm_py(m.group(1)))
    return deps


class Result:
    def __init__(self):
        self.stacks = {}  # id -> set(evidence)
        self.extras = {"data_layer": set(), "auth": set(), "payments": set(), "llm": set()}
        self.notable = {}

    def add(self, sid: str, evidence: str):
        self.stacks.setdefault(sid, set()).add(evidence)

    def note(self, kind: str, rel: str, cap: int = 25):
        bucket = self.notable.setdefault(kind, [])
        if len(bucket) < cap:
            bucket.append(rel)


def classify_extras(res: Result, deps):
    for d in deps:
        dl = d.lower()
        if dl in LLM_DEPS or dl.startswith(("@ai-sdk/", "@langchain/", "langchain-")):
            res.extras["llm"].add(d)
        if dl in DATA_DEPS:
            res.extras["data_layer"].add(DATA_DEPS[dl])
        if dl in AUTH_DEPS:
            res.extras["auth"].add(AUTH_DEPS[dl])
        if dl in PAYMENT_DEPS:
            res.extras["payments"].add(PAYMENT_DEPS[dl])


def detect(root: Path) -> dict:
    EXCLUDED.clear()
    res = Result()
    package_roots = []
    saw = {"php": False, "rb": False, "py": False}

    for path in walk(root):
        rel = str(path.relative_to(root))
        name = path.name
        low = name.lower()
        parts = path.relative_to(root).parts

        # ---- JavaScript / TypeScript
        if name == "package.json":
            try:
                pkg = json.loads(read(path) or "{}")
            except json.JSONDecodeError:
                pkg = {}
            deps = {}
            if isinstance(pkg, dict):
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    if isinstance(pkg.get(key), dict):
                        deps.update(pkg[key])
            matched = False
            for dep, sid in JS_DEPS:
                if dep in deps:
                    res.add(sid, f"{rel}: {dep}@{deps[dep]}")
                    matched = True
            if deps and not matched:
                res.add("node", f"{rel}: package.json with no recognized framework")
            classify_extras(res, deps.keys())
            package_roots.append(str(path.parent.relative_to(root)) or ".")

        # ---- Python
        elif low.startswith("requirements") and low.endswith(".txt") or name in (
                "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"):
            deps = py_deps_from(path)
            matched = False
            for dep, sid in PY_DEPS:
                if dep in deps:
                    res.add(sid, f"{rel}: {dep}")
                    matched = True
            if not matched and name != "setup.cfg":
                saw["py"] = True
            classify_extras(res, deps)
        elif name == "manage.py":
            res.add("django", f"{rel}")

        # ---- PHP
        elif name == "composer.json":
            text = read(path)
            if "laravel/framework" in text:
                res.add("laravel", f"{rel}: laravel/framework")
            else:
                saw["php"] = True
            for key, label in (("stripe/stripe-php", "Stripe"), ("yabacon/paystack-php", "Paystack"),
                               ("unicodeveloper/laravel-paystack", "Paystack")):
                if key in text:
                    res.extras["payments"].add(label)
            for key in ("openai-php/client", "openai-php/laravel"):
                if key in text:
                    res.extras["llm"].add(key)
        elif name == "artisan":
            res.add("laravel", f"{rel}")

        # ---- Ruby
        elif name == "Gemfile":
            text = read(path)
            if re.search(r"""gem\s+["']rails["']""", text):
                res.add("rails", f"{rel}: rails")
            else:
                saw["rb"] = True
            if re.search(r"""gem\s+["']devise["']""", text):
                res.extras["auth"].add("Devise")
            if re.search(r"""gem\s+["'](pundit|cancancan)["']""", text):
                res.extras["auth"].add("Pundit/CanCanCan")
            if re.search(r"""gem\s+["'](ruby-openai|anthropic)["']""", text):
                res.extras["llm"].add("ruby LLM client")

        # ---- Flutter
        elif name == "pubspec.yaml":
            text = read(path)
            if re.search(r"^\s*flutter\s*:", text, re.M):
                res.add("flutter", f"{rel}")
            if "supabase_flutter" in text:
                res.add("supabase", f"{rel}: supabase_flutter")
            if re.search(r"\b(firebase_core|cloud_firestore|firebase_auth)\b", text):
                res.add("firebase", f"{rel}: firebase packages")
            if re.search(r"\b(dart_openai|google_generative_ai|langchain)\b", text):
                res.extras["llm"].add("dart LLM client")

        # ---- Android
        elif name == "AndroidManifest.xml":
            res.note("android_manifests", rel)
            if "src" in parts and not any(p in ("node_modules",) for p in parts):
                res.add("android", f"{rel}")
        elif name in ("build.gradle", "build.gradle.kts"):
            text = read(path)
            if "com.android.application" in text or "com.android.library" in text:
                res.add("android", f"{rel}: Android Gradle plugin")
            if "org.springframework.boot" in text:
                res.add("spring", f"{rel}: Spring Boot")

        # ---- iOS
        elif name == "Info.plist":
            res.note("ios_plists", rel)
            if not any(p.endswith(".framework") for p in parts):
                res.add("ios", f"{rel}")
        elif name in ("Podfile", "Package.swift"):
            res.add("ios", f"{rel}")

        # ---- Generic-tier ecosystems
        elif name == "go.mod":
            res.add("go", rel)
        elif name == "pom.xml":
            text = read(path)
            res.add("spring" if "spring-boot" in text else "java", rel)
        elif low.endswith((".csproj", ".fsproj", ".sln")):
            res.add("dotnet", rel)
        elif name == "Cargo.toml":
            res.add("rust", rel)
        elif name == "mix.exs":
            res.add("elixir", rel)

        # ---- BaaS config and rules
        if name in ("firebase.json", ".firebaserc"):
            res.add("firebase", rel)
        if low in ("firestore.rules", "storage.rules", "database.rules.json"):
            res.add("firebase", rel)
            res.note("security_rules", rel)
        if len(parts) >= 2 and parts[-2] == "supabase" and name == "config.toml":
            res.add("supabase", rel)
            res.note("security_rules", rel)
        if "supabase" in parts and "migrations" in parts and low.endswith(".sql"):
            res.add("supabase", "supabase/migrations/*.sql")
            res.note("sql_migrations", rel)
        elif low.endswith(".sql") and any(p in ("migrations", "schema", "db", "database", "sql") for p in parts):
            res.note("sql_migrations", rel)
        if name in ("google-services.json", "GoogleService-Info.plist"):
            res.add("firebase", rel)

        # ---- Notable files
        if low == ".env" or low.startswith(".env."):
            res.note("env_files", rel)
        if low in ("dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") \
                or low.startswith("dockerfile."):
            res.note("containers", rel)
        if (".github" in parts and "workflows" in parts) or low in (".gitlab-ci.yml", "bitbucket-pipelines.yml", "jenkinsfile") \
                or ".circleci" in parts:
            res.note("ci_cd", rel)
        if low.endswith((".tf", ".tfvars")) or low.endswith(".tfstate"):
            res.note("infrastructure_as_code", rel)
        if low in ("vercel.json", "netlify.toml", "nginx.conf", ".htaccess", "fly.toml", "render.yaml",
                   "serverless.yml", "app.yaml", "wrangler.toml", "railway.json", "procfile"):
            res.note("hosting_config", rel)
        if low.endswith((".pem", ".p12", ".pfx", ".jks", ".keystore", ".mobileprovision")) \
                or low in ("id_rsa", "id_ed25519", "key.properties") \
                or re.search(r"service[-_]?account.*\.json$", low) or low.endswith(".tfstate"):
            res.note("sensitive_files", rel)
        if low in ("middleware.ts", "middleware.js", "next.config.js", "next.config.mjs", "next.config.ts",
                   "settings.py", "app.json", "app.config.js", "app.config.ts", "nuxt.config.ts",
                   "svelte.config.js", "cors.php", "auth.php", "routes.rb", "web.php", "api.php",
                   "network_security_config.xml"):
            res.note("key_config", rel)
        if low.endswith((".sqlite", ".sqlite3", ".db", ".dump", ".bak")) or low.endswith(".sql.gz"):
            res.note("data_files", rel)

    # Language fallbacks when no framework was recognized
    if saw["py"] and not ({"django", "flask", "fastapi"} & res.stacks.keys()):
        res.add("python", "Python manifest with no recognized web framework")
    if saw["php"] and "laravel" not in res.stacks:
        res.add("php", "composer.json with no recognized framework")
    if saw["rb"] and "rails" not in res.stacks:
        res.add("ruby", "Gemfile without rails")

    # Tidy overlaps
    s = res.stacks
    if "nextjs" in s or "react-native" in s or "expo" in s or "remix" in s:
        # react is implied; keep it only if it is the sole frontend in some package
        if "react" in s:
            implied_roots = set()
            for sid in ("nextjs", "react-native", "expo", "remix"):
                for e in s.get(sid, ()):
                    implied_roots.add(e.split(": ")[0])
            s["react"] = {e for e in s["react"] if e.split(": ")[0] not in implied_roots}
            if not s["react"]:
                del s["react"]
    for parent, child in (("nuxt", "vue"), ("sveltekit", "svelte"), ("expo", "react-native")):
        if parent in s and child in s:
            roots = {e.split(": ")[0] for e in s[parent]}
            s[child] = {e for e in s[child] if e.split(": ")[0] not in roots}
            if not s[child]:
                del s[child]
    if "spring" in s and "java" in s:
        del s["java"]
    # An Android/iOS folder inside a cross-platform project is part of that project
    cross = [k for k in ("react-native", "expo", "flutter") if k in s]
    native_note = None
    if cross:
        for nat in ("android", "ios"):
            if nat in s:
                native_note = "Native android/ and ios/ folders belong to the cross-platform app; review their manifests and plists using the native sections of stack-mobile.md."
                del s[nat]
    stacks_out = []
    kinds = set()
    refs = []
    for sid, evidence in s.items():
        display, tier, kind, ref = STACKS[sid]
        kinds.add(kind)
        if ref not in refs:
            refs.append(ref)
        stacks_out.append({
            "id": sid, "name": display, "coverage_tier": tier, "kind": kind,
            "evidence": sorted(evidence)[:6], "reference": ref,
        })
    stacks_out.sort(key=lambda x: (x["coverage_tier"] != "full", x["name"]))

    has_infra = any(k in res.notable for k in ("containers", "ci_cd", "infrastructure_as_code", "hosting_config"))
    if (has_infra or not stacks_out) and "references/stack-generic.md" not in refs:
        refs.append("references/stack-generic.md")

    frameworks = ["OWASP Top 10:2025"]
    if kinds & {"api", "web", "baas"} or (kinds & {"mobile"}):
        frameworks.append("OWASP API Security Top 10 (2023)")
    if "mobile" in kinds:
        frameworks.append("OWASP Mobile Top 10 (2024)")
    if res.extras["llm"]:
        frameworks.append("OWASP Top 10 for LLM Applications (2025)")

    notes = []
    if not stacks_out:
        notes.append("No recognized stack. Inspect the directory manually and use references/stack-generic.md.")
    if native_note:
        notes.append(native_note)
    if len(package_roots) > 1:
        notes.append(f"Multiple JavaScript packages found ({len(package_roots)}); this may be a monorepo. Treat each app as its own target.")
    if "mobile" in kinds and not (kinds & {"api", "web"}) and "baas" not in kinds:
        notes.append("Mobile app with no backend code detected. Ask whether backend code is available; otherwise list 'backend not reviewed' as a limitation.")
    if "baas" in kinds and not res.notable.get("security_rules") and not res.notable.get("sql_migrations"):
        notes.append("Supabase/Firebase detected but no rules or migrations found in the repository. Ask the user to export them (see references/stack-baas.md).")
    if any(x["coverage_tier"] == "generic" for x in stacks_out):
        notes.append("One or more stacks have generic-tier coverage. Tell the user and state it in the report.")
    if res.notable.get("env_files"):
        notes.append("Env files present. Check whether they are tracked by git and whether they hold live secrets; mask values in any output.")
    if res.notable.get("sensitive_files"):
        notes.append("Key or credential files present in the tree. Check whether they are tracked by git.")

    return {
        "project_root": str(root),
        "stacks": stacks_out,
        "components": {k: sorted(v) for k, v in res.extras.items() if v},
        "frameworks_to_apply": frameworks,
        "references_to_read": ["references/frameworks.md"] + refs,
        "package_roots": sorted(package_roots)[:30],
        "notable_files": res.notable,
        "notes": notes,
        "excluded_paths": list(EXCLUDED),
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        sys.exit(2)
    root = Path(args[0]).resolve()
    if not root.is_dir():
        print(json.dumps({"error": f"not a directory: {root}"}))
        sys.exit(1)
    print(json.dumps(detect(root), indent=2))


if __name__ == "__main__":
    main()
