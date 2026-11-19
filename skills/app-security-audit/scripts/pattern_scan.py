#!/usr/bin/env python3
"""Regex sweep for hard-coded secrets and well-known risky code patterns.

Usage:
    python pattern_scan.py <project-root> [--format json|text]
                           [--min-severity critical|high|medium|low]
                           [--max-per-rule N]

Output is a list of LEADS, not findings. Every lead must be verified by
reading the code: this scan has no knowledge of data flow, reachability or
context, produces false positives, and cannot find logic flaws such as
missing authorization.

Secret values are masked in the output. Read-only; standard library only.
"""

import argparse
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


SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    "Gemfile.lock", "poetry.lock", "Pipfile.lock", "pubspec.lock",
    "Podfile.lock", "Cargo.lock", "go.sum", "uv.lock", "bun.lockb",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov",
    ".jar", ".aar", ".apk", ".ipa", ".so", ".dylib", ".dll", ".exe", ".class",
    ".pyc", ".lock", ".map", ".bin", ".wasm", ".keystore", ".jks", ".p12",
}
MAX_FILE_BYTES = 1_000_000
MAX_LINE_LEN = 2000  # skip minified lines

JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
PY = {".py"}
PHP = {".php"}
RB = {".rb", ".erb"}
DART = {".dart"}
KT = {".kt", ".java"}
SWIFT = {".swift", ".m"}
SQL = {".sql"}
CODE = JS | PY | PHP | RB | DART | KT | SWIFT | {".go", ".cs"}
ANY = None  # all text files

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def R(rule_id, title, severity, owasp, pattern, exts=ANY, names=None, secret=False,
      flags=re.I, exclude=None, note=""):
    return {
        "id": rule_id, "title": title, "severity": severity, "owasp": owasp,
        "re": re.compile(pattern, flags), "exts": exts, "names": names,
        "secret": secret, "exclude": re.compile(exclude, re.I) if exclude else None,
        "note": note,
    }


PLACEHOLDER = (r"(your[_-]?|example|placeholder|changeme|change[_-]me|xxxx|<[^>]+>|\$\{|process\.env|"
               r"os\.environ|getenv|env\(|dummy|sample|test[_-]?key|redacted|\*\*\*\*|\.\.\.|todo|insert|"
               r"import\.meta|config\(|secrets\.|vault|null|undefined|none)")

RULES = [
    # ------------------------------------------------------------ secrets (A04)
    R("SEC-PRIVATE-KEY", "Private key material in file", "critical", "A04:2025",
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", secret=True, flags=0),
    R("SEC-AWS-KEY", "AWS access key ID", "critical", "A04:2025",
      r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", secret=True, flags=0),
    R("SEC-STRIPE-LIVE", "Stripe live secret key", "critical", "A04:2025",
      r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}", secret=True, flags=0),
    R("SEC-PAYSTACK-LIVE", "Paystack live secret key", "critical", "A04:2025",
      r"\bsk_live_[0-9a-f]{30,}", secret=True, flags=0),
    R("SEC-FLW-LIVE", "Flutterwave secret key", "critical", "A04:2025",
      r"\bFLWSECK-[0-9A-Za-z]{12,}", secret=True, flags=0, exclude=r"FLWSECK_TEST"),
    R("SEC-SUPABASE-SECRET", "Supabase secret key", "critical", "A04:2025",
      r"\bsb_secret_[0-9A-Za-z_\-]{16,}", secret=True, flags=0),
    R("SEC-OPENAI", "OpenAI API key", "critical", "A04:2025",
      r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}", secret=True, flags=0,
      exclude=r"sk-ant-"),
    R("SEC-ANTHROPIC", "Anthropic API key", "critical", "A04:2025",
      r"\bsk-ant-[A-Za-z0-9_\-]{24,}", secret=True, flags=0),
    R("SEC-GITHUB", "GitHub token", "critical", "A04:2025",
      r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}", secret=True, flags=0),
    R("SEC-SLACK", "Slack token or webhook", "high", "A04:2025",
      r"\bxox[baprs]-[0-9A-Za-z\-]{10,}|hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+",
      secret=True, flags=0),
    R("SEC-SENDGRID", "SendGrid API key", "high", "A04:2025",
      r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", secret=True, flags=0),
    R("SEC-TWILIO", "Twilio API key", "high", "A04:2025",
      r"\bSK[0-9a-f]{32}\b", secret=True, flags=0),
    R("SEC-GOOGLE-API", "Google API key (public for Firebase web config; verify restrictions)", "low", "A04:2025",
      r"\bAIza[0-9A-Za-z_\-]{35}\b", secret=True, flags=0,
      note="Firebase web apiKey is public by design. Report only if it is an unrestricted key for a paid API."),
    R("SEC-SERVICE-ACCOUNT", "Google service account credentials", "critical", "A04:2025",
      r'"type"\s*:\s*"service_account"', secret=False),
    R("SEC-SERVICE-ROLE-JWT", "Supabase service_role JWT literal", "critical", "A04:2025",
      r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]*(?:c2VydmljZV9yb2xl|InNlcnZpY2Vfcm9sZS)[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]{10,}",
      secret=True, flags=0),
    R("SEC-DB-URL", "Database connection string with embedded password", "high", "A04:2025",
      r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@\"']+:[^\s@\"'$<{]{3,}@[^\s\"']+",
      secret=True, exclude=r"(localhost|127\.0\.0\.1|user:pass|username:password|:password@|example|\$\{|<password>|postgres:postgres@(?:db|localhost))"),
    R("SEC-GENERIC-ASSIGN", "Hard-coded credential in assignment", "high", "A04:2025",
      r"""\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret|secret[_-]?key|app[_-]?key)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']""",
      secret=True, exclude=PLACEHOLDER,
      note="Check whether the value is real and whether the file ships. Tests and examples are common false positives."),
    R("SEC-PUBLIC-ENV-SECRET", "Secret-looking variable with a client-exposed prefix", "critical", "A04:2025",
      r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|ADMIN|PASSWORD|DATABASE_URL|DB_URL|OPENAI|ANTHROPIC|GEMINI|SK_|_SK\b)[A-Z0-9_]*",
      flags=0, exclude=r"PUBLISHABLE",
      note="Public-prefixed variables are compiled into the client bundle."),
    R("SEC-SERVICE-ROLE-CLIENT", "service_role key referenced; confirm it is server-only", "high", "A04:2025",
      r"service[_-]?role", exts=JS | DART | KT | SWIFT,
      exclude=r"^\s*(//|\*|#)",
      note="Critical if this file can be bundled for the browser or a mobile app."),
    R("SEC-INSECURE-DEFAULT", "Secret with an insecure fallback default", "medium", "A04:2025",
      r"""(?:SECRET|JWT|KEY|TOKEN|PASSWORD)[A-Z_]*["']?\s*(?:\)|\])?\s*(?:\|\||\?\?)\s*["'][^"']{3,}["']|environ\.get\(\s*["'][A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z_]*["']\s*,\s*["'][^"']{3,}["']""",
      exts=JS | PY, flags=0),

    # ------------------------------------------------------------ injection (A05)
    R("INJ-SQL-JS", "SQL built with template literal or concatenation", "high", "A05:2025",
      r"""\.(?:query|execute|raw|unsafe)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+)""",
      exts=JS),
    R("INJ-PRISMA-UNSAFE", "Prisma raw unsafe query", "high", "A05:2025",
      r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(", exts=JS, flags=0),
    R("INJ-SQL-PY", "SQL built with f-string, format or %", "high", "A05:2025",
      r"""(?:execute|executemany|raw|text)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\.format\(|\+))""", exts=PY),
    R("INJ-SQL-PHP", "SQL with interpolated variable", "high", "A05:2025",
      r"""(?:mysqli_query|->query|DB::(?:select|statement|raw|insert|update|delete)|whereRaw|selectRaw|orderByRaw|havingRaw)\s*\([^;]*["'][^"';]*(?:\$[A-Za-z_{]|["']\s*\.\s*\$)""",
      exts=PHP),
    R("INJ-SQL-RB", "SQL with string interpolation", "high", "A05:2025",
      r"""(?:\.where|\.order|\.find_by_sql|\.joins|\.select|\.pluck|\.execute)\s*\(?\s*["'][^"']*#\{""", exts=RB),
    R("INJ-SQL-ANDROID", "rawQuery/execSQL with concatenation", "high", "A05:2025",
      r"""(?:rawQuery|execSQL)\s*\(\s*["'][^"']*["']\s*\+|(?:rawQuery|execSQL)\s*\(\s*"[^"]*\$""", exts=KT | DART),
    R("INJ-SQL-GENERIC", "SQL built with Sprintf or concatenation", "high", "A05:2025",
      r"""(?:Sprintf|String\.format|string\.Format)\s*\(\s*["'`][^"'`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b""",
      exts={".go", ".java", ".kt", ".cs"}),
    R("INJ-EVAL", "Dynamic code evaluation", "high", "A05:2025",
      r"(?<![\w.])(?:eval|exec)\s*\(\s*(?!['\"]\s*\))[^)]|new\s+Function\s*\(", exts=JS | PY | PHP | RB,
      exclude=r"(\.exec\(|regex|RegExp|re\.|cursor|conn|db\.|session\.|\bexec\s*\(\s*['\"]|#\s*nosec)"),
    R("INJ-CMD-JS", "Shell command with interpolated input", "high", "A05:2025",
      r"""(?:child_process\.)?\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)"'`]*\+)""", exts=JS,
      exclude=r"\.exec\("),
    R("INJ-CMD-PY", "Shell execution", "high", "A05:2025",
      r"os\.system\s*\(|os\.popen\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", exts=PY),
    R("INJ-CMD-PHP", "Shell execution with variable", "high", "A05:2025",
      r"\b(?:shell_exec|passthru|system|popen|proc_open|exec)\s*\([^)]*\$", exts=PHP),
    R("INJ-CMD-RB", "Shell execution with interpolation", "high", "A05:2025",
      r"""(?:\bsystem|\bexec|%x|IO\.popen|Open3\.[a-z0-9_]+)\s*[\(\{\[ ]\s*["'][^"']*#\{|`[^`]*#\{[^`]*`""", exts={".rb"}),
    R("INJ-XSS-REACT", "dangerouslySetInnerHTML", "medium", "A05:2025",
      r"dangerouslySetInnerHTML", exts=JS, flags=0),
    R("INJ-XSS-DOM", "Raw HTML sink (innerHTML, document.write, v-html, @html)", "medium", "A05:2025",
      r"\.(?:innerHTML|outerHTML)\s*=(?!=)|document\.write\s*\(|\bv-html\s*=|\{@html\s|insertAdjacentHTML\s*\(", exts=JS | {".html"}),
    R("INJ-XSS-TEMPLATE", "Template escaping bypassed", "medium", "A05:2025",
      r"\{!!.*!!\}|\|\s*safe\b|mark_safe\s*\(|autoescape\s+off|\.html_safe\b|<%==|\braw\s*\(|\bMarkup\s*\(|Html\.Raw\s*\(",
      exts=PHP | PY | RB | {".html", ".jinja", ".jinja2", ".j2", ".cshtml", ".twig"}),
    R("INJ-SSTI", "Template rendered from a string", "high", "A05:2025",
      r"render_template_string\s*\(|render\s+inline\s*:", exts=PY | RB),
    R("INJ-NOSQL-WHERE", "MongoDB $where or request body passed straight to a query", "medium", "A05:2025",
      r"""["']?\$where["']?\s*:|\.(?:find|findOne|findOneAndUpdate|updateOne|deleteOne|deleteMany)\s*\(\s*req\.(?:body|query)\s*[,)]""",
      exts=JS),
    R("INJ-PATH", "File path built from request input", "medium", "A01:2025",
      r"""(?:sendFile|readFile(?:Sync)?|createReadStream|unlink(?:Sync)?|writeFile(?:Sync)?|send_file|send_from_directory|open|Storage::(?:get|download|delete))\s*\([^)]*(?:req\.(?:params|query|body)|request\.(?:args|form|GET|POST|query_params)|\$request->|\$_(?:GET|POST|REQUEST)|params\[)""",
      exts=JS | PY | PHP | RB),
    R("INJ-INCLUDE-PHP", "include/require with request input", "critical", "A05:2025",
      r"\b(?:include|require)(?:_once)?\s*\(?\s*[^;]*\$_(?:GET|POST|REQUEST|COOKIE)", exts=PHP),

    # ------------------------------------------------------------ integrity (A08)
    R("INT-DESERIALIZE", "Unsafe deserialization", "high", "A08:2025",
      r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|yaml\.unsafe_load|marshal\.loads?\s*\(|Marshal\.load\s*\(|\bunserialize\s*\(|ObjectInputStream\s*\(|BinaryFormatter|jsonpickle\.decode",
      exts=PY | RB | PHP | KT | {".cs"}),

    # ------------------------------------------------------------ access control (A01)
    R("AC-CORS-WILDCARD", "CORS allows any origin", "medium", "A01:2025",
      r"""Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|allow_origins\s*=\s*\[\s*["']\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|origin\s*:\s*(?:["']\*["']|true)\b|['"]allowed_origins['"]\s*=>\s*\[\s*['"]\*|origins\s+['"]\*['"]|\bapp\.use\(\s*cors\(\s*\)\s*\)|\bCORS\(\s*app\s*\)""",
      note="Serious when combined with credentials; otherwise often Low."),
    R("AC-CSRF-DISABLED", "CSRF protection disabled", "medium", "A01:2025",
      r"@csrf_exempt|csrf\(\)\.disable\(\)|csrf\.disable\(\)|skip_forgery_protection|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session|checkOrigin\s*:\s*false|WTF_CSRF_ENABLED\s*=\s*False|IgnoreAntiforgeryToken"),
    R("AC-MASS-ASSIGN", "Request body bound directly to a model", "medium", "A01:2025",
      r"""\.(?:create|update|insert|insertMany|updateOne|findByIdAndUpdate|findOneAndUpdate)\s*\([^)]*\breq\.body\s*[,)]|::create\(\s*\$request->all\(\)|->(?:update|fill)\(\s*\$request->all\(\)|\$guarded\s*=\s*\[\s*\]|params\.permit!|fields\s*=\s*["']__all__["']|\*\*request\.(?:json|data|POST)|Object\.assign\([^,]+,\s*req\.body""",
      note="Check whether the user can set privileged fields (role, owner, price)."),
    R("AC-PERMIT-ALL", "Explicitly public endpoint or open permission", "low", "A01:2025",
      r"AllowAny|permitAll\(\)|\[AllowAnonymous\]|@Public\(\)|skip_before_action\s+:authenticate|authorize\(\)\s*(?::\s*bool\s*)?\{\s*return\s+true",
      note="Confirm each one is meant to be public."),
    R("AC-OPEN-REDIRECT", "Redirect to a request-supplied URL", "medium", "A01:2025",
      r"""redirect(?:_to)?\s*\(?\s*(?:req\.(?:query|body|params)\.|request\.(?:args|GET|POST|query_params)(?:\.get\(|\[)|params\[:|searchParams\.get\(|\$request->(?:input|get|query)\(|\$_GET)""",
      exts=JS | PY | PHP | RB),
    R("AC-SSRF", "Server-side request to a request-supplied URL", "medium", "A01:2025",
      r"""(?:\bfetch|axios(?:\.get|\.post)?|got|requests\.(?:get|post|request)|httpx\.(?:get|post)|urllib\.request\.urlopen|Http::get|file_get_contents|curl_init|Net::HTTP\.get|URI\.open|open-uri)\s*\(\s*(?:req\.(?:query|body|params)\.|request\.(?:args|json|form|GET|POST|query_params)|params\[:|\$request->|\$_(?:GET|POST))""",
      exts=JS | PY | PHP | RB),
    R("AC-FIREBASE-OPEN", "Firebase rule open to everyone", "critical", "A01:2025",
      r"allow\s+[a-z, ]*(?:read|write|create|update|delete|get|list)[a-z, ]*:\s*if\s+true\s*;|allow\s+[a-z, ]+;|\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")",
      names=("firestore.rules", "storage.rules", "database.rules.json"), exts={".rules"}),
    R("AC-FIREBASE-TESTMODE", "Firebase test-mode (time-limited open) rule", "critical", "A01:2025",
      r"request\.time\s*<\s*timestamp\.date", exts={".rules"}),
    R("AC-FIREBASE-AUTHONLY", "Firebase rule allows any signed-in user", "high", "A01:2025",
      r"allow\s+[a-z, ]+:\s*if\s+request\.auth\s*!=\s*null\s*;|\"\.(?:read|write)\"\s*:\s*\"auth\s*!=\s*null\"",
      names=("database.rules.json",), exts={".rules"},
      note="Fine for shared public content; a finding for user-owned data."),
    R("AC-RLS-PERMISSIVE", "Row level security policy with a constant-true condition", "high", "A01:2025",
      r"(?:using|with\s+check)\s*\(\s*true\s*\)", exts=SQL,
      note="Acceptable only for content meant to be public."),
    R("AC-RLS-DISABLED", "Row level security explicitly disabled", "critical", "A01:2025",
      r"disable\s+row\s+level\s+security", exts=SQL),
    R("AC-RLS-AUTHONLY", "RLS policy checks only that the user is signed in", "high", "A01:2025",
      r"(?:using|with\s+check)\s*\(\s*(?:auth\.role\(\)\s*=\s*'authenticated'|auth\.uid\(\)\s+is\s+not\s+null)\s*\)", exts=SQL),
    R("AC-SECURITY-DEFINER", "SECURITY DEFINER function (bypasses RLS)", "medium", "A01:2025",
      r"security\s+definer", exts=SQL, note="Check caller validation and a fixed search_path."),
    R("AC-USER-METADATA", "Authorization based on user-editable user_metadata", "high", "A01:2025",
      r"user_metadata", exts=SQL),
    R("AC-POSTMESSAGE", "postMessage handler or wildcard target; check origin validation", "low", "A01:2025",
      r"""addEventListener\(\s*["']message["']|postMessage\([^)]*,\s*["']\*["']""", exts=JS),

    # ------------------------------------------------------------ misconfiguration (A02)
    R("CFG-DEBUG", "Debug mode enabled", "high", "A02:2025",
      r"^\s*DEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|^\s*APP_DEBUG\s*=\s*true|consider_all_requests_local\s*=\s*true|FLASK_DEBUG\s*=\s*1|android:debuggable\s*=\s*\"true\"|^\s*debuggable\s+true|\bdebuggable\s*=\s*true",
      flags=re.I | re.M, note="Severity depends on whether this configuration reaches production."),
    R("CFG-ALLOWED-HOSTS", "Django ALLOWED_HOSTS wildcard", "medium", "A02:2025",
      r"ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']", exts=PY),
    R("CFG-TLS-DISABLED", "TLS certificate verification disabled", "high", "A04:2025",
      r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|InsecureSkipVerify\s*:\s*true|badCertificateCallback\s*=|onBadCertificate|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|ALLOW_ALL_HOSTNAME_VERIFIER|VERIFY_NONE|ServerCertificateCustomValidationCallback|disableEvaluation|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"),
    R("CFG-CLEARTEXT", "Cleartext traffic permitted (mobile)", "medium", "M5 / A04:2025",
      r"usesCleartextTraffic\s*[=:]\s*\"?true|cleartextTrafficPermitted\s*=\s*\"true\"|NSAllowsArbitraryLoads</key>\s*<true|NSAllowsArbitraryLoads[\"']?\s*:\s*true",
      flags=re.I | re.S),
    R("CFG-ARBITRARY-LOADS", "iOS App Transport Security: arbitrary loads key present", "medium", "M5 / A04:2025",
      r"NSAllowsArbitraryLoads", exts={".plist"}, flags=0, note="Check the value on the following line."),
    R("CFG-ANDROID-BACKUP", "Android backup enabled", "low", "M8 / A02:2025",
      r"android:allowBackup\s*=\s*\"true\"", exts={".xml"}),
    R("CFG-ANDROID-EXPORTED", "Exported Android component", "low", "M8 / A01:2025",
      r"android:exported\s*=\s*\"true\"", exts={".xml"},
      note="Expected for the launcher activity. Check every other one for a permission and input validation."),
    R("CFG-WEBVIEW", "WebView with risky settings", "medium", "M4 / A05:2025",
      r"addJavascriptInterface|setAllowUniversalAccessFromFileURLs\s*\(\s*true|setAllowFileAccessFromFileURLs\s*\(\s*true|originWhitelist=\{\[\s*['\"]\*['\"]|JavaScriptMode\.unrestricted|allowUniversalAccessFromFileURLs|mixedContentMode=[\"']always",
      exts=KT | JS | DART),
    R("CFG-COOKIE-INSECURE", "Cookie security flag disabled", "medium", "A02:2025",
      r"httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|['\"]http_only['\"]\s*=>\s*false|sameSite\s*:\s*[\"']none[\"']",
      note="'secure: false' may be development-only; check how it is set in production."),
    R("CFG-SOURCEMAPS", "Production browser source maps enabled", "low", "A02:2025",
      r"productionBrowserSourceMaps\s*:\s*true", exts=JS),
    R("CFG-GRAPHQL", "GraphQL introspection or playground enabled", "low", "A02:2025",
      r"introspection\s*:\s*true|playground\s*:\s*true|graphiql\s*[:=]\s*true", exts=JS | PY),
    R("CFG-ACTUATOR", "Spring actuator endpoints fully exposed", "high", "A02:2025",
      r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*[\"']?\*", exts={".properties", ".yml", ".yaml"}),
    R("CFG-JWT-VERIFY-OFF", "Supabase Edge Function JWT verification off", "medium", "A07:2025",
      r"verify_jwt\s*=\s*false", exts={".toml"}),
    R("CFG-DOCKER-SECRET", "Possible secret baked into container image", "high", "A04:2025",
      r"^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*[= ]\s*\S{6,}|^\s*COPY\s+\.env",
      names=("dockerfile",), flags=re.I | re.M, exclude=r"\$\{?[A-Z_]+\}?\s*$"),
    R("CFG-COMPOSE-PORT", "Datastore port published on all interfaces", "medium", "A02:2025",
      r"""^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379|9200|5984|11211):""",
      exts={".yml", ".yaml"}, flags=re.M),
    R("CFG-CI-PRT", "pull_request_target workflow trigger", "medium", "A08:2025",
      r"pull_request_target", exts={".yml", ".yaml"},
      note="Dangerous if the workflow checks out and runs pull request code with secrets."),

    # ------------------------------------------------------------ crypto (A04)
    R("CRY-WEAK-HASH", "Weak hash function (verify it is not used for passwords or security)", "medium", "A04:2025",
      r"hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*[\"'](?:md5|sha1)[\"']|\bmd5\s*\(\s*\$|\bsha1\s*\(\s*\$|Digest::(?:MD5|SHA1)|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|CC_MD5\s*\(|Insecure\.(?:MD5|SHA1)|\bmd5\.convert\("),
    R("CRY-PASSWORD-FAST-HASH", "Password hashed with a fast hash", "high", "A04:2025",
      r"(?:sha256|sha512|md5|sha1)\s*\([^)]*passw|createHash\([^)]*\)[^;\n]*passw|hashlib\.[a-z0-9]+\([^)]*passw"),
    R("CRY-WEAK-CIPHER", "Weak cipher or mode", "medium", "A04:2025",
      r"AES/ECB|\bDES(?:ede)?/|[\"']des-|[\"']rc4|aes-\d+-ecb|kCCOptionECBMode|Cipher\.getInstance\(\s*\"AES\"\s*\)|MODE_ECB"),
    R("CRY-WEAK-RANDOM", "Non-cryptographic randomness near a security value", "medium", "A04:2025",
      r"(?:token|secret|otp|password|reset|session|nonce|salt|code|apikey|api_key)\w*\s*[:=][^;\n]*(?:Math\.random\(|random\.(?:random|randint|choice|choices)\(|\brand\(|mt_rand\(|new Random\()|(?:Math\.random\(|random\.(?:randint|choice|choices)\()[^;\n]*(?:token|otp|secret|reset)"),
    R("CRY-JWT", "JWT verification weakened or decode used without verify", "high", "A07:2025",
      r"""verify_signature["']?\s*:\s*False|algorithms\s*[:=]\s*\[\s*["']none["']|["']alg["']\s*:\s*["']none["']|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|\bjwt\.decode\s*\(\s*(?:token|req|auth)[^)]*\)\s*(?:;|$)|jwtDecode\s*\(""",
      exts=JS | PY | RB | PHP | KT | DART, flags=re.I | re.M,
      note="jwt.decode / jwtDecode in JS does not verify signatures. Fine on the client for display; a flaw if a server trusts it."),

    # ------------------------------------------------------------ auth / storage (A07, M9)
    R("STO-WEB-TOKEN", "Token or secret in web storage", "medium", "A07:2025",
      r"(?:localStorage|sessionStorage)\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|secret|password|auth|session)", exts=JS),
    R("STO-MOBILE-TOKEN", "Token or secret in unencrypted mobile storage", "high", "M9",
      r"AsyncStorage\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|secret|password|auth|session|pin)|(?:prefs|preferences|sharedPreferences|SharedPreferences)[\w.()]*\.(?:setString|putString)\(\s*[\"'][^\"']*(?:token|jwt|secret|password|auth|session|pin)|UserDefaults\.standard\.set\([^)]*forKey:\s*\"[^\"]*(?:token|jwt|secret|password|auth|session|pin)",
      exts=JS | DART | KT | SWIFT),
    R("STO-KEYSTORE-CREDS", "Signing credentials in build files", "high", "M1 / A04:2025",
      r"(?:storePassword|keyPassword)\s*[=:]?\s*[\"'][^\"'$]{3,}[\"']|^(?:storePassword|keyPassword)\s*=\s*\S+",
      exts={".gradle", ".kts", ".properties"}, secret=True, flags=re.I | re.M),

    # ------------------------------------------------------------ logging / errors (A09, A10)
    R("LOG-SENSITIVE", "Sensitive value written to a log", "medium", "A09:2025",
      r"(?:console\.(?:log|info|debug|warn|error)|print|println|debugPrint|NSLog|os_log|Log\.[dviwe]|logger\.\w+|logging\.\w+|error_log|Rails\.logger\.\w+|\\?Log::\w+)\s*\([^)\n]*(?:password|passwd|secret|token|authorization|api[_-]?key|card[_-]?number|cvv|\bssn\b|\bpin\b)",
      exts=CODE, exclude=r"(invalid|missing|expired|required|not found|failed|error)[^)\n]{0,40}$"),
    R("ERR-SWALLOWED", "Swallowed exception", "low", "A10:2025",
      r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|except[^:\n]*:\s*(?:pass|\.\.\.)\s*$|rescue\s*(?:=>\s*\w+)?\s*;?\s*(?:nil)?\s*end\b|catch\s*\{\s*\}",
      exts=CODE, flags=re.I | re.M,
      note="Matters when it wraps an authentication, authorization, payment or validation step."),
    R("ERR-STACK-LEAK", "Error details returned to the client", "medium", "A10:2025",
      r"""res\.(?:status\(\d+\)\.)?(?:send|json)\([^)]*(?:err|error|e)\.(?:stack|message)|(?:jsonify|JSONResponse|Response)\([^)]*(?:str\(e\)|traceback|repr\(e\))|display_errors\s*=\s*(?:On|1)|->getTraceAsString\(\)|\$e->getMessage\(\)\s*\]""",
      exts=JS | PY | PHP | {".ini"}),

    # ------------------------------------------------------------ LLM
    R("LLM-BROWSER-KEY", "LLM client configured to run in the browser", "critical", "LLM10:2025 / A04:2025",
      r"dangerouslyAllowBrowser\s*:\s*true", exts=JS, flags=0),
]

def mask(text: str) -> str:
    """Mask long token-like runs so secrets are not echoed."""
    def repl(m):
        tok = m.group(0)
        return tok[:4] + "*" * 8 + f"[{len(tok)} chars]"
    return re.sub(r"[A-Za-z0-9_\-+/=.]{16,}", repl, text)


def mask_match(line: str, m: re.Match) -> str:
    val = m.group(0)
    # keep the identifier part of assignments readable, mask the quoted value
    qm = re.search(r"""["']([^"']{6,})["']\s*$""", val)
    if qm:
        secret = qm.group(1)
        masked_val = val.replace(secret, secret[:4] + "*" * 8 + f"[{len(secret)} chars]")
    else:
        masked_val = val[:4] + "*" * 8 + f"[{len(val)} chars]" if len(val) > 8 else val
    out = line.replace(val, masked_val)
    return mask(out) if out == line else out


def scrub(snippet: str) -> str:
    """Mask anything matching a specific secret rule, whichever rule produced the lead."""
    for rule in RULES:
        if rule["secret"] and rule["id"] != "SEC-GENERIC-ASSIGN":
            snippet = rule["re"].sub(
                lambda m: m.group(0)[:4] + "*" * 8 + f"[{len(m.group(0))} chars]", snippet)
    return snippet


TABLE_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?([a-z_][a-z0-9_]*)\"?\s*\(", re.I)
RLS_ON_RE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?public\"?\.)?\"?([a-z_][a-z0-9_]*)\"?\s+(?:enable|force)\s+row\s+level\s+security", re.I)
OTHER_SCHEMA_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?\"?(?!public\b)[a-z_][a-z0-9_]*\"?\.", re.I)


def is_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(2048)
        return b"\x00" not in chunk
    except OSError:
        return False


def context_hint(rel: str) -> str:
    low = rel.lower()
    if re.search(r"(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|__mocks__|e2e|cypress|playwright)(/|$)|\.(test|spec)\.[a-z]+$|_test\.(go|py|dart)$|test_[^/]+\.py$", low):
        return "test"
    if re.search(r"(^|/)(examples?|samples?|docs?|demo|seeds?|seeders?|stories)(/|$)|\.example$|\.sample$|\.md$|\.stories\.[a-z]+$", low):
        return "example-or-docs"
    return "application"


def scan(root: Path, max_per_rule: int):
    EXCLUDED.clear()
    leads, counts, files_scanned = [], {}, 0
    sql_tables, sql_rls_on, sql_is_supabase = {}, set(), False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not _is_own_skill_dir(Path(dirpath) / d)]
        for name in filenames:
            path = Path(dirpath) / name
            ext = path.suffix.lower()
            low = name.lower()
            if name in SKIP_FILES or ext in BINARY_EXT or low.endswith((".min.js", ".min.css", ".bundle.js")):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if not is_text(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = str(path.relative_to(root))
            hint = context_hint(rel)
            lines = text.splitlines()
            is_env = low == ".env" or low.startswith(".env")

            for rule in RULES:
                by_name = bool(rule["names"]) and any(low == n or low.startswith(n) for n in rule["names"])
                if rule["names"] and rule["exts"] is None:
                    applies = by_name
                elif rule["exts"] is None:
                    applies = True
                else:
                    applies = by_name or ext in rule["exts"]
                if not applies:
                    continue
                if counts.get(rule["id"], 0) >= max_per_rule:
                    continue
                for i, line in enumerate(lines, 1):
                    if len(line) > MAX_LINE_LEN:
                        continue
                    m = rule["re"].search(line)
                    if not m:
                        continue
                    if rule["id"] == "LOG-SENSITIVE":
                        # ignore keywords that only appear inside plain string literals
                        bare = re.sub(r"\"[^\"$#{]*\"|'[^'$#{]*'", '""', line)
                        if not rule["re"].search(bare):
                            continue
                    if rule["exclude"] and rule["exclude"].search(line):
                        continue
                    snippet = line.strip()
                    if rule["secret"]:
                        snippet = mask_match(snippet, m) if m.group(0) in snippet else mask(snippet)
                    elif is_env:
                        snippet = mask(snippet)
                    snippet = scrub(snippet)[:220]
                    counts[rule["id"]] = counts.get(rule["id"], 0) + 1
                    leads.append({
                        "rule": rule["id"], "title": rule["title"],
                        "severity_hint": rule["severity"], "owasp": rule["owasp"],
                        "file": rel, "line": i, "context": hint, "snippet": snippet,
                        **({"note": rule["note"]} if rule["note"] else {}),
                    })
                    if counts[rule["id"]] >= max_per_rule:
                        break

            # Python: except ...: followed by a bare pass on the next line
            if ext == ".py":
                for i, line in enumerate(lines[:-1], 1):
                    if re.match(r"\s*except\b[^:]*:\s*(#.*)?$", line) and re.match(r"\s*(pass|\.\.\.)\s*(#.*)?$", lines[i]):
                        leads.append({
                            "rule": "ERR-SWALLOWED", "title": "Swallowed exception",
                            "severity_hint": "low", "owasp": "A10:2025", "file": rel, "line": i,
                            "context": hint, "snippet": line.strip() + " pass",
                            "note": "Matters when it wraps an authentication, authorization, payment or validation step.",
                        })

            # SQL: remember tables and RLS statements for the cross-file check below
            if ext == ".sql":
                if "supabase" in rel.lower().split(os.sep) or re.search(r"row\s+level\s+security|auth\.uid\(\)", text, re.I):
                    sql_is_supabase = True
                for i, line in enumerate(lines, 1):
                    if OTHER_SCHEMA_RE.search(line):
                        continue
                    m = TABLE_RE.search(line)
                    if m:
                        sql_tables.setdefault(m.group(1).lower(), (rel, i, hint))
                    m = RLS_ON_RE.search(line)
                    if m:
                        sql_rls_on.add(m.group(1).lower())

            # .env files: flag populated secret-looking entries (values masked)
            if is_env and not low.endswith((".example", ".sample", ".template", ".dist")):
                for i, line in enumerate(lines, 1):
                    m = re.match(r"\s*(?:export\s+)?([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE|SERVICE_ROLE|API_KEY|DATABASE_URL)[A-Z0-9_]*)\s*=\s*[\"']?([^\"'\s#]{6,})", line)
                    if m and not re.search(PLACEHOLDER, m.group(2), re.I):
                        v = m.group(2)
                        leads.append({
                            "rule": "SEC-ENV-FILE", "title": "Populated secret in env file",
                            "severity_hint": "high", "owasp": "A04:2025", "file": rel, "line": i,
                            "context": hint,
                            "snippet": f"{m.group(1)}={v[:4]}{'*' * 8}[{len(v)} chars]",
                            "note": "A finding if this file is tracked by git or shipped. Check `git ls-files`.",
                        })

    if sql_is_supabase:
        for table, (rel, line_no, hint) in sorted(sql_tables.items()):
            if table not in sql_rls_on:
                leads.append({
                    "rule": "AC-RLS-MISSING", "title": f"Table '{table}' has no ENABLE ROW LEVEL SECURITY statement in the SQL files",
                    "severity_hint": "critical", "owasp": "A01:2025", "file": rel, "line": line_no,
                    "context": hint, "snippet": f"create table {table} (...)",
                    "note": "Without RLS the table is readable and writable with the public key. RLS may have been enabled in the dashboard; ask the user to confirm (see stack-baas.md).",
                })

    leads.sort(key=lambda l: (SEVERITY_ORDER[l["severity_hint"]], l["context"] != "application", l["file"], l["line"]))
    return leads, files_scanned


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--format", choices=("json", "text"), default="text")
    ap.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="low")
    ap.add_argument("--max-per-rule", type=int, default=40)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    leads, files_scanned = scan(root, args.max_per_rule)
    cutoff = SEVERITY_ORDER[args.min_severity]
    leads = [l for l in leads if SEVERITY_ORDER[l["severity_hint"]] <= cutoff]

    summary = {}
    for l in leads:
        summary[l["severity_hint"]] = summary.get(l["severity_hint"], 0) + 1

    if args.format == "json":
        print(json.dumps({
            "disclaimer": "Leads only. Verify each by reading the code. This scan cannot detect logic flaws such as missing authorization.",
            "files_scanned": files_scanned, "lead_count": len(leads),
            "by_severity_hint": summary,
            "excluded_paths": list(EXCLUDED),
            "leads": leads,
        }, indent=2))
        return

    print(f"Pattern scan: {files_scanned} files, {len(leads)} leads {summary}")
    print("Leads only. Verify each by reading the code.")
    for e in EXCLUDED:
        print(f"Excluded (this skill's own files): {e}")
    print()
    for l in leads:
        ctx = "" if l["context"] == "application" else f" [{l['context']}]"
        print(f"[{l['severity_hint'].upper():8}] {l['rule']}  {l['file']}:{l['line']}{ctx}")
        print(f"    {l['title']} ({l['owasp']})")
        print(f"    > {l['snippet']}")
        if l.get("note"):
            print(f"    note: {l['note']}")
        print()


if __name__ == "__main__":
    main()
