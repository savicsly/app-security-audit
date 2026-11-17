# Python stacks

Contents: All Python projects · Django (and Django REST Framework) · Flask · FastAPI · Fix patterns

Each item names the OWASP Top 10:2025 category it usually maps to.

## All Python projects

- **Dependencies (A03).** `pip-audit` against `requirements.txt` or the lockfile. Unpinned requirements. Verify unfamiliar package names exist on PyPI and are the intended ones.
- **Secrets (A04).** Keys in `settings.py`, `config.py`, notebooks, committed `.env`. Default fallbacks such as `os.environ.get("SECRET_KEY", "dev-secret")` that silently apply in production.
- **Command execution (A05).** `os.system`, `subprocess.*` with `shell=True` and interpolated input, `eval`, `exec`.
- **Deserialization (A08).** `pickle.load(s)`, `yaml.load` without `SafeLoader`, `marshal`, `shelve`, `jsonpickle` on untrusted data. Loading ML model files from untrusted sources.
- **SQL (A05).** f-strings, `%` or `.format` inside `cursor.execute`, `text()` in SQLAlchemy with interpolation.
- **Paths (A01).** `open(os.path.join(base, user_input))` without resolving and confining; `send_file` with user input; archive extraction without member path checks.
- **Outbound requests (A01 SSRF, A04).** `requests.get(user_url)`; `verify=False`; no timeout (A10).
- **Templates (A05).** `render_template_string` or `Template(user_input)` with user-controlled template source is server-side template injection.
- **Hashing and randomness (A04).** `hashlib.md5/sha1/sha256` for passwords; `random` module for tokens (use `secrets`).
- **Errors (A10).** Bare `except: pass` around auth or payment logic.
- **XML (A05).** `xml.etree`/`lxml` parsing untrusted XML with entity resolution; prefer `defusedxml`.

## Django

**Settings (A02, A04).** Run `python manage.py check --deploy` if the environment allows; it reports most of these.
- `DEBUG = True` in production settings, or driven by an env var that defaults to true.
- `SECRET_KEY` hard-coded or with an insecure default.
- `ALLOWED_HOSTS = ["*"]`.
- Missing `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`.
- `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True`.
- Weak or reordered `PASSWORD_HASHERS`; `AUTH_PASSWORD_VALIDATORS` emptied.
- Admin at the default `/admin/` with no extra protection; rate as Low unless combined with weak passwords.

**Access control (A01).**
- Views without `@login_required` / `LoginRequiredMixin` / permission checks. List URL patterns and check each view.
- Object-level: `Model.objects.get(pk=pk)` without filtering by `request.user`. Prefer `get_object_or_404(Model, pk=pk, owner=request.user)`.
- `ModelForm` with `fields = "__all__"` or `exclude`, letting users set owner, role or status fields (mass assignment).

**Django REST Framework (A01).**
- `DEFAULT_PERMISSION_CLASSES` unset (defaults to `AllowAny`) or views with `permission_classes = [AllowAny]`.
- `ModelViewSet` with `queryset = Model.objects.all()` and no `get_queryset` scoped to the user: every authenticated user can read and edit everything.
- Serializers with `fields = "__all__"` exposing or accepting sensitive fields; missing `read_only_fields`.
- No throttling classes (A06).
- Browsable API and schema endpoints exposed in production (A02).

**Injection (A05).**
- `.raw()`, `.extra()`, `RawSQL`, `cursor.execute` with string formatting.
- `mark_safe`, `|safe`, `{% autoescape off %}`, `format_html` misuse with user data.
- User-controlled keys in `filter(**request.GET.dict())` allowing lookups across relations to sensitive fields.

**CSRF (A01).** `@csrf_exempt` on cookie-authenticated views; CSRF middleware removed.

**Files (A05, A02).** `FileField` uploads without type and size validation; `MEDIA_ROOT` served by the app with executable types; user-controlled filenames.

**Redirects (A01).** `redirect(request.GET["next"])` without `url_has_allowed_host_and_scheme`.

## Flask

Flask gives few protections by default, so check that each was added.

- `app.run(debug=True)` or `FLASK_DEBUG=1` reachable in production: the Werkzeug debugger allows code execution (A02). Rate Critical if deployed that way.
- `app.secret_key` hard-coded or weak: sessions are signed client-side cookies, so a known key lets anyone forge a session (A04, A07).
- No CSRF protection unless Flask-WTF `CSRFProtect` or similar is installed (A01).
- Routes without `@login_required` or an equivalent check; ownership not checked (A01).
- `render_template_string` with user input (A05). `Markup()` and `|safe` on user data (A05).
- `send_file`/`send_from_directory` with unchecked input; uploads saved without `secure_filename` (A01).
- Session cookie flags: `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE` (A02).
- `flask-cors` with `CORS(app)` default allowing all origins, with `supports_credentials=True` (A02).
- No rate limiting (Flask-Limiter) on auth routes (A06).
- SQLAlchemy `db.session.execute(text(f"..."))`, or `db.engine.execute` with formatting (A05).

## FastAPI

- **Auth is opt-in per route (A01).** Every route or router needs a `Depends(get_current_user)` (or a router-level dependency). List routes and check each. Routers included without the dependency are open.
- **Ownership (A01).** `db.get(Model, item_id)` returned without comparing the owner to the current user.
- **Response models (A01, API3).** Routes returning ORM objects without a `response_model` that excludes sensitive fields (hashed password, internal flags).
- **Input models (A01 mass assignment).** A single Pydantic model reused for create, update and admin operations, letting clients set `is_admin`, `owner_id`, `role`. Use separate input schemas; consider `extra="forbid"`.
- **JWT (A07, A04).** `jwt.decode` without `algorithms`, with `options={"verify_signature": False}`, with a hard-coded or default secret, without expiry.
- **CORS (A02).** `allow_origins=["*"]` with `allow_credentials=True`.
- **Docs (A02).** `/docs`, `/redoc`, `/openapi.json` public in production; acceptable for a public API, a finding when it exposes internal or admin endpoints.
- **Uploads (A05, A06).** `UploadFile` without size or type checks; reading whole files into memory.
- **SQL (A05).** `text()` with f-strings; raw `execute`.
- **Rate limiting (A06).** None built in; check for slowapi or a gateway.
- **Background tasks and WebSockets (A01).** WebSocket endpoints frequently skip authentication entirely.
- **Debug (A02).** `uvicorn --reload` or `debug=True` in the production start command.

## Fix patterns

Django object-level check:

```python
@login_required
def invoice_detail(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)
    ...
```

DRF scoped queryset and safe serializer:

```python
class InvoiceViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)   # never from the request body

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "amount", "status"]
        read_only_fields = ["id", "status"]
```

FastAPI dependency plus ownership plus response model:

```python
@router.get("/items/{item_id}", response_model=ItemOut)
def read_item(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
    if item is None:
        raise HTTPException(status_code=404)
    return item
```

Parameterized SQL:

```python
# before: cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
cur.execute("SELECT id, name FROM users WHERE email = %s", (email,))
```

Secret without an insecure fallback:

```python
SECRET_KEY = os.environ["SECRET_KEY"]   # fail at startup if missing
```
