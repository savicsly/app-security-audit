# Laravel and Rails

Contents: Laravel · Ruby on Rails · Fix patterns

Both frameworks ship strong defaults. Most findings are places where the defaults were switched off, bypassed, or never applied to a new route. Each item names the OWASP Top 10:2025 category it usually maps to.

## Laravel

**Configuration (A02, A04).**
- `APP_DEBUG=true` in production: error pages expose environment variables, including database credentials. Rate High or Critical if deployed.
- `.env` committed, or reachable because the web root is the project root and not `public/`.
- `APP_KEY` missing, committed or shared across environments.
- Telescope, Horizon, Debugbar or Ignition reachable in production without a gate.
- `config/cors.php` with `allowed_origins => ['*']` and `supports_credentials => true`.
- Session cookie settings in `config/session.php`: `secure`, `http_only`, `same_site`.

**Access control (A01).**
- Routes in `routes/web.php` and `routes/api.php` outside `auth` / `auth:sanctum` middleware groups. Run `php artisan route:list` if possible and check the middleware column.
- Controllers that never call `$this->authorize()`, a Policy, or a Gate before acting on a model. Route model binding fetches by ID with no ownership check: `public function show(Invoice $invoice)` returns any invoice unless a policy or scope stops it.
- Form Requests whose `authorize()` simply returns `true`.
- **Mass assignment:** models with `$guarded = []`, or `$fillable` including `role`, `is_admin`, `user_id`; `Model::create($request->all())` and `->update($request->all())`. Use `$request->validated()` and a tight `$fillable`.
- API Resources absent, so `return $user;` serializes hidden fields unless `$hidden` is set.

**Injection (A05).**
- `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `DB::select` with interpolated variables. Column names from user input in `orderBy`.
- Blade `{!! $var !!}` with user content (the escaped form is `{{ }}`).
- `exec`, `shell_exec`, `system`, `passthru`, backticks, `eval` with user input.
- `unserialize` on user data (A08).
- `include`/`require` with user-influenced paths.

**CSRF (A01).** Routes added to the `VerifyCsrfToken` `$except` list beyond genuine webhooks; state-changing GET routes.

**Uploads and files (A05, A01).** Validation missing `mimes`/`max`; files stored on the `public` disk with original names; `Storage::download($request->path)` without confinement.

**Auth (A07).** No `throttle` middleware on login, register, password reset and OTP routes; Sanctum tokens with no expiry and wide abilities; custom password reset logic.

**Webhooks (A08).** Payment callbacks (Paystack, Flutterwave, Stripe) trusted without signature verification or without re-querying the transaction from the provider.

**Dependencies (A03).** `composer audit`.

## Ruby on Rails

**Configuration (A02, A04).**
- `config/master.key`, `credentials.yml.enc` key, or `secret_key_base` committed.
- `config.force_ssl` not enabled in production.
- `config.consider_all_requests_local = true` in production.
- Development tools (web-console, better_errors) outside the development group.
- `rack-cors` with `origins '*'` and credentials.

**Access control (A01).**
- Controllers without `before_action :authenticate_user!` (Devise) or with broad `skip_before_action`.
- No authorization layer (Pundit, CanCanCan), or controllers that skip `authorize`. With Pundit, check `verify_authorized` is enforced.
- Unscoped finds: `Invoice.find(params[:id])` where it should be `current_user.invoices.find(params[:id])`.
- **Strong parameters:** `params.permit!`, or `permit` lists including `role`, `admin`, `user_id`.
- Serializers or `render json: @user` exposing all attributes.

**Injection (A05).**
- String interpolation in `where("name = '#{params[:q]}'")`, `order(params[:sort])`, `find_by_sql`, `pluck` and `select` with user strings, `ActiveRecord::Base.connection.execute`.
- `html_safe`, `raw`, `<%==`, and `content_tag` with unescaped user data.
- `render inline:` or `render params[:template]` with user input.
- `system`, backticks, `%x`, `Kernel#open` with user input (a leading pipe runs a command), `send`/`public_send`/`constantize` with user-supplied names.
- `Marshal.load`, `YAML.load` (unsafe on older versions) on untrusted data (A08).

**CSRF (A01).** `skip_forgery_protection` or `protect_from_forgery with: :null_session` on cookie-authenticated controllers.

**Redirects (A01).** `redirect_to params[:return_to]` without restricting the host.

**Files (A05).** Active Storage or CarrierWave uploads without content-type and size validation; `send_file` with user paths.

**Auth (A07).** No `rack-attack` or equivalent throttling; Devise modules such as `lockable` and `timeoutable` unused in sensitive apps; custom token generation not using `SecureRandom`.

**Tools (A03, general).** `bundle audit` (bundler-audit) for dependencies and `brakeman` for static analysis. Brakeman is accurate on Rails and worth installing.

## Fix patterns

Laravel policy and validated input:

```php
public function update(UpdateInvoiceRequest $request, Invoice $invoice)
{
    $this->authorize('update', $invoice);          // InvoicePolicy@update checks ownership
    $invoice->update($request->validated());       // only validated fields
    return new InvoiceResource($invoice);          // only exposed fields
}
```

Laravel parameter binding:

```php
// before: DB::select("SELECT * FROM users WHERE email = '$email'")
DB::select('SELECT id, name FROM users WHERE email = ?', [$email]);
```

Rails scoped find and strong parameters:

```ruby
def update
  invoice = current_user.invoices.find(params[:id])
  invoice.update!(invoice_params)
end

private

def invoice_params
  params.require(:invoice).permit(:number, :amount)   # no role, no user_id
end
```

Rails parameterized where and safe ordering:

```ruby
User.where("name = ?", params[:q])
SORTABLE = %w[created_at amount].freeze
scope.order(SORTABLE.include?(params[:sort]) ? params[:sort] : "created_at")
```
