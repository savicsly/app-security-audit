# JavaScript and TypeScript stacks

Contents: All JS/TS projects · Next.js · React single-page apps (Vite, CRA) · Vue and Nuxt · SvelteKit · Express and Fastify · NestJS · Data layer (Prisma, Drizzle, Mongoose, raw drivers) · Auth libraries · Fix patterns

Each item names the OWASP Top 10:2025 category it usually maps to.

## All JS/TS projects

**Environment variables and the client bundle (A04, A02).** Anything with a public prefix is compiled into JavaScript that every visitor downloads: `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_` (SvelteKit), `NUXT_PUBLIC_`. Search for these prefixes on any name suggesting a secret (SECRET, PRIVATE, SERVICE_ROLE, ADMIN, a database URL, a payment secret key, an LLM provider key). Also search client-side files for server-only variables referenced directly, and for keys pasted as string literals.

**Committed env files (A04).** Check whether `.env`, `.env.local`, `.env.production` are tracked: `git ls-files | grep -i '\.env'`. Check `.gitignore`. If one was ever committed, the secrets are in history and need rotating.

**Dependencies (A03).** `npm audit` / `pnpm audit` / `yarn npm audit`. Check a lockfile is committed. Look at unfamiliar package names closely; generated code sometimes imports packages that do not exist or are near-misses of real ones.

**Dangerous sinks (A05).** `eval`, `new Function`, `setTimeout` with a string, `child_process.exec` with interpolated input (prefer `execFile` with an argument array), `vm` module with user code, dynamic `require`/`import` of user-influenced paths, `fs` calls with user-supplied paths without normalizing and confining to a base directory.

**Prototype pollution (A05, A08).** Deep merges or `Object.assign` of request bodies into config or model objects; old versions of lodash and similar.

**Regex denial of service (A10).** User-controlled input into complex regexes, or user-supplied regexes.

## Next.js

**Server Actions are public endpoints (A01).** Every function marked `"use server"` can be called by anyone with a crafted POST, regardless of which page renders the button. Each one must check the session and the caller's right to act on the specific record, inside the function. Treat arguments as untrusted and validate them with a schema.

**Route Handlers and API routes (A01).** `app/**/route.ts` and `pages/api/**`. List every one and fill in the three-question table (signed in? allowed? owns the record?). Handlers that read an `id` from params and query by it alone are the classic gap.

**Middleware as the only gate (A01).** Auth done only in `middleware.ts` is fragile: matchers miss paths, and a 2025 vulnerability (CVE-2025-29927) allowed middleware to be skipped with a crafted header on unpatched versions. Check the Next.js version through the dependency audit, and check that handlers and data access repeat the authorization.

**React Server Components (A03, A08).** A critical remote code execution flaw in the RSC protocol was disclosed in December 2025 (CVE-2025-55182). Confirm React and Next.js versions are patched via the dependency audit.

**Data leaking to the client (A01, A04).** Server components or `getServerSideProps` passing whole database rows as props to client components sends every field to the browser, including ones the UI never shows (password hashes, emails of other users, internal flags). Select only needed fields. Check `import "server-only"` is used on modules that hold secrets or data access.

**Client-side authorization (A01).** `if (user.role === 'admin')` around UI, with the underlying action or API open. The server must enforce it.

**Raw HTML (A05).** `dangerouslySetInnerHTML` with user or CMS or LLM content that is not sanitized (DOMPurify or equivalent).

**Redirects (A01).** `redirect(searchParams.next)` or `router.push` with a user-supplied URL: open redirect. Allow only relative paths or an allowlist.

**Server-side fetch of user URLs (A01 SSRF).** Link previews, image proxies, webhooks testers, "import from URL". Also `images.remotePatterns` with wildcards in `next.config`.

**Headers and config (A02).** `next.config` `headers()` for CSP, HSTS, frame protection. `productionBrowserSourceMaps: true` exposes source. `poweredByHeader`. CORS headers set to `*` on API routes that use cookies.

**Webhooks (A08).** Stripe, Paystack, Flutterwave, Clerk and others sign their webhooks. The handler must verify the signature against the raw body before trusting the event. An unverified payment webhook lets anyone mark an order as paid.

**Rate limiting (A06).** Next.js has none built in. Login, signup, reset, OTP, contact forms, and any route calling a paid API need it.

## React single-page apps (Vite, CRA)

Everything in the SPA is public: code, routes, keys, feature flags, and any "hidden" admin screens. The audit question is always what the backend enforces.

- Secrets in `VITE_`/`REACT_APP_` variables or source (A04).
- Route guards as the only access control (A01). Find the API the guarded page calls and audit that.
- Tokens in `localStorage` (A07): readable by any script, so any XSS becomes account takeover. HttpOnly cookies are safer when the architecture allows. Rate it by XSS exposure.
- `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `href={userUrl}` allowing `javascript:` URLs (A05).
- `postMessage` listeners that do not check `event.origin` (A01).
- Third-party scripts without Subresource Integrity (A03).

## Vue and Nuxt

- `v-html` with untrusted content (A05).
- Nuxt `runtimeConfig`: only keys under `public` should reach the client; check that secrets are not placed there (A04).
- Nuxt server routes in `server/api/**` and `server/routes/**`: same three-question audit (A01). Validate bodies read with `readBody`.
- `server/middleware` auth that individual handlers do not repeat (A01).

## SvelteKit

- `{@html ...}` with untrusted content (A05).
- `$env/static/private` and `$env/dynamic/private` are server-only; anything imported from `$env/*/public` ships to the browser (A04).
- `+server.ts` endpoints and form `actions` in `+page.server.ts`: each needs its own auth and ownership checks; `hooks.server.ts` alone is not sufficient if handlers assume it (A01).
- `load` functions in `+page.server.ts` returning whole records (A01, A04).
- CSRF origin checking is on by default; check it was not disabled in `svelte.config.js` (A01).

## Express and Fastify

- **Auth middleware coverage (A01).** Middleware is applied per router or per route. List routes and confirm each sensitive one is behind it. Routes registered before `app.use(auth)` are unprotected.
- **Ownership (A01).** `Model.findById(req.params.id)` without also filtering by the session user.
- **Mass assignment (A01).** `Model.create(req.body)`, `findByIdAndUpdate(id, req.body)`, `Object.assign(user, req.body)`. Allowlist fields.
- **Validation (A05).** No schema validation (zod, joi, express-validator; Fastify JSON schemas) on bodies, params and queries.
- **NoSQL injection (A05).** `User.findOne({ email: req.body.email, password: req.body.password })` accepts `{"$ne": null}`. Cast to string or validate types.
- **CORS (A01, A02).** `cors()` with no options allows all origins; `origin: true` with `credentials: true` reflects any origin with cookies.
- **Headers (A02).** `helmet` absent. `x-powered-by` enabled.
- **Sessions and cookies (A07).** `express-session` with a hard-coded or default secret, the in-memory store in production, cookies without `secure`, `httpOnly`, `sameSite`.
- **CSRF (A01).** Cookie-authenticated state-changing routes with no CSRF token and `sameSite` not set.
- **JWT (A07, A04).** `jwt.verify` without an `algorithms` allowlist; `jwt.decode` used where `verify` is needed; weak or hard-coded secret; no expiry.
- **Uploads (A05, A06).** `multer` with no size limit or type check, files stored under the web root with their original names, served with user-controlled content types.
- **File serving (A01).** `res.sendFile(path.join(dir, req.params.name))` without confining the resolved path.
- **Body limits and rate limits (A06, A10).** No `express-rate-limit` or equivalent on auth routes; large or unlimited JSON body size.
- **Errors (A10, A02).** Error handler returning `err.stack` or raw database errors. Missing handler for async errors in Express 4.
- **Password hashing (A04).** Anything other than bcrypt/argon2/scrypt.

## NestJS

- Controllers or handlers missing `@UseGuards`, or a global guard with `@Public()` applied too widely (A01).
- Role guards present, ownership checks absent in the service (A01).
- `ValidationPipe` not global, or without `whitelist: true` and `forbidNonWhitelisted: true`, allowing extra properties through to entities (A01 mass assignment, A05).
- Entities returned directly from controllers, exposing fields; use DTOs or `ClassSerializerInterceptor` with `@Exclude` (A01).
- GraphQL: introspection and playground enabled in production, no depth or complexity limit, resolvers without guards (A02, A06).
- Swagger UI exposed in production (A02).

## Data layer

- **Prisma:** `$queryRawUnsafe` and `$executeRawUnsafe` with interpolated input are injectable; the tagged-template `$queryRaw` is parameterized. Check `where` clauses include the owner or tenant. `include` and returning whole models can over-expose.
- **Drizzle / Knex / Sequelize / TypeORM:** `sql.raw`, `knex.raw`, `sequelize.query`, `createQueryBuilder().where("... " + input)` with interpolation.
- **Raw drivers (pg, mysql2):** template strings in `query()`; require placeholders.
- **Mongoose/MongoDB:** operator injection as above; `$where` with user input.
- **Database URL** with credentials committed, or an admin-level database user used by the app (A02).

## Auth libraries

- **NextAuth / Auth.js:** `NEXTAUTH_SECRET`/`AUTH_SECRET` set and not committed; `callbacks.session` not leaking fields; role carried in the token is re-checked server side for sensitive actions; `allowDangerousEmailAccountLinking` not enabled without reason.
- **Clerk / Auth0 / Supabase Auth / Firebase Auth:** the server must verify the token on each request (`auth()`, `getUser()`, `verifyIdToken`) and must not trust a user ID sent in the body or a header. Supabase: prefer `getUser()` to `getSession()` on the server, since the session read from cookies is not revalidated.
- **Custom auth:** treat as high risk; review hashing, token generation (`crypto.randomBytes`, not `Math.random`), reset flow, session invalidation, and timing-safe comparison.

## Fix patterns

Ownership check in a handler:

```ts
const session = await auth();
if (!session?.user) return new Response("Unauthorized", { status: 401 });

const doc = await db.document.findFirst({
  where: { id: params.id, ownerId: session.user.id }, // scope by owner
  select: { id: true, title: true, body: true },      // only needed fields
});
if (!doc) return new Response("Not found", { status: 404 });
```

Server Action with validation and authorization:

```ts
"use server";
const Input = z.object({ id: z.string().uuid(), title: z.string().min(1).max(200) });

export async function renameProject(raw: unknown) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  const { id, title } = Input.parse(raw);
  const result = await db.project.updateMany({
    where: { id, ownerId: session.user.id },
    data: { title },
  });
  if (result.count === 0) throw new Error("Not found");
}
```

Parameterized query:

```ts
// before: db.query(`SELECT * FROM users WHERE email = '${email}'`)
await db.query("SELECT id, name FROM users WHERE email = $1", [email]);
```

Webhook signature verification (shape; use the provider's SDK):

```ts
const raw = await req.text();                       // raw body, before JSON parsing
const sig = req.headers.get("stripe-signature");
const event = stripe.webhooks.constructEvent(raw, sig!, process.env.STRIPE_WEBHOOK_SECRET!);
```
