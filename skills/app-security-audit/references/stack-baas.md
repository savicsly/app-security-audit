# Supabase and Firebase

Contents: Why these need special attention · Supabase · Firebase · Fix patterns

## Why these need special attention

With a backend-as-a-service, the client talks to the database directly. There is no server code between the user and the data, so the database rules are the entire access control layer. The client key is public by design. If the rules are missing or permissive, anyone can read or rewrite the data using the key from the app bundle, with no skill required. This is the most common cause of data leaks in quickly built apps, so a rule-by-rule review is the heart of the audit here. Most of these findings map to A01 Broken Access Control and A02 Security Misconfiguration.

Rules often live only in the provider's dashboard. If the repository has no migrations or rules files, the audit cannot see them. Say so prominently, ask the user to export them (instructions below), and list "database rules not reviewed" as a major limitation if they cannot.

## Supabase

**Keys (A04).**
- Public by design: the anon key, or a publishable key starting `sb_publishable_`. Not a finding.
- Must never reach a client: the `service_role` key, or a secret key starting `sb_secret_`, the database password and connection string, the JWT secret. These bypass row level security completely. Search client code, public-prefixed env variables and mobile bundles for them. Finding one there is Critical.
- A client created with the service role key in code that can run in the browser (shared `lib/supabase.ts` imported from both sides) has the same effect.

**Row level security (A01).** Look in `supabase/migrations/*.sql`, `schema.sql`, seed files.
- Every table in an exposed schema (normally `public`) needs `alter table ... enable row level security`. A table without it is fully readable and writable with the public key. List every `create table` and match it to an enable statement.
- RLS enabled with no policies denies everything to clients, which is safe, though it may indicate the app uses the service key everywhere instead; check.
- Policies with `using (true)` or `with check (true)` for `anon` or `authenticated` on anything other than public content.
- Policies that only check `auth.role() = 'authenticated'` or `auth.uid() is not null`: any signed-up user can access every row. Since signup is usually open, this is close to public.
- `for update` or `for insert` policies without a `with check` clause, letting a user reassign a row to someone else or insert rows owned by others.
- `for all` policies written with read access in mind, which also grant delete.
- Policies trusting `auth.jwt() -> 'user_metadata'`: users can edit their own `user_metadata`. Roles belong in `app_metadata` or a table users cannot write.
- A `profiles` or `users` table whose update policy lets users change their own `role`, `is_admin`, `plan` or `credits` columns.
- Multi-tenant apps: policies must check membership of the organization, not just ownership.

**Functions, views and storage (A01).**
- `security definer` functions run with the creator's rights and bypass RLS. Check each validates the caller, has a fixed `search_path`, and that execute is not granted to `anon` unintentionally.
- Views do not apply the caller's RLS unless created with `security_invoker = true`.
- Storage: buckets marked public; `storage.objects` policies missing or permissive; upload policies without path ownership (for example, first folder equals `auth.uid()`), size or type limits.
- Realtime enabled on sensitive tables relies on the same RLS.

**Edge Functions and server code (A01, A07).**
- Functions deployed with JWT verification off (`verify_jwt = false` in `supabase/config.toml`) and no check of their own.
- Functions using the service role client and trusting a `user_id` from the request body. Derive the user from the verified token.
- Server-side Next.js or similar: use `supabase.auth.getUser()` to authenticate; `getSession()` reads the cookie without revalidating it.

**Auth settings (A07).** Visible in `config.toml` when present: email confirmation disabled, weak minimum password length, wildcard redirect URLs, no captcha or rate limiting on signup for an app with abuse potential.

**Asking the user to export rules.** If migrations are absent, ask them to run this in the SQL editor and share the output:

```sql
select schemaname, tablename, rowsecurity from pg_tables where schemaname = 'public';
select tablename, policyname, roles, cmd, qual, with_check from pg_policies where schemaname = 'public';
```

## Firebase

**Keys and config (A04).**
- Public by design: the web config object (`apiKey`, `projectId`, and so on) and `google-services.json` / `GoogleService-Info.plist`. Not a finding by themselves. Recommend API key restrictions and App Check as hardening.
- Must never be in a client or the repository: a service account JSON (contains `private_key`), Admin SDK credentials, server keys for other providers. Critical when found.

**Firestore rules (`firestore.rules`) (A01).**
- `allow read, write: if true;` anywhere, especially on `match /{document=**}`. Critical.
- Test-mode rules with a date: `allow read, write: if request.time < timestamp.date(...)`. Open until the date, then the app breaks.
- `allow read, write: if request.auth != null;` at the top level: every signed-in user can read and modify every document. With open signup or anonymous auth, effectively public.
- Ownership missing: rules should compare `request.auth.uid` to the document path or an owner field, and on writes check `request.resource.data` so ownership cannot be reassigned.
- Role checks reading a user document that the same user can write (`get(/users/$(request.auth.uid)).data.role == 'admin'` where users may update their own document). Use custom claims set by the Admin SDK, or make the role field unwritable.
- No validation of incoming data: users can add fields such as `isAdmin` or `credits`, or write huge documents. Check key allowlists and types on create and update.
- A recursive wildcard `{document=**}` granting broader access than narrower matches intend; any matching allow wins.
- `list` allowed where only `get` was meant, enabling collection dumps.

**Realtime Database rules (`database.rules.json`) (A01).** `".read": true` or `".write": true` at the root; `"auth != null"` only; rules cascade downward, so a permissive parent overrides children.

**Cloud Storage rules (`storage.rules`) (A01, A05).** Open read or write; no check that the path belongs to `request.auth.uid`; no `request.resource.size` or `contentType` limits.

**Cloud Functions (A01, A06).**
- `onRequest` HTTP functions are public URLs. Each must verify the ID token (`verifyIdToken`) and authorize.
- `onCall` functions must check `context.auth` (or `request.auth`) and must not trust a UID passed in the data.
- Functions using the Admin SDK bypass all rules, so every authorization check has to be in the function.
- Functions that call paid APIs without per-user limits.
- Secrets in `functions.config()` output or source committed; prefer the secrets manager.

**Auth (A07).** Roles stored only in client state; anonymous auth enabled alongside "any authenticated user" rules; email enumeration protection off.

**If rules are not in the repository,** ask the user to copy them from the Firebase console (Firestore, Storage and Realtime Database each have a Rules tab) or run `firebase init` to pull them.

## Fix patterns

Supabase table with owner-scoped policies:

```sql
alter table public.notes enable row level security;

create policy "notes_select_own" on public.notes
  for select to authenticated
  using (user_id = (select auth.uid()));

create policy "notes_insert_own" on public.notes
  for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "notes_update_own" on public.notes
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "notes_delete_own" on public.notes
  for delete to authenticated
  using (user_id = (select auth.uid()));
```

Protecting privileged columns on a profile table: move `role`, `plan` and `credits` to a separate table with no client write policy, or restrict updates with column-level grants.

Firestore owner-scoped rules with field validation:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid}/notes/{noteId} {
      allow read, delete: if request.auth != null && request.auth.uid == uid;
      allow create, update: if request.auth != null && request.auth.uid == uid
        && request.resource.data.keys().hasOnly(['title', 'body', 'updatedAt'])
        && request.resource.data.title is string
        && request.resource.data.title.size() <= 200;
    }
  }
}
```

Callable function that derives identity from the token:

```ts
export const cancelOrder = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in required");
  const order = await db.doc(`orders/${request.data.orderId}`).get();
  if (!order.exists || order.get("userId") !== request.auth.uid) {
    throw new HttpsError("permission-denied", "Not your order");
  }
  ...
});
```

When a rules change is proposed, remind the user to test it (Supabase: query as different users; Firebase: the Rules Playground or emulator) before deploying, because a too-strict rule breaks the app and a wrong one gives false comfort.
