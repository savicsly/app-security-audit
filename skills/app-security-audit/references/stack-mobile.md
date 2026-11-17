# Mobile stacks

Contents: Principles for all mobile apps · React Native and Expo · Flutter · Native Android (Kotlin/Java) · Native iOS (Swift) · Fix patterns

Items are tagged with the OWASP Mobile Top 10 (2024) ID, and the web Top 10:2025 ID where one applies.

## Principles for all mobile apps

- **The app binary is public.** Anyone can download it, unpack it, and read every string, key, endpoint and piece of logic in it. Obfuscation slows this down and never prevents it. So a secret in the app is a leaked secret (M1), and a check done only in the app is not a check (M3).
- **The backend is where security lives.** Most serious mobile findings are backend findings: the API trusted the app. Audit the API the app calls with the web and API lists if its code is available. If it is not, record "backend not reviewed" as a limitation.
- **The device is semi-trusted storage.** Use the platform keystore for tokens and secrets; assume other storage can be read on a compromised or backed-up device (M9).

Check in every mobile project:

- Hard-coded API keys, client secrets, signing keys, admin credentials, private endpoints (M1).
- Auth tokens, PINs, personal data in plain storage (M9).
- Cleartext HTTP allowed; certificate validation disabled (M5).
- Deep links and app links that trigger actions or load content without validating parameters (M4).
- WebViews loading remote or user-influenced content with JavaScript and native bridges enabled (M4).
- Sensitive data in logs, analytics events, crash reports, screenshots, clipboard (M6, M9).
- Third-party SDKs: versions, permissions requested, data they collect (M2, M6).
- Permissions requested beyond what the app needs (M8, M6).
- Release build settings: debuggable, backups, obfuscation (M7, M8).
- Signing material in the repository: `.jks`/`.keystore`, `key.properties`, `.p12`, `.mobileprovision`, store API keys, with passwords in Gradle files or CI config (M1, A03).

## React Native and Expo

- **Env variables (M1).** `EXPO_PUBLIC_*` values and anything read through `react-native-config`, `react-native-dotenv` or `app.config.js` `extra` are bundled into the app. Only public values belong there.
- **Storage (M9).** `AsyncStorage` is unencrypted. Tokens, refresh tokens and secrets belong in `expo-secure-store` or `react-native-keychain`. Check Redux Persist, Zustand persist and MMKV (without an encryption key) for persisted sensitive state.
- **Config files (M8).** `app.json` / `app.config.js`: `android.usesCleartextTraffic`, permissions list, `scheme` and intent filters for deep links, `ios.infoPlist` transport security exceptions. Also check the native `android/` and `ios/` folders if present (bare workflow) using the native sections below.
- **Deep links (M4).** Handlers for `Linking` events or router params (Expo Router, React Navigation linking config) that perform actions, navigate to privileged screens or load URLs from the link.
- **WebView (M4).** `react-native-webview` with `originWhitelist={['*']}`, `javaScriptEnabled` with `onMessage` handlers that trust the page, `source={{ uri: userUrl }}`, `allowFileAccess`, `mixedContentMode="always"`.
- **Logging (M9).** `console.log` of tokens, responses and user data left in release builds.
- **OTA updates (M2, A08).** Expo Updates or CodePush channels and keys; code signing for updates on sensitive apps.
- **Dependencies (M2).** `npm audit`; abandoned native modules.
- **Backend-as-a-service.** If the app uses Supabase or Firebase directly, read `stack-baas.md`; the rules are the security.

## Flutter

- **Secrets (M1).** Keys in Dart source, `.env` files loaded with `flutter_dotenv` (bundled as an asset, trivially extracted), `--dart-define` values (compiled in), `assets/` config JSON.
- **Storage (M9).** `shared_preferences` and Hive (without encryption) for tokens; use `flutter_secure_storage`. Local SQLite (`sqflite`) holding sensitive data unencrypted.
- **Network (M5).** `HttpClient.badCertificateCallback = (...) => true`, Dio `onBadCertificate` returning true, `http://` endpoints.
- **WebView (M4).** `webview_flutter` with unrestricted JavaScript mode and JavaScript channels exposed to arbitrary pages; no navigation delegate restricting hosts.
- **Deep links (M4).** `go_router`, `uni_links`/`app_links` handlers acting on parameters without validation.
- **Logging (M9).** `print`/`debugPrint` of sensitive values.
- **Build (M7).** Release built without `--obfuscate --split-debug-info` for apps with sensitive logic (Low; hardening).
- **Native folders.** Review `android/app/src/main/AndroidManifest.xml`, `android/app/build.gradle`, `android/key.properties`, and `ios/Runner/Info.plist` using the sections below.
- **Dependencies (M2).** `flutter pub outdated`; check advisories for packages in `pubspec.lock`.

## Native Android (Kotlin/Java)

**Manifest (`AndroidManifest.xml`) (M8).**
- `android:debuggable="true"` in a release manifest.
- `android:allowBackup="true"` (or absent on older targets) with sensitive data in app storage; check `dataExtractionRules` / `fullBackupContent`.
- `android:usesCleartextTraffic="true"`, or a `networkSecurityConfig` permitting cleartext or trusting user-installed certificates in release.
- Components (`activity`, `service`, `receiver`, `provider`) with `android:exported="true"` or with intent filters, lacking a permission: other apps can invoke them. Check what each does with incoming intent extras.
- Content providers exported with `grantUriPermissions` or path traversal in `openFile`.
- Excess permissions.

**Code.**
- Secrets in source, `strings.xml`, `BuildConfig` fields, `gradle.properties`, `local.properties` committed (M1).
- `SharedPreferences` for tokens or personal data; prefer Keystore-backed encryption (M9). Files written to external storage. `MODE_WORLD_READABLE`.
- WebView: `setJavaScriptEnabled(true)` with `addJavascriptInterface`, `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs(true)`, loading URLs from intents (M4).
- Intents: implicit intents carrying sensitive data; `PendingIntent` without `FLAG_IMMUTABLE`; unvalidated extras and deep link data used for navigation, file paths or URLs (M4).
- TLS: custom `X509TrustManager` or `HostnameVerifier` that accepts everything (M5).
- Crypto: hard-coded keys and IVs, `AES/ECB`, `DES`, MD5/SHA-1 for security purposes, `java.util.Random` for tokens (M10).
- SQL: `rawQuery`/`execSQL` with concatenation (M4, A05).
- Logging: `Log.d`/`Log.v` with sensitive data (M9).
- Biometrics used as a UI gate without a Keystore-bound key (M3).

**Build (`build.gradle`) (M7, M1).** `minifyEnabled false` for release; signing config with plaintext passwords; `debuggable true` in release type; keystore file committed.

## Native iOS (Swift)

**`Info.plist` (M5, M8).**
- `NSAppTransportSecurity` with `NSAllowsArbitraryLoads = true`, or broad exception domains.
- Custom URL schemes (`CFBundleURLTypes`): any app can register the same scheme, so schemes must not carry secrets (such as OAuth codes without PKCE) or trigger sensitive actions. Prefer universal links.
- Usage description strings for permissions the app does not need.

**Code.**
- Secrets in source, plists, `.xcconfig` files committed (M1).
- `UserDefaults` or plain files or unencrypted Core Data/SQLite for tokens and personal data; use Keychain with an appropriate accessibility class (avoid the `Always` variants) (M9). File protection attributes.
- TLS: `URLSessionDelegate` that accepts any server trust; Alamofire `ServerTrustManager` with evaluation disabled (M5).
- `WKWebView` with message handlers exposed to untrusted content, `loadFileURL` with wide read access, JavaScript evaluation of untrusted strings; any remaining `UIWebView` (M4).
- URL handling in `application(_:open:options:)` / `onOpenURL` / universal link handlers without validating parameters (M4).
- Crypto: CommonCrypto with ECB, hard-coded keys, MD5/SHA-1 for security purposes (M10).
- Logging: `print`/`NSLog`/`os_log` with sensitive values, without privacy redaction (M9).
- Pasteboard use for sensitive values; no snapshot protection on sensitive screens (M6, hardening).
- Biometrics via `LAContext.evaluatePolicy` alone as a gate, without Keychain access control (M3).

**Project.** Signing certificates, provisioning profiles, App Store Connect API keys in the repository (M1). `Podfile.lock` / `Package.resolved` for outdated SDKs (M2).

## Fix patterns

Move a secret off the device: the app calls your backend endpoint, which authenticates the user, applies a rate limit, and calls the third-party API with the key held in server environment configuration. The key in the app must also be rotated, since it has already shipped.

React Native token storage:

```ts
import * as SecureStore from "expo-secure-store";
await SecureStore.setItemAsync("refresh_token", token);   // not AsyncStorage
```

Flutter token storage:

```dart
const storage = FlutterSecureStorage();
await storage.write(key: 'refresh_token', value: token);  // not SharedPreferences
```

Android manifest hardening:

```xml
<application
    android:allowBackup="false"
    android:usesCleartextTraffic="false"
    ...>
    <activity android:name=".InternalActivity" android:exported="false" />
</application>
```

iOS: remove `NSAllowsArbitraryLoads`; if one legacy host needs an exception, scope it to that domain only.

Deep link validation (shape): parse the URL, accept only expected hosts and paths, treat every parameter as untrusted, and require the normal in-app confirmation and server authorization for any action the link starts.
