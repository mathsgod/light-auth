# mathsgod/light-auth

A PHP **8.3+** authentication library prototype. No dependency on Light Framework, Light DB, RBAC, GraphQL or OAuth2. It does not create database tables, change existing applications, start sessions or issue tokens.

## Included

- Password login with account status and optional password expiry.
- A rolling login limit for both known and unknown usernames, selectable as username + IP lockout or a shared IP rate limit. The default preserves username + IP behavior.
- TOTP setup and confirmation with expiring browser/user-bound pending secrets, bounded confirmation attempts and application-owned persistence.
- Two-step password + TOTP login, expiring browser/IP-bound single-use challenges, and TOTP replay protection across IPs.
- WebAuthn/passkey creation and attestation verification, returning a validated record for application-owned storage.
- Discoverable WebAuthn/passkey login using `web-auth/webauthn-lib` v5, exact allowed origins, required authenticator user verification, single-use challenges and credential counter persistence.
- PDO adapters for **existing** user tables and JSON credential fields. All table/column mappings are configurable.
- PSR-16 cache state, PSR-20 clock, and Symfony locks for atomic state updates.

This initial scope is login, TOTP enrollment and passkey enrollment. Account registration, passkey removal, password reset/change, session lifecycle and OAuth authorization remain application responsibilities. The library supplies no HTTP endpoints or UI.

## Install and verify

```bash
composer install
composer test
composer analyse
php examples/demo.php
```

`composer.json` pins the dependency resolution platform to PHP 8.3. SQLite repository tests require `pdo_sqlite`; concurrency tests use `pcntl`. Runtime PDO is needed only when using the bundled adapters.

## Connect an existing database

The default PDO mapping reads the existing Light-style `User` table:

| Authentication data | Existing column |
| --- | --- |
| ID | `user_id` |
| Username | `username` |
| Password hash | `password` |
| Disabled state | `status` (`0` means active) |
| TOTP secret | `secret` (null/empty means no TOTP) |

There are **no package migrations**. Constructing an adapter performs no schema writes.

```php
use Light\Auth\Pdo\PdoUserRepository;
use Light\Auth\Pdo\UserMapping;

$users = new PdoUserRepository($pdo); // existing User table

// A different application, with no TOTP or expiry column:
$users = new PdoUserRepository($pdo, new UserMapping(
    table: 'members',
    id: 'uuid',
    username: 'login',
    passwordHash: 'password_hash',
    disabled: 'is_disabled',
    passwordExpiresAt: null,
    totpSecret: null,
));
```

Usernames use `strtolower(trim($username))` (ASCII case normalization). Adapters must resolve the same canonical identity; applications with Unicode or other alias rules should canonicalize consistently before calling the service and in their repository. Existing usernames must already follow that lookup policy or use a custom repository.

`passwordExpiresAt`, when mapped, must be a nullable Unix timestamp. For Light's calculated `password_dt` + duration policy, map that calculation in a `UserRepository` implementation. See [examples/FrameworkUserRepository.php](examples/FrameworkUserRepository.php). This example depends on Framework; the library does not.

The core repository returns `Light\Auth\User`, not an ORM model. Implement `UserRepository` to use any ORM, SQL driver or external identity store. Provisioning and credential changes stay with the application. Protect stored TOTP secrets using your application's existing encryption and access controls; this prototype's PDO adapter expects the value already usable by the verifier.

## Password login

```php
use Light\Auth\{AttemptLimiter, Challenges, LoginService, Policy, Status, TotpVerifier};
use Light\Auth\Cache\CacheStateStore;
use Symfony\Component\Cache\{Adapter\FilesystemAdapter, Psr16Cache};
use Symfony\Component\Lock\{LockFactory, Store\FlockStore};

$policy = new Policy(maxAttempts: 5, windowSeconds: 900, challengeSeconds: 300);
$state = new CacheStateStore(
    new Psr16Cache(new FilesystemAdapter('my_app_auth')),
    new LockFactory(new FlockStore()),
    namespace: 'my_app_auth',
);
$limiter = new AttemptLimiter($state, $policy);
$challenges = new Challenges($state, $policy);
$login = new LoginService($users, $limiter, $challenges, new TotpVerifier($state));

// Obtain these from the application: a trusted client IP and an opaque,
// unpredictable browser-session binding, not username or IP alone.
$result = $login->password($username, $password, $ip, $browserBinding);

if ($result->status === Status::SecondFactorRequired) {
    // Save/return challengeToken for this browser; do NOT mark the user logged in.
    $result = $login->secondFactor($result->challengeToken, $code, $ip, $browserBinding);
}

if ($result->status === Status::Authenticated) {
    // Only here may the application rotate its session ID and establish identity.
    // $result->userId is now available.
}
```

Only `Authenticated` contains a user ID. An expired password result is not authentication and cannot be used as authority to reset a password. Disabled users, absent users and incorrect passwords return the same `InvalidCredentials` result. Both existing and nonexistent usernames receive the same limit and `Locked` result with `retryAfter` seconds. A wrong MFA code consumes the pending challenge; start password login again. TOTP accepts the current 30-second step with 6 digits/SHA-1 and prevents its reuse.

Attempts are reserved before verification so parallel requests cannot bypass the threshold. In the default username/IP mode, a fully successful login clears that username/IP's attempts. An MFA-pending password attempt remains counted until MFA succeeds. Blocked requests do not append timestamps or extend the rolling lock window.

### Choose the login rate-limit scope

```php
use Light\Auth\{Policy, RateLimitScope};

// Default: separate failed/incomplete attempts for each username + IP.
$policy = new Policy(maxAttempts: 5, windowSeconds: 900,
    scope: RateLimitScope::UsernameIp);

// One login-submission quota per IP, regardless of username.
$policy = new Policy(maxAttempts: 20, windowSeconds: 60,
    scope: RateLimitScope::Ip);
```

Pass the selected policy to the `AttemptLimiter` shared by your login services. Changing `Policy` alone does not change an already constructed limiter.

| Scope | Aggregation | Successful login |
| --- | --- | --- |
| `username_ip` (default) | Username + IP; case variants share a counter | Clears that username/IP counter |
| `ip` | One IP quota shared across usernames and password/passkey login submissions | Counts toward the quota and never clears it |

In IP mode, a correct login or second-factor completion cannot clear attempts accumulated against other accounts. Password submission reserves one attempt; its subsequent TOTP completion does not reserve a second one. Passkey assertion submission also reserves one attempt. Setup/enrollment limits keep their existing per-user semantics. Options/challenge creation endpoints still need HTTP-level rate limiting.

Both modes keep rolling expiry, atomic concurrency protection and identical behavior for known/unknown accounts. Blocked requests do not extend expiry. Distinct IPs remain independent. Switching modes uses separate keys; it does not migrate or erase the previous mode's counters. Multiple users behind the same IP share its quota, so choose an appropriate limit for that deployment.

The legacy static `AttemptLimiter::key()` still produces username/IP keys. Custom login integrations should call the limiter instance's `loginKey()` and `loginSucceeded()` so the policy applies; generic `reserve()`/`clear()` remain available for other limits.

The dummy password hash follows the runtime's `PASSWORD_DEFAULT`. If your stored hashes use different algorithms or costs, supply a matching valid `dummyPasswordHash` to `LoginService`. Identical outward results do not promise constant-time database/cache operations.

For production, use persistent cache and locks with the **same sharing scope**. Filesystem cache + Flock works across processes on one host. A multi-host deployment needs shared cache and a shared lock backend, with an appropriate lock lease. Cache persistence failures propagate instead of authenticating. Cache eviction/loss also loses throttling and replay state: configure a dedicated, appropriately retained store. The store is deliberately injectable.

The library never reads `$_SERVER`, cookies, env variables or a global container. The HTTP layer must supply the trusted IP, binding, CSRF protection and response mapping. Use the same error mapping for known and unknown usernames. Rate limit challenge-creation endpoints at the HTTP layer as well.

## Enable TOTP

`TotpEnrollment` generates the server-side secret and confirms the first Authenticator code. It creates no tables and never updates the user repository. The application must require an authenticated session, recent password/passkey re-verification and CSRF validation on both endpoints. Always obtain `userId` from that server-side session, not request parameters.

```php
use Light\Auth\TotpEnrollment;

$totpEnrollment = new TotpEnrollment($users, $state, $policy, new TotpVerifier($state));

// Start endpoint, after re-verification:
$setup = $totpEnrollment->begin(
    userId: $authenticatedUserId,
    label: $user->email,
    issuer: 'My App',
    binding: $browserBinding,
);
// Return setupToken, expiresAt and provisioningUri to this browser only.
// Render provisioningUri as a QR code locally. This does NOT enable TOTP.

// Confirmation endpoint, with the same authenticated user and binding:
$confirmed = $totpEnrollment->confirm(
    userId: $authenticatedUserId,
    setupToken: $setupToken,
    code: $code,
    binding: $browserBinding,
);
if ($confirmed === null) {
    // Report invalid/expired setup or code. No secret is returned.
} else {
    // Application persists $confirmed->secret for $confirmed->userId.
    // Only after that write succeeds should the UI report TOTP as enabled.
}
```

`begin()` returns `TotpSetup` and rejects absent/disabled/already-enrolled users with `DomainException`. Blank labels, issuers or bindings are invalid. One enrollment is pending per user; restarting creates a fresh secret and invalidates older tokens, including tokens from another browser.

`confirm()` returns `ConfirmedTotpEnrollment` only after a valid six-digit code. Wrong codes count toward `Policy::maxAttempts`; reaching the limit discards that setup. `Policy::challengeSeconds` controls expiry, which failed requests do not extend. Wrong users, tokens or browser bindings cannot consume a valid setup. Successful confirmation consumes it atomically. Changes to the password, password-expiry policy, account status or existing TOTP invalidate pending setup. The first confirmed TOTP step is also marked used by `TotpVerifier`, preventing reuse of the enrollment code for login.

The application must save the secret **only if the account is still active and TOTP is still absent**, using a transaction/row lock or conditional write. This prevents an older confirmation overwriting a secret saved by another request. [FrameworkTotpEnrollmentStorage](examples/FrameworkTotpEnrollmentStorage.php) shows saving to the existing `User.secret` with a row lock and `User::save()`, preserving model audit behavior. It is an integration example for the existing MySQL-backed Framework, not a library dependency or automatic controller registration.

The confirmed secret stays server-side. Never accept a secret supplied directly by the browser as a confirmed result. Keep pending cache data and provisioning URIs out of logs and third-party QR services. If persistence fails after confirmation, start a new setup; consumed tokens cannot be retried. Rate limit setup/restart endpoints in the application.

Run `php examples/totp-enrollment.php` for a standalone demonstration. QR image rendering is left to the application; the library supplies the standard `otpauth://` URI.

## WebAuthn / passkeys

```php
use Light\Auth\Pdo\PdoCredentialRepository;
use Light\Auth\WebAuthn\WebAuthnService;

$passkeys = new WebAuthnService(
    $users,
    new PdoCredentialRepository($pdo),
    $challenges,
    $limiter,
    rpId: 'example.com',
    allowedOrigins: ['https://example.com'],
);

$request = $passkeys->begin($browserBinding);
// Send request.publicKey to the browser; convert base64url fields to/from
// ArrayBuffers for navigator.credentials.get(). Keep request.token for completion.
$result = $passkeys->complete($request->token, $assertion, $ip, $browserBinding);
```

This is discoverable-credential login: no username-dependent credential list is returned. The existing credential record's user handle is checked by the WebAuthn library. UV is required; a UV-verified passkey is treated as complete login without an additional TOTP step. Password expiry only applies to password login. Adjust this policy before adopting if your application requires TOTP even after passkey verification.

`PdoCredentialRepository` reuses the existing `User.credential` JSON array, including Light's `{uuid, name, credential: {...}}` wrappers. It preserves wrapper metadata and other credentials while persisting counter updates with optimistic concurrency checks. Table, ID column, JSON column and wrapper key are configurable. For a raw array of credential records, use `wrapperKey: null`.

The supplied adapter scans existing JSON arrays to locate a credential, matching the current storage shape. For a large user base, supply an indexed `CredentialRepository` using your existing credential storage. It also implements `CredentialInventory::forUser()` for enrollment exclusion lists; assertion-only repositories do not have to implement this additional interface.

### Register a passkey (creation / attestation)

Require an authenticated session, recent password/passkey re-verification and CSRF protection on the enrollment endpoints. User IDs come from that authenticated server-side session. Enrollment adds a credential to an existing account; it does not create an account or establish a login session.

```php
use Light\Auth\WebAuthn\WebAuthnEnrollment;

$enrollment = new WebAuthnEnrollment(
    $users,
    new PdoCredentialRepository($pdo),
    $challenges,
    $limiter,
    rpId: 'example.com',
    rpName: 'My App',
    allowedOrigins: ['https://example.com'],
);

$request = $enrollment->begin($authenticatedUserId, $displayName, $browserBinding);
// Send request.publicKey to navigator.credentials.create({ publicKey: ... }).
// Decode challenge, user.id and excludeCredentials[].id from base64url to
// ArrayBuffers; encode binary fields in the returned credential as base64url.

$verified = $enrollment->confirm($authenticatedUserId, $request->token, $attestation, $browserBinding);
if ($verified !== null) {
    // Application saves this server-produced StoredCredential, preserving
    // global credential-ID uniqueness and ownership. Never save raw client JSON.
}
```

`begin()` returns a `RegistrationRequest` with a random challenge and a token bound to the authenticated user and browser. Creation requests require resident/discoverable credentials and user verification. They advertise ES256/RS256, include the user's existing credentials in `excludeCredentials`, and use a stable opaque SHA-256 user handle independent of email or username. Existing handles on previously stored credentials continue to work for assertion.

The default attestation conveyance is `none`, using the upstream library's `none` attestation support. This validates the registration ceremony without requesting manufacturer identity/certificate trust. It is not enterprise/device-provenance attestation. Authenticator attachment is unrestricted, allowing compatible platform and roaming authenticators.

`confirm()` validates the response with `AuthenticatorAttestationResponseValidator`. Challenges expire and are single-use, including after malformed or invalid responses. Wrong users/browser bindings cannot consume another setup. Disabled/deleted accounts and changes to password, TOTP or password-expiry policy invalidate pending registration. Existing credential IDs are rejected even when owned by another user; response raw ID must match the validated attested ID. Valid confirmations alone return a `StoredCredential` containing its binary ID, owner ID and serialized `CredentialRecord`.

Invalid confirmations are limited per user with the existing `AttemptLimiter`, including attempts across new challenges. Rate limit enrollment-start endpoints in the application too. Cache/repository failures propagate; verification does not write to the database.

After confirmation, **application persistence must recheck account status and enforce credential-ID uniqueness atomically**, preserving existing credentials. A duplicate check performed during verification cannot prevent a race between two subsequent database writes. [FrameworkWebAuthnEnrollmentStorage](examples/FrameworkWebAuthnEnrollmentStorage.php) shows app-side storage in the existing `User.credential` array using a shared enrollment-write lock, a row-locking transaction and `User::save()`. All credential registration writers must use that same lock and cache namespace. Custom adapters with an existing indexed credential table can enforce uniqueness through their own storage constraints instead. No new table is required by this library.

After the application saves the verified record, `WebAuthnService` can immediately use it for assertion/login. If persistence fails, start a new registration because the verification token has already been consumed. Store only the server-produced result; never deserialize a browser-supplied `StoredCredential` as proof of verification.

## OAuth2 and RBAC integration

`light-auth` authenticates identity; it does not decide consent, scopes or permissions. Its dependencies contain neither `mathsgod/light-oauth2` nor `light-rbac`.

1. Your normal login endpoint calls `LoginService` or `WebAuthnService`.
2. Only `Authenticated` establishes the application's login session, with session ID rotation.
3. The existing OAuth `AuthorizationFlow` reads that established identity and separately handles consent.
4. After explicit consent, the adapter can return `Light\OAuth2\Contract\AuthorizationDecision($userId, $approved, true)`.
5. `light-oauth2` continues code/token issuance and scope checks; RBAC remains an independent application integration.

OAuth request state and return destinations belong to that OAuth flow, never to a raw client-supplied redirect accepted by this library. Do not issue OAuth credentials from a pending MFA challenge.
