# Disposable WordPress integration environment

This environment exercises WordPress authentication, the bridge cookie helper, and the provider-agnostic validator boundary. It installs no production JWT provider. A test-only validator uses the pinned audited `firebase/php-jwt` library with an ephemeral local key to cryptographically verify tokens issued inside the disposable environment.

## Dependency assumptions from the repository

- WordPress is required. The plugin uses the REST API, `WP_Session_Tokens`, pluggable auth-cookie functions, current-user filters, redirects, and cookie constants.
- PHP must support typed declarations and the options-array form of `setcookie()`; the latter requires PHP 7.3 or newer. The plugin metadata currently declares no minimum PHP or WordPress version.
- WooCommerce is optional to the helper because `WC()` is guarded, but it is required for the documented `order-pay` production flow. The harness installs it to exercise plugin coexistence.
- Production declares no JWT package. A trusted site extension must register exactly one explicitly selected validator; WordPress current-user hooks are not accepted as JWT validation.

## Pinned components

- WordPress `7.1.3`, Apache variant with PHP `8.3`: `wordpress@sha256:8ecd8d8e374167ea22235acf30f80d1165b82f07ffa5bcef90c1cad8f7be251f`
- WP-CLI `2.12.0`, PHP `8.3`: `wordpress@sha256:36243da432a0f0a3b56dc3240ecee9b159108d71305e7c064d987a20a465bfde`
- WooCommerce `11.2.0`: archive SHA-256 `66e91b45b057b64c73d4521111cea5bdc78c4c89de8fa2ca4b18b9422706d722`
- MariaDB `11.4.5`: `mariadb@sha256:49117dcc565cf51aa57ac5fca59ab31213402ff0eae6ffc13c46a37b938f7e4b`
- nginx `1.27.4-alpine`: `nginx@sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591`
- Test-only `firebase/php-jwt` `6.11.1`: source archive SHA-256 `1c46f1c7ec7e1a378966f19b8a828cd21d42d4967b7b789d0d432f536277cc3d`

The Compose file pins both readable version tags and immutable image digests. The runner verifies the WooCommerce archive before installation.

## Run

Prerequisites are Docker Compose, OpenSSL, curl, and Python 3.

```bash
tests/integration/run.sh
```

The runner creates a temporary directory containing random database, WordPress, test-user, and endpoint credentials plus a one-day self-signed certificate. Nothing secret is written inside the repository. Containers, volumes, and the temporary directory are removed at exit. Set `KEEP_INTEGRATION=1` only for local debugging.

The HTTPS endpoint uses `shop.example.test` through curl's `--resolve` option, so `/etc/hosts` is not modified. The runner executes the suite with no bridge-domain override, with the exact host, and with `.example.test` as a parent domain. WordPress core retains its default host-only `COOKIE_DOMAIN` behavior in all three scenarios.

## Coverage and boundaries

The tests cover:

- Standard WordPress login, session creation, logout, and session revocation.
- Core auth-cookie Domain and Path headers.
- The bridge helper's three cookie headers, shared session token, Domain, Path, Secure, HttpOnly, and SameSite attributes.
- Conflicting `Set-Cookie` identities in the observed responses.
- Standard WordPress logout after a session was created by the bridge helper.
- Real signed JWT success through Bearer and form POST transports.
- Missing, malformed, invalid-signature, expired, future-`nbf`, wrong-issuer, and invalid-user failures.
- Invalid JWT requests cannot create sessions through an existing WordPress cookie or Application Password.
- Fail-closed behavior for unconfigured, missing, and duplicate validator registrations.
- Browser-cookie/JWT identity conflicts, ambiguous transports, query tokens, checkout redirect, popup, and bounce responses.
- Transport-aware Origin enforcement for Bearer, form, and JSON tokens, including canonical ports and rejection before JWT validation.

Standard logout must both revoke the bridge-created session and leave no WordPress authentication cookies in curl's cookie jar in every scope scenario.

The test-only must-use plugin is copied into the disposable WordPress volume and protects its endpoints with a generated secret. It directly calls `jwt_login_cookie_set_auth_cookies()` only for Phase 1 lifecycle tests. Phase 2 cases issue and verify real HS256 JWTs with `firebase/php-jwt`; the random key remains in the temporary runtime directory and is removed at exit. This validator is test infrastructure, not a supported production provider.

Not covered without additional configuration:

- Production proxy/header behavior and production cookie-domain overrides.
- Browser-specific Origin emission, third-party-cookie, popup, and iframe behavior.
- A completed WooCommerce payment. The bridge checkout redirect, popup, and bounce responses are covered, but real-browser behavior, CORS, CSP, and login-CSRF/Origin enforcement are not.
