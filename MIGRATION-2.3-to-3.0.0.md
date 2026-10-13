# Migrating JWT Login Cookie Bridge 2.3 to 3.0.0

The planned 3.0.0 release is intentionally breaking. Version 2.3 could rely on ambient WordPress authentication behavior from another JWT plugin. The hardened Bridge accepts a JWT only through one explicitly selected, trusted validator and applies stricter token transport, Origin, cookie, redirect, and framing rules.

Do not upgrade a production site until the validator and Origin configuration below have passed staging tests. The Bridge is provider-neutral: 3.0.0 is **not automatically compatible with any JWT provider**, and the included RS256 example is not a universal adapter for WordPress JWT plugins.

## Pre-upgrade checklist

- Identify every application that calls `/wp-json/custom/v1/login_via_jwt`, which JWT it sends, and whether it uses a Bearer header, form body, or JSON body.
- Identify the JWT issuer, signing algorithm, verification key, required issuer and audience, time claims, and the signed claim that maps to an existing positive WordPress user ID.
- Do not assume that an application JWT is the same token as a WordPress JWT. A token issued for another API may have a different key, audience, identity, or security lifecycle and must not be accepted without an explicit validation design.
- Implement and stage exactly one validator registration. Define `JWT_LOGIN_ACTIVE_VALIDATOR` to select its exact ID.
- Configure the complete trusted frontend-Origin list from an MU-plugin as described below. Remove example and obsolete origins.
- Inventory popup `return_origin`, bounce `return_to`, WordPress `redirect`, and any iframe checkout use. Confirm exact schemes and effective ports.
- Record the current `COOKIE_DOMAIN`, any `JWT_LOGIN_COOKIE_DOMAIN`, WordPress home/site URLs, reverse-proxy HTTPS behavior, and logout flow.
- Back up the database, `wp-config.php`, active plugin files, MU-plugins, and the current 2.3 package. Record active plugin versions and configuration without copying private keys into the backup archive unnecessarily.
- Test the complete login, conflict, checkout, logout, and rollback plan in a staging environment that matches production HTTPS, hostnames, cookie domains, proxy headers, and WooCommerce configuration.
- Schedule the upgrade so 2.3 can be restored promptly if staging-only assumptions prove wrong. Do not use ambient JWT trust or disabled Origin checks as a rollback workaround.

## 1. Install and select a trusted validator

The Bridge no longer obtains JWT trust from `determine_current_user` or from whichever authentication plugin happens to populate the current WordPress user. A validator must cryptographically verify the exact supplied JWT and return `JWT_Login_Verified_Identity` containing a positive WordPress user ID. The Bridge then confirms that the user exists.

Trusted site code must register the validator on `jwt_login_register_validators` and select it with `JWT_LOGIN_ACTIVE_VALIDATOR`. Exactly one callable must be registered under the selected ID. Registration must be attached while plugins load; `init`, `rest_api_init`, and later hooks are too late because the registry is locked at `plugins_loaded` priority 20.

```php
define('JWT_LOGIN_ACTIVE_VALIDATOR', 'site/example');

add_action('jwt_login_register_validators', function (): void {
    jwt_login_register_validator('site/example', function (string $raw_jwt) {
        // Verify the exact compact JWT: signature, fixed algorithm, issuer,
        // audience, time limits, and a signed WordPress user-ID claim.
        $user_id = site_verify_and_map_jwt($raw_jwt);

        return is_wp_error($user_id)
            ? $user_id
            : new JWT_Login_Verified_Identity($user_id);
    });
});
```

Merely decoding a JWT, trusting a user ID supplied outside the signature, or accepting the current ambient WordPress user is not validation.

### Optional RS256 example

The repository includes an independently installable adapter in `examples/rs256-validator`. It accepts only RS256 tokens matching one configured RSA public key, issuer, audience, lifetime policy, and positive WordPress user-ID claim. To use it:

1. Copy `examples/rs256-validator` to `wp-content/plugins/jwt-login-rs256-validator`.
2. Run `composer install --no-dev --classmap-authoritative` inside that adapter directory.
3. Configure `JWT_LOGIN_ACTIVE_VALIDATOR`, public-key file, issuer, audience, identity claim, and maximum lifetime in `wp-config.php`.
4. Activate the adapter and test tokens from the actual issuer.

Follow the adapter's [complete installation and configuration guide](examples/rs256-validator/README.md). It does not load automatically, does not support symmetric algorithms, email mapping, arbitrary provider claims, or every WordPress JWT plugin. Confirm the provider's exact token contract before selecting it.

## 2. Configure persistent trusted frontend origins

Do not edit the Bridge file. Create `wp-content/mu-plugins/jwt-login-bridge-config.php`:

```php
<?php
/**
 * Plugin Name: JWT Login Bridge Site Configuration
 */

add_filter('jwt_login_allowed_origins', function (array $default_origins): array {
    return [
        'https://app.example.com',
        'https://account.example.com:8443',
    ];
});
```

Register the filter at file scope. Return the complete list rather than appending to the defaults. An MU-plugin is recommended because WordPress loads it before normal plugins and upgrades do not overwrite it. A normal trusted configuration plugin may also register the filter at file scope, but it must be active and loaded before any code evaluates the origin list.

Values must be exact absolute HTTP(S) origins. Do not use wildcards or include credentials, paths, queries, fragments, malformed ports, control characters, or backslashes. Explicit HTTPS `:443` and HTTP `:80` canonicalize to the omitted default port. A non-default port is trusted only when explicitly present. Invalid entries are not trusted; any invalid entry also prevents the Bridge from relaxing checkout framing.

This list has several separate effects: it permits browser request Origins, CORS credential responses, popup message targets, bounce destinations, and eligible WooCommerce checkout frame ancestors. It does not authorize WordPress-host redirects, select a validator, or make two origins equivalent. Keep the list as small as possible.

The old `function_exists` compatibility guard remains, so a legacy MU-plugin that defines `jwt_login_allowed_origins()` before the Bridge still takes precedence. Migrate such overrides to the filter; do not configure both mechanisms.

## 3. Update clients and transports

- A form or JSON body `token` is browser-capable and requires one valid, trusted `Origin` header. Missing, `null`, malformed, or untrusted Origins receive HTTP 403 before JWT validation.
- A correctly formed `Authorization: Bearer <JWT>` request may omit `Origin` for genuine server-to-server use. If it sends an Origin, that Origin must be trusted. Do not strip browser Origin headers to imitate a server client.
- Query-string tokens are rejected. They leak through browser history, logs, referrers, and intermediaries.
- Supplying both Bearer and body tokens, both form and JSON token values, or a malformed Bearer header is rejected as an ambiguous request with HTTP 400.
- The token is capped at 8192 bytes.

## 4. Understand failure responses

- **400**: malformed or ambiguous transport, query token, or oversized token.
- **401**: missing token, failed cryptographic/claim validation, unknown mapped WordPress user, or another validator rejection.
- **403**: missing or untrusted required Origin, an invalid supplied Bearer Origin, or an invalid/denied preflight.
- **409**: a valid JWT maps to a different user than the browser's existing WordPress login cookie. The Bridge never silently replaces that identity.
- **503**: no selected validator, missing or duplicate selected registration, validator exception, invalid validator return type, missing dependency, or unusable validator configuration.

Clients should handle these statuses explicitly and must not retry 403, 409, or 503 responses with weaker security settings.

## 5. Review cookies, domains, HTTPS, and logout

Bridge cookies remain `Secure`, `HttpOnly`, and `SameSite=None`, so production login and subsequent browser requests require correctly detected HTTPS. Configure reverse proxies so WordPress recognizes TLS. Modern browsers reject `SameSite=None` cookies without `Secure` and may apply additional third-party-cookie restrictions.

The default Bridge cookie scope is host-only. `JWT_LOGIN_COOKIE_DOMAIN` or WordPress `COOKIE_DOMAIN` may intentionally widen it. A parent-domain cookie such as `.example.com` is sent to sibling hosts, expands the impact of every sibling host, and can collide with host-only cookies of the same name. Use it only when the domain trust model requires it and every relevant subdomain is controlled.

When Bridge and WordPress core cookie scopes differ, successful Bridge login expires core-scope authentication tuples before issuing Bridge cookies; successful core login expires Bridge-scope tuples. Logout clears the additional Bridge scope when required, and all Bridge cookies share one revocable WordPress session token. Staging tests must cover login transitions in both directions and confirm that logout removes authentication at every configured scope.

## 6. Review navigation and iframe compatibility

- **Popup:** `return_origin` must be one trusted canonical frontend origin. Default ports are normalized. Invalid or untrusted values do not cancel successful authentication, but no message is sent to them. The only message is `woo-login-ok`; it contains no JWT, cookie, or user data.
- **Bounce:** `return_to` must be an absolute HTTP(S) URL whose complete canonical origin is in the trusted frontend list. Paths, queries, and fragments are preserved only after origin validation.
- **Redirect:** `redirect` is independent of the frontend list and must resolve to a configured WordPress home/site origin before `wp_safe_redirect` accepts it.
- **Iframe checkout:** the exception is limited to WooCommerce's configured checkout page and `order-pay`. Other endpoints retain native framing protections. Every frontend entry must be a valid exact origin; otherwise the exception fails closed. Existing `X-Frame-Options` or CSP `frame-ancestors` remains authoritative, and proxy/CDN headers must be changed at their source.

Adding an origin does not make these modes interchangeable and does not require the request Origin to equal the popup or bounce destination. Each boundary is validated independently.

## 7. Stage, deploy, and roll back safely

In staging, test valid and invalid JWTs, each transport, allowed and denied Origins, CORS preflights, existing-cookie identity conflicts, popup and bounce destinations, WordPress redirects, checkout/order-pay framing, all cookie-domain transitions, logout, and validator-unavailable behavior. Test with the actual frontend and issuer over HTTPS.

Before production deployment, take a fresh backup and keep the known-good 2.3 package and configuration available. If the upgrade fails, restore the previous plugin package and its matching configuration/database backup according to the site's normal rollback procedure, then diagnose the validator or Origin mismatch in staging. Do not restore service by accepting ambient users, skipping signature verification, permitting wildcard Origins, disabling Origin checks, or moving JWTs into query strings.
