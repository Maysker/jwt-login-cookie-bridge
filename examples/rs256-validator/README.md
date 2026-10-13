# Optional RS256 validator example

This directory is an independently installable WordPress plugin demonstrating the validator API exposed by JWT Login Cookie Bridge. It is optional: the Bridge does not load it, select it, or depend on Composer or `firebase/php-jwt`.

The example accepts only RS256 tokens verified by one administrator-configured RSA public key. It requires exact issuer and audience matches, mandatory integer `iat`, `nbf`, and `exp` claims, a configured maximum lifetime, and a configurable claim containing a positive WordPress user ID. The Bridge separately confirms that the user exists.

## Release ZIP installation

The curated validator release ZIP includes its own reviewed Composer dependencies. Before activation, place the public key at its protected absolute path and add the trusted configuration below to `wp-config.php`. Then upload the separately distributed adapter ZIP through **Plugins → Add Plugin → Upload Plugin**, activate it, and test the Bridge in staging with tokens from the actual issuer.

The adapter's `Update URI` prevents a WordPress.org slug collision; it does not automatically deliver updates from GitHub.

## Installation from source

1. Copy this directory to `wp-content/plugins/jwt-login-rs256-validator`.
2. In that directory, install the adapter-owned dependency:

   ```bash
   composer install --no-dev --classmap-authoritative
   ```

3. Add the configuration below to `wp-config.php` before WordPress loads plugins.
4. Activate **JWT Login Cookie Bridge - Example RS256 Validator**.

## Configuration

```php
define('JWT_LOGIN_ACTIVE_VALIDATOR', 'example/rs256');
define('JWT_LOGIN_RS256_PUBLIC_KEY_FILE', '/absolute/path/outside-the-web-root/jwt-public.pem');
define('JWT_LOGIN_RS256_ISSUER', 'https://issuer.example.com');
define('JWT_LOGIN_RS256_AUDIENCE', 'wordpress-store');
define('JWT_LOGIN_RS256_IDENTITY_CLAIM', 'wp_user_id');
define('JWT_LOGIN_RS256_MAXIMUM_LIFETIME', 300);
```

The key file must contain a usable RSA public key of at least 2048 bits. Do not place a private key in WordPress, source control, or this plugin. The issuer, audience, identity-claim name, key path, and algorithm are trusted server configuration and are never taken from the JWT.

The configured identity claim may contain a positive PHP integer or its canonical decimal string representation. Zero, negative values, leading signs or zeroes, non-decimal values, and values greater than `PHP_INT_MAX` are rejected. The example does not create users or map email addresses.

Keep issuer clocks synchronized. This minimal adapter uses no clock-skew allowance and limits `exp - iat` to the configured maximum. For immediate revocation, extend the adapter to require `jti` and consult trusted server-side revocation state before returning `JWT_Login_Verified_Identity`.

## MU-plugin installation

WordPress automatically loads only PHP files directly inside `wp-content/mu-plugins`; it does not discover plugin headers in nested directories. Install dependencies in a nested directory, for example:

```text
wp-content/mu-plugins/
├── jwt-login-rs256-validator-loader.php
└── jwt-login-rs256-validator/
    ├── jwt-login-rs256-validator.php
    └── vendor/
```

The top-level loader must contain:

```php
<?php
require_once WPMU_PLUGIN_DIR . '/jwt-login-rs256-validator/jwt-login-rs256-validator.php';
```

Registering at file scope is intentional. The adapter attaches to `jwt_login_register_validators` while plugins load; the Bridge fires that action at `plugins_loaded` priority 20 and locks the registry immediately afterward. Registering from `init`, `rest_api_init`, or a later hook is too late.

## Failure behavior

- Signature or claim rejection returns `WP_Error`; the Bridge responds with HTTP 401 without creating cookies or a session.
- Missing dependencies, incomplete configuration, or an invalid public key throw sanitized configuration exceptions; the Bridge responds with HTTP 503.
- Missing, duplicate, or unselected validator registrations remain fail-closed.
- Origin authorization still happens before validation, and the Bridge still returns HTTP 409 instead of silently replacing a different authenticated browser user.

Never log raw JWTs, keys, or detailed cryptographic exceptions.
