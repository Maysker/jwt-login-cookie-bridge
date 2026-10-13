# JWT Login Cookie Bridge (SameSite + CORS)

**Version:** 3.0.0\
**Author:** Adam Gazdiev\
**License:** GPLv3 or later

---

## 🔍 Overview

**JWT Login Cookie Bridge** is a lightweight WordPress plugin that enables **secure cross-domain login** between an external frontend (for example, an Angular or React SPA) and a WordPress/WooCommerce backend.

It acts as a **bridge** that exchanges a verified JWT token for native WordPress cookies — configured for modern browser requirements (`SameSite=None; Secure; HttpOnly`) and protected by a strict CORS whitelist.

This plugin was originally developed for **AiroCollect**, a SaaS platform integrating WooCommerce orders with its own Angular-based frontend, but it can be adapted to any environment where you need to authenticate users across different domains.

---

## ✨ Key Features

-  Exchange JWT for native WP/Woo cookies (auth, secure\_auth, logged\_in)
-  Full CORS control via origin whitelist
-  Optional iframe embedding (Content-Security-Policy / frame-ancestors)
-  Supports multiple redirect modes: `popup`, `bounce`, `redirect`
-  Enforces modern cookie attributes: `SameSite=None; Secure; HttpOnly`
-  Provider-agnostic validation contract with explicit server-side selection
-  Optional WooCommerce session and checkout integration
-  WordPress and WooCommerce API–safe (no core file modification)

---

## 🧰 Installation

1. **Install the release ZIP** in **Plugins → Add Plugin → Upload Plugin**, or extract it so the entry file is located at:

   ```bash
   wp-content/plugins/jwt-login-cookie/jwt-login-cookie.php
   ```

2. **Activate it** in your WordPress admin:\
   Go to **Plugins → Installed Plugins → Activate**

3. **Install and select exactly one trusted JWT validator.** The Bridge does not automatically use another JWT plugin. See [JWT-based login endpoint](#1-jwt-based-login-endpoint) and the migration guide.

4. **Configure trusted frontend origins** from a persistent MU-plugin or trusted configuration plugin. Do not edit `jwt-login-cookie.php`; see [Persistent frontend-Origin configuration](#persistent-frontend-origin-configuration).

Basic WordPress login bridging does not require WooCommerce. WooCommerce is needed only for WooCommerce session bootstrapping and the documented checkout, `order-pay`, and optional iframe integration.

For existing 2.3 installations, complete the [2.3 to 3.0.0 migration guide](MIGRATION-2.3-to-3.0.0.md) before upgrading. The planned 3.0.0 release does not automatically trust JWTs accepted by another WordPress plugin.

### Persistent frontend-Origin configuration

The `jwt_login_allowed_origins` filter is the public server-side configuration API. Register it at file scope from trusted code and return the complete list for the current environment. Returning a replacement list avoids retaining the example defaults unintentionally.

Create `wp-content/mu-plugins/jwt-login-bridge-config.php` (WordPress automatically loads PHP files directly in `mu-plugins`):

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

This callback must use server-controlled values; never build the list from `Origin`, `Host`, `Referer`, request parameters, or JWT claims. Each entry must be one absolute HTTP(S) origin containing only scheme, host, and optional port. Wildcards, credentials, paths, queries, fragments, control characters, backslashes, and malformed ports are rejected. Scheme and host are case-normalized, `:443` for HTTPS and `:80` for HTTP are removed, and every non-default port must be listed explicitly. Duplicate canonical origins collapse to one entry. Returning an empty array trusts no frontend origins. With no filter, the existing built-in list is unchanged.

The same frontend list controls browser request-Origin authorization, Bridge CORS grants, popup targets, bounce destinations, and the optional WooCommerce checkout `frame-ancestors` exception. Listing an origin therefore also makes it eligible to frame supported checkout and `order-pay` responses when no stricter existing CSP or X-Frame-Options policy blocks framing. Add only origins that should receive all of those narrowly scoped privileges. An invalid entry is never trusted for login or navigation and causes the optional checkout frame exception to fail closed.

### Iframe checkout policy

The optional iframe exception applies only when WooCommerce identifies the current response as its configured checkout page or `order-pay` endpoint. Custom checkout slugs and WordPress subdirectory installations therefore do not require URI-prefix configuration. Every configured frame ancestor must be one exact HTTP(S) origin; wildcards, paths, malformed origins, and fallback origins are not accepted.

The plugin appends a separate `frame-ancestors` policy and never deletes an existing CSP. If another plugin, the theme, WooCommerce, or PHP has already emitted `X-Frame-Options` or a CSP `frame-ancestors` directive, that policy remains authoritative and the plugin fires `jwt_login_frame_policy_conflict` with a sanitized reason. An administrator must explicitly update or remove the conflicting policy at its source before cross-origin framing will work. Headers added later by a reverse proxy or CDN cannot be changed or reliably detected by this plugin and must be configured there.

---

## 🔑 Usage

### 1. JWT-based login endpoint

Send a POST request from your frontend to:

```
POST https://your-woo-domain.com/wp-json/custom/v1/login_via_jwt
```

#### Headers

```
Authorization: Bearer <JWT>
Content-Type: application/json
```

#### Body (optional)

```json
{
  "mode": "popup",
  "return_origin": "https://your-frontend-domain.com"
}
```

The plugin requires one explicitly configured server-side validator to cryptographically verify the exact JWT and return a `JWT_Login_Verified_Identity`. It then sets secure cookies and optionally returns control via popup, bounce, or redirect. Installed WordPress authentication plugins are not used automatically.

Example registration from a trusted site plugin or adapter:

```php
define('JWT_LOGIN_ACTIVE_VALIDATOR', 'example/validator');

add_action('jwt_login_register_validators', function (): void {
    jwt_login_register_validator('example/validator', function (string $raw_jwt) {
        // Verify signature, algorithm, time constraints and required claims here.
        // Return WP_Error on every failure. Never merely decode the payload.
        $verified_wordpress_user_id = example_verify_jwt($raw_jwt);
        return is_wp_error($verified_wordpress_user_id)
            ? $verified_wordpress_user_id
            : new JWT_Login_Verified_Identity($verified_wordpress_user_id);
    });
});
```

This is an API example, not a built-in validator. Without exactly one registration matching `JWT_LOGIN_ACTIVE_VALIDATOR`, login fails closed.

A complete optional RS256 adapter with its own Composer dependency and installation instructions is available in [`examples/rs256-validator`](examples/rs256-validator/README.md). It is not loaded or selected automatically and does not add a JWT dependency to the Bridge.

### 2. Top-level popup example

Popup and bounce modes return navigation HTML and must be used as top-level window/form navigations, not as XHR or `fetch()` response handlers. Never put the JWT in the URL. This example opens a named popup and POSTs the token in a form body; the browser supplies the request `Origin`:

```typescript
function loginWithPopup(bridgeUrl: string, jwt: string): Window | null {
  const target = 'jwt-login-bridge-popup';
  const popup = window.open('', target, 'popup,width=520,height=640');
  if (!popup) return null;

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = bridgeUrl;
  form.target = target;

  for (const [name, value] of Object.entries({
    token: jwt,
    mode: 'popup',
    return_origin: window.location.origin,
  })) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  }

  document.body.appendChild(form);
  form.submit();
  form.remove();
  return popup;
}
```

The opener must accept only the fixed `woo-login-ok` message and must verify `event.origin` against its expected WordPress origin. The popup target is validated independently against the configured frontend-origin list. Browser cookie policy still applies; cross-site contexts require HTTPS and may be affected by third-party-cookie restrictions.

XHR or `fetch()` is appropriate only when the caller expects the normal JSON result and does not request popup, bounce, or redirect navigation behavior.

---

## 🧪 Real-world Example: Angular + Woo order-pay flow

Below is a top-level form-navigation pattern for a WooCommerce `/checkout/order-pay/:id` page. It is valid only when the selected Bridge validator has been explicitly configured to verify the exact token contract returned by the token issuer; installing a WordPress JWT plugin alone does not establish that compatibility.

```typescript
// ------------ Woo order-pay helpers ------------
private getWpBase(): string {
  const w: any = window as any;
  return (w.WP_BASE_URL as string) || 'https://yourdomain.com';
}

private buildPayUrl(base: string, orderId: number, orderKey: string, checkoutSlug = 'checkout'): string {
  return `${base.replace(/\/?$/, '')}/${checkoutSlug}/order-pay/${orderId}/?pay_for_order=true&key=${orderKey}`;
}

private async loginOnShopAndGoToPayTopLevel(opts: {
  wpBase: string;
  jwt: string;
  orderId: number;
  orderKey: string;
  checkoutSlug?: string;
}): Promise<void> {
  const checkoutSlug = opts.checkoutSlug ?? 'checkout';
  const payUrl = this.buildPayUrl(opts.wpBase, opts.orderId, opts.orderKey, checkoutSlug);

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${opts.wpBase}/wp-json/custom/v1/login_via_jwt`;
  form.target = '_self';

  const inpToken = document.createElement('input');
  inpToken.type = 'hidden';
  inpToken.name = 'token';
  inpToken.value = opts.jwt;

  const inpRedirect = document.createElement('input');
  inpRedirect.type = 'hidden';
  inpRedirect.name = 'redirect';
  inpRedirect.value = payUrl;

  form.appendChild(inpToken);
  form.appendChild(inpRedirect);
  document.body.appendChild(form);
  form.submit();
  form.remove();
}
```

### Flow Summary
1. The application obtains a JWT from the issuer configured for the selected Bridge validator.
2. It submits a hidden top-level form to `/wp-json/custom/v1/login_via_jwt` (this plugin).
3. Plugin sets WordPress cookies and redirects user to `/checkout/order-pay/...`.
4. User is recognized as logged-in WooCommerce customer.

---

## ⚙️ Configuration Options

| Setting                                   | Description                                                |
| ----------------------------------------- | ---------------------------------------------------------- |
| `jwt_login_allowed_origins` filter        | Replaces the trusted frontend-origin list from server-side code |
| `JWT_LOGIN_COOKIE_DOMAIN`                 | Optional cookie domain override                            |
| `JWT_LOGIN_ACTIVE_VALIDATOR`              | Required server-side ID of the trusted JWT validator       |
| `jwt_login_register_validator()`          | Registers a validator during `jwt_login_register_validators` |
| `jwt_login_cookie_set_auth_cookies()`     | Custom cookie setter with `SameSite=None` enforced         |
| `jwt_login_maybe_bootstrap_woo_session()` | Initializes WooCommerce session if available               |

---

## 🧩 Supported Redirect Modes

| Mode       | Description                                                           |
| ---------- | --------------------------------------------------------------------- |
| `popup`    | Sends `postMessage('woo-login-ok')` to frontend and closes the window |
| `bounce`   | Redirects user back to frontend URL with origin validation            |
| `redirect` | Simple same-host redirect (safe internal navigation)                  |

---

## 🛡️ Security

- Strict origin checking for CORS and redirects.
- No tokens or credentials are stored server-side.
- Cookies are always `HttpOnly`, `Secure`, and `SameSite=None`.
- Works with HTTPS only.

The selected validator is responsible for the cryptographic algorithm, key, temporal constraints and provider-specific required claims. Do not log raw JWTs or secrets.

Body-token requests require an exact trusted HTTP(S) `Origin`. Bearer requests may omit `Origin` for server-to-server compatibility, but any supplied Origin must be trusted. Trusted frontend origins come from the `jwt_login_allowed_origins` filter; configured WordPress home/site origins are also trusted for request authorization. CORS remains separate from this authorization check.

Bounce and WordPress redirect destinations are checked independently using their complete canonical origins, including scheme, host, and effective port. Explicit default ports are equivalent to omitted defaults; non-default ports must be explicitly trusted.

The plugin header's `Update URI` protects this independently hosted plugin from an unrelated WordPress.org slug collision. It does not make GitHub deliver updates automatically; updates remain a manual release-installation responsibility unless a separate trusted updater is configured.

The declared minimums are WordPress 5.8 and PHP 7.4 based on the APIs and language features used. Release installation is verified on the pinned WordPress 7.1.3/PHP 8.3 environment; older supported combinations are not part of the release-candidate runtime matrix.

---

## 📦 Version History

| Version | Description                                                                      |
| ------- | -------------------------------------------------------------------------------- |
| 3.0.0   | Breaking validator, transport, Origin, cookie, redirect, and framing hardening   |
| 2.3     | Stable release with popup/bounce/redirect modes, CSP support, long-lived cookies |
| 2.4–2.5 | Internal revisions, not published                                                |
| 2.6     | Production-optimized version for environments with server-level XFO disabled     |

---

## 📄 License & Attribution

**License:** GPLv3 or later\
**License URI:** [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html)

You are free to use, modify, and redistribute this plugin under the same license. Attribution to the original author must be retained in derivative works.

**Author:** [Adam Gazdiev](https://www.linkedin.com/in/adam-gazdiev/)\
**Original project:** [https://github.com/Maysker/jwt-login-cookie](https://github.com/Maysker/jwt-login-cookie-bridge)

---

## 💬 Notes

This plugin was created in real-world production conditions, under limited administrative control, to solve authentication issues between an Angular SPA and WooCommerce.

While situational by origin, its architecture is intentionally generic — anyone can adapt it for their own SSO or cross-domain login needs.

> *“A small bridge between two worlds — WordPress and modern web apps.”*
