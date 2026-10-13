# JWT Login Cookie Bridge (SameSite + CORS)

**Version:** 2.3\
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
-  Compatible with WooCommerce session handling
-  WordPress and WooCommerce API–safe (no core file modification)

---

## 🧰 Installation

1. **Create plugin folder:**

   ```bash
   mkdir /var/www/html/wp-content/plugins/jwt-login-cookie
   cd /var/www/html/wp-content/plugins/jwt-login-cookie
   ```

2. **Copy the main file:** Save your plugin as:

   ```bash
   jwt-login-cookie.php
   ```

3. **Activate it** in your WordPress admin:\
   Go to **Plugins → Installed Plugins → Activate**

4. **Adjust your CORS whitelist** in `jwt_login_allowed_origins()` — include all frontend domains that should be allowed to log in.

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

### 2. Example (Angular frontend)

```typescript
this.http.post(
  'https://your-woo-domain.com/wp-json/custom/v1/login_via_jwt',
  { mode: 'popup', return_origin: window.location.origin },
  { withCredentials: true, headers: { Authorization: `Bearer ${jwt}` } }
).subscribe();
```

After success, WordPress recognizes the user as authenticated — your WooCommerce cart, orders, and account pages will now be accessible.

---

## 🧪 Real-world Example: Angular + Woo order-pay flow

Below is a real integration pattern used in production — an Angular component that logs in the user on WooCommerce using JWT, then redirects to the correct `/checkout/order-pay/:id` page.

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
  username: string;
  password: string;
  orderId: number;
  orderKey: string;
  checkoutSlug?: string;
}): Promise<void> {
  const checkoutSlug = opts.checkoutSlug ?? 'checkout';
  const payUrl = this.buildPayUrl(opts.wpBase, opts.orderId, opts.orderKey, checkoutSlug);

  const jwtRes = await fetch(`${opts.wpBase}/wp-json/jwt-auth/v1/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: opts.username, password: opts.password })
  });
  if (!jwtRes.ok) throw new Error(`JWT request failed: ${jwtRes.status}`);
  const { token } = await jwtRes.json();

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${opts.wpBase}/wp-json/custom/v1/login_via_jwt`;
  form.target = '_self';

  const inpToken = document.createElement('input');
  inpToken.type = 'hidden';
  inpToken.name = 'token';
  inpToken.value = token;

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
1. Angular app requests JWT via `/wp-json/jwt-auth/v1/token`.
2. Submits a hidden form to `/wp-json/custom/v1/login_via_jwt` (this plugin).
3. Plugin sets WordPress cookies and redirects user to `/checkout/order-pay/...`.
4. User is recognized as logged-in WooCommerce customer.

---

## ⚙️ Configuration Options

| Setting                                   | Description                                                |
| ----------------------------------------- | ---------------------------------------------------------- |
| `jwt_login_allowed_origins()`             | List of allowed frontend origins (CORS whitelist)          |
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

Body-token requests require an exact trusted HTTP(S) `Origin`. Bearer requests may omit `Origin` for server-to-server compatibility, but any supplied Origin must be trusted. Trusted origins are taken from `jwt_login_allowed_origins()` and the configured WordPress home/site URLs. CORS remains separate from this authorization check.

Bounce and WordPress redirect destinations are checked independently using their complete canonical origins, including scheme, host, and effective port. Explicit default ports are equivalent to omitted defaults; non-default ports must be explicitly trusted.

---

## 📦 Version History

| Version | Description                                                                      |
| ------- | -------------------------------------------------------------------------------- |
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
