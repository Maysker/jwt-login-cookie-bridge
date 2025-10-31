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
-  Works with most JWT authentication plugins (no dependencies)
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

The plugin validates the JWT (using your active JWT plugin), sets secure cookies, and optionally returns control via popup, bounce, or redirect.

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

To harden security further, ensure your JWT plugin verifies `iss`, `aud`, and token expiration properly.

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

