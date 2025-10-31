<?php
/**
 * Plugin Name: JWT Login Cookie (SameSite + CORS, Popup/Bounce, Embed Exception)
 * Description: Exchange a JWT for WP login cookies (SameSite=None; Secure) with strict CORS. Supports popup & same-tab bounce SSO. 
 * Adds an embed exception for WooCommerce checkout so it can be framed by your app.
 * Version: 2.3
 * Author: Adam Gazdiev(Airobot nv)
 * License: GPLv3 or later
 * License URL: https://www.gnu.org/licenses/gpl-3.0.html
 */

// =========================================================
// Config
// =========================================================
// In dev keep cookies on the exact host (e.g., dev.example.com).
// For prod you MAY override cookie domain (e.g., '.example.com').
// define('JWT_LOGIN_COOKIE_DOMAIN', '.example.com');

if (!function_exists('jwt_login_allowed_origins')) {
    /**
     * Whitelisted frontend origins (exact matches; no wildcards).
     * Adjust per environment.
     */
    function jwt_login_allowed_origins(): array {
        return [
            'https://frontend.example.com',
            // keep these for local/dev/testing if needed
            'https://dev.example.com',
            'https://localhost:4200',
            'http://localhost:4200',
        ];
    }
}

// =========================================================
// Helpers
// =========================================================
if (!function_exists('jwt_login_cookie_domain')) {
    /**
     * Return cookie domain to use.
     * - Dev: exact HTTP_HOST (first-party on dev host)
     * - Prod: override via JWT_LOGIN_COOKIE_DOMAIN if defined
     */
    function jwt_login_cookie_domain(): string {
        if (defined('JWT_LOGIN_COOKIE_DOMAIN') && JWT_LOGIN_COOKIE_DOMAIN) {
            return JWT_LOGIN_COOKIE_DOMAIN; 
        }
        if (defined('COOKIE_DOMAIN') && COOKIE_DOMAIN) {
            return COOKIE_DOMAIN;
        }
        return $_SERVER['HTTP_HOST'] ?? '';
    }
}

if (!function_exists('jwt_login_cookie_set_auth_cookies')) {
    /**
     * Set WP auth cookies manually with SameSite=None; Secure; HttpOnly.
     * Mirrors core behavior but forces attributes for cross-site usage.
     */
    function jwt_login_cookie_set_auth_cookies(int $user_id, bool $remember = true): void {
        $secure     = is_ssl();
        $httponly   = true;
        $domain     = jwt_login_cookie_domain();
        $now        = time();
        $expiration = $remember ? ($now + 14 * DAY_IN_SECONDS) : ($now + 2 * DAY_IN_SECONDS);

        // Generate cookies like core
        $auth_cookie         = wp_generate_auth_cookie($user_id, $expiration, 'auth');
        $secure_auth_cookie  = wp_generate_auth_cookie($user_id, $expiration, 'secure_auth');
        $logged_in_cookie    = wp_generate_auth_cookie($user_id, $expiration, 'logged_in');

        // Core paths
        $auth_path   = defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '/wp-admin';
        $logged_path = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';

        // AUTH
        setcookie(AUTH_COOKIE, $auth_cookie, [
            'expires'  => $expiration,
            'path'     => $auth_path,
            'domain'   => $domain,
            'secure'   => true,      // force Secure
            'httponly' => $httponly,
            'samesite' => 'None',
        ]);

        // SECURE_AUTH
        setcookie(SECURE_AUTH_COOKIE, $secure_auth_cookie, [
            'expires'  => $expiration,
            'path'     => $auth_path,
            'domain'   => $domain,
            'secure'   => true,
            'httponly' => $httponly,
            'samesite' => 'None',
        ]);

        // LOGGED_IN
        setcookie(LOGGED_IN_COOKIE, $logged_in_cookie, [
            'expires'  => $expiration,
            'path'     => $logged_path,
            'domain'   => $domain,
            'secure'   => true,
            'httponly' => $httponly,
            'samesite' => 'None',
        ]);
    }
}

if (!function_exists('jwt_login_maybe_bootstrap_woo_session')) {
    /**
     * Best-effort Woo session kick; harmless if Woo is not present.
     */
    function jwt_login_maybe_bootstrap_woo_session(): void {
        if (function_exists('WC') && method_exists(WC(), 'initialize_session')) {
            try { WC()->initialize_session(); } catch (\Throwable $e) {}
        }
    }
}

// Prevent core from sending its own cookies (we control attributes)
add_filter('send_auth_cookies', '__return_false');

// =========================================================
// REST: POST /wp-json/custom/v1/login_via_jwt
// Accept JWT via Authorization header OR request body (token).
// Supports modes:
//   - popup   : returns tiny HTML that postMessages 'woo-login-ok' and closes
//   - bounce  : returns tiny HTML that location.replace() back to your app
//   - redirect: same-host redirect to any URL (e.g., order-pay)
// =========================================================

add_action('rest_api_init', function () {
    register_rest_route('custom/v1', '/login_via_jwt', [
        'methods'             => 'POST',
        'permission_callback' => '__return_true',
        'callback'            => function (\WP_REST_Request $request) {
            // 1) Read token from Authorization header or body
            $authHeader = $request->get_header('authorization');
            $token = null;
            if ($authHeader && preg_match('/Bearer\s+(\S+)/', $authHeader, $m)) {
                $token = $m[1];
            }
            if (!$token) {
                $token = $request->get_param('token');
            }
            if (!$token) {
                return new \WP_Error('unauthorized', 'Missing token', ['status' => 401]);
            }

            // 2) Synthesize Authorization header if missing (for JWT plugins that read only headers)
            if (!$authHeader) {
                $fake = 'Bearer ' . $token;
                $_SERVER['HTTP_AUTHORIZATION']          = $fake;
                $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = $fake; // Apache/FastCGI
            }

            // 3) Resolve current user from JWT plugin hooks
            $user_id = apply_filters('determine_current_user', 0);
            if (!$user_id) { $user_id = apply_filters('determine_current_user', 0, $token); }
            if (!$user_id) {
                return new \WP_Error('unauthorized', 'Invalid token', ['status' => 401]);
            }

            // 4) Set current user + cookies and optionally initialize Woo session
            wp_set_current_user($user_id);
            jwt_login_cookie_set_auth_cookies($user_id, true);
            jwt_login_maybe_bootstrap_woo_session();

            // 5) Modes / redirects
            $mode          = $request->get_param('mode');          // 'popup' | 'bounce' | null
            $return_origin = $request->get_param('return_origin'); // for popup
            $return_to     = $request->get_param('return_to');     // for bounce
            $redirect      = $request->get_param('redirect');      // same-host redirect (e.g., order-pay)

            // --- POPUP ---
            if ($mode === 'popup') {
                $allowed = jwt_login_allowed_origins();
                $ok_origin = ($return_origin && in_array($return_origin, $allowed, true)) ? $return_origin : '';
                header('Content-Type: text/html; charset=utf-8');
                ?>
                <!doctype html><meta charset="utf-8">
                <script>
                  try {
                    var origin = <?php echo json_encode($ok_origin); ?>;
                    if (origin) { (window.opener || window.parent).postMessage('woo-login-ok', origin); }
                  } catch (e) {}
                  try { window.close(); } catch (e) {}
                </script>
                Logged in. You can close this window.
                <?php
                exit;
            }

            // --- BOUNCE ---
            if ($mode === 'bounce' && $return_to) {
                $allowed = jwt_login_allowed_origins();
                $host = parse_url($return_to, PHP_URL_HOST);
                $scheme = parse_url($return_to, PHP_URL_SCHEME);
                $origin = ($scheme && $host) ? ($scheme . '://' . $host) : '';
                if ($origin && in_array($origin, $allowed, true)) {
                    header('Content-Type: text/html; charset=utf-8');
                    ?>
                    <!doctype html><meta charset="utf-8">
                    <script>
                      try { window.location.replace(<?php echo json_encode($return_to); ?>); }
                      catch (e) { location.href = <?php echo json_encode($return_to); ?>; }
                    </script>
                    Redirecting...
                    <?php
                    exit;
                }
            }

            // --- Same-host redirect (safe) ---
            if ($redirect) {
                $this_host = $_SERVER['HTTP_HOST'] ?? '';
                $host = parse_url($redirect, PHP_URL_HOST);
                if ($host && $this_host && strcasecmp($host, $this_host) === 0) {
                    wp_safe_redirect($redirect);
                    exit;
                }
            }

            return ['success' => true, 'user_id' => $user_id];
        },
    ]);
});

// =========================================================
// CORS (strict whitelist)
// =========================================================
add_action('rest_api_init', function () {
    // Remove WP's default CORS so we can send strict headers
    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');

    add_filter('rest_pre_serve_request', function ($value) {
        $origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
        $allowed = jwt_login_allowed_origins();
        if ($origin && in_array($origin, $allowed, true)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Vary: Origin');
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Headers: Authorization, Content-Type');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        }
        return $value;
    });
}, 15);

// =========================================================
// Preflight for REST only (allowed origins)
// =========================================================
add_action('init', function () {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? '');
    $uri    = $_SERVER['REQUEST_URI'] ?? '';
    if ($method === 'OPTIONS' && strpos($uri, '/wp-json/') === 0) {
        $origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
        $allowed = jwt_login_allowed_origins();
        if ($origin && in_array($origin, $allowed, true)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Vary: Origin');
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Headers: Authorization, Content-Type');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            status_header(204);
            exit;
        }
        status_header(403);
        exit;
    }
});

// =========================================================
// EMBED EXCEPTION for Woo checkout (iframe from frontend.example.com)
// =========================================================
add_action('send_headers', function () {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (preg_match('#^/checkout/(?:order-pay/)?#', $uri)) {
        // Remove X-Frame-Options (added by WP core or security plugins)
        header_remove('X-Frame-Options');
        header('X-Frame-Options: ', true);

        // Build CSP frame-ancestors from allowed origins
        $origins = array_filter(jwt_login_allowed_origins(), function ($o) {
            return is_string($o) && preg_match('#^https?://#', $o);
        });
        $origins = array_map(function ($o) { return rtrim($o, '/'); }, $origins);
        if (!$origins) { $origins = ['https://frontend.example.com']; }

        // Replace any existing CSP to avoid conflicting policies
        header_remove('Content-Security-Policy');
        header("Content-Security-Policy: frame-ancestors 'self' " . implode(' ', $origins), true);
    }
}, 1000);

// Core sometimes adds X-Frame-Options via this hook on frontend
remove_action('template_redirect', 'wp_frame_options_header');