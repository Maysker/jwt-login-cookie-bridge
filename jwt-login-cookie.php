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

/**
 * Immutable proof returned by a trusted validator after it has verified the
 * exact JWT supplied to the bridge. The initial mapping contract deliberately
 * supports only a signed, positive WordPress user ID.
 */
if (!class_exists('JWT_Login_Verified_Identity')) {
    final class JWT_Login_Verified_Identity {
        private int $user_id;

        public function __construct(int $user_id) {
            if ($user_id < 1) {
                throw new \InvalidArgumentException('A verified positive WordPress user ID is required.');
            }
            $this->user_id = $user_id;
        }

        public function user_id(): int {
            return $this->user_id;
        }
    }
}

if (!function_exists('jwt_login_register_validator')) {
    /**
     * Register a trusted server-side validator.
     *
     * Extensions should register during the jwt_login_register_validators
     * action. The callback receives the exact raw JWT and must return either a
     * JWT_Login_Verified_Identity after cryptographic verification or WP_Error.
     */
    function jwt_login_register_validator(string $id, callable $validator): bool {
        if (!empty($GLOBALS['jwt_login_validator_registry_locked']) || $id === '') {
            return false;
        }
        if (!isset($GLOBALS['jwt_login_validator_registry'][$id])) {
            $GLOBALS['jwt_login_validator_registry'][$id] = [];
        }
        $GLOBALS['jwt_login_validator_registry'][$id][] = $validator;
        return true;
    }
}

add_action('plugins_loaded', function (): void {
    $GLOBALS['jwt_login_validator_registry'] = [];
    do_action('jwt_login_register_validators');
    $GLOBALS['jwt_login_validator_registry_locked'] = true;
}, 20);

// =========================================================
// Helpers
// =========================================================
if (!function_exists('jwt_login_cookie_domain')) {
    /**
     * Return cookie domain to use.
     * - Default: host-only cookie (empty domain)
     * - Override via JWT_LOGIN_COOKIE_DOMAIN or WordPress COOKIE_DOMAIN
     */
    function jwt_login_cookie_domain(): string {
        if (defined('JWT_LOGIN_COOKIE_DOMAIN') && JWT_LOGIN_COOKIE_DOMAIN) {
            return JWT_LOGIN_COOKIE_DOMAIN;
        }
        if (defined('COOKIE_DOMAIN') && COOKIE_DOMAIN) {
            return COOKIE_DOMAIN;
        }
        return '';
    }
}

if (!function_exists('jwt_login_core_cookie_domain')) {
    /**
     * Return the cookie domain used by WordPress core.
     */
    function jwt_login_core_cookie_domain(): string {
        return defined('COOKIE_DOMAIN') && COOKIE_DOMAIN ? (string) COOKIE_DOMAIN : '';
    }
}

if (!function_exists('jwt_login_cookie_scopes_differ')) {
    /**
     * Whether core and Bridge cookies use distinct browser storage scopes.
     */
    function jwt_login_cookie_scopes_differ(): bool {
        $bridge_domain = jwt_login_cookie_domain();
        $core_domain   = jwt_login_core_cookie_domain();

        // An omitted Domain is host-only and differs from an explicit Domain,
        // including when that explicit Domain names the current site host.
        if (($bridge_domain === '') !== ($core_domain === '')) {
            return true;
        }

        $normalize = static function (string $value): string {
            return ltrim(strtolower($value), '.');
        };

        return $normalize($bridge_domain) !== $normalize($core_domain);
    }
}

if (!function_exists('jwt_login_cookie_expire_tuples')) {
    /**
     * Expire unique authentication cookie name/path tuples at one domain scope.
     *
     * @param array<int,array{name:string,path:string}> $tuples
     */
    function jwt_login_cookie_expire_tuples(array $tuples, string $domain): void {
        $options = [
            'expires'  => time() - YEAR_IN_SECONDS,
            'domain'   => $domain,
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'None',
        ];
        $sent = [];

        foreach ($tuples as $tuple) {
            $identity = $tuple['name'] . "\0" . $domain . "\0" . $tuple['path'];
            if (isset($sent[$identity])) {
                continue;
            }
            $sent[$identity] = true;
            setcookie($tuple['name'], '', array_merge($options, ['path' => $tuple['path']]));
        }
    }
}

if (!function_exists('jwt_login_cookie_expire_bridge_scope')) {
    /**
     * Expire the exact three cookie tuples emitted by the Bridge.
     */
    function jwt_login_cookie_expire_bridge_scope(): void {
        $auth_path   = defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '/wp-admin';
        $logged_path = defined('COOKIEPATH') && COOKIEPATH ? COOKIEPATH : '/';

        jwt_login_cookie_expire_tuples([
            ['name' => AUTH_COOKIE, 'path' => $auth_path],
            ['name' => SECURE_AUTH_COOKIE, 'path' => $auth_path],
            ['name' => LOGGED_IN_COOKIE, 'path' => $logged_path],
        ], jwt_login_cookie_domain());
    }
}

if (!function_exists('jwt_login_cookie_expire_core_scope')) {
    /**
     * Expire authentication cookie tuples issued by WordPress core.
     */
    function jwt_login_cookie_expire_core_scope(): void {
        $admin_path   = defined('ADMIN_COOKIE_PATH') ? (string) ADMIN_COOKIE_PATH : '/wp-admin';
        $plugins_path = defined('PLUGINS_COOKIE_PATH') ? (string) PLUGINS_COOKIE_PATH : '/wp-content/plugins';
        $cookie_path  = defined('COOKIEPATH') ? (string) COOKIEPATH : '/';
        $site_path    = defined('SITECOOKIEPATH') ? (string) SITECOOKIEPATH : '/';

        jwt_login_cookie_expire_tuples([
            ['name' => AUTH_COOKIE, 'path' => $admin_path],
            ['name' => SECURE_AUTH_COOKIE, 'path' => $admin_path],
            ['name' => AUTH_COOKIE, 'path' => $plugins_path],
            ['name' => SECURE_AUTH_COOKIE, 'path' => $plugins_path],
            ['name' => LOGGED_IN_COOKIE, 'path' => $cookie_path],
            ['name' => LOGGED_IN_COOKIE, 'path' => $site_path],
        ], jwt_login_core_cookie_domain());
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

        // Generate cookies like core, sharing one revocable session token.
        $session_token      = WP_Session_Tokens::get_instance($user_id)->create($expiration);
        $auth_cookie        = wp_generate_auth_cookie($user_id, $expiration, 'auth', $session_token);
        $secure_auth_cookie = wp_generate_auth_cookie($user_id, $expiration, 'secure_auth', $session_token);
        $logged_in_cookie   = wp_generate_auth_cookie($user_id, $expiration, 'logged_in', $session_token);

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

if (!function_exists('jwt_login_cookie_clear_auth_cookies')) {
    /**
     * Clear bridge cookies when their explicit domain differs from core.
     */
    function jwt_login_cookie_clear_auth_cookies(): void {
        if (!defined('JWT_LOGIN_COOKIE_DOMAIN') || !JWT_LOGIN_COOKIE_DOMAIN) {
            return;
        }

        // Core clears this scope itself when the configured domains match.
        if (!jwt_login_cookie_scopes_differ()) {
            return;
        }

        jwt_login_cookie_expire_bridge_scope();
    }
}

add_action('clear_auth_cookie', 'jwt_login_cookie_clear_auth_cookies');

if (!function_exists('jwt_login_cookie_clear_bridge_scope_after_core_login')) {
    /**
     * Keep successful core login authoritative when cookie scopes differ.
     */
    function jwt_login_cookie_clear_bridge_scope_after_core_login(): void {
        if (jwt_login_cookie_scopes_differ()) {
            jwt_login_cookie_expire_bridge_scope();
        }
    }
}

add_action('wp_login', 'jwt_login_cookie_clear_bridge_scope_after_core_login', 10, 0);

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

if (!function_exists('jwt_login_extract_token')) {
    /**
     * Read one JWT from an exact Bearer header or POST body, never the query.
     *
     * @return array{token:string,transport:string}|WP_Error
     */
    function jwt_login_extract_token(\WP_REST_Request $request) {
        $query = $request->get_query_params();
        if (array_key_exists('token', $query)) {
            return new \WP_Error('invalid_request', 'JWT query parameters are not accepted.', ['status' => 400]);
        }

        $form = $request->get_body_params();
        $json = $request->get_json_params();
        $has_form_token = array_key_exists('token', $form);
        $has_json_token = is_array($json) && array_key_exists('token', $json);
        if ($has_form_token && $has_json_token) {
            return new \WP_Error('invalid_request', 'Multiple token body values are not accepted.', ['status' => 400]);
        }
        $body_token = $has_form_token ? $form['token'] : ($has_json_token ? $json['token'] : null);

        $auth_header = $request->get_header('authorization');
        $has_auth_header = is_string($auth_header) && $auth_header !== '';
        $header_token = null;
        if ($has_auth_header) {
            if (!preg_match('/\ABearer[ \t]+([^\s]+)\z/i', $auth_header, $matches)) {
                return new \WP_Error('invalid_request', 'Authorization header must contain one Bearer token.', ['status' => 400]);
            }
            $header_token = $matches[1];
        }

        if ($header_token !== null && $body_token !== null) {
            return new \WP_Error('invalid_request', 'Use either a Bearer token or a body token, not both.', ['status' => 400]);
        }

        $token = $header_token ?? $body_token;
        if (!is_string($token) || $token === '') {
            return new \WP_Error('unauthorized', 'Missing token', ['status' => 401]);
        }
        if (strlen($token) > 8192) {
            return new \WP_Error('invalid_request', 'Token is too large.', ['status' => 400]);
        }

        return [
            'token'     => $token,
            'transport' => $header_token !== null ? 'bearer' : 'body',
        ];
    }
}

if (!function_exists('jwt_login_canonical_origin')) {
    /**
     * Return a canonical HTTP(S) origin, or an empty string when invalid.
     * WordPress URLs may contain an installation path; request/configured
     * origins may not.
     */
    function jwt_login_canonical_origin($value, bool $allow_path = false): string {
        if (!is_string($value) || $value === '' || $value === 'null') {
            return '';
        }
        if (preg_match('/[\x00-\x20\x7f,]/', $value)) {
            return '';
        }

        $parts = wp_parse_url($value);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return '';
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            return '';
        }
        if (!$allow_path && isset($parts['path']) && $parts['path'] !== '') {
            return '';
        }

        $scheme = strtolower((string) $parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            return '';
        }

        $host = strtolower((string) $parts['host']);
        if ($host === '') {
            return '';
        }
        if (strpos($host, ':') !== false && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : null;
        if ($port !== null && ($port < 1 || $port > 65535)) {
            return '';
        }
        $default_port = $scheme === 'https' ? 443 : 80;

        return $scheme . '://' . $host . (($port !== null && $port !== $default_port) ? ':' . $port : '');
    }
}

if (!function_exists('jwt_login_trusted_origins')) {
    /**
     * Return canonical frontend origins plus trusted WordPress URL origins.
     */
    function jwt_login_trusted_origins(): array {
        $origins = [];
        foreach (jwt_login_allowed_origins() as $allowed_origin) {
            $origin = jwt_login_canonical_origin($allowed_origin);
            if ($origin !== '') {
                $origins[$origin] = true;
            }
        }
        foreach ([home_url('/'), site_url('/')] as $wordpress_url) {
            $origin = jwt_login_canonical_origin($wordpress_url, true);
            if ($origin !== '') {
                $origins[$origin] = true;
            }
        }

        return array_keys($origins);
    }
}

if (!function_exists('jwt_login_destination_origin')) {
    /**
     * Return the canonical origin of an absolute HTTP(S) destination URL.
     * Paths, queries, and fragments are allowed; credentials and ambiguous
     * backslash syntax are not.
     */
    function jwt_login_destination_origin($value): string {
        if (!is_string($value)
            || $value === ''
            || preg_match('/[\x00-\x20\x7f\\\\]/', $value)
        ) {
            return '';
        }

        $parts = wp_parse_url($value);
        if (!is_array($parts)
            || empty($parts['scheme'])
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            return '';
        }

        $host = (string) $parts['host'];
        if (strpos($host, ':') !== false && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }
        $origin = (string) $parts['scheme'] . '://' . $host;
        if (isset($parts['port'])) {
            $origin .= ':' . (string) $parts['port'];
        }

        return jwt_login_canonical_origin($origin);
    }
}

if (!function_exists('jwt_login_allowed_frontend_origins')) {
    function jwt_login_allowed_frontend_origins(): array {
        $origins = [];
        foreach (jwt_login_allowed_origins() as $configured_origin) {
            $origin = jwt_login_canonical_origin($configured_origin);
            if ($origin !== '') {
                $origins[$origin] = true;
            }
        }

        return array_keys($origins);
    }
}

if (!function_exists('jwt_login_wordpress_origins')) {
    function jwt_login_wordpress_origins(): array {
        $origins = [];
        foreach ([home_url('/'), site_url('/')] as $wordpress_url) {
            $origin = jwt_login_canonical_origin($wordpress_url, true);
            if ($origin !== '') {
                $origins[$origin] = true;
            }
        }

        return array_keys($origins);
    }
}

if (!function_exists('jwt_login_destination_is_allowed')) {
    function jwt_login_destination_is_allowed($destination, array $trusted_origins): bool {
        $origin = jwt_login_destination_origin($destination);

        return $origin !== '' && in_array($origin, $trusted_origins, true);
    }
}

if (!function_exists('jwt_login_authorize_origin')) {
    /**
     * Body tokens are browser-capable and always require a trusted Origin.
     * Bearer clients may omit Origin, but a supplied Origin must be trusted.
     *
     * @return true|WP_Error
     */
    function jwt_login_authorize_origin(\WP_REST_Request $request, string $transport) {
        $raw_origin = $request->get_header('origin');
        if (!is_string($raw_origin) || $raw_origin === '') {
            return $transport === 'bearer'
                ? true
                : new \WP_Error('forbidden_origin', 'Request origin is not allowed.', ['status' => 403]);
        }

        $origin = jwt_login_canonical_origin($raw_origin);
        if ($origin === '' || !in_array($origin, jwt_login_trusted_origins(), true)) {
            return new \WP_Error('forbidden_origin', 'Request origin is not allowed.', ['status' => 403]);
        }

        return true;
    }
}

if (!function_exists('jwt_login_validate_and_map_token')) {
    /**
     * Validate the exact JWT with the one explicitly selected validator and
     * map its verified user ID to an existing WordPress user.
     *
     * @return WP_User|WP_Error
     */
    function jwt_login_validate_and_map_token(string $token) {
        if (!defined('JWT_LOGIN_ACTIVE_VALIDATOR') || !is_string(JWT_LOGIN_ACTIVE_VALIDATOR) || JWT_LOGIN_ACTIVE_VALIDATOR === '') {
            return new \WP_Error('validator_unavailable', 'JWT validator is unavailable.', ['status' => 503]);
        }

        $registered = $GLOBALS['jwt_login_validator_registry'][JWT_LOGIN_ACTIVE_VALIDATOR] ?? [];
        if (count($registered) !== 1 || !is_callable($registered[0])) {
            return new \WP_Error('validator_unavailable', 'JWT validator is unavailable.', ['status' => 503]);
        }

        try {
            $identity = call_user_func($registered[0], $token);
        } catch (\Throwable $error) {
            return new \WP_Error('validator_failure', 'JWT validator failed.', ['status' => 503]);
        }

        if (is_wp_error($identity)) {
            return new \WP_Error('unauthorized', 'Invalid token', ['status' => 401]);
        }
        if (!$identity instanceof JWT_Login_Verified_Identity) {
            return new \WP_Error('validator_failure', 'JWT validator failed.', ['status' => 503]);
        }

        $user = get_user_by('id', $identity->user_id());
        if (!$user instanceof \WP_User) {
            return new \WP_Error('unauthorized', 'Invalid token', ['status' => 401]);
        }

        return $user;
    }
}

if (!function_exists('jwt_login_browser_cookie_user_id')) {
    /**
     * Return only the user authenticated by the browser's logged-in cookie.
     * This is used after JWT validation solely for identity-conflict policy.
     */
    function jwt_login_browser_cookie_user_id(): int {
        if (!defined('LOGGED_IN_COOKIE') || empty($_COOKIE[LOGGED_IN_COOKIE]) || !is_string($_COOKIE[LOGGED_IN_COOKIE])) {
            return 0;
        }
        $user_id = wp_validate_auth_cookie(wp_unslash($_COOKIE[LOGGED_IN_COOKIE]), 'logged_in');
        return $user_id ? (int) $user_id : 0;
    }
}

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
            // 1) Extract the exact JWT and identify its transport.
            $token_input = jwt_login_extract_token($request);
            if (is_wp_error($token_input)) {
                return $token_input;
            }

            // 2) Authorize browser-capable requests before JWT validation.
            $origin_authorized = jwt_login_authorize_origin($request, $token_input['transport']);
            if (is_wp_error($origin_authorized)) {
                return $origin_authorized;
            }

            // 3) Independently validate and map the exact supplied JWT.
            $user = jwt_login_validate_and_map_token($token_input['token']);
            if (is_wp_error($user)) {
                return $user;
            }
            $user_id = (int) $user->ID;

            // 4) Never silently replace a different browser-cookie identity.
            $cookie_user_id = jwt_login_browser_cookie_user_id();
            if ($cookie_user_id && $cookie_user_id !== $user_id) {
                return new \WP_Error('identity_conflict', 'JWT user conflicts with the browser session.', ['status' => 409]);
            }

            // 5) Set current user + cookies and optionally initialize Woo session.
            wp_set_current_user($user_id);
            if (jwt_login_cookie_scopes_differ()) {
                jwt_login_cookie_expire_core_scope();
            }
            jwt_login_cookie_set_auth_cookies($user_id, true);
            jwt_login_maybe_bootstrap_woo_session();

            // 6) Modes / redirects
            $mode          = $request->get_param('mode');          // 'popup' | 'bounce' | null
            $return_origin = $request->get_param('return_origin'); // for popup
            $return_to     = $request->get_param('return_to');     // for bounce
            $redirect      = $request->get_param('redirect');      // same-host redirect (e.g., order-pay)

            // --- POPUP ---
            if ($mode === 'popup') {
                $ok_origin = jwt_login_canonical_origin($return_origin);
                if ($ok_origin === '' || !in_array($ok_origin, jwt_login_allowed_frontend_origins(), true)) {
                    $ok_origin = '';
                }
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
                if (jwt_login_destination_is_allowed($return_to, jwt_login_allowed_frontend_origins())) {
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

            // --- Configured WordPress-origin redirect ---
            if ($redirect) {
                if (jwt_login_destination_is_allowed($redirect, jwt_login_wordpress_origins())
                    && wp_safe_redirect($redirect)
                ) {
                    exit;
                }
            }

            return ['success' => true, 'user_id' => $user_id];
        },
    ]);
});

// =========================================================
// Bridge-only REST CORS and preflight handling
// =========================================================
if (!function_exists('jwt_login_is_bridge_rest_request')) {
    function jwt_login_is_bridge_rest_request(\WP_REST_Request $request): bool {
        return $request->get_route() === '/custom/v1/login_via_jwt';
    }
}

if (!function_exists('jwt_login_trusted_request_origin')) {
    function jwt_login_trusted_request_origin(\WP_REST_Request $request): string {
        $origin = jwt_login_canonical_origin($request->get_header('origin'));

        return $origin !== '' && in_array($origin, jwt_login_trusted_origins(), true)
            ? $origin
            : '';
    }
}

if (!function_exists('jwt_login_preflight_headers_are_allowed')) {
    function jwt_login_preflight_headers_are_allowed($value): bool {
        if (!is_string($value) || $value === '') {
            return true;
        }

        $allowed = ['authorization' => true, 'content-type' => true];
        foreach (explode(',', $value) as $header) {
            $header = trim($header);
            if ($header === ''
                || !preg_match("/\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\\z/", $header)
                || !isset($allowed[strtolower($header)])
            ) {
                return false;
            }
        }

        return true;
    }
}

if (!function_exists('jwt_login_add_vary_header')) {
    /**
     * Add one Vary token without discarding values emitted by WordPress or plugins.
     */
    function jwt_login_add_vary_header(string $required): void {
        $tokens = [];
        foreach (headers_list() as $header) {
            if (stripos($header, 'Vary:') !== 0) {
                continue;
            }
            foreach (explode(',', substr($header, 5)) as $token) {
                $token = trim($token);
                if ($token !== '') {
                    $tokens[strtolower($token)] = $token;
                }
            }
        }

        if (!isset($tokens['*'])) {
            $tokens[strtolower($required)] = $required;
        }

        header_remove('Vary');
        header('Vary: ' . implode(', ', $tokens), true);
    }
}

add_filter('rest_pre_dispatch', function ($result, \WP_REST_Server $server, \WP_REST_Request $request) {
    if (!jwt_login_is_bridge_rest_request($request) || strtoupper($request->get_method()) !== 'OPTIONS') {
        return $result;
    }

    if (jwt_login_trusted_request_origin($request) === '') {
        return new \WP_Error('forbidden_origin', 'Request origin is not allowed.', ['status' => 403]);
    }

    $requested_method = $request->get_header('access-control-request-method');
    if (!is_string($requested_method)
        || strcasecmp(trim($requested_method), 'POST') !== 0
        || !jwt_login_preflight_headers_are_allowed($request->get_header('access-control-request-headers'))
    ) {
        return new \WP_Error('invalid_preflight', 'Preflight request is not allowed.', ['status' => 403]);
    }

    $response = new \WP_REST_Response(null, 204);
    $response->header('Allow', 'POST, OPTIONS');
    return $response;
}, 9, 3);

add_filter('rest_pre_serve_request', function ($served, $result, \WP_REST_Request $request) {
    if (!jwt_login_is_bridge_rest_request($request)) {
        return $served;
    }

    foreach ([
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Allow-Headers',
        'Access-Control-Allow-Methods',
    ] as $header) {
        header_remove($header);
    }

    jwt_login_add_vary_header('Origin');
    $origin = jwt_login_trusted_request_origin($request);
    if ($origin !== '') {
        header('Access-Control-Allow-Origin: ' . $origin, true);
        header('Access-Control-Allow-Credentials: true', true);

        if (strtoupper($request->get_method()) === 'OPTIONS') {
            header('Access-Control-Allow-Headers: Authorization, Content-Type', true);
            header('Access-Control-Allow-Methods: POST, OPTIONS', true);
        }
    }

    return $served;
}, 20, 3);

// =========================================================
// Scoped frame policy for verified WooCommerce checkout pages
// =========================================================
if (!function_exists('jwt_login_is_embeddable_checkout_request')) {
    function jwt_login_is_embeddable_checkout_request(): bool {
        if (is_admin()
            || (function_exists('wp_doing_ajax') && wp_doing_ajax())
            || (defined('REST_REQUEST') && REST_REQUEST)
            || !function_exists('is_checkout')
            || !is_checkout()
        ) {
            return false;
        }

        // The checkout page and order-pay endpoint are supported. Other
        // checkout endpoints retain their native framing policy.
        if (function_exists('is_wc_endpoint_url') && is_wc_endpoint_url()) {
            return is_wc_endpoint_url('order-pay');
        }

        return true;
    }
}

if (!function_exists('jwt_login_frame_ancestor_origins')) {
    /**
     * Return strictly canonical configured origins, or null on invalid config.
     */
    function jwt_login_frame_ancestor_origins(): ?array {
        $origins = [];
        foreach (jwt_login_allowed_origins() as $configured_origin) {
            $origin = jwt_login_canonical_origin($configured_origin);
            if ($origin === '') {
                return null;
            }
            $origins[$origin] = true;
        }

        return $origins ? array_keys($origins) : null;
    }
}

if (!function_exists('jwt_login_response_header_values')) {
    /**
     * Return current PHP response-header values without altering them.
     */
    function jwt_login_response_header_values(string $name): array {
        $values = [];
        $prefix = strtolower($name) . ':';
        foreach (headers_list() as $header) {
            if (strpos(strtolower($header), $prefix) === 0) {
                $values[] = trim(substr($header, strlen($prefix)));
            }
        }

        return $values;
    }
}

if (!function_exists('jwt_login_csp_has_frame_ancestors')) {
    function jwt_login_csp_has_frame_ancestors(array $policies): bool {
        foreach ($policies as $policy) {
            foreach (explode(';', $policy) as $directive) {
                $parts = preg_split('/\s+/', trim($directive), 2);
                if (is_array($parts) && isset($parts[0]) && strtolower($parts[0]) === 'frame-ancestors') {
                    return true;
                }
            }
        }

        return false;
    }
}

add_action('template_redirect', function (): void {
    if (!jwt_login_is_embeddable_checkout_request()) {
        return;
    }

    $origins = jwt_login_frame_ancestor_origins();
    if ($origins === null) {
        do_action('jwt_login_frame_policy_conflict', 'invalid_frame_ancestor_origin');
        return;
    }

    // WooCommerce's default callback runs later on template_redirect and adds
    // SAMEORIGIN headers. Suppress it only for this verified checkout response;
    // any policy already emitted by another component remains authoritative.
    remove_action('template_redirect', 'wc_send_frame_options_header');

    if (jwt_login_response_header_values('X-Frame-Options')) {
        do_action('jwt_login_frame_policy_conflict', 'existing_x_frame_options');
        return;
    }

    $policies = jwt_login_response_header_values('Content-Security-Policy');
    if (jwt_login_csp_has_frame_ancestors($policies)) {
        do_action('jwt_login_frame_policy_conflict', 'existing_content_security_policy_frame_ancestors');
        return;
    }

    // A separate policy preserves all existing CSP directives. Multiple CSP
    // headers are enforced together, so this can only narrow framing access.
    header("Content-Security-Policy: frame-ancestors 'self' " . implode(' ', $origins), false);
}, 0);
