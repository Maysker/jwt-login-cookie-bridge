<?php
/**
 * Plugin Name: JWT Bridge Integration Test Driver
 * Description: Test-only endpoints for the disposable integration environment.
 */

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

if (isset($_GET['jwt_bridge_origin_fixture'])) {
    $jwt_bridge_origin_fixture = (string) $_GET['jwt_bridge_origin_fixture'];
    add_filter('jwt_login_allowed_origins', function (array $default_origins) use ($jwt_bridge_origin_fixture): array {
        if ($jwt_bridge_origin_fixture === 'single') {
            return ['https://single.example.com:443'];
        }
        if ($jwt_bridge_origin_fixture === 'ports') {
            return [
                'https://frontend.example.com',
                'http://http-frontend.example.com',
                'https://ports.example.com:4443',
            ];
        }
        if ($jwt_bridge_origin_fixture === 'duplicates') {
            return [
                'https://frontend.example.com',
                'https://FRONTEND.example.com:443',
                'https://ports.example.com:4443',
                'https://ports.example.com:4443',
            ];
        }
        if ($jwt_bridge_origin_fixture === 'invalid') {
            return [
                'https://frontend.example.com',
                'https://*.example.com',
                'https://user:password@frontend.example.com',
                'https://frontend.example.com/path',
                'https://frontend.example.com?query=value',
                'https://frontend.example.com#fragment',
                'https://frontend.example.com:99999',
                '//frontend.example.com',
                "https://frontend.example.com\\evil",
                "https://frontend.example.com\x01",
            ];
        }
        if ($jwt_bridge_origin_fixture === 'empty') {
            return [];
        }

        return $default_origins;
    });
}

if (getenv('JWT_BRIDGE_TEST_DISABLE_FIREBASE_AUTOLOAD') !== '1') {
    spl_autoload_register(function (string $class): void {
        $prefix = 'Firebase\\JWT\\';
        if (strpos($class, $prefix) !== 0) {
            return;
        }
        $file = __DIR__ . '/jwt-bridge-test-vendor/php-jwt/src/' . substr($class, strlen($prefix)) . '.php';
        if (is_readable($file)) {
            require_once $file;
        }
    });
}

function jwt_bridge_test_authorized(WP_REST_Request $request): bool {
    $expected = getenv('JWT_BRIDGE_TEST_SECRET');
    $provided = $request->get_header('x-jwt-bridge-test-secret');

    return is_string($expected)
        && $expected !== ''
        && is_string($provided)
        && hash_equals($expected, $provided);
}

add_action('jwt_login_register_validators', function (): void {
    $mode = getenv('JWT_BRIDGE_TEST_VALIDATOR_MODE') ?: 'reference';
    if ($mode === 'missing') {
        return;
    }

    $validator = function (string $raw_token) use ($mode) {
        if ($mode === 'throw') {
            throw new RuntimeException('Intentional test validator failure.');
        }
        if ($mode === 'unexpected-return') {
            return true;
        }

        $key       = getenv('JWT_BRIDGE_TEST_JWT_KEY');
        $algorithm = getenv('JWT_BRIDGE_TEST_JWT_ALGORITHM');
        $issuer    = getenv('JWT_BRIDGE_TEST_JWT_ISSUER');
        if (!$key || !$algorithm || !$issuer) {
            return new WP_Error('test_validator_config', 'Test validator is not configured.');
        }

        try {
            $claims = JWT::decode($raw_token, new Key($key, $algorithm));
        } catch (Throwable $error) {
            return new WP_Error('test_invalid_jwt', 'Test JWT validation failed.');
        }

        if (!isset($claims->iss) || !is_string($claims->iss) || !hash_equals($issuer, $claims->iss)) {
            return new WP_Error('test_invalid_issuer', 'Test JWT issuer is invalid.');
        }
        $user_id = $claims->wp_user_id ?? null;
        if (!(is_int($user_id) || (is_string($user_id) && preg_match('/\A[1-9][0-9]*\z/', $user_id)))) {
            return new WP_Error('test_invalid_identity', 'Test JWT identity is invalid.');
        }

        return new JWT_Login_Verified_Identity((int) $user_id);
    };

    jwt_login_register_validator('test/reference', $validator);
    if ($mode === 'duplicate') {
        jwt_login_register_validator('test/reference', $validator);
    }
});

add_action('rest_api_init', function (): void {
    register_rest_route('jwt-bridge-test/v1', '/origin-config', [
        'methods'             => 'GET',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (): WP_REST_Response {
            return new WP_REST_Response([
                'allowed' => jwt_login_allowed_frontend_origins(),
                'frame'   => jwt_login_frame_ancestor_origins(),
            ]);
        },
    ]);

    register_rest_route('jwt-bridge-test/v1', '/authenticated-user', [
        'methods'             => 'GET',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (): WP_REST_Response {
            // REST cookie authentication requires a REST nonce, so validate the
            // browser cookie directly to observe the identity selected by PHP.
            $cookie = isset($_COOKIE[LOGGED_IN_COOKIE]) && is_string($_COOKIE[LOGGED_IN_COOKIE])
                ? wp_unslash($_COOKIE[LOGGED_IN_COOKIE])
                : '';
            $user_id = $cookie !== '' ? wp_validate_auth_cookie($cookie, 'logged_in') : false;

            return new WP_REST_Response([
                'user_id' => $user_id ? (int) $user_id : 0,
            ]);
        },
    ]);

    register_rest_route('jwt-bridge-test/v1', '/session-count', [
        'methods'             => 'GET',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (WP_REST_Request $request): WP_REST_Response {
            $user_id = absint($request->get_param('user_id'));
            $sessions = WP_Session_Tokens::get_instance($user_id)->get_all();

            return new WP_REST_Response(['count' => count($sessions)]);
        },
    ]);

    register_rest_route('jwt-bridge-test/v1', '/create-cookie-session', [
        'methods'             => 'POST',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (WP_REST_Request $request) {
            $user_id = absint($request->get_param('user_id'));
            if (!$user_id || !get_user_by('id', $user_id)) {
                return new WP_Error('invalid_user', 'A valid integration-test user is required.', ['status' => 400]);
            }

            wp_set_current_user($user_id);
            jwt_login_cookie_set_auth_cookies($user_id, true);

            return new WP_REST_Response(['created' => true, 'user_id' => $user_id]);
        },
    ]);

    register_rest_route('jwt-bridge-test/v1', '/reset-sessions', [
        'methods'             => 'POST',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (WP_REST_Request $request): WP_REST_Response {
            $user_id = absint($request->get_param('user_id'));
            WP_Session_Tokens::get_instance($user_id)->destroy_all();

            return new WP_REST_Response(['reset' => true]);
        },
    ]);

    register_rest_route('jwt-bridge-test/v1', '/issue-jwt', [
        'methods'             => 'POST',
        'permission_callback' => 'jwt_bridge_test_authorized',
        'callback'            => function (WP_REST_Request $request) {
            $key       = getenv('JWT_BRIDGE_TEST_JWT_KEY');
            $algorithm = getenv('JWT_BRIDGE_TEST_JWT_ALGORITHM');
            $issuer    = getenv('JWT_BRIDGE_TEST_JWT_ISSUER');
            if (!$key || !$algorithm || !$issuer) {
                return new WP_Error('test_issuer_config', 'Test JWT issuer is not configured.', ['status' => 500]);
            }

            $user_id = $request->get_param('user_id');
            if (!(is_int($user_id) || (is_string($user_id) && preg_match('/\A[1-9][0-9]*\z/', $user_id)))) {
                return new WP_Error('test_issuer_user', 'A positive test user ID is required.', ['status' => 400]);
            }

            $now = time();
            $variant = (string) $request->get_param('variant');
            $claims = [
                'iss'        => $issuer,
                'iat'        => $now,
                'nbf'        => $now - 1,
                'exp'        => $now + 300,
                'wp_user_id' => (int) $user_id,
            ];
            $signing_key = $key;

            if ($variant === 'invalid-signature') {
                $signing_key .= '-invalid';
            } elseif ($variant === 'expired') {
                $claims['iat'] = $now - 300;
                $claims['nbf'] = $now - 300;
                $claims['exp'] = $now - 60;
            } elseif ($variant === 'future-nbf') {
                $claims['iat'] = $now;
                $claims['nbf'] = $now + 300;
                $claims['exp'] = $now + 600;
            } elseif ($variant === 'wrong-issuer') {
                $claims['iss'] = 'https://wrong-issuer.example.invalid';
            } elseif ($variant === 'invalid-user') {
                $claims['wp_user_id'] = 2147483647;
            }

            return new WP_REST_Response([
                'token' => JWT::encode($claims, $signing_key, $algorithm),
            ]);
        },
    ]);
});

add_filter('rest_pre_serve_request', function ($served, $result, WP_REST_Request $request) {
    if ($request->get_route() === '/custom/v1/login_via_jwt') {
        header('Vary: Accept-Encoding', false);
    }

    return $served;
}, 15, 3);

add_action('send_headers', function (): void {
    $fixture = isset($_GET['jwt_bridge_frame_fixture'])
        ? sanitize_key(wp_unslash($_GET['jwt_bridge_frame_fixture']))
        : '';

    if ($fixture === 'existing-csp') {
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; report-uri /csp-report", false);
    } elseif ($fixture === 'restrictive-csp') {
        header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; report-to csp-endpoint", false);
    } elseif ($fixture === 'xfo') {
        header('X-Frame-Options: DENY', true);
    }
}, 900);

add_action('jwt_login_frame_policy_conflict', function (string $reason): void {
    header('X-JWT-Bridge-Test-Frame-Conflict: ' . $reason, false);
});
