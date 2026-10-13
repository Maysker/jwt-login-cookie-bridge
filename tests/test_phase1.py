import re
import unittest
from pathlib import Path


PLUGIN = Path(__file__).resolve().parents[1] / "jwt-login-cookie.php"


class PhaseOneRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PLUGIN.read_text(encoding="utf-8")

    def function_source(self, name):
        match = re.search(
            rf"function {name}\([^)]*\).*?\n    \}}\n\}}",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(match, f"Could not find {name}()")
        return match.group(0)

    def test_login_route_and_token_inputs_are_preserved(self):
        self.assertIn("register_rest_route('custom/v1', '/login_via_jwt'", self.source)
        self.assertIn("'methods'             => 'POST'", self.source)
        self.assertIn("$request->get_header('authorization')", self.source)
        self.assertIn("$request->get_body_params()", self.source)
        self.assertIn("$request->get_json_params()", self.source)

    def test_response_modes_are_preserved(self):
        for mode in ("popup", "bounce"):
            self.assertIn(f"$mode === '{mode}'", self.source)
        self.assertIn("$request->get_param('redirect')", self.source)
        self.assertIn("wp_safe_redirect($redirect)", self.source)

    def test_cookie_attributes_and_paths_are_preserved(self):
        setter = self.function_source("jwt_login_cookie_set_auth_cookies")
        self.assertIn("ADMIN_COOKIE_PATH", setter)
        self.assertIn("COOKIEPATH", setter)
        self.assertEqual(3, setter.count("'secure'   => true"))
        self.assertEqual(3, setter.count("'httponly' => $httponly"))
        self.assertEqual(3, setter.count("'samesite' => 'None'"))
        self.assertEqual(3, setter.count("'domain'   => $domain"))

    def test_default_cookie_scope_is_host_only(self):
        domain_helper = self.function_source("jwt_login_cookie_domain")
        self.assertNotIn("HTTP_HOST", domain_helper)
        self.assertIn("return '';", domain_helper)

    def test_explicit_bridge_domain_is_cleared_on_core_logout(self):
        clearer = self.function_source("jwt_login_cookie_clear_auth_cookies")
        self.assertIn("JWT_LOGIN_COOKIE_DOMAIN", clearer)
        self.assertIn("jwt_login_cookie_scopes_differ()", clearer)
        self.assertIn("jwt_login_cookie_expire_bridge_scope()", clearer)

        expirer = self.function_source("jwt_login_cookie_expire_tuples")
        self.assertIn("time() - YEAR_IN_SECONDS", expirer)
        self.assertIn("'secure'   => true", expirer)
        self.assertIn("'httponly' => true", expirer)
        self.assertIn("'samesite' => 'None'", expirer)
        self.assertIn("setcookie($tuple['name']", expirer)

        bridge_scope = self.function_source("jwt_login_cookie_expire_bridge_scope")
        self.assertIn("AUTH_COOKIE", bridge_scope)
        self.assertIn("SECURE_AUTH_COOKIE", bridge_scope)
        self.assertIn("LOGGED_IN_COOKIE", bridge_scope)
        self.assertIn(
            "add_action('clear_auth_cookie', 'jwt_login_cookie_clear_auth_cookies')",
            self.source,
        )

    def test_mixed_login_transitions_clear_the_other_cookie_scope(self):
        scope_check = self.function_source("jwt_login_cookie_scopes_differ")
        self.assertIn("($bridge_domain === '') !== ($core_domain === '')", scope_check)

        core_cleanup = self.source.index("jwt_login_cookie_expire_core_scope();")
        bridge_set = self.source.index("jwt_login_cookie_set_auth_cookies($user_id, true);", core_cleanup)
        self.assertLess(core_cleanup, bridge_set)

        self.assertIn(
            "add_action('wp_login', 'jwt_login_cookie_clear_bridge_scope_after_core_login', 10, 0)",
            self.source,
        )

    def test_auth_cookie_suppression_is_not_global(self):
        self.assertNotIn(
            "add_filter('send_auth_cookies', '__return_false')",
            self.source,
        )

    def test_all_auth_cookies_share_one_session_token(self):
        create_calls = re.findall(
            r"WP_Session_Tokens::get_instance\(\$user_id\)->create\(\$expiration\)",
            self.source,
        )
        self.assertEqual(1, len(create_calls))

        generate_calls = re.findall(
            r"wp_generate_auth_cookie\(\$user_id, \$expiration, "
            r"'(auth|secure_auth|logged_in)', \$session_token\)",
            self.source,
        )
        self.assertCountEqual(
            ["auth", "secure_auth", "logged_in"],
            generate_calls,
        )

    def test_jwt_validation_does_not_use_ambient_wordpress_authentication(self):
        for forbidden in (
            "determine_current_user",
            "get_current_user_id",
            "is_user_logged_in",
            "HTTP_AUTHORIZATION",
            "REDIRECT_HTTP_AUTHORIZATION",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_validator_boundary_requires_typed_verified_identity(self):
        self.assertIn("final class JWT_Login_Verified_Identity", self.source)
        self.assertIn("function jwt_login_register_validator", self.source)
        self.assertIn("JWT_LOGIN_ACTIVE_VALIDATOR", self.source)
        self.assertIn("$identity instanceof JWT_Login_Verified_Identity", self.source)
        self.assertIn("get_user_by('id', $identity->user_id())", self.source)

    def test_token_transport_is_strict(self):
        self.assertIn("$request->get_query_params()", self.source)
        self.assertIn("strlen($token) > 8192", self.source)
        self.assertIn("Use either a Bearer token or a body token, not both.", self.source)
        self.assertIn("Authorization header must contain one Bearer token.", self.source)
        self.assertIn("'transport' => $header_token !== null ? 'bearer' : 'body'", self.source)

    def test_origin_policy_is_transport_aware_and_precedes_validation(self):
        origin_helper = self.function_source("jwt_login_authorize_origin")
        self.assertIn("$transport === 'bearer'", origin_helper)
        self.assertIn("jwt_login_canonical_origin($raw_origin)", origin_helper)
        self.assertIn("jwt_login_trusted_origins()", origin_helper)
        self.assertIn("['status' => 403]", origin_helper)

        extraction = self.source.index("jwt_login_extract_token($request)")
        authorization = self.source.index("jwt_login_authorize_origin($request", extraction)
        validation = self.source.index("jwt_login_validate_and_map_token($token_input['token'])", authorization)
        self.assertLess(extraction, authorization)
        self.assertLess(authorization, validation)

    def test_trusted_origins_do_not_use_client_controlled_destinations(self):
        trusted = self.function_source("jwt_login_trusted_origins")
        self.assertIn("jwt_login_allowed_origins()", trusted)
        self.assertIn("home_url('/')", trusted)
        self.assertIn("site_url('/')", trusted)
        for forbidden in ("HTTP_HOST", "Referer", "return_origin", "return_to", "redirect"):
            self.assertNotIn(forbidden, trusted)

    def test_browser_cookie_conflict_is_checked_after_validation(self):
        validation = self.source.index("jwt_login_validate_and_map_token($token_input['token'])")
        cookie_check = self.source.index("jwt_login_browser_cookie_user_id()", validation)
        self.assertLess(validation, cookie_check)
        self.assertIn("['status' => 409]", self.source[cookie_check:])

    def test_rest_cors_and_options_are_bridge_scoped(self):
        route_check = self.function_source("jwt_login_is_bridge_rest_request")
        self.assertIn("$request->get_route() === '/custom/v1/login_via_jwt'", route_check)
        self.assertIn("add_filter('rest_pre_dispatch'", self.source)
        self.assertIn("add_filter('rest_pre_serve_request'", self.source)
        self.assertNotIn("remove_filter('rest_pre_serve_request', 'rest_send_cors_headers')", self.source)
        self.assertNotIn("strpos($uri, '/wp-json/')", self.source)

    def test_frame_policy_is_scoped_to_verified_woocommerce_checkout(self):
        route_check = self.function_source("jwt_login_is_embeddable_checkout_request")
        self.assertIn("is_checkout()", route_check)
        self.assertIn("is_wc_endpoint_url('order-pay')", route_check)
        self.assertNotIn("REQUEST_URI", route_check)

        origins = self.function_source("jwt_login_frame_ancestor_origins")
        self.assertIn("jwt_login_canonical_origin($configured_origin)", origins)
        self.assertNotIn("HTTP_HOST", origins)

        self.assertIn(
            "remove_action('template_redirect', 'wc_send_frame_options_header')",
            self.source,
        )
        self.assertNotIn(
            "remove_action('template_redirect', 'wp_frame_options_header')",
            self.source,
        )
        self.assertNotIn("header_remove('Content-Security-Policy')", self.source)
        self.assertNotIn("header_remove('X-Frame-Options')", self.source)
        self.assertIn("jwt_login_frame_policy_conflict", self.source)


if __name__ == "__main__":
    unittest.main()
