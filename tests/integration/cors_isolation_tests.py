import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
RESOLVE = os.environ["JWT_BRIDGE_CURL_RESOLVE"]
TEST_SECRET = os.environ["JWT_BRIDGE_TEST_SECRET"]
TEST_USER_ID = os.environ["JWT_BRIDGE_TEST_USER_ID"]
MODE = os.environ.get("JWT_BRIDGE_CORS_MODE", "verify")
BASELINE_FILE = Path(os.environ["JWT_BRIDGE_CORS_BASELINE_FILE"])

BRIDGE_ROUTE = "/wp-json/custom/v1/login_via_jwt"
ALLOWED_ORIGIN = "https://frontend.example.com"
RELEVANT_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-expose-headers",
    "allow",
    "vary",
}


def final_header_block(raw_headers):
    blocks = [block for block in raw_headers.replace("\r\n", "\n").split("\n\n") if block.strip()]
    return blocks[-1]


def parse_headers(raw_headers):
    parsed = {}
    for line in final_header_block(raw_headers).splitlines()[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        parsed.setdefault(name.strip().lower(), []).append(value.strip())
    return parsed


def comparable_response(status, raw_headers):
    headers = parse_headers(raw_headers)
    return {
        "status": status,
        "headers": {
            name: headers[name]
            for name in sorted(RELEVANT_HEADERS)
            if name in headers
        },
    }


class CurlClient:
    def request(self, path, *, method="GET", data=None, headers=None):
        with tempfile.TemporaryDirectory() as directory:
            header_file = Path(directory) / "headers.txt"
            body_file = Path(directory) / "body.txt"
            command = [
                "curl", "--noproxy", "*", "--insecure", "--silent", "--show-error",
                "--resolve", RESOLVE,
                "--dump-header", str(header_file),
                "--output", str(body_file),
                "--write-out", "%{http_code}",
                "--request", method,
            ]
            for name, value in (headers or {}).items():
                command.extend(["--header", f"{name}: {value}"])
            if data is not None:
                command.extend(["--data", data])
            command.append(BASE_URL + path)
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            return int(result.stdout), header_file.read_text(), body_file.read_text()


UNRELATED_REQUESTS = {
    "core_allowed": (
        "OPTIONS",
        "/wp-json/wp/v2/posts",
        {
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type",
        },
    ),
    "core_query_untrusted": (
        "OPTIONS",
        "/wp-json/wp/v2/posts?context=edit",
        {
            "Origin": "https://unrelated.example.invalid",
            "Access-Control-Request-Method": "GET",
        },
    ),
    "core_rest_route_query": (
        "OPTIONS",
        "/?rest_route=/wp/v2/posts&context=edit",
        {
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    ),
    "core_missing_origin": (
        "OPTIONS",
        "/wp-json/wp/v2/posts",
        {"Access-Control-Request-Method": "GET"},
    ),
    "woocommerce_allowed": (
        "OPTIONS",
        "/wp-json/wc/v3/products?per_page=1",
        {
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        },
    ),
    "core_get_allowed": (
        "GET",
        "/wp-json/wp/v2/posts?per_page=1",
        {"Origin": ALLOWED_ORIGIN},
    ),
    "core_get_untrusted": (
        "GET",
        "/wp-json/wp/v2/posts?per_page=1",
        {"Origin": "https://unrelated.example.invalid"},
    ),
    "woocommerce_get_allowed": (
        "GET",
        "/wp-json/wc/v3/products?per_page=1",
        {"Origin": ALLOWED_ORIGIN},
    ),
}


class CORSIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CurlClient()

    def capture_unrelated(self):
        captured = {}
        for name, (method, path, headers) in UNRELATED_REQUESTS.items():
            status, raw_headers, _ = self.client.request(path, method=method, headers=headers)
            captured[name] = comparable_response(status, raw_headers)
        return captured

    def issue_token(self):
        status, _, body = self.client.request(
            "/wp-json/jwt-bridge-test/v1/issue-jwt/",
            method="POST",
            data=urlencode({"user_id": TEST_USER_ID, "variant": "valid"}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status)
        return json.loads(body)["token"]

    def assert_single_header(self, headers, name, expected):
        self.assertEqual([expected], headers.get(name.lower()))

    def assert_vary_contains(self, headers, *expected):
        tokens = {
            token.strip().lower()
            for value in headers.get("vary", [])
            for token in value.split(",")
            if token.strip()
        }
        for token in expected:
            self.assertIn(token.lower(), tokens)

    def test_unrelated_rest_behavior_matches_bridge_disabled_baseline(self):
        current = self.capture_unrelated()
        if MODE == "capture":
            BASELINE_FILE.write_text(json.dumps(current, indent=2, sort_keys=True))
            return

        baseline = json.loads(BASELINE_FILE.read_text())
        self.assertEqual(baseline, current)

    @unittest.skipUnless(MODE == "verify", "Bridge-specific checks require the plugin")
    def test_allowed_json_and_bearer_preflights(self):
        cases = [
            (BRIDGE_ROUTE, ALLOWED_ORIGIN, ALLOWED_ORIGIN, "Content-Type"),
            (BRIDGE_ROUTE + "?mode=popup", ALLOWED_ORIGIN, ALLOWED_ORIGIN, "Authorization"),
            ("/?rest_route=/custom/v1/login_via_jwt&mode=popup", ALLOWED_ORIGIN, ALLOWED_ORIGIN, "Authorization"),
            (BRIDGE_ROUTE, "https://frontend.example.com:443", ALLOWED_ORIGIN, "Authorization, Content-Type"),
            (BRIDGE_ROUTE, BASE_URL, BASE_URL, "Content-Type"),
        ]
        for path, origin, expected_origin, requested_headers in cases:
            with self.subTest(path=path, origin=origin, requested_headers=requested_headers):
                status, raw_headers, _ = self.client.request(
                    path,
                    method="OPTIONS",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": requested_headers,
                    },
                )
                headers = parse_headers(raw_headers)
                self.assertEqual(204, status)
                self.assert_single_header(headers, "Access-Control-Allow-Origin", expected_origin)
                self.assert_single_header(headers, "Access-Control-Allow-Credentials", "true")
                self.assert_single_header(headers, "Access-Control-Allow-Methods", "POST, OPTIONS")
                self.assert_single_header(headers, "Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.assert_vary_contains(headers, "Origin", "Accept-Encoding")

    @unittest.skipUnless(MODE == "verify", "Bridge-specific checks require the plugin")
    def test_invalid_preflight_origins_are_rejected_without_cors_grant(self):
        origins = [None, "null", "https://untrusted.example.invalid", "https://frontend.example.com, https://evil.example"]
        for origin in origins:
            with self.subTest(origin=origin):
                request_headers = {"Access-Control-Request-Method": "POST"}
                if origin is not None:
                    request_headers["Origin"] = origin
                status, raw_headers, _ = self.client.request(
                    BRIDGE_ROUTE,
                    method="OPTIONS",
                    headers=request_headers,
                )
                headers = parse_headers(raw_headers)
                self.assertEqual(403, status)
                self.assertNotIn("access-control-allow-origin", headers)
                self.assert_vary_contains(headers, "Origin", "Accept-Encoding")

    @unittest.skipUnless(MODE == "verify", "Bridge-specific checks require the plugin")
    def test_invalid_preflight_method_and_headers_are_rejected(self):
        cases = [
            ("GET", "Content-Type"),
            ("PATCH", "Authorization"),
            ("POST", "X-WP-Nonce"),
            ("POST", "Content-Type,,Authorization"),
        ]
        for method, requested_headers in cases:
            with self.subTest(method=method, requested_headers=requested_headers):
                status, raw_headers, _ = self.client.request(
                    BRIDGE_ROUTE,
                    method="OPTIONS",
                    headers={
                        "Origin": ALLOWED_ORIGIN,
                        "Access-Control-Request-Method": method,
                        "Access-Control-Request-Headers": requested_headers,
                    },
                )
                headers = parse_headers(raw_headers)
                self.assertEqual(403, status)
                self.assert_single_header(headers, "Access-Control-Allow-Origin", ALLOWED_ORIGIN)
                self.assert_vary_contains(headers, "Origin", "Accept-Encoding")

    @unittest.skipUnless(MODE == "verify", "Bridge-specific checks require the plugin")
    def test_successful_and_failed_bridge_posts_have_scoped_cors(self):
        token = self.issue_token()
        cases = [
            (token, ALLOWED_ORIGIN, 200, True),
            ("not-a-jwt", ALLOWED_ORIGIN, 401, True),
            (token, "https://untrusted.example.invalid", 403, False),
            (token, None, 200, False),
        ]
        for token_value, origin, expected_status, cors_allowed in cases:
            with self.subTest(origin=origin, expected_status=expected_status):
                request_headers = {"Authorization": f"Bearer {token_value}"}
                if origin is not None:
                    request_headers["Origin"] = origin
                status, raw_headers, _ = self.client.request(
                    BRIDGE_ROUTE,
                    method="POST",
                    headers=request_headers,
                )
                headers = parse_headers(raw_headers)
                self.assertEqual(expected_status, status)
                if cors_allowed:
                    self.assert_single_header(headers, "Access-Control-Allow-Origin", ALLOWED_ORIGIN)
                else:
                    self.assertNotIn("access-control-allow-origin", headers)
                self.assert_vary_contains(headers, "Origin", "Accept-Encoding")

    @unittest.skipUnless(MODE == "verify", "Bridge-specific checks require the plugin")
    def test_top_level_form_post_remains_supported(self):
        token = self.issue_token()
        status, raw_headers, _ = self.client.request(
            BRIDGE_ROUTE,
            method="POST",
            data=urlencode({"token": token}),
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        headers = parse_headers(raw_headers)
        self.assertEqual(200, status)
        self.assert_single_header(headers, "Access-Control-Allow-Origin", ALLOWED_ORIGIN)


if __name__ == "__main__":
    names = unittest.TestLoader().getTestCaseNames(CORSIsolationTests)
    if MODE == "capture":
        names = ["test_unrelated_rest_behavior_matches_bridge_disabled_baseline"]
    suite = unittest.TestSuite(CORSIsolationTests(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
