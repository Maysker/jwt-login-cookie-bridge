import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
RESOLVE = os.environ["JWT_BRIDGE_CURL_RESOLVE"]
TEST_SECRET = os.environ["JWT_BRIDGE_TEST_SECRET"]
TEST_USER_ID = os.environ["JWT_BRIDGE_TEST_USER_ID"]
BRIDGE_ROUTE = "/wp-json/custom/v1/login_via_jwt"
ORIGIN_CONFIG_ROUTE = "/wp-json/jwt-bridge-test/v1/origin-config"
ALLOWED_REQUEST_ORIGIN = "https://frontend.example.com"


class CurlClient:
    def __init__(self, directory):
        self.directory = Path(directory)

    def request(self, path, *, method=None, data=None, headers=None):
        response_headers = self.directory / "headers.txt"
        response_body = self.directory / "body.txt"
        command = [
            "curl", "--noproxy", "*", "--insecure", "--silent", "--show-error",
            "--resolve", RESOLVE,
            "--dump-header", str(response_headers),
            "--output", str(response_body),
            "--write-out", "%{http_code}",
        ]
        for key, value in (headers or {}).items():
            command.extend(["--header", f"{key}: {value}"])
        if method is not None:
            command.extend(["--request", method])
        if data is not None:
            command.extend(["--data", data])
        command.append(BASE_URL + path)
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return (
            int(result.stdout),
            response_headers.read_text(encoding="utf-8"),
            response_body.read_text(encoding="utf-8"),
        )


class DestinationValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.client = CurlClient(cls.temporary_directory.name)
        status, headers, body = cls.client.request(
            "/wp-json/jwt-bridge-test/v1/issue-jwt/",
            data=urlencode({"user_id": TEST_USER_ID, "variant": "valid"}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        if status != 200:
            raise AssertionError(headers)
        cls.token = json.loads(body)["token"]

    @classmethod
    def tearDownClass(cls):
        cls.temporary_directory.cleanup()

    @staticmethod
    def fixture_path(route, fixture):
        return route if fixture is None else f"{route}?jwt_bridge_origin_fixture={fixture}"

    def bridge_request(self, *, fixture="ports", request_host=None,
                       request_origin=ALLOWED_REQUEST_ORIGIN, **parameters):
        payload = {"token": self.token, **parameters}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": request_origin,
        }
        if request_host is not None:
            headers["Host"] = request_host
        return self.client.request(
            self.fixture_path(BRIDGE_ROUTE, fixture),
            data=urlencode(payload),
            headers=headers,
        )

    def configured_origins(self, fixture=None):
        path = self.fixture_path(ORIGIN_CONFIG_ROUTE, fixture)
        status, headers, body = self.client.request(
            path,
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, status, headers)
        return json.loads(body)

    def assert_bounce_allowed(self, destination):
        status, headers, body = self.bridge_request(mode="bounce", return_to=destination)
        self.assertEqual(200, status, headers)
        match = re.search(r"window\.location\.replace\((\"(?:\\.|[^\"])*\")\)", body)
        self.assertIsNotNone(match, body)
        self.assertEqual(destination, json.loads(match.group(1)))

    def popup_target_origin(self, **parameters):
        status, headers, body = self.bridge_request(mode="popup", **parameters)
        self.assertEqual(200, status, headers)
        self.assertIn("'woo-login-ok'", body)
        match = re.search(r"var origin = (\"(?:\\.|[^\"])*\");", body)
        self.assertIsNotNone(match, body)
        return json.loads(match.group(1))

    def assert_popup_rejected(self, return_origin=None, *, include_origin=True):
        parameters = {"return_origin": return_origin} if include_origin else {}
        self.assertEqual("", self.popup_target_origin(**parameters))

    def assert_navigation_rejected(self, *, request_host=None, **parameters):
        status, headers, body = self.bridge_request(request_host=request_host, **parameters)
        self.assertEqual(200, status, headers)
        self.assertNotIn("window.location.replace(", body)
        self.assertNotRegex(headers.lower(), r"(?:^|\n)location:")
        self.assertTrue(json.loads(body)["success"])

    def test_bounce_accepts_complete_allowlisted_origins_and_preserves_url(self):
        destinations = [
            "https://frontend.example.com/payment/complete?order=123&result=ok#receipt",
            "https://frontend.example.com:443/payment/complete?order=123",
            "http://http-frontend.example.com:80/payment/complete?order=123",
            "https://ports.example.com:4443/payment/complete?order=123",
        ]
        for destination in destinations:
            with self.subTest(destination=destination):
                self.assert_bounce_allowed(destination)

    def test_bounce_rejects_unauthorized_or_ambiguous_destinations(self):
        destinations = [
            "https://frontend.example.com:8443/payment/complete",
            "http://frontend.example.com/payment/complete",
            "https://frontend.example.com.evil.test/payment/complete",
            "https://evil.frontend.example.com/payment/complete",
            "https://user:password@frontend.example.com/payment/complete",
            "https://frontend.example.com:99999/payment/complete",
            "//frontend.example.com/payment/complete",
            "https:\\frontend.example.com\\payment\\complete",
            "https:///frontend.example.com/payment/complete",
        ]
        for destination in destinations:
            with self.subTest(destination=destination):
                self.assert_navigation_rejected(mode="bounce", return_to=destination)

    def test_popup_accepts_trusted_origins_and_uses_canonical_target(self):
        destinations = {
            "https://frontend.example.com": "https://frontend.example.com",
            "https://frontend.example.com:443": "https://frontend.example.com",
            "http://http-frontend.example.com:80": "http://http-frontend.example.com",
            "https://ports.example.com:4443": "https://ports.example.com:4443",
        }
        for destination, expected_target in destinations.items():
            with self.subTest(destination=destination):
                self.assertEqual(
                    expected_target,
                    self.popup_target_origin(return_origin=destination),
                )

    def test_popup_rejects_untrusted_or_non_origin_destinations(self):
        destinations = [
            "https://frontend.example.com:8443",
            "http://frontend.example.com",
            "https://frontend.example.com.evil.test",
            "https://evil.frontend.example.com",
            "frontend.example.com",
            "//frontend.example.com",
            "/frontend.example.com",
            "https://frontend.example.com/path",
            "https://frontend.example.com?query=value",
            "https://frontend.example.com#fragment",
            "https://user:password@frontend.example.com",
            "https://frontend.example.com:99999",
            "https://frontend.example.com:invalid",
            "https://frontend.example.com\x01",
            "https://frontend.example.com,https://evil.example.test",
            "https:\\frontend.example.com",
            "https:///frontend.example.com",
            "null",
        ]
        for destination in destinations:
            with self.subTest(destination=repr(destination)):
                self.assert_popup_rejected(destination)

    def test_popup_rejects_missing_return_origin_without_failing_login(self):
        self.assert_popup_rejected(include_origin=False)

    def test_origin_filter_handles_defaults_canonicalization_and_invalid_entries(self):
        cases = {
            None: {
                "allowed": [
                    "https://frontend.example.com",
                    "https://dev.example.com",
                    "https://localhost:4200",
                    "http://localhost:4200",
                ],
                "frame": [
                    "https://frontend.example.com",
                    "https://dev.example.com",
                    "https://localhost:4200",
                    "http://localhost:4200",
                ],
            },
            "single": {
                "allowed": ["https://single.example.com"],
                "frame": ["https://single.example.com"],
            },
            "ports": {
                "allowed": [
                    "https://frontend.example.com",
                    "http://http-frontend.example.com",
                    "https://ports.example.com:4443",
                ],
                "frame": [
                    "https://frontend.example.com",
                    "http://http-frontend.example.com",
                    "https://ports.example.com:4443",
                ],
            },
            "duplicates": {
                "allowed": [
                    "https://frontend.example.com",
                    "https://ports.example.com:4443",
                ],
                "frame": [
                    "https://frontend.example.com",
                    "https://ports.example.com:4443",
                ],
            },
            "invalid": {
                "allowed": ["https://frontend.example.com"],
                "frame": None,
            },
            "empty": {"allowed": [], "frame": None},
        }
        for fixture, expected in cases.items():
            with self.subTest(fixture=fixture):
                self.assertEqual(expected, self.configured_origins(fixture))

    def test_empty_or_unlisted_configuration_rejects_browser_requests(self):
        for fixture, origin in [
            ("empty", ALLOWED_REQUEST_ORIGIN),
            ("single", ALLOWED_REQUEST_ORIGIN),
            ("ports", "https://untrusted.example.invalid"),
        ]:
            with self.subTest(fixture=fixture, origin=origin):
                status, _, body = self.bridge_request(
                    fixture=fixture,
                    request_origin=origin,
                )
                self.assertEqual(403, status)
                self.assertEqual("forbidden_origin", json.loads(body)["code"])

    def test_custom_origin_filter_preserves_cors_preflight_behavior(self):
        origin = "https://ports.example.com:4443"
        status, headers, _ = self.client.request(
            self.fixture_path(BRIDGE_ROUTE, "ports"),
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        self.assertEqual(204, status, headers)
        self.assertIn(f"Access-Control-Allow-Origin: {origin}".lower(), headers.lower())

    def test_same_origin_redirect_accepts_exact_effective_port_and_preserves_url(self):
        destination = BASE_URL + "/checkout/order-pay/123/?key=test-key&source=bridge#payment"
        status, headers, _ = self.bridge_request(redirect=destination)
        self.assertEqual(302, status, headers)
        locations = [
            line.split(":", 1)[1].strip()
            for line in headers.splitlines()
            if line.lower().startswith("location:")
        ]
        self.assertEqual([destination], locations)

    def test_same_origin_redirect_rejects_other_origins_and_ambiguous_urls(self):
        base = urlsplit(BASE_URL)
        other_port = 4443 if base.port != 4443 else 4444
        destinations = [
            urlunsplit((base.scheme, f"{base.hostname}:{other_port}", "/checkout/", "", "")),
            urlunsplit(("http" if base.scheme == "https" else "https", base.netloc, "/checkout/", "", "")),
            f"{base.scheme}://evil.example.test/checkout/",
            f"{base.scheme}://{base.hostname}.evil.test/checkout/",
            f"{base.scheme}://user:password@{base.netloc}/checkout/",
            f"{base.scheme}://{base.hostname}:99999/checkout/",
            f"//{base.netloc}/checkout/",
            f"{base.scheme}:\\{base.netloc}\\checkout\\",
            f"{base.scheme}:///{base.hostname}/checkout/",
        ]
        for destination in destinations:
            with self.subTest(destination=destination):
                self.assert_navigation_rejected(
                    request_host=base.hostname,
                    redirect=destination,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
