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
BRIDGE_PATH = "/wp-json/custom/v1/login_via_jwt?jwt_bridge_destination_fixture=ports"
ALLOWED_REQUEST_ORIGIN = "https://frontend.example.com"


class CurlClient:
    def __init__(self, directory):
        self.directory = Path(directory)

    def request(self, path, *, data=None, headers=None):
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

    def bridge_request(self, *, request_host=None, **parameters):
        payload = {"token": self.token, **parameters}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": ALLOWED_REQUEST_ORIGIN,
        }
        if request_host is not None:
            headers["Host"] = request_host
        return self.client.request(
            BRIDGE_PATH,
            data=urlencode(payload),
            headers=headers,
        )

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
