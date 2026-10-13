import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
RESOLVE = os.environ["JWT_BRIDGE_CURL_RESOLVE"]
MODE = os.environ.get("JWT_BRIDGE_FRAME_MODE", "verify")
BASELINE_FILE = Path(os.environ["JWT_BRIDGE_FRAME_BASELINE_FILE"])
CHECKOUT_PATH = os.environ["JWT_BRIDGE_FRAME_CHECKOUT_PATH"]
ORDER_PAY_PATH = os.environ["JWT_BRIDGE_FRAME_ORDER_PAY_PATH"]
ORDINARY_PATH = os.environ["JWT_BRIDGE_FRAME_ORDINARY_PATH"]
UNRELATED_CHECKOUT_PATH = os.environ["JWT_BRIDGE_FRAME_UNRELATED_CHECKOUT_PATH"]

FRAME_POLICY = (
    "frame-ancestors 'self' https://frontend.example.com https://dev.example.com "
    "https://localhost:4200 http://localhost:4200"
)
EXISTING_CSP = "default-src 'self'; script-src 'self'; report-uri /csp-report"
RESTRICTIVE_CSP = "default-src 'self'; frame-ancestors 'none'; report-to csp-endpoint"
SECURITY_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-jwt-bridge-test-frame-conflict",
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
            for name in sorted(SECURITY_HEADERS)
            if name in headers
        },
    }


class CurlClient:
    def request(self, path):
        with tempfile.TemporaryDirectory() as directory:
            header_file = Path(directory) / "headers.txt"
            body_file = Path(directory) / "body.txt"
            result = subprocess.run(
                [
                    "curl", "--noproxy", "*", "--insecure", "--silent", "--show-error",
                    "--resolve", RESOLVE,
                    "--dump-header", str(header_file),
                    "--output", str(body_file),
                    "--write-out", "%{http_code}",
                    BASE_URL + path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return int(result.stdout), header_file.read_text(), body_file.read_text()


UNAFFECTED_REQUESTS = {
    "ordinary_frontend": ORDINARY_PATH,
    "wordpress_login": "/wp-login.php",
    "wordpress_admin": "/wp-admin/",
    "former_checkout_page": "/checkout/",
    "unrelated_checkout_child": UNRELATED_CHECKOUT_PATH,
    "unrelated_checkout_existing_csp": UNRELATED_CHECKOUT_PATH + "?jwt_bridge_frame_fixture=existing-csp",
    "unrelated_checkout_restrictive_csp": UNRELATED_CHECKOUT_PATH + "?jwt_bridge_frame_fixture=restrictive-csp",
    "unrelated_checkout_xfo": UNRELATED_CHECKOUT_PATH + "?jwt_bridge_frame_fixture=xfo",
}


class FramePolicyIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CurlClient()

    def capture_unaffected(self):
        captured = {}
        for name, path in UNAFFECTED_REQUESTS.items():
            status, raw_headers, _ = self.client.request(path)
            captured[name] = comparable_response(status, raw_headers)
        return captured

    def security_headers(self, path):
        status, raw_headers, _ = self.client.request(path)
        self.assertIn(status, (200, 302, 403))
        return parse_headers(raw_headers)

    def test_unrelated_pages_match_bridge_disabled_baseline(self):
        current = self.capture_unaffected()
        if MODE == "capture":
            BASELINE_FILE.write_text(json.dumps(current, indent=2, sort_keys=True))
            return

        self.assertEqual(json.loads(BASELINE_FILE.read_text()), current)

    @unittest.skipUnless(MODE == "verify", "Checkout checks require the plugin")
    def test_verified_checkout_receives_frame_policy(self):
        headers = self.security_headers(CHECKOUT_PATH)
        self.assertEqual([FRAME_POLICY], headers.get("content-security-policy"))
        self.assertNotIn("x-frame-options", headers)
        self.assertNotIn("x-jwt-bridge-test-frame-conflict", headers)

    @unittest.skipUnless(MODE == "verify", "Checkout checks require the plugin")
    def test_order_pay_receives_scoped_frame_policy(self):
        headers = self.security_headers(ORDER_PAY_PATH)
        self.assertEqual([FRAME_POLICY], headers.get("content-security-policy"))
        self.assertNotIn("x-jwt-bridge-test-frame-conflict", headers)
        self.assertNotIn("x-frame-options", headers)

    @unittest.skipUnless(MODE == "verify", "Checkout checks require the plugin")
    def test_existing_non_frame_csp_is_preserved(self):
        headers = self.security_headers(CHECKOUT_PATH + "?jwt_bridge_frame_fixture=existing-csp")
        self.assertEqual(
            [EXISTING_CSP, FRAME_POLICY],
            headers.get("content-security-policy"),
        )
        self.assertNotIn("x-frame-options", headers)

    @unittest.skipUnless(MODE == "verify", "Checkout checks require the plugin")
    def test_existing_frame_ancestors_remains_authoritative(self):
        headers = self.security_headers(CHECKOUT_PATH + "?jwt_bridge_frame_fixture=restrictive-csp")
        self.assertEqual([RESTRICTIVE_CSP], headers.get("content-security-policy"))
        self.assertEqual(
            ["existing_content_security_policy_frame_ancestors"],
            headers.get("x-jwt-bridge-test-frame-conflict"),
        )
        self.assertNotIn("x-frame-options", headers)

    @unittest.skipUnless(MODE == "verify", "Checkout checks require the plugin")
    def test_existing_x_frame_options_is_not_removed(self):
        headers = self.security_headers(CHECKOUT_PATH + "?jwt_bridge_frame_fixture=xfo")
        self.assertEqual(["DENY"], headers.get("x-frame-options"))
        self.assertNotIn("content-security-policy", headers)
        self.assertEqual(
            ["existing_x_frame_options"],
            headers.get("x-jwt-bridge-test-frame-conflict"),
        )


if __name__ == "__main__":
    names = unittest.TestLoader().getTestCaseNames(FramePolicyIsolationTests)
    if MODE == "capture":
        names = ["test_unrelated_pages_match_bridge_disabled_baseline"]
    suite = unittest.TestSuite(FramePolicyIsolationTests(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
