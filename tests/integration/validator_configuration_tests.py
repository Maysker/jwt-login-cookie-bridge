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
EXPECTED_STATUS = int(os.environ["JWT_BRIDGE_EXPECTED_VALIDATOR_STATUS"])


class ValidatorConfigurationTests(unittest.TestCase):
    def request(self, path, *, data=None, headers=None):
        with tempfile.TemporaryDirectory() as directory:
            header_file = Path(directory) / "headers.txt"
            body_file = Path(directory) / "body.txt"
            command = [
                "curl", "--noproxy", "*", "--insecure", "--silent", "--show-error",
                "--resolve", RESOLVE,
                "--dump-header", str(header_file),
                "--output", str(body_file),
                "--write-out", "%{http_code}",
                "--request", "POST",
            ]
            for key, value in (headers or {}).items():
                command.extend(["--header", f"{key}: {value}"])
            if data is not None:
                command.extend(["--data", data])
            command.append(BASE_URL + path)
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            return int(result.stdout), header_file.read_text(), body_file.read_text()

    def session_count(self):
        with tempfile.TemporaryDirectory() as directory:
            body_file = Path(directory) / "body.txt"
            command = [
                "curl", "--noproxy", "*", "--insecure", "--silent", "--show-error",
                "--resolve", RESOLVE,
                "--header", f"X-JWT-Bridge-Test-Secret: {TEST_SECRET}",
                "--output", str(body_file),
                BASE_URL + f"/wp-json/jwt-bridge-test/v1/session-count/?user_id={TEST_USER_ID}",
            ]
            subprocess.run(command, check=True)
            return json.loads(body_file.read_text())["count"]

    def test_configured_validator_must_exist_exactly_once(self):
        status, _, _ = self.request(
            "/wp-json/jwt-bridge-test/v1/reset-sessions/",
            data=urlencode({"user_id": TEST_USER_ID}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status)

        status, _, issue_body = self.request(
            "/wp-json/jwt-bridge-test/v1/issue-jwt/",
            data=urlencode({"user_id": TEST_USER_ID, "variant": "valid"}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status)
        token = json.loads(issue_body)["token"]

        status, response_headers, _ = self.request(
            "/wp-json/custom/v1/login_via_jwt",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(EXPECTED_STATUS, status)
        self.assertNotIn("set-cookie: wordpress_", response_headers.lower())
        self.assertEqual(0, self.session_count())


if __name__ == "__main__":
    unittest.main(verbosity=2)
