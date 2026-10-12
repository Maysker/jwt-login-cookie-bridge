import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
RESOLVE = os.environ["JWT_BRIDGE_CURL_RESOLVE"]
TEST_SECRET = os.environ["JWT_BRIDGE_TEST_SECRET"]
TEST_USER_ID = int(os.environ["JWT_BRIDGE_TEST_USER_ID"])
PRIVATE_KEY = os.environ["JWT_BRIDGE_RS256_PRIVATE_KEY"]
OTHER_PRIVATE_KEY = os.environ["JWT_BRIDGE_RS256_OTHER_PRIVATE_KEY"]
ISSUER = os.environ["JWT_BRIDGE_RS256_ISSUER"]
AUDIENCE = os.environ["JWT_BRIDGE_RS256_AUDIENCE"]
IDENTITY_CLAIM = os.environ["JWT_BRIDGE_RS256_IDENTITY_CLAIM"]
MODE = os.environ.get("JWT_BRIDGE_RS256_TEST_MODE", "normal")


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def encode_json(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rs256_token(claims, *, private_key=PRIVATE_KEY, algorithm="RS256"):
    header = base64url(encode_json({"alg": algorithm, "typ": "JWT"}))
    payload = base64url(encode_json(claims))
    signing_input = f"{header}.{payload}".encode("ascii")
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", private_key],
        input=signing_input,
        check=True,
        capture_output=True,
    )
    return f"{header}.{payload}.{base64url(result.stdout)}"


def hs256_token(claims):
    header = base64url(encode_json({"alg": "HS256", "typ": "JWT"}))
    payload = base64url(encode_json(claims))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(b"untrusted-test-key", signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{base64url(signature)}"


class RS256ValidatorIntegrationTests(unittest.TestCase):
    def request(self, path, *, method="POST", data=None, headers=None):
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
            for key, value in (headers or {}).items():
                command.extend(["--header", f"{key}: {value}"])
            if data is not None:
                command.extend(["--data", data])
            command.append(BASE_URL + path)
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            return int(result.stdout), header_file.read_text(), body_file.read_text()

    def setUp(self):
        status, _, _ = self.request(
            "/wp-json/jwt-bridge-test/v1/reset-sessions/",
            data=urlencode({"user_id": TEST_USER_ID}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status)

    def base_claims(self):
        now = int(time.time())
        return {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now - 1,
            "nbf": now - 1,
            "exp": now + 240,
            IDENTITY_CLAIM: TEST_USER_ID,
        }

    def session_count(self, user_id=TEST_USER_ID):
        status, _, body = self.request(
            f"/wp-json/jwt-bridge-test/v1/session-count/?user_id={user_id}",
            method="GET",
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, status)
        return int(json.loads(body)["count"])

    def authenticate(self, token):
        return self.request(
            "/wp-json/custom/v1/login_via_jwt",
            headers={"Authorization": f"Bearer {token}"},
        )

    def assert_rejected(self, token, expected_status=401):
        status, headers, _ = self.authenticate(token)
        self.assertEqual(expected_status, status)
        self.assertNotIn("set-cookie: wordpress_", headers.lower())
        self.assertEqual(0, self.session_count())

    def test_valid_token_authenticates(self):
        status, headers, body = self.authenticate(rs256_token(self.base_claims()))
        self.assertEqual(200, status, body)
        self.assertIn("set-cookie: wordpress_", headers.lower())
        self.assertEqual(TEST_USER_ID, int(json.loads(body)["user_id"]))
        self.assertEqual(1, self.session_count())

    def test_valid_array_audience_authenticates(self):
        claims = self.base_claims()
        claims["aud"] = ["unrelated-audience", AUDIENCE]
        status, _, body = self.authenticate(rs256_token(claims))
        self.assertEqual(200, status, body)
        self.assertEqual(1, self.session_count())

    def test_incorrect_signature_is_rejected(self):
        self.assert_rejected(rs256_token(self.base_claims(), private_key=OTHER_PRIVATE_KEY))

    def test_wrong_algorithm_is_rejected(self):
        self.assert_rejected(hs256_token(self.base_claims()))

    def test_wrong_issuer_and_audience_are_rejected(self):
        for claim, value in (("iss", "https://wrong.example.invalid"), ("aud", "wrong-audience")):
            with self.subTest(claim=claim):
                claims = self.base_claims()
                claims[claim] = value
                self.assert_rejected(rs256_token(claims))

    def test_malformed_and_missing_claims_are_rejected(self):
        variants = []
        missing_exp = self.base_claims()
        del missing_exp["exp"]
        variants.append(missing_exp)
        string_iat = self.base_claims()
        string_iat["iat"] = str(string_iat["iat"])
        variants.append(string_iat)
        object_audience = self.base_claims()
        object_audience["aud"] = {"unexpected": AUDIENCE}
        variants.append(object_audience)
        mixed_audience = self.base_claims()
        mixed_audience["aud"] = [AUDIENCE, {"unexpected": "value"}]
        variants.append(mixed_audience)

        for claims in variants:
            with self.subTest(claims=sorted(claims)):
                self.assert_rejected(rs256_token(claims))
        self.assert_rejected("not-a-jwt")

    def test_expired_future_and_excessive_lifetime_tokens_are_rejected(self):
        now = int(time.time())
        expired = self.base_claims()
        expired.update({"iat": now - 300, "nbf": now - 300, "exp": now - 60})
        future = self.base_claims()
        future.update({"iat": now + 300, "nbf": now + 300, "exp": now + 540})
        excessive = self.base_claims()
        excessive.update({"iat": now - 1, "nbf": now - 1, "exp": now + 301})

        for claims in (expired, future, excessive):
            self.assert_rejected(rs256_token(claims))

    def test_invalid_identities_are_rejected(self):
        for identity in (0, -1, "0", "-1", "01", "not-a-user", str(2**63)):
            with self.subTest(identity=identity):
                claims = self.base_claims()
                claims[IDENTITY_CLAIM] = identity
                self.assert_rejected(rs256_token(claims))

    def test_unknown_wordpress_user_is_rejected(self):
        claims = self.base_claims()
        unknown_user_id = 2147483647
        claims[IDENTITY_CLAIM] = unknown_user_id
        self.assert_rejected(rs256_token(claims))
        self.assertEqual(0, self.session_count(unknown_user_id))

    def test_broken_configuration_fails_closed(self):
        self.assert_rejected(rs256_token(self.base_claims()), expected_status=503)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    names = loader.getTestCaseNames(RS256ValidatorIntegrationTests)
    selected = [
        name for name in names
        if (MODE == "normal") == (name != "test_broken_configuration_fails_closed")
    ]
    suite = unittest.TestSuite(RS256ValidatorIntegrationTests(name) for name in selected)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
