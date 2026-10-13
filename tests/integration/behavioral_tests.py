import base64
import hashlib
import html
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote, urlencode


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
RESOLVE = os.environ["JWT_BRIDGE_CURL_RESOLVE"]
TEST_SECRET = os.environ["JWT_BRIDGE_TEST_SECRET"]
TEST_USER_ID = os.environ["JWT_BRIDGE_TEST_USER_ID"]
TEST_USER_B_ID = os.environ["JWT_BRIDGE_TEST_USER_B_ID"]
TEST_USERNAME = os.environ["JWT_BRIDGE_TEST_USERNAME"]
TEST_USER_B_USERNAME = os.environ["JWT_BRIDGE_TEST_USER_B_USERNAME"]
TEST_PASSWORD = os.environ["JWT_BRIDGE_TEST_PASSWORD"]
TEST_APPLICATION_PASSWORD = os.environ["JWT_BRIDGE_TEST_APPLICATION_PASSWORD"]
EXPECTED_COOKIE_DOMAIN = os.environ["JWT_BRIDGE_EXPECTED_COOKIE_DOMAIN"]


def parse_set_cookies(header_text):
    cookies = []
    for line in header_text.splitlines():
        if not line.lower().startswith("set-cookie:"):
            continue
        parts = [part.strip() for part in line.split(":", 1)[1].split(";")]
        name, value = parts[0].split("=", 1)
        attributes = {}
        for part in parts[1:]:
            if "=" in part:
                key, attribute_value = part.split("=", 1)
                attributes[key.lower()] = attribute_value
            else:
                attributes[part.lower()] = True
        cookies.append({"name": name, "value": value, "attributes": attributes})
    return cookies


def conflicting_cookie_identities(cookies):
    identities = {}
    conflicts = []
    for cookie in cookies:
        attributes = cookie["attributes"]
        identity = (
            cookie["name"],
            attributes.get("domain", "<host-only>"),
            attributes.get("path", "<default-path>"),
        )
        previous = identities.setdefault(identity, cookie["value"])
        if previous != cookie["value"]:
            conflicts.append(identity)
    return conflicts


class CurlClient:
    def __init__(self, directory, jar_name):
        self.directory = Path(directory)
        self.cookie_jar = self.directory / jar_name

    def request(self, path, *, method="GET", data=None, headers=None, follow=False):
        response_headers = self.directory / "headers.txt"
        response_body = self.directory / "body.txt"
        command = [
            "curl",
            "--noproxy", "*",
            "--insecure",
            "--silent",
            "--show-error",
            "--resolve", RESOLVE,
            "--cookie", str(self.cookie_jar),
            "--cookie-jar", str(self.cookie_jar),
            "--dump-header", str(response_headers),
            "--output", str(response_body),
            "--write-out", "%{http_code}",
        ]
        if follow:
            command.append("--location")
        if method != "GET":
            command.extend(["--request", method])
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

    def stored_wordpress_auth_cookies(self):
        if not self.cookie_jar.exists():
            return []
        cookies = []
        for line in self.cookie_jar.read_text(encoding="utf-8").splitlines():
            if line.startswith("#HttpOnly_"):
                line = line.removeprefix("#HttpOnly_")
            elif line.startswith("#") or not line:
                continue
            fields = line.split("\t")
            if len(fields) == 7 and fields[5].startswith("wordpress_") and fields[5] != "wordpress_test_cookie":
                decoded_value = unquote(fields[6])
                value_parts = decoded_value.split("|")
                token_fingerprint = None
                if len(value_parts) >= 3:
                    token_fingerprint = hashlib.sha256(value_parts[2].encode("utf-8")).hexdigest()
                cookies.append({
                    "domain": fields[0].lstrip(".").lower(),
                    "host_only": fields[1].upper() == "FALSE",
                    "path": fields[2],
                    "name": fields[5],
                    "token_fingerprint": token_fingerprint,
                })
        return cookies


class WordPressCookieIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary_directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary_directory.cleanup()

    def setUp(self):
        client = CurlClient(self.directory, "reset-cookies.txt")
        for user_id in (TEST_USER_ID, TEST_USER_B_ID):
            status, headers, _ = client.request(
                "/wp-json/jwt-bridge-test/v1/reset-sessions/",
                method="POST",
                data=urlencode({"user_id": user_id}),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-JWT-Bridge-Test-Secret": TEST_SECRET,
                },
            )
            self.assertEqual(200, status, headers)

    def session_count(self, user_id=TEST_USER_ID):
        client = CurlClient(self.directory, "metadata-cookies.txt")
        status, headers, body = client.request(
            f"/wp-json/jwt-bridge-test/v1/session-count/?user_id={user_id}",
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, status, headers)
        return json.loads(body)["count"]

    def issue_token(self, *, user_id=TEST_USER_ID, variant="valid"):
        client = CurlClient(self.directory, f"issuer-{user_id}-{variant}.txt")
        status, headers, body = client.request(
            "/wp-json/jwt-bridge-test/v1/issue-jwt/",
            method="POST",
            data=urlencode({"user_id": user_id, "variant": variant}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status, headers)
        return json.loads(body)["token"]

    def standard_login(self, client, username=TEST_USERNAME):
        status, _, _ = client.request("/wp-login.php")
        self.assertEqual(200, status)
        payload = urlencode({
            "log": username,
            "pwd": TEST_PASSWORD,
            "wp-submit": "Log In",
            "redirect_to": BASE_URL + "/wp-admin/",
            "testcookie": "1",
        })
        return client.request(
            "/wp-login.php",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def bridge_login(self, client, user_id=TEST_USER_ID):
        token = self.issue_token(user_id=user_id)
        return client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            headers={"Authorization": f"Bearer {token}"},
        )

    def authenticated_user_id(self, client):
        status, headers, body = client.request(
            "/wp-json/jwt-bridge-test/v1/authenticated-user/",
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, status, headers)
        return int(json.loads(body)["user_id"])

    def logout_url(self, client):
        status, _, _ = client.request("/wp-admin/", follow=True)
        self.assertEqual(200, status)
        status, _, body = client.request("/wp-login.php?action=logout")
        self.assertEqual(403, status)
        match = re.search(r'href="([^"]*action=logout[^"]*)"', body)
        self.assertIsNotNone(match, "WordPress logout confirmation did not contain a nonce URL")
        return html.unescape(match.group(1)).replace(BASE_URL, "")

    def assert_no_conflicting_set_cookies(self, cookies):
        self.assertEqual([], conflicting_cookie_identities(cookies))

    def cookie_identity(self, cookie):
        domain = cookie["attributes"].get("domain")
        scope = domain.lstrip(".").lower() if domain else "<host-only>"
        return (cookie["name"], scope, cookie["attributes"].get("path", "<default-path>"))

    def stored_cookie_identity(self, cookie):
        scope = "<host-only>" if cookie["host_only"] else cookie["domain"]
        return (cookie["name"], scope, cookie["path"])

    def assert_logout_clears_browser_authentication(self, client):
        stored_before = client.stored_wordpress_auth_cookies()
        self.assertNotEqual([], stored_before)

        logout_path = self.logout_url(client)
        status, logout_headers, _ = client.request(logout_path)
        self.assertEqual(302, status)

        self.assert_expiration_headers_cover(logout_headers, stored_before)

        self.assertEqual([], client.stored_wordpress_auth_cookies())
        self.assertEqual(0, self.authenticated_user_id(client))
        status, _, _ = client.request("/wp-admin/")
        self.assertEqual(302, status)
        return logout_headers

    def expiration_auth_cookies(self, response_headers):
        return [
            cookie for cookie in parse_set_cookies(response_headers)
            if cookie["name"].startswith("wordpress_")
            and cookie["name"] != "wordpress_test_cookie"
            and cookie["attributes"].get("max-age") == "0"
        ]

    def assert_expiration_headers_cover(self, response_headers, stored_cookies, require_unique=False):
        expiration_cookies = self.expiration_auth_cookies(response_headers)
        self.assert_no_conflicting_set_cookies(expiration_cookies)
        expiration_identities = [self.cookie_identity(cookie) for cookie in expiration_cookies]
        if require_unique:
            self.assertEqual(len(expiration_identities), len(set(expiration_identities)))
        expired_identities = set(expiration_identities)
        for stored_cookie in stored_cookies:
            self.assertIn(self.stored_cookie_identity(stored_cookie), expired_identities)

    def active_auth_cookies(self, response_headers):
        return [
            cookie for cookie in parse_set_cookies(response_headers)
            if cookie["name"].startswith("wordpress_")
            and cookie["name"] != "wordpress_test_cookie"
            and cookie not in self.expiration_auth_cookies(response_headers)
        ]

    def bridge_auth_cookies(self, response_headers):
        return self.active_auth_cookies(response_headers)

    def assert_bridge_cookie_scope(self, cookies):
        self.assertEqual(3, len(cookies))
        self.assert_no_conflicting_set_cookies(cookies)
        if EXPECTED_COOKIE_DOMAIN:
            self.assertTrue(all(
                cookie["attributes"].get("domain", "").lstrip(".").lower()
                == EXPECTED_COOKIE_DOMAIN.lstrip(".").lower()
                for cookie in cookies
            ))
        else:
            self.assertTrue(all("domain" not in cookie["attributes"] for cookie in cookies))
        self.assertTrue(all(cookie["attributes"].get("secure") is True for cookie in cookies))
        self.assertTrue(all(cookie["attributes"].get("httponly") is True for cookie in cookies))
        self.assertTrue(all(cookie["attributes"].get("samesite") == "None" for cookie in cookies))

    def assert_one_browser_identity(self, client, expected_user_id):
        self.assertEqual(int(expected_user_id), self.authenticated_user_id(client))
        cookies = client.stored_wordpress_auth_cookies()
        self.assertNotEqual([], cookies)
        self.assertTrue(all(cookie["token_fingerprint"] for cookie in cookies))
        return cookies

    def assert_transition_scope(self, response_headers, previous_cookies, client, expected_host_only):
        if EXPECTED_COOKIE_DOMAIN:
            self.assert_expiration_headers_cover(
                response_headers, previous_cookies, require_unique=True
            )
            auth_cookies = [
                cookie for cookie in parse_set_cookies(response_headers)
                if cookie["name"].startswith("wordpress_")
                and cookie["name"] != "wordpress_test_cookie"
            ]
            expiration_indexes = [
                index for index, cookie in enumerate(auth_cookies)
                if cookie["attributes"].get("max-age") == "0"
            ]
            active_indexes = [
                index for index, cookie in enumerate(auth_cookies)
                if cookie["attributes"].get("max-age") != "0"
            ]
            self.assertTrue(expiration_indexes)
            self.assertTrue(active_indexes)
            if expected_host_only:
                self.assertLess(max(active_indexes), min(expiration_indexes))
            else:
                self.assertLess(max(expiration_indexes), min(active_indexes))

            expired_identities = {
                self.cookie_identity(auth_cookies[index]) for index in expiration_indexes
            }
            active_identities = {
                self.cookie_identity(auth_cookies[index]) for index in active_indexes
            }
            self.assertTrue(expired_identities.isdisjoint(active_identities))
        cookies = client.stored_wordpress_auth_cookies()
        self.assertNotEqual([], cookies)
        self.assertTrue(all(cookie["host_only"] is expected_host_only for cookie in cookies))

    def test_01_standard_wordpress_login_and_logout(self):
        self.assertEqual(0, self.session_count())
        client = CurlClient(self.directory, "standard-login-cookies.txt")

        status, headers, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assert_no_conflicting_set_cookies(parse_set_cookies(headers))
        cookies = self.active_auth_cookies(headers)

        secure_auth = [cookie for cookie in cookies if cookie["name"].startswith("wordpress_sec_")]
        logged_in = [cookie for cookie in cookies if cookie["name"].startswith("wordpress_logged_in_")]
        self.assertEqual({"/wp-admin", "/wp-content/plugins"}, {
            cookie["attributes"].get("path") for cookie in secure_auth
        })
        self.assertEqual({"/"}, {cookie["attributes"].get("path") for cookie in logged_in})
        self.assertTrue(all("domain" not in cookie["attributes"] for cookie in secure_auth + logged_in))
        self.assertEqual(1, self.session_count())

        logout_path = self.logout_url(client)
        status, logout_headers, _ = client.request(logout_path)
        self.assertEqual(302, status)
        self.assert_no_conflicting_set_cookies(parse_set_cookies(logout_headers))
        self.assertEqual(0, self.session_count())
        self.assertEqual([], client.stored_wordpress_auth_cookies())

        status, _, _ = client.request("/wp-admin/")
        self.assertEqual(302, status)

    def test_02_bridge_cookie_helper_and_standard_logout(self):
        self.assertEqual(0, self.session_count())
        client = CurlClient(self.directory, "bridge-cookies.txt")
        status, headers, _ = client.request(
            "/wp-json/jwt-bridge-test/v1/create-cookie-session/",
            method="POST",
            data=urlencode({"user_id": TEST_USER_ID}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
        )
        self.assertEqual(200, status)
        cookies = parse_set_cookies(headers)
        auth_cookies = [
            cookie for cookie in cookies
            if cookie["name"].startswith("wordpress_")
        ]
        self.assertEqual(3, len(auth_cookies))
        self.assert_no_conflicting_set_cookies(auth_cookies)
        if EXPECTED_COOKIE_DOMAIN:
            self.assertTrue(all("domain" in cookie["attributes"] for cookie in auth_cookies))
            self.assertTrue(all(
                cookie["attributes"]["domain"].lstrip(".").lower()
                == EXPECTED_COOKIE_DOMAIN.lstrip(".").lower()
                for cookie in auth_cookies
            ))
        else:
            self.assertTrue(all("domain" not in cookie["attributes"] for cookie in auth_cookies))
        self.assertTrue(all(cookie["attributes"].get("secure") is True for cookie in auth_cookies))
        self.assertTrue(all(cookie["attributes"].get("httponly") is True for cookie in auth_cookies))
        self.assertTrue(all(cookie["attributes"].get("samesite") == "None" for cookie in auth_cookies))

        paths = {cookie["name"]: cookie["attributes"].get("path") for cookie in auth_cookies}
        self.assertEqual("/wp-admin", next(path for name, path in paths.items() if name.startswith("wordpress_sec_")))
        self.assertEqual("/wp-admin", next(path for name, path in paths.items() if name.startswith("wordpress_") and not name.startswith("wordpress_sec_") and not name.startswith("wordpress_logged_in_")))
        self.assertEqual("/", next(path for name, path in paths.items() if name.startswith("wordpress_logged_in_")))

        decoded_values = [unquote(cookie["value"]) for cookie in auth_cookies]
        session_tokens = [value.split("|")[2] for value in decoded_values]
        self.assertEqual(1, len(set(session_tokens)))
        self.assertEqual(1, self.session_count())

        logout_path = self.logout_url(client)
        status, logout_headers, _ = client.request(logout_path)
        self.assertEqual(302, status)
        self.assert_no_conflicting_set_cookies(parse_set_cookies(logout_headers))
        self.assertEqual(0, self.session_count())
        self.assertEqual([], client.stored_wordpress_auth_cookies())

        status, _, _ = client.request("/wp-admin/")
        self.assertEqual(302, status)

    def test_03_valid_signed_jwt_via_bearer_creates_session(self):
        client = CurlClient(self.directory, "valid-bearer.txt")
        token = self.issue_token()
        status, headers, body = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(200, status, body)
        self.assertEqual(int(TEST_USER_ID), json.loads(body)["user_id"])
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assertEqual(1, self.session_count())

    def test_04_valid_signed_jwt_via_form_creates_session(self):
        client = CurlClient(self.directory, "valid-form.txt")
        token = self.issue_token()
        status, headers, body = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            data=urlencode({"token": token}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_URL,
            },
        )
        self.assertEqual(200, status, body)
        self.assertEqual(int(TEST_USER_ID), json.loads(body)["user_id"])
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assertEqual(1, self.session_count())

    def test_04a_valid_signed_jwt_via_json_creates_session(self):
        client = CurlClient(self.directory, "valid-json.txt")
        token = self.issue_token()
        status, headers, body = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            data=json.dumps({"token": token}),
            headers={
                "Content-Type": "application/json",
                "Origin": "https://frontend.example.com:443",
            },
        )
        self.assertEqual(200, status, body)
        self.assertEqual(int(TEST_USER_ID), json.loads(body)["user_id"])
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assertEqual(1, self.session_count())

    def test_04b_body_tokens_require_one_valid_trusted_origin(self):
        token = self.issue_token()
        attempts = [
            ("missing", None),
            ("null", "null"),
            ("untrusted", "https://attacker.example.invalid"),
            ("wrong-port", "https://frontend.example.com:444"),
            ("path", "https://frontend.example.com/path"),
            ("comma-list", "https://frontend.example.com,https://attacker.example.invalid"),
            ("space-list", "https://frontend.example.com https://attacker.example.invalid"),
            ("scheme", "ftp://frontend.example.com"),
            ("credentials", "https://user@frontend.example.com"),
        ]
        for transport in ("form", "json"):
            for name, origin in attempts:
                with self.subTest(transport=transport, origin=name):
                    client = CurlClient(self.directory, f"denied-{transport}-{name}.txt")
                    headers = {
                        "Content-Type": (
                            "application/x-www-form-urlencoded"
                            if transport == "form"
                            else "application/json"
                        ),
                    }
                    if origin is not None:
                        headers["Origin"] = origin
                    data = urlencode({"token": token}) if transport == "form" else json.dumps({"token": token})
                    status, response_headers, _ = client.request(
                        "/wp-json/custom/v1/login_via_jwt",
                        method="POST",
                        data=data,
                        headers=headers,
                    )
                    self.assertEqual(403, status)
                    self.assertEqual([], self.bridge_auth_cookies(response_headers))
                    self.assertEqual(0, self.session_count())

    def test_04c_bearer_origin_is_optional_but_strict_when_present(self):
        allowed_origins = [
            "https://FRONTEND.EXAMPLE.COM:443",
            "http://LOCALHOST:4200",
            BASE_URL,
        ]
        for index, origin in enumerate(allowed_origins):
            with self.subTest(allowed=origin):
                client = CurlClient(self.directory, f"allowed-bearer-origin-{index}.txt")
                status, response_headers, _ = client.request(
                    "/wp-json/custom/v1/login_via_jwt",
                    method="POST",
                    headers={"Authorization": "Bearer not-a-jwt", "Origin": origin},
                )
                self.assertEqual(401, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(0, self.session_count())

        denied_origins = [
            "null",
            "https://attacker.example.invalid",
            "https://frontend.example.com:444",
            "https://frontend.example.com/path",
            "https://frontend.example.com,https://attacker.example.invalid",
        ]
        token = self.issue_token()
        for index, origin in enumerate(denied_origins):
            with self.subTest(denied=origin):
                client = CurlClient(self.directory, f"denied-bearer-origin-{index}.txt")
                status, response_headers, _ = client.request(
                    "/wp-json/custom/v1/login_via_jwt",
                    method="POST",
                    headers={"Authorization": f"Bearer {token}", "Origin": origin},
                )
                self.assertEqual(403, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(0, self.session_count())

    def test_04d_origin_rejection_precedes_jwt_validation(self):
        client = CurlClient(self.directory, "origin-before-validation.txt")
        status, response_headers, _ = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            headers={
                "Authorization": "Bearer not-a-jwt",
                "Origin": "https://attacker.example.invalid",
            },
        )
        self.assertEqual(403, status)
        self.assertEqual([], self.bridge_auth_cookies(response_headers))
        self.assertEqual(0, self.session_count())

    def invalid_tokens(self):
        return {
            "malformed": "not-a-jwt",
            "invalid-signature": self.issue_token(variant="invalid-signature"),
            "expired": self.issue_token(variant="expired"),
            "future-nbf": self.issue_token(variant="future-nbf"),
            "wrong-issuer": self.issue_token(variant="wrong-issuer"),
            "invalid-user": self.issue_token(variant="invalid-user"),
        }

    def test_05_invalid_tokens_never_create_sessions(self):
        attempts = {"missing": None, **self.invalid_tokens()}
        for name, token in attempts.items():
            with self.subTest(name=name):
                client = CurlClient(self.directory, f"invalid-{name}.txt")
                headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
                status, response_headers, _ = client.request(
                    "/wp-json/custom/v1/login_via_jwt",
                    method="POST",
                    headers=headers,
                )
                self.assertEqual(401, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(0, self.session_count())

    def test_06_valid_cookie_cannot_bypass_invalid_jwt(self):
        client = CurlClient(self.directory, "cookie-cannot-bypass.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assertEqual(1, self.session_count())

        for name, token in self.invalid_tokens().items():
            with self.subTest(name=name):
                status, response_headers, _ = client.request(
                    "/wp-json/custom/v1/login_via_jwt",
                    method="POST",
                    headers={"Authorization": f"Bearer {token}"},
                )
                self.assertEqual(401, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(1, self.session_count())

    def test_07_application_password_cannot_bypass_invalid_form_jwt(self):
        credentials = base64.b64encode(
            f"{TEST_USERNAME}:{TEST_APPLICATION_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        for name, token in self.invalid_tokens().items():
            with self.subTest(name=name):
                client = CurlClient(self.directory, f"application-password-{name}.txt")
                status, response_headers, _ = client.request(
                    "/wp-json/custom/v1/login_via_jwt",
                    method="POST",
                    data=urlencode({"token": token}),
                    headers={
                        "Authorization": f"Basic {credentials}",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": BASE_URL,
                    },
                )
                self.assertEqual(400, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(0, self.session_count())

    def test_08_different_valid_jwt_and_cookie_users_conflict(self):
        client = CurlClient(self.directory, "identity-conflict.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        token = self.issue_token(user_id=TEST_USER_B_ID)
        status, response_headers, _ = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(409, status)
        self.assertEqual([], self.bridge_auth_cookies(response_headers))
        self.assertEqual(1, self.session_count(TEST_USER_ID))
        self.assertEqual(0, self.session_count(TEST_USER_B_ID))

    def test_09_ambiguous_and_query_transports_are_rejected(self):
        token = self.issue_token()
        credentials = base64.b64encode(
            f"{TEST_USERNAME}:{TEST_APPLICATION_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        attempts = [
            (
                "/wp-json/custom/v1/login_via_jwt",
                {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"},
                urlencode({"token": token}),
            ),
            (f"/wp-json/custom/v1/login_via_jwt?token={token}", {}, None),
            (
                "/wp-json/custom/v1/login_via_jwt",
                {"Authorization": f"Basic {credentials}", "Content-Type": "application/x-www-form-urlencoded"},
                urlencode({"token": token}),
            ),
        ]
        for index, (path, headers, data) in enumerate(attempts):
            with self.subTest(index=index):
                client = CurlClient(self.directory, f"ambiguous-{index}.txt")
                status, response_headers, _ = client.request(
                    path, method="POST", headers=headers, data=data
                )
                self.assertEqual(400, status)
                self.assertEqual([], self.bridge_auth_cookies(response_headers))
                self.assertEqual(0, self.session_count())

    def test_10_checkout_redirect_is_preserved(self):
        client = CurlClient(self.directory, "checkout-redirect.txt")
        token = self.issue_token()
        redirect = BASE_URL + "/checkout/order-pay/123/?key=non-secret-test-key"
        status, headers, _ = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            data=urlencode({"token": token, "redirect": redirect}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_URL,
            },
        )
        self.assertEqual(302, status)
        self.assertIn(f"location: {redirect}".lower(), headers.lower())
        self.assertEqual(1, self.session_count())

    def test_11_popup_flow_is_preserved(self):
        client = CurlClient(self.directory, "popup.txt")
        token = self.issue_token()
        status, _, body = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            data=urlencode({
                "token": token,
                "mode": "popup",
                "return_origin": "https://frontend.example.com",
            }),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://frontend.example.com",
            },
        )
        self.assertEqual(200, status)
        self.assertIn("woo-login-ok", body)
        self.assertEqual(1, self.session_count())

    def test_12_bounce_flow_is_preserved(self):
        client = CurlClient(self.directory, "bounce.txt")
        token = self.issue_token()
        return_to = "https://frontend.example.com/payment-complete"
        status, _, body = client.request(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            data=urlencode({"token": token, "mode": "bounce", "return_to": return_to}),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://frontend.example.com",
            },
        )
        self.assertEqual(200, status)
        self.assertIn("frontend.example.com", body)
        self.assertIn("payment-complete", body)
        self.assertIn("window.location.replace", body)
        self.assertEqual(1, self.session_count())

    def test_13_standard_a_then_bridge_a_then_logout(self):
        client = CurlClient(self.directory, "mixed-standard-a-bridge-a.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assertEqual(int(TEST_USER_ID), self.authenticated_user_id(client))
        self.assertEqual(1, self.session_count(TEST_USER_ID))
        standard_cookies = client.stored_wordpress_auth_cookies()

        status, headers, body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assert_transition_scope(
            headers, standard_cookies, client, expected_host_only=not bool(EXPECTED_COOKIE_DOMAIN)
        )
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assertEqual(2, self.session_count(TEST_USER_ID))

        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(1, self.session_count(TEST_USER_ID))

    def test_14_bridge_a_then_standard_a_then_logout(self):
        client = CurlClient(self.directory, "mixed-bridge-a-standard-a.txt")
        status, headers, body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assert_one_browser_identity(client, TEST_USER_ID)
        bridge_cookies = client.stored_wordpress_auth_cookies()

        status, standard_headers, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assert_transition_scope(
            standard_headers, bridge_cookies, client, expected_host_only=True
        )
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assertEqual(2, self.session_count(TEST_USER_ID))

        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(1, self.session_count(TEST_USER_ID))

    def test_15_repeated_bridge_a_then_logout(self):
        client = CurlClient(self.directory, "mixed-repeated-bridge-a.txt")
        first_status, first_headers, first_body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, first_status, first_body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(first_headers))
        first_fingerprints = {
            cookie["token_fingerprint"] for cookie in self.assert_one_browser_identity(client, TEST_USER_ID)
        }

        second_status, second_headers, second_body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, second_status, second_body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(second_headers))
        second_fingerprints = {
            cookie["token_fingerprint"] for cookie in self.assert_one_browser_identity(client, TEST_USER_ID)
        }
        self.assertNotEqual(first_fingerprints, second_fingerprints)
        self.assertTrue(all(
            cookie["host_only"] is (not bool(EXPECTED_COOKIE_DOMAIN))
            for cookie in client.stored_wordpress_auth_cookies()
        ))
        self.assertEqual(2, self.session_count(TEST_USER_ID))

        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(1, self.session_count(TEST_USER_ID))

    def test_16_standard_a_logout_then_bridge_a(self):
        client = CurlClient(self.directory, "mixed-standard-a-logout-bridge-a.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(0, self.session_count(TEST_USER_ID))

        status, headers, body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assertTrue(all(
            cookie["host_only"] is (not bool(EXPECTED_COOKIE_DOMAIN))
            for cookie in client.stored_wordpress_auth_cookies()
        ))
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assertEqual(1, self.session_count(TEST_USER_ID))

    def test_17_standard_a_then_bridge_b_is_rejected(self):
        client = CurlClient(self.directory, "mixed-standard-a-bridge-b.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        cookies_before = client.stored_wordpress_auth_cookies()
        self.assert_one_browser_identity(client, TEST_USER_ID)

        status, headers, _ = self.bridge_login(client, TEST_USER_B_ID)
        self.assertEqual(409, status)
        self.assertEqual([], self.bridge_auth_cookies(headers))
        self.assertEqual(cookies_before, client.stored_wordpress_auth_cookies())
        self.assertEqual(1, self.session_count(TEST_USER_ID))
        self.assertEqual(0, self.session_count(TEST_USER_B_ID))
        self.assertEqual(int(TEST_USER_ID), self.authenticated_user_id(client))

    def test_18_bridge_a_then_standard_b_then_logout(self):
        client = CurlClient(self.directory, "mixed-bridge-a-standard-b.txt")
        status, headers, body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assert_one_browser_identity(client, TEST_USER_ID)
        bridge_cookies = client.stored_wordpress_auth_cookies()

        status, standard_headers, _ = self.standard_login(client, TEST_USER_B_USERNAME)
        self.assertEqual(302, status)
        self.assert_transition_scope(
            standard_headers, bridge_cookies, client, expected_host_only=True
        )
        self.assert_one_browser_identity(client, TEST_USER_B_ID)
        self.assertEqual(1, self.session_count(TEST_USER_ID))
        self.assertEqual(1, self.session_count(TEST_USER_B_ID))

        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(1, self.session_count(TEST_USER_ID))
        self.assertEqual(0, self.session_count(TEST_USER_B_ID))

    def test_19_bridge_a_logout_then_standard_b(self):
        client = CurlClient(self.directory, "mixed-bridge-a-logout-standard-b.txt")
        status, headers, body = self.bridge_login(client, TEST_USER_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(0, self.session_count(TEST_USER_ID))

        status, _, _ = self.standard_login(client, TEST_USER_B_USERNAME)
        self.assertEqual(302, status)
        self.assert_one_browser_identity(client, TEST_USER_B_ID)
        self.assertEqual(1, self.session_count(TEST_USER_B_ID))

    def test_20_standard_a_logout_then_bridge_b(self):
        client = CurlClient(self.directory, "mixed-standard-a-logout-bridge-b.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assert_one_browser_identity(client, TEST_USER_ID)
        self.assert_logout_clears_browser_authentication(client)
        self.assertEqual(0, self.session_count(TEST_USER_ID))

        status, headers, body = self.bridge_login(client, TEST_USER_B_ID)
        self.assertEqual(200, status, body)
        self.assert_bridge_cookie_scope(self.bridge_auth_cookies(headers))
        self.assert_one_browser_identity(client, TEST_USER_B_ID)
        self.assertEqual(1, self.session_count(TEST_USER_B_ID))

    def test_21_repeated_core_bridge_scope_transitions(self):
        client = CurlClient(self.directory, "mixed-repeated-scope-transitions.txt")
        status, _, _ = self.standard_login(client)
        self.assertEqual(302, status)
        self.assert_one_browser_identity(client, TEST_USER_ID)

        for _ in range(2):
            core_cookies = client.stored_wordpress_auth_cookies()
            status, bridge_headers, body = self.bridge_login(client, TEST_USER_ID)
            self.assertEqual(200, status, body)
            self.assert_bridge_cookie_scope(self.bridge_auth_cookies(bridge_headers))
            self.assert_transition_scope(
                bridge_headers,
                core_cookies,
                client,
                expected_host_only=not bool(EXPECTED_COOKIE_DOMAIN),
            )
            self.assert_one_browser_identity(client, TEST_USER_ID)

            bridge_cookies = client.stored_wordpress_auth_cookies()
            status, core_headers, _ = self.standard_login(client)
            self.assertEqual(302, status)
            self.assert_transition_scope(
                core_headers, bridge_cookies, client, expected_host_only=True
            )
            self.assert_one_browser_identity(client, TEST_USER_ID)

        self.assert_logout_clears_browser_authentication(client)


if __name__ == "__main__":
    unittest.main(verbosity=2)
