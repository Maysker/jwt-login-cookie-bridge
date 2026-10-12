import html
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support.ui import WebDriverWait


BASE_URL = os.environ["JWT_BRIDGE_BASE_URL"]
TEST_SECRET = os.environ["JWT_BRIDGE_TEST_SECRET"]
TEST_USER_ID = int(os.environ["JWT_BRIDGE_TEST_USER_ID"])
TEST_USER_B_ID = int(os.environ["JWT_BRIDGE_TEST_USER_B_ID"])
TEST_USERNAME = os.environ["JWT_BRIDGE_TEST_USERNAME"]
TEST_USER_B_USERNAME = os.environ["JWT_BRIDGE_TEST_USER_B_USERNAME"]
TEST_PASSWORD = os.environ["JWT_BRIDGE_TEST_PASSWORD"]
EXPECTED_COOKIE_DOMAIN = os.environ["JWT_BRIDGE_EXPECTED_COOKIE_DOMAIN"]
BROWSER = os.environ["JWT_BRIDGE_BROWSER"]


def auth_cookies(driver):
    result = {}
    # WebDriver returns cookies applicable to the current URL, not necessarily
    # every stored path. Visit each WordPress authentication-cookie path and
    # combine metadata without reading or reporting any cookie value.
    for path in ("/", "/wp-admin/admin-ajax.php", "/wp-content/plugins/"):
        driver.get(BASE_URL + path)
        for cookie in driver.get_cookies():
            if not cookie["name"].startswith("wordpress_") or cookie["name"] == "wordpress_test_cookie":
                continue
            domain = cookie["domain"].lower()
            item = {
                "name": cookie["name"],
                "domain": domain.lstrip("."),
                "host_only": not domain.startswith("."),
                "path": cookie["path"],
                "secure": cookie["secure"],
                "http_only": cookie.get("httpOnly", False),
                "same_site": cookie.get("sameSite"),
                "persistent": "expiry" in cookie,
            }
            result[(item["name"], domain, item["path"])] = item
    return sorted(result.values(), key=lambda item: (item["name"], item["domain"], item["path"]))


class FormHandler(BaseHTTPRequestHandler):
    document = ""

    def do_GET(self):
        body = self.document.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class BrowserCookieTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = cls.create_driver()
        cls.wait = WebDriverWait(cls.driver, 15)
        cls.form_server = ThreadingHTTPServer(("127.0.0.1", 4200), FormHandler)
        cls.form_thread = threading.Thread(target=cls.form_server.serve_forever, daemon=True)
        cls.form_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.form_server.shutdown()
        cls.form_server.server_close()
        cls.driver.quit()

    @classmethod
    def create_driver(cls):
        if BROWSER == "chromium":
            options = webdriver.ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--host-resolver-rules=MAP shop.example.test 127.0.0.1")
            options.set_capability("acceptInsecureCerts", True)
            return webdriver.Chrome(options=options)
        if BROWSER == "firefox":
            options = webdriver.FirefoxOptions()
            options.add_argument("-headless")
            options.accept_insecure_certs = True
            options.set_preference("network.dns.localDomains", "shop.example.test")
            return webdriver.Firefox(
                options=options,
                service=FirefoxService(executable_path="/snap/bin/geckodriver"),
            )
        raise RuntimeError(f"Unsupported browser: {BROWSER}")

    def setUp(self):
        self.driver.get(BASE_URL + "/wp-login.php")
        self.driver.delete_all_cookies()
        for user_id in (TEST_USER_ID, TEST_USER_B_ID):
            result = self.fetch(
                "/wp-json/jwt-bridge-test/v1/reset-sessions/",
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-JWT-Bridge-Test-Secret": TEST_SECRET,
                },
                body=f"user_id={user_id}",
            )
            self.assertEqual(200, result["status"], result)

    def fetch(self, path, *, method="GET", headers=None, body=None):
        return self.driver.execute_async_script(
            """
            const [url, method, headers, body, done] = arguments;
            fetch(url, {method, headers, body, credentials: 'include'})
              .then(async response => done({status: response.status, body: await response.text()}))
              .catch(error => done({status: 0, body: String(error)}));
            """,
            BASE_URL + path,
            method,
            headers or {},
            body,
        )

    def issue_token(self, user_id):
        result = self.fetch(
            "/wp-json/jwt-bridge-test/v1/issue-jwt/",
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-JWT-Bridge-Test-Secret": TEST_SECRET,
            },
            body=f"user_id={user_id}&variant=valid",
        )
        self.assertEqual(200, result["status"], result)
        return json.loads(result["body"])["token"]

    def bridge_login(self, user_id):
        token = self.issue_token(user_id)
        return self.fetch(
            "/wp-json/custom/v1/login_via_jwt",
            method="POST",
            headers={"Authorization": "Bearer " + token},
        )

    def bridge_form_login(self, user_id):
        token = self.issue_token(user_id)
        FormHandler.document = (
            "<!doctype html><meta charset=utf-8>"
            f"<form id=submit method=post action=\"{html.escape(BASE_URL + '/wp-json/custom/v1/login_via_jwt', quote=True)}\">"
            f"<input type=hidden name=token value=\"{html.escape(token, quote=True)}\">"
            "</form><script>document.getElementById('submit').submit()</script>"
        )
        self.driver.get("http://localhost:4200/")
        self.wait.until(lambda driver: urlparse(driver.current_url).hostname == "shop.example.test")
        return self.driver.find_element(By.TAG_NAME, "body").text

    def standard_login(self, username):
        self.driver.get(BASE_URL + "/wp-login.php")
        FormHandler.document = (
            "<!doctype html><meta charset=utf-8>"
            f"<form id=submit method=post action=\"{html.escape(BASE_URL + '/wp-login.php', quote=True)}\">"
            f"<input type=hidden name=log value=\"{html.escape(username, quote=True)}\">"
            f"<input type=hidden name=pwd value=\"{html.escape(TEST_PASSWORD, quote=True)}\">"
            "<input type=hidden name=wp-submit value=\"Log In\">"
            f"<input type=hidden name=redirect_to value=\"{html.escape(BASE_URL + '/', quote=True)}\">"
            "<input type=hidden name=testcookie value=1>"
            "</form><script>document.getElementById('submit').submit()</script>"
        )
        self.driver.get("http://localhost:4200/")
        self.wait.until(lambda driver: urlparse(driver.current_url).hostname == "shop.example.test")
        self.wait.until(lambda driver: "/wp-login.php" not in driver.current_url)

    def identity(self):
        result = self.fetch(
            "/wp-json/jwt-bridge-test/v1/authenticated-user/",
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, result["status"], result)
        return int(json.loads(result["body"])["user_id"])

    def session_count(self, user_id):
        result = self.fetch(
            f"/wp-json/jwt-bridge-test/v1/session-count/?user_id={user_id}",
            headers={"X-JWT-Bridge-Test-Secret": TEST_SECRET},
        )
        self.assertEqual(200, result["status"], result)
        return int(json.loads(result["body"])["count"])

    def logout(self):
        self.driver.get(BASE_URL + "/wp-login.php?action=logout")
        link = self.driver.find_element(By.CSS_SELECTOR, "a[href*='action=logout']")
        link.click()
        self.wait.until(lambda _driver: self.identity() == 0)

    def assert_scope(self, expected_host_only):
        cookies = auth_cookies(self.driver)
        if EXPECTED_COOKIE_DOMAIN:
            self.assertEqual(3, len(cookies), cookies)
        else:
            # With one shared host-only scope, core's plugin-path secure cookie
            # can coexist with the Bridge's three tuples without ambiguity.
            self.assertIn(len(cookies), (3, 4), cookies)
        self.assertTrue(all(cookie["host_only"] is expected_host_only for cookie in cookies), cookies)
        self.assertTrue(all(cookie["secure"] and cookie["http_only"] for cookie in cookies), cookies)
        self.assertEqual(len(cookies), len({
            (cookie["name"], cookie["domain"], cookie["host_only"], cookie["path"])
            for cookie in cookies
        }))
        print("cookie-metadata=" + json.dumps(cookies, sort_keys=True))

    def assert_logged_out(self):
        self.assertEqual(0, self.identity())
        self.assertEqual([], auth_cookies(self.driver))

    def test_01_standard_a_bridge_a_logout(self):
        self.standard_login(TEST_USERNAME)
        self.assertEqual(TEST_USER_ID, self.identity())
        self.assert_scope(True)
        response_body = self.bridge_form_login(TEST_USER_ID)
        self.assertIn('"success":true', response_body.replace(" ", ""))
        self.assertEqual(TEST_USER_ID, self.identity())
        self.assert_scope(not bool(EXPECTED_COOKIE_DOMAIN))
        self.logout()
        self.assert_logged_out()

    def test_02_bridge_a_standard_a_logout(self):
        result = self.bridge_login(TEST_USER_ID)
        self.assertEqual(200, result["status"], result)
        self.assertEqual(TEST_USER_ID, self.identity())
        self.assert_scope(not bool(EXPECTED_COOKIE_DOMAIN))
        self.standard_login(TEST_USERNAME)
        self.assertEqual(TEST_USER_ID, self.identity())
        self.assert_scope(True)
        self.logout()
        self.assert_logged_out()

    def test_03_bridge_a_standard_b(self):
        result = self.bridge_login(TEST_USER_ID)
        self.assertEqual(200, result["status"], result)
        self.assertEqual(TEST_USER_ID, self.identity())
        self.standard_login(TEST_USER_B_USERNAME)
        self.assertEqual(TEST_USER_B_ID, self.identity())
        self.assert_scope(True)

    def test_04_standard_a_bridge_b_conflict(self):
        self.standard_login(TEST_USERNAME)
        self.assertEqual(TEST_USER_ID, self.identity())
        sessions_before = self.session_count(TEST_USER_B_ID)
        result = self.bridge_login(TEST_USER_B_ID)
        self.assertEqual(409, result["status"], result)
        self.assertEqual(TEST_USER_ID, self.identity())
        self.assertEqual(sessions_before, self.session_count(TEST_USER_B_ID))
        self.assert_scope(True)

    def test_05_repeated_scope_alternation(self):
        self.standard_login(TEST_USERNAME)
        for _ in range(2):
            result = self.bridge_login(TEST_USER_ID)
            self.assertEqual(200, result["status"], result)
            self.assertEqual(TEST_USER_ID, self.identity())
            self.assert_scope(not bool(EXPECTED_COOKIE_DOMAIN))
            self.standard_login(TEST_USERNAME)
            self.assertEqual(TEST_USER_ID, self.identity())
            self.assert_scope(True)
        self.logout()
        self.assert_logged_out()


if __name__ == "__main__":
    unittest.main(verbosity=2)
