#!/usr/bin/env bash
set -euo pipefail

integration_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
runtime_dir=$(mktemp -d -t jwt-bridge-integration-XXXXXX)
chmod 711 "$runtime_dir"
compose_project="jwt_bridge_phase1_${$}"
compose_file="$integration_dir/compose.yaml"
env_file="$runtime_dir/environment"

cleanup() {
    if [[ "${KEEP_INTEGRATION:-0}" != "1" ]]; then
        docker compose --project-name "$compose_project" --env-file "$env_file" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
        if [[ "$runtime_dir" == /tmp/jwt-bridge-integration-* ]]; then
            rm -rf -- "$runtime_dir"
        fi
    else
        printf 'Integration environment retained at %s\n' "$runtime_dir"
    fi
}
trap cleanup EXIT

https_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
database_password=$(openssl rand -hex 24)
database_root_password=$(openssl rand -hex 24)
admin_password=$(openssl rand -hex 24)
test_password=$(openssl rand -hex 24)
test_secret=$(openssl rand -hex 32)
jwt_test_key=$(openssl rand -hex 48)
woocommerce_archive="$runtime_dir/woocommerce.11.2.0.zip"
php_jwt_archive="$runtime_dir/php-jwt.6.11.1.zip"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$runtime_dir/key.pem" \
    -out "$runtime_dir/cert.pem" \
    -subj '/CN=shop.example.test' \
    -addext 'subjectAltName=DNS:shop.example.test' >/dev/null 2>&1

curl --fail --silent --show-error --location \
    'https://downloads.wordpress.org/plugin/woocommerce.11.2.0.zip' \
    --output "$woocommerce_archive"
chmod 644 "$woocommerce_archive"
printf '%s  %s\n' \
    '66e91b45b057b64c73d4521111cea5bdc78c4c89de8fa2ca4b18b9422706d722' \
    "$woocommerce_archive" | sha256sum --check --status

curl --fail --silent --show-error --location \
    'https://github.com/firebase/php-jwt/archive/refs/tags/v6.11.1.zip' \
    --output "$php_jwt_archive"
printf '%s  %s\n' \
    '1c46f1c7ec7e1a378966f19b8a828cd21d42d4967b7b789d0d432f536277cc3d' \
    "$php_jwt_archive" | sha256sum --check --status
unzip -q "$php_jwt_archive" -d "$runtime_dir"

printf '%s\n' \
    "COMPOSE_PROJECT_NAME=$compose_project" \
    "HTTPS_PORT=$https_port" \
    "TLS_CERT_FILE=$runtime_dir/cert.pem" \
    "TLS_KEY_FILE=$runtime_dir/key.pem" \
    "INTEGRATION_RUNTIME_DIR=$runtime_dir" \
    'WP_DB_NAME=wordpress' \
    'WP_DB_USER=wordpress' \
    "WP_DB_PASSWORD=$database_password" \
    "WP_DB_ROOT_PASSWORD=$database_root_password" \
    "JWT_BRIDGE_TEST_SECRET=$test_secret" \
    "JWT_BRIDGE_TEST_JWT_KEY=$jwt_test_key" \
    'JWT_BRIDGE_TEST_JWT_ALGORITHM=HS256' \
    'JWT_BRIDGE_TEST_JWT_ISSUER=https://jwt-issuer.example.test' \
    'JWT_BRIDGE_TEST_VALIDATOR_MODE=reference' \
    'JWT_LOGIN_ACTIVE_VALIDATOR=test/reference' >"$env_file"
chmod 600 "$env_file"

compose=(docker compose --project-name "$compose_project" --env-file "$env_file" --file "$compose_file")
base_url="https://shop.example.test:$https_port"
curl_resolve="shop.example.test:$https_port:127.0.0.1"

wait_for_wordpress() {
    for attempt in $(seq 1 60); do
        if curl --noproxy '*' --insecure --silent --fail --resolve "$curl_resolve" "$base_url/wp-login.php" >/dev/null 2>&1; then
            return
        fi
        if [[ "$attempt" == "60" ]]; then
            echo 'WordPress did not become ready in time.' >&2
            exit 1
        fi
        sleep 2
    done
}

"${compose[@]}" pull
"${compose[@]}" up --detach database wordpress proxy
wait_for_wordpress

"${compose[@]}" run --rm cli wp core install \
    --url="$base_url" \
    --title='JWT Bridge Integration' \
    --admin_user=integration-admin \
    --admin_password="$admin_password" \
    --admin_email=integration-admin@example.invalid \
    --skip-email
"${compose[@]}" run --rm cli wp rewrite structure '/%postname%/' --hard

"${compose[@]}" exec --no-TTY wordpress sh -eu -c '
    mkdir -p /var/www/html/wp-content/plugins/jwt-login-cookie
    mkdir -p /var/www/html/wp-content/mu-plugins
    mkdir -p /var/www/html/wp-content/mu-plugins/jwt-bridge-test-vendor/php-jwt
    cp /workspace/jwt-login-cookie.php /var/www/html/wp-content/plugins/jwt-login-cookie/jwt-login-cookie.php
    cp /workspace/tests/integration/fixtures/jwt-bridge-test-driver.php /var/www/html/wp-content/mu-plugins/jwt-bridge-test-driver.php
    cp -R /integration-runtime/php-jwt-6.11.1/src /var/www/html/wp-content/mu-plugins/jwt-bridge-test-vendor/php-jwt/src
    chown -R www-data:www-data /var/www/html/wp-content/plugins/jwt-login-cookie /var/www/html/wp-content/mu-plugins
'

"${compose[@]}" run --rm cli wp plugin activate jwt-login-cookie
"${compose[@]}" run --rm cli wp plugin install /integration-runtime/woocommerce.11.2.0.zip --activate
test_user_id=$("${compose[@]}" run --rm --quiet cli wp user create integration-user integration-user@example.invalid \
    --role=administrator \
    --user_pass="$test_password" \
    --porcelain)
test_application_password=$("${compose[@]}" run --rm --quiet cli wp user application-password create \
    "$test_user_id" jwt-bridge-phase2-audit --porcelain)
test_user_b_id=$("${compose[@]}" run --rm --quiet cli wp user create integration-user-b integration-user-b@example.invalid \
    --role=customer \
    --user_pass="$test_password" \
    --porcelain)

echo 'Pinned integration environment:'
"${compose[@]}" run --rm cli wp core version
"${compose[@]}" run --rm cli wp eval 'echo PHP_VERSION . PHP_EOL;'
"${compose[@]}" run --rm cli wp plugin get woocommerce --field=version
"${compose[@]}" exec --no-TTY database mariadb --version

run_cookie_scope() {
    local scenario=$1
    local cookie_domain=$2

    echo "Cookie scope scenario: $scenario"
    JWT_LOGIN_COOKIE_DOMAIN="$cookie_domain" "${compose[@]}" up --detach --no-deps --force-recreate wordpress
    wait_for_wordpress

    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    JWT_BRIDGE_TEST_USER_B_ID="$test_user_b_id" \
    JWT_BRIDGE_TEST_USERNAME=integration-user \
    JWT_BRIDGE_TEST_PASSWORD="$test_password" \
    JWT_BRIDGE_TEST_APPLICATION_PASSWORD="$test_application_password" \
    JWT_BRIDGE_EXPECTED_COOKIE_DOMAIN="$cookie_domain" \
    python3 "$integration_dir/behavioral_tests.py"
}

run_cookie_scope host-only ''
run_cookie_scope exact-host 'shop.example.test'
run_cookie_scope parent-domain '.example.test'

run_validator_failure() {
    local scenario=$1
    local active_validator=$2
    local validator_mode=$3

    echo "Validator failure scenario: $scenario"
    JWT_LOGIN_COOKIE_DOMAIN='' \
    JWT_LOGIN_ACTIVE_VALIDATOR="$active_validator" \
    JWT_BRIDGE_TEST_VALIDATOR_MODE="$validator_mode" \
    "${compose[@]}" up --detach --no-deps --force-recreate wordpress
    wait_for_wordpress

    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    JWT_BRIDGE_EXPECTED_VALIDATOR_STATUS=503 \
    python3 "$integration_dir/validator_configuration_tests.py"
}

run_validator_failure unconfigured '' reference
run_validator_failure missing 'test/missing' reference
run_validator_failure duplicate 'test/reference' duplicate
run_validator_failure exception 'test/reference' throw
run_validator_failure unexpected-return 'test/reference' unexpected-return
