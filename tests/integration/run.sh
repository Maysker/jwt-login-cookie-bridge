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
php_jwt_archive="$runtime_dir/php-jwt.7.2.1.zip"
rs256_private_key="$runtime_dir/rs256-private.pem"
rs256_other_private_key="$runtime_dir/rs256-other-private.pem"
rs256_public_key="$runtime_dir/rs256-public.pem"
rs256_ec_private_key="$runtime_dir/rs256-ec-private.pem"
rs256_ec_public_key="$runtime_dir/rs256-ec-public.pem"
rs256_invalid_key="$runtime_dir/rs256-invalid-public.pem"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$runtime_dir/key.pem" \
    -out "$runtime_dir/cert.pem" \
    -subj '/CN=shop.example.test' \
    -addext 'subjectAltName=DNS:shop.example.test' >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$rs256_private_key" >/dev/null 2>&1
openssl pkey -in "$rs256_private_key" -pubout -out "$rs256_public_key"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$rs256_other_private_key" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$rs256_ec_private_key" >/dev/null 2>&1
openssl pkey -in "$rs256_ec_private_key" -pubout -out "$rs256_ec_public_key"
printf '%s\n' 'not a public key' >"$rs256_invalid_key"
chmod 600 "$rs256_private_key" "$rs256_other_private_key" "$rs256_ec_private_key"
chmod 644 "$rs256_public_key" "$rs256_ec_public_key" "$rs256_invalid_key"

curl --fail --silent --show-error --location \
    'https://downloads.wordpress.org/plugin/woocommerce.11.2.0.zip' \
    --output "$woocommerce_archive"
chmod 644 "$woocommerce_archive"
printf '%s  %s\n' \
    '66e91b45b057b64c73d4521111cea5bdc78c4c89de8fa2ca4b18b9422706d722' \
    "$woocommerce_archive" | sha256sum --check --status

curl --fail --silent --show-error --location \
    'https://github.com/googleapis/php-jwt/archive/refs/tags/v7.2.1.zip' \
    --output "$php_jwt_archive"
printf '%s  %s\n' \
    '95dacc206254d7c6272d9b9aaf25862dbe26c769010e1de3725f7fe0c2a85e14' \
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
    mkdir -p /var/www/html/wp-content/plugins/jwt-login-rs256-validator/vendor/firebase/php-jwt
    mkdir -p /var/www/html/wp-content/plugins/jwt-login-rs256-validator-missing
    mkdir -p /var/www/html/wp-content/mu-plugins
    mkdir -p /var/www/html/wp-content/mu-plugins/jwt-bridge-test-vendor/php-jwt
    cp /workspace/jwt-login-cookie.php /var/www/html/wp-content/plugins/jwt-login-cookie/jwt-login-cookie.php
    cp -R /workspace/examples/rs256-validator/. /var/www/html/wp-content/plugins/jwt-login-rs256-validator/
    cp /workspace/examples/rs256-validator/jwt-login-rs256-validator.php /var/www/html/wp-content/plugins/jwt-login-rs256-validator-missing/jwt-login-rs256-validator.php
    cp /workspace/tests/integration/fixtures/rs256-vendor-autoload.php /var/www/html/wp-content/plugins/jwt-login-rs256-validator/vendor/autoload.php
    cp -R /integration-runtime/php-jwt-7.2.1/src /var/www/html/wp-content/plugins/jwt-login-rs256-validator/vendor/firebase/php-jwt/src
    cp /workspace/tests/integration/fixtures/jwt-bridge-test-driver.php /var/www/html/wp-content/mu-plugins/jwt-bridge-test-driver.php
    cp -R /integration-runtime/php-jwt-7.2.1/src /var/www/html/wp-content/mu-plugins/jwt-bridge-test-vendor/php-jwt/src
    chown -R www-data:www-data /var/www/html/wp-content/plugins/jwt-login-cookie /var/www/html/wp-content/plugins/jwt-login-rs256-validator /var/www/html/wp-content/plugins/jwt-login-rs256-validator-missing /var/www/html/wp-content/mu-plugins
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

run_cors_isolation() {
    local baseline_file="$runtime_dir/cors-unrelated-baseline.json"

    echo 'REST CORS isolation baseline: Bridge disabled'
    "${compose[@]}" run --rm cli wp plugin deactivate jwt-login-cookie
    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    JWT_BRIDGE_CORS_MODE=capture \
    JWT_BRIDGE_CORS_BASELINE_FILE="$baseline_file" \
    python3 "$integration_dir/cors_isolation_tests.py"

    "${compose[@]}" run --rm cli wp plugin activate jwt-login-cookie
    echo 'REST CORS isolation verification: Bridge enabled'
    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    JWT_BRIDGE_CORS_MODE=verify \
    JWT_BRIDGE_CORS_BASELINE_FILE="$baseline_file" \
    python3 "$integration_dir/cors_isolation_tests.py"
}

if [[ "${JWT_BRIDGE_SKIP_CORS:-0}" != "1" ]]; then
    run_cors_isolation
fi

if [[ "${JWT_BRIDGE_ONLY_CORS:-0}" == "1" ]]; then
    exit 0
fi

run_frame_policy_isolation() {
    local baseline_file="$runtime_dir/frame-policy-baseline.json"
    local original_checkout_id
    local custom_checkout_id
    local ordinary_page_id
    local unrelated_page_id
    local order_pay_url
    local order_pay_path

    original_checkout_id=$("${compose[@]}" run --rm --quiet cli wp option get woocommerce_checkout_page_id)
    custom_checkout_id=$("${compose[@]}" run --rm --quiet cli wp post create \
        --post_type=page --post_status=publish --post_title='Embedded Checkout' \
        --post_name=embedded-checkout --post_content='[woocommerce_checkout]' --porcelain)
    ordinary_page_id=$("${compose[@]}" run --rm --quiet cli wp post create \
        --post_type=page --post_status=publish --post_title='Frame Ordinary' \
        --post_name=frame-ordinary --porcelain)
    unrelated_page_id=$("${compose[@]}" run --rm --quiet cli wp post create \
        --post_type=page --post_status=publish --post_title='Checkout Unrelated' \
        --post_name=frame-unrelated --post_parent="$original_checkout_id" --porcelain)
    "${compose[@]}" run --rm cli wp option update woocommerce_checkout_page_id "$custom_checkout_id"
    order_pay_url=$("${compose[@]}" run --rm --quiet cli wp eval \
        '$order = wc_create_order(); $order->set_status("pending"); $order->save(); echo $order->get_checkout_payment_url();')
    order_pay_path=$(python3 -c 'import sys,urllib.parse; u=urllib.parse.urlsplit(sys.argv[1]); print(u.path + (("?" + u.query) if u.query else ""))' "$order_pay_url")

    echo 'Frame policy isolation baseline: Bridge disabled'
    "${compose[@]}" run --rm cli wp plugin deactivate jwt-login-cookie
    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_FRAME_MODE=capture \
    JWT_BRIDGE_FRAME_BASELINE_FILE="$baseline_file" \
    JWT_BRIDGE_FRAME_CHECKOUT_PATH='/embedded-checkout/' \
    JWT_BRIDGE_FRAME_ORDER_PAY_PATH="$order_pay_path" \
    JWT_BRIDGE_FRAME_ORDINARY_PATH='/frame-ordinary/' \
    JWT_BRIDGE_FRAME_UNRELATED_CHECKOUT_PATH='/checkout/frame-unrelated/' \
    python3 "$integration_dir/frame_policy_tests.py"

    "${compose[@]}" run --rm cli wp plugin activate jwt-login-cookie
    echo 'Frame policy isolation verification: Bridge enabled'
    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_FRAME_MODE=verify \
    JWT_BRIDGE_FRAME_BASELINE_FILE="$baseline_file" \
    JWT_BRIDGE_FRAME_CHECKOUT_PATH='/embedded-checkout/' \
    JWT_BRIDGE_FRAME_ORDER_PAY_PATH="$order_pay_path" \
    JWT_BRIDGE_FRAME_ORDINARY_PATH='/frame-ordinary/' \
    JWT_BRIDGE_FRAME_UNRELATED_CHECKOUT_PATH='/checkout/frame-unrelated/' \
    python3 "$integration_dir/frame_policy_tests.py"

    "${compose[@]}" run --rm cli wp option update woocommerce_checkout_page_id "$original_checkout_id"
}

if [[ "${JWT_BRIDGE_SKIP_FRAME_POLICY:-0}" != "1" ]]; then
    run_frame_policy_isolation
fi

if [[ "${JWT_BRIDGE_ONLY_FRAME_POLICY:-0}" == "1" ]]; then
    exit 0
fi

run_destination_validation() {
    echo 'Bounce and redirect destination validation'
    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    python3 "$integration_dir/destination_validation_tests.py"
}

if [[ "${JWT_BRIDGE_SKIP_DESTINATIONS:-0}" != "1" ]]; then
    run_destination_validation
fi

if [[ "${JWT_BRIDGE_ONLY_DESTINATIONS:-0}" == "1" ]]; then
    exit 0
fi

run_cookie_scope() {
    local scenario=$1
    local cookie_domain=$2

    echo "Cookie scope scenario: $scenario"
    JWT_LOGIN_COOKIE_DOMAIN="$cookie_domain" "${compose[@]}" up --detach --no-deps --force-recreate wordpress
    wait_for_wordpress

    if [[ "${JWT_BRIDGE_SKIP_BEHAVIORAL:-0}" != "1" ]]; then
        PYTHONDONTWRITEBYTECODE=1 \
        JWT_BRIDGE_BASE_URL="$base_url" \
        JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
        JWT_BRIDGE_TEST_SECRET="$test_secret" \
        JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
        JWT_BRIDGE_TEST_USER_B_ID="$test_user_b_id" \
        JWT_BRIDGE_TEST_USERNAME=integration-user \
        JWT_BRIDGE_TEST_USER_B_USERNAME=integration-user-b \
        JWT_BRIDGE_TEST_PASSWORD="$test_password" \
        JWT_BRIDGE_TEST_APPLICATION_PASSWORD="$test_application_password" \
        JWT_BRIDGE_EXPECTED_COOKIE_DOMAIN="$cookie_domain" \
        python3 "$integration_dir/behavioral_tests.py"
    fi

    if [[ -n "${JWT_BRIDGE_BROWSER_PYTHON:-}" ]]; then
        local browser_test_args=()
        if [[ -n "${JWT_BRIDGE_BROWSER_TEST:-}" ]]; then
            browser_test_args+=("$JWT_BRIDGE_BROWSER_TEST")
        fi
        for browser in ${JWT_BRIDGE_BROWSERS:-chromium firefox}; do
            JWT_BRIDGE_BASE_URL="$base_url" \
            JWT_BRIDGE_TEST_SECRET="$test_secret" \
            JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
            JWT_BRIDGE_TEST_USER_B_ID="$test_user_b_id" \
            JWT_BRIDGE_TEST_USERNAME=integration-user \
            JWT_BRIDGE_TEST_USER_B_USERNAME=integration-user-b \
            JWT_BRIDGE_TEST_PASSWORD="$test_password" \
            JWT_BRIDGE_EXPECTED_COOKIE_DOMAIN="$cookie_domain" \
            JWT_BRIDGE_BROWSER="$browser" \
            "$JWT_BRIDGE_BROWSER_PYTHON" "$integration_dir/browser_tests.py" \
                "${browser_test_args[@]}"
        done
    fi
}

suite_status=0
case "${JWT_BRIDGE_COOKIE_SCOPE:-all}" in
    all)
        run_cookie_scope host-only '' || suite_status=$?
        run_cookie_scope exact-host 'shop.example.test' || suite_status=$?
        run_cookie_scope parent-domain '.example.test' || suite_status=$?
        ;;
    host-only)
        run_cookie_scope host-only '' || suite_status=$?
        ;;
    exact-host)
        run_cookie_scope exact-host 'shop.example.test' || suite_status=$?
        ;;
    parent-domain)
        run_cookie_scope parent-domain '.example.test' || suite_status=$?
        ;;
    *)
        echo "Unknown JWT_BRIDGE_COOKIE_SCOPE: $JWT_BRIDGE_COOKIE_SCOPE" >&2
        exit 2
        ;;
esac

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

if [[ "${JWT_BRIDGE_SKIP_VALIDATORS:-0}" != "1" ]]; then
    run_validator_failure unconfigured '' reference || suite_status=$?
    run_validator_failure missing 'test/missing' reference || suite_status=$?
    run_validator_failure duplicate 'test/reference' duplicate || suite_status=$?
    run_validator_failure exception 'test/reference' throw || suite_status=$?
    run_validator_failure unexpected-return 'test/reference' unexpected-return || suite_status=$?
fi

run_rs256_scenario() {
    local scenario=$1
    local public_key_file=$2
    local audience=$3

    echo "RS256 example validator scenario: $scenario"
    JWT_LOGIN_ACTIVE_VALIDATOR='example/rs256' \
    JWT_LOGIN_COOKIE_DOMAIN='' \
    JWT_LOGIN_RS256_PUBLIC_KEY_FILE="$public_key_file" \
    JWT_LOGIN_RS256_ISSUER='https://rs256-issuer.example.test' \
    JWT_LOGIN_RS256_AUDIENCE="$audience" \
    JWT_LOGIN_RS256_IDENTITY_CLAIM='wp_user_id' \
    JWT_LOGIN_RS256_MAXIMUM_LIFETIME='300' \
    JWT_BRIDGE_TEST_DISABLE_FIREBASE_AUTOLOAD='1' \
    "${compose[@]}" up --detach --no-deps --force-recreate wordpress
    wait_for_wordpress

    PYTHONDONTWRITEBYTECODE=1 \
    JWT_BRIDGE_BASE_URL="$base_url" \
    JWT_BRIDGE_CURL_RESOLVE="$curl_resolve" \
    JWT_BRIDGE_TEST_SECRET="$test_secret" \
    JWT_BRIDGE_TEST_USER_ID="$test_user_id" \
    JWT_BRIDGE_RS256_PRIVATE_KEY="$rs256_private_key" \
    JWT_BRIDGE_RS256_OTHER_PRIVATE_KEY="$rs256_other_private_key" \
    JWT_BRIDGE_RS256_ISSUER='https://rs256-issuer.example.test' \
    JWT_BRIDGE_RS256_AUDIENCE='wordpress-store' \
    JWT_BRIDGE_RS256_IDENTITY_CLAIM='wp_user_id' \
    JWT_BRIDGE_RS256_TEST_MODE="$scenario" \
    python3 "$integration_dir/rs256_validator_tests.py"
}

if [[ "${JWT_BRIDGE_SKIP_RS256:-0}" != "1" ]]; then
    "${compose[@]}" run --rm cli wp plugin activate jwt-login-rs256-validator

    run_rs256_scenario normal '/integration-runtime/rs256-public.pem' 'wordpress-store' || suite_status=$?
    run_rs256_scenario invalid-key '/integration-runtime/rs256-invalid-public.pem' 'wordpress-store' || suite_status=$?
    run_rs256_scenario wrong-key-type '/integration-runtime/rs256-ec-public.pem' 'wordpress-store' || suite_status=$?
    run_rs256_scenario missing-config '/integration-runtime/rs256-public.pem' '' || suite_status=$?

    "${compose[@]}" run --rm cli wp plugin deactivate jwt-login-rs256-validator
    "${compose[@]}" run --rm cli wp plugin activate jwt-login-rs256-validator-missing/jwt-login-rs256-validator.php
    run_rs256_scenario missing-dependency '/integration-runtime/rs256-public.pem' 'wordpress-store' || suite_status=$?
fi

exit "$suite_status"
