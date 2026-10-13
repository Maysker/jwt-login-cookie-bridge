<?php
/**
 * Plugin Name: JWT Login Cookie Bridge - Example RS256 Validator
 * Plugin URI: https://github.com/Maysker/jwt-login-cookie-bridge/tree/master/examples/rs256-validator
 * Description: Optional provider-neutral RS256 validator for JWT Login Cookie Bridge.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 8.0
 * Author: Adam Gazdiev (Airobot nv)
 * License: GPLv3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Update URI: https://github.com/Maysker/jwt-login-cookie-bridge/tree/master/examples/rs256-validator
 */

defined('ABSPATH') || exit;

$jwt_login_rs256_autoload = __DIR__ . '/vendor/autoload.php';
if (is_readable($jwt_login_rs256_autoload)) {
    require_once $jwt_login_rs256_autoload;
}
unset($jwt_login_rs256_autoload);

if (!class_exists('JWT_Login_RS256_Example_Validator', false)) {
    final class JWT_Login_RS256_Example_Validator {
        private const ALGORITHM = 'RS256';

        /**
         * Verify and map one exact raw JWT.
         *
         * Invalid tokens return WP_Error and become HTTP 401 responses. Broken
         * server configuration throws a sanitized exception and becomes 503.
         *
         * @return JWT_Login_Verified_Identity|WP_Error
         */
        public static function validate(string $raw_jwt) {
            $configuration = self::configuration();

            if (!class_exists('Firebase\\JWT\\JWT') || !class_exists('Firebase\\JWT\\Key')) {
                throw new RuntimeException('RS256 validator dependency is unavailable.');
            }

            $public_key = self::public_key($configuration['public_key_file']);

            try {
                $claims = \Firebase\JWT\JWT::decode(
                    $raw_jwt,
                    new \Firebase\JWT\Key($public_key, self::ALGORITHM)
                );
            } catch (Throwable $error) {
                return self::invalid_token();
            }

            if (!is_object($claims)) {
                return self::invalid_token();
            }

            foreach (['iat', 'nbf', 'exp'] as $claim_name) {
                if (!isset($claims->{$claim_name}) || !is_int($claims->{$claim_name}) || $claims->{$claim_name} < 1) {
                    return self::invalid_token();
                }
            }

            if (!isset($claims->iss)
                || !is_string($claims->iss)
                || !hash_equals($configuration['issuer'], $claims->iss)
                || !self::audience_matches($claims->aud ?? null, $configuration['audience'])
            ) {
                return self::invalid_token();
            }

            $now = time();
            if ($claims->iat > $now
                || $claims->nbf > $now
                || $claims->exp <= $now
                || $claims->exp <= $claims->iat
                || $claims->exp <= $claims->nbf
                || ($claims->exp - $claims->iat) > $configuration['maximum_lifetime']
            ) {
                return self::invalid_token();
            }

            $identity_claim = $configuration['identity_claim'];
            $user_id = self::positive_integer($claims->{$identity_claim} ?? null);
            if ($user_id === null) {
                return self::invalid_token();
            }

            return new JWT_Login_Verified_Identity($user_id);
        }

        /**
         * @return array{public_key_file:string,issuer:string,audience:string,identity_claim:string,maximum_lifetime:int}
         */
        private static function configuration(): array {
            $required_strings = [
                'JWT_LOGIN_RS256_PUBLIC_KEY_FILE' => 'public_key_file',
                'JWT_LOGIN_RS256_ISSUER'          => 'issuer',
                'JWT_LOGIN_RS256_AUDIENCE'        => 'audience',
                'JWT_LOGIN_RS256_IDENTITY_CLAIM'  => 'identity_claim',
            ];
            $configuration = [];

            foreach ($required_strings as $constant_name => $configuration_name) {
                if (!defined($constant_name)) {
                    throw new RuntimeException('RS256 validator configuration is incomplete.');
                }
                $value = constant($constant_name);
                if (!is_string($value) || trim($value) === '') {
                    throw new RuntimeException('RS256 validator configuration is invalid.');
                }
                $configuration[$configuration_name] = $value;
            }

            if (!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,127}\z/', $configuration['identity_claim'])) {
                throw new RuntimeException('RS256 validator configuration is invalid.');
            }

            if (!defined('JWT_LOGIN_RS256_MAXIMUM_LIFETIME')) {
                throw new RuntimeException('RS256 validator configuration is incomplete.');
            }
            $maximum_lifetime = constant('JWT_LOGIN_RS256_MAXIMUM_LIFETIME');
            if (!is_int($maximum_lifetime) || $maximum_lifetime < 1) {
                throw new RuntimeException('RS256 validator configuration is invalid.');
            }
            $configuration['maximum_lifetime'] = $maximum_lifetime;

            return $configuration;
        }

        private static function public_key(string $file): string {
            if (!is_file($file) || !is_readable($file)) {
                throw new RuntimeException('RS256 verification key is unavailable.');
            }

            $pem = file_get_contents($file);
            if (!is_string($pem) || $pem === '') {
                throw new RuntimeException('RS256 verification key is unavailable.');
            }

            $key = openssl_pkey_get_public($pem);
            if ($key === false) {
                throw new RuntimeException('RS256 verification key is invalid.');
            }
            $details = openssl_pkey_get_details($key);
            if (!is_array($details)
                || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
                || !isset($details['bits'])
                || !is_int($details['bits'])
                || $details['bits'] < 2048
            ) {
                throw new RuntimeException('RS256 verification key is invalid.');
            }

            return $pem;
        }

        private static function audience_matches($claim, string $expected): bool {
            if (is_string($claim)) {
                $audiences = [$claim];
            } elseif (is_array($claim) && $claim !== []) {
                $audiences = $claim;
            } else {
                return false;
            }

            foreach ($audiences as $audience) {
                if (!is_string($audience)) {
                    return false;
                }
            }

            foreach ($audiences as $audience) {
                if (hash_equals($expected, $audience)) {
                    return true;
                }
            }
            return false;
        }

        private static function positive_integer($value): ?int {
            if (is_int($value)) {
                return $value > 0 ? $value : null;
            }
            if (!is_string($value) || !preg_match('/\A[1-9][0-9]*\z/', $value)) {
                return null;
            }

            $maximum = (string) PHP_INT_MAX;
            if (strlen($value) > strlen($maximum)
                || (strlen($value) === strlen($maximum) && strcmp($value, $maximum) > 0)
            ) {
                return null;
            }

            $integer = (int) $value;
            return $integer > 0 ? $integer : null;
        }

        private static function invalid_token(): WP_Error {
            return new WP_Error('invalid_jwt', 'Invalid token.');
        }
    }
}

add_action('jwt_login_register_validators', static function (): void {
    jwt_login_register_validator(
        'example/rs256',
        ['JWT_Login_RS256_Example_Validator', 'validate']
    );
});
