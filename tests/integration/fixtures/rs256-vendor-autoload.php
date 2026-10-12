<?php

spl_autoload_register(static function (string $class): void {
    $prefix = 'Firebase\\JWT\\';
    if (strpos($class, $prefix) !== 0) {
        return;
    }

    $file = __DIR__ . '/firebase/php-jwt/src/' . substr($class, strlen($prefix)) . '.php';
    if (is_readable($file)) {
        require_once $file;
    }
});
