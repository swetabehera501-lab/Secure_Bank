<?php
/* ============================================================
   SecureBank — php/db.php
   ONLY PURPOSE: Connect to MySQL. Nothing else.
   Edit DB_NAME, DB_USER, DB_PASS below if needed.
   XAMPP default: root / (empty password)
============================================================ */

define('DB_HOST', 'localhost');
define('DB_NAME', 'securebank_db');
define('DB_USER', 'root');
define('DB_PASS', '');     // ← leave empty for XAMPP default

try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    // Always return JSON because this file is called from api.php
    header('Content-Type: application/json');
    http_response_code(500);

    $msg = $e->getMessage();

    // Give helpful diagnosis
    if (str_contains($msg, 'Unknown database')) {
        $hint = 'Database "securebank_db" does not exist. Open phpMyAdmin and run sql/setup.sql first.';
    } elseif (str_contains($msg, 'Connection refused') || str_contains($msg, '2002')) {
        $hint = 'MySQL is not running. Open XAMPP Control Panel and click START next to MySQL.';
    } elseif (str_contains($msg, 'Access denied')) {
        $hint = 'Wrong username or password. Edit DB_USER and DB_PASS in php/db.php.';
    } else {
        $hint = $msg;
    }

    die(json_encode([
        'error' => 'Database connection failed',
        'hint'  => $hint,
        'fix'   => 'Make sure XAMPP Apache + MySQL are both running, then visit http://localhost/securebank/'
    ]));
}
?>
