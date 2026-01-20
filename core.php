<?php
// core.php - GŁÓWNY PLIK KONFIGURACYJNY

// 1. Inicjalizacja sesji
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_strict_mode', 1);
    session_start();
}

// 2. Konfiguracja
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
ini_set('display_errors', 0); // Zmień na 1 w razie problemów

// 3. Baza Danych
$host = getenv('MYSQL_HOST') ?: 'mysql';
$user = getenv('MYSQL_USER') ?: 'user';
$pass = getenv('MYSQL_PASSWORD') ?: 'password';
$dbname = getenv('MYSQL_DATABASE') ?: 'moja_baza';

try {
    $conn = new mysqli($host, $user, $pass, $dbname);
    $conn->set_charset("utf8mb4");
    if ($conn->connect_error) throw new Exception("Connection failed");
} catch (Exception $e) {
    error_log("DB Error: " . $e->getMessage());
    die("Błąd systemu.");
}

// 4. Nagłówki
if (!headers_sent()) {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
}

// 5. CSRF (To naprawia Twój błąd)
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token'])) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}

function checkCSRFOrDie() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            http_response_code(403);
            die('Błąd bezpieczeństwa CSRF. Odśwież stronę.');
        }
    }
}

function getCSRFInput() {
    $token = generateCSRFToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

// 6. Hasła
class PasswordSecurity {
    public static function validatePassword($p) {
        $e = [];
        if(strlen($p)<8) $e[]="Min 8 znaków";
        return ['valid'=>empty($e), 'errors'=>$e];
    }
    public static function hashPassword($p) { return password_hash($p, PASSWORD_ARGON2ID); }
    public static function verifyPassword($p, $h) { return password_verify($p, $h); }
}

// 7. Rate Limiting
function checkLoginAttempts($conn, $ip) {
    $conn->query("CREATE TABLE IF NOT EXISTS login_attempts (id INT AUTO_INCREMENT PRIMARY KEY, ip_address VARCHAR(45), attempt_time DATETIME)");
    $conn->query("DELETE FROM login_attempts WHERE attempt_time < NOW() - INTERVAL 15 MINUTE");
    $stmt = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $count = 0;
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();
    return $count < 5;
}

function logFailedLogin($conn, $ip) {
    $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, NOW())");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $stmt->close();
}

function ensureSession() { if(session_status() === PHP_SESSION_NONE) session_start(); }
?>