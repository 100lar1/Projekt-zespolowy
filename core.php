<?php
// core.php - Serce systemu (Baza, Sesje, Bezpieczeństwo)

// 1. Inicjalizacja sesji (jeśli nie wystartowała)
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_strict_mode', 1);
    session_start();
}

// 2. Konfiguracja i Baza Danych
// Wyłącz wyświetlanie błędów użytkownikowi na produkcji
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
ini_set('display_errors', 0); // Zmień na 1 tylko w trybie deweloperskim

// Dane do bazy - pobierane ze zmiennych środowiskowych (lub domyślne dla deweloperki)
$host = getenv('MYSQL_HOST') ?: 'mysql';
$user = getenv('MYSQL_USER') ?: 'user';
$pass = getenv('MYSQL_PASSWORD') ?: 'password';
$dbname = getenv('MYSQL_DATABASE') ?: 'moja_baza';

try {
    $conn = new mysqli($host, $user, $pass, $dbname);
    $conn->set_charset("utf8mb4");
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
} catch (Exception $e) {
    // Loguj błąd do pliku serwera
    error_log("DB Error: " . $e->getMessage());
    die("Wystąpił błąd systemu. Proszę spróbować później.");
}

// 3. Nagłówki Bezpieczeństwa
if (!headers_sent()) {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
    // CSP: Dostosowane do Chart.js i stylów inline
    $csp = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';";
    header("Content-Security-Policy: " . $csp);
}

// 4. Ochrona CSRF - TE FUNKCJE BYŁY BRAKUJĄCE
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function checkCSRFOrDie() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
            http_response_code(403);
            die('Błąd bezpieczeństwa CSRF. Token jest nieprawidłowy lub wygasł. Odśwież stronę i spróbuj ponownie.');
        }
    }
}

function getCSRFInput() {
    $token = generateCSRFToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

// 5. Rate Limiting (Ochrona przed Brute Force)
function checkLoginAttempts($conn, $ip) {
    // Utwórz tabelę, jeśli nie istnieje (dla uproszczenia wdrożenia)
    $conn->query("CREATE TABLE IF NOT EXISTS login_attempts (id INT AUTO_INCREMENT PRIMARY KEY, ip_address VARCHAR(45), attempt_time DATETIME)");
    
    // Usuń stare wpisy (> 15 min)
    $conn->query("DELETE FROM login_attempts WHERE attempt_time < NOW() - INTERVAL 15 MINUTE");
    
    // Sprawdź liczbę prób
    $stmt = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $count = 0;
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();
    
    return $count < 5; // Max 5 prób na 15 minut
}

function logFailedLogin($conn, $ip) {
    $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, NOW())");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $stmt->close();
}

// 6. Bezpieczeństwo Haseł
class PasswordSecurity {
    public static function validatePassword($password) {
        $errors = [];
        if (strlen($password) < 8) $errors[] = "Hasło musi mieć min. 8 znaków";
        if (!preg_match('/[A-Z]/', $password)) $errors[] = "Wymagana wielka litera";
        if (!preg_match('/[a-z]/', $password)) $errors[] = "Wymagana mała litera";
        if (!preg_match('/[0-9]/', $password)) $errors[] = "Wymagana cyfra";
        if (!preg_match('/[^a-zA-Z0-9]/', $password)) $errors[] = "Wymagany znak specjalny";
        
        return ['valid' => empty($errors), 'errors' => $errors];
    }

    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    // JS helper do walidacji w przeglądarce
    public static function getClientSideValidationJS() {
        return "
        function validatePasswordStrength(password) {
            let errors = [];
            if(password.length < 8) errors.push('Min. 8 znaków');
            if(!/[A-Z]/.test(password)) errors.push('Brak wielkiej litery');
            if(!/[a-z]/.test(password)) errors.push('Brak małej litery');
            if(!/[0-9]/.test(password)) errors.push('Brak cyfry');
            return errors;
        }";
    }
    public static function getPasswordStrengthCSS() { return ""; }
}

// Funkcja pomocnicza dla kompatybilności
function ensureSession() {
    if (session_status() === PHP_SESSION_NONE) session_start();
}
?>