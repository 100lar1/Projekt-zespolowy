<?php
/**
 * Prosty system ochrony CSRF - NAPRAWIONA WERSJA
 * ✅ NAPRAWIONE: Stabilniejsze zarządzanie tokenami
 */

/**
 * Bezpiecznie rozpoczyna sesję tylko jeśli nie istnieje
 */
function ensureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        // Sprawdź czy nagłówki już wysłane
        if (headers_sent($filename, $line)) {
            error_log("Cannot start session - headers already sent in $filename:$line");
            return false;
        }
        session_start();
    }
    return true;
}

/**
 * Generuje token CSRF i zapisuje go w sesji
 * ✅ NAPRAWKA: Token nie jest regenerowany za każdym razem
 * @return string Token CSRF
 */
function generateCSRFToken() {
    if (!ensureSession()) {
        return false;
    }
    
    // Jeśli token już istnieje i jest świeży (mniej niż 30 minut), użyj go
    if (isset($_SESSION['csrf_token']) && isset($_SESSION['csrf_token_time'])) {
        $tokenAge = time() - $_SESSION['csrf_token_time'];
        if ($tokenAge < 1800) { // 30 minut
            return $_SESSION['csrf_token'];
        }
    }
    
    // Generuj nowy token tylko jeśli nie ma lub jest stary
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_token_time'] = time();
    
    return $token;
}

/**
 * Weryfikuje token CSRF
 * ✅ NAPRAWKA: NIE regeneruje tokenu po weryfikacji
 * @param string $token Token do weryfikacji
 * @return bool True jeśli token jest prawidłowy
 */
function verifyCSRFToken($token) {
    if (!ensureSession()) {
        return false;
    }
    
    // Sprawdź czy token istnieje w sesji
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
        error_log("CSRF: Brak tokenu w sesji");
        return false;
    }
    
    // Sprawdź czy token nie wygasł (ważny przez 1 godzinę)
    if (time() - $_SESSION['csrf_token_time'] > 3600) {
        error_log("CSRF: Token wygasł");
        unset($_SESSION['csrf_token']);
        unset($_SESSION['csrf_token_time']);
        return false;
    }
    
    // Porównaj tokeny używając hash_equals dla bezpieczeństwa
    $isValid = hash_equals($_SESSION['csrf_token'], $token);
    
    if (!$isValid) {
        error_log("CSRF: Token nie pasuje. Oczekiwany: " . substr($_SESSION['csrf_token'], 0, 10) . "..., Otrzymany: " . substr($token, 0, 10) . "...");
    }
    
    // ✅ GŁÓWNA NAPRAWKA: NIE regeneruj tokenu po każdej weryfikacji
    // Token pozostaje aktywny do wygaśnięcia
    
    return $isValid;
}

/**
 * Zwraca HTML input z tokenem CSRF
 * @return string HTML input z tokenem
 */
function getCSRFInput() {
    $token = generateCSRFToken();
    if (!$token) {
        return '<!-- CSRF token error -->';
    }
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
}

/**
 * Sprawdza token CSRF z POST i kończy skrypt jeśli nieprawidłowy
 * ✅ NAPRAWKA: Lepsze komunikaty błędów
 */
function checkCSRFOrDie() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        
        if (empty($token)) {
            error_log("CSRF: Brak tokenu w POST");
            http_response_code(403);
            die('Błąd bezpieczeństwa: Brak tokenu CSRF. <a href="javascript:history.back()">Wróć</a> i spróbuj ponownie.');
        }
        
        if (!verifyCSRFToken($token)) {
            error_log("CSRF: Weryfikacja nie powiodła się");
            http_response_code(403);
            die('Błąd bezpieczeństwa: Nieprawidłowy token CSRF. <a href="javascript:location.reload()">Odśwież stronę</a> i spróbuj ponownie.');
        }
    }
}

/**
 * ✅ NOWA FUNKCJA: Wymuś regenerację tokenu (np. po zalogowaniu)
 */
function regenerateCSRFToken() {
    if (!ensureSession()) {
        return false;
    }
    
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_token_time'] = time();
    
    return $token;
}
?>