<?php
/**
 * Kompleksowa konfiguracja nagłówków bezpieczeństwa
 */
function setSecurityHeaders() {
    // Zapobiega atakom clickjacking
    header("X-Frame-Options: DENY");
    // Zapobiega sniffowaniu typu MIME
    header("X-Content-Type-Options: nosniff");
    // Włącza ochronę XSS w przeglądarkach
    header("X-XSS-Protection: 1; mode=block");
    // Strict Transport Security (tylko HTTPS)
    // Włącz to tylko jeśli używasz HTTPS w produkcji
    // header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"); 
    // Content Security Policy - restrykcyjne ale funkcjonalne
    $csp = "default-src 'self'; " .
           "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; " .
           "style-src 'self' 'unsafe-inline'; " .
           "img-src 'self' data:; " .
           "font-src 'self' https://fonts.gstatic.com; " .
           "connect-src 'self'; " .
           "frame-ancestors 'none'; " .
           "base-uri 'self'; " .
           "form-action 'self';"; 
    header("Content-Security-Policy: " . $csp);
    // Polityka Referrer - ogranicza wyciek informacji
    header("Referrer-Policy: strict-origin-when-cross-origin");
    // Polityka Uprawnień (Feature Policy) - wyłącza niepotrzebne funkcje
    $permissions = "camera=(), " .
                  "microphone=(), " .
                  "geolocation=(), " .
                  "payment=(), " .
                  "usb=(), " .
                  "bluetooth=(), " .
                  "magnetometer=(), " .
                  "gyroscope=(), " .
                  "accelerometer=()";
    header("Permissions-Policy: " . $permissions);
    // Zapobiega ujawnianiu informacji
    header("Server: WebServer");
    header("X-Powered-By: ");
    // Kontrola cache dla wrażliwych stron
    if (session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['user_id'])) {
        header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
        header("Pragma: no-cache");
        header("Expires: Sat, 01 Jan 2000 00:00:00 GMT");
    }
}
/**
 * Ustawia nagłówki bezpieczeństwa specjalnie dla endpointów API
 */
function setAPISecurityHeaders() {
    // Podstawowe nagłówki bezpieczeństwa dla API
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    // CSP specyficzne dla API
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none';");
    // Brak cache dla odpowiedzi API zawierających wrażliwe dane
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache");
    // Usuwa informacje o serwerze
    header("Server: API");
    header("X-Powered-By: ");
}
/**
 * Ustawia nagłówki bezpieczeństwa dla stron logowania/rejestracji
 */
function setAuthPageHeaders() {
    setSecurityHeaders();  
    // Dodatkowe bezpieczeństwo dla stron uwierzytelniania
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache");
    header("Expires: Sat, 01 Jan 2000 00:00:00 GMT");
}
/**
 * Nagłówki bezpieczeństwa dla stron publicznych (index.php)
 */
function setPublicPageHeaders() {
    // Podstawowe nagłówki bezpieczeństwa
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
    
    // Bardziej permisywne CSP dla stron publicznych
    $csp = "default-src 'self'; " .
           "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " .
           "style-src 'self' 'unsafe-inline'; " .
           "img-src 'self' data:; " .
           "frame-ancestors 'none'; " .
           "base-uri 'self';";
    
    header("Content-Security-Policy: " . $csp);
    header("Referrer-Policy: strict-origin-when-cross-origin");
    
    // Pozwala na cache dla zawartości publicznej
    header("Cache-Control: public, max-age=300");
}
// Automatycznie ustawia nagłówki na podstawie bieżącego skryptu
function autoSetSecurityHeaders() {
    $script = basename($_SERVER['SCRIPT_NAME']);   
    switch ($script) {
        case 'results_api.php':
            setAPISecurityHeaders();
            break;   
        case 'login.php':
        case 'register.php':
            setAuthPageHeaders();
            break;           
        case 'index.php':
            setPublicPageHeaders();
            break;           
        default:
            // Dla wszystkich innych stron (dashboard, admin, itp.)
            setSecurityHeaders();
            break;
    }
}
?>