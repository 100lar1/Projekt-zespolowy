<?php
// Wyłącz Notice dla session_start
error_reporting(E_ALL & ~E_NOTICE);
$host = 'mysql'; // <- nazwa usługi z docker-compose.yml
$user = 'user';
$pass = 'password';
$dbname = 'moja_baza';

try {
    $conn = new mysqli($host, $user, $pass, $dbname);
    
    // Ustawienie charset na UTF-8 dla bezpieczeństwa
    $conn->set_charset("utf8mb4");
    
    if ($conn->connect_error) {
        throw new Exception("Błąd połączenia: " . $conn->connect_error);
    }
    
    // Debug output tylko w trybie deweloperskim
    if (defined('DEBUG_MODE') && DEBUG_MODE === true) {
       // echo "Połączenie działa!";
    }
    
} catch (Exception $e) {
    // Logowanie błędu zamiast wyświetlania użytkownikowi
    error_log("Database connection error: " . $e->getMessage());
    
    // W produkcji pokaż ogólny komunikat
    if (!defined('DEBUG_MODE') || DEBUG_MODE !== true) {
        die("Przepraszamy, wystąpił problem z połączeniem do bazy danych. Spróbuj ponownie później.");
    } else {
        die("Błąd połączenia z bazą danych: " . $e->getMessage());
    }
}
?>