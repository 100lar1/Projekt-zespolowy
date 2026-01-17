<?php
session_start();
if (!isset($_SESSION['user_id']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit;
}
include 'db.php';
include 'csrf_protection.php';

// Debug informacje (można usunąć po naprawie)
error_log("POST data: " . print_r($_POST, true));
error_log("Session CSRF token: " . ($_SESSION['csrf_token'] ?? 'BRAK'));
error_log("POST CSRF token: " . ($_POST['csrf_token'] ?? 'BRAK'));

// ✅ Sprawdzenie CSRF dla wszystkich POST requestów
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        error_log("CSRF verification failed in admin_panel.php");
        http_response_code(403);
        die('Błąd bezpieczeństwa: Nieprawidłowy token CSRF. <a href="admin_panel.php">Odśwież stronę</a> i spróbuj ponownie.');
    }
}

// ✅ FUNKCJA POMOCNICZA - normalizacja polskich znaków
function normalizePolishChars($text) {
    $polish_chars = ['ą', 'ć', 'ę', 'ł', 'ń', 'ó', 'ś', 'ź', 'ż'];
    $latin_chars = ['a', 'c', 'e', 'l', 'n', 'o', 's', 'z', 'z'];
    return str_replace($polish_chars, $latin_chars, strtolower(trim($text)));
}

// ✅ FUNKCJA POMOCNICZA - sprawdzanie unikalności nazwy administratora
function isAdminUsernameUnique($username, $conn) {
    $check_stmt = $conn->prepare("SELECT id FROM users WHERE admin_username = ?");
    if (!$check_stmt) {
        error_log("Database prepare error: " . $conn->error);
        return false;
    }
    
    $check_stmt->bind_param("s", $username);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    $is_unique = ($result->num_rows === 0);
    $check_stmt->close();
    
    return $is_unique;
}

// ✅ FUNKCJA POMOCNICZA - znajdowanie unikalnej nazwy z licznikiem
function findUniqueUsername($base_username, $conn) {
    $username = $base_username;
    $counter = 1;
    
    while (!isAdminUsernameUnique($username, $conn)) {
        // Utwórz nową nazwę z licznikiem
        $counter_str = (string)$counter;
        $max_base_length = 50 - strlen($counter_str); // Maksymalna długość kolumny minus licznik
        
        if ($max_base_length < 1) {
            // W skrajnym przypadku użyj prostej nazwy
            $username = 'a' . $counter;
        } else {
            $base_truncated = substr($base_username, 0, $max_base_length);
            $username = $base_truncated . $counter;
        }
        
        $counter++;
        
        // Zabezpieczenie przed nieskończoną pętlą
        if ($counter > 99999) {
            $username = 'admin' . substr(time(), -5);
            error_log("Fallback username generated: $username");
            break;
        }
    }
    
    return $username;
}

// ✅ ZREFAKTOROWANA funkcja generowania nazwy administratora
function generateAdminUsername($name, $surname, $conn) {
    // Normalizuj dane wejściowe
    $name_clean = normalizePolishChars($name);
    $surname_clean = normalizePolishChars($surname);
    
    // Usuń wszystko oprócz liter i cyfr
    $name_clean = preg_replace('/[^a-z0-9]/', '', $name_clean);
    $surname_clean = preg_replace('/[^a-z0-9]/', '', $surname_clean);
    
    // Utwórz bazową nazwę: pierwsze 2 litery imienia + pierwsze 3 litery nazwiska + 'adm'
    $name_part = substr($name_clean, 0, 2);
    $surname_part = substr($surname_clean, 0, 3);
    $base_username = $name_part . $surname_part . 'adm';
    
    // Jeśli za krótkie, dodaj brakujące znaki
    if (strlen($base_username) < 6) {
        $base_username = $base_username . str_repeat('x', 6 - strlen($base_username));
    }
    
    // Ogranicz do maksymalnie 8 znaków (zostawi miejsce na licznik)
    $base_username = substr($base_username, 0, 8);
    
    return findUniqueUsername($base_username, $conn);
}

// ✅ ALTERNATYWNA, prosta funkcja generowania nazwy administratora
function generateAdminUsernameSimple($name, $surname, $conn) {
    $name_clean = normalizePolishChars($name);
    $surname_clean = normalizePolishChars($surname);
    
    $name_letter = substr(preg_replace('/[^a-z]/', '', $name_clean), 0, 1);
    $surname_letter = substr(preg_replace('/[^a-z]/', '', $surname_clean), 0, 1);
    
    // Jeśli nie ma liter, użyj 'x'
    if (empty($name_letter)) $name_letter = 'x';
    if (empty($surname_letter)) $surname_letter = 'x';
    
    $base_username = 'adm' . $name_letter . $surname_letter; // np. "admjk"
    
    return findUniqueUsername($base_username, $conn);
}

// ✅ FUNKCJA POMOCNICZA - bezpieczna promocja użytkownika
function promoteUserToAdmin($user_id, $conn) {
    if ($user_id <= 0) {
        return ['success' => false, 'message' => 'Nieprawidłowy ID użytkownika.'];
    }
    
    // Pobierz dane użytkownika
    $user_stmt = $conn->prepare("SELECT id, name, surname, pesel, is_admin, admin_username FROM users WHERE id = ?");
    if (!$user_stmt) {
        return ['success' => false, 'message' => 'Błąd bazy danych: ' . $conn->error];
    }
    
    $user_stmt->bind_param("i", $user_id);
    $user_stmt->execute();
    $user_result = $user_stmt->get_result();
    
    if ($user_result->num_rows === 0) {
        $user_stmt->close();
        return ['success' => false, 'message' => 'Użytkownik nie istnieje.'];
    }
    
    $user_data = $user_result->fetch_assoc();
    $user_stmt->close();
    
    if ($user_data['is_admin'] == 1) {
        return ['success' => false, 'message' => 'Użytkownik już jest administratorem.'];
    }
    
    // Wygeneruj unikalną nazwę administratora
    $admin_username = generateAdminUsername($user_data['name'], $user_data['surname'], $conn);
    
    if (empty($admin_username)) {
        error_log("Failed to generate admin username for user ID: $user_id");
        return ['success' => false, 'message' => 'Błąd podczas generowania nazwy administratora.'];
    }
    
    // Rozpocznij transakcję
    $conn->begin_transaction();
    
    try {
        // Aktualizuj użytkownika
        $update_stmt = $conn->prepare("UPDATE users SET admin_username = ?, is_admin = 1 WHERE id = ?");
        if (!$update_stmt) {
            throw new Exception("Błąd przygotowania zapytania: " . $conn->error);
        }
        
        $update_stmt->bind_param("si", $admin_username, $user_id);
        
        if (!$update_stmt->execute() || $update_stmt->affected_rows === 0) {
            throw new Exception("Błąd wykonania zapytania lub brak zmian");
        }
        
        $update_stmt->close();
        $conn->commit();
        
        $success_message = "Użytkownik został pomyślnie awansowany na administratora!<br>";
        $success_message .= "<strong>Nazwa administratora:</strong> " . htmlspecialchars($admin_username) . "<br>";
        $success_message .= "<strong>Informacja:</strong> PESEL (" . htmlspecialchars($user_data['pesel']) . ") pozostaje bez zmian dla dostępu do wyborów.<br>";
        $success_message .= "<strong>Logowanie do panelu admina:</strong> Użyj nazwy administratora i hasła.";
        
        error_log("SUCCESS: User ID $user_id promoted to admin. PESEL: {$user_data['pesel']}, Admin username: $admin_username");
        
        return ['success' => true, 'message' => $success_message];
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("ERROR promoting user ID $user_id: " . $e->getMessage());
        return ['success' => false, 'message' => 'Błąd podczas awansowania użytkownika: ' . $e->getMessage()];
    }
}

// ✅ FUNKCJA POMOCNICZA - bezpieczna degradacja administratora
function demoteAdminToUser($user_id, $current_user_id, $conn) {
    if ($user_id <= 0) {
        return ['success' => false, 'message' => 'Nieprawidłowy ID użytkownika.'];
    }
    
    if ($user_id == $current_user_id) {
        return ['success' => false, 'message' => 'Nie możesz zdegradować samego siebie.'];
    }
    
    // Sprawdź czy użytkownik jest administratorem
    $user_stmt = $conn->prepare("SELECT id, name, surname, is_admin FROM users WHERE id = ? AND is_admin = 1");
    if (!$user_stmt) {
        return ['success' => false, 'message' => 'Błąd bazy danych: ' . $conn->error];
    }
    
    $user_stmt->bind_param("i", $user_id);
    $user_stmt->execute();
    $user_result = $user_stmt->get_result();
    
    if ($user_result->num_rows === 0) {
        $user_stmt->close();
        return ['success' => false, 'message' => 'Użytkownik nie jest administratorem lub nie istnieje.'];
    }
    
    $user_data = $user_result->fetch_assoc();
    $user_stmt->close();
    
    // Rozpocznij transakcję
    $conn->begin_transaction();
    
    try {
        // Degraduj administratora - ustaw is_admin na 0 i wyczyść admin_username
        $update_stmt = $conn->prepare("UPDATE users SET is_admin = 0, admin_username = NULL WHERE id = ?");
        if (!$update_stmt) {
            throw new Exception("Błąd przygotowania zapytania: " . $conn->error);
        }
        
        $update_stmt->bind_param("i", $user_id);
        
        if (!$update_stmt->execute()) {
            throw new Exception("Błąd wykonania zapytania: " . $conn->error);
        }
        
        $update_stmt->close();
        $conn->commit();
        
        error_log("SUCCESS: Admin ID $user_id demoted to user");
        
        return ['success' => true, 'message' => 'Administrator został zdegradowany do zwykłego użytkownika. Nazwa administratora została usunięta.'];
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("ERROR demoting admin ID $user_id: " . $e->getMessage());
        return ['success' => false, 'message' => 'Błąd podczas degradacji administratora: ' . $e->getMessage()];
    }
}

// ✅ OBSŁUGA PROMOCJI UŻYTKOWNIKA
if (isset($_POST['promote_user'])) {
    $user_id = (int)$_POST['user_id'];
    $result = promoteUserToAdmin($user_id, $conn);
    
    if ($result['success']) {
        $success = $result['message'];
    } else {
        $error = $result['message'];
    }
}

// ✅ OBSŁUGA DEGRADACJI ADMINISTRATORA
if (isset($_POST['demote_admin'])) {
    $user_id = (int)$_POST['user_id'];
    $result = demoteAdminToUser($user_id, $_SESSION['user_id'], $conn);
    
    if ($result['success']) {
        $success = $result['message'];
    } else {
        $error = $result['message'];
    }
}

// ✅ TESTOWANIE GENEROWANIA NAZW ADMINISTRATORA
if (isset($_POST['test_username_generation']) && isset($_POST['test_name']) && isset($_POST['test_surname'])) {
    echo "<div style='background:#e7f3ff; padding:15px; margin:20px 0; border:1px solid #b3d9ff; border-radius:5px;'>";
    echo "<h4>Test generowania nazwy administratora:</h4>";
    
    $test_name = trim($_POST['test_name']);
    $test_surname = trim($_POST['test_surname']);
    
    if (!empty($test_name) && !empty($test_surname)) {
        $test_username = generateAdminUsername($test_name, $test_surname, $conn);
        echo "<strong>Imię:</strong> " . htmlspecialchars($test_name) . "<br>";
        echo "<strong>Nazwisko:</strong> " . htmlspecialchars($test_surname) . "<br>";
        echo "<strong>Wygenerowana nazwa:</strong> " . htmlspecialchars($test_username) . "<br>";
        
        if (isAdminUsernameUnique($test_username, $conn)) {
            echo "<strong>Status:</strong> <span style='color:green;'>✅ Nazwa jest unikalna</span>";
        } else {
            echo "<strong>Status:</strong> <span style='color:red;'>❌ Nazwa już istnieje</span>";
        }
    } else {
        echo "<span style='color:red;'>❌ Wprowadź imię i nazwisko</span>";
    }
    echo "</div>";
}

// ✅ USUWANIE UŻYTKOWNIKA
if (isset($_POST['delete_user'])) {
    $user_id = (int)$_POST['user_id'];
    
    if ($user_id <= 0) {
        $error = "Nieprawidłowy ID użytkownika.";
    } elseif ($user_id == $_SESSION['user_id']) {
        $error = "Nie możesz usunąć samego siebie.";
    } else {
        // Rozpocznij transakcję
        $conn->begin_transaction();
        
        try {
            // Usuń tokeny głosowania użytkownika
            $delete_tokens_stmt = $conn->prepare("DELETE FROM vote_tokens WHERE user_id = ?");
            $delete_tokens_stmt->bind_param("i", $user_id);
            $delete_tokens_stmt->execute();
            $delete_tokens_stmt->close();
            
            // Usuń użytkownika
            $delete_user_stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $delete_user_stmt->bind_param("i", $user_id);
            
            if ($delete_user_stmt->execute()) {
                $conn->commit();
                $success = "Użytkownik został pomyślnie usunięty.";
            } else {
                throw new Exception("Błąd podczas usuwania użytkownika: " . $conn->error);
            }
            $delete_user_stmt->close();
            
        } catch (Exception $e) {
            $conn->rollback();
            $error = $e->getMessage();
        }
    }
}

// ✅ DODAWANIE NOWYCH WYBORÓW
if (isset($_POST['create_election'])) {
    $name = trim($_POST['election_name']);
    $start = $_POST['start_time'];
    $end = $_POST['end_time'];

    if (empty($name) || empty($start) || empty($end)) {
        $error = "Wszystkie pola są wymagane.";
    } elseif (strtotime($start) >= strtotime($end)) {
        $error = "Data rozpoczęcia musi być wcześniejsza niż data zakończenia.";
    } else {
        $stmt = $conn->prepare("INSERT INTO elections (name, start_time, end_time) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $start, $end);
        
        if ($stmt->execute()) {
            $success = "Wybory zostały utworzone pomyślnie!";
        } else {
            $error = "Błąd podczas tworzenia wyborów: " . $conn->error;
        }
        $stmt->close();
    }
}

// ✅ DODAWANIE NOWEGO KANDYDATA
if (isset($_POST['add_candidate'])) {
    $election_id = (int)$_POST['election_id'];
    $name = trim($_POST['candidate_name']);
    $description = trim($_POST['candidate_description']);

    if (empty($name) || empty($description) || $election_id <= 0) {
        $error = "Wszystkie pola są wymagane.";
    } else {
        // Sprawdź czy wybory istnieją
        $check_stmt = $conn->prepare("SELECT id FROM elections WHERE id = ?");
        $check_stmt->bind_param("i", $election_id);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        
        if ($check_result->num_rows === 0) {
            $error = "Wybrane wybory nie istnieją.";
        } else {
            $stmt = $conn->prepare("INSERT INTO candidates (name, description, election_id, votes) VALUES (?, ?, ?, 0)");
            $stmt->bind_param("ssi", $name, $description, $election_id);
            
            if ($stmt->execute()) {
                $success = "Kandydat został dodany pomyślnie!";
            } else {
                $error = "Błąd podczas dodawania kandydata: " . $conn->error;
            }
            $stmt->close();
        }
        $check_stmt->close();
    }
}

// ✅ POBIERZ DANE DLA WIDOKU
$elections = $conn->query("SELECT * FROM elections ORDER BY id DESC");
$users = $conn->query("SELECT id, name, surname, pesel, email, is_admin, admin_username FROM users ORDER BY is_admin DESC, id ASC");
?><!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Panel Admina</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .message {
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .debug-info {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 10px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 12px;
        }

        /* Kontener dla tabeli z overflow */
        .table-container {
            width: 100%;
            overflow-x: auto;
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .user-table {
            width: 100%;
            min-width: 800px; /* Minimalna szerokość tabeli */
            border-collapse: collapse;
            margin: 0;
            background-color: white;
        }

        .user-table th, .user-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
            vertical-align: middle;
            word-wrap: break-word;
        }

        /* Ustalenie szerokości kolumn */
        .user-table th:nth-child(1), .user-table td:nth-child(1) { width: 50px; } /* ID */
        .user-table th:nth-child(2), .user-table td:nth-child(2) { width: 100px; } /* Imię */
        .user-table th:nth-child(3), .user-table td:nth-child(3) { width: 100px; } /* Nazwisko */
        .user-table th:nth-child(4), .user-table td:nth-child(4) { width: 120px; } /* PESEL */
        .user-table th:nth-child(5), .user-table td:nth-child(5) { width: 150px; } /* Email */
        .user-table th:nth-child(6), .user-table td:nth-child(6) { width: 80px; } /* Rola */
        .user-table th:nth-child(7), .user-table td:nth-child(7) { width: 140px; } /* Logowanie */
        .user-table th:nth-child(8), .user-table td:nth-child(8) { width: 160px; } /* Akcje */

        .user-table th {
            background-color: #f2f2f2;
            font-weight: bold;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .user-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        .user-table tr:hover {
            background-color: #e9ecef;
            transition: background-color 0.2s ease;
        }

        .admin-badge {
            background-color: #28a745;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }

        .user-badge {
            background-color: #6c757d;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }

        /* Przyciski akcji - lepsze formatowanie */
        .actions-cell {
            white-space: nowrap;
            text-align: center;
        }

        .action-btn {
            padding: 6px 10px;
            margin: 2px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            display: inline-block;
            text-decoration: none;
            transition: all 0.2s ease;
            min-width: 70px;
            text-align: center;
        }

        .promote-btn {
            background-color: #007bff;
            color: white;
        }

        .demote-btn {
            background-color: #ffc107;
            color: black;
        }

        .delete-btn {
            background-color: #dc3545;
            color: white;
        }

        .action-btn:hover {
            opacity: 0.8;
            transform: translateY(-1px);
        }

        .admin-username {
            font-style: italic;
            color: #007bff;
            font-weight: bold;
            display: block;
            margin: 2px 0;
        }

        .login-info {
            font-size: 11px;
            color: #666;
            margin: 2px 0;
            line-height: 1.3;
        }

        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 2px solid #ddd;
        }

        .tab {
            padding: 10px 20px;
            background-color: #f8f9fa;
            cursor: pointer;
            border: none;
            border-bottom: 2px solid transparent;
            margin-right: 5px;
        }

        .tab.active {
            background-color: #007bff;
            color: white;
            border-bottom-color: #007bff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .search-container {
            margin: 20px 0;
            position: relative;
            max-width: 400px;
        }

        .search-input {
            width: 100%;
            padding: 12px 45px 12px 15px;
            border: 2px solid #ddd;
            border-radius: 25px;
            font-size: 16px;
            outline: none;
            transition: border-color 0.3s;
        }

        .search-input:focus {
            border-color: #007bff;
        }

        .search-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #666;
            font-size: 18px;
            pointer-events: none;
        }

        .no-results {
            text-align: center;
            padding: 20px;
            color: #666;
            font-style: italic;
        }

        .results-count {
            margin: 10px 0;
            color: #666;
            font-size: 14px;
        }

        .test-section {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }

        .test-section h4 {
            color: #856404;
            margin-top: 0;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .table-container {
                margin: 10px -15px; /* Rozciągnij na całą szerokość na małych ekranach */
            }
            
            .action-btn {
                padding: 4px 6px;
                font-size: 10px;
                min-width: 60px;
                margin: 1px;
            }
        }
    </style>
    <script>
        function showTab(tabName) {
            // Ukryj wszystkie zakładki
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Pokaż wybraną zakładkę
            document.getElementById(tabName).classList.add('active');
            document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
        }
        
        function confirmAction(action, username) {
            return confirm(`Czy na pewno chcesz ${action} użytkownika "${username}"?`);
        }
        
        function searchUsers() {
            const input = document.getElementById('userSearch');
            const filter = input.value.toLowerCase();
            const table = document.querySelector('.user-table tbody');
            const rows = table.querySelectorAll('tr');
            let visibleCount = 0;
            
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                let found = false;
                
                // Przeszukaj wszystkie komórki w wierszu
                cells.forEach(cell => {
                    if (cell.textContent.toLowerCase().includes(filter)) {
                        found = true;
                    }
                });
                
                if (found || filter === '') {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Aktualizuj licznik rezultatów
            const resultsCount = document.getElementById('resultsCount');
            if (filter === '') {
                resultsCount.textContent = `Wyświetlono wszystkich użytkowników (${visibleCount})`;
            } else {
                resultsCount.textContent = `Znaleziono ${visibleCount} użytkowników dla: "${input.value}"`;
            }
            
            // Pokaż komunikat o braku wyników
            const noResults = document.getElementById('noResults');
            if (visibleCount === 0 && filter !== '') {
                noResults.style.display = 'block';
            } else {
                noResults.style.display = 'none';
            }
        }
        
        // Dodaj event listener po załadowaniu strony
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('userSearch');
            if (searchInput) {
                searchInput.addEventListener('keyup', searchUsers);
                searchInput.addEventListener('search', searchUsers); // Dla przycisku X w Chrome
            }
        });
    </script>
</head>
<body>
<div class="container">
    <h2>Panel Admina</h2>
    <a href="logout.php" class="logout-link">Wyloguj się</a>
    
    <?php if (isset($error)): ?>
        <div class="message error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    
    <?php if (isset($success)): ?>
        <div class="message success"><?= $success ?></div>
    <?php endif; ?>
    
    <!-- Debug informacje (usuń w produkcji) -->
    <div class="debug-info">
        <strong>Debug:</strong><br>
        Session ID: <?= session_id() ?><br>
        CSRF Token w sesji: <?= isset($_SESSION['csrf_token']) ? 'TAK' : 'NIE' ?><br>
        User ID: <?= $_SESSION['user_id'] ?? 'BRAK' ?><br>
        Is Admin: <?= $_SESSION['is_admin'] ? 'TAK' : 'NIE' ?>
    </div>
    
    <!-- Zakładki -->
    <div class="tabs">
        <button class="tab active" onclick="showTab('users')">Zarządzanie Użytkownikami</button>
        <button class="tab" onclick="showTab('elections')">Zarządzanie Wyborami</button>
        <button class="tab" onclick="showTab('candidates')">Zarządzanie Kandydatami</button>
    </div>
    
    <!-- Zakładka Użytkownicy -->
    <div id="users" class="tab-content active">
        <h3>Zarządzanie Użytkownikami</h3>
        <p><strong>Informacja:</strong> Po awansowaniu użytkownika na administratora, otrzyma on dodatkową nazwę administratora do logowania do panelu admina. PESEL pozostanie bez zmian i nadal będzie służyć do logowania do wyborów.</p>
        
        <!-- Wyszukiwarka -->
        <div class="search-container">
            <input type="text" id="userSearch" class="search-input" placeholder="Szukaj użytkowników (imię, nazwisko, PESEL, email)...">
            <span class="search-icon">🔍</span>
        </div>
        
        <div id="resultsCount" class="results-count"></div>
        
        <?php if ($users && $users->num_rows > 0): ?>
            <div class="table-container">
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Imię</th>
                            <th>Nazwisko</th>
                            <th>PESEL</th>
                            <th>Email</th>
                            <th>Rola</th>
                            <th>Logowanie</th>
                            <th>Akcje</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($user = $users->fetch_assoc()): ?>
                            <tr>
                                <td><?= $user['id'] ?></td>
                                <td><?= htmlspecialchars($user['name']) ?></td>
                                <td><?= htmlspecialchars($user['surname']) ?></td>
                                <td><?= htmlspecialchars($user['pesel']) ?></td>
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                <td>
                                    <?php if ($user['is_admin']): ?>
                                        <span class="admin-badge">ADMIN</span>
                                    <?php else: ?>
                                        <span class="user-badge">USER</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['is_admin'] && !empty($user['admin_username'])): ?>
                                        <div class="login-info">
                                            <strong>Panel Admin:</strong><br>
                                            <span class="admin-username"><?= htmlspecialchars($user['admin_username']) ?></span>
                                        </div>
                                        <div class="login-info">
                                            <strong>Wybory:</strong><br>
                                            <?= htmlspecialchars($user['pesel']) ?>
                                        </div>
                                    <?php else: ?>
                                        <div class="login-info">
                                            <strong>Wybory:</strong><br>
                                            <?= htmlspecialchars($user['pesel']) ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td class="actions-cell">
                                    <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                        <?php if (!$user['is_admin']): ?>
                                            <form method="POST" style="display: inline;">
                                                <?= getCSRFInput() ?>
                                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                <button type="submit" name="promote_user" class="action-btn promote-btn" 
                                                        onclick="return confirmAction('awansować na administratora', '<?= htmlspecialchars($user['name'] . ' ' . $user['surname']) ?>')">
                                                    Awansuj
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <form method="POST" style="display: inline;">
                                                <?= getCSRFInput() ?>
                                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                                <button type="submit" name="demote_admin" class="action-btn demote-btn" 
                                                        onclick="return confirmAction('zdegradować z roli administratora', '<?= htmlspecialchars($user['name'] . ' ' . $user['surname']) ?>')">
                                                    Degraduj
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <form method="POST" style="display: inline;">
                                            <?= getCSRFInput() ?>
                                            <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                            <button type="submit" name="delete_user" class="action-btn delete-btn" 
                                                    onclick="return confirmAction('usunąć', '<?= htmlspecialchars($user['name'] . ' ' . $user['surname']) ?>')">
                                                Usuń
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <em>To jesteś Ty</em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
            
            <div id="noResults" class="no-results" style="display: none;">
                <p>Nie znaleziono użytkowników pasujących do wyszukiwanego hasła.</p>
            </div>
            
        <?php else: ?>
            <p>Brak użytkowników w systemie.</p>
        <?php endif; ?>
    </div>
    
    <!-- Zakładka Wybory -->
    <div id="elections" class="tab-content">
        <h3>Dodaj nowe wybory</h3>
        <form method="POST">
            <?= getCSRFInput() ?>
            <label>Nazwa wyborów:</label>
            <input type="text" name="election_name" required maxlength="255">
            <label>Data rozpoczęcia:</label>
            <input type="datetime-local" name="start_time" required>
            <label>Data zakończenia:</label>
            <input type="datetime-local" name="end_time" required>
            <button type="submit" name="create_election">Utwórz wybory</button>
        </form>
        
        <h3>Lista wyborów</h3>
        <?php 
        // Reset result pointer for elections
        $elections = $conn->query("SELECT * FROM elections ORDER BY id DESC");
        if ($elections && $elections->num_rows > 0): 
        ?>
            <?php while ($row = $elections->fetch_assoc()): ?>
                <div class="election-item">
                    <strong><?= htmlspecialchars($row['name']) ?></strong><br>
                    <?= htmlspecialchars($row['start_time']) ?> - <?= htmlspecialchars($row['end_time']) ?>
                </div>
            <?php endwhile; ?>
        <?php else: ?>
            <p>Brak wyborów w systemie.</p>
        <?php endif; ?>
    </div>
    
    <!-- Zakładka Kandydaci -->
    <div id="candidates" class="tab-content">
        <h3>Dodaj kandydata</h3>
        <form method="POST">
            <?= getCSRFInput() ?>
            <label>Wybory:</label>
            <select name="election_id" required>
                <option value="">-- wybierz wybory --</option>
                <?php
                $res = $conn->query("SELECT * FROM elections ORDER BY id DESC");
                while ($row = $res->fetch_assoc()) {
                    echo "<option value='{$row['id']}'>" . htmlspecialchars($row['name']) . "</option>";
                }
                ?>
            </select>
            <label>Imię i nazwisko kandydata:</label>
            <input type="text" name="candidate_name" required maxlength="255">
            <label>Opis kandydata:</label>
            <textarea name="candidate_description" required maxlength="1000" rows="4"></textarea>
            <button type="submit" name="add_candidate">Dodaj kandydata</button>
        </form>
    </div>
</div>
</body>
</html>