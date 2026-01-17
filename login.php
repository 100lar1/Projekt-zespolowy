<?php
// ✅ ZUNIFIKOWANY SYSTEM LOGOWANIA
// Obsługuje logowanie do wyborów i panelu admina w jednym miejscu

// ✅ NAJPIERW session_start()
session_start();

// ✅ POTEM nagłówki bezpieczeństwa  
include 'security_headers.php';
setAuthPageHeaders();

// ✅ POTEM includy
include 'db.php';
include 'csrf_protection.php';

// ✅ Sprawdzenie CSRF dla POST requestów
checkCSRFOrDie();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $login_input = trim($_POST["login_input"]);
    $password = $_POST["password"];
    
    error_log("Próba logowania: $login_input");
    
    if (empty($login_input) || empty($password)) {
        $error = "Dane logowania są wymagane.";
    } else {
        // ✅ UNIWERSALNE ZAPYTANIE - sprawdza zarówno PESEL jak i admin_username
        $stmt = $conn->prepare("SELECT id, name, surname, pesel, password_hash, is_admin, admin_username FROM users WHERE pesel = ? OR admin_username = ?");
        
        if (!$stmt) {
            $error = "Błąd bazy danych: " . $conn->error;
            error_log("Database error: " . $conn->error);
        } else {
            $stmt->bind_param("ss", $login_input, $login_input);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();
                error_log("Znaleziony użytkownik: ID=" . $user['id'] . ", Admin=" . ($user['is_admin'] ? 'TAK' : 'NIE'));
                
                // Sprawdź hasło
                if (password_verify($password, $user['password_hash'])) {
                    error_log("Hasło poprawne dla użytkownika ID: " . $user['id']);
                    
                    // ✅ USTAW PODSTAWOWE DANE SESJI
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_name'] = $user['name'];
                    $_SESSION['user_surname'] = $user['surname'];
                    $_SESSION['user_pesel'] = $user['pesel'];
                    $_SESSION['logged_in_for_voting'] = true;
                    
                    // ✅ SPRAWDŹ CZY TO ADMIN I USTAW UPRAWNIENIA
                    if ($user['is_admin']) {
                        $_SESSION['is_admin'] = true;
                        $_SESSION['admin_username'] = $user['admin_username'];
                        error_log("Zalogowany jako admin: " . $user['admin_username']);
                    }
                    
                    // Zapisz informacje o typie logowania dla debugowania
                    if ($login_input === $user['pesel']) {
                        error_log("Użytkownik ID=" . $user['id'] . " zalogowany przez PESEL");
                    } elseif ($login_input === $user['admin_username']) {
                        error_log("Admin ID=" . $user['id'] . " zalogowany przez admin_username");
                    }
                    
                    // ✅ PRZEKIERUJ DO ODPOWIEDNIEJ STRONY
                    if (file_exists('dashboard.php')) {
                        header("Location: dashboard.php");
                    } elseif (file_exists('elections.php')) {
                        header("Location: elections.php");
                    } elseif (file_exists('index.php')) {
                        header("Location: index.php");
                    } else {
                        // Jeśli żaden plik nie istnieje, pokaż komunikat sukcesu
                        $success_message = "Logowanie pomyślne! Użytkownik: " . htmlspecialchars($user['name'] . ' ' . $user['surname']);
                        if ($user['is_admin']) {
                            $success_message .= " (Administrator)";
                        }
                    }
                    
                    if (!isset($success_message)) {
                        exit;
                    }
                } else {
                    $error = "Nieprawidłowe dane logowania.";
                    error_log("Błędne hasło dla: " . $login_input);
                }
            } else {
                $error = "Nieprawidłowe dane logowania.";
                error_log("Nie znaleziono użytkownika: " . $login_input);
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logowanie - System Wyborczy</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .container {
            max-width: 450px;
            margin: 50px auto;
            padding: 30px;
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        .login-info {
            background-color: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-size: 14px;
        }
        
        .login-info h4 {
            margin-top: 0;
            color: #0066cc;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            border-color: #007bff;
            outline: none;
            box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
        }
        
        .login-btn {
            width: 100%;
            background-color: #007bff;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .login-btn:hover {
            background-color: #0056b3;
        }
        
        .error-message {
            color: #dc3545;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 6px;
            padding: 12px;
            margin: 15px 0;
        }
        
        .success-message {
            color: #155724;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 6px;
            padding: 12px;
            margin: 15px 0;
            text-align: center;
        }
        
        .success-message ul {
            list-style: none;
            padding: 0;
        }
        
        .success-message li {
            margin: 5px 0;
        }
        
        .success-message a {
            color: #007bff;
            text-decoration: none;
            font-weight: bold;
        }
        
        .success-message a:hover {
            text-decoration: underline;
        }
        
        .register-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .register-link a {
            color: #28a745;
            text-decoration: none;
            font-weight: bold;
        }
        
        .register-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>System Wyborczy - Logowanie</h2>
        
        <!-- Informacje o logowaniu -->
        <div class="login-info active">
            <h4>🔐 Logowanie do Systemu</h4>
            <p><strong>Wszyscy użytkownicy</strong> logują się tym samym formularzem:</p>
            <ul>
                <li><strong>Zwykli użytkownicy:</strong> Logują się swoim numerem PESEL</li>
                <li><strong>Administratorzy:</strong> Mogą logować się numerem PESEL lub nazwą administratora</li>
            </ul>
            <p><em>Po zalogowaniu otrzymasz odpowiedni dostęp do systemu w zależności od swoich uprawnień.</em></p>
        </div>
        
        <form method="POST" id="loginForm">
            <?= getCSRFInput() ?>
            
            <div class="form-group">
                <label for="login_input">PESEL lub Nazwa Administratora:</label>
                <input type="text" 
                       id="login_input"
                       name="login_input" 
                       placeholder="Wprowadź PESEL lub nazwę administratora" 
                       required
                       autocomplete="username"
                       value="<?= isset($_POST['login_input']) ? htmlspecialchars($_POST['login_input']) : '' ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Hasło:</label>
                <input type="password" 
                       id="password"
                       name="password" 
                       placeholder="Wprowadź hasło" 
                       required
                       autocomplete="current-password">
            </div>
            
            <button type="submit" class="login-btn">
                🔐 Zaloguj się do Systemu
            </button>
        </form>

        <?php if (!empty($error)): ?>
            <div class="error-message">
                ❌ <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($success_message)): ?>
            <div class="success-message">
                ✅ <?= $success_message ?>
                <br><br>
                <strong>Dostępne opcje:</strong>
                <ul style="text-align: left; margin-top: 10px;">
                    <li><a href="dashboard.php">Dashboard</a></li>
                    <li><a href="index.php">Strona główna</a></li>
                    <?php if ($_SESSION['is_admin'] ?? false): ?>
                        <li><a href="admin_panel.php">Panel Administratora</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        <?php endif; ?>

        <div class="register-link">
            <p>Nie masz jeszcze konta? 
                <a href="register.php">📝 Zarejestruj się</a>
            </p>
        </div>
    </div>
</body>
</html>