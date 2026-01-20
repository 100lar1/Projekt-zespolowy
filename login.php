<?php
require_once 'core.php';

// Ensure session is active
ensureSession();

// If user is already logged in, redirect them immediately
if (isLoggedIn()) {
    if (isAdmin()) {
        redirectTo('admin_panel.php');
    } else {
        redirectTo('dashboard.php');
    }
}

// Brute Force Protection
$ip = $_SERVER['REMOTE_ADDR'];
if (!checkLoginAttempts($conn, $ip)) {
    die("Too many failed login attempts. Please try again in 15 minutes.");
}

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verify CSRF token
    checkCSRFOrDie();
    
    $login_input = trim($_POST["login_input"] ?? '');
    $password = $_POST["password"] ?? '';
    
    if (empty($login_input) || empty($password)) {
        $error = "Login and password are required.";
    } else {
        // Query looking for PESEL OR admin_username
        $stmt = $conn->prepare("SELECT id, name, surname, pesel, password_hash, is_admin, admin_username FROM users WHERE pesel = ? OR admin_username = ?");
        
        if (!$stmt) {
            error_log("SQL prepare error: " . $conn->error);
            $error = "System error. Please try again later.";
        } else {
            // Bind the same input twice (once for pesel, once for username)
            $stmt->bind_param("ss", $login_input, $login_input);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();
                
                // Verify Password
                if (PasswordSecurity::verifyPassword($password, $user['password_hash'])) {
                    // Regenerate session ID to prevent Session Fixation
                    session_regenerate_id(true);
                    
                    // Set Session Data
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['is_admin'] = (int)$user['is_admin'];
                    $_SESSION['admin_username'] = $user['admin_username'];
                    $_SESSION['user_name'] = $user['name'];
                    $_SESSION['user_surname'] = $user['surname'];
                    $_SESSION['logged_in_at'] = time();
                    
                    // Redirect
                    if ($user['is_admin']) {
                        redirectTo('admin_panel.php');
                    } else {
                        redirectTo('dashboard.php');
                    }
                } else {
                    // Wrong password
                    logFailedLogin($conn, $ip);
                    $error = "Invalid login credentials.";
                }
            } else {
                // User not found
                logFailedLogin($conn, $ip);
                $error = "Invalid login credentials.";
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
    <title>Logowanie - Portal Wyborczy</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h2>Logowanie</h2>
        
        <?php if ($error): ?>
            <div class="message error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
        
        <form method="POST" action="login.php">
            <?= getCSRFInput() ?>
            
            <label for="login_input">PESEL lub Login Admina:</label>
            <input type="text" id="login_input" name="login_input" required autocomplete="username">
            
            <label for="password">Hasło:</label>
            <input type="password" id="password" name="password" required autocomplete="current-password">
            
            <button type="submit">Zaloguj się</button>
        </form>
        
        <p style="text-align:center; margin-top: 20px;">
            <a href="register.php">Rejestracja</a> | <a href="index.php">Strona główna</a>
        </p>
    </div>
</body>
</html>