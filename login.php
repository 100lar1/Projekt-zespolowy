<?php
require_once 'core.php';

// Ochrona przed Brute Force
$ip = $_SERVER['REMOTE_ADDR'];
if (!checkLoginAttempts($conn, $ip)) {
    die("Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 15 minut.");
}

checkCSRFOrDie();

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $login_input = trim($_POST["login_input"]);
    $password = $_POST["password"];
    
    if (empty($login_input) || empty($password)) {
        $error = "Dane logowania są wymagane.";
    } else {
        // Sprawdzamy PESEL lub nazwę admina
        $stmt = $conn->prepare("SELECT id, name, surname, pesel, password_hash, is_admin, admin_username FROM users WHERE pesel = ? OR admin_username = ?");
        $stmt->bind_param("ss", $login_input, $login_input);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            if (PasswordSecurity::verifyPassword($password, $user['password_hash'])) {
                // Logowanie udane
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['is_admin'] = $user['is_admin'];
                $_SESSION['admin_username'] = $user['admin_username'];
                $_SESSION['user_name'] = $user['name'];
                
                // Przekierowanie
                if ($user['is_admin']) {
                    header("Location: admin_panel.php");
                } else {
                    header("Location: dashboard.php");
                }
                exit;
            }
        }
        
        // Logowanie nieudane
        logFailedLogin($conn, $ip);
        $error = "Nieprawidłowe dane logowania.";
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Logowanie</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h2>Logowanie</h2>
        <form method="POST">
            <?= getCSRFInput() ?>
            <label>PESEL lub Login Admina:</label>
            <input type="text" name="login_input" required>
            <label>Hasło:</label>
            <input type="password" name="password" required>
            <button type="submit">Zaloguj się</button>
        </form>
        
        <?php if ($error): ?>
            <div class="message error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <p style="text-align:center">
            <a href="register.php">Zarejestruj się</a> | <a href="index.php">Strona główna</a>
        </p>
    </div>
</body>
</html>