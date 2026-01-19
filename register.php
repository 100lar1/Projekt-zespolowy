<?php
require_once 'core.php';

function isValidPESEL($pesel) {
    if (!preg_match('/^[0-9]{11}$/', $pesel)) return false;
    $weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    $sum = 0;
    for ($i = 0; $i < 10; $i++) $sum += $weights[$i] * intval($pesel[$i]);
    $checkDigit = (10 - ($sum % 10)) % 10;
    return $checkDigit == intval($pesel[10]);
}

$errors = [];
$success = '';

checkCSRFOrDie();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST["name"]);
    $surname = trim($_POST["surname"]);
    $pesel = trim($_POST["pesel"]);
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    $confirm = $_POST["confirm_password"];
    
    if (!isValidPESEL($pesel)) $errors[] = "Nieprawidłowy PESEL";
    if ($password !== $confirm) $errors[] = "Hasła nie są identyczne";
    
    $val = PasswordSecurity::validatePassword($password);
    if (!$val['valid']) $errors = array_merge($errors, $val['errors']);
    
    // Sprawdź duplikaty
    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE pesel = ? OR email = ?");
        $stmt->bind_param("ss", $pesel, $email);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) $errors[] = "Użytkownik już istnieje.";
    }
    
    if (empty($errors)) {
        $hash = PasswordSecurity::hashPassword($password);
        $stmt = $conn->prepare("INSERT INTO users (name, surname, pesel, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, 0)");
        $stmt->bind_param("sssss", $name, $surname, $pesel, $email, $hash);
        
        if ($stmt->execute()) {
            $success = "Konto utworzone! <a href='login.php'>Zaloguj się</a>";
        } else {
            $errors[] = "Błąd bazy danych.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Rejestracja</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h2>Rejestracja</h2>
        <?php if ($errors): ?>
            <div class="message error">
                <ul><?php foreach($errors as $e) echo "<li>$e</li>"; ?></ul>
            </div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="message success"><?= $success ?></div>
        <?php else: ?>
            <form method="POST">
                <?= getCSRFInput() ?>
                <label>Imię:</label><input type="text" name="name" required>
                <label>Nazwisko:</label><input type="text" name="surname" required>
                <label>PESEL:</label><input type="text" name="pesel" required maxlength="11">
                <label>Email:</label><input type="email" name="email" required>
                <label>Hasło:</label><input type="password" name="password" required>
                <label>Potwierdź hasło:</label><input type="password" name="confirm_password" required>
                <button type="submit">Zarejestruj się</button>
            </form>
        <?php endif; ?>
        <p><a href="login.php">Powrót do logowania</a></p>
    </div>
</body>
</html>