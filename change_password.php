<?php
session_start();
include 'db.php';
include 'csrf_protection.php';
include 'password_security.php'; // ✅ Nowy system bezpieczeństwa haseł
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
    $user_id = $_SESSION['user_id'];
    $success = '';
    $error = '';
    $password_validation = null;
// ✅ Sprawdzenie CSRF dla POST requestów
checkCSRFOrDie();
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $current = $_POST['current_password'];
    $new = $_POST['new_password'];
    $confirm = $_POST['confirm_password'];
    // Sprawdzenie czy nowe hasło i potwierdzenie się zgadzają
    if ($new !== $confirm) {
        $error = "Nowe hasło i jego potwierdzenie nie są identyczne.";
    } else {
        // Walidacja siły nowego hasła
        $password_validation = PasswordSecurity::validatePassword($new);
        if (!$password_validation['valid']) {
            $error = "Nowe hasło nie spełnia wymagań bezpieczeństwa:<br>• " . implode("<br>• ", $password_validation['errors']);
        } else {
            // Sprawdzenie aktualnego hasła
            $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            if (PasswordSecurity::verifyPassword($current, $row['password_hash'])) {
                // Sprawdzenie czy nowe hasło nie jest takie samo jak aktualne
                if (PasswordSecurity::verifyPassword($new, $row['password_hash'])) {
                    $error = "Nowe hasło musi być różne od aktualnego hasła.";
                } else {
                    // Hash nowego hasła używając zaawansowanego algorytmu
                    $new_hashed = PasswordSecurity::hashPassword($new);
                    
                    // ✅ NAPRAWKA: Usuń nieistniejącą kolumnę password_changed_at
                    $update = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                    $update->bind_param("si", $new_hashed, $user_id);
                    if ($update->execute()) {
                        $success = "Hasło zostało pomyślnie zmienione. Siła hasła: " . 
                                 $password_validation['strength'] . " (" . $password_validation['score'] . "/100 punktów).";
                        // Wyloguj użytkownika z innych sesji (opcjonalne)
                        // session_regenerate_id(true);
                        // Log security event
                        error_log("Password changed for user ID: " . $user_id . " at " . date('Y-m-d H:i:s'));
                    } else {
                        $error = "Wystąpił błąd podczas zmiany hasła. Spróbuj ponownie.";
                    }
                }
            } else {
                $error = "Nieprawidłowe aktualne hasło.";
                
                // Log failed attempt
                error_log("Failed password change attempt for user ID: " . $user_id . " at " . date('Y-m-d H:i:s'));
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zmień hasło</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        <?= PasswordSecurity::getPasswordStrengthCSS() ?>
        
        .password-input-group {
            position: relative;
            margin-bottom: 15px;
        }
        .password-toggle {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: #666;
            font-size: 14px;
        }
        .password-toggle:hover {
            color: #333;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .form-group input:focus {
            outline: none;
            border-color: #007bff;
        }
        .password-generator {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        .password-generator button {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 10px;
        }
        .password-generator button:hover {
            background: #138496;
        }
        .security-tips {
            background: #e9ecef;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            font-size: 14px;
        }
        .security-tips h4 {
            margin-top: 0;
            color: #495057;
        }
        .security-tips ul {
            margin-bottom: 0;
        }
    </style>
</head>
<body>
<div class="container">
    <h2>Zmień hasło</h2>
    <form method="POST" id="changePasswordForm">
        <?= getCSRFInput() ?>       
        <div class="form-group">
            <label for="current_password">Aktualne hasło:</label>
            <div class="password-input-group">
                <input type="password" id="current_password" name="current_password" required>
                <button type="button" class="password-toggle" onclick="togglePassword('current_password')">👁</button>
            </div>
        </div>
        <div class="form-group">
            <label for="new_password">Nowe hasło:</label>
            <div class="password-input-group">
                <input type="password" id="new_password" name="new_password" required>
                <button type="button" class="password-toggle" onclick="togglePassword('new_password')">👁</button>
            </div>
            <div id="password-strength-indicator" class="password-strength"></div>
        </div>
        <div class="form-group">
            <label for="confirm_password">Potwierdź nowe hasło:</label>
            <div class="password-input-group">
                <input type="password" id="confirm_password" name="confirm_password" required>
                <button type="button" class="password-toggle" onclick="togglePassword('confirm_password')">👁</button>
            </div>
            <div id="password-match-indicator"></div>
        </div>
        <button type="submit" id="submitBtn" disabled>Zmień hasło</button>
    </form>
    <div class="password-generator">
        <h4>Generator bezpiecznego hasła</h4>
        <input type="text" id="generated-password" readonly style="width: 250px;">
        <button type="button" onclick="generateSecurePassword()">Generuj hasło</button>
        <button type="button" onclick="useGeneratedPassword()">Użyj tego hasła</button>
    </div>
    <div class="security-tips">
        <h4>🔒 Wskazówki bezpieczeństwa</h4>
        <ul>
            <li>Używaj unikalnych haseł dla każdego konta</li>
            <li>Nie udostępniaj swojego hasła nikomu</li>
            <li>Zmieniaj hasło regularnie (co 3-6 miesięcy)</li>
            <li>Używaj menedżera haseł do przechowywania różnych haseł</li>
            <li>Unikaj używania osobistych informacji w haśle</li>
            <li>Włącz uwierzytelnianie dwuskładnikowe gdy to możliwe</li>
        </ul>
    </div>
    <?php if ($success): ?>
        <div class="message success">
            <strong>✅ Sukces!</strong><br>
            <?= $success ?>
        </div>
    <?php elseif ($error): ?>
        <div class="message error">
            <strong>❌ Błąd!</strong><br>
            <?= $error ?>
        </div>
    <?php endif; ?>
    <a href="dashboard.php" class="back-link">← Powrót do panelu</a>
</div>
<script>
    <?= PasswordSecurity::getClientSideValidationJS() ?>
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const submitBtn = document.getElementById('submitBtn');
    const passwordMatchIndicator = document.getElementById('password-match-indicator');
    let passwordValid = false;
    let passwordsMatch = false;

    // Walidacja hasła w czasie rzeczywistym
    newPasswordInput.addEventListener('input', () => {
        const result = updatePasswordIndicator(newPasswordInput.value, 'password-strength-indicator');
        passwordValid = result.valid;
        checkFormValidity();
        checkPasswordMatch();
    });
    // Sprawdzanie zgodności haseł
    confirmPasswordInput.addEventListener('input', checkPasswordMatch);
    function checkPasswordMatch() {
        const newPass = newPasswordInput.value;
        const confirmPass = confirmPasswordInput.value;
        if (confirmPass === '') {
            passwordMatchIndicator.innerHTML = '';
            passwordsMatch = false;
        } else if (newPass === confirmPass) {
            passwordMatchIndicator.innerHTML = '<span style="color: green;">✓ Hasła są identyczne</span>';
            passwordsMatch = true;
        } else {
            passwordMatchIndicator.innerHTML = '<span style="color: red;">✗ Hasła nie są identyczne</span>';
            passwordsMatch = false;
        }
        checkFormValidity();
    }
    function checkFormValidity() {
        submitBtn.disabled = !(passwordValid && passwordsMatch && newPasswordInput.value !== '');
    }
    function togglePassword(fieldId) {
        const field = document.getElementById(fieldId);
        const button = field.nextElementSibling;
        if (field.type === 'password') {
            field.type = 'text';
            button.textContent = '🙈';
        } else {
            field.type = 'password';
            button.textContent = '👁';
        }
    }
    function generateSecurePassword() {
        // Implementacja generatora haseł po stronie klienta
        const length = 16;
        const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        // Zagwarantuj przynajmniej jeden znak z każdej kategorii
        password += getRandomChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); // Wielka litera
        password += getRandomChar('abcdefghijklmnopqrstuvwxyz'); // Mała litera
        password += getRandomChar('0123456789'); // Cyfra
        password += getRandomChar('!@#$%^&*()_+-=[]{}|;:,.<>?'); // Znak specjalny
        // Dopełnij resztę hasła
        for (let i = 4; i < length; i++) {
            password += getRandomChar(charset);
        }
        // Przemieszaj znaki
        password = password.split('').sort(() => Math.random() - 0.5).join('');
        document.getElementById('generated-password').value = password;
    }

    function getRandomChar(charset) {
        return charset.charAt(Math.floor(Math.random() * charset.length));
    }
    function useGeneratedPassword() {
        const generatedPassword = document.getElementById('generated-password').value;
        if (generatedPassword) {
            newPasswordInput.value = generatedPassword;
            confirmPasswordInput.value = generatedPassword;
            
            // Trigger walidację
            newPasswordInput.dispatchEvent(new Event('input'));
            confirmPasswordInput.dispatchEvent(new Event('input'));
        }
    }
    // Zapobieganie wysłaniu formularza gdy hasła nie są prawidłowe
    document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
        if (!passwordValid || !passwordsMatch) {
            e.preventDefault();
            alert('Proszę sprawdzić wymagania dotyczące hasła przed kontynuowaniem.');
        }
    });
    // Czyszczenie formularza po udanej zmianie hasła
    <?php if ($success): ?>
    document.getElementById('changePasswordForm').reset();
    document.getElementById('password-strength-indicator').innerHTML = '';
    document.getElementById('password-match-indicator').innerHTML = '';
    <?php endif; ?>
</script>
</body>
</html>