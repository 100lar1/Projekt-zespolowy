<?php
// ✅ NAJPIERW session_start() - zanim jakiekolwiek output
session_start();

// ✅ POTEM nagłówki bezpieczeństwa
include 'security_headers.php';
setAuthPageHeaders();

// ✅ POTEM includy
include 'db.php';
include 'csrf_protection.php';
include 'password_security.php';

function isValidPESEL($pesel) {
    if (!preg_match('/^[0-9]{11}$/', $pesel)) {
        return false;
    }
    $weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    $sum = 0;
    for ($i = 0; $i < 10; $i++) {
        $sum += $weights[$i] * intval($pesel[$i]);
    }
    $checkDigit = (10 - ($sum % 10)) % 10;

    return $checkDigit == intval($pesel[10]);
}

$errors = [];
$success = '';

// Sprawdzenie CSRF dla POST requestów
checkCSRFOrDie();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST["name"]);
    $surname = trim($_POST["surname"]);
    $pesel = trim($_POST["pesel"]);
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    $confirm_password = $_POST["confirm_password"];   
    
    // Walidacja podstawowych danych
    if (empty($name)) {
        $errors[] = "Imię jest wymagane";
    }  
    
    if (empty($surname)) {
        $errors[] = "Nazwisko jest wymagane";
    }
    
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Prawidłowy adres email jest wymagany";
    }
    
    // Walidacja PESEL
    if (!isValidPESEL($pesel)) {
        $errors[] = "Nieprawidłowy numer PESEL";
    }
    
    // ✅ WALIDACJA SIŁY HASŁA
    $passwordValidation = PasswordSecurity::validatePassword($password);
    if (!$passwordValidation['valid']) {
        $errors = array_merge($errors, $passwordValidation['errors']);
    }
    
    // Sprawdzenie potwierdzenia hasła
    if ($password !== $confirm_password) {
        $errors[] = "Hasła nie są identyczne";
    }
    
    // Sprawdzenie czy użytkownik już istnieje
    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE pesel = ? OR email = ?");
        $stmt->bind_param("ss", $pesel, $email);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows > 0) {
            $errors[] = "Użytkownik z tym PESEL lub adresem email już istnieje";
        }
        $stmt->close();
    }
    
    // Jeśli brak błędów, wykonaj rejestrację
    if (empty($errors)) {
        // ✅ Bezpieczne hashowanie hasła
        $hash = PasswordSecurity::hashPassword($password);
        
        $stmt = $conn->prepare("INSERT INTO users (name, surname, pesel, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, 0)");
        $stmt->bind_param("sssss", $name, $surname, $pesel, $email, $hash);

        if ($stmt->execute()) {
            $success = "Rejestracja zakończona sukcesem! Możesz się teraz zalogować.";
            // Wyczyść zmienne po udanej rejestracji
            $name = $surname = $pesel = $email = '';
        } else {
            $errors[] = "Wystąpił błąd podczas rejestracji. Spróbuj ponownie.";
            error_log("Registration error: " . $stmt->error);
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rejestracja</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        <?= PasswordSecurity::getPasswordStrengthCSS() ?>       
        .form-container {
            max-width: 500px;
            margin: 0 auto;
            padding: 20px;
        }       
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }        
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }        
        .error-list {
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }      
        .success-message {
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }       
        .password-requirements {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        #submitBtn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
    </style>
</head>
<body>

<div class="form-container">
    <h2>Rejestracja w Portalu Wyborczym</h2>
    
    <?php if (!empty($errors)): ?>
        <div class="error-list">
            <h4>Wystąpiły następujące błędy:</h4>
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>
    
    <?php if ($success): ?>
        <div class="success-message">
            <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>
        </div>
        <p><a href="login.php">← Przejdź do logowania</a></p>
    <?php else: ?>
    
    <form method="POST" id="registrationForm">
        <?= getCSRFInput() ?>
        
        <div class="form-group">
            <label for="name">Imię:</label>
            <input type="text" id="name" name="name" value="<?= htmlspecialchars($name ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>
        
        <div class="form-group">
            <label for="surname">Nazwisko:</label>
            <input type="text" id="surname" name="surname" value="<?= htmlspecialchars($surname ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>
        
        <div class="form-group">
            <label for="pesel">PESEL:</label>
            <input type="text" id="pesel" name="pesel" value="<?= htmlspecialchars($pesel ?? '', ENT_QUOTES, 'UTF-8') ?>" pattern="[0-9]{11}" maxlength="11" required>
            <div class="password-requirements">11 cyfr numeru PESEL</div>
        </div>
        
        <div class="form-group">
            <label for="email">Adres email:</label>
            <input type="email" id="email" name="email" value="<?= htmlspecialchars($email ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
        </div>
        
        <div class="form-group">
            <label for="password">Hasło:</label>
            <input type="password" id="password" name="password" required>
            <div class="password-requirements">
                Wymagania: min. 8 znaków, wielka i mała litera, cyfra, znak specjalny
            </div>
            <div id="password-strength"></div>
        </div>
        
        <div class="form-group">
            <label for="confirm_password">Potwierdź hasło:</label>
            <input type="password" id="confirm_password" name="confirm_password" required>
            <div id="password-match"></div>
        </div>
        
        <button type="submit" id="submitBtn" disabled>Zarejestruj się</button>
    </form>
    
    <?php endif; ?>
    
    <p style="text-align: center; margin-top: 20px;">
        Masz już konto? <a href="login.php">Zaloguj się</a>
    </p>
</div>

<script>
<?= PasswordSecurity::getClientSideValidationJS() ?>

document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const submitBtn = document.getElementById('submitBtn');
    const passwordMatchDiv = document.getElementById('password-match');
    
    let passwordValid = false;
    let passwordsMatch = false;
    
    function updateSubmitButton() {
        submitBtn.disabled = !(passwordValid && passwordsMatch);
    }
    
    passwordInput.addEventListener('input', function() {
        const result = updatePasswordIndicator(this.value, 'password-strength');
        passwordValid = result.valid;
        updateSubmitButton();
        
        // Sprawdź ponownie zgodność haseł
        if (confirmPasswordInput.value) {
            checkPasswordMatch();
        }
    });
    
    function checkPasswordMatch() {
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        if (confirmPassword === '') {
            passwordMatchDiv.innerHTML = '';
            passwordsMatch = false;
        } else if (password === confirmPassword) {
            passwordMatchDiv.innerHTML = '<div style="color: green;">✓ Hasła są identyczne</div>';
            passwordsMatch = true;
        } else {
            passwordMatchDiv.innerHTML = '<div style="color: red;">✗ Hasła nie są identyczne</div>';
            passwordsMatch = false;
        }
        
        updateSubmitButton();
    }
    
    confirmPasswordInput.addEventListener('input', checkPasswordMatch);
    
    // Walidacja PESEL po stronie klienta
    document.getElementById('pesel').addEventListener('input', function() {
        const pesel = this.value;
        if (pesel.length === 11) {
            // Podstawowa walidacja PESEL
            if (!/^[0-9]{11}$/.test(pesel)) {
                this.style.borderColor = 'red';
            } else {
                this.style.borderColor = 'green';
            }
        } else {
            this.style.borderColor = '#ddd';
        }
    });
});
</script>

</body>
</html>