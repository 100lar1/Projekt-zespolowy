<?php
session_start();
include 'db.php';
include 'csrf_protection.php'; //

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$now = date("Y-m-d H:i:s");

// ✅ Sprawdzenie CSRF dla POST requestów
checkCSRFOrDie();

// NAPRAWKA 1: Prepared statement dla pobrania aktywnych wyborów
$stmt = $conn->prepare("SELECT * FROM elections WHERE start_time <= ? AND end_time >= ?");
$stmt->bind_param("ss", $now, $now);
$stmt->execute();
$elections = $stmt->get_result();

$message = '';
$error = '';
$vote_link = '';

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $election_id = $_POST['election_id'];
    
    // NAPRAWKA 2: Walidacja danych wejściowych
    if (!is_numeric($election_id)) {
        $error = "Nieprawidłowe ID wyborów.";
    } else {
        $election_id = (int)$election_id;
        
        // NAPRAWKA 3: Sprawdzenie czy wybory są aktywne
        $check_election = $conn->prepare("SELECT id, name FROM elections WHERE id = ? AND start_time <= ? AND end_time >= ?");
        $check_election->bind_param("iss", $election_id, $now, $now);
        $check_election->execute();
        $election_result = $check_election->get_result();
        
        if ($election_result->num_rows === 0) {
            $error = "Wybrane wybory nie są aktywne lub nie istnieją.";
        } else {
            // NAPRAWKA 4: Sprawdzenie czy token już istnieje (prepared statement)
            $check_token = $conn->prepare("SELECT id FROM vote_tokens WHERE user_id = ? AND election_id = ?");
            $check_token->bind_param("ii", $user_id, $election_id);
            $check_token->execute();
            $existing_token = $check_token->get_result();
            
            if ($existing_token->num_rows > 0) {
                $error = "Już wygenerowano token dla tych wyborów.";
            } else {
                // NAPRAWKA 5: Bezpieczne generowanie i zapisywanie tokenu
                $token = bin2hex(random_bytes(32)); // Zwiększony rozmiar tokenu dla bezpieczeństwa
                $expires = date("Y-m-d H:i:s", strtotime("+1 hour"));
                
                $insert_token = $conn->prepare("INSERT INTO vote_tokens (user_id, election_id, token, expires_at, used) VALUES (?, ?, ?, ?, 0)");
                $insert_token->bind_param("iiss", $user_id, $election_id, $token, $expires);
                
                if ($insert_token->execute()) {
                    $message = "Token został wygenerowany pomyślnie!";
                    $vote_link = "vote.php?token=" . urlencode($token);
                } else {
                    $error = "Wystąpił błąd podczas generowania tokenu.";
                    error_log("Token generation error: " . $conn->error);
                }
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
    <title>Panel Głosowania</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<h2>Panel Głosowania</h2>

<div class="links">
    <a href="dashboard.php">Powrót do panelu głównego</a>
    <a href="change_password.php">Zmień hasło</a>
    <a href="logout.php">Wyloguj</a>
</div>

<div class="container">
    <?php if ($error): ?>
        <div class="message error" style="background-color: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
        </div>
    <?php endif; ?>
    
    <?php if ($message): ?>
        <div class="message success" style="background-color: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
        
        <?php if ($vote_link): ?>
            <div class="vote-info" style="margin-top: 20px; padding: 15px; background-color: #e7f3ff; border-radius: 5px;">
                <h4>Twój link do głosowania:</h4>
                <p><a href="<?= $vote_link ?>" style="color: #007bff; font-weight: bold;">Kliknij tutaj, aby głosować</a></p>
                <p style="font-size: 0.9em; color: #666;">Link wygasa za 1 godzinę.</p>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <h3>Wybierz wybory:</h3>
    <form method="POST" class="vote-form">
        <?= getCSRFInput() ?> <!-- ✅ Token CSRF -->
        <select name="election_id" required>
            <option value="">-- wybierz wybory --</option>
            <?php 
            // Reset pointer
            $elections->data_seek(0);
            while ($row = $elections->fetch_assoc()): ?>
                <option value="<?= $row['id'] ?>"><?= htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') ?></option>
            <?php endwhile; ?>
        </select>
        <button type="submit">Generuj token do głosowania</button>
    </form>
</div>

</body>
</html>