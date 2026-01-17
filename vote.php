<?php
include 'db.php';

// Bezpieczne pobranie tokenu z parametru GET
$token = $_GET['token'] ?? '';
$now = date("Y-m-d H:i:s");

// NAPRAWKA 1: Używanie prepared statements zamiast bezpośredniego wstawiania
$stmt = $conn->prepare("SELECT * FROM vote_tokens WHERE token = ? AND used = 0 AND expires_at >= ?");
$stmt->bind_param("ss", $token, $now);
$stmt->execute();
$token_data = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$token_data) {
    die("Token nieważny lub wygasł.");
}

$election_id = $token_data["election_id"];

// NAPRAWKA 2: Prepared statement dla pobrania kandydatów
$stmt = $conn->prepare("SELECT * FROM candidates WHERE election_id = ?");
$stmt->bind_param("i", $election_id);
$stmt->execute();
$candidates = $stmt->get_result();

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $candidate_id = $_POST["candidate_id"];
    
    // NAPRAWKA 3: Walidacja czy candidate_id jest liczbą i należy do wybranych wyborów
    if (!is_numeric($candidate_id)) {
        die("Nieprawidłowy ID kandydata.");
    }
    
    $candidate_id = (int)$candidate_id;
    
    // Sprawdzenie czy kandydat należy do tych wyborów
    $verify_stmt = $conn->prepare("SELECT id FROM candidates WHERE id = ? AND election_id = ?");
    $verify_stmt->bind_param("ii", $candidate_id, $election_id);
    $verify_stmt->execute();
    $verify_result = $verify_stmt->get_result();
    
    if ($verify_result->num_rows === 0) {
        die("Kandydat nie należy do tych wyborów.");
    }
    $verify_stmt->close();
    
    // NAPRAWKA 4: Bezpieczne aktualizowanie głosów i tokenów
    $conn->begin_transaction();
    
    try {
        // Aktualizacja głosów kandydata
        $update_votes = $conn->prepare("UPDATE candidates SET votes = votes + 1 WHERE id = ?");
        $update_votes->bind_param("i", $candidate_id);
        $update_votes->execute();
        
        // Oznaczenie tokenu jako użytego
        $update_token = $conn->prepare("UPDATE vote_tokens SET used = 1 WHERE id = ?");
        $update_token->bind_param("i", $token_data["id"]);
        $update_token->execute();
        
        $conn->commit();
        $message = "Głos został oddany pomyślnie!";
        
    } catch (Exception $e) {
        $conn->rollback();
        error_log("Voting error: " . $e->getMessage());
        die("Wystąpił błąd podczas głosowania. Spróbuj ponownie.");
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Głosowanie</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

<h2>Głosowanie</h2>

<div class="container">
    <?php if (isset($message)): ?>
        <div class="message">
            <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
        </div>
        <a href="dashboard.php" class="back-button">Powrót do panelu</a>
    <?php else: ?>
        <h3>Wybierz kandydata:</h3>
        <form method="POST" class="vote-form">
            <?php 
            // Reset pointer do początku wyniku
            $candidates->data_seek(0);
            while ($c = $candidates->fetch_assoc()): ?>
                <div>
                    <input type="radio" id="candidate_<?= $c['id'] ?>" name="candidate_id" value="<?= $c['id'] ?>" required>
                    <label for="candidate_<?= $c['id'] ?>"><?= htmlspecialchars($c['name'], ENT_QUOTES, 'UTF-8') ?></label>
                </div>
            <?php endwhile; ?>
            <button type="submit">Oddaj głos</button>
        </form>
    <?php endif; ?>
</div>

</body>
</html>