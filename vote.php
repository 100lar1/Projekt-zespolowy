<?php
require_once 'core.php';

$token = $_GET['token'] ?? '';
if (!$token) die("Brak tokenu lub błędny link.");

// Sprawdź ważność tokenu
$stmt = $conn->prepare("SELECT vt.id, vt.election_id FROM vote_tokens vt WHERE vt.token = ? AND vt.used = 0 AND vt.expires_at > NOW()");
$stmt->bind_param("s", $token);
$stmt->execute();
$res = $stmt->get_result();

if ($res->num_rows === 0) {
    die("<h3>Link do głosowania jest nieważny, wygasł lub głos został już oddany.</h3><a href='index.php'>Wróć na stronę główną</a>");
}

$tokenData = $res->fetch_assoc();
$electionId = $tokenData['election_id'];
$tokenId = $tokenData['id'];

// Obsługa oddania głosu
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cid = (int)$_POST['candidate_id'];
    
    // Sprawdź czy kandydat należy do tych wyborów
    $check = $conn->prepare("SELECT id FROM candidates WHERE id = ? AND election_id = ?");
    $check->bind_param("ii", $cid, $electionId);
    $check->execute();
    
    if ($check->get_result()->num_rows === 0) {
        die("Nieprawidłowy kandydat.");
    }
    
    // Transakcja: Zapisz głos + Oznacz token jako zużyty
    $conn->begin_transaction();
    try {
        $conn->query("UPDATE candidates SET votes = votes + 1 WHERE id = $cid");
        $conn->query("UPDATE vote_tokens SET used = 1 WHERE id = $tokenId");
        $conn->commit();
        $message = "Twój głos został oddany pomyślnie! Dziękujemy.";
        $tokenData = null; // Blokuje ponowne wyświetlenie formularza
    } catch (Exception $e) {
        $conn->rollback();
        die("Wystąpił błąd systemu. Proszę spróbować ponownie.");
    }
}

// Pobierz listę kandydatów
$cands = $conn->prepare("SELECT * FROM candidates WHERE election_id = ?");
$cands->bind_param("i", $electionId);
$cands->execute();
$candidates = $cands->get_result();
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Karta do głosowania</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h2>Karta do głosowania</h2>
        <?php if (isset($message)): ?>
            <div class="message success"><?= $message ?></div>
            <a href="index.php">Wróć na stronę główną</a>
        <?php elseif ($tokenData): ?>
            <form method="POST">
                <p>Wybierz kandydata z listy:</p>
                <?php while($c = $candidates->fetch_assoc()): ?>
                    <div style="margin: 10px 0; padding: 10px; border: 1px solid #eee; border-radius: 5px;">
                        <label style="display:block; cursor:pointer;">
                            <input type="radio" name="candidate_id" value="<?= $c['id'] ?>" required>
                            <span style="font-weight:bold; font-size:1.1em;"><?= htmlspecialchars($c['name']) ?></span>
                            <br>
                            <small style="color:#666; margin-left: 25px;"><?= htmlspecialchars($c['description']) ?></small>
                        </label>
                    </div>
                <?php endwhile; ?>
                <button type="submit">ODDAJ GŁOS</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>