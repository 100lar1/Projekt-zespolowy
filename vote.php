<?php
require_once 'core.php';
ensureSession();

$token = $_GET['token'] ?? '';
$error = '';
$voted = false;

if (empty($token)) {
    die("Brak tokenu głosowania. <a href='index.php'>Powrót</a>");
}

// Sprawdź ważność tokenu
$stmt = $conn->prepare("SELECT vt.*, e.name as election_name FROM vote_tokens vt 
                        JOIN elections e ON vt.election_id = e.id 
                        WHERE vt.token = ? AND vt.used = 0 AND vt.expires_at > NOW()");
$stmt->bind_param("s", $token);
$stmt->execute();
$tok = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$tok) {
    die("Token nieważny, wygasł lub został już użyty. <a href='index.php'>Powrót</a>");
}

// Obsługa głosowania
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCSRFOrDie();
    
    $candidate_id = (int)($_POST['candidate_id'] ?? 0);
    
    if ($candidate_id == 0) {
        $error = "Musisz wybrać kandydata.";
    } else {
        // Sprawdź czy kandydat należy do tych wyborów
        $stmt = $conn->prepare("SELECT id FROM candidates WHERE id = ? AND election_id = ?");
        $stmt->bind_param("ii", $candidate_id, $tok['election_id']);
        $stmt->execute();
        
        if ($stmt->get_result()->num_rows === 0) {
            $error = "Nieprawidłowy kandydat.";
        } else {
            // Rozpocznij transakcję
            $conn->begin_transaction();
            
            try {
                // Dodaj głos
                $update_stmt = $conn->prepare("UPDATE candidates SET votes = votes + 1 WHERE id = ?");
                $update_stmt->bind_param("i", $candidate_id);
                $update_stmt->execute();
                $update_stmt->close();
                
                // Oznacz token jako użyty
                $token_stmt = $conn->prepare("UPDATE vote_tokens SET used = 1 WHERE id = ?");
                $token_stmt->bind_param("i", $tok['id']);
                $token_stmt->execute();
                $token_stmt->close();
                
                // Zatwierdź transakcję
                $conn->commit();
                $voted = true;
                
            } catch (Exception $e) {
                $conn->rollback();
                error_log("Voting error: " . $e->getMessage());
                $error = "Błąd podczas oddawania głosu. Spróbuj ponownie.";
            }
        }
        $stmt->close();
    }
}

// Pobierz kandydatów
if (!$voted) {
    $cands = $conn->prepare("SELECT * FROM candidates WHERE election_id = ? ORDER BY name ASC");
    $cands->bind_param("i", $tok['election_id']);
    $cands->execute();
    $candidates = $cands->get_result();
    $cands->close();
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Głosowanie - Portal Wyborczy</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .candidate-option {
            padding: 15px;
            margin: 10px 0;
            border: 2px solid #ddd;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .candidate-option:hover {
            border-color: #007bff;
            background: #f0f8ff;
        }
        .candidate-option input[type="radio"] {
            margin-right: 10px;
        }
        .success-box {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <?php if ($voted): ?>
            <div class="success-box">
                <h2>✓ Głos oddany pomyślnie!</h2>
                <p>Dziękujemy za udział w głosowaniu.</p>
                <p><a href="index.php" style="font-weight: bold;">Powrót do strony głównej</a></p>
            </div>
        <?php else: ?>
            <h2>Głosowanie: <?= htmlspecialchars($tok['election_name'], ENT_QUOTES, 'UTF-8') ?></h2>
            
            <?php if ($error): ?>
                <div class="message error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
            <?php endif; ?>
            
            <p><strong>Wybierz kandydata:</strong></p>
            
            <form method="POST">
                <?= getCSRFInput() ?>
                
                <?php if ($candidates->num_rows > 0): ?>
                    <?php while($c = $candidates->fetch_assoc()): ?>
                        <label class="candidate-option">
                            <input type="radio" name="candidate_id" value="<?= $c['id'] ?>" required>
                            <strong><?= htmlspecialchars($c['name'], ENT_QUOTES, 'UTF-8') ?></strong>
                            <?php if (!empty($c['description'])): ?>
                                <br>
                                <small><?= htmlspecialchars($c['description'], ENT_QUOTES, 'UTF-8') ?></small>
                            <?php endif; ?>
                        </label>
                    <?php endwhile; ?>
                    
                    <button type="submit" style="margin-top: 20px; width: 100%; padding: 15px; font-size: 1.1em;">
                        Oddaj Głos
                    </button>
                <?php else: ?>
                    <p>Brak kandydatów w tych wyborach.</p>
                <?php endif; ?>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>