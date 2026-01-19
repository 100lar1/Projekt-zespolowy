<?php
require_once 'core.php';
ensureSession();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$view = $_GET['view'] ?? 'main'; // Domyślny widok
$message = '';
$error = '';

// --- OBSŁUGA WYLOGOWANIA ---
if ($view === 'logout') {
    session_destroy();
    header("Location: index.php");
    exit;
}

checkCSRFOrDie(); // Chroni wszystkie formularze POST poniżej

// --- LOGIKA: ZMIANA HASŁA ---
if ($view === 'password' && $_SERVER["REQUEST_METHOD"] === "POST") {
    $current = $_POST['current_password'];
    $new = $_POST['new_password'];
    $confirm = $_POST['confirm_password'];
    
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    
    $val = PasswordSecurity::validatePassword($new);
    
    if (!PasswordSecurity::verifyPassword($current, $user['password_hash'])) {
        $error = "Aktualne hasło jest nieprawidłowe.";
    } elseif ($new !== $confirm) {
        $error = "Hasła nie są identyczne.";
    } elseif (!$val['valid']) {
        $error = "Słabe hasło: " . implode(", ", $val['errors']);
    } else {
        $newHash = PasswordSecurity::hashPassword($new);
        $upd = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $upd->bind_param("si", $newHash, $user_id);
        $upd->execute();
        $message = "Hasło zostało zmienione!";
    }
}

// --- LOGIKA: GENEROWANIE TOKENU (GŁOSOWANIE) ---
$vote_link = '';
if ($view === 'vote' && $_SERVER["REQUEST_METHOD"] === "POST") {
    $election_id = (int)$_POST['election_id'];
    
    // Sprawdź czy wybory aktywne
    $stmt = $conn->prepare("SELECT id FROM elections WHERE id = ? AND start_time <= NOW() AND end_time >= NOW()");
    $stmt->bind_param("i", $election_id);
    $stmt->execute();
    if ($stmt->get_result()->num_rows === 0) {
        $error = "Wybory nieaktywne.";
    } else {
        // Sprawdź czy już ma token
        $stmt = $conn->prepare("SELECT id FROM vote_tokens WHERE user_id = ? AND election_id = ?");
        $stmt->bind_param("ii", $user_id, $election_id);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            $error = "Już masz token do tych wyborów.";
        } else {
            $token = bin2hex(random_bytes(32));
            $expires = date("Y-m-d H:i:s", strtotime("+1 hour"));
            $ins = $conn->prepare("INSERT INTO vote_tokens (user_id, election_id, token, expires_at) VALUES (?, ?, ?, ?)");
            $ins->bind_param("iiss", $user_id, $election_id, $token, $expires);
            if ($ins->execute()) {
                $message = "Token wygenerowany!";
                $vote_link = "vote.php?token=" . $token;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Panel Użytkownika</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .nav-bar { background: #eee; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
        .nav-bar a { margin-right: 15px; text-decoration: none; color: #333; font-weight: bold; }
        .nav-bar a.active { color: #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav-bar">
            <a href="?view=main" class="<?= $view=='main'?'active':'' ?>">Główna</a>
            <a href="?view=vote" class="<?= $view=='vote'?'active':'' ?>">Głosuj</a>
            <a href="?view=candidates" class="<?= $view=='candidates'?'active':'' ?>">Kandydaci</a>
            <a href="?view=password" class="<?= $view=='password'?'active':'' ?>">Hasło</a>
            <?php if ($_SESSION['is_admin']): ?>
                <a href="admin_panel.php" style="color: #d63384">Panel Admina</a>
            <?php endif; ?>
            <a href="?view=logout" style="float:right; color: red;">Wyloguj</a>
        </div>

        <?php if ($message) echo "<div class='message success'>$message</div>"; ?>
        <?php if ($error) echo "<div class='message error'>$error</div>"; ?>

        <!-- WIDOK: GŁÓWNY (WYKRESY) -->
        <?php if ($view === 'main'): ?>
            <h3>Wyniki Wyborów</h3>
            <form method="GET">
                <input type="hidden" name="view" value="main">
                <select name="election_id" onchange="this.form.submit()">
                    <option value="">-- Wybierz wybory --</option>
                    <?php 
                    $res = $conn->query("SELECT * FROM elections");
                    while($r = $res->fetch_assoc()): ?>
                        <option value="<?= $r['id'] ?>" <?= ($_GET['election_id']??0)==$r['id']?'selected':'' ?>>
                            <?= htmlspecialchars($r['name']) ?>
                        </option>
                    <?php endwhile; ?>
                </select>
            </form>
            <?php if (!empty($_GET['election_id'])): ?>
                <canvas id="chart"></canvas>
                <script>
                    fetch(`results_api.php?election_id=<?= (int)$_GET['election_id'] ?>`)
                    .then(r => r.json())
                    .then(d => {
                        new Chart(document.getElementById('chart'), {
                            type: 'bar',
                            data: { labels: d.names, datasets: [{ label: 'Głosy', data: d.votes }] }
                        });
                    });
                </script>
            <?php endif; ?>

        <!-- WIDOK: GŁOSOWANIE -->
        <?php elseif ($view === 'vote'): ?>
            <h3>Generuj Token do Głosowania</h3>
            <?php if ($vote_link): ?>
                <div style="background:#e7f3ff; padding:15px; border-radius:5px;">
                    <a href="<?= $vote_link ?>" style="font-size:1.2em; font-weight:bold;">KLIKNIJ ABY ZAGŁOSOWAĆ</a>
                    <p>Link ważny przez 1h.</p>
                </div>
            <?php else: ?>
                <form method="POST">
                    <?= getCSRFInput() ?>
                    <select name="election_id" required>
                        <option value="">-- Wybierz aktywne wybory --</option>
                        <?php 
                        $res = $conn->query("SELECT * FROM elections WHERE start_time <= NOW() AND end_time >= NOW()");
                        while($r = $res->fetch_assoc()) echo "<option value='{$r['id']}'>".htmlspecialchars($r['name'])."</option>"; 
                        ?>
                    </select>
                    <button type="submit">Generuj Token</button>
                </form>
            <?php endif; ?>

        <!-- WIDOK: KANDYDACI -->
        <?php elseif ($view === 'candidates'): ?>
            <h3>Lista Kandydatów</h3>
            <form method="GET">
                <input type="hidden" name="view" value="candidates">
                <select name="election_id" onchange="this.form.submit()">
                    <option value="">-- Wybierz wybory --</option>
                    <?php 
                    $res = $conn->query("SELECT * FROM elections");
                    while($r = $res->fetch_assoc()) echo "<option value='{$r['id']}' ".(($_GET['election_id']??0)==$r['id']?'selected':'').">".htmlspecialchars($r['name'])."</option>"; 
                    ?>
                </select>
            </form>
            <?php if (!empty($_GET['election_id'])): 
                $stmt = $conn->prepare("SELECT * FROM candidates WHERE election_id = ?");
                $stmt->bind_param("i", $_GET['election_id']);
                $stmt->execute();
                $res = $stmt->get_result();
                echo "<ul>";
                while($c = $res->fetch_assoc()) {
                    echo "<li><strong>".htmlspecialchars($c['name'])."</strong>: ".htmlspecialchars($c['description'])."</li>";
                }
                echo "</ul>";
            endif; ?>

        <!-- WIDOK: HASŁO -->
        <?php elseif ($view === 'password'): ?>
            <h3>Zmiana Hasła</h3>
            <form method="POST">
                <?= getCSRFInput() ?>
                <label>Obecne hasło:</label><input type="password" name="current_password" required>
                <label>Nowe hasło:</label><input type="password" name="new_password" required>
                <label>Potwierdź nowe:</label><input type="password" name="confirm_password" required>
                <button type="submit">Zmień hasło</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>