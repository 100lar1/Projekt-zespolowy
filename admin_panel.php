<?php
require_once 'core.php';

if (!isset($_SESSION['user_id']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit;
}

checkCSRFOrDie();

// Funkcje pomocnicze
function generateAdminUsername($name, $surname, $conn) {
    // Prosta implementacja - w produkcji może być bardziej złożona
    $base = strtolower(substr($name,0,3) . substr($surname,0,3) . rand(10,99));
    return $base; 
}

// Logika Promocji
if (isset($_POST['promote_user'])) {
    $uid = (int)$_POST['user_id'];
    $conn->begin_transaction();
    try {
        // Pobierz dane, wygeneruj nazwę, zaktualizuj
        $stmt = $conn->prepare("SELECT name, surname FROM users WHERE id = ?");
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        $uData = $stmt->get_result()->fetch_assoc();
        
        $admName = generateAdminUsername($uData['name'], $uData['surname'], $conn);
        
        $upd = $conn->prepare("UPDATE users SET is_admin=1, admin_username=? WHERE id=?");
        $upd->bind_param("si", $admName, $uid);
        $upd->execute();
        
        $conn->commit();
        $success = "Awansowano użytkownika. Login admina: $admName";
    } catch (Exception $e) {
        $conn->rollback();
        $error = "Błąd: " . $e->getMessage();
    }
}

// Logika Dodawania Wyborów
if (isset($_POST['create_election'])) {
    $name = $_POST['election_name'];
    $start = $_POST['start_time'];
    $end = $_POST['end_time'];
    
    $stmt = $conn->prepare("INSERT INTO elections (name, start_time, end_time) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $start, $end);
    if($stmt->execute()) $success = "Utworzono wybory.";
    else $error = "Błąd.";
}

// Logika Dodawania Kandydata
if (isset($_POST['add_candidate'])) {
    $eid = (int)$_POST['election_id'];
    $name = $_POST['candidate_name'];
    $desc = $_POST['candidate_description'];
    
    $stmt = $conn->prepare("INSERT INTO candidates (name, description, election_id) VALUES (?, ?, ?)");
    $stmt->bind_param("ssi", $name, $desc, $eid);
    if($stmt->execute()) $success = "Dodano kandydata.";
    else $error = "Błąd.";
}

// Pobieranie danych do widoku
$users = $conn->query("SELECT * FROM users");
$elections = $conn->query("SELECT * FROM elections");

?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Panel Admina</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .section { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; }
        td, th { border: 1px solid #ddd; padding: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Panel Administratora</h2>
        <a href="dashboard.php">Widok Użytkownika</a> | <a href="dashboard.php?view=logout">Wyloguj</a>
        
        <?php if ($success) echo "<div class='message success'>$success</div>"; ?>
        <?php if ($error) echo "<div class='message error'>$error</div>"; ?>

        <div class="section">
            <h3>Dodaj Wybory</h3>
            <form method="POST">
                <?= getCSRFInput() ?>
                <input type="text" name="election_name" placeholder="Nazwa" required>
                <input type="datetime-local" name="start_time" required>
                <input type="datetime-local" name="end_time" required>
                <button type="submit" name="create_election">Utwórz</button>
            </form>
        </div>

        <div class="section">
            <h3>Dodaj Kandydata</h3>
            <form method="POST">
                <?= getCSRFInput() ?>
                <select name="election_id" required>
                    <option value="">Wybierz wybory</option>
                    <?php 
                    $elections->data_seek(0);
                    while($e=$elections->fetch_assoc()) echo "<option value='{$e['id']}'>{$e['name']}</option>"; 
                    ?>
                </select>
                <input type="text" name="candidate_name" placeholder="Imię i Nazwisko" required>
                <textarea name="candidate_description" placeholder="Opis"></textarea>
                <button type="submit" name="add_candidate">Dodaj</button>
            </form>
        </div>

        <div class="section">
            <h3>Użytkownicy</h3>
            <table>
                <tr><th>ID</th><th>Imię</th><th>Nazwisko</th><th>PESEL</th><th>Admin?</th><th>Akcja</th></tr>
                <?php while($u = $users->fetch_assoc()): ?>
                <tr>
                    <td><?= $u['id'] ?></td>
                    <td><?= htmlspecialchars($u['name']) ?></td>
                    <td><?= htmlspecialchars($u['surname']) ?></td>
                    <td><?= htmlspecialchars($u['pesel']) ?></td>
                    <td><?= $u['is_admin'] ? 'TAK' : 'NIE' ?></td>
                    <td>
                        <?php if(!$u['is_admin']): ?>
                        <form method="POST" style="display:inline;">
                            <?= getCSRFInput() ?>
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <button type="submit" name="promote_user" onclick="return confirm('Awansować?')">Awansuj</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endwhile; ?>
            </table>
        </div>
    </div>
</body>
</html>