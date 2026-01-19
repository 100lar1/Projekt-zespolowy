<?php
require_once 'core.php';

if (!isset($_SESSION['user_id']) || !$_SESSION['is_admin']) {
    header("Location: login.php");
    exit;
}

checkCSRFOrDie();

$success = '';
$error = '';

if (isset($_POST['create_election'])) {
    $stmt = $conn->prepare("INSERT INTO elections (name, start_time, end_time) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $_POST['election_name'], $_POST['start_time'], $_POST['end_time']);
    if($stmt->execute()) $success = "Dodano wybory.";
    else $error = "Błąd.";
}

if (isset($_POST['add_candidate'])) {
    $stmt = $conn->prepare("INSERT INTO candidates (name, description, election_id) VALUES (?, ?, ?)");
    $stmt->bind_param("ssi", $_POST['candidate_name'], $_POST['candidate_description'], $_POST['election_id']);
    if($stmt->execute()) $success = "Dodano kandydata.";
    else $error = "Błąd.";
}

if (isset($_POST['promote_user'])) {
    $uid = (int)$_POST['user_id'];
    // Prosta logika promocji (w core.php można by to wydzielić, ale tu też ok)
    $conn->query("UPDATE users SET is_admin=1, admin_username=CONCAT('admin', id) WHERE id=$uid");
    $success = "Awansowano.";
}

$users = $conn->query("SELECT * FROM users");
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Panel Admina</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <h2>Admin Panel</h2>
        <a href="dashboard.php">Powrót</a>
        <?php if ($success) echo "<div class='message success'>$success</div>"; ?>
        
        <h3>Dodaj Wybory</h3>
        <form method="POST">
            <?= getCSRFInput() ?>
            <input type="text" name="election_name" placeholder="Nazwa" required>
            <input type="datetime-local" name="start_time" required>
            <input type="datetime-local" name="end_time" required>
            <button type="submit" name="create_election">Dodaj</button>
        </form>

        <h3>Dodaj Kandydata</h3>
        <form method="POST">
            <?= getCSRFInput() ?>
            <select name="election_id">
                <?php 
                $el = $conn->query("SELECT * FROM elections");
                while($e = $el->fetch_assoc()) echo "<option value='{$e['id']}'>{$e['name']}</option>"; 
                ?>
            </select>
            <input type="text" name="candidate_name" placeholder="Imię" required>
            <textarea name="candidate_description" placeholder="Opis"></textarea>
            <button type="submit" name="add_candidate">Dodaj</button>
        </form>

        <h3>Użytkownicy</h3>
        <table>
            <?php while($u = $users->fetch_assoc()): ?>
            <tr>
                <td><?= htmlspecialchars($u['name']) ?></td>
                <td><?= $u['is_admin']?'Admin':'User' ?></td>
                <td>
                    <?php if(!$u['is_admin']): ?>
                    <form method="POST" style="display:inline;">
                        <?= getCSRFInput() ?>
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <button type="submit" name="promote_user">Awansuj</button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endwhile; ?>
        </table>
    </div>
</body>
</html>