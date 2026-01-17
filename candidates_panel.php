<?php
    session_start();
    if (!isset($_SESSION["user_id"])) {
        header("Location: login.php");
        exit;
    }
include 'db.php';
// Pobranie listy wyborów
$elections = $conn->query("SELECT * FROM elections");
$selected_election_id = $_GET['election_id'] ?? null;
$candidates = [];
    if ($selected_election_id) {
        $stmt = $conn->prepare("SELECT * FROM candidates WHERE election_id = ?");
        $stmt->bind_param("i", $selected_election_id);
        $stmt->execute();
        $candidates = $stmt->get_result();
    }
?>
<!DOCTYPE html>
<html>
    <head>
        <title>Kandydaci</title>
        <link rel="stylesheet" href="css/style.css">
    </head>
    <body>
<h2>Lista kandydatów</h2>
<a href="dashboard.php"><button>Powrót do panelu</button></a>
<hr>
    <form method="GET" action="candidates_panel.php">
        <label for="election_id">Wybierz wybory:</label>
        <select name="election_id" id="election_id" onchange="this.form.submit()">
            <option value="">-- wybierz wybory --</option>
            <?php while ($row = $elections->fetch_assoc()): ?>
                <option value="<?= $row['id'] ?>" <?= ($selected_election_id == $row['id']) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($row['name']) ?>
                </option>
            <?php endwhile; ?>
        </select>
    </form>
<?php if ($selected_election_id && $candidates->num_rows > 0): ?>
    <h3>Kandydaci:</h3>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>Imię i nazwisko</th>
            <th>Opis</th>
        </tr>
        <?php while ($candidate = $candidates->fetch_assoc()): ?>
            <tr>
                <td><?= htmlspecialchars($candidate['name']) ?></td>
                <td><?= htmlspecialchars($candidate['description']) ?></td>
            </tr>
        <?php endwhile; ?>
    </table>
<?php elseif ($selected_election_id): ?>
    <p>Brak kandydatów w wybranych wyborach.</p>
<?php endif; ?>
</body>
</html>