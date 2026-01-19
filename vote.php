<?php
require_once 'core.php';

$token = $_GET['token'] ?? '';
$stmt = $conn->prepare("SELECT * FROM vote_tokens WHERE token=? AND used=0 AND expires_at > NOW()");
$stmt->bind_param("s", $token);
$stmt->execute();
$tok = $stmt->get_result()->fetch_assoc();

if (!$tok) die("Token nieważny.");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cid = (int)$_POST['candidate_id'];
    $conn->begin_transaction();
    $conn->query("UPDATE candidates SET votes=votes+1 WHERE id=$cid");
    $conn->query("UPDATE vote_tokens SET used=1 WHERE id={$tok['id']}");
    $conn->commit();
    die("Głos oddany! <a href='index.php'>Powrót</a>");
}

$cands = $conn->prepare("SELECT * FROM candidates WHERE election_id=?");
$cands->bind_param("i", $tok['election_id']);
$cands->execute();
$res = $cands->get_result();
?>
<!DOCTYPE html>
<html>
<head><title>Głosuj</title><link rel="stylesheet" href="css/style.css"></head>
<body>
    <div class="container">
        <h2>Głosowanie</h2>
        <form method="POST">
            <?php while($c = $res->fetch_assoc()): ?>
                <label>
                    <input type="radio" name="candidate_id" value="<?= $c['id'] ?>" required>
                    <?= htmlspecialchars($c['name']) ?>
                </label><br>
            <?php endwhile; ?>
            <button type="submit">Głosuj</button>
        </form>
    </div>
</body>
</html>