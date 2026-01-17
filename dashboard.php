<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
include 'db.php';
$is_admin = $_SESSION['is_admin'] ?? false;

// Pobierz wszystkie wybory
$elections = $conn->query("SELECT * FROM elections");
?>

<!DOCTYPE html>
<html>
<head>
    <title>Panel Główny</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
</head>
<body>
    <h2>Panel Główny</h2>

    <div class="links">
        <?php if ($is_admin): ?>
            <a href="admin_panel.php">Panel Admina</a>
        <?php else: ?>
            <a href="vote_panel.php">Głosuj</a>
        <?php endif; ?>
        <a href="candidates_panel.php">Kandydaci</a>
        <a href="change_password.php">Zmień hasło</a>
        <a href="logout.php">Wyloguj</a>
    </div>

    <h3>Wybierz wybory:</h3>
    <form method="GET" action="dashboard.php">
        <select name="election_id" id="election_id" onchange="this.form.submit()">
            <option value="">-- wybierz wybory --</option>
            <?php while ($row = $elections->fetch_assoc()): ?>
                <option value="<?= $row['id'] ?>" <?= (isset($_GET['election_id']) && $_GET['election_id'] == $row['id']) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($row['name']) ?>
                </option>
            <?php endwhile; ?>
        </select>
    </form>

    <?php if (isset($_GET['election_id']) && $_GET['election_id']): ?>
        <h3>Wyniki głosowania</h3>
        <canvas id="votesChart" width="700" height="400"></canvas>

        <script>
        const electionId = <?= (int)$_GET['election_id'] ?>;
        
        fetch(`results_api.php?election_id=${electionId}`)
            .then(res => res.json())
            .then(data => {
                const ctx = document.getElementById('votesChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.names,
                        datasets: [{
                            label: 'Głosy',
                            data: data.votes,
                            backgroundColor: 'rgba(0,123,255,0.6)',
                            borderColor: 'rgba(0,123,255,1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            })
            .catch(err => {
                console.error("Błąd ładowania danych:", err);
            });
        </script>
    <?php endif; ?>

</body>
</html>




