<?php
// Include security headers BEFORE any other output
include 'security_headers.php';
setPublicPageHeaders();

// Bezpieczne uwzględnienie połączenia z bazą danych
include 'db.php';

// Inicjalizacja zmiennych
$elections = null;
$current_id = isset($_GET['election_id']) ? intval($_GET['election_id']) : null;
$names = [];
$votes = [];
$error_message = '';

try {
    // Sprawdzenie czy tabela elections istnieje
    $check_table = $conn->query("SHOW TABLES LIKE 'elections'");
    if ($check_table->num_rows == 0) {
        throw new Exception("Tabela 'elections' nie istnieje. Proszę zaimportować strukturę bazy danych.");
    }
    
    // Bezpieczne pobranie listy wyborów
    $stmt = $conn->prepare("SELECT * FROM elections ORDER BY id DESC");
    $stmt->execute();
    $elections = $stmt->get_result();
    
    // Jeśli wybrano konkretne wybory, pobierz kandydatów
    if ($current_id) {
        $stmt = $conn->prepare("SELECT name, votes FROM candidates WHERE election_id = ?");
        $stmt->bind_param("i", $current_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        while ($row = $result->fetch_assoc()) {
            $names[] = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
            $votes[] = intval($row['votes']);
        }
        $stmt->close();
    }
    
} catch (Exception $e) {
    $error_message = $e->getMessage();
    error_log("Database error in index.php: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal Wyborczy</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

<h2>Witamy w Portalu Wyborczym</h2>

<?php if ($error_message): ?>
    <div style="background-color: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3>Błąd systemu</h3>
        <p><?= htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8') ?></p>
        <p><strong>Rozwiązanie:</strong></p>
        <ol>
            <li>Zaimportuj plik <code>wybory_portal.sql</code> do bazy danych</li>
            <li>Lub uruchom następujące polecenie w kontenerze MySQL:</li>
        </ol>
        <code style="background: #f1f1f1; padding: 10px; display: block; margin: 10px 0;">
            docker exec -i mysql-db mysql -u user -ppassword moja_baza &lt; wybory_portal.sql
        </code>
    </div>
<?php else: ?>
    
    <div style="margin-bottom: 20px;">
        <a href="register.php"><button>Zarejestruj się</button></a>
        <a href="login.php"><button>Zaloguj się</button></a>
    </div>

    <?php if ($elections && $elections->num_rows > 0): ?>
        <form method="GET" style="max-width: 400px; margin: 0 auto;">
            <select name="election_id" onchange="this.form.submit()">
                <option value="">-- Wybierz wybory --</option>
                <?php 
                $elections->data_seek(0); // Reset pointer
                while ($e = $elections->fetch_assoc()): ?>
                    <option value="<?= intval($e['id']) ?>" <?= ($e['id'] == $current_id ? 'selected' : '') ?>>
                        <?= htmlspecialchars($e['name'], ENT_QUOTES, 'UTF-8') ?>
                    </option>
                <?php endwhile; ?>
            </select>
        </form>

        <?php if (!empty($names) && !empty($votes)): ?>
            <canvas id="votesChart"></canvas>
            <script>
                const ctx = document.getElementById('votesChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: <?= json_encode($names, JSON_HEX_TAG | JSON_HEX_AMP) ?>,
                        datasets: [{
                            label: 'Głosy',
                            data: <?= json_encode($votes) ?>,
                            backgroundColor: 'rgba(54, 162, 235, 0.6)',
                            borderColor: 'rgba(54, 162, 235, 1)',
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
            </script>
        <?php elseif ($current_id): ?>
            <p>Brak kandydatów dla tych wyborów.</p>
        <?php endif; ?>
        
    <?php else: ?>
        <div style="text-align: center; margin: 40px 0;">
            <h3>Brak dostępnych wyborów</h3>
            <p>Skontaktuj się z administratorem w celu utworzenia wyborów.</p>
        </div>
    <?php endif; ?>

<?php endif; ?>

</body>
</html>