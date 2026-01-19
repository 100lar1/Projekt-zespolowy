<?php
require_once 'core.php';
// Core.php automatycznie ustawia nagłówki bezpieczeństwa

$elections = $conn->query("SELECT * FROM elections WHERE end_time < NOW() OR start_time <= NOW() ORDER BY id DESC");
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Portal Wyborczy</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h2>Portal Wyborczy</h2>
        <div style="text-align:center; margin-bottom:20px;">
            <a href="login.php" class="button">Zaloguj się</a>
            <a href="register.php" class="button">Zarejestruj się</a>
        </div>
        
        <h3>Wyniki Wyborów</h3>
        <select id="electionSelect" onchange="loadChart(this.value)">
            <option value="">-- Wybierz wybory --</option>
            <?php while($e = $elections->fetch_assoc()): ?>
                <option value="<?= $e['id'] ?>"><?= htmlspecialchars($e['name']) ?></option>
            <?php endwhile; ?>
        </select>
        
        <canvas id="publicChart"></canvas>
    </div>

    <script>
    let myChart = null;
    
    function loadChart(id) {
        if(!id) return;
        fetch('results_api.php?election_id=' + id)
            .then(r => r.json())
            .then(data => {
                const ctx = document.getElementById('publicChart');
                if(myChart) myChart.destroy();
                
                myChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.names,
                        datasets: [{
                            label: 'Liczba głosów',
                            data: data.votes,
                            backgroundColor: 'rgba(54, 162, 235, 0.5)'
                        }]
                    }
                });
            });
    }
    </script>
</body>
</html>