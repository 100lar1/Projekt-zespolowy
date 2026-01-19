<?php
require_once 'core.php';
$elections = $conn->query("SELECT * FROM elections");
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Portal</title>
    <link rel="stylesheet" href="css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h2>Portal Wyborczy</h2>
        <a href="login.php">Logowanie</a> | <a href="register.php">Rejestracja</a>
        <hr>
        <select onchange="loadChart(this.value)">
            <option>Wybierz...</option>
            <?php while($e=$elections->fetch_assoc()) echo "<option value='{$e['id']}'>{$e['name']}</option>"; ?>
        </select>
        <canvas id="chart"></canvas>
    </div>
    <script>
    function loadChart(id) {
        fetch('results_api.php?election_id='+id).then(r=>r.json()).then(d=>{
            new Chart(document.getElementById('chart'), {
                type:'bar', data:{labels:d.names, datasets:[{label:'Głosy', data:d.votes}]}
            });
        });
    }
    </script>
</body>
</html>