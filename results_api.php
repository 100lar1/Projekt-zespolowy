<?php
header('Content-Type: application/json');
include 'db.php';

// Sprawdź, czy election_id jest podane i jest liczbą
if (!isset($_GET['election_id']) || !is_numeric($_GET['election_id'])) {
    http_response_code(400);
    echo json_encode(["error" => "Nieprawidłowe ID wyborów"]);
    exit;
}

$election_id = (int)$_GET['election_id'];

try {
    // Sprawdź czy wybory istnieją
    $check_stmt = $conn->prepare("SELECT id FROM elections WHERE id = ?");
    $check_stmt->bind_param("i", $election_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    
    if ($check_result->num_rows === 0) {
        http_response_code(404);
        echo json_encode(["error" => "Wybory nie zostały znalezione"]);
        exit;
    }
    
    // Pobierz wyniki głosowania dla danego wyboru - BEZPIECZNE ZAPYTANIE
    $stmt = $conn->prepare("SELECT name, votes FROM candidates WHERE election_id = ? ORDER BY votes DESC");
    $stmt->bind_param("i", $election_id);
    $stmt->execute();
    $result = $stmt->get_result();

    $names = [];
    $votes = [];
    
    while ($row = $result->fetch_assoc()) {
        $names[] = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
        $votes[] = (int)$row['votes'];
    }

    // Zwróć dane jako JSON
    echo json_encode([
        "names" => $names, 
        "votes" => $votes,
        "total_candidates" => count($names),
        "total_votes" => array_sum($votes)
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    error_log("API Error in results_api.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(["error" => "Błąd serwera"]);
}
?>