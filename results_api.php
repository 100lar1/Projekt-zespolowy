<?php
require_once 'core.php'; // Inicjalizuje połączenie DB

header('Content-Type: application/json');

if (!isset($_GET['election_id']) || !is_numeric($_GET['election_id'])) {
    http_response_code(400);
    echo json_encode(["error" => "Brak ID"]);
    exit;
}

$eid = (int)$_GET['election_id'];

$stmt = $conn->prepare("SELECT name, votes FROM candidates WHERE election_id = ? ORDER BY votes DESC");
$stmt->bind_param("i", $eid);
$stmt->execute();
$res = $stmt->get_result();

$data = ['names' => [], 'votes' => []];
while($row = $res->fetch_assoc()) {
    $data['names'][] = $row['name']; // JSON encoder sam escapuje znaki, ale htmlspecialchars w HTML jest potrzebne
    $data['votes'][] = $row['votes'];
}

echo json_encode($data);
?>