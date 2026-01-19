<?php
require_once 'core.php';
header('Content-Type: application/json');

$eid = (int)($_GET['election_id'] ?? 0);
if (!$eid) { echo json_encode([]); exit; }

$stmt = $conn->prepare("SELECT name, votes FROM candidates WHERE election_id = ?");
$stmt->bind_param("i", $eid);
$stmt->execute();
$res = $stmt->get_result();

$data = ['names'=>[], 'votes'=>[]];
while($r = $res->fetch_assoc()) {
    $data['names'][] = $r['name'];
    $data['votes'][] = $r['votes'];
}
echo json_encode($data);
?>