<?php
// debug_login.php - Run this to diagnose login issues
ini_set('display_errors', 1);
error_reporting(E_ALL);
require_once 'core.php';

echo "<h2>Login Debug Tool</h2>";

// 1. Check Database Column
echo "<h3>1. Database Structure Check</h3>";
$res = $conn->query("DESCRIBE users");
if ($res) {
    echo "<table border='1'><tr><th>Field</th><th>Type</th></tr>";
    while($row = $res->fetch_assoc()) {
        echo "<tr><td>{$row['Field']}</td><td>{$row['Type']}</td></tr>";
        if ($row['Field'] === 'password_hash') {
            $type = $row['Type'];
            if (strpos($type, 'varchar') !== false) {
                preg_match('/\d+/', $type, $matches);
                $len = $matches[0] ?? 0;
                if ($len < 60) {
                    echo "<tr><td colspan='2' style='color:red; font-weight:bold;'>CRITICAL: 'password_hash' column is too short ($len chars). It needs to be at least 60 (preferably 255).</td></tr>";
                } elseif ($len < 90) {
                     echo "<tr><td colspan='2' style='color:orange;'>WARNING: 'password_hash' is $len chars. This works for Bcrypt (PASSWORD_DEFAULT) but breaks Argon2.</td></tr>";
                } else {
                    echo "<tr><td colspan='2' style='color:green;'>OK: Column length is sufficient ($len chars).</td></tr>";
                }
            }
        }
    }
    echo "</table>";
} else {
    echo "Error getting table info: " . $conn->error;
}

?>

<h3>2. Test Login Logic</h3>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
    Login (PESEL/Admin): <input type="text" name="login" required>
    Password: <input type="text" name="pass" required>
    <button type="submit">Test User</button>
</form>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim($_POST['login']);
    $pass = $_POST['pass'];
    
    echo "<h3>3. Results for '$login'</h3>";
    
    $stmt = $conn->prepare("SELECT id, password_hash, is_admin FROM users WHERE pesel = ? OR admin_username = ?");
    $stmt->bind_param("ss", $login, $login);
    $stmt->execute();
    $res = $stmt->get_result();
    
    if ($res->num_rows === 0) {
        echo "<div style='color:red'>User NOT FOUND in database.</div>";
    } else {
        $u = $res->fetch_assoc();
        echo "User found (ID: {$u['id']}). <br>";
        echo "Stored Hash Length: " . strlen($u['password_hash']) . " chars.<br>";
        echo "Stored Hash: " . htmlspecialchars($u['password_hash']) . "<br>";
        
        if (PasswordSecurity::verifyPassword($pass, $u['password_hash'])) {
            echo "<div style='color:green; font-weight:bold; font-size:1.2em;'>SUCCESS! Password matches.</div>";
        } else {
            echo "<div style='color:red; font-weight:bold; font-size:1.2em;'>FAILURE: Password mismatch.</div>";
            echo "Possible reasons:<br>";
            echo "1. The hash in the DB is truncated (see length above).<br>";
            echo "2. The password stored is plain text (not hashed).<br>";
        }
    }
}
?>