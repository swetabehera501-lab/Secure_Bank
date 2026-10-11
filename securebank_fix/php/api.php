<?php
/* ============================================================
   SecureBank — php/api.php
   Called by fetch() in index.html  →  returns JSON only
   All actions: ?action=xxx
============================================================ */
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Use __DIR__ so the path works regardless of where Apache calls from
require_once __DIR__ . '/db.php';

$action = $_GET['action'] ?? '';
$data   = json_decode(file_get_contents('php://input'), true) ?? [];

function isAdmin() { return !empty($_SESSION['sb_admin']); }

// Auto-generate next ID like CUST0005, ACC0003, TXN00010
function nextId(PDO $pdo, string $table, string $col, string $prefix, int $pad = 4): string {
    $len  = strlen($prefix);
    $stmt = $pdo->query("SELECT MAX(CAST(SUBSTRING($col, " . ($len + 1) . ") AS UNSIGNED)) AS n FROM $table");
    $n    = ($stmt->fetch()['n'] ?? 0) + 1;
    return $prefix . str_pad($n, $pad, '0', STR_PAD_LEFT);
}

switch ($action) {

/* ══════════════ ADMIN AUTH ══════════════════════════ */
case 'admin_login':
    $user = trim($data['username'] ?? '');
    $pass = $data['password']      ?? '';
    if (!$user || !$pass) {
        echo json_encode(['ok'=>false,'msg'=>'Username and password are required.']); break;
    }
    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE username=? LIMIT 1");
    $stmt->execute([$user]);
    $row = $stmt->fetch();

    $loginOk = false;

    if ($row) {
        if (password_verify($pass, $row['password_hash'])) {
            // Normal login — hash is correct
            $loginOk = true;
        } else {
            // Hash in DB is wrong — auto-fix it if credentials match default
            // This handles the case where setup.sql inserted a wrong hash
            $knownDefaults = ['admin' => 'admin123'];
            if (isset($knownDefaults[$user]) && $pass === $knownDefaults[$user]) {
                $correctHash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 10]);
                $pdo->prepare("UPDATE admin_users SET password_hash=? WHERE username=?")
                    ->execute([$correctHash, $user]);
                $loginOk = true;
            }
        }
    } else {
        // Admin user does not exist at all — create it automatically
        $knownDefaults = ['admin' => 'admin123'];
        if (isset($knownDefaults[$user]) && $pass === $knownDefaults[$user]) {
            $correctHash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 10]);
            $pdo->prepare("INSERT INTO admin_users (username, password_hash) VALUES (?,?)")
                ->execute([$user, $correctHash]);
            $loginOk = true;
        }
    }

    if ($loginOk) {
        $_SESSION['sb_admin']    = true;
        $_SESSION['sb_username'] = $user;
        try { $pdo->prepare("INSERT INTO login_logs (username,ip_address,status) VALUES (?,?,'SUCCESS')")->execute([$user,$_SERVER['REMOTE_ADDR']??'']); } catch(Exception $e){}
        echo json_encode(['ok'=>true, 'username'=>$user]);
    } else {
        try { $pdo->prepare("INSERT INTO login_logs (username,ip_address,status) VALUES (?,?,'FAILED')")->execute([$user,$_SERVER['REMOTE_ADDR']??'']); } catch(Exception $e){}
        echo json_encode(['ok'=>false,'msg'=>'Wrong username or password.']);
    }
    break;

case 'admin_logout':
    session_destroy();
    echo json_encode(['ok'=>true]);
    break;

case 'admin_check':
    echo json_encode(['ok'=>isAdmin(),'username'=>$_SESSION['sb_username']??'']);
    break;

/* ══════════════ CUSTOMERS ═══════════════════════════ */
case 'get_customers':
    $rows = $pdo->query("SELECT * FROM customers ORDER BY created_at DESC")->fetchAll();
    echo json_encode($rows);
    break;

case 'add_customer':
    $name  = trim($data['name']  ?? '');
    $email = trim($data['email'] ?? '');
    $phone = trim($data['phone'] ?? '');
    $city  = trim($data['city']  ?? '');
    if (!$name || !$email || !$phone)
        { echo json_encode(['ok'=>false,'msg'=>'Name, email and phone are required.']); break; }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        { echo json_encode(['ok'=>false,'msg'=>'Invalid email address.']); break; }
    if (!preg_match('/^\d{10}$/', $phone))
        { echo json_encode(['ok'=>false,'msg'=>'Phone must be exactly 10 digits.']); break; }
    $chk = $pdo->prepare("SELECT id FROM customers WHERE email=?");
    $chk->execute([$email]);
    if ($chk->fetch()) { echo json_encode(['ok'=>false,'msg'=>'This email is already registered.']); break; }
    $cid = nextId($pdo,'customers','customer_id','CUST');
    $pdo->prepare("INSERT INTO customers (customer_id,name,email,phone,city) VALUES (?,?,?,?,?)")
        ->execute([$cid,$name,$email,$phone,$city]);
    echo json_encode(['ok'=>true,'id'=>$cid,'msg'=>"Customer $cid added."]);
    break;

case 'delete_customer':
    $id = $data['id'] ?? '';
    if (!$id) { echo json_encode(['ok'=>false,'msg'=>'ID required.']); break; }
    $pdo->prepare("DELETE FROM customers WHERE customer_id=?")->execute([$id]);
    echo json_encode(['ok'=>true]);
    break;

/* ══════════════ ACCOUNTS ════════════════════════════ */
case 'get_accounts':
    $rows = $pdo->query("
        SELECT a.*, c.name AS cust_name, c.email AS cust_email
        FROM accounts a
        JOIN customers c ON a.customer_id = c.customer_id
        ORDER BY a.created_at DESC")->fetchAll();
    echo json_encode($rows);
    break;

case 'add_account':
    $cid    = $data['customer_id']  ?? '';
    $type   = $data['account_type'] ?? '';
    $bal    = (float)($data['balance'] ?? 0);
    $status = $data['status'] ?? 'Active';
    if (!$cid || !$type)
        { echo json_encode(['ok'=>false,'msg'=>'Customer and account type are required.']); break; }
    $cust = $pdo->prepare("SELECT customer_id,name FROM customers WHERE customer_id=?");
    $cust->execute([$cid]); $cust = $cust->fetch();
    if (!$cust) { echo json_encode(['ok'=>false,'msg'=>'Customer not found.']); break; }
    $aid = nextId($pdo,'accounts','account_id','ACC');
    $pdo->prepare("INSERT INTO accounts (account_id,customer_id,account_type,balance,status) VALUES (?,?,?,?,?)")
        ->execute([$aid,$cid,$type,$bal,$status]);
    echo json_encode(['ok'=>true,'id'=>$aid,'msg'=>"Account $aid created."]);
    break;

case 'toggle_account':
    if (!isAdmin()) { echo json_encode(['ok'=>false,'msg'=>'Admin login required to lock/unlock accounts.']); break; }
    $id = $data['id'] ?? '';
    $row = $pdo->prepare("SELECT status FROM accounts WHERE account_id=?");
    $row->execute([$id]); $row = $row->fetch();
    if (!$row) { echo json_encode(['ok'=>false,'msg'=>'Account not found.']); break; }
    $new = $row['status']==='Active' ? 'Frozen' : 'Active';
    $pdo->prepare("UPDATE accounts SET status=? WHERE account_id=?")->execute([$new,$id]);
    echo json_encode(['ok'=>true,'status'=>$new]);
    break;

/* ══════════════ TRANSACTIONS ════════════════════════ */
case 'get_transactions':
    $rows = $pdo->query("
        SELECT t.*, c.name AS cust_name, c.email AS cust_email
        FROM transactions t
        JOIN accounts a ON t.account_id = a.account_id
        JOIN customers c ON a.customer_id = c.customer_id
        ORDER BY t.tx_time DESC LIMIT 200")->fetchAll();
    echo json_encode($rows);
    break;

case 'add_transaction':
    /*
     * PHP inserts ONE row into transactions.
     * MySQL TRIGGERS (setup.sql) fire automatically AFTER that INSERT.
     * Triggers check all 5 fraud rules and INSERT into fraud_alerts if any match.
     * PHP then reads back what the triggers created to return to the frontend.
     */
    $accId  = $data['account_id'] ?? '';
    $amount = (float)($data['amount']  ?? 0);
    $type   = $data['tx_type']    ?? '';
    $loc    = $data['location']   ?? '';

    if (!$accId || $amount <= 0 || !$type || !$loc)
        { echo json_encode(['ok'=>false,'msg'=>'All fields are required.']); break; }

    $acc = $pdo->prepare("
        SELECT a.*, c.name AS cname, c.email AS cemail
        FROM accounts a
        JOIN customers c ON a.customer_id = c.customer_id
        WHERE a.account_id = ?");
    $acc->execute([$accId]); $acc = $acc->fetch();

    if (!$acc)
        { echo json_encode(['ok'=>false,'msg'=>'Account not found.']); break; }
    if ($acc['status'] === 'Frozen')
        { echo json_encode(['ok'=>false,'msg'=>"Account $accId is frozen. Contact admin to unlock.",'frozen'=>true]); break; }

    $txId = nextId($pdo,'transactions','tx_id','TXN',5);

    // INSERT — 5 MySQL TRIGGERS fire here automatically
    $pdo->prepare("INSERT INTO transactions (tx_id, account_id, amount, tx_type, location) VALUES (?,?,?,?,?)")
        ->execute([$txId, $accId, $amount, $type, $loc]);

    // Update account balance
    if ($type === 'Deposit') {
        $pdo->prepare("UPDATE accounts SET balance = balance + ? WHERE account_id = ?")->execute([$amount, $accId]);
    } elseif (in_array($type, ['Withdraw','Transfer','ATM'])) {
        $pdo->prepare("UPDATE accounts SET balance = balance - ? WHERE account_id = ?")->execute([$amount, $accId]);
    }

    // Read fraud alerts the triggers created
    $alerts = $pdo->prepare("SELECT * FROM fraud_alerts WHERE transaction_id = ?");
    $alerts->execute([$txId]); $alerts = $alerts->fetchAll();

    if ($alerts) {
        $pdo->prepare("UPDATE transactions SET flagged = 1 WHERE tx_id = ?")->execute([$txId]);
    }

    echo json_encode([
        'ok'           => true,
        'tx_id'        => $txId,
        'fraud'        => $alerts,
        'cust_email'   => $acc['cemail'],
        'cust_name'    => $acc['cname'],
    ]);
    break;

/* ══════════════ FRAUD ALERTS ════════════════════════ */
case 'get_alerts':
    $rows = $pdo->query("
        SELECT f.*, c.name AS cust_name, c.email AS cust_email,
               t.amount, t.tx_type, t.location
        FROM fraud_alerts f
        JOIN transactions t ON f.transaction_id = t.tx_id
        JOIN accounts a ON t.account_id = a.account_id
        JOIN customers c ON a.customer_id = c.customer_id
        ORDER BY f.created_at DESC LIMIT 200")->fetchAll();
    echo json_encode($rows);
    break;

case 'clear_alerts':
    if (!isAdmin()) { echo json_encode(['ok'=>false,'msg'=>'Admin login required.']); break; }
    $pdo->exec("DELETE FROM fraud_alerts");
    $pdo->exec("UPDATE transactions SET flagged = 0");
    echo json_encode(['ok'=>true]);
    break;

/* ══════════════ REPORTS ═════════════════════════════ */
case 'get_stats':
    $r = $pdo->query("SELECT
        (SELECT COUNT(*) FROM customers)                          AS customers,
        (SELECT COUNT(*) FROM accounts)                           AS accounts,
        (SELECT COUNT(*) FROM transactions)                       AS transactions,
        (SELECT COUNT(*) FROM fraud_alerts)                       AS alerts,
        (SELECT COUNT(*) FROM fraud_alerts WHERE severity='HIGH') AS high_alerts,
        (SELECT COUNT(*) FROM fraud_alerts WHERE severity='MEDIUM') AS med_alerts,
        (SELECT COUNT(*) FROM accounts WHERE status='Frozen')     AS frozen")->fetch();
    echo json_encode($r);
    break;

case 'get_high_risk':
    $rows = $pdo->query("
        SELECT a.account_id, c.name AS cust_name, COUNT(f.id) AS cnt
        FROM fraud_alerts f
        JOIN accounts a ON f.account_id = a.account_id
        JOIN customers c ON a.customer_id = c.customer_id
        GROUP BY a.account_id, c.name
        ORDER BY cnt DESC LIMIT 10")->fetchAll();
    echo json_encode($rows);
    break;

case 'get_atm_summary':
    $rows = $pdo->query("
        SELECT t.account_id, DATE(t.tx_time) AS d,
               COUNT(*) AS cnt, SUM(t.amount) AS total
        FROM transactions t WHERE t.tx_type = 'ATM'
        GROUP BY t.account_id, DATE(t.tx_time)
        ORDER BY total DESC LIMIT 20")->fetchAll();
    echo json_encode($rows);
    break;

case 'get_large_tx':
    $rows = $pdo->query("
        SELECT t.tx_id, t.account_id, c.name AS cust_name,
               t.amount, t.tx_type, t.location, t.tx_time
        FROM transactions t
        JOIN accounts a ON t.account_id = a.account_id
        JOIN customers c ON a.customer_id = c.customer_id
        WHERE t.amount > 50000
        ORDER BY t.amount DESC LIMIT 50")->fetchAll();
    echo json_encode($rows);
    break;

/* ══════════════ ADMIN ACTIONS ═══════════════════════ */
case 'flag_password':
    if (!isAdmin()) { echo json_encode(['ok'=>false,'msg'=>'Admin required.']); break; }
    $id = $data['account_id'] ?? '';
    $pdo->prepare("UPDATE accounts SET password_changed_at = NOW() WHERE account_id = ?")->execute([$id]);
    echo json_encode(['ok'=>true,'msg'=>"Password change flagged for $id. Rule 5 is now active for 10 minutes."]);
    break;

case 'get_login_logs':
    if (!isAdmin()) { echo json_encode(['ok'=>false,'msg'=>'Admin required.']); break; }
    $rows = $pdo->query("SELECT * FROM login_logs ORDER BY logged_at DESC LIMIT 30")->fetchAll();
    echo json_encode($rows);
    break;

case 'admin_get_stats':
    if (!isAdmin()) { echo json_encode(['ok'=>false,'msg'=>'Admin required.']); break; }
    $r = $pdo->query("SELECT
        (SELECT COUNT(*) FROM fraud_alerts)                   AS total_alerts,
        (SELECT COUNT(*) FROM accounts WHERE status='Frozen') AS frozen,
        (SELECT COUNT(*) FROM accounts WHERE status='Active') AS active_acc,
        (SELECT COUNT(*) FROM customers)                      AS customers,
        (SELECT COUNT(*) FROM transactions)                   AS transactions")->fetch();
    echo json_encode(array_merge($r, ['ok'=>true]));
    break;

default:
    echo json_encode(['error' => 'Unknown action: ' . htmlspecialchars($action)]);
}
?>
