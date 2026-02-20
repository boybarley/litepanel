#!/bin/bash
###############################################################################
# LitePanel Repair Installer - Clean Version
# For Ubuntu 22.04 + OpenLiteSpeed
###############################################################################

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
step() { echo -e "\n${YELLOW}===== $1 =====${NC}"; }

[[ $EUID -ne 0 ]] && fail "Run as root"

step "LitePanel Repair Installer"
read -rp "Cloudflare Account Email: " CF_EMAIL
[[ -z "$CF_EMAIL" ]] && fail "Email required"
read -rp "Cloudflare API Token: " CF_TOKEN
[[ -z "$CF_TOKEN" ]] && fail "Token required"
read -rp "Main Domain (e.g., example.com): " DOMAIN
[[ -z "$DOMAIN" ]] && fail "Domain required"
echo ""
info "Email:  $CF_EMAIL"
info "Domain: $DOMAIN"
read -rp "Continue? (y/n): " CONFIRM
[[ "$CONFIRM" != "y" ]] && exit 0

DB_USER_PASS=$(openssl rand -hex 16)
ADMIN_PASS=$(openssl rand -hex 12)
LSPHP="/usr/local/lsws/lsphp81/bin/lsphp"

##############################################################################
step "Step 1: Install Prerequisites"
##############################################################################
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

if [[ ! -f /usr/local/lsws/bin/lswsctrl ]]; then
    info "Installing OpenLiteSpeed..."
    wget -qO - https://repo.litespeed.sh | bash
    apt-get install -y -qq openlitespeed lsphp81 lsphp81-mysql lsphp81-curl lsphp81-common lsphp81-json lsphp81-opcache lsphp81-iconv
    ok "OpenLiteSpeed installed"
else
    ok "OpenLiteSpeed already installed"
fi

if ! command -v mariadb &>/dev/null; then
    info "Installing MariaDB..."
    apt-get install -y -qq mariadb-server mariadb-client
    systemctl enable --now mariadb
    ok "MariaDB installed"
else
    ok "MariaDB already installed"
fi

apt-get install -y -qq curl wget ufw fail2ban jq
systemctl enable --now mariadb

if ! command -v cloudflared &>/dev/null; then
    info "Installing cloudflared..."
    curl -sL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflared.list
    apt-get update -qq && apt-get install -y -qq cloudflared
fi
ok "All prerequisites ready"

[[ -f "$LSPHP" ]] || fail "lsphp81 not found at $LSPHP"
ADMIN_HASH=$("$LSPHP" -r "echo password_hash('${ADMIN_PASS}', PASSWORD_DEFAULT);" 2>/dev/null)
[[ -z "$ADMIN_HASH" ]] && fail "Failed to generate password hash"
ok "Password hash generated"

##############################################################################
step "Step 2: Create Directories"
##############################################################################
mkdir -p /opt/litepanel/{public,includes,sessions,logs,ssl,vhosts,backups}
mkdir -p /var/www/html
ok "Directories created"

##############################################################################
step "Step 3: Setup Database"
##############################################################################
mariadb -e "CREATE DATABASE IF NOT EXISTS litepanel_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
ok "Database created"

mariadb -e "DROP USER IF EXISTS 'litepanel_user'@'localhost';"
mariadb -e "CREATE USER 'litepanel_user'@'localhost' IDENTIFIED BY '${DB_USER_PASS}';"
mariadb -e "GRANT ALL PRIVILEGES ON litepanel_db.* TO 'litepanel_user'@'localhost';"
mariadb -e "FLUSH PRIVILEGES;"
ok "Database user created"

mariadb litepanel_db << 'SQLTABLES'
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT NULL,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    document_root VARCHAR(512) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active','inactive') DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS login_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(64) DEFAULT NULL,
    success TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQLTABLES
ok "Tables created"

printf "DELETE FROM users WHERE username='admin'; INSERT INTO users (username, password) VALUES ('admin', '%s');\n" "$ADMIN_HASH" | mariadb litepanel_db
ok "Admin user created"

##############################################################################
step "Step 4: Create PHP Includes"
##############################################################################

cat > /opt/litepanel/includes/config.php << 'XEOF'
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'litepanel_db');
define('DB_USER', 'litepanel_user');
define('DB_PASS', '__DBPASS__');
define('PANEL_DOMAIN', '__DOMAINX__');
define('BASE_PATH', '/opt/litepanel');
define('SESSION_LIFETIME', 3600);
session_save_path(BASE_PATH . '/sessions');
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
session_set_cookie_params(['lifetime' => SESSION_LIFETIME, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
XEOF
sed -i "s|__DBPASS__|${DB_USER_PASS}|g" /opt/litepanel/includes/config.php
sed -i "s|__DOMAINX__|${DOMAIN}|g" /opt/litepanel/includes/config.php
ok "config.php"

cat > /opt/litepanel/includes/database.php << 'XEOF'
<?php
class Database {
    private static $instance = null;
    private $pdo;
    private function __construct() {
        try {
            $this->pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
        } catch (PDOException $e) { error_log("DB: ".$e->getMessage()); die("Database error"); }
    }
    public static function getInstance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }
    public function query($sql, $params = []) { $s = $this->pdo->prepare($sql); $s->execute($params); return $s; }
    public function fetch($sql, $params = []) { return $this->query($sql, $params)->fetch(); }
    public function fetchAll($sql, $params = []) { return $this->query($sql, $params)->fetchAll(); }
    public function lastInsertId() { return $this->pdo->lastInsertId(); }
}
XEOF
ok "database.php"

cat > /opt/litepanel/includes/auth.php << 'XEOF'
<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';

function startSecureSession() { if (session_status() === PHP_SESSION_NONE) session_start(); }
function isLoggedIn() { startSecureSession(); return isset($_SESSION['user_id'], $_SESSION['username']); }
function requireLogin() { if (!isLoggedIn()) { header('Location: /index.php'); exit; } }

function login($username, $password) {
    $db = Database::getInstance();
    $user = $db->fetch("SELECT * FROM users WHERE username = ?", [$username]);
    if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time())
        return ['success' => false, 'message' => 'Account locked. Try later.'];
    if ($user && password_verify($password, $user['password'])) {
        startSecureSession(); session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $db->query("UPDATE users SET last_login=NOW(), failed_attempts=0 WHERE id=?", [$user['id']]);
        $db->query("INSERT INTO login_log (ip_address,username,success) VALUES (?,?,1)", [$_SERVER['REMOTE_ADDR']??'0.0.0.0',$username]);
        return ['success' => true];
    }
    if ($user) {
        $a = $user['failed_attempts'] + 1;
        $lock = $a >= 5 ? ", locked_until=DATE_ADD(NOW(), INTERVAL 15 MINUTE)" : "";
        $db->query("UPDATE users SET failed_attempts={$a}{$lock} WHERE id=?", [$user['id']]);
    }
    $db->query("INSERT INTO login_log (ip_address,username,success) VALUES (?,?,0)", [$_SERVER['REMOTE_ADDR']??'0.0.0.0',$username]);
    return ['success' => false, 'message' => 'Invalid credentials'];
}

function logout() {
    startSecureSession(); $_SESSION = [];
    if (ini_get("session.use_cookies")) { $p=session_get_cookie_params(); setcookie(session_name(),'',time()-42000,$p["path"],$p["domain"],$p["secure"],$p["httponly"]); }
    session_destroy(); header('Location: /index.php'); exit;
}
function e($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
XEOF
ok "auth.php"

cat > /opt/litepanel/includes/functions.php << 'XEOF'
<?php
function getSystemInfo() {
    $i = [];
    $i['hostname'] = gethostname();
    $i['os'] = php_uname('s').' '.php_uname('r');
    $i['uptime'] = trim(shell_exec("uptime -p") ?? 'N/A');
    $i['load'] = sys_getloadavg();
    $f = shell_exec("free -b");
    if (preg_match('/Mem:\s+(\d+)\s+(\d+)/', $f, $m)) { $i['mem_total']=$m[1]; $i['mem_used']=$m[2]; $i['mem_percent']=round(($m[2]/$m[1])*100,1); }
    $i['disk_total'] = disk_total_space('/'); $i['disk_free'] = disk_free_space('/');
    $i['disk_used'] = $i['disk_total'] - $i['disk_free'];
    $i['disk_percent'] = round(($i['disk_used']/$i['disk_total'])*100,1);
    $i['cpu'] = trim(shell_exec("nproc") ?? '1');
    return $i;
}
function formatBytes($b, $p=2) { $u=['B','KB','MB','GB','TB']; $b=max($b,0); $pw=floor(($b?log($b):0)/log(1024)); $pw=min($pw,count($u)-1); return round($b/(1024**$pw),$p).' '.$u[$pw]; }
function getServiceStatus($s) { return trim(shell_exec("systemctl is-active ".escapeshellarg($s)." 2>/dev/null") ?? '') === 'active'; }
function flash($t,$m) { $_SESSION['flash']=['type'=>$t,'message'=>$m]; }
function getFlash() { if(isset($_SESSION['flash'])){$f=$_SESSION['flash'];unset($_SESSION['flash']);return $f;} return null; }
XEOF
ok "functions.php"

cat > /opt/litepanel/includes/security.php << 'XEOF'
<?php
function generateCsrfToken() { if(empty($_SESSION['csrf_token'])) $_SESSION['csrf_token']=bin2hex(random_bytes(32)); return $_SESSION['csrf_token']; }
function validateCsrfToken($t) { return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'],$t); }
function sanitizeInput($i) { if(is_array($i)) return array_map('sanitizeInput',$i); return htmlspecialchars(strip_tags(trim($i)),ENT_QUOTES,'UTF-8'); }
XEOF
ok "security.php"

cat > /opt/litepanel/includes/header.php << 'XEOF'
<?php require_once __DIR__.'/auth.php'; requireLogin(); require_once __DIR__.'/functions.php'; require_once __DIR__.'/security.php'; $csrfToken=generateCsrfToken(); ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel - <?php echo $pageTitle??'Dashboard';?></title><link rel="stylesheet" href="/style.css"></head><body><div class="layout">
<?php require_once __DIR__.'/sidebar.php'; ?>
<main class="main-content"><div class="top-bar"><h1><?php echo $pageTitle??'Dashboard';?></h1>
<div class="user-info"><span><?php echo e($_SESSION['username']);?></span><a href="/logout.php" class="btn btn-sm btn-danger">Logout</a></div></div><div class="content">
<?php $flash=getFlash(); if($flash): ?><div class="alert alert-<?php echo $flash['type'];?>"><?php echo e($flash['message']);?></div><?php endif; ?>
XEOF
ok "header.php"

cat > /opt/litepanel/includes/sidebar.php << 'XEOF'
<aside class="sidebar"><div class="sidebar-header"><h2>LitePanel</h2></div><nav><ul>
<li><a href="/dashboard.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='dashboard.php'?'active':'';?>">Dashboard</a></li>
<li><a href="/domains.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='domains.php'?'active':'';?>">Domains</a></li>
<li><a href="/databases.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='databases.php'?'active':'';?>">Databases</a></li>
<li><a href="/filemanager.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='filemanager.php'?'active':'';?>">File Manager</a></li>
<li><a href="/ssl.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='ssl.php'?'active':'';?>">SSL</a></li>
<li><a href="/phpmyadmin/" target="_blank">phpMyAdmin</a></li>
</ul></nav></aside>
XEOF
ok "sidebar.php"

##############################################################################
step "Step 5: Create Public Pages"
##############################################################################

cat > /opt/litepanel/public/index.php << 'XEOF'
<?php
require_once __DIR__.'/../includes/config.php';
require_once __DIR__.'/../includes/auth.php';
startSecureSession();
if (isLoggedIn()) { header('Location: /dashboard.php'); exit; }
$error = '';
if ($_SERVER['REQUEST_METHOD']==='POST') {
    $r = login(trim($_POST['username']??''), $_POST['password']??'');
    if ($r['success']) { header('Location: /dashboard.php'); exit; }
    $error = $r['message'];
}
?><!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel Login</title><link rel="stylesheet" href="/style.css"></head>
<body class="login-body"><div class="login-container"><div class="login-box">
<h1>LitePanel</h1><p class="login-subtitle">Server Management Panel</p>
<?php if($error):?><div class="alert alert-danger"><?php echo htmlspecialchars($error);?></div><?php endif;?>
<form method="POST"><div class="form-group"><label>Username</label><input type="text" name="username" required autofocus></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn btn-primary btn-block">Login</button></form></div></div></body></html>
XEOF
ok "index.php"

cat > /opt/litepanel/public/dashboard.php << 'XEOF'
<?php $pageTitle='Dashboard'; require_once __DIR__.'/../includes/header.php';
$sys=getSystemInfo(); $db=Database::getInstance();
$dc=$db->fetch("SELECT COUNT(*) as c FROM domains")['c'];
$sv=['OpenLiteSpeed'=>getServiceStatus('lsws'),'MariaDB'=>getServiceStatus('mariadb'),'Cloudflared'=>getServiceStatus('cloudflared'),'Fail2Ban'=>getServiceStatus('fail2ban'),'UFW'=>getServiceStatus('ufw')];
?>
<div class="stats-grid">
<div class="stat-card"><h3>CPU Load</h3><div class="stat-value"><?php echo $sys['load'][0];?></div><p><?php echo $sys['cpu'];?> cores</p></div>
<div class="stat-card"><h3>Memory</h3><div class="stat-value"><?php echo $sys['mem_percent']??0;?>%</div><p><?php echo formatBytes($sys['mem_used']??0);?> / <?php echo formatBytes($sys['mem_total']??0);?></p></div>
<div class="stat-card"><h3>Disk</h3><div class="stat-value"><?php echo $sys['disk_percent'];?>%</div><p><?php echo formatBytes($sys['disk_used']);?> / <?php echo formatBytes($sys['disk_total']);?></p></div>
<div class="stat-card"><h3>Domains</h3><div class="stat-value"><?php echo $dc;?></div><p>Active domains</p></div>
</div>
<h2>Services</h2><table class="table"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>
<?php foreach($sv as $n=>$a):?><tr><td><?php echo $n;?></td><td><span class="badge <?php echo $a?'badge-success':'badge-danger';?>"><?php echo $a?'Running':'Stopped';?></span></td></tr><?php endforeach;?>
</tbody></table>
<h2>System</h2><table class="table">
<tr><td><strong>Hostname</strong></td><td><?php echo e($sys['hostname']);?></td></tr>
<tr><td><strong>OS</strong></td><td><?php echo e($sys['os']);?></td></tr>
<tr><td><strong>Uptime</strong></td><td><?php echo e($sys['uptime']);?></td></tr>
</table></div></main></div></body></html>
XEOF
ok "dashboard.php"

cat > /opt/litepanel/public/domains.php << 'XEOF'
<?php $pageTitle='Domains'; require_once __DIR__.'/../includes/header.php';
$db=Database::getInstance();
if($_SERVER['REQUEST_METHOD']==='POST' && validateCsrfToken($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='add'){
        $dom=preg_replace('/[^a-zA-Z0-9.-]/','',$_POST['domain']??'');
        if($dom){ $dr="/var/www/{$dom}/public_html";
            try{ $db->query("INSERT INTO domains (domain,document_root) VALUES (?,?)",[$dom,$dr]);
                if(!is_dir($dr)){mkdir($dr,0755,true);file_put_contents("{$dr}/index.html","<h1>Welcome to {$dom}</h1>");chown($dr,'nobody');chgrp($dr,'nogroup');}
                flash('success',"Domain {$dom} added");
            }catch(Exception $e){flash('danger',$e->getMessage());}
        }
    }elseif($act==='delete'){$db->query("DELETE FROM domains WHERE id=?",[(int)($_POST['id']??0)]);flash('success','Domain deleted');}
    header('Location: /domains.php'); exit;
}
$domains=$db->fetchAll("SELECT * FROM domains ORDER BY created_at DESC");
?>
<div class="card"><h3>Add Domain</h3><form method="POST" class="form-inline">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="add">
<div class="form-group"><input type="text" name="domain" placeholder="example.com" required></div>
<button type="submit" class="btn btn-primary">Add Domain</button></form></div>
<table class="table"><thead><tr><th>Domain</th><th>Document Root</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>
<?php if(empty($domains)):?><tr><td colspan="5" class="text-center">No domains</td></tr>
<?php else: foreach($domains as $d):?><tr>
<td><strong><?php echo e($d['domain']);?></strong></td><td><code><?php echo e($d['document_root']);?></code></td>
<td><span class="badge badge-success"><?php echo e($d['status']);?></span></td><td><?php echo e($d['created_at']);?></td>
<td><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="delete">
<input type="hidden" name="id" value="<?php echo $d['id'];?>"><button type="submit" class="btn btn-sm btn-danger">Delete</button></form></td>
</tr><?php endforeach;endif;?></tbody></table></div></main></div></body></html>
XEOF
ok "domains.php"

cat > /opt/litepanel/public/databases.php << 'XEOF'
<?php $pageTitle='Databases'; require_once __DIR__.'/../includes/header.php';
if($_SERVER['REQUEST_METHOD']==='POST' && validateCsrfToken($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='create'){
        $dn=preg_replace('/[^a-zA-Z0-9_]/','',$_POST['dbname']??'');
        $du=preg_replace('/[^a-zA-Z0-9_]/','',$_POST['dbuser']??'');
        $dp=$_POST['dbpass']??bin2hex(random_bytes(8));
        if($dn&&$du){
            $out=shell_exec(sprintf("mariadb -e %s 2>&1",escapeshellarg("CREATE DATABASE IF NOT EXISTS \`{$dn}\` CHARACTER SET utf8mb4; CREATE USER IF NOT EXISTS '{$du}'@'localhost' IDENTIFIED BY '{$dp}'; GRANT ALL ON \`{$dn}\`.* TO '{$du}'@'localhost'; FLUSH PRIVILEGES;")));
            if(empty($out)) flash('success',"DB '{$dn}' created. User:{$du} Pass:{$dp}"); else flash('danger',$out);
        }
    }elseif($act==='drop'){
        $dn=preg_replace('/[^a-zA-Z0-9_]/','',$_POST['dbname']??'');
        if($dn&&!in_array($dn,['mysql','information_schema','performance_schema','sys','litepanel_db'])){
            shell_exec("mariadb -e ".escapeshellarg("DROP DATABASE IF EXISTS \`{$dn}\`;")." 2>&1"); flash('success',"Deleted {$dn}");
        }
    }
    header('Location: /databases.php'); exit;
}
$dbs=[]; $out=shell_exec("mariadb -N -e 'SHOW DATABASES' 2>/dev/null");
if($out){$dbs=array_filter(explode("\n",trim($out))); $dbs=array_diff($dbs,['information_schema','performance_schema','mysql','sys']);}
?>
<div class="card"><h3>Create Database</h3><form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="create">
<div class="form-row">
<div class="form-group"><label>Database Name</label><input type="text" name="dbname" required pattern="[a-zA-Z0-9_]+"></div>
<div class="form-group"><label>Username</label><input type="text" name="dbuser" required pattern="[a-zA-Z0-9_]+"></div>
<div class="form-group"><label>Password</label><input type="text" name="dbpass" placeholder="auto-generate"></div></div>
<button type="submit" class="btn btn-primary">Create</button></form></div>
<h2>Databases</h2><table class="table"><thead><tr><th>Name</th><th>Actions</th></tr></thead><tbody>
<?php foreach($dbs as $d):?><tr><td><strong><?php echo e($d);?></strong></td><td>
<?php if($d!=='litepanel_db'):?><form method="POST" style="display:inline" onsubmit="return confirm('Drop <?php echo e($d);?>?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="drop">
<input type="hidden" name="dbname" value="<?php echo e($d);?>"><button class="btn btn-sm btn-danger">Drop</button></form>
<?php else:?><span class="badge badge-warning">System</span><?php endif;?></td></tr><?php endforeach;?>
</tbody></table></div></main></div></body></html>
XEOF
ok "databases.php"

cat > /opt/litepanel/public/filemanager.php << 'XEOF'
<?php $pageTitle='File Manager'; require_once __DIR__.'/../includes/header.php';
$base='/var/www'; $dir=realpath($_GET['dir']??$base)?:$base;
if(strpos($dir,$base)!==0) $dir=$base;
if($_SERVER['REQUEST_METHOD']==='POST' && validateCsrfToken($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='upload'&&isset($_FILES['file'])){$t=$dir.'/'.basename($_FILES['file']['name']);if(strpos(realpath(dirname($t))?:'',$base)===0)move_uploaded_file($_FILES['file']['tmp_name'],$t);flash('success','Uploaded');}
    elseif($act==='mkdir'){$n=preg_replace('/[^a-zA-Z0-9._-]/','',$_POST['dirname']??'');if($n){mkdir($dir.'/'.$n,0755);flash('success','Created');}}
    elseif($act==='delete'){$t=realpath($dir.'/'.basename($_POST['filename']??''));if($t&&strpos($t,$base)===0&&$t!==$base){is_dir($t)?rmdir($t):unlink($t);flash('success','Deleted');}}
    elseif($act==='save'){$t=realpath($dir.'/'.basename($_POST['filename']??''));if($t&&strpos($t,$base)===0){file_put_contents($t,$_POST['content']??'');flash('success','Saved');}}
    header("Location: /filemanager.php?dir=".urlencode($dir)); exit;
}
$edit=null;$ec='';
if(isset($_GET['edit'])){$ef=realpath($dir.'/'.basename($_GET['edit']));if($ef&&strpos($ef,$base)===0&&is_file($ef)&&filesize($ef)<1048576){$edit=$ef;$ec=file_get_contents($ef);}}
$items=[];if(is_dir($dir)){foreach(scandir($dir) as $f){if($f==='.')continue;$p=$dir.'/'.$f;$items[]=['name'=>$f,'is_dir'=>is_dir($p),'size'=>is_file($p)?filesize($p):0,'mod'=>filemtime($p),'perm'=>substr(sprintf('%o',fileperms($p)),-4)];}
usort($items,function($a,$b){if($a['name']==='..')return -1;if($b['name']==='..')return 1;if($a['is_dir']!==$b['is_dir'])return $b['is_dir']-$a['is_dir'];return strcasecmp($a['name'],$b['name']);});}
?>
<div class="breadcrumb">Path: <strong><?php echo e($dir);?></strong></div>
<?php if($edit):?>
<div class="card"><h3>Edit: <?php echo e(basename($edit));?></h3><form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="save">
<input type="hidden" name="filename" value="<?php echo e(basename($edit));?>">
<textarea name="content" class="code-editor" rows="20"><?php echo e($ec);?></textarea><br>
<button class="btn btn-primary">Save</button> <a href="/filemanager.php?dir=<?php echo urlencode($dir);?>" class="btn btn-secondary">Cancel</a></form></div>
<?php else:?>
<div class="card" style="display:flex;gap:10px;flex-wrap:wrap;">
<form method="POST" enctype="multipart/form-data" style="display:flex;gap:10px;align-items:flex-end;">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="upload">
<div class="form-group"><label>Upload</label><input type="file" name="file" required></div><button class="btn btn-primary">Upload</button></form>
<form method="POST" style="display:flex;gap:10px;align-items:flex-end;">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="mkdir">
<div class="form-group"><label>New Dir</label><input type="text" name="dirname" required></div><button class="btn btn-success">Create</button></form></div>
<table class="table"><thead><tr><th>Name</th><th>Size</th><th>Perms</th><th>Modified</th><th>Actions</th></tr></thead><tbody>
<?php foreach($items as $f):?><tr><td>
<?php if($f['is_dir']):?><a href="/filemanager.php?dir=<?php echo urlencode($dir.'/'.$f['name']);?>"><strong><?php echo e($f['name']);?>/</strong></a>
<?php else:echo e($f['name']);endif;?></td>
<td><?php echo $f['is_dir']?'-':formatBytes($f['size']);?></td><td><code><?php echo $f['perm'];?></code></td>
<td><?php echo date('Y-m-d H:i',$f['mod']);?></td><td>
<?php if(!$f['is_dir']):?><a href="/filemanager.php?dir=<?php echo urlencode($dir);?>&edit=<?php echo urlencode($f['name']);?>" class="btn btn-sm btn-primary">Edit</a><?php endif;?>
<?php if($f['name']!=='..'):?><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="delete">
<input type="hidden" name="filename" value="<?php echo e($f['name']);?>"><button class="btn btn-sm btn-danger">Del</button></form><?php endif;?>
</td></tr><?php endforeach;?></tbody></table><?php endif;?>
</div></main></div></body></html>
XEOF
ok "filemanager.php"

cat > /opt/litepanel/public/ssl.php << 'XEOF'
<?php $pageTitle='SSL Certificates'; require_once __DIR__.'/../includes/header.php';
$db=Database::getInstance(); $domains=$db->fetchAll("SELECT * FROM domains ORDER BY domain");
?>
<div class="card"><h3>SSL Information</h3>
<p>SSL/HTTPS is handled automatically by Cloudflare Tunnel.</p>
<p>All traffic between visitors and Cloudflare is encrypted.</p></div>
<h2>Domains</h2><table class="table"><thead><tr><th>Domain</th><th>SSL Status</th><th>Provider</th></tr></thead><tbody>
<?php if(empty($domains)):?><tr><td colspan="3" class="text-center">No domains</td></tr>
<?php else:foreach($domains as $d):?><tr><td><strong><?php echo e($d['domain']);?></strong></td>
<td><span class="badge badge-success">Active</span></td><td>Cloudflare</td></tr><?php endforeach;endif;?>
</tbody></table></div></main></div></body></html>
XEOF
ok "ssl.php"

cat > /opt/litepanel/public/logout.php << 'XEOF'
<?php require_once __DIR__.'/../includes/auth.php'; logout();
XEOF
ok "logout.php"

##############################################################################
step "Step 6: Create CSS"
##############################################################################

cat > /opt/litepanel/public/style.css << 'XEOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#333}
.login-body{display:flex;justify-content:center;align-items:center;min-height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
.login-container{width:100%;max-width:400px;padding:20px}
.login-box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3);text-align:center}
.login-box h1{font-size:2em;margin-bottom:5px}
.login-subtitle{color:#888;margin-bottom:25px}
.layout{display:flex;min-height:100vh}
.sidebar{width:250px;background:#1e293b;color:#fff;flex-shrink:0}
.sidebar-header{padding:20px;border-bottom:1px solid #334155}
.sidebar-header h2{font-size:1.4em}
.sidebar nav ul{list-style:none;padding:10px 0}
.sidebar nav a{display:block;padding:12px 20px;color:#94a3b8;text-decoration:none;transition:.2s}
.sidebar nav a:hover,.sidebar nav a.active{background:#334155;color:#fff}
.main-content{flex:1;display:flex;flex-direction:column}
.top-bar{display:flex;justify-content:space-between;align-items:center;padding:15px 25px;background:#fff;border-bottom:1px solid #e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.top-bar h1{font-size:1.3em}
.user-info{display:flex;align-items:center;gap:10px}
.content{padding:25px;flex:1}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:25px}
.stat-card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.stat-card h3{font-size:.85em;color:#64748b;text-transform:uppercase}
.stat-value{font-size:2em;font-weight:700;color:#1e293b;margin:5px 0}
.stat-card p{font-size:.85em;color:#94a3b8}
.card{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1);margin-bottom:20px}
.card h3{margin-bottom:15px}
.table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,.1);margin-bottom:20px}
.table th,.table td{padding:12px 15px;text-align:left;border-bottom:1px solid #e2e8f0}
.table th{background:#f8fafc;font-weight:600;color:#64748b;font-size:.85em;text-transform:uppercase}
.table tr:hover{background:#f8fafc}
.form-group{margin-bottom:15px}
.form-group label{display:block;margin-bottom:5px;font-weight:500;font-size:.9em}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:.95em}
.form-group input:focus,.form-group textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.2)}
.form-inline{display:flex;gap:10px;align-items:flex-end}
.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px}
.btn{display:inline-block;padding:10px 18px;border:none;border-radius:6px;cursor:pointer;font-size:.9em;text-decoration:none;transition:.2s}
.btn-primary{background:#667eea;color:#fff}.btn-primary:hover{background:#5a67d8}
.btn-success{background:#10b981;color:#fff}.btn-danger{background:#ef4444;color:#fff}
.btn-secondary{background:#6b7280;color:#fff}.btn-block{width:100%}.btn-sm{padding:5px 10px;font-size:.8em}
.badge{padding:4px 8px;border-radius:12px;font-size:.8em;font-weight:500}
.badge-success{background:#d1fae5;color:#065f46}.badge-danger{background:#fee2e2;color:#991b1b}.badge-warning{background:#fef3c7;color:#92400e}
.alert{padding:12px 16px;border-radius:6px;margin-bottom:15px}
.alert-success{background:#d1fae5;color:#065f46;border:1px solid #a7f3d0}
.alert-danger{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
.alert-info{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}
.breadcrumb{background:#fff;padding:10px 15px;border-radius:6px;margin-bottom:15px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.breadcrumb a{color:#667eea;text-decoration:none}
.code-editor{font-family:'Courier New',monospace;font-size:14px;width:100%;padding:15px;border:1px solid #d1d5db;border-radius:6px;background:#1e293b;color:#e2e8f0;tab-size:4}
.text-center{text-align:center}
code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:.85em}
@media(max-width:768px){.layout{flex-direction:column}.sidebar{width:100%}.stats-grid{grid-template-columns:1fr 1fr}.form-inline{flex-direction:column}.form-row{grid-template-columns:1fr}}
XEOF
ok "style.css"

##############################################################################
step "Step 7: Set Permissions"
##############################################################################
chown -R nobody:nogroup /opt/litepanel
chmod -R 750 /opt/litepanel
chmod 700 /opt/litepanel/sessions
find /opt/litepanel/public -type f -exec chmod 644 {} \;
chmod 600 /opt/litepanel/includes/config.php
ok "Permissions set"

##############################################################################
step "Step 8: Configure OpenLiteSpeed"
##############################################################################

cat > /opt/litepanel/vhconf.conf << 'XEOF'
docRoot                   /opt/litepanel/public
index  {
  useServer               0
  indexFiles              index.php
}
context / {
  location                /opt/litepanel/public
  allowBrowse             1
  rewrite  {
    enable                1
  }
}
rewrite  {
  enable                  1
}
XEOF

cat > /var/www/vhconf.conf << 'XEOF'
docRoot                   /var/www/html
index  {
  useServer               0
  indexFiles              index.html, index.php
}
XEOF

cat > /var/www/html/index.html << 'XEOF'
<!DOCTYPE html><html><head><title>LitePanel</title></head>
<body style="font-family:sans-serif;text-align:center;padding:50px;">
<h1>LitePanel is Working!</h1><p>Configure your domains in the panel.</p></body></html>
XEOF

cp /usr/local/lsws/conf/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf.bak 2>/dev/null || true

cat > /usr/local/lsws/conf/httpd_config.conf << 'XEOF'
serverName                LitePanel
user                      nobody
group                     nogroup
priority                  0
autoRestart               1
chrootPath                /
enableChroot              0
inMemBufSize              60M
swappingDir               /tmp/lshttpd/swap
autoFix503                1
gracefulRestartTimeout    300
mime                      conf/mime.properties
showVersionNumber         0
adminEmails               root@localhost

errorlog logs/error.log {
  logLevel                WARN
  debugLevel              0
  rollingSize             10M
  enableStderrLog         1
}

accesslog logs/access.log {
  rollingSize             10M
  keepDays                30
  compressArchive         0
}

indexFiles                index.html, index.php

tuning {
  maxConnections          2000
  maxSSLConnections       1000
  connTimeout             300
  maxKeepAliveReq         1000
  keepAliveTimeout        5
  maxReqURLLen            8192
  maxReqHeaderSize        16380
  maxReqBodySize          50M
  maxDynRespHeaderSize    8192
  maxDynRespSize          2047M
  maxCachedFileSize       4096
  totalInMemCacheSize     20M
  maxMMapFileSize         256K
  totalMMapCacheSize      40M
  useSendfile             1
  fileETag                28
  SSLStrongDhKey          1
}

accessDenyDir {
  dir                     /
  dir                     /etc/*
  dir                     /dev/*
  dir                     /proc/*
  dir                     /sys/*
}

scripthandler {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/lsphp81.sock
  maxConns                20
  env                     PHP_LSAPI_CHILDREN=20
  env                     LSAPI_AVOID_FORK=200M
  initTimeout             60
  retryTimeout            0
  pcKeepAliveTimeout      15
  respBuffer              0
  autoStart               2
  path                    /usr/local/lsws/lsphp81/bin/lsphp
  backlog                 100
  instances               1
  priority                0
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           1400
  procHardLimit           1500
}

listener HTTP {
  address                 *:8080
  secure                  0
  map                     DefaultSite *
}

listener PanelHTTP {
  address                 *:2087
  secure                  0
  map                     LitePanelVHost *
}

virtualhost DefaultSite {
  vhRoot                  /var/www
  configFile              /var/www/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
}

virtualhost LitePanelVHost {
  vhRoot                  /opt/litepanel
  configFile              /opt/litepanel/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
  setUIDMode              2
}
XEOF

/usr/local/lsws/bin/lswsctrl stop 2>/dev/null || true
sleep 2
/usr/local/lsws/bin/lswsctrl start
sleep 2
ok "OpenLiteSpeed configured and restarted"

##############################################################################
step "Step 9: Install phpMyAdmin"
##############################################################################
if [[ ! -d /opt/litepanel/public/phpmyadmin ]]; then
    info "Downloading phpMyAdmin..."
    cd /tmp
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.tar.gz" -O pma.tar.gz
    tar xzf pma.tar.gz
    mv phpMyAdmin-5.2.1-all-languages /opt/litepanel/public/phpmyadmin
    BLOWFISH=$(openssl rand -hex 16)
    cat > /opt/litepanel/public/phpmyadmin/config.inc.php << PMAEOF
<?php
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0; \$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['TempDir'] = '/tmp';
PMAEOF
    chown -R nobody:nogroup /opt/litepanel/public/phpmyadmin
    rm -f /tmp/pma.tar.gz
    ok "phpMyAdmin installed"
else
    ok "phpMyAdmin exists"
fi

##############################################################################
step "Step 10: Cloudflare Tunnel"
##############################################################################
info "Connecting to Cloudflare API..."

CF_ACCOUNT_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.result[0].id // empty')

if [[ -z "$CF_ACCOUNT_ID" ]]; then
    fail "Cannot get Cloudflare Account ID. Check API token."
fi
ok "Account ID: ${CF_ACCOUNT_ID}"

CF_ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.result[0].id // empty')

if [[ -z "$CF_ZONE_ID" ]]; then
    fail "Cannot get Zone ID for ${DOMAIN}. Is domain added to Cloudflare?"
fi
ok "Zone ID: ${CF_ZONE_ID}"

TUNNEL_NAME="litepanel-$(hostname)"
TUNNEL_SECRET=$(openssl rand -base64 32)

TUNNEL_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${TUNNEL_NAME}\",\"tunnel_secret\":\"${TUNNEL_SECRET}\"}")

TUNNEL_ID=$(echo "$TUNNEL_RESPONSE" | jq -r '.result.id // empty')

if [[ -z "$TUNNEL_ID" ]]; then
    info "Tunnel may exist, searching..."
    TUNNEL_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
fi

if [[ -z "$TUNNEL_ID" ]]; then
    fail "Failed to create Cloudflare Tunnel"
fi
ok "Tunnel ID: ${TUNNEL_ID}"

for SUB in "" "panel" "db"; do
    [[ -z "$SUB" ]] && RN="${DOMAIN}" || RN="${SUB}.${DOMAIN}"
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"CNAME\",\"name\":\"${RN}\",\"content\":\"${TUNNEL_ID}.cfargotunnel.com\",\"proxied\":true}" > /dev/null 2>&1
    ok "DNS: ${RN}"
done

mkdir -p /etc/cloudflared

cat > /etc/cloudflared/credentials.json << CREDEOF
{"AccountTag":"${CF_ACCOUNT_ID}","TunnelID":"${TUNNEL_ID}","TunnelSecret":"${TUNNEL_SECRET}"}
CREDEOF

cat > /etc/cloudflared/config.yml << CFGEOF
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/credentials.json
ingress:
  - hostname: panel.${DOMAIN}
    service: http://localhost:2087
  - hostname: db.${DOMAIN}
    service: http://localhost:2087
  - hostname: ${DOMAIN}
    service: http://localhost:8080
  - hostname: "*.${DOMAIN}"
    service: http://localhost:8080
  - service: http_status:404
CFGEOF

chmod 600 /etc/cloudflared/credentials.json

cat > /etc/systemd/system/cloudflared.service << 'XEOF'
[Unit]
Description=Cloudflare Tunnel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
XEOF

systemctl daemon-reload
systemctl enable cloudflared
systemctl restart cloudflared
sleep 3
systemctl is-active --quiet cloudflared && ok "Tunnel running" || info "Tunnel may need time to start"

##############################################################################
step "Step 11: Firewall"
##############################################################################
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow 22/tcp > /dev/null 2>&1
ufw allow from 192.168.0.0/16 to any port 2087 > /dev/null 2>&1
ufw allow from 192.168.0.0/16 to any port 8080 > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1
ok "Firewall configured"

##############################################################################
step "Step 12: Save Credentials"
##############################################################################

cat > /root/.litepanel_credentials << CREDFILE
============================================
  LitePanel Credentials
============================================

Panel Admin:
  Username: admin
  Password: ${ADMIN_PASS}

Database (for phpMyAdmin):
  DB Name:  litepanel_db
  Username: litepanel_user
  Password: ${DB_USER_PASS}

Local Access:
  Panel: http://192.168.1.76:2087
  Web:   http://192.168.1.76:8080

Remote Access:
  Panel: https://panel.${DOMAIN}
  Web:   https://${DOMAIN}

Tunnel ID: ${TUNNEL_ID}
============================================
CREDFILE
chmod 600 /root/.litepanel_credentials

##############################################################################
step "INSTALLATION COMPLETE"
##############################################################################
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  LitePanel Installed Successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Panel:    ${CYAN}http://192.168.1.76:2087${NC}"
echo -e "  Username: ${CYAN}admin${NC}"
echo -e "  Password: ${CYAN}${ADMIN_PASS}${NC}"
echo ""
echo -e "  Remote:   ${CYAN}https://panel.${DOMAIN}${NC}"
echo ""
echo "  Credentials: /root/.litepanel_credentials"
echo ""
echo "--- Quick Test ---"
curl -s -o /dev/null -w "Panel: HTTP %{http_code}\n" http://localhost:2087/ 2>/dev/null
curl -s -o /dev/null -w "Web:   HTTP %{http_code}\n" http://localhost:8080/ 2>/dev/null
echo ""
