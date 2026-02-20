cat > /root/install.sh << 'MAINEOF'
#!/bin/bash
###############################################################################
# LitePanel Installer v2.0 - FINAL (All-in-One)
# Ubuntu 22.04 + OpenLiteSpeed + MariaDB + Cloudflare Tunnel
# No patches needed. No repair needed.
###############################################################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!!]${NC} $1"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}═══════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════${NC}"; }

[[ $EUID -ne 0 ]] && fail "Run as root"

###############################################################################
# COLLECT INFO
###############################################################################
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    LitePanel Installer v2.0 FINAL     ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════╝${NC}"
echo ""

read -rp "Cloudflare Email: " CF_EMAIL
[[ -z "$CF_EMAIL" ]] && fail "Email required"
read -rp "Cloudflare API Token: " CF_TOKEN
[[ -z "$CF_TOKEN" ]] && fail "Token required"
read -rp "Main Domain (e.g. example.com): " DOMAIN
[[ -z "$DOMAIN" ]] && fail "Domain required"

echo ""
info "Email:  $CF_EMAIL"
info "Domain: $DOMAIN"
info "Panel:  panel.$DOMAIN"
info "DB:     db.$DOMAIN"
echo ""
read -rp "Continue? (y/n): " CONFIRM
[[ "$CONFIRM" != "y" ]] && exit 0

###############################################################################
# SAFE PASSWORDS (alphanumeric only - no bash issues)
###############################################################################
genpw() { openssl rand -hex "${1:-16}"; }

ADMIN_PASS=$(genpw 12)
DB_ROOT_PASS=$(genpw 16)
DB_USER_PASS=$(genpw 16)
OLS_ADMIN_PASS=$(genpw 12)
PMA_BLOWFISH=$(genpw 32)
CSRF_SECRET=$(genpw 32)
TUNNEL_NAME="litepanel-$(hostname -s)"

###############################################################################
step "1/12 - System Update & Prerequisites"
###############################################################################
dpkg --configure -a 2>/dev/null || true
apt --fix-broken install -y 2>/dev/null || true
apt-get update -y
apt-get upgrade -y
apt-get install -y software-properties-common apt-transport-https \
    ca-certificates curl wget unzip gnupg lsb-release cron procps \
    net-tools bc jq ufw fail2ban
info "System updated"

###############################################################################
step "2/12 - Install OpenLiteSpeed + PHP 8.1"
###############################################################################
if [[ ! -f /usr/local/lsws/bin/lswsctrl ]]; then
    wget -qO - https://repo.litespeed.sh | bash 2>/dev/null || true
    apt-get update -y
    apt-get install -y openlitespeed
fi

apt-get install -y lsphp81 lsphp81-common lsphp81-mysql lsphp81-opcache \
    lsphp81-curl lsphp81-mbstring lsphp81-xml lsphp81-zip lsphp81-gd \
    lsphp81-intl lsphp81-imap 2>/dev/null || true

LSPHP="/usr/local/lsws/lsphp81/bin/lsphp"
[[ ! -f "$LSPHP" ]] && LSPHP=$(find /usr/local/lsws/ -name "lsphp" -path "*/81/*" 2>/dev/null | head -1)
[[ ! -f "$LSPHP" ]] && fail "lsphp81 not found"

/usr/local/lsws/admin/misc/admpass.sh <<EOF
admin
${OLS_ADMIN_PASS}
${OLS_ADMIN_PASS}
EOF
info "OpenLiteSpeed + PHP 8.1 ready"

###############################################################################
# Generate admin password hash (needs PHP)
###############################################################################
ADMIN_HASH=$("$LSPHP" -r "echo password_hash('${ADMIN_PASS}', PASSWORD_DEFAULT);" 2>/dev/null)
[[ -z "$ADMIN_HASH" ]] && fail "Cannot generate password hash"

###############################################################################
step "3/12 - Install & Configure MariaDB"
###############################################################################
# Clean broken state if exists
if dpkg -l 2>/dev/null | grep -q "mariadb-server" && ! systemctl is-active --quiet mariadb 2>/dev/null; then
    warn "Broken MariaDB detected, purging..."
    systemctl stop mariadb 2>/dev/null || true
    killall -9 mysqld mysqld_safe 2>/dev/null || true
    sleep 2
    apt-get purge -y mariadb-server mariadb-client mariadb-common galera-4 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    rm -rf /var/lib/mysql /etc/mysql /var/log/mysql /run/mysqld
    dpkg --configure -a 2>/dev/null || true
    apt --fix-broken install -y 2>/dev/null || true
fi

if ! command -v mariadb &>/dev/null; then
    apt-get install -y mariadb-server mariadb-client
fi

systemctl enable mariadb
systemctl start mariadb
sleep 3

if ! systemctl is-active --quiet mariadb; then
    fail "MariaDB failed to start"
fi

# === KEY FIX: Set root with mysql_native_password ===
mariadb << EOSQL
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DB_ROOT_PASS}');
UPDATE mysql.user SET plugin='mysql_native_password' WHERE User='root' AND Host='localhost';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
EOSQL

# Create .my.cnf immediately (for cron & shell commands)
cat > /root/.my.cnf << MYCNF
[client]
user=root
password=${DB_ROOT_PASS}
[mysqldump]
user=root
password=${DB_ROOT_PASS}
MYCNF
chmod 600 /root/.my.cnf

# Verify root login works
if ! mariadb -u root -p"${DB_ROOT_PASS}" -e "SELECT 1" &>/dev/null; then
    fail "MariaDB root login failed"
fi
info "MariaDB installed & root configured with mysql_native_password"

###############################################################################
step "4/12 - Create Database, Tables & Panel User"
###############################################################################
mariadb -u root -p"${DB_ROOT_PASS}" << EOSQL
CREATE DATABASE IF NOT EXISTS litepanel_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS 'litepanel_user'@'localhost';
CREATE USER 'litepanel_user'@'localhost' IDENTIFIED BY '${DB_USER_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'litepanel_user'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOSQL

mariadb -u root -p"${DB_ROOT_PASS}" litepanel_db << 'EOSQL'
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
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    document_root VARCHAR(512) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active','inactive') DEFAULT 'active'
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(64) DEFAULT NULL,
    success TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
EOSQL

# Insert admin (use printf to safely handle $ in hash)
printf "DELETE FROM users WHERE username='admin'; INSERT INTO users (username,password) VALUES ('admin','%s');\n" "$ADMIN_HASH" | mariadb -u root -p"${DB_ROOT_PASS}" litepanel_db
info "Database & tables created"

###############################################################################
step "5/12 - Create Panel PHP Application"
###############################################################################
mkdir -p /opt/litepanel/{public,includes,sessions,logs,data,backups}
mkdir -p /var/www/html

# ---- config.php ----
cat > /opt/litepanel/includes/config.php << XEOF
<?php
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'litepanel_db');
define('DB_USER', 'litepanel_user');
define('DB_PASS', '${DB_USER_PASS}');
define('DB_ROOT_PASS', '${DB_ROOT_PASS}');
define('PANEL_DOMAIN', '${DOMAIN}');
define('CSRF_SECRET', '${CSRF_SECRET}');
define('BASE_PATH', '/opt/litepanel');
define('PANEL_VERSION', '2.0.0');
define('SESSION_LIFETIME', 3600);
session_save_path(BASE_PATH . '/sessions');
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', BASE_PATH . '/logs/php_error.log');
XEOF

# ---- database.php ----
cat > /opt/litepanel/includes/database.php << 'XEOF'
<?php
class Database {
    private static $instance = null;
    private $pdo;
    private function __construct() {
        try {
            $this->pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
        } catch (PDOException $e) { error_log("DB: ".$e->getMessage()); die("Database connection error."); }
    }
    public static function getInstance() { if (self::$instance === null) self::$instance = new self(); return self::$instance; }
    public function query($sql, $params = []) { $s = $this->pdo->prepare($sql); $s->execute($params); return $s; }
    public function fetch($sql, $params = []) { return $this->query($sql, $params)->fetch(); }
    public function fetchAll($sql, $params = []) { return $this->query($sql, $params)->fetchAll(); }
    public function lastId() { return $this->pdo->lastInsertId(); }
    public function getPdo() { return $this->pdo; }
}
XEOF

# ---- auth.php ----
cat > /opt/litepanel/includes/auth.php << 'XEOF'
<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/security.php';

function startSession() { if (session_status() === PHP_SESSION_NONE) session_start(); }
function isLoggedIn() { startSession(); return isset($_SESSION['user_id'],$_SESSION['username']); }
function requireLogin() { if (!isLoggedIn()) { header('Location: /index.php'); exit; } }
function e($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

function login($username, $password) {
    $db = Database::getInstance();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $user = $db->fetch("SELECT * FROM users WHERE username = ?", [$username]);
    if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time())
        return ['success' => false, 'message' => 'Account locked. Try again later.'];
    if ($user && password_verify($password, $user['password'])) {
        startSession(); session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['login_time'] = time();
        $db->query("UPDATE users SET last_login=NOW(), failed_attempts=0 WHERE id=?", [$user['id']]);
        $db->query("INSERT INTO login_log (ip_address,username,success) VALUES (?,?,1)", [$ip,$username]);
        return ['success' => true];
    }
    if ($user) {
        $a = $user['failed_attempts'] + 1;
        $lock = $a >= 5 ? ", locked_until=DATE_ADD(NOW(), INTERVAL 15 MINUTE)" : "";
        $db->query("UPDATE users SET failed_attempts={$a}{$lock} WHERE id=?", [$user['id']]);
    }
    $db->query("INSERT INTO login_log (ip_address,username,success) VALUES (?,?,0)", [$ip,$username]);
    return ['success' => false, 'message' => 'Invalid username or password.'];
}

function logout() {
    startSession(); $_SESSION = [];
    if (ini_get("session.use_cookies")) { $p=session_get_cookie_params(); setcookie(session_name(),'',time()-42000,$p["path"],$p["domain"],$p["secure"],$p["httponly"]); }
    session_destroy(); header('Location: /index.php'); exit;
}
XEOF

# ---- security.php ----
cat > /opt/litepanel/includes/security.php << 'XEOF'
<?php
function generateCsrfToken() { if(empty($_SESSION['csrf_token'])) $_SESSION['csrf_token']=bin2hex(random_bytes(32)); return $_SESSION['csrf_token']; }
function validateCsrf($t) { return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'],$t); }
function securityHeaders() {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate');
}
XEOF

# ---- functions.php ----
cat > /opt/litepanel/includes/functions.php << 'XEOF'
<?php
function getSystemInfo() {
    $i = ['hostname'=>gethostname(),'os'=>php_uname('s').' '.php_uname('r'),'uptime'=>trim(shell_exec("uptime -p 2>/dev/null")?:'N/A'),'load'=>sys_getloadavg(),'cpu'=>(int)trim(shell_exec("nproc 2>/dev/null")?:'1')];
    $f=shell_exec("free -b 2>/dev/null");
    if(preg_match('/Mem:\s+(\d+)\s+(\d+)/',$f,$m)){$i['mem_total']=$m[1];$i['mem_used']=$m[2];$i['mem_percent']=round(($m[2]/$m[1])*100,1);}
    else{$i['mem_total']=$i['mem_used']=$i['mem_percent']=0;}
    $i['disk_total']=disk_total_space('/');$i['disk_free']=disk_free_space('/');$i['disk_used']=$i['disk_total']-$i['disk_free'];
    $i['disk_percent']=round(($i['disk_used']/$i['disk_total'])*100,1);
    return $i;
}
function formatBytes($b,$p=2){$u=['B','KB','MB','GB','TB'];$b=max($b,0);$pw=floor(($b?log($b):0)/log(1024));$pw=min($pw,count($u)-1);return round($b/(1024**$pw),$p).' '.$u[$pw];}
function svcStatus($s){return trim(shell_exec("systemctl is-active ".escapeshellarg($s)." 2>/dev/null")?:'')==='active';}
function flash($t,$m){$_SESSION['flash']=['type'=>$t,'msg'=>$m];}
function getFlash(){if(isset($_SESSION['flash'])){$f=$_SESSION['flash'];unset($_SESSION['flash']);return $f;}return null;}

class DomainManager {
    private $db;
    public function __construct(){$this->db=Database::getInstance();}
    public function list(){return $this->db->fetchAll("SELECT * FROM domains ORDER BY created_at DESC");}
    public function add($dom){
        $dom=preg_replace('/[^a-zA-Z0-9.\-]/','',$dom);
        if(empty($dom))return['success'=>false,'msg'=>'Invalid domain'];
        $dr="/var/www/{$dom}/public_html";
        try{$this->db->query("INSERT INTO domains (domain,document_root) VALUES (?,?)",[$dom,$dr]);
            if(!is_dir($dr)){mkdir($dr,0755,true);file_put_contents("{$dr}/index.html","<h1>Welcome to {$dom}</h1><p>Hosted on LitePanel</p>");chown($dr,'nobody');chgrp($dr,'nogroup');}
            return['success'=>true,'msg'=>"Domain {$dom} added"];
        }catch(\Exception $e){return['success'=>false,'msg'=>$e->getMessage()];}
    }
    public function remove($id){$this->db->query("DELETE FROM domains WHERE id=?",[(int)$id]);return['success'=>true,'msg'=>'Domain removed'];}
}

class DatabaseManager {
    private $db;
    public function __construct(){$this->db=Database::getInstance();}
    public function listDbs(){
        $r=$this->db->fetchAll("SHOW DATABASES");$skip=['information_schema','performance_schema','mysql','sys'];$out=[];
        foreach($r as $row){$n=reset($row);if(!in_array($n,$skip))$out[]=$n;}return $out;
    }
    public function listUsers(){return $this->db->fetchAll("SELECT User,Host FROM mysql.user WHERE User NOT IN ('root','mysql','mariadb.sys','debian-sys-maint') ORDER BY User");}
    public function createDb($name){
        $name=preg_replace('/[^a-zA-Z0-9_]/','',$name);if(empty($name))return['success'=>false,'msg'=>'Invalid name'];
        try{$this->db->query("CREATE DATABASE IF NOT EXISTS `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");return['success'=>true,'msg'=>"Database {$name} created"];}
        catch(\Exception $e){return['success'=>false,'msg'=>$e->getMessage()];}
    }
    public function dropDb($name){
        $name=preg_replace('/[^a-zA-Z0-9_]/','',$name);
        if(in_array($name,['litepanel_db','mysql','information_schema','performance_schema','sys']))return['success'=>false,'msg'=>'Protected database'];
        try{$this->db->query("DROP DATABASE IF EXISTS `{$name}`");return['success'=>true,'msg'=>"Database {$name} dropped"];}
        catch(\Exception $e){return['success'=>false,'msg'=>$e->getMessage()];}
    }
    public function createUser($user,$pass,$dbname=''){
        $user=preg_replace('/[^a-zA-Z0-9_]/','',$user);if(empty($user)||empty($pass))return['success'=>false,'msg'=>'Invalid input'];
        try{$this->db->query("CREATE USER IF NOT EXISTS ?@'localhost' IDENTIFIED BY ?",[$user,$pass]);
            if(!empty($dbname)){$dbname=preg_replace('/[^a-zA-Z0-9_]/','',$dbname);$this->db->query("GRANT ALL ON `{$dbname}`.* TO ?@'localhost'",[$user]);}
            $this->db->query("FLUSH PRIVILEGES");return['success'=>true,'msg'=>"User {$user} created"];}
        catch(\Exception $e){return['success'=>false,'msg'=>$e->getMessage()];}
    }
}
XEOF

# ---- header.php ----
cat > /opt/litepanel/includes/header.php << 'XEOF'
<?php require_once __DIR__.'/auth.php'; requireLogin(); securityHeaders();
$csrfToken=generateCsrfToken(); ?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel - <?php echo $pageTitle??'Panel';?></title><link rel="stylesheet" href="/style.css"></head><body><div class="layout">
<?php require __DIR__.'/sidebar.php'; ?>
<main class="main-content"><div class="top-bar"><h1><?php echo $pageTitle??'';?></h1>
<div class="user-info"><span><?php echo e($_SESSION['username']);?></span> <a href="/logout.php" class="btn btn-sm btn-danger">Logout</a></div></div>
<div class="content">
<?php $fl=getFlash();if($fl):?><div class="alert alert-<?php echo $fl['type'];?>"><?php echo e($fl['msg']);?></div><?php endif;?>
XEOF

# ---- sidebar.php ----
cat > /opt/litepanel/includes/sidebar.php << 'XEOF'
<aside class="sidebar"><div class="sidebar-header"><h2>LitePanel</h2><small>v<?php echo PANEL_VERSION;?></small></div><nav><ul>
<li><a href="/dashboard.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='dashboard.php'?'active':'';?>">&#127968; Dashboard</a></li>
<li><a href="/domains.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='domains.php'?'active':'';?>">&#127760; Domains</a></li>
<li><a href="/databases.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='databases.php'?'active':'';?>">&#128451; Databases</a></li>
<li><a href="/filemanager.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='filemanager.php'?'active':'';?>">&#128193; File Manager</a></li>
<li><a href="/ssl.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='ssl.php'?'active':'';?>">&#128274; SSL / Tunnel</a></li>
<li><a href="/terminal.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='terminal.php'?'active':'';?>">&#128187; Terminal</a></li>
<li><a href="/backups.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='backups.php'?'active':'';?>">&#128190; Backups</a></li>
<li><a href="/settings.php" class="<?php echo basename($_SERVER['PHP_SELF'])=='settings.php'?'active':'';?>">&#9881; Settings</a></li>
<li><a href="/phpmyadmin/" target="_blank">&#128202; phpMyAdmin</a></li>
</ul></nav><div class="sidebar-footer">&#128100; <?php echo e($_SESSION['username']??'');?></div></aside>
XEOF

# ---- footer.php ----
cat > /opt/litepanel/includes/footer.php << 'XEOF'
</div></main></div></body></html>
XEOF

info "PHP includes created"

###############################################################################
step "6/12 - Create Panel Pages"
###############################################################################

# ---- index.php (login) ----
cat > /opt/litepanel/public/index.php << 'XEOF'
<?php
require_once __DIR__.'/../includes/config.php';
require_once __DIR__.'/../includes/auth.php';
startSession();
if(isLoggedIn()){header('Location: /dashboard.php');exit;}
$error='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    $r=login(trim($_POST['username']??''),$_POST['password']??'');
    if($r['success']){header('Location: /dashboard.php');exit;}
    $error=$r['message'];
}
?><!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel Login</title><link rel="stylesheet" href="/style.css"></head>
<body class="login-body"><div class="login-container"><div class="login-box">
<h1>&#128736; LitePanel</h1><p class="login-sub">Server Management Panel</p>
<?php if($error):?><div class="alert alert-danger"><?php echo htmlspecialchars($error);?></div><?php endif;?>
<form method="POST"><div class="form-group"><label>Username</label><input type="text" name="username" required autofocus></div>
<div class="form-group"><label>Password</label><input type="password" name="password" required></div>
<button type="submit" class="btn btn-primary btn-block">Sign In</button></form></div></div></body></html>
XEOF

# ---- dashboard.php ----
cat > /opt/litepanel/public/dashboard.php << 'XEOF'
<?php $pageTitle='Dashboard'; require __DIR__.'/../includes/header.php';
$sys=getSystemInfo(); $db=Database::getInstance();
$dc=$db->fetch("SELECT COUNT(*) as c FROM domains")['c']??0;
$svcs=['OpenLiteSpeed'=>svcStatus('lsws'),'MariaDB'=>svcStatus('mariadb'),'Cloudflared'=>svcStatus('cloudflared'),'Fail2Ban'=>svcStatus('fail2ban'),'UFW'=>svcStatus('ufw')];
?>
<div class="stats-grid">
<div class="stat-card"><h3>CPU Load</h3><div class="stat-value"><?php echo $sys['load'][0];?></div><p><?php echo $sys['cpu'];?> cores</p></div>
<div class="stat-card"><h3>Memory</h3><div class="stat-value"><?php echo $sys['mem_percent'];?>%</div><p><?php echo formatBytes($sys['mem_used']);?> / <?php echo formatBytes($sys['mem_total']);?></p></div>
<div class="stat-card"><h3>Disk</h3><div class="stat-value"><?php echo $sys['disk_percent'];?>%</div><p><?php echo formatBytes($sys['disk_used']);?> / <?php echo formatBytes($sys['disk_total']);?></p></div>
<div class="stat-card"><h3>Domains</h3><div class="stat-value"><?php echo $dc;?></div><p>Active</p></div>
</div>
<div class="card"><h3>&#128994; Services</h3><div class="svc-grid">
<?php foreach($svcs as $n=>$a):?><div class="svc-item"><span><?php echo $n;?></span><span class="badge <?php echo $a?'badge-success':'badge-danger';?>"><?php echo $a?'Running':'Stopped';?></span></div><?php endforeach;?>
</div></div>
<div class="card"><h3>System Info</h3><table class="table">
<tr><td>Hostname</td><td><?php echo e($sys['hostname']);?></td></tr>
<tr><td>OS</td><td><?php echo e($sys['os']);?></td></tr>
<tr><td>Uptime</td><td><?php echo e($sys['uptime']);?></td></tr>
</table></div>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- domains.php ----
cat > /opt/litepanel/public/domains.php << 'XEOF'
<?php $pageTitle='Domains'; require __DIR__.'/../includes/header.php';
$mgr=new DomainManager();
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='add'){$r=$mgr->add($_POST['domain']??'');flash($r['success']?'success':'danger',$r['msg']);}
    elseif($act==='delete'){$r=$mgr->remove($_POST['id']??0);flash($r['success']?'success':'danger',$r['msg']);}
    header('Location: /domains.php');exit;
}
$domains=$mgr->list();
?>
<div class="card"><h3>Add Domain</h3><form method="POST" class="form-inline">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="add">
<div class="form-group"><input type="text" name="domain" placeholder="example.com" required></div>
<button class="btn btn-success">Add</button></form></div>
<table class="table"><thead><tr><th>Domain</th><th>Document Root</th><th>Status</th><th>Actions</th></tr></thead><tbody>
<?php if(empty($domains)):?><tr><td colspan="4" style="text-align:center;color:#888">No domains</td></tr>
<?php else:foreach($domains as $d):?><tr>
<td><strong><?php echo e($d['domain']);?></strong></td><td><code><?php echo e($d['document_root']);?></code></td>
<td><span class="badge badge-success"><?php echo e($d['status']);?></span></td>
<td><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="delete">
<input type="hidden" name="id" value="<?php echo $d['id'];?>"><button class="btn btn-sm btn-danger">Delete</button></form></td>
</tr><?php endforeach;endif;?></tbody></table>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- databases.php ----
cat > /opt/litepanel/public/databases.php << 'XEOF'
<?php $pageTitle='Databases'; require __DIR__.'/../includes/header.php';
$mgr=new DatabaseManager();
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='create_db'){$r=$mgr->createDb($_POST['dbname']??'');flash($r['success']?'success':'danger',$r['msg']);}
    elseif($act==='drop_db'){$r=$mgr->dropDb($_POST['dbname']??'');flash($r['success']?'success':'danger',$r['msg']);}
    elseif($act==='create_user'){$r=$mgr->createUser($_POST['dbuser']??'',$_POST['dbpass']??bin2hex(random_bytes(8)),$_POST['dbgrant']??'');flash($r['success']?'success':'danger',$r['msg']);}
    header('Location: /databases.php');exit;
}
$dbs=$mgr->listDbs();$users=$mgr->listUsers();
?>
<div class="card"><h3>Create Database</h3><form method="POST" class="form-inline">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="create_db">
<div class="form-group"><input type="text" name="dbname" placeholder="database_name" required pattern="[a-zA-Z0-9_]+"></div>
<button class="btn btn-success">Create</button></form></div>
<div class="card"><h3>Create User</h3><form method="POST" class="form-row">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="create_user">
<div class="form-group"><label>Username</label><input type="text" name="dbuser" required></div>
<div class="form-group"><label>Password</label><input type="text" name="dbpass" placeholder="auto-generate"></div>
<div class="form-group"><label>Grant to DB</label><select name="dbgrant"><option value="">None</option>
<?php foreach($dbs as $d):?><option value="<?php echo e($d);?>"><?php echo e($d);?></option><?php endforeach;?></select></div>
<button class="btn btn-success" style="align-self:flex-end">Create</button></form></div>
<h3>Databases (<?php echo count($dbs);?>)</h3>
<table class="table"><thead><tr><th>Name</th><th>Actions</th></tr></thead><tbody>
<?php foreach($dbs as $d):?><tr><td><strong><?php echo e($d);?></strong></td><td>
<?php if($d!=='litepanel_db'):?><form method="POST" style="display:inline" onsubmit="return confirm('Drop?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="drop_db">
<input type="hidden" name="dbname" value="<?php echo e($d);?>"><button class="btn btn-sm btn-danger">Drop</button></form>
<?php endif;?></td></tr><?php endforeach;?></tbody></table>
<h3>Users</h3><table class="table"><thead><tr><th>User</th><th>Host</th></tr></thead><tbody>
<?php foreach($users as $u):?><tr><td><?php echo e($u['User']);?></td><td><?php echo e($u['Host']);?></td></tr><?php endforeach;?></tbody></table>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- filemanager.php ----
cat > /opt/litepanel/public/filemanager.php << 'XEOF'
<?php $pageTitle='File Manager'; require __DIR__.'/../includes/header.php';
$base='/var/www'; $dir=realpath($_GET['dir']??$base)?:$base;
if(strpos($dir,$base)!==0)$dir=$base;
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='upload'&&isset($_FILES['file'])){$t=$dir.'/'.basename($_FILES['file']['name']);if(strpos(realpath(dirname($t))?:$dir,$base)===0)move_uploaded_file($_FILES['file']['tmp_name'],$t);flash('success','Uploaded');}
    elseif($act==='mkdir'){$n=preg_replace('/[^a-zA-Z0-9._-]/','',$_POST['dirname']??'');if($n)mkdir($dir.'/'.$n,0755);flash('success','Created');}
    elseif($act==='delete'){$t=realpath($dir.'/'.basename($_POST['fname']??''));if($t&&strpos($t,$base)===0&&$t!==$base){is_dir($t)?shell_exec("rm -rf ".escapeshellarg($t)):unlink($t);flash('success','Deleted');}}
    elseif($act==='save'){$t=realpath($dir.'/'.basename($_POST['fname']??''));if($t&&strpos($t,$base)===0)file_put_contents($t,$_POST['content']??'');flash('success','Saved');}
    header("Location: /filemanager.php?dir=".urlencode($dir));exit;
}
$edit=null;$ec='';
if(isset($_GET['edit'])){$ef=realpath($dir.'/'.basename($_GET['edit']));if($ef&&strpos($ef,$base)===0&&is_file($ef)&&filesize($ef)<2097152){$edit=$ef;$ec=file_get_contents($ef);}}
$items=[];if(is_dir($dir)){foreach(scandir($dir) as $f){if($f==='.')continue;$p=$dir.'/'.$f;$items[]=['name'=>$f,'dir'=>is_dir($p),'size'=>is_file($p)?filesize($p):0,'mod'=>filemtime($p),'perm'=>substr(sprintf('%o',fileperms($p)),-4)];}
usort($items,function($a,$b){if($a['name']==='..')return -1;if($b['name']==='..')return 1;if($a['dir']!==$b['dir'])return $b['dir']-$a['dir'];return strcasecmp($a['name'],$b['name']);});}
?>
<div class="breadcrumb">&#128193; <strong><?php echo e($dir);?></strong></div>
<?php if($edit):?>
<div class="card"><h3>Editing: <?php echo e(basename($edit));?></h3><form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="save">
<input type="hidden" name="fname" value="<?php echo e(basename($edit));?>">
<textarea name="content" class="code-editor" rows="25"><?php echo e($ec);?></textarea><br>
<button class="btn btn-success">Save</button> <a href="/filemanager.php?dir=<?php echo urlencode($dir);?>" class="btn btn-secondary">Cancel</a></form></div>
<?php else:?>
<div class="card" style="display:flex;gap:10px;flex-wrap:wrap">
<form method="POST" enctype="multipart/form-data" style="display:flex;gap:10px;align-items:flex-end">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="upload">
<div class="form-group"><label>Upload</label><input type="file" name="file" required></div><button class="btn btn-primary">Upload</button></form>
<form method="POST" style="display:flex;gap:10px;align-items:flex-end">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="mkdir">
<div class="form-group"><label>New Dir</label><input type="text" name="dirname" required></div><button class="btn btn-success">Create</button></form></div>
<table class="table"><thead><tr><th>Name</th><th>Size</th><th>Perms</th><th>Modified</th><th>Actions</th></tr></thead><tbody>
<?php foreach($items as $f):?><tr><td>
<?php if($f['dir']):?><a href="/filemanager.php?dir=<?php echo urlencode($dir.'/'.$f['name']);?>"><strong>&#128193; <?php echo e($f['name']);?>/</strong></a>
<?php else:?>&#128196; <?php echo e($f['name']);endif;?></td>
<td><?php echo $f['dir']?'-':formatBytes($f['size']);?></td><td><code><?php echo $f['perm'];?></code></td>
<td><?php echo date('Y-m-d H:i',$f['mod']);?></td><td>
<?php if(!$f['dir']&&$f['name']!=='..'):?><a href="/filemanager.php?dir=<?php echo urlencode($dir);?>&edit=<?php echo urlencode($f['name']);?>" class="btn btn-sm btn-primary">Edit</a><?php endif;?>
<?php if($f['name']!=='..'):?><form method="POST" style="display:inline" onsubmit="return confirm('Delete?')">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="delete">
<input type="hidden" name="fname" value="<?php echo e($f['name']);?>"><button class="btn btn-sm btn-danger">Del</button></form><?php endif;?></td></tr><?php endforeach;?></tbody></table>
<?php endif; require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- ssl.php ----
cat > /opt/litepanel/public/ssl.php << 'XEOF'
<?php $pageTitle='SSL & Tunnel'; require __DIR__.'/../includes/header.php';
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='restart_tunnel'){shell_exec('sudo systemctl restart cloudflared 2>&1');flash('success','Tunnel restarted');}
    elseif($act==='restart_ols'){shell_exec('sudo /usr/local/lsws/bin/lswsctrl restart 2>&1');flash('success','OLS restarted');}
    header('Location: /ssl.php');exit;
}
$ts=svcStatus('cloudflared');$tc=file_exists('/etc/cloudflared/config.yml')?file_get_contents('/etc/cloudflared/config.yml'):'Not found';
?>
<div class="stats-grid"><div class="stat-card"><h3>Tunnel Status</h3>
<div class="stat-value"><span class="badge <?php echo $ts?'badge-success':'badge-danger';?>"><?php echo $ts?'Running':'Stopped';?></span></div>
<p>SSL is automatic via Cloudflare</p></div></div>
<div class="card"><h3>Controls</h3><div style="display:flex;gap:10px">
<form method="POST"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="restart_tunnel"><button class="btn btn-primary">Restart Tunnel</button></form>
<form method="POST"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="restart_ols"><button class="btn btn-success">Restart OLS</button></form></div></div>
<div class="card"><h3>Tunnel Config</h3><pre class="code-block"><?php echo e($tc);?></pre></div>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- settings.php ----
cat > /opt/litepanel/public/settings.php << 'XEOF'
<?php $pageTitle='Settings'; require __DIR__.'/../includes/header.php';
$db=Database::getInstance();
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='change_pass'){
        $cur=$_POST['cur_pass']??'';$new=$_POST['new_pass']??'';$cfm=$_POST['cfm_pass']??'';
        if(empty($cur)||empty($new))flash('danger','All fields required');
        elseif($new!==$cfm)flash('danger','Passwords do not match');
        elseif(strlen($new)<8)flash('danger','Min 8 characters');
        else{$u=$db->fetch("SELECT * FROM users WHERE id=?",[$_SESSION['user_id']]);
            if($u&&password_verify($cur,$u['password'])){$db->query("UPDATE users SET password=? WHERE id=?",[password_hash($new,PASSWORD_DEFAULT),$_SESSION['user_id']]);flash('success','Password changed');}
            else flash('danger','Current password incorrect');}
    }elseif($act==='restart_svc'){
        $svc=$_POST['svc']??'';$ok=['lsws','mariadb','cloudflared','fail2ban'];
        if(in_array($svc,$ok)){if($svc==='lsws')shell_exec('sudo /usr/local/lsws/bin/lswsctrl restart 2>&1');else shell_exec('sudo systemctl restart '.escapeshellarg($svc).' 2>&1');sleep(2);flash('success',ucfirst($svc).' restarted');}
    }
    header('Location: /settings.php');exit;
}
$user=$db->fetch("SELECT * FROM users WHERE id=?",[$_SESSION['user_id']]);
$logs=$db->fetchAll("SELECT * FROM login_log ORDER BY created_at DESC LIMIT 20");
$svcs=[['id'=>'lsws','name'=>'OpenLiteSpeed'],['id'=>'mariadb','name'=>'MariaDB'],['id'=>'cloudflared','name'=>'Cloudflared'],['id'=>'fail2ban','name'=>'Fail2Ban']];
?>
<div class="card"><h3>&#128272; Change Password</h3><form method="POST" style="max-width:400px">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="change_pass">
<div class="form-group"><label>Current Password</label><input type="password" name="cur_pass" required></div>
<div class="form-group"><label>New Password</label><input type="password" name="new_pass" required minlength="8"></div>
<div class="form-group"><label>Confirm</label><input type="password" name="cfm_pass" required></div>
<button class="btn btn-primary">Change</button></form></div>
<div class="card"><h3>&#9881; Services</h3><div class="svc-grid">
<?php foreach($svcs as $s):?><div class="svc-item"><span><span class="badge <?php echo svcStatus($s['id'])?'badge-success':'badge-danger';?>"><?php echo svcStatus($s['id'])?'ON':'OFF';?></span> <?php echo $s['name'];?></span>
<form method="POST"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="restart_svc"><input type="hidden" name="svc" value="<?php echo $s['id'];?>">
<button class="btn btn-sm btn-primary" onclick="return confirm('Restart?')">Restart</button></form></div><?php endforeach;?></div></div>
<div class="card"><h3>&#128373; Login Log</h3><table class="table"><thead><tr><th>Time</th><th>IP</th><th>User</th><th>Status</th></tr></thead><tbody>
<?php foreach($logs as $l):?><tr><td><?php echo e($l['created_at']);?></td><td><code><?php echo e($l['ip_address']);?></code></td>
<td><?php echo e($l['username']??'-');?></td><td><span class="badge <?php echo $l['success']?'badge-success':'badge-danger';?>"><?php echo $l['success']?'OK':'FAIL';?></span></td></tr><?php endforeach;?></tbody></table></div>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- backups.php ----
cat > /opt/litepanel/public/backups.php << 'XEOF'
<?php $pageTitle='Backups'; require __DIR__.'/../includes/header.php';
$bdir=BASE_PATH.'/backups';$mgr=new DatabaseManager();$dmgr=new DomainManager();
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $act=$_POST['action']??'';
    if($act==='backup_db'){$dn=preg_replace('/[^a-zA-Z0-9_]/','',$_POST['dbname']??'');if($dn){$fn=$dn.'_'.date('Ymd_His').'.sql.gz';$fp=$bdir.'/'.$fn;shell_exec("mysqldump --defaults-file=/root/.my.cnf ".escapeshellarg($dn)." 2>/dev/null | gzip > ".escapeshellarg($fp));if(file_exists($fp)&&filesize($fp)>0){chmod($fp,0600);flash('success',"Backup: {$fn}");}else{@unlink($fp);flash('danger','Backup failed');}}}
    elseif($act==='backup_files'){$dom=preg_replace('/[^a-zA-Z0-9.\-]/','',$_POST['domain']??'');$sp="/var/www/{$dom}";if($dom&&is_dir($sp)){$fn=$dom.'_files_'.date('Ymd_His').'.tar.gz';$fp=$bdir.'/'.$fn;shell_exec("tar -czf ".escapeshellarg($fp)." -C /var/www ".escapeshellarg($dom)." 2>/dev/null");if(file_exists($fp)&&filesize($fp)>0){chmod($fp,0600);flash('success',"Backup: {$fn}");}else{@unlink($fp);flash('danger','Failed');}}}
    elseif($act==='delete'){$fn=basename($_POST['file']??'');$fp=$bdir.'/'.$fn;if($fn&&file_exists($fp)){unlink($fp);flash('success','Deleted');}}
    elseif($act==='download'){$fn=basename($_POST['file']??'');$fp=$bdir.'/'.$fn;if($fn&&file_exists($fp)){header('Content-Type: application/octet-stream');header('Content-Disposition: attachment; filename="'.$fn.'"');header('Content-Length: '.filesize($fp));readfile($fp);exit;}}
    if($act!=='download'){header('Location: /backups.php');exit;}
}
$backups=[];if(is_dir($bdir)){foreach(scandir($bdir) as $f){if($f==='.'||$f==='..')continue;$fp=$bdir.'/'.$f;if(is_file($fp))$backups[]=['name'=>$f,'size'=>formatBytes(filesize($fp)),'date'=>date('Y-m-d H:i',filemtime($fp))];} usort($backups,function($a,$b){return strcmp($b['date'],$a['date']);});}
$dbs=$mgr->listDbs();$doms=$dmgr->list();
?>
<div class="stats-grid">
<div class="stat-card"><h3>&#128451; DB Backup</h3><form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="backup_db">
<div class="form-group"><select name="dbname" required><option value="">Select DB</option>
<?php foreach($dbs as $d):?><option><?php echo e($d);?></option><?php endforeach;?></select></div>
<button class="btn btn-success btn-sm">Backup</button></form></div>
<div class="stat-card"><h3>&#128193; File Backup</h3><form method="POST">
<input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="backup_files">
<div class="form-group"><select name="domain" required><option value="">Select Domain</option>
<?php foreach($doms as $d):?><option value="<?php echo e($d['domain']);?>"><?php echo e($d['domain']);?></option><?php endforeach;?></select></div>
<button class="btn btn-success btn-sm">Backup</button></form></div></div>
<table class="table"><thead><tr><th>File</th><th>Size</th><th>Date</th><th>Actions</th></tr></thead><tbody>
<?php if(empty($backups)):?><tr><td colspan="4" style="text-align:center;color:#888">No backups</td></tr>
<?php else:foreach($backups as $b):?><tr><td><code><?php echo e($b['name']);?></code></td><td><?php echo $b['size'];?></td><td><?php echo $b['date'];?></td><td>
<form method="POST" style="display:inline"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="download"><input type="hidden" name="file" value="<?php echo e($b['name']);?>"><button class="btn btn-sm btn-primary">Download</button></form>
<form method="POST" style="display:inline" onsubmit="return confirm('Delete?')"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="file" value="<?php echo e($b['name']);?>"><button class="btn btn-sm btn-danger">Delete</button></form>
</td></tr><?php endforeach;endif;?></tbody></table>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- terminal.php ----
cat > /opt/litepanel/public/terminal.php << 'XEOF'
<?php $pageTitle='Terminal'; require __DIR__.'/../includes/header.php';
$output='';$allowed=['ls','cat','head','tail','wc','df','du','free','uptime','whoami','hostname','uname','date','pwd','ps','top','netstat','ss','ip','systemctl','journalctl','grep','find','which','file','stat','dig','nslookup','ping','curl','tar','chmod','chown','mkdir','touch'];
$blocked=['rm -rf /','mkfs','dd if=',':(){','> /dev/sd','shutdown','reboot','halt','poweroff','passwd','useradd','userdel','/etc/shadow'];
if($_SERVER['REQUEST_METHOD']==='POST'&&validateCsrf($_POST['csrf_token']??'')){
    $cmd=trim($_POST['cmd']??'');
    if(!empty($cmd)){$blk=false;foreach($blocked as $p)if(stripos($cmd,$p)!==false){$blk=true;break;}
        if($blk){$output="BLOCKED: dangerous command";}
        else{$base=basename(explode(' ',$cmd)[0]);$safe=in_array($base,$allowed);
            if($safe){$output=shell_exec($cmd." 2>&1")??'(no output)';}
            else{$output="Command '{$base}' not allowed.\n\nAllowed: ".implode(', ',$allowed);}}}
}
?>
<div class="alert alert-info">Safe mode: only whitelisted commands allowed.</div>
<div style="background:#111;border-radius:8px;padding:20px">
<pre style="color:#0f0;min-height:200px;max-height:500px;overflow:auto;margin-bottom:15px;font-size:13px"><?php echo $output?e($output):'LitePanel Terminal v2.0 - Type a command';?></pre>
<form method="POST" style="display:flex;gap:10px"><input type="hidden" name="csrf_token" value="<?php echo e($csrfToken);?>">
<span style="color:#0f0;padding:8px">$</span><input type="text" name="cmd" style="flex:1;background:#222;border:1px solid #333;color:#0f0;padding:10px;font-family:monospace" autofocus autocomplete="off" placeholder="Enter command...">
<button class="btn btn-success">Run</button></form>
<div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:5px">
<?php foreach(['uptime','free -h','df -h','ps aux --sort=-rss | head -15','systemctl status lsws','systemctl status mariadb','systemctl status cloudflared','ss -tlnp','uname -a'] as $q):?>
<button onclick="document.querySelector('[name=cmd]').value='<?php echo $q;?>';document.querySelector('[name=cmd]').form.submit()" style="background:#222;color:#888;border:1px solid #333;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px"><?php echo $q;?></button>
<?php endforeach;?></div></div>
<?php require __DIR__.'/../includes/footer.php';?>
XEOF

# ---- api.php ----
cat > /opt/litepanel/public/api.php << 'XEOF'
<?php
require_once __DIR__.'/../includes/config.php';
require_once __DIR__.'/../includes/auth.php';
startSession(); header('Content-Type: application/json');
if(!isLoggedIn()){http_response_code(401);echo json_encode(['error'=>'Unauthorized']);exit;}
require_once __DIR__.'/../includes/functions.php';
require_once __DIR__.'/../includes/database.php';
$act=$_GET['action']??'';
if($act==='stats'){$s=getSystemInfo();echo json_encode(['cpu'=>$s['load'][0],'mem'=>$s['mem_percent']??0,'disk'=>$s['disk_percent'],'services'=>['lsws'=>svcStatus('lsws'),'mariadb'=>svcStatus('mariadb'),'cloudflared'=>svcStatus('cloudflared')]]);}
else echo json_encode(['error'=>'Unknown']);
XEOF

# ---- logout.php ----
cat > /opt/litepanel/public/logout.php << 'XEOF'
<?php require_once __DIR__.'/../includes/auth.php'; logout();
XEOF

info "All pages created"

###############################################################################
step "7/12 - Create CSS"
###############################################################################
cat > /opt/litepanel/public/style.css << 'XEOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#333}
.login-body{display:flex;justify-content:center;align-items:center;min-height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
.login-container{width:100%;max-width:400px;padding:20px}
.login-box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.3);text-align:center}
.login-box h1{font-size:2em;margin-bottom:5px;color:#333}
.login-sub{color:#888;margin-bottom:25px}
.layout{display:flex;min-height:100vh}
.sidebar{width:250px;background:#1e293b;color:#fff;flex-shrink:0;display:flex;flex-direction:column}
.sidebar-header{padding:20px;border-bottom:1px solid #334155}
.sidebar-header h2{font-size:1.4em;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-header small{color:#64748b;font-size:.75em}
.sidebar nav{flex:1}
.sidebar nav ul{list-style:none;padding:10px 0}
.sidebar nav a{display:block;padding:12px 20px;color:#94a3b8;text-decoration:none;transition:.2s;border-left:3px solid transparent}
.sidebar nav a:hover,.sidebar nav a.active{background:#334155;color:#fff;border-left-color:#667eea}
.sidebar-footer{padding:15px 20px;border-top:1px solid #334155;color:#64748b;font-size:.85em}
.main-content{flex:1;display:flex;flex-direction:column}
.top-bar{display:flex;justify-content:space-between;align-items:center;padding:15px 25px;background:#fff;border-bottom:1px solid #e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.top-bar h1{font-size:1.3em;color:#1e293b}
.user-info{display:flex;align-items:center;gap:10px;font-size:.9em;color:#64748b}
.content{padding:25px;flex:1}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:25px}
.stat-card{background:#fff;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);border:1px solid #e2e8f0}
.stat-card h3{font-size:.8em;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.stat-value{font-size:2em;font-weight:700;color:#1e293b}
.stat-card p{font-size:.8em;color:#94a3b8;margin-top:4px}
.card{background:#fff;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);border:1px solid #e2e8f0;margin-bottom:20px}
.card h3{margin-bottom:15px;font-size:1.05em;color:#1e293b}
.table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.06);border:1px solid #e2e8f0;margin-bottom:20px}
.table th,.table td{padding:12px 15px;text-align:left;border-bottom:1px solid #f1f5f9}
.table th{background:#f8fafc;font-weight:600;color:#64748b;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}
.table tr:hover{background:#fafbfc}
.form-group{margin-bottom:15px}
.form-group label{display:block;margin-bottom:5px;font-weight:500;font-size:.85em;color:#475569}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:.9em;transition:border .2s}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
.form-inline{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.form-inline .form-group{margin-bottom:0;flex:1;min-width:200px}
.form-row{display:flex;gap:15px;flex-wrap:wrap;align-items:flex-end}
.form-row .form-group{flex:1;min-width:180px}
.btn{display:inline-block;padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-size:.9em;font-weight:500;text-decoration:none;transition:.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 8px rgba(0,0,0,.1)}
.btn-primary{background:#667eea;color:#fff}.btn-primary:hover{background:#5a67d8}
.btn-success{background:#10b981;color:#fff}.btn-success:hover{background:#059669}
.btn-danger{background:#ef4444;color:#fff}.btn-danger:hover{background:#dc2626}
.btn-secondary{background:#6b7280;color:#fff}
.btn-block{width:100%}
.btn-sm{padding:5px 12px;font-size:.8em}
.badge{padding:4px 10px;border-radius:20px;font-size:.75em;font-weight:600}
.badge-success{background:#d1fae5;color:#065f46}
.badge-danger{background:#fee2e2;color:#991b1b}
.badge-warning{background:#fef3c7;color:#92400e}
.alert{padding:12px 16px;border-radius:8px;margin-bottom:15px;font-size:.9em}
.alert-success{background:#d1fae5;color:#065f46;border:1px solid #a7f3d0}
.alert-danger{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
.alert-info{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}
.svc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.svc-item{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0}
.breadcrumb{background:#fff;padding:12px 16px;border-radius:8px;margin-bottom:15px;box-shadow:0 1px 3px rgba(0,0,0,.05);border:1px solid #e2e8f0}
.breadcrumb a{color:#667eea;text-decoration:none}
.code-editor{font-family:'Courier New',monospace;font-size:13px;width:100%;padding:15px;border:1px solid #334155;border-radius:8px;background:#1e293b;color:#e2e8f0;tab-size:4;line-height:1.5}
.code-block{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;font-family:monospace;white-space:pre-wrap}
code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:.85em;color:#475569}
h2,h3{color:#1e293b}
@media(max-width:768px){.layout{flex-direction:column}.sidebar{width:100%;flex-shrink:initial}.stats-grid{grid-template-columns:1fr}.form-inline,.form-row{flex-direction:column}}
XEOF
info "CSS created"

###############################################################################
step "8/12 - Install phpMyAdmin"
###############################################################################
PMA_DIR="/opt/litepanel/public/phpmyadmin"

if [[ ! -d "$PMA_DIR" ]]; then
    cd /tmp
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.tar.gz" -O pma.tar.gz 2>/dev/null || \
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/5.2.0/phpMyAdmin-5.2.0-all-languages.tar.gz" -O pma.tar.gz 2>/dev/null || true
    if [[ -f pma.tar.gz ]]; then
        tar xzf pma.tar.gz
        PMA_EXTRACTED=$(ls -d phpMyAdmin-*-all-languages 2>/dev/null | head -1)
        [[ -n "$PMA_EXTRACTED" ]] && mv "$PMA_EXTRACTED" "$PMA_DIR"
        rm -f pma.tar.gz
    fi
fi

# === KEY FIX: phpMyAdmin config with 127.0.0.1 (TCP) ===
if [[ -d "$PMA_DIR" ]]; then
    cat > "${PMA_DIR}/config.inc.php" << PMAEOF
<?php
\$cfg['blowfish_secret'] = '${PMA_BLOWFISH}';
\$i = 0; \$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '3306';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['TempDir'] = '/tmp/phpmyadmin';
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
PMAEOF
    mkdir -p /tmp/phpmyadmin
    chmod 777 /tmp/phpmyadmin
    chown -R nobody:nogroup "$PMA_DIR"
    info "phpMyAdmin installed (host=127.0.0.1, TCP mode)"
else
    warn "phpMyAdmin download failed - install manually later"
fi

###############################################################################
step "9/12 - Configure OpenLiteSpeed"
###############################################################################

# Panel vhost config with phpMyAdmin context
cat > /opt/litepanel/vhconf.conf << 'XEOF'
docRoot                   /opt/litepanel/public
enableGzip                1
enableBr                  1

index  {
  useServer               0
  indexFiles               index.php, index.html
}

context /phpmyadmin/ {
  location                /opt/litepanel/public/phpmyadmin/
  allowBrowse             1
  indexFiles               index.php
  accessControl  {
    allow                  *
  }
  phpIniOverride  {
    php_value upload_max_filesize 128M
    php_value post_max_size 128M
    php_value memory_limit 256M
    php_value max_execution_time 300
  }
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/litepanel_lsphp.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
  initTimeout             60
  retryTimeout            0
  persistConn             1
  pcKeepAliveTimeout      60
  respBuffer              0
  autoStart               2
  path                    /usr/local/lsws/lsphp81/bin/lsphp
  backlog                 100
  instances               1
  runOnStartUp            2
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

phpIniOverride  {
  php_value upload_max_filesize 64M
  php_value post_max_size 64M
  php_value memory_limit 256M
  php_value session.save_path /opt/litepanel/sessions
  php_flag display_errors Off
  php_flag log_errors On
  php_value error_log /opt/litepanel/logs/php_error.log
}

accesslog /opt/litepanel/logs/access.log {
  useServer               0
  rollingSize             100M
}
errorlog /opt/litepanel/logs/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}
XEOF

# Default website vhost
mkdir -p /usr/local/lsws/conf/vhosts/default
cat > /var/www/vhconf.conf << 'XEOF'
docRoot                   /var/www/html
enableGzip                1
index  {
  useServer               0
  indexFiles               index.html, index.php
}
scripthandler  {
  add                     lsapi:lsphp81 php
}
rewrite  {
  enable                  1
  autoLoadHtaccess        1
}
XEOF

cat > /var/www/html/index.html << 'XEOF'
<!DOCTYPE html><html><head><title>LitePanel</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px;background:#f0f2f5;color:#333}h1{font-size:2.5em;margin-bottom:10px}p{color:#666}</style></head>
<body><h1>&#128736; LitePanel</h1><p>Your server is running. Configure domains in the panel.</p></body></html>
XEOF

# Main OLS config
cp /usr/local/lsws/conf/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf.bak."$(date +%s)" 2>/dev/null || true

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
  enableGzipCompress      1
  enableDynGzipCompress   1
  gzipCompressLevel       6
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
  restrained              1
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

mkdir -p /tmp/lshttpd
chown nobody:nogroup /tmp/lshttpd 2>/dev/null || true

/usr/local/lsws/bin/lswsctrl stop 2>/dev/null || true
sleep 2
/usr/local/lsws/bin/lswsctrl start
sleep 2
info "OpenLiteSpeed configured"

###############################################################################
step "10/12 - Cloudflare Tunnel"
###############################################################################
if ! command -v cloudflared &>/dev/null; then
    curl -sL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-archive-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflared.list
    apt-get update -qq && apt-get install -y cloudflared
fi

CF_ACCOUNT_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
[[ -z "$CF_ACCOUNT_ID" ]] && fail "Cannot get Cloudflare Account ID. Check API token."
info "Account ID: ${CF_ACCOUNT_ID}"

CF_ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
[[ -z "$CF_ZONE_ID" ]] && fail "Cannot get Zone ID for ${DOMAIN}"
info "Zone ID: ${CF_ZONE_ID}"

TUNNEL_SECRET=$(openssl rand -base64 32)
TUNNEL_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${TUNNEL_NAME}\",\"tunnel_secret\":\"${TUNNEL_SECRET}\"}")
TUNNEL_ID=$(echo "$TUNNEL_RESPONSE" | jq -r '.result.id // empty')

if [[ -z "$TUNNEL_ID" ]]; then
    TUNNEL_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
fi
[[ -z "$TUNNEL_ID" ]] && fail "Failed to create/find tunnel"
info "Tunnel ID: ${TUNNEL_ID}"

# DNS records
for SUB in "" "panel" "db"; do
    [[ -z "$SUB" ]] && RN="${DOMAIN}" || RN="${SUB}.${DOMAIN}"
    # Delete existing then create
    EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?type=CNAME&name=${RN}" \
        -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" | jq -r '.result[0].id // empty')
    [[ -n "$EXISTING" ]] && curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${EXISTING}" \
        -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" &>/dev/null
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
        -d "{\"type\":\"CNAME\",\"name\":\"${RN}\",\"content\":\"${TUNNEL_ID}.cfargotunnel.com\",\"proxied\":true}" &>/dev/null
    info "DNS: ${RN}"
done

mkdir -p /etc/cloudflared
cat > /etc/cloudflared/credentials.json << CREDEOF
{"AccountTag":"${CF_ACCOUNT_ID}","TunnelID":"${TUNNEL_ID}","TunnelSecret":"${TUNNEL_SECRET}"}
CREDEOF
chmod 600 /etc/cloudflared/credentials.json

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
chmod 600 /etc/cloudflared/config.yml

# Systemd service
systemctl stop cloudflared 2>/dev/null || true
cloudflared service uninstall 2>/dev/null || true
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
svc_status=$(systemctl is-active cloudflared 2>/dev/null || echo "starting")
info "Cloudflared: ${svc_status}"

###############################################################################
step "11/12 - Security (Firewall, Fail2Ban, Sudoers, Monitoring)"
###############################################################################

# UFW
ufw --force reset &>/dev/null
ufw default deny incoming &>/dev/null
ufw default allow outgoing &>/dev/null
ufw allow 22/tcp &>/dev/null
ufw --force enable &>/dev/null
info "Firewall: only port 22 open"

# Fail2Ban
cat > /etc/fail2ban/jail.local << 'XEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
banaction = ufw
[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 7200
XEOF
systemctl enable fail2ban
systemctl restart fail2ban
info "Fail2Ban configured"

# Sudoers for nobody (OLS process)
cat > /etc/sudoers.d/litepanel << 'XEOF'
nobody ALL=(ALL) NOPASSWD: /usr/local/lsws/bin/lswsctrl *
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart cloudflared
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lsws
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart mariadb
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart fail2ban
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *
XEOF
chmod 440 /etc/sudoers.d/litepanel
info "Sudoers configured"

# Monitor script
cat > /usr/local/bin/litepanel-monitor.sh << 'XEOF'
#!/bin/bash
LOG="/var/log/litepanel-monitor.log"
for svc in lsws mariadb cloudflared; do
    if ! systemctl is-active --quiet "$svc"; then
        systemctl restart "$svc" 2>/dev/null
        echo "$(date): Restarted ${svc}" >> "$LOG"
    fi
done
DISK=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
[[ "$DISK" -gt 90 ]] && echo "$(date): WARN disk ${DISK}%" >> "$LOG"
XEOF
chmod 750 /usr/local/bin/litepanel-monitor.sh

# Cron
cat > /etc/cron.d/litepanel << 'XEOF'
*/5 * * * * root /usr/local/bin/litepanel-monitor.sh >/dev/null 2>&1
0 3 * * 0 root mariadb --defaults-file=/root/.my.cnf litepanel_db -e "DELETE FROM login_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);" >/dev/null 2>&1
0 4 * * * root find /opt/litepanel/sessions -type f -mtime +1 -delete >/dev/null 2>&1
XEOF
chmod 644 /etc/cron.d/litepanel

# Logrotate
cat > /etc/logrotate.d/litepanel << 'XEOF'
/opt/litepanel/logs/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 640 nobody nogroup
}
XEOF
info "Monitoring & cron configured"

###############################################################################
step "12/12 - Permissions & Final Start"
###############################################################################
chown -R nobody:nogroup /opt/litepanel
chmod -R 750 /opt/litepanel
chmod 700 /opt/litepanel/sessions /opt/litepanel/data /opt/litepanel/backups
find /opt/litepanel/public -type f -exec chmod 644 {} \;
chmod 600 /opt/litepanel/includes/config.php

if [[ -d "$PMA_DIR" ]]; then
    chown -R nobody:nogroup "$PMA_DIR"
    find "$PMA_DIR" -type d -exec chmod 750 {} \;
    find "$PMA_DIR" -type f -exec chmod 640 {} \;
fi

chown -R nobody:nogroup /var/www
chmod -R 755 /var/www

# Restart everything
systemctl restart mariadb
/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || true
systemctl restart cloudflared 2>/dev/null || true
sleep 3

###############################################################################
# SAVE CREDENTIALS
###############################################################################
cat > /root/.litepanel_credentials << CREDEOF
================================================
  LitePanel v2.0 Credentials
  Generated: $(date)
================================================

Panel Admin:
  Username: admin
  Password: ${ADMIN_PASS}

MariaDB Root:
  Password: ${DB_ROOT_PASS}

Panel Database:
  DB Name:  litepanel_db
  Username: litepanel_user
  Password: ${DB_USER_PASS}

phpMyAdmin Login:
  User: root
  Pass: ${DB_ROOT_PASS}

OLS WebAdmin (https://localhost:7080):
  User: admin
  Pass: ${OLS_ADMIN_PASS}

Remote Access:
  Panel:      https://panel.${DOMAIN}
  Website:    https://${DOMAIN}
  phpMyAdmin: https://panel.${DOMAIN}/phpmyadmin/

Tunnel: ${TUNNEL_NAME} (${TUNNEL_ID})
================================================
CREDEOF
chmod 600 /root/.litepanel_credentials

###############################################################################
# SUMMARY
###############################################################################
OLS_S=$(systemctl is-active lsws 2>/dev/null || echo "?")
DB_S=$(systemctl is-active mariadb 2>/dev/null || echo "?")
CF_S=$(systemctl is-active cloudflared 2>/dev/null || echo "?")
F2B_S=$(systemctl is-active fail2ban 2>/dev/null || echo "?")

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     LitePanel v2.0 - INSTALLED!           ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                           ║${NC}"
echo -e "${GREEN}║  Panel:  ${CYAN}https://panel.${DOMAIN}${GREEN}${NC}"
echo -e "${GREEN}║  Web:    ${CYAN}https://${DOMAIN}${GREEN}${NC}"
echo -e "${GREEN}║  PMA:    ${CYAN}https://panel.${DOMAIN}/phpmyadmin/${GREEN}${NC}"
echo -e "${GREEN}║                                           ║${NC}"
echo -e "${GREEN}║  Panel Login:                             ║${NC}"
echo -e "${GREEN}║    User: ${YELLOW}admin${NC}"
echo -e "${GREEN}║    Pass: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "${GREEN}║                                           ║${NC}"
echo -e "${GREEN}║  phpMyAdmin Login:                        ║${NC}"
echo -e "${GREEN}║    User: ${YELLOW}root${NC}"
echo -e "${GREEN}║    Pass: ${YELLOW}${DB_ROOT_PASS}${NC}"
echo -e "${GREEN}║                                           ║${NC}"
echo -e "${GREEN}║  Services:                                ║${NC}"
echo -e "${GREEN}║    OpenLiteSpeed: ${OLS_S}${NC}"
echo -e "${GREEN}║    MariaDB:       ${DB_S}${NC}"
echo -e "${GREEN}║    Cloudflared:   ${CF_S}${NC}"
echo -e "${GREEN}║    Fail2Ban:      ${F2B_S}${NC}"
echo -e "${GREEN}║                                           ║${NC}"
echo -e "${GREEN}║  Credentials: /root/.litepanel_credentials║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""

# Quick test
echo "--- Quick Test ---"
curl -s -o /dev/null -w "Panel (2087): HTTP %{http_code}\n" http://localhost:2087/ 2>/dev/null || true
curl -s -o /dev/null -w "Web   (8080): HTTP %{http_code}\n" http://localhost:8080/ 2>/dev/null || true
mariadb -u root -p"${DB_ROOT_PASS}" -e "SELECT 'MariaDB: OK'" 2>/dev/null || echo "MariaDB: connection test"
echo ""
MAINEOF

chmod +x /root/install.sh
echo "Script saved. Run with: bash /root/install.sh"
