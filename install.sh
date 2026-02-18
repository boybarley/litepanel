```bash
#!/bin/bash
###############################################################################
# LitePanel Auto Installer for Ubuntu 22.04
# Home Server / Lab Edition with Cloudflare Tunnel & Zero Trust
# Version: 1.0.0
###############################################################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

if [[ ! -f /etc/os-release ]] || ! grep -q "22.04" /etc/os-release; then
    log_warn "This script is designed for Ubuntu 22.04. Proceeding anyway..."
fi

###############################################################################
# COLLECT CLOUDFLARE INFO
###############################################################################
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}   LitePanel Installer - Home Server    ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

read -rp "Cloudflare Account Email: " CF_EMAIL
while [[ -z "$CF_EMAIL" ]]; do
    read -rp "Email cannot be empty. Cloudflare Account Email: " CF_EMAIL
done

read -rp "Cloudflare API Token (with Tunnel & DNS permissions): " CF_API_TOKEN
while [[ -z "$CF_API_TOKEN" ]]; do
    read -rp "Token cannot be empty. Cloudflare API Token: " CF_API_TOKEN
done

read -rp "Main Domain (e.g., example.com): " MAIN_DOMAIN
while [[ -z "$MAIN_DOMAIN" ]]; do
    read -rp "Domain cannot be empty. Main Domain: " MAIN_DOMAIN
done

echo ""
log_info "Configuration:"
log_info "  Email:  $CF_EMAIL"
log_info "  Domain: $MAIN_DOMAIN"
log_info "  Panel:  panel.$MAIN_DOMAIN"
log_info "  DB:     db.$MAIN_DOMAIN"
echo ""
read -rp "Continue? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    log_error "Aborted by user."
    exit 1
fi

###############################################################################
# VARIABLES
###############################################################################
INSTALL_PATH="/opt/litepanel"
PANEL_PORT=2087
WEB_PORT=8080
TUNNEL_NAME="litepanel-home"

generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' < /dev/urandom | head -c 24 2>/dev/null || openssl rand -base64 24 | head -c 24
}

generate_alphanum_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24 2>/dev/null || openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24
}

ADMIN_PASSWORD=$(generate_alphanum_password)
DB_ROOT_PASSWORD=$(generate_alphanum_password)
DB_NAME="litepanel_db"
DB_USER="litepanel_user"
DB_PASSWORD=$(generate_alphanum_password)
OLS_ADMIN_PASSWORD=$(generate_alphanum_password)
PANEL_SESSION_SECRET=$(generate_alphanum_password)
CSRF_SECRET=$(generate_alphanum_password)

CREDS_FILE="/root/.litepanel_credentials"

###############################################################################
# STEP 1: System Update
###############################################################################
log_step "1/15 - Updating system..."
apt-get update -y
apt-get upgrade -y
apt-get install -y software-properties-common apt-transport-https ca-certificates \
    curl wget unzip gnupg lsb-release cron procps net-tools bc

###############################################################################
# STEP 2: Install OpenLiteSpeed
###############################################################################
log_step "2/15 - Installing OpenLiteSpeed..."
if ! command -v /usr/local/lsws/bin/lswsctrl &>/dev/null; then
    wget -qO - https://repo.litespeed.sh | bash 2>/dev/null || true
    apt-get update -y
    apt-get install -y openlitespeed
fi

# Install LiteSpeed PHP 8.1
log_step "Installing PHP for OpenLiteSpeed..."
apt-get install -y lsphp81 lsphp81-common lsphp81-mysql lsphp81-opcache \
    lsphp81-curl lsphp81-json lsphp81-mbstring lsphp81-xml \
    lsphp81-zip lsphp81-gd lsphp81-intl lsphp81-imap 2>/dev/null || true

# Fallback if json is built-in
apt-get install -y lsphp81 lsphp81-common lsphp81-mysql lsphp81-opcache \
    lsphp81-curl lsphp81-mbstring lsphp81-xml \
    lsphp81-zip lsphp81-gd lsphp81-intl 2>/dev/null || true

PHP_BIN="/usr/local/lsws/lsphp81/bin/lsphp"
if [[ ! -f "$PHP_BIN" ]]; then
    PHP_BIN=$(find /usr/local/lsws/ -name "lsphp" -path "*/81/*" 2>/dev/null | head -1)
fi

# Set OLS admin password
/usr/local/lsws/admin/misc/admpass.sh <<EOF
admin
${OLS_ADMIN_PASSWORD}
${OLS_ADMIN_PASSWORD}
EOF

###############################################################################
# STEP 3: Install MariaDB
###############################################################################
log_step "3/15 - Installing MariaDB..."
if ! command -v mariadb &>/dev/null; then
    apt-get install -y mariadb-server mariadb-client
fi
systemctl enable mariadb
systemctl start mariadb

# Secure MariaDB
log_step "Securing MariaDB..."
mariadb -u root <<EOSQL || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASSWORD}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOSQL

# Create database and user
mariadb -u root -p"${DB_ROOT_PASSWORD}" <<EOSQL || true
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOSQL

###############################################################################
# STEP 4: Create LitePanel directory structure
###############################################################################
log_step "4/15 - Creating LitePanel directory structure..."
mkdir -p "${INSTALL_PATH}"/{public,includes,sessions,logs,tmp,data}
mkdir -p /home/default/public_html

###############################################################################
# STEP 5: Create LitePanel database tables
###############################################################################
log_step "5/15 - Creating database tables..."
mariadb -u root -p"${DB_ROOT_PASSWORD}" "${DB_NAME}" <<'EOSQL'
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL UNIQUE,
    `password` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `last_login` DATETIME DEFAULT NULL,
    `login_attempts` INT DEFAULT 0,
    `locked_until` DATETIME DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `domains` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `domain_name` VARCHAR(255) NOT NULL UNIQUE,
    `document_root` VARCHAR(512) NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `status` ENUM('active','inactive') DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `login_log` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `ip_address` VARCHAR(45) NOT NULL,
    `username` VARCHAR(64) DEFAULT NULL,
    `success` TINYINT(1) DEFAULT 0,
    `attempted_at` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOSQL

# Insert admin user
ADMIN_HASH=$(php -r "echo password_hash('${ADMIN_PASSWORD}', PASSWORD_BCRYPT);")
if ! command -v php &>/dev/null; then
    ADMIN_HASH=$(/usr/local/lsws/lsphp81/bin/php -r "echo password_hash('${ADMIN_PASSWORD}', PASSWORD_BCRYPT);")
fi

mariadb -u root -p"${DB_ROOT_PASSWORD}" "${DB_NAME}" <<EOSQL
INSERT INTO users (username, password) VALUES ('admin', '${ADMIN_HASH}')
ON DUPLICATE KEY UPDATE password='${ADMIN_HASH}';
EOSQL

###############################################################################
# STEP 6: Generate LitePanel PHP Application
###############################################################################
log_step "6/15 - Generating LitePanel PHP application..."

# config.php
cat > "${INSTALL_PATH}/includes/config.php" <<PHPEOF
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASS', '${DB_PASSWORD}');
define('CSRF_SECRET', '${CSRF_SECRET}');
define('SESSION_NAME', 'LITEPANEL_SID');
define('SESSION_LIFETIME', 3600);
define('RATE_LIMIT_ATTEMPTS', 5);
define('RATE_LIMIT_WINDOW', 900);
define('INSTALL_PATH', '${INSTALL_PATH}');
define('OLS_BIN', '/usr/local/lsws/bin/lswsctrl');
define('PANEL_VERSION', '1.0.0');
PHPEOF

# database.php
cat > "${INSTALL_PATH}/includes/database.php" <<'PHPEOF'
<?php
class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        try {
            $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            error_log('Database connection failed: ' . $e->getMessage());
            die('Database connection error.');
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getPdo() {
        return $this->pdo;
    }

    public function query($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public function fetchOne($sql, $params = []) {
        return $this->query($sql, $params)->fetch();
    }

    public function fetchAll($sql, $params = []) {
        return $this->query($sql, $params)->fetchAll();
    }
}
PHPEOF

# auth.php
cat > "${INSTALL_PATH}/includes/auth.php" <<'PHPEOF'
<?php
class Auth {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    public function generateCsrfToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public function validateCsrfToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    public function isRateLimited($ip) {
        $result = $this->db->fetchOne(
            "SELECT COUNT(*) as cnt FROM login_log WHERE ip_address = ? AND success = 0 AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)",
            [$ip, RATE_LIMIT_WINDOW]
        );
        return ($result['cnt'] >= RATE_LIMIT_ATTEMPTS);
    }

    public function logAttempt($ip, $username, $success) {
        $this->db->query(
            "INSERT INTO login_log (ip_address, username, success) VALUES (?, ?, ?)",
            [$ip, $username, $success ? 1 : 0]
        );
    }

    public function login($username, $password) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        if ($this->isRateLimited($ip)) {
            return ['success' => false, 'message' => 'Too many login attempts. Please wait 15 minutes.'];
        }

        $user = $this->db->fetchOne("SELECT * FROM users WHERE username = ?", [$username]);

        if ($user && password_verify($password, $user['password'])) {
            $this->logAttempt($ip, $username, true);
            $this->db->query("UPDATE users SET last_login = NOW(), login_attempts = 0 WHERE id = ?", [$user['id']]);

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();

            session_regenerate_id(true);
            return ['success' => true];
        }

        $this->logAttempt($ip, $username, false);
        return ['success' => false, 'message' => 'Invalid username or password.'];
    }

    public function isLoggedIn() {
        if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
            return false;
        }
        if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > SESSION_LIFETIME) {
            $this->logout();
            return false;
        }
        return true;
    }

    public function logout() {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params['path'], $params['domain'],
                $params['secure'], $params['httponly']
            );
        }
        session_destroy();
    }

    public function requireLogin() {
        if (!$this->isLoggedIn()) {
            header('Location: /index.php');
            exit;
        }
    }
}
PHPEOF

# functions.php
cat > "${INSTALL_PATH}/includes/functions.php" <<'PHPEOF'
<?php
class SystemInfo {
    public static function getCpuUsage() {
        $load = sys_getloadavg();
        $cores = (int)trim(shell_exec("nproc 2>/dev/null") ?: "1");
        $usage = round(($load[0] / $cores) * 100, 1);
        return min(100, $usage);
    }

    public static function getCpuInfo() {
        $load = sys_getloadavg();
        $cores = (int)trim(shell_exec("nproc 2>/dev/null") ?: "1");
        $model = trim(shell_exec("grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2") ?: "Unknown");
        return [
            'model' => $model,
            'cores' => $cores,
            'load' => $load,
            'usage' => self::getCpuUsage()
        ];
    }

    public static function getMemoryInfo() {
        $free = shell_exec("free -b 2>/dev/null");
        if (!$free) return ['total' => 0, 'used' => 0, 'free' => 0, 'percent' => 0];

        preg_match('/Mem:\s+(\d+)\s+(\d+)\s+(\d+)/', $free, $matches);
        if (count($matches) < 4) return ['total' => 0, 'used' => 0, 'free' => 0, 'percent' => 0];

        $total = (int)$matches[1];
        $used = (int)$matches[2];
        $free_mem = (int)$matches[3];
        $percent = $total > 0 ? round(($used / $total) * 100, 1) : 0;

        return [
            'total' => self::formatBytes($total),
            'used' => self::formatBytes($used),
            'free' => self::formatBytes($free_mem),
            'percent' => $percent
        ];
    }

    public static function getDiskInfo() {
        $total = disk_total_space('/');
        $free = disk_free_space('/');
        $used = $total - $free;
        $percent = $total > 0 ? round(($used / $total) * 100, 1) : 0;

        return [
            'total' => self::formatBytes($total),
            'used' => self::formatBytes($used),
            'free' => self::formatBytes($free),
            'percent' => $percent
        ];
    }

    public static function getServiceStatus($service) {
        $output = trim(shell_exec("systemctl is-active " . escapeshellarg($service) . " 2>/dev/null") ?: "");
        return $output === 'active';
    }

    public static function getUptime() {
        $uptime = (float)trim(shell_exec("cat /proc/uptime 2>/dev/null | awk '{print $1}'") ?: "0");
        $days = floor($uptime / 86400);
        $hours = floor(($uptime % 86400) / 3600);
        $minutes = floor(($uptime % 3600) / 60);
        return "${days}d ${hours}h ${minutes}m";
    }

    public static function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        return round($bytes / pow(1024, $pow), $precision) . ' ' . $units[$pow];
    }

    public static function getHostname() {
        return trim(shell_exec("hostname 2>/dev/null") ?: "localhost");
    }

    public static function getOsInfo() {
        return trim(shell_exec("lsb_release -ds 2>/dev/null") ?: "Ubuntu");
    }
}

class DomainManager {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    public function addDomain($domain) {
        $domain = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $domain);
        if (empty($domain)) {
            return ['success' => false, 'message' => 'Invalid domain name.'];
        }

        $existing = $this->db->fetchOne("SELECT id FROM domains WHERE domain_name = ?", [$domain]);
        if ($existing) {
            return ['success' => false, 'message' => 'Domain already exists.'];
        }

        $docRoot = "/home/{$domain}/public_html";
        if (!is_dir($docRoot)) {
            mkdir($docRoot, 0755, true);
        }

        file_put_contents("{$docRoot}/index.html", "<!DOCTYPE html><html><head><title>Welcome to {$domain}</title></head><body><h1>Welcome to {$domain}</h1><p>This site is hosted on LitePanel.</p></body></html>");
        chown("/home/{$domain}", 'nobody');
        chgrp("/home/{$domain}", 'nogroup');
        chmod("/home/{$domain}", 0755);
        chown($docRoot, 'nobody');
        chgrp($docRoot, 'nogroup');

        $this->createVhostConfig($domain, $docRoot);

        $this->db->query(
            "INSERT INTO domains (domain_name, document_root) VALUES (?, ?)",
            [$domain, $docRoot]
        );

        shell_exec("sudo /usr/local/lsws/bin/lswsctrl restart 2>/dev/null &");

        return ['success' => true, 'message' => "Domain {$domain} added successfully."];
    }

    public function removeDomain($domain) {
        $domain = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $domain);
        $vhostConf = "/usr/local/lsws/conf/vhosts/{$domain}";
        if (is_dir($vhostConf)) {
            shell_exec("rm -rf " . escapeshellarg($vhostConf));
        }

        $this->removeVhostFromHttpd($domain);
        $this->db->query("DELETE FROM domains WHERE domain_name = ?", [$domain]);
        shell_exec("sudo /usr/local/lsws/bin/lswsctrl restart 2>/dev/null &");

        return ['success' => true, 'message' => "Domain {$domain} removed."];
    }

    public function listDomains() {
        return $this->db->fetchAll("SELECT * FROM domains ORDER BY created_at DESC");
    }

    private function createVhostConfig($domain, $docRoot) {
        $vhostDir = "/usr/local/lsws/conf/vhosts/{$domain}";
        if (!is_dir($vhostDir)) {
            mkdir($vhostDir, 0755, true);
        }

        $vhostConf = "docRoot                   {$docRoot}
vhDomain                  {$domain}
enableGzip                1
enableBr                  1

index  {
  useServer               0
  indexFiles               index.php, index.html
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/{$domain}_lsphp.sock
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

accesslog {$vhostDir}/access.log {
  useServer               0
  rollingSize             100M
}

errorlog {$vhostDir}/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}
";
        file_put_contents("{$vhostDir}/vhconf.conf", $vhostConf);

        $this->addVhostToHttpd($domain);
    }

    private function addVhostToHttpd($domain) {
        $httpdConf = "/usr/local/lsws/conf/httpd_config.conf";
        $content = file_get_contents($httpdConf);

        if (strpos($content, "member   {$domain}") !== false) {
            return;
        }

        $vhostBlock = "
virtualhost {$domain} {
  vhRoot                  /usr/local/lsws/conf/vhosts/{$domain}/
  configFile              /usr/local/lsws/conf/vhosts/{$domain}/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}
";
        $content .= $vhostBlock;

        $listenerMap = "
listener Default{
  map                     {$domain} {$domain}
}
";

        if (strpos($content, 'listener Default{') !== false || strpos($content, 'listener Default {') !== false) {
            $content = preg_replace(
                '/(listener\s+Default\s*\{)/s',
                "$1\n  map                     {$domain} {$domain}",
                $content,
                1
            );
        }

        file_put_contents($httpdConf, $content);
    }

    private function removeVhostFromHttpd($domain) {
        $httpdConf = "/usr/local/lsws/conf/httpd_config.conf";
        $content = file_get_contents($httpdConf);

        $content = preg_replace("/virtualhost\s+{$domain}\s*\{[^}]*\}\s*/s", '', $content);
        $content = preg_replace("/\s*map\s+{$domain}\s+{$domain}\s*/", "\n", $content);

        file_put_contents($httpdConf, $content);
    }
}

class DatabaseManager {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }

    public function listDatabases() {
        $result = $this->db->fetchAll("SHOW DATABASES");
        $systemDbs = ['information_schema', 'performance_schema', 'mysql', 'sys'];
        $databases = [];
        foreach ($result as $row) {
            $dbName = reset($row);
            if (!in_array($dbName, $systemDbs)) {
                $databases[] = $dbName;
            }
        }
        return $databases;
    }

    public function createDatabase($name) {
        $name = preg_replace('/[^a-zA-Z0-9_]/', '', $name);
        if (empty($name)) {
            return ['success' => false, 'message' => 'Invalid database name.'];
        }
        try {
            $this->db->query("CREATE DATABASE IF NOT EXISTS `{$name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            return ['success' => true, 'message' => "Database {$name} created."];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    public function dropDatabase($name) {
        $name = preg_replace('/[^a-zA-Z0-9_]/', '', $name);
        $protected = ['litepanel_db', 'mysql', 'information_schema', 'performance_schema', 'sys'];
        if (in_array($name, $protected)) {
            return ['success' => false, 'message' => 'Cannot drop protected database.'];
        }
        try {
            $this->db->query("DROP DATABASE IF EXISTS `{$name}`");
            return ['success' => true, 'message' => "Database {$name} dropped."];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    public function listUsers() {
        return $this->db->fetchAll("SELECT User, Host FROM mysql.user WHERE User NOT IN ('root', 'mysql', 'mariadb.sys', 'debian-sys-maint') ORDER BY User");
    }

    public function createUser($username, $password, $database) {
        $username = preg_replace('/[^a-zA-Z0-9_]/', '', $username);
        $database = preg_replace('/[^a-zA-Z0-9_]/', '', $database);
        if (empty($username) || empty($password)) {
            return ['success' => false, 'message' => 'Invalid username or password.'];
        }
        try {
            $this->db->query("CREATE USER IF NOT EXISTS ?@'localhost' IDENTIFIED BY ?", [$username, $password]);
            if (!empty($database)) {
                $this->db->query("GRANT ALL PRIVILEGES ON `{$database}`.* TO ?@'localhost'", [$username]);
            }
            $this->db->query("FLUSH PRIVILEGES");
            return ['success' => true, 'message' => "User {$username} created."];
        } catch (Exception $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
}

class FileManager {
    private $baseDir;

    public function __construct($baseDir = '/home') {
        $this->baseDir = realpath($baseDir) ?: $baseDir;
    }

    public function listFiles($path = '') {
        $fullPath = $this->resolvePath($path);
        if (!$fullPath || !is_dir($fullPath)) {
            return ['success' => false, 'message' => 'Invalid directory.', 'files' => []];
        }

        $items = [];
        $entries = scandir($fullPath);
        foreach ($entries as $entry) {
            if ($entry === '.') continue;
            $fp = $fullPath . '/' . $entry;
            $items[] = [
                'name' => $entry,
                'type' => is_dir($fp) ? 'dir' : 'file',
                'size' => is_file($fp) ? SystemInfo::formatBytes(filesize($fp)) : '-',
                'modified' => date('Y-m-d H:i:s', filemtime($fp)),
                'permissions' => substr(sprintf('%o', fileperms($fp)), -4),
            ];
        }

        usort($items, function($a, $b) {
            if ($a['name'] === '..') return -1;
            if ($b['name'] === '..') return 1;
            if ($a['type'] !== $b['type']) return $a['type'] === 'dir' ? -1 : 1;
            return strcasecmp($a['name'], $b['name']);
        });

        return ['success' => true, 'path' => $fullPath, 'relative' => $path, 'files' => $items];
    }

    public function readFile($path) {
        $fullPath = $this->resolvePath($path);
        if (!$fullPath || !is_file($fullPath)) {
            return ['success' => false, 'message' => 'File not found.'];
        }
        $size = filesize($fullPath);
        if ($size > 2 * 1024 * 1024) {
            return ['success' => false, 'message' => 'File too large to edit (max 2MB).'];
        }
        return ['success' => true, 'content' => file_get_contents($fullPath), 'path' => $path];
    }

    public function saveFile($path, $content) {
        $fullPath = $this->resolvePath($path);
        if (!$fullPath) {
            return ['success' => false, 'message' => 'Invalid path.'];
        }
        file_put_contents($fullPath, $content);
        return ['success' => true, 'message' => 'File saved.'];
    }

    public function createDirectory($path, $name) {
        $name = preg_replace('/[^a-zA-Z0-9_\.\-]/', '', $name);
        $fullPath = $this->resolvePath($path);
        if (!$fullPath || !is_dir($fullPath)) {
            return ['success' => false, 'message' => 'Invalid path.'];
        }
        $newDir = $fullPath . '/' . $name;
        if (!is_dir($newDir)) {
            mkdir($newDir, 0755, true);
        }
        return ['success' => true, 'message' => "Directory {$name} created."];
    }

    public function deleteItem($path) {
        $fullPath = $this->resolvePath($path);
        if (!$fullPath || $fullPath === $this->baseDir) {
            return ['success' => false, 'message' => 'Cannot delete this item.'];
        }
        if (is_dir($fullPath)) {
            shell_exec("rm -rf " . escapeshellarg($fullPath));
        } else {
            unlink($fullPath);
        }
        return ['success' => true, 'message' => 'Deleted successfully.'];
    }

    private function resolvePath($path) {
        $path = str_replace(['../', '..\\'], '', $path);
        $full = realpath($this->baseDir . '/' . $path);
        if (!$full) {
            $full = $this->baseDir . '/' . $path;
        }
        if (strpos($full, $this->baseDir) !== 0) {
            return false;
        }
        return $full;
    }
}
PHPEOF

# header.php
cat > "${INSTALL_PATH}/includes/header.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/functions.php';

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.save_path', INSTALL_PATH . '/sessions');

session_name(SESSION_NAME);
session_start();

$auth = new Auth();

function e($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
PHPEOF

# CSS/Theme asset
cat > "${INSTALL_PATH}/public/style.css" <<'CSSEOF'
:root {
    --primary: #2563eb;
    --primary-dark: #1d4ed8;
    --bg: #0f172a;
    --bg-card: #1e293b;
    --bg-sidebar: #1a2332;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --border: #334155;
    --success: #22c55e;
    --danger: #ef4444;
    --warning: #f59e0b;
    --info: #3b82f6;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
}
.login-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
}
.login-box {
    background: var(--bg-card);
    border-radius: 16px;
    padding: 40px;
    width: 400px;
    max-width: 95%;
    box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    border: 1px solid var(--border);
}
.login-box h1 {
    text-align: center;
    font-size: 28px;
    margin-bottom: 8px;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.login-box .subtitle {
    text-align: center;
    color: var(--text-muted);
    font-size: 14px;
    margin-bottom: 30px;
}
.form-group { margin-bottom: 20px; }
.form-group label {
    display: block;
    margin-bottom: 6px;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-muted);
}
.form-group input, .form-group select, .form-group textarea {
    width: 100%;
    padding: 12px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    transition: border-color 0.2s;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(37,99,235,0.2);
}
.btn {
    display: inline-block;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
    text-align: center;
}
.btn-primary { background: var(--primary); color: #fff; width: 100%; }
.btn-primary:hover { background: var(--primary-dark); transform: translateY(-1px); }
.btn-success { background: var(--success); color: #fff; }
.btn-success:hover { opacity: 0.9; }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { opacity: 0.9; }
.btn-sm { padding: 6px 14px; font-size: 12px; }
.alert {
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-size: 14px;
    border: 1px solid;
}
.alert-error { background: rgba(239,68,68,0.1); border-color: var(--danger); color: #fca5a5; }
.alert-success { background: rgba(34,197,94,0.1); border-color: var(--success); color: #86efac; }
.alert-info { background: rgba(59,130,246,0.1); border-color: var(--info); color: #93c5fd; }
.layout { display: flex; min-height: 100vh; }
.sidebar {
    width: 260px;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    padding: 20px 0;
    position: fixed;
    height: 100vh;
    overflow-y: auto;
}
.sidebar-brand {
    padding: 0 20px 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 10px;
}
.sidebar-brand h2 {
    font-size: 22px;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.sidebar-brand small { color: var(--text-muted); font-size: 11px; }
.nav-menu { list-style: none; }
.nav-menu li a {
    display: flex;
    align-items: center;
    padding: 12px 24px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 14px;
    transition: all 0.2s;
    border-left: 3px solid transparent;
}
.nav-menu li a:hover, .nav-menu li a.active {
    background: rgba(37,99,235,0.1);
    color: var(--text);
    border-left-color: var(--primary);
}
.nav-menu li a .icon { margin-right: 12px; font-size: 18px; width: 24px; text-align: center; }
.main-content {
    margin-left: 260px;
    flex: 1;
    padding: 30px;
    min-height: 100vh;
}
.top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
}
.top-bar h1 { font-size: 24px; font-weight: 700; }
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.stat-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 24px;
    border: 1px solid var(--border);
    transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-card .stat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}
.stat-card .stat-label { color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-card .stat-icon { font-size: 24px; opacity: 0.7; }
.stat-card .stat-value { font-size: 28px; font-weight: 700; }
.stat-card .stat-detail { color: var(--text-muted); font-size: 12px; margin-top: 4px; }
.progress-bar {
    width: 100%;
    height: 8px;
    background: var(--bg);
    border-radius: 4px;
    margin-top: 12px;
    overflow: hidden;
}
.progress-bar .fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s;
}
.fill-blue { background: linear-gradient(90deg, #3b82f6, #60a5fa); }
.fill-green { background: linear-gradient(90deg, #22c55e, #4ade80); }
.fill-yellow { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
.fill-red { background: linear-gradient(90deg, #ef4444, #f87171); }
.card {
    background: var(--bg-card);
    border-radius: 12px;
    border: 1px solid var(--border);
    margin-bottom: 20px;
}
.card-header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.card-header h3 { font-size: 16px; font-weight: 600; }
.card-body { padding: 24px; }
table { width: 100%; border-collapse: collapse; }
table th, table td {
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 14px;
}
table th { color: var(--text-muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
table tr:hover { background: rgba(255,255,255,0.02); }
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
}
.badge-success { background: rgba(34,197,94,0.15); color: #4ade80; }
.badge-danger { background: rgba(239,68,68,0.15); color: #f87171; }
.badge-info { background: rgba(59,130,246,0.15); color: #60a5fa; }
.services-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-top: 20px;
}
.service-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px;
    background: var(--bg);
    border-radius: 8px;
    border: 1px solid var(--border);
}
.service-name { font-weight: 500; }
.status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 8px;
}
.status-dot.online { background: var(--success); box-shadow: 0 0 8px rgba(34,197,94,0.5); }
.status-dot.offline { background: var(--danger); box-shadow: 0 0 8px rgba(239,68,68,0.5); }
.file-browser { font-family: 'Courier New', monospace; }
.breadcrumb { display: flex; gap: 4px; align-items: center; margin-bottom: 16px; font-size: 14px; flex-wrap: wrap; }
.breadcrumb a { color: var(--primary); text-decoration: none; }
.breadcrumb span { color: var(--text-muted); }
.editor-area {
    width: 100%;
    min-height: 400px;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    resize: vertical;
}
.modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    z-index: 1000;
    justify-content: center;
    align-items: center;
}
.modal-overlay.active { display: flex; }
.modal {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 30px;
    width: 500px;
    max-width: 95%;
    border: 1px solid var(--border);
}
.modal h3 { margin-bottom: 20px; }
.inline-form { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
.inline-form .form-group { margin-bottom: 0; flex: 1; min-width: 200px; }
@media (max-width: 768px) {
    .sidebar { display: none; }
    .main-content { margin-left: 0; padding: 16px; }
    .stats-grid { grid-template-columns: 1fr; }
    .inline-form { flex-direction: column; }
}
CSSEOF

# index.php (login)
cat > "${INSTALL_PATH}/public/index.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';

if ($auth->isLoggedIn()) {
    header('Location: /dashboard.php');
    exit;
}

$error = '';
$csrfToken = $auth->generateCsrfToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$auth->validateCsrfToken($token)) {
        $error = 'Invalid request. Please try again.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $result = $auth->login($username, $password);
        if ($result['success']) {
            header('Location: /dashboard.php');
            exit;
        } else {
            $error = $result['message'];
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Login</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="login-wrapper">
    <div class="login-box">
        <h1>&#128736; LitePanel</h1>
        <p class="subtitle">Home Server Control Panel</p>
        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo e($error); ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autofocus autocomplete="username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn btn-primary">Sign In</button>
        </form>
    </div>
</div>
</body>
</html>
PHPEOF

# dashboard.php
cat > "${INSTALL_PATH}/public/dashboard.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();

$cpu = SystemInfo::getCpuInfo();
$mem = SystemInfo::getMemoryInfo();
$disk = SystemInfo::getDiskInfo();
$uptime = SystemInfo::getUptime();
$hostname = SystemInfo::getHostname();
$osInfo = SystemInfo::getOsInfo();

$services = [
    'lsws' => ['name' => 'OpenLiteSpeed', 'status' => SystemInfo::getServiceStatus('lsws')],
    'mariadb' => ['name' => 'MariaDB', 'status' => SystemInfo::getServiceStatus('mariadb')],
    'cloudflared' => ['name' => 'Cloudflare Tunnel', 'status' => SystemInfo::getServiceStatus('cloudflared')],
    'fail2ban' => ['name' => 'Fail2Ban', 'status' => SystemInfo::getServiceStatus('fail2ban')],
    'ufw' => ['name' => 'UFW Firewall', 'status' => SystemInfo::getServiceStatus('ufw')],
];

$domainMgr = new DomainManager();
$domainCount = count($domainMgr->listDomains());
$dbMgr = new DatabaseManager();
$dbCount = count($dbMgr->listDatabases());

function getBarColor($pct) {
    if ($pct > 90) return 'fill-red';
    if ($pct > 70) return 'fill-yellow';
    if ($pct > 40) return 'fill-blue';
    return 'fill-green';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Dashboard</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar">
            <h1>Dashboard</h1>
            <div>
                <span style="color:var(--text-muted);font-size:13px;">
                    <?php echo e($hostname); ?> &bull; <?php echo e($osInfo); ?> &bull; Uptime: <?php echo e($uptime); ?>
                </span>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-label">CPU Usage</span>
                    <span class="stat-icon">&#9889;</span>
                </div>
                <div class="stat-value"><?php echo $cpu['usage']; ?>%</div>
                <div class="stat-detail"><?php echo e($cpu['model']); ?> (<?php echo $cpu['cores']; ?> cores)</div>
                <div class="progress-bar"><div class="fill <?php echo getBarColor($cpu['usage']); ?>" style="width:<?php echo $cpu['usage']; ?>%"></div></div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-label">Memory</span>
                    <span class="stat-icon">&#128200;</span>
                </div>
                <div class="stat-value"><?php echo $mem['percent']; ?>%</div>
                <div class="stat-detail"><?php echo $mem['used']; ?> / <?php echo $mem['total']; ?></div>
                <div class="progress-bar"><div class="fill <?php echo getBarColor($mem['percent']); ?>" style="width:<?php echo $mem['percent']; ?>%"></div></div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-label">Disk</span>
                    <span class="stat-icon">&#128451;</span>
                </div>
                <div class="stat-value"><?php echo $disk['percent']; ?>%</div>
                <div class="stat-detail"><?php echo $disk['used']; ?> / <?php echo $disk['total']; ?></div>
                <div class="progress-bar"><div class="fill <?php echo getBarColor($disk['percent']); ?>" style="width:<?php echo $disk['percent']; ?>%"></div></div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-label">Overview</span>
                    <span class="stat-icon">&#127760;</span>
                </div>
                <div class="stat-value"><?php echo $domainCount; ?></div>
                <div class="stat-detail">Domains &bull; <?php echo $dbCount; ?> Databases</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#128994; Services Status</h3></div>
            <div class="card-body">
                <div class="services-grid">
                    <?php foreach ($services as $svc): ?>
                    <div class="service-item">
                        <span class="service-name"><?php echo e($svc['name']); ?></span>
                        <span>
                            <span class="status-dot <?php echo $svc['status'] ? 'online' : 'offline'; ?>"></span>
                            <?php echo $svc['status'] ? 'Running' : 'Stopped'; ?>
                        </span>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

# sidebar.php
cat > "${INSTALL_PATH}/includes/sidebar.php" <<'PHPEOF'
<div class="sidebar">
    <div class="sidebar-brand">
        <h2>&#128736; LitePanel</h2>
        <small>v<?php echo PANEL_VERSION; ?> &bull; Home Server</small>
    </div>
    <ul class="nav-menu">
        <li><a href="/dashboard.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'dashboard.php' ? 'active' : ''; ?>"><span class="icon">&#127968;</span> Dashboard</a></li>
        <li><a href="/domains.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'domains.php' ? 'active' : ''; ?>"><span class="icon">&#127760;</span> Domains</a></li>
        <li><a href="/databases.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'databases.php' ? 'active' : ''; ?>"><span class="icon">&#128451;</span> Databases</a></li>
        <li><a href="/filemanager.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'filemanager.php' ? 'active' : ''; ?>"><span class="icon">&#128193;</span> File Manager</a></li>
        <li><a href="/ssl.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'ssl.php' ? 'active' : ''; ?>"><span class="icon">&#128274;</span> SSL / Tunnel</a></li>
        <li><a href="/phpmyadmin/" target="_blank"><span class="icon">&#128202;</span> phpMyAdmin</a></li>
        <li><a href="/logout.php"><span class="icon">&#128682;</span> Logout</a></li>
    </ul>
</div>
PHPEOF

# domains.php
cat > "${INSTALL_PATH}/public/domains.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$domainMgr = new DomainManager();
$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$auth->validateCsrfToken($token)) {
        $message = 'Invalid request.';
        $msgType = 'error';
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'add') {
            $result = $domainMgr->addDomain($_POST['domain'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        } elseif ($action === 'remove') {
            $result = $domainMgr->removeDomain($_POST['domain'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

$domains = $domainMgr->listDomains();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Domains</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>Domain Management</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <div class="card">
            <div class="card-header"><h3>Add Domain</h3></div>
            <div class="card-body">
                <form method="POST" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="add">
                    <div class="form-group">
                        <label>Domain Name</label>
                        <input type="text" name="domain" placeholder="example.com" required>
                    </div>
                    <button type="submit" class="btn btn-success">Add Domain</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Domains (<?php echo count($domains); ?>)</h3></div>
            <div class="card-body">
                <?php if (empty($domains)): ?>
                    <p style="color:var(--text-muted)">No domains configured.</p>
                <?php else: ?>
                <table>
                    <thead><tr><th>Domain</th><th>Document Root</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($domains as $d): ?>
                    <tr>
                        <td><strong><?php echo e($d['domain_name']); ?></strong></td>
                        <td><code><?php echo e($d['document_root']); ?></code></td>
                        <td><span class="badge badge-<?php echo $d['status'] === 'active' ? 'success' : 'danger'; ?>"><?php echo e($d['status']); ?></span></td>
                        <td><?php echo e($d['created_at']); ?></td>
                        <td>
                            <form method="POST" style="display:inline" onsubmit="return confirm('Remove this domain?');">
                                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                                <input type="hidden" name="action" value="remove">
                                <input type="hidden" name="domain" value="<?php echo e($d['domain_name']); ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

# databases.php
cat > "${INSTALL_PATH}/public/databases.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$dbMgr = new DatabaseManager();
$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$auth->validateCsrfToken($token)) {
        $message = 'Invalid request.';
        $msgType = 'error';
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'create_db') {
            $result = $dbMgr->createDatabase($_POST['dbname'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        } elseif ($action === 'drop_db') {
            $result = $dbMgr->dropDatabase($_POST['dbname'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        } elseif ($action === 'create_user') {
            $result = $dbMgr->createUser($_POST['db_username'] ?? '', $_POST['db_password'] ?? '', $_POST['db_grant'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

$databases = $dbMgr->listDatabases();
$users = $dbMgr->listUsers();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Databases</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>Database Management</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <div class="card">
            <div class="card-header"><h3>Create Database</h3></div>
            <div class="card-body">
                <form method="POST" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="create_db">
                    <div class="form-group">
                        <label>Database Name</label>
                        <input type="text" name="dbname" required pattern="[a-zA-Z0-9_]+" title="Alphanumeric and underscore only">
                    </div>
                    <button type="submit" class="btn btn-success">Create</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Create Database User</h3></div>
            <div class="card-body">
                <form method="POST" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="create_user">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="db_username" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="text" name="db_password" required>
                    </div>
                    <div class="form-group">
                        <label>Grant to Database</label>
                        <select name="db_grant">
                            <option value="">-- None --</option>
                            <?php foreach ($databases as $db): ?>
                            <option value="<?php echo e($db); ?>"><?php echo e($db); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-success">Create User</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Databases (<?php echo count($databases); ?>)</h3></div>
            <div class="card-body">
                <table>
                    <thead><tr><th>Database Name</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($databases as $db): ?>
                    <tr>
                        <td><strong><?php echo e($db); ?></strong></td>
                        <td>
                            <form method="POST" style="display:inline" onsubmit="return confirm('Drop database <?php echo e($db); ?>?');">
                                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                                <input type="hidden" name="action" value="drop_db">
                                <input type="hidden" name="dbname" value="<?php echo e($db); ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Drop</button>
                            </form>
                            <a href="/phpmyadmin/" target="_blank" class="btn btn-primary btn-sm" style="color:#fff;margin-left:5px;">phpMyAdmin</a>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Database Users</h3></div>
            <div class="card-body">
                <table>
                    <thead><tr><th>Username</th><th>Host</th></tr></thead>
                    <tbody>
                    <?php foreach ($users as $u): ?>
                    <tr><td><?php echo e($u['User']); ?></td><td><?php echo e($u['Host']); ?></td></tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

# filemanager.php
cat > "${INSTALL_PATH}/public/filemanager.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$fm = new FileManager('/home');
$message = '';
$msgType = '';
$editMode = false;
$editContent = '';
$editPath = '';

$currentPath = $_GET['path'] ?? '';
$currentPath = str_replace('../', '', $currentPath);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if ($auth->validateCsrfToken($token)) {
        $action = $_POST['action'] ?? '';
        if ($action === 'mkdir') {
            $result = $fm->createDirectory($currentPath, $_POST['dirname'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        } elseif ($action === 'delete') {
            $result = $fm->deleteItem($_POST['filepath'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        } elseif ($action === 'save') {
            $result = $fm->saveFile($_POST['filepath'] ?? '', $_POST['content'] ?? '');
            $message = $result['message'];
            $msgType = $result['success'] ? 'success' : 'error';
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

if (isset($_GET['edit'])) {
    $editData = $fm->readFile($_GET['edit']);
    if ($editData['success']) {
        $editMode = true;
        $editContent = $editData['content'];
        $editPath = $_GET['edit'];
    } else {
        $message = $editData['message'];
        $msgType = 'error';
    }
}

$listing = $fm->listFiles($currentPath);

function buildBreadcrumb($path) {
    $parts = array_filter(explode('/', $path));
    $crumbs = [['name' => 'Home', 'path' => '']];
    $accumulated = '';
    foreach ($parts as $part) {
        $accumulated .= ($accumulated ? '/' : '') . $part;
        $crumbs[] = ['name' => $part, 'path' => $accumulated];
    }
    return $crumbs;
}
$breadcrumbs = buildBreadcrumb($currentPath);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - File Manager</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>File Manager</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <?php if ($editMode): ?>
        <div class="card">
            <div class="card-header">
                <h3>Editing: <?php echo e($editPath); ?></h3>
                <a href="/filemanager.php?path=<?php echo e($currentPath); ?>" class="btn btn-sm btn-primary" style="color:#fff">Back</a>
            </div>
            <div class="card-body">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="save">
                    <input type="hidden" name="filepath" value="<?php echo e($editPath); ?>">
                    <div class="form-group">
                        <textarea name="content" class="editor-area"><?php echo e($editContent); ?></textarea>
                    </div>
                    <button type="submit" class="btn btn-success">Save File</button>
                </form>
            </div>
        </div>
        <?php else: ?>
        <div class="card">
            <div class="card-header">
                <h3>
                    <div class="breadcrumb">
                        <?php foreach ($breadcrumbs as $i => $crumb): ?>
                            <?php if ($i > 0): ?><span>/</span><?php endif; ?>
                            <a href="/filemanager.php?path=<?php echo urlencode($crumb['path']); ?>"><?php echo e($crumb['name']); ?></a>
                        <?php endforeach; ?>
                    </div>
                </h3>
                <form method="POST" class="inline-form" style="gap:5px">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="mkdir">
                    <input type="text" name="dirname" placeholder="New folder" style="width:150px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px" required>
                    <button type="submit" class="btn btn-success btn-sm">Create Dir</button>
                </form>
            </div>
            <div class="card-body file-browser">
                <table>
                    <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Perms</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php if ($listing['success']): ?>
                        <?php foreach ($listing['files'] as $file): ?>
                        <tr>
                            <td>
                                <?php if ($file['type'] === 'dir'): ?>
                                    &#128193; <a href="/filemanager.php?path=<?php echo urlencode(trim($currentPath . '/' . $file['name'], '/')); ?>" style="color:var(--primary);text-decoration:none"><?php echo e($file['name']); ?></a>
                                <?php else: ?>
                                    &#128196; <?php echo e($file['name']); ?>
                                <?php endif; ?>
                            </td>
                            <td><?php echo e($file['size']); ?></td>
                            <td><?php echo e($file['modified']); ?></td>
                            <td><code><?php echo e($file['permissions']); ?></code></td>
                            <td>
                                <?php if ($file['name'] !== '..'): ?>
                                    <?php if ($file['type'] === 'file'): ?>
                                        <a href="/filemanager.php?path=<?php echo urlencode($currentPath); ?>&edit=<?php echo urlencode(trim($currentPath . '/' . $file['name'], '/')); ?>" class="btn btn-primary btn-sm" style="color:#fff">Edit</a>
                                    <?php endif; ?>
                                    <form method="POST" style="display:inline" onsubmit="return confirm('Delete <?php echo e($file['name']); ?>?');">
                                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                                        <input type="hidden" name="action" value="delete">
                                        <input type="hidden" name="filepath" value="<?php echo e(trim($currentPath . '/' . $file['name'], '/')); ?>">
                                        <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
PHPEOF

# ssl.php
cat > "${INSTALL_PATH}/public/ssl.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if ($auth->validateCsrfToken($token)) {
        $action = $_POST['action'] ?? '';
        if ($action === 'restart_tunnel') {
            shell_exec('sudo systemctl restart cloudflared 2>&1');
            $message = 'Cloudflare tunnel restarted.';
            $msgType = 'success';
        } elseif ($action === 'restart_ols') {
            shell_exec('sudo /usr/local/lsws/bin/lswsctrl restart 2>&1');
            $message = 'OpenLiteSpeed restarted.';
            $msgType = 'success';
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

$tunnelStatus = trim(shell_exec('systemctl is-active cloudflared 2>/dev/null') ?: 'unknown');
$tunnelConfig = '';
if (file_exists('/etc/cloudflared/config.yml')) {
    $tunnelConfig = file_get_contents('/etc/cloudflared/config.yml');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - SSL & Tunnel</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>SSL & Cloudflare Tunnel</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <span class="stat-label">Tunnel Status</span>
                    <span class="stat-icon">&#128272;</span>
                </div>
                <div class="stat-value">
                    <span class="status-dot <?php echo $tunnelStatus === 'active' ? 'online' : 'offline'; ?>"></span>
                    <?php echo e(ucfirst($tunnelStatus)); ?>
                </div>
                <div class="stat-detail">Cloudflare Tunnel provides automatic SSL</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Service Controls</h3></div>
            <div class="card-body">
                <div class="inline-form" style="gap:10px">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                        <input type="hidden" name="action" value="restart_tunnel">
                        <button type="submit" class="btn btn-primary">Restart Tunnel</button>
                    </form>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                        <input type="hidden" name="action" value="restart_ols">
                        <button type="submit" class="btn btn-success">Restart OLS</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Tunnel Configuration</h3></div>
            <div class="card-body">
                <pre style="background:var(--bg);padding:16px;border-radius:8px;overflow-x:auto;font-size:13px;border:1px solid var(--border)"><?php echo e($tunnelConfig ?: 'Configuration file not found.'); ?></pre>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#128274; SSL Information</h3></div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Cloudflare Tunnel provides automatic SSL/TLS.</strong><br>
                    All traffic through Cloudflare Tunnel is automatically encrypted with SSL certificates managed by Cloudflare.<br>
                    No manual SSL certificate management is needed for domains routed through the tunnel.
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#128737; Zero Trust Security</h3></div>
            <div class="card-body">
                <div class="alert alert-info">
                    <strong>Recommended: Enable Cloudflare Zero Trust Access</strong><br><br>
                    To secure your panel with email-based authentication:<br><br>
                    1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:var(--primary)">Cloudflare Zero Trust Dashboard</a><br>
                    2. Navigate to <strong>Access &rarr; Applications</strong><br>
                    3. Click <strong>Add an application</strong> &rarr; <strong>Self-hosted</strong><br>
                    4. Set application domain to your panel subdomain<br>
                    5. Add a policy: <strong>Allow</strong> &rarr; <strong>Emails</strong> &rarr; enter your email<br>
                    6. Save and test access<br>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

# logout.php
cat > "${INSTALL_PATH}/public/logout.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->logout();
header('Location: /index.php');
exit;
PHPEOF

###############################################################################
# STEP 7: Set permissions
###############################################################################
log_step "7/15 - Setting permissions..."
chown -R nobody:nogroup "${INSTALL_PATH}"
chmod -R 750 "${INSTALL_PATH}"
chmod 700 "${INSTALL_PATH}/sessions"
chmod 700 "${INSTALL_PATH}/data"
find "${INSTALL_PATH}" -type f -exec chmod 640 {} \;
find "${INSTALL_PATH}/public" -type f -exec chmod 644 {} \;
chmod 600 "${INSTALL_PATH}/includes/config.php"

###############################################################################
# STEP 8: Install phpMyAdmin
###############################################################################
log_step "8/15 - Installing phpMyAdmin..."
PMA_VERSION="5.2.1"
PMA_DIR="${INSTALL_PATH}/public/phpmyadmin"

if [[ ! -d "$PMA_DIR" ]]; then
    cd /tmp
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.zip" -O phpmyadmin.zip 2>/dev/null || \
    wget -q "https://files.phpmyadmin.net/phpMyAdmin/5.2.0/phpMyAdmin-5.2.0-all-languages.zip" -O phpmyadmin.zip 2>/dev/null || true

    if [[ -f phpmyadmin.zip ]]; then
        unzip -qo phpmyadmin.zip
        PMA_EXTRACTED=$(ls -d phpMyAdmin-*-all-languages 2>/dev/null | head -1)
        if [[ -n "$PMA_EXTRACTED" && -d "$PMA_EXTRACTED" ]]; then
            mv "$PMA_EXTRACTED" "$PMA_DIR"
            PMA_BLOWFISH=$(generate_alphanum_password)
            cat > "${PMA_DIR}/config.inc.php" <<PMAEOF
<?php
\$cfg['blowfish_secret'] = '${PMA_BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '/tmp';
\$cfg['DefaultLang'] = 'en';
\$cfg['ThemeDefault'] = 'pmahomme';
PMAEOF

        chown -R nobody:nogroup "$PMA_DIR"
        chmod -R 750 "$PMA_DIR"
        find "$PMA_DIR" -type f -exec chmod 640 {} \;
        fi
        rm -f phpmyadmin.zip
    fi
fi

###############################################################################
# STEP 9: Configure OpenLiteSpeed
###############################################################################
log_step "9/15 - Configuring OpenLiteSpeed..."

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

# Backup original config
cp "${OLS_CONF}" "${OLS_CONF}.bak.$(date +%s)" 2>/dev/null || true

cat > "${OLS_CONF}" <<OLSEOF
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
  logLevel                ERROR
  debugLevel              0
  rollingSize             10M
  enableStderrLog         1
}

accesslog logs/access.log {
  rollingSize             10M
  keepDays                30
  compressArchive         0
}

indexFiles                index.php, index.html

expires  {
  enableExpires           1
  expiresByType           image/*=A604800,text/css=A604800,application/javascript=A604800
}

tuning  {
  maxConnections          2000
  maxSSLConnections       1000
  connTimeout             300
  maxKeepAliveReq         1000
  keepAliveTimeout        5
  sndBufSize              0
  rcvBufSize              0
  maxReqURLLen            32768
  maxReqHeaderSize        65536
  maxReqBodySize          2047M
  maxDynRespHeaderSize    32768
  maxDynRespSize          2047M
  maxCachedFileSize       4096
  totalInMemCacheSize     20M
  maxMMapFileSize         256K
  totalMMapCacheSize      40M
  useSendfile             1
  fileETag                28
  enableGzipCompress      1
  enableBrCompress        1
  enableDynGzipCompress   1
  gzipCompressLevel       6
  brStaticCompressLevel   6
  compressibleTypes       default
  gzipAutoUpdateStatic    1
  gzipStaticCompressLevel 6
  gzipMaxFileSize         10M
  gzipMinFileSize         300
}

fileAccessControl  {
  followSymbolLink         1
  checkSymbolLink          0
  requiredPermissionMask   000
  restrictedPermissionMask 000
}

perClientConnLimit  {
  staticReqPerSec          0
  dynReqPerSec             0
  outBandwidth             0
  inBandwidth              0
  softLimit                10000
  hardLimit                10000
  gracePeriod              15
  banPeriod                300
}

CGIRLimit  {
  maxCGIInstances          20
  minUID                   11
  minGID                   10
  priority                 0
  CPUSoftLimit             10
  CPUHardLimit             50
  memSoftLimit             1460M
  memHardLimit             1470M
  procSoftLimit            400
  procHardLimit            450
}

accessDenyDir  {
  dir                      /
  dir                      /etc/*
  dir                      /dev/*
  dir                      /proc/*
  dir                      /sys/*
}

scripthandler  {
  add                      lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                     lsapi
  address                  uds://tmp/lshttpd/lsphp81.sock
  maxConns                 10
  env                      PHP_LSAPI_CHILDREN=10
  env                      LSAPI_AVOID_FORK=200M
  initTimeout              60
  retryTimeout             0
  persistConn              1
  pcKeepAliveTimeout       60
  respBuffer               0
  autoStart                2
  path                     /usr/local/lsws/lsphp81/bin/lsphp
  backlog                  100
  instances                1
  priority                 0
  memSoftLimit             2047M
  memHardLimit             2047M
  procSoftLimit            1400
  procHardLimit            1500
  runOnStartUp             2
}

module cache {
  internal                 1
  checkPrivateCache        1
  checkPublicCache         1
  maxCacheObjSize          10000000
  maxStaleAge              200
  qsCache                  1
  reqCookieCache           1
  respCookieCache          1
  ignoreReqCacheCtrl       1
  ignoreRespCacheCtrl      0
  enableCache              0
  expireInSeconds          3600
  enablePrivateCache       0
  privateExpireInSeconds   3600
}

virtualhost LitePanel {
  vhRoot                   ${INSTALL_PATH}/
  configFile               ${INSTALL_PATH}/vhconf.conf
  allowSymbolLink          1
  enableScript             1
  restrained               0
}

virtualhost DefaultSite {
  vhRoot                   /home/default/
  configFile               /usr/local/lsws/conf/vhosts/default/vhconf.conf
  allowSymbolLink          1
  enableScript             1
  restrained               1
}

listener PanelListener {
  address                  *:${PANEL_PORT}
  secure                   0
  map                      LitePanel *
}

listener DefaultListener {
  address                  *:${WEB_PORT}
  secure                   0
  map                      DefaultSite *
}
OLSEOF

# Create LitePanel vhost config
cat > "${INSTALL_PATH}/vhconf.conf" <<VHEOF
docRoot                   \$VH_ROOT/public/
enableGzip                1
enableBr                  1

index  {
  useServer               0
  indexFiles               index.php, index.html
}

context /phpmyadmin/ {
  location                \$VH_ROOT/public/phpmyadmin/
  allowBrowse             1
  indexFiles               index.php

  accessControl  {
    allow                  *
  }

  rewrite  {
    enable                0
  }

  addDefaultCharset       off

  phpIniOverride  {
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
  enable                  0
}

accesslog \$VH_ROOT/logs/access.log {
  useServer               0
  rollingSize             100M
}

errorlog \$VH_ROOT/logs/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}
VHEOF

# Create default site vhost
mkdir -p /usr/local/lsws/conf/vhosts/default
cat > "/usr/local/lsws/conf/vhosts/default/vhconf.conf" <<DVHEOF
docRoot                   /home/default/public_html/
enableGzip                1
enableBr                  1

index  {
  useServer               0
  indexFiles               index.php, index.html
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/default_lsphp.sock
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
DVHEOF

# Create default landing page
cat > /home/default/public_html/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to LitePanel</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { text-align: center; max-width: 600px; padding: 40px; }
        h1 { font-size: 3em; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        p { color: #94a3b8; font-size: 1.1em; line-height: 1.8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#128736; LitePanel</h1>
        <p>Your home server is running successfully.<br>Powered by OpenLiteSpeed + Cloudflare Tunnel.</p>
    </div>
</body>
</html>
HTMLEOF

chown -R nobody:nogroup /home/default
chmod -R 755 /home/default

###############################################################################
# STEP 10: Install and configure Cloudflared
###############################################################################
log_step "10/15 - Installing Cloudflare Tunnel..."

if ! command -v cloudflared &>/dev/null; then
    ARCH=$(dpkg --print-architecture)
    wget -q "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb" -O /tmp/cloudflared.deb 2>/dev/null || true
    if [[ -f /tmp/cloudflared.deb ]]; then
        dpkg -i /tmp/cloudflared.deb 2>/dev/null || apt-get install -f -y
        rm -f /tmp/cloudflared.deb
    fi
fi

mkdir -p /etc/cloudflared
mkdir -p /root/.cloudflared

# Authenticate using API token
log_step "Configuring Cloudflare Tunnel..."

# Get Account ID using API
log_info "Fetching Cloudflare account information..."
CF_ACCOUNTS_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json")

CF_ACCOUNT_ID=$(echo "$CF_ACCOUNTS_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$CF_ACCOUNT_ID" ]]; then
    log_warn "Could not fetch account ID automatically. Tunnel may need manual setup."
    CF_ACCOUNT_ID="unknown"
fi

log_info "Account ID: ${CF_ACCOUNT_ID}"

# Generate tunnel secret
TUNNEL_SECRET=$(openssl rand -base64 32 | tr -d '=+/' | head -c 44)
TUNNEL_SECRET_B64=$(echo -n "${TUNNEL_SECRET}" | base64 | tr -d '\n')

# Check if tunnel already exists
EXISTING_TUNNEL=$(curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json")

TUNNEL_ID=$(echo "$EXISTING_TUNNEL" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]]; then
    log_info "Creating new tunnel: ${TUNNEL_NAME}..."
    CREATE_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"name\":\"${TUNNEL_NAME}\",\"tunnel_secret\":\"${TUNNEL_SECRET_B64}\"}")

    TUNNEL_ID=$(echo "$CREATE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]]; then
        log_warn "Failed to create tunnel via API. Will attempt manual setup."
        log_warn "API Response: ${CREATE_RESPONSE}"
        TUNNEL_ID="manual-setup-needed"
    else
        log_info "Tunnel created: ${TUNNEL_ID}"
    fi
else
    log_info "Existing tunnel found: ${TUNNEL_ID}"
fi

# Get Zone ID for DNS records
log_info "Fetching zone information for ${MAIN_DOMAIN}..."
ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${MAIN_DOMAIN}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json")
ZONE_ID=$(echo "$ZONE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -n "$ZONE_ID" && "$ZONE_ID" != "null" && "$TUNNEL_ID" != "manual-setup-needed" ]]; then
    log_info "Zone ID: ${ZONE_ID}"

    # Create DNS CNAME records for tunnel
    for SUBDOMAIN in "panel" "db" "@"; do
        if [[ "$SUBDOMAIN" == "@" ]]; then
            DNS_NAME="${MAIN_DOMAIN}"
        else
            DNS_NAME="${SUBDOMAIN}.${MAIN_DOMAIN}"
        fi

        log_info "Creating DNS record for ${DNS_NAME}..."

        # Check if record exists
        EXISTING_DNS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=CNAME&name=${DNS_NAME}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json")

        EXISTING_DNS_ID=$(echo "$EXISTING_DNS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

        if [[ -n "$EXISTING_DNS_ID" && "$EXISTING_DNS_ID" != "null" ]]; then
            # Update existing
            curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${EXISTING_DNS_ID}" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"CNAME\",\"name\":\"${DNS_NAME}\",\"content\":\"${TUNNEL_ID}.cfargotunnel.com\",\"ttl\":1,\"proxied\":true}" >/dev/null 2>&1
        else
            # Create new
            curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
                -H "Authorization: Bearer ${CF_API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "{\"type\":\"CNAME\",\"name\":\"${DNS_NAME}\",\"content\":\"${TUNNEL_ID}.cfargotunnel.com\",\"ttl\":1,\"proxied\":true}" >/dev/null 2>&1
        fi
    done
fi

# Write credentials file
if [[ "$TUNNEL_ID" != "manual-setup-needed" ]]; then
    cat > /etc/cloudflared/credentials.json <<CREDEOF
{
    "AccountTag": "${CF_ACCOUNT_ID}",
    "TunnelSecret": "${TUNNEL_SECRET_B64}",
    "TunnelID": "${TUNNEL_ID}"
}
CREDEOF
    chmod 600 /etc/cloudflared/credentials.json

    # Also write to root cloudflared dir
    cp /etc/cloudflared/credentials.json "/root/.cloudflared/${TUNNEL_ID}.json"
fi

# Generate config.yml
cat > /etc/cloudflared/config.yml <<CFEOF
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/credentials.json

ingress:
  - hostname: panel.${MAIN_DOMAIN}
    service: http://localhost:${PANEL_PORT}
  - hostname: db.${MAIN_DOMAIN}
    service: http://localhost:${PANEL_PORT}
    path: phpmyadmin
  - hostname: ${MAIN_DOMAIN}
    service: http://localhost:${WEB_PORT}
  - service: http_status:404
CFEOF

chmod 600 /etc/cloudflared/config.yml

# Install cloudflared as service
cloudflared service install 2>/dev/null || true

# Create systemd service manually if needed
if [[ ! -f /etc/systemd/system/cloudflared.service ]]; then
    cat > /etc/systemd/system/cloudflared.service <<SVCEOF
[Unit]
Description=Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=on-failure
RestartSec=5s
KillMode=process
TimeoutStartSec=0
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
fi

systemctl daemon-reload
systemctl enable cloudflared 2>/dev/null || true

###############################################################################
# STEP 11: Configure Firewall
###############################################################################
log_step "11/15 - Configuring firewall..."

# Reset UFW
ufw --force reset 2>/dev/null || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw --force enable

###############################################################################
# STEP 12: Install and configure Fail2Ban
###############################################################################
log_step "12/15 - Configuring Fail2Ban..."
apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local <<'F2BEOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
F2BEOF

systemctl enable fail2ban
systemctl restart fail2ban

###############################################################################
# STEP 13: Security Hardening
###############################################################################
log_step "13/15 - Applying security hardening..."

# Disable root SSH login
SSHD_CONF="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONF" ]]; then
    cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%s)"

    # Disable root login
    if grep -q "^PermitRootLogin" "$SSHD_CONF"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
    elif grep -q "^#PermitRootLogin" "$SSHD_CONF"; then
        sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
    else
        echo "PermitRootLogin no" >> "$SSHD_CONF"
    fi

    # Restrict SSH
    if ! grep -q "^MaxAuthTries" "$SSHD_CONF"; then
        echo "MaxAuthTries 3" >> "$SSHD_CONF"
    fi
    if ! grep -q "^ClientAliveInterval" "$SSHD_CONF"; then
        echo "ClientAliveInterval 300" >> "$SSHD_CONF"
        echo "ClientAliveCountMax 2" >> "$SSHD_CONF"
    fi

    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
fi

# Secure shared memory
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
fi

###############################################################################
# STEP 14: Setup Cron Jobs
###############################################################################
log_step "14/15 - Setting up monitoring cron jobs..."

cat > /usr/local/bin/litepanel-monitor.sh <<'MONEOF'
#!/bin/bash
# LitePanel Service Monitor

# Check and restart OpenLiteSpeed
if ! systemctl is-active --quiet lsws; then
    systemctl restart lsws
    echo "$(date): OpenLiteSpeed restarted" >> /var/log/litepanel-monitor.log
fi

# Check and restart MariaDB
if ! systemctl is-active --quiet mariadb; then
    systemctl restart mariadb
    echo "$(date): MariaDB restarted" >> /var/log/litepanel-monitor.log
fi

# Check and restart Cloudflared
if ! systemctl is-active --quiet cloudflared; then
    systemctl restart cloudflared
    echo "$(date): Cloudflared restarted" >> /var/log/litepanel-monitor.log
fi

# Rotate monitor log if > 10M
if [[ -f /var/log/litepanel-monitor.log ]]; then
    LOG_SIZE=$(stat -f%z /var/log/litepanel-monitor.log 2>/dev/null || stat -c%s /var/log/litepanel-monitor.log 2>/dev/null || echo 0)
    if [[ "$LOG_SIZE" -gt 10485760 ]]; then
        mv /var/log/litepanel-monitor.log /var/log/litepanel-monitor.log.old
    fi
fi
MONEOF

chmod 750 /usr/local/bin/litepanel-monitor.sh

# Install crontabs
CRON_FILE="/etc/cron.d/litepanel"
cat > "$CRON_FILE" <<'CRONEOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Monitor services every 5 minutes
*/5 * * * * root /usr/local/bin/litepanel-monitor.sh >/dev/null 2>&1

# Clean old login logs weekly
0 3 * * 0 root mariadb -u root litepanel_db -e "DELETE FROM login_log WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 30 DAY);" >/dev/null 2>&1

# Clean PHP sessions daily
0 4 * * * root find /opt/litepanel/sessions -type f -mtime +1 -delete >/dev/null 2>&1
CRONEOF

chmod 644 "$CRON_FILE"

###############################################################################
# STEP 15: Start Services
###############################################################################
log_step "15/15 - Starting all services..."

# Ensure directories exist
mkdir -p /tmp/lshttpd
chown -R nobody:nogroup /tmp/lshttpd 2>/dev/null || true

# Restart OLS
/usr/local/lsws/bin/lswsctrl stop 2>/dev/null || true
sleep 2
/usr/local/lsws/bin/lswsctrl start 2>/dev/null || true

# Re-enable & start services
systemctl enable lsws 2>/dev/null || true
systemctl enable mariadb 2>/dev/null || true
systemctl restart mariadb

# Start cloudflared
systemctl restart cloudflared 2>/dev/null || true

# Wait for services
sleep 3

###############################################################################
# SAVE CREDENTIALS
###############################################################################
cat > "${CREDS_FILE}" <<CREDFILE
###############################################
# LitePanel Credentials
# Generated: $(date)
# KEEP THIS FILE SECURE - DELETE AFTER NOTING
###############################################

Panel Admin:
  Username: admin
  Password: ${ADMIN_PASSWORD}

OLS WebAdmin:
  URL: https://localhost:7080
  Username: admin
  Password: ${OLS_ADMIN_PASSWORD}

Database Root:
  Password: ${DB_ROOT_PASSWORD}

Database:
  Name: ${DB_NAME}
  User: ${DB_USER}
  Password: ${DB_PASSWORD}

Cloudflare:
  Tunnel ID: ${TUNNEL_ID}
  Tunnel Name: ${TUNNEL_NAME}

URLs:
  Panel: https://panel.${MAIN_DOMAIN}
  Website: https://${MAIN_DOMAIN}
  phpMyAdmin: https://db.${MAIN_DOMAIN}
CREDFILE

chmod 600 "${CREDS_FILE}"

###############################################################################
# OUTPUT SUMMARY
###############################################################################

OLS_STATUS=$(systemctl is-active lsws 2>/dev/null || echo "unknown")
MARIADB_STATUS=$(systemctl is-active mariadb 2>/dev/null || echo "unknown")
CLOUDFLARED_STATUS=$(systemctl is-active cloudflared 2>/dev/null || echo "unknown")
FAIL2BAN_STATUS=$(systemctl is-active fail2ban 2>/dev/null || echo "unknown")
UFW_STATUS=$(ufw status 2>/dev/null | head -1 || echo "unknown")

echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}         LitePanel Installation Complete!                        ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""
echo -e "${GREEN}ACCESS URLS:${NC}"
echo -e "  LitePanel:    ${YELLOW}https://panel.${MAIN_DOMAIN}${NC}"
echo -e "  Main Website: ${YELLOW}https://${MAIN_DOMAIN}${NC}"
echo -e "  phpMyAdmin:   ${YELLOW}https://db.${MAIN_DOMAIN}${NC}"
echo ""
echo -e "${GREEN}PANEL LOGIN:${NC}"
echo -e "  Username: ${YELLOW}admin${NC}"
echo -e "  Password: ${YELLOW}${ADMIN_PASSWORD}${NC}"
echo ""
echo -e "${GREEN}OLS WEBADMIN:${NC}"
echo -e "  Username: ${YELLOW}admin${NC}"
echo -e "  Password: ${YELLOW}${OLS_ADMIN_PASSWORD}${NC}"
echo ""
echo -e "${GREEN}DATABASE:${NC}"
echo -e "  Root Password:     ${YELLOW}${DB_ROOT_PASSWORD}${NC}"
echo -e "  Panel DB Name:     ${YELLOW}${DB_NAME}${NC}"
echo -e "  Panel DB User:     ${YELLOW}${DB_USER}${NC}"
echo -e "  Panel DB Password: ${YELLOW}${DB_PASSWORD}${NC}"
echo ""
echo -e "${GREEN}CLOUDFLARE TUNNEL:${NC}"
echo -e "  Tunnel Name: ${YELLOW}${TUNNEL_NAME}${NC}"
echo -e "  Tunnel ID:   ${YELLOW}${TUNNEL_ID}${NC}"
echo ""
echo -e "${GREEN}SERVICE STATUS:${NC}"
echo -e "  OpenLiteSpeed:     ${OLS_STATUS}"
echo -e "  MariaDB:           ${MARIADB_STATUS}"
echo -e "  Cloudflare Tunnel: ${CLOUDFLARED_STATUS}"
echo -e "  Fail2Ban:          ${FAIL2BAN_STATUS}"
echo -e "  UFW Firewall:      ${UFW_STATUS}"
echo ""
echo -e "${GREEN}FIREWALL:${NC}"
echo -e "  Only port 22 (SSH) is open"
echo -e "  All web access is via Cloudflare Tunnel"
echo ""
echo -e "${GREEN}SECURITY:${NC}"
echo -e "  Root SSH login disabled"
echo -e "  Fail2Ban protecting SSH"
echo -e "  Service auto-restart monitoring enabled"
echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${YELLOW}  ZERO TRUST SETUP (RECOMMENDED):${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""
echo -e "  1. Go to: ${YELLOW}https://one.dash.cloudflare.com${NC}"
echo -e "  2. Select your account"
echo -e "  3. Navigate to ${YELLOW}Access > Applications${NC}"
echo -e "  4. Click ${YELLOW}Add an application${NC} > ${YELLOW}Self-hosted${NC}"
echo -e "  5. Application name: ${YELLOW}LitePanel${NC}"
echo -e "  6. Application domain: ${YELLOW}panel.${MAIN_DOMAIN}${NC}"
echo -e "  7. Add policy:"
echo -e "     - Name: ${YELLOW}Admin Only${NC}"
echo -e "     - Action: ${YELLOW}Allow${NC}"
echo -e "     - Include: ${YELLOW}Emails${NC} = ${YELLOW}${CF_EMAIL}${NC}"
echo -e "  8. Repeat for ${YELLOW}db.${MAIN_DOMAIN}${NC} (phpMyAdmin)"
echo -e ""
echo -e "  This adds email-based authentication BEFORE"
echo -e "  users can even reach your login page."
echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${RED}  IMPORTANT: Credentials saved to ${CREDS_FILE}${NC}"
echo -e "${RED}  Please note them down and delete the file!${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""
```
