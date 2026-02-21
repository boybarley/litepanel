#!/bin/bash
###############################################################################
# LitePanel v2.0 — Production Installer
# Platform   : Ubuntu 22.04 LTS
# Components : OpenLiteSpeed, MariaDB 10.6, Node.js 18, phpMyAdmin,
#              Fail2Ban, Cloudflare Tunnel (optional)
# Author     : LitePanel Team
# License    : MIT
###############################################################################

set -euo pipefail

#── Constants ─────────────────────────────────────────────────────────────────
readonly PANEL_DIR="/opt/litepanel"
readonly PANEL_PORT=3000
readonly OLS_HTTP_PORT=8088
readonly OLS_ADMIN_PORT=7080
readonly OLS_BASE="/usr/local/lsws"
readonly OLS_VHOST_DIR="${OLS_BASE}/conf/vhosts/Example"
readonly OLS_DOC_ROOT="${OLS_BASE}/Example/html"
readonly PMA_DIR="${OLS_DOC_ROOT}/phpmyadmin"
readonly CONFIG_FILE="${PANEL_DIR}/config.json"
readonly LOG_FILE="/var/log/litepanel-install.log"
readonly MY_CNF="/root/.my.cnf"

#── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

#── Logging ───────────────────────────────────────────────────────────────────
exec > >(tee -a "$LOG_FILE") 2>&1

log_info()  { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BOLD}${CYAN}════════ $1 ════════${NC}\n"; }

#── Pre-flight checks ────────────────────────────────────────────────────────
preflight() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
  fi

  if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    log_error "This script requires Ubuntu (22.04 LTS recommended)"
    exit 1
  fi

  log_info "Starting LitePanel v2.0 installation..."
  log_info "Log file: ${LOG_FILE}"
}

#── Generate secure credentials ──────────────────────────────────────────────
generate_credentials() {
  log_step "Generating Credentials"

  local panel_pass
  panel_pass=$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9' | head -c 16)
  local db_root_pass
  db_root_pass=$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9' | head -c 20)
  local ols_admin_pass
  ols_admin_pass=$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9' | head -c 16)
  local pma_blowfish
  pma_blowfish=$(openssl rand -hex 16)
  local jwt_secret
  jwt_secret=$(openssl rand -hex 32)

  mkdir -p "$PANEL_DIR"

  cat > "$CONFIG_FILE" <<CEOF
{
  "panelUser": "admin",
  "panelPass": "${panel_pass}",
  "dbRootPass": "${db_root_pass}",
  "olsAdminPass": "${ols_admin_pass}",
  "pmaBlowfish": "${pma_blowfish}",
  "jwtSecret": "${jwt_secret}",
  "panelPort": ${PANEL_PORT},
  "olsHttpPort": ${OLS_HTTP_PORT},
  "installedAt": "$(date -Iseconds)"
}
CEOF
  chmod 600 "$CONFIG_FILE"
  log_ok "Credentials generated → ${CONFIG_FILE}"
}

#── System update & base packages ────────────────────────────────────────────
install_base() {
  log_step "System Update & Base Packages"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y \
    curl wget gnupg2 software-properties-common apt-transport-https \
    ca-certificates lsb-release ufw jq openssl rsync zip unzip \
    cron logrotate

  log_ok "Base packages installed"
}

#── OpenLiteSpeed ─────────────────────────────────────────────────────────────
install_openlitespeed() {
  log_step "Installing OpenLiteSpeed"

  # Add OLS repository
  if [[ ! -f /etc/apt/sources.list.d/lst_debian_repo.list ]]; then
    wget -qO - https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg \
      | gpg --dearmor -o /usr/share/keyrings/lst-debian-repo.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/lst-debian-repo.gpg] \
      https://rpms.litespeedtech.com/debian/ $(lsb_release -sc) main" \
      > /etc/apt/sources.list.d/lst_debian_repo.list
    apt-get update -y
  fi

  apt-get install -y openlitespeed

  # Install lsphp81 + extensions
  apt-get install -y \
    lsphp81 lsphp81-common lsphp81-mysql lsphp81-curl \
    lsphp81-intl lsphp81-imap lsphp81-opcache lsphp81-mbstring

  # Set OLS admin password
  local ols_pass
  ols_pass=$(jq -r '.olsAdminPass' "$CONFIG_FILE")
  "${OLS_BASE}/admin/misc/admpass.sh" <<EOF
admin
${ols_pass}
${ols_pass}
EOF

  log_ok "OpenLiteSpeed installed (admin: admin / ${ols_pass})"
}

#── Configure OpenLiteSpeed ──────────────────────────────────────────────────
configure_openlitespeed() {
  log_step "Configuring OpenLiteSpeed"

  #── Main httpd_config.conf ──
  cat > "${OLS_BASE}/conf/httpd_config.conf" <<'HTTPCONF'
#
# LitePanel — OpenLiteSpeed Main Configuration
#
serverName                LitePanelServer
user                      nobody
group                     nogroup

autoLoadHtaccess          1
adminEmails               admin@localhost

errorlog $SERVER_ROOT/logs/error.log {
  logLevel                WARN
  debugLevel              0
  rollingSize             10M
  keepDays                30
  compressArchive         1
}

accesslog $SERVER_ROOT/logs/access.log {
  rollingSize             10M
  keepDays                30
  compressArchive         0
}

indexFiles                index.php, index.html

expires  {
  enableExpires           1
  expiresByType           image/*=A604800, text/css=A604800, application/javascript=A604800
}

tuning  {
  maxConnections          10000
  maxSSLConnections       10000
  connTimeout             300
  maxKeepAliveReq         10000
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
  SSLStrongDhKey          1
}

fileAccessControl  {
  followSymbolLink        1
  checkSymbolLink         0
  requiredPermissionMask  000
  restrictedPermissionMask 000
}

perClientConnLimit  {
  staticReqPerSec         0
  dynReqPerSec            0
  outBandwidth            0
  inBandwidth             0
  softLimit               10000
  hardLimit               10000
  gracePeriod             15
  banPeriod               300
}

CGIRLimit  {
  maxCGIInstances         20
  minUID                  11
  minGID                  10
  priority                0
  CPUSoftLimit            10
  CPUHardLimit            50
  memSoftLimit            1460M
  memHardLimit            1470M
  procSoftLimit           400
  procHardLimit           450
}

accessDenyDir  {
  dir                     /
  dir                     /etc/*
  dir                     /dev/*
  dir                     /proc/*
  dir                     /sys/*
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/lsphp81.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
  env                     LSAPI_AVOID_FORK=200M
  initTimeout             60
  retryTimeout            0
  pcKeepAliveTimeout      0
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

listener Default {
  address                 *:8088
  secure                  0
  map                     Example *
}

listenerAdmin {
  address                 *:7080
  secure                  1
}

vhTemplate centralConfigLog {
  templateFile            conf/templates/ccl.conf
  listeners               Default
}

module cache {
  internal                1
  checkPrivateCache       1
  checkPublicCache        1
  maxCacheObjSize         10000000
  maxStaleAge             200
  qsCache                 1
  reqCookieCache           1
  respCookieCache         1
  ignoreReqCacheCtrl      1
  ignoreRespCacheCtrl     0
  enableCache             0
  expireInSeconds         3600
  enablePrivateCache      0
  privateExpireInSeconds  3600
}

virtualhost Example {
  vhRoot                  /usr/local/lsws/Example
  configFile              conf/vhosts/Example/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
}
HTTPCONF

  #── Example vhost config ──
  mkdir -p "$OLS_VHOST_DIR"

  cat > "${OLS_VHOST_DIR}/vhconf.conf" <<'VHEOF'
docRoot                   $VH_ROOT/html

index  {
  useServer               0
  indexFiles              index.php, index.html
  autoIndex               0
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

accessControl  {
  allow                   *
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}
VHEOF

  # Ensure doc root exists
  mkdir -p "$OLS_DOC_ROOT"

  # Fix permissions
  chown -R nobody:nogroup "$OLS_DOC_ROOT"
  chown -R lsadm:lsadm "${OLS_BASE}/conf"

  systemctl enable lsws
  systemctl restart lsws

  log_ok "OpenLiteSpeed configured"
}

#── MariaDB ───────────────────────────────────────────────────────────────────
install_mariadb() {
  log_step "Installing MariaDB 10.6"

  apt-get install -y mariadb-server mariadb-client

  # Ensure service directories exist
  mkdir -p /var/run/mysqld
  chown mysql:mysql /var/run/mysqld
  chmod 755 /var/run/mysqld

  systemctl enable mariadb
  systemctl start mariadb

  # Wait for MariaDB to be ready
  local retries=0
  while ! mysqladmin ping --silent 2>/dev/null; do
    retries=$((retries + 1))
    if [[ $retries -ge 30 ]]; then
      log_error "MariaDB failed to start within 30 seconds"
      journalctl -u mariadb --no-pager -n 20
      exit 1
    fi
    sleep 1
  done

  log_ok "MariaDB 10.6 installed and running"
}

#── Configure MariaDB auth (safe & reliable) ─────────────────────────────────
configure_mariadb() {
  log_step "Configuring MariaDB Authentication"

  local db_pass
  db_pass=$(jq -r '.dbRootPass' "$CONFIG_FILE")

  # At fresh install, root uses unix_socket — this always works as root
  # Set dual auth: password (for apps/phpMyAdmin) + unix_socket (for CLI)
  mysql -u root <<SQLEOF
-- Remove anonymous users
DELETE FROM mysql.global_priv WHERE User='';
-- Remove remote root
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- Set root password with dual auth (MariaDB 10.4+)
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password BY '${db_pass}' OR unix_socket;
FLUSH PRIVILEGES;
SQLEOF

  if [[ $? -ne 0 ]]; then
    log_warn "Dual auth failed, trying simple password..."
    mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${db_pass}'; FLUSH PRIVILEGES;"
  fi

  # Create /root/.my.cnf for password-free CLI access
  cat > "$MY_CNF" <<MYCNF
[client]
user=root
password=${db_pass}
MYCNF
  chmod 600 "$MY_CNF"

  # Verify
  if mysql -e "SELECT 1" -s -N > /dev/null 2>&1; then
    log_ok "MariaDB auth configured (root / ${db_pass})"
  else
    log_error "MariaDB auth verification failed!"
    exit 1
  fi

  # MariaDB tuning for small VPS
  cat > /etc/mysql/conf.d/litepanel-tuning.cnf <<'TUNING'
[mysqld]
innodb_buffer_pool_size = 128M
innodb_log_file_size    = 48M
innodb_flush_method     = O_DIRECT
innodb_file_per_table   = 1
max_connections         = 100
key_buffer_size         = 16M
query_cache_type        = 1
query_cache_size        = 16M
tmp_table_size          = 32M
max_heap_table_size     = 32M
character-set-server    = utf8mb4
collation-server        = utf8mb4_unicode_ci
TUNING

  systemctl restart mariadb
  sleep 2

  log_ok "MariaDB tuning applied"
}

#── phpMyAdmin ────────────────────────────────────────────────────────────────
install_phpmyadmin() {
  log_step "Installing phpMyAdmin"

  local pma_version="5.2.1"
  local pma_url="https://files.phpmyadmin.net/phpMyAdmin/${pma_version}/phpMyAdmin-${pma_version}-all-languages.tar.gz"

  mkdir -p "$PMA_DIR"

  cd /tmp
  if wget -q "$pma_url" -O pma.tar.gz; then
    tar xzf pma.tar.gz
    cp -rf phpMyAdmin-${pma_version}-all-languages/* "$PMA_DIR/"
    rm -rf phpMyAdmin-${pma_version}-all-languages pma.tar.gz
  else
    log_warn "Specific version failed, trying latest..."
    wget -q "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz" -O pma.tar.gz
    tar xzf pma.tar.gz
    cp -rf phpMyAdmin-*/* "$PMA_DIR/"
    rm -rf phpMyAdmin-* pma.tar.gz
  fi

  # Configure phpMyAdmin
  local blowfish
  blowfish=$(jq -r '.pmaBlowfish' "$CONFIG_FILE")

  cat > "${PMA_DIR}/config.inc.php" <<PMACONF
<?php
\$cfg['blowfish_secret'] = '${blowfish}';

\$i = 0;
\$i++;

\$cfg['Servers'][\$i]['host']          = 'localhost';
\$cfg['Servers'][\$i]['port']          = '';
\$cfg['Servers'][\$i]['socket']        = '';
\$cfg['Servers'][\$i]['auth_type']     = 'cookie';
\$cfg['Servers'][\$i]['user']          = '';
\$cfg['Servers'][\$i]['password']      = '';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;

\$cfg['UploadDir']   = '';
\$cfg['SaveDir']     = '';
\$cfg['TempDir']     = '/tmp';
\$cfg['DefaultLang'] = 'en';
\$cfg['ThemeDefault'] = 'pmahomme';
PMACONF

  # Fix permissions
  chown -R nobody:nogroup "$PMA_DIR"

  # Verify
  if [[ -f "${PMA_DIR}/index.php" ]]; then
    log_ok "phpMyAdmin installed at ${PMA_DIR}"
  else
    log_error "phpMyAdmin installation failed!"
    exit 1
  fi
}

#── Node.js ───────────────────────────────────────────────────────────────────
install_nodejs() {
  log_step "Installing Node.js 18 LTS"

  if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
  fi

  local node_ver
  node_ver=$(node -v)
  log_ok "Node.js ${node_ver} installed"

  # Install panel dependencies
  cd "$PANEL_DIR"
  cat > package.json <<'PKGJSON'
{
  "name": "litepanel",
  "version": "2.0.0",
  "private": true,
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "cookie-parser": "^1.4.6"
  }
}
PKGJSON
  npm install --production
  log_ok "Panel dependencies installed"
}

#── Panel Backend (app.js) ────────────────────────────────────────────────────
create_panel_backend() {
  log_step "Creating Panel Backend"

  cat > "${PANEL_DIR}/app.js" <<'APPJS'
/******************************************************************************
 * LitePanel v2.0 — Backend API Server
 * Node.js + Express — Production-grade hosting control panel
 *****************************************************************************/

'use strict';

var express    = require('express');
var cp         = require('child_process');
var fs         = require('fs');
var path       = require('path');
var jwt        = require('jsonwebtoken');
var cookieParser = require('cookie-parser');

var app     = express();
var config  = JSON.parse(fs.readFileSync('/opt/litepanel/config.json', 'utf8'));
var SECRET  = config.jwtSecret || 'fallback-secret-change-me';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

/*─── Helpers ──────────────────────────────────────────────────────────────*/

/**
 * Execute a shell command synchronously.
 * Returns stdout on success, throws on failure.
 */
function run(cmd) {
  try {
    return cp.execSync(cmd, {
      encoding: 'utf8',
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch (e) {
    var stderr = (e.stderr || '').trim();
    var stdout = (e.stdout || '').trim();
    throw new Error(stderr || stdout || 'Command failed: ' + cmd);
  }
}

/**
 * Execute a MySQL query using a temporary SQL file.
 * Prevents shell injection by never interpolating SQL into command line.
 */
function mysqlQuery(sql) {
  var tmpFile = '/tmp/lp_sql_' + Date.now() + '_' + Math.random().toString(36).slice(2) + '.sql';
  fs.writeFileSync(tmpFile, sql, { mode: 0o600 });
  try {
    var result = run('mysql --defaults-file=/root/.my.cnf -s -N < ' + tmpFile);
    fs.unlinkSync(tmpFile);
    return result;
  } catch (e) {
    try { fs.unlinkSync(tmpFile); } catch (x) { /* ignore */ }
    throw e;
  }
}

/**
 * Execute a MySQL statement (no output expected).
 */
function mysqlExec(sql) {
  var tmpFile = '/tmp/lp_sql_' + Date.now() + '_' + Math.random().toString(36).slice(2) + '.sql';
  fs.writeFileSync(tmpFile, sql, { mode: 0o600 });
  try {
    run('mysql --defaults-file=/root/.my.cnf < ' + tmpFile);
    fs.unlinkSync(tmpFile);
  } catch (e) {
    try { fs.unlinkSync(tmpFile); } catch (x) { /* ignore */ }
    throw e;
  }
}

/**
 * Read a file safely, return empty string on error.
 */
function readFileSafe(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch (e) { return ''; }
}

/**
 * Validate names: only letters, numbers, underscore.
 */
function isValidName(str) {
  return /^[a-zA-Z0-9_]+$/.test(str);
}

/*─── Authentication ───────────────────────────────────────────────────────*/

function auth(req, res, next) {
  var token = req.cookies.token ||
    (req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null);

  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    jwt.verify(token, SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/*─── Auth Routes ──────────────────────────────────────────────────────────*/

app.post('/api/login', function (req, res) {
  var user = (req.body.user || '').trim();
  var pass = (req.body.pass || '').trim();

  if (user === config.panelUser && pass === config.panelPass) {
    var token = jwt.sign({ user: user }, SECRET, { expiresIn: '24h' });
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 86400000
    });
    return res.json({ ok: true });
  }

  return res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', function (req, res) {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/auth/check', auth, function (req, res) {
  res.json({ ok: true });
});

/*─── Dashboard ────────────────────────────────────────────────────────────*/

app.get('/api/dashboard', auth, function (req, res) {
  try {
    var hostname  = run('hostname');
    var uptime    = run('uptime -p');
    var loadAvg   = run("cat /proc/loadavg | awk '{print $1, $2, $3}'");
    var memInfo   = run("free -m | awk '/Mem:/{printf \"%d/%d MB (%.0f%%)\", $3, $2, $3/$2*100}'");
    var diskInfo  = run("df -h / | awk 'NR==2{printf \"%s/%s (%s)\", $3, $2, $5}'");
    var os        = run("lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2");
    var kernel    = run('uname -r');
    var serverIp  = run("hostname -I | awk '{print $1}'");

    // Count websites (vhosts)
    var vhostDir = '/usr/local/lsws/conf/vhosts';
    var sites = 0;
    try {
      var dirs = fs.readdirSync(vhostDir);
      sites = dirs.filter(function (d) { return d !== 'Example'; }).length;
    } catch (e) { /* ignore */ }

    // Count databases
    var dbCount = 0;
    try {
      var dbOut = mysqlQuery('SHOW DATABASES;');
      var skip = ['information_schema', 'performance_schema', 'mysql', 'sys'];
      dbCount = dbOut.split('\n').filter(function (d) {
        return d.trim() && !skip.includes(d.trim());
      }).length;
    } catch (e) { /* ignore */ }

    res.json({
      hostname: hostname,
      uptime: uptime,
      load: loadAvg,
      memory: memInfo,
      disk: diskInfo,
      os: os,
      kernel: kernel,
      ip: serverIp,
      sites: sites,
      databases: dbCount,
      panelPort: config.panelPort || 3000,
      olsPort: 8088,
      olsAdminPort: 7080,
      olsAdminUser: 'admin',
      olsAdminPass: config.olsAdminPass,
      panelUser: config.panelUser,
      panelPass: config.panelPass,
      dbRootPass: config.dbRootPass
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/*─── Services ─────────────────────────────────────────────────────────────*/

var SERVICES = ['lsws', 'mariadb', 'fail2ban', 'cloudflared'];

app.get('/api/services', auth, function (req, res) {
  var result = [];
  SERVICES.forEach(function (svc) {
    var running = false;
    try {
      run('systemctl is-active ' + svc);
      running = true;
    } catch (e) { /* not running */ }
    result.push({ name: svc, running: running });
  });
  res.json(result);
});

app.post('/api/services/:name/:action', auth, function (req, res) {
  var name   = req.params.name;
  var action = req.params.action;

  if (!SERVICES.includes(name)) {
    return res.status(400).json({ error: 'Unknown service: ' + name });
  }
  if (!['start', 'stop', 'restart'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action: ' + action });
  }

  try {
    run('systemctl ' + action + ' ' + name);
    res.json({ ok: true, message: name + ' ' + action + 'ed successfully' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to ' + action + ' ' + name + ': ' + e.message });
  }
});

/*─── Databases ────────────────────────────────────────────────────────────*/

app.get('/api/databases', auth, function (req, res) {
  try {
    var out  = mysqlQuery('SHOW DATABASES;');
    var skip = ['information_schema', 'performance_schema', 'mysql', 'sys'];
    var dbs  = out.split('\n').filter(function (d) {
      return d.trim() && !skip.includes(d.trim());
    });
    res.json(dbs);
  } catch (e) {
    res.json([]);
  }
});

app.post('/api/databases', auth, function (req, res) {
  var name     = (req.body.name || '').trim();
  var user     = (req.body.user || '').trim();
  var password = (req.body.password || '').trim();

  if (!name || !isValidName(name)) {
    return res.status(400).json({ error: 'Invalid DB name (letters, numbers, underscore only)' });
  }
  if (user && !isValidName(user)) {
    return res.status(400).json({ error: 'Invalid username (letters, numbers, underscore only)' });
  }

  try {
    mysqlExec('CREATE DATABASE `' + name + '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;');

    if (user && password) {
      mysqlExec("CREATE USER '" + user + "'@'localhost' IDENTIFIED BY '" + password.replace(/'/g, "\\'") + "';");
      mysqlExec("GRANT ALL PRIVILEGES ON `" + name + "`.* TO '" + user + "'@'localhost';");
      mysqlExec('FLUSH PRIVILEGES;');
    }

    res.json({ ok: true, message: 'Database "' + name + '" created' + (user ? ' with user "' + user + '"' : '') });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/databases/:name', auth, function (req, res) {
  var name = req.params.name;

  if (!isValidName(name)) {
    return res.status(400).json({ error: 'Invalid database name' });
  }

  try {
    mysqlExec('DROP DATABASE IF EXISTS `' + name + '`;');
    res.json({ ok: true, message: 'Database "' + name + '" dropped' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/*─── Websites ─────────────────────────────────────────────────────────────*/

app.get('/api/websites', auth, function (req, res) {
  var vhostRoot = '/usr/local/lsws/conf/vhosts';
  try {
    var dirs = fs.readdirSync(vhostRoot).filter(function (d) {
      return d !== 'Example' && fs.statSync(path.join(vhostRoot, d)).isDirectory();
    });

    var sites = dirs.map(function (name) {
      var confFile = path.join(vhostRoot, name, 'vhconf.conf');
      var conf = readFileSafe(confFile);
      var docRootMatch = conf.match(/docRoot\s+(.+)/);
      var docRoot = docRootMatch ? docRootMatch[1].trim() : '/var/www/' + name;
      return { name: name, docRoot: docRoot };
    });

    res.json(sites);
  } catch (e) {
    res.json([]);
  }
});

app.post('/api/websites', auth, function (req, res) {
  var domain = (req.body.domain || '').trim().toLowerCase();

  if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain name' });
  }

  var vhDir   = '/usr/local/lsws/conf/vhosts/' + domain;
  var docRoot = '/var/www/' + domain + '/html';

  if (fs.existsSync(vhDir)) {
    return res.status(400).json({ error: 'Website already exists' });
  }

  try {
    // Create directories
    fs.mkdirSync(vhDir, { recursive: true });
    fs.mkdirSync(docRoot, { recursive: true });

    // Create vhost config
    var vhConf = [
      'docRoot                   ' + docRoot,
      '',
      'index  {',
      '  useServer               0',
      '  indexFiles              index.php, index.html',
      '  autoIndex               0',
      '}',
      '',
      'scripthandler  {',
      '  add                     lsapi:lsphp81 php',
      '}',
      '',
      'accessControl  {',
      '  allow                   *',
      '}',
      '',
      'rewrite  {',
      '  enable                  1',
      '  autoLoadHtaccess        1',
      '}',
    ].join('\n');

    fs.writeFileSync(path.join(vhDir, 'vhconf.conf'), vhConf);

    // Create default index page
    var indexHtml = [
      '<!DOCTYPE html>',
      '<html><head><title>' + domain + '</title></head>',
      '<body><h1>Welcome to ' + domain + '</h1>',
      '<p>Website is ready. Upload your files to ' + docRoot + '</p>',
      '</body></html>'
    ].join('\n');

    fs.writeFileSync(path.join(docRoot, 'index.html'), indexHtml);

    // Add vhost to main OLS config
    var mainConf = readFileSafe('/usr/local/lsws/conf/httpd_config.conf');

    // Add virtualhost block
    var vhBlock = [
      '',
      'virtualhost ' + domain + ' {',
      '  vhRoot                  /var/www/' + domain,
      '  configFile              conf/vhosts/' + domain + '/vhconf.conf',
      '  allowSymbolLink         1',
      '  enableScript            1',
      '  restrained              0',
      '}',
    ].join('\n');

    if (mainConf.indexOf('virtualhost ' + domain) === -1) {
      fs.appendFileSync('/usr/local/lsws/conf/httpd_config.conf', vhBlock);
    }

    // Add listener mapping
    var mapLine = '  map                     ' + domain + ' ' + domain;
    if (mainConf.indexOf(mapLine.trim()) === -1) {
      // Insert map line into Default listener
      mainConf = readFileSafe('/usr/local/lsws/conf/httpd_config.conf');
      mainConf = mainConf.replace(
        /(listener Default \{[^}]*map\s+Example \*)/,
        '$1\n' + mapLine
      );
      fs.writeFileSync('/usr/local/lsws/conf/httpd_config.conf', mainConf);
    }

    // Fix permissions
    run('chown -R nobody:nogroup ' + docRoot);
    run('chown -R lsadm:lsadm ' + vhDir);

    // Graceful restart OLS
    run('systemctl restart lsws');

    res.json({ ok: true, message: 'Website "' + domain + '" created', docRoot: docRoot });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/websites/:name', auth, function (req, res) {
  var name = req.params.name;

  if (name === 'Example') {
    return res.status(400).json({ error: 'Cannot delete default vhost' });
  }

  try {
    // Remove vhost directory
    var vhDir = '/usr/local/lsws/conf/vhosts/' + name;
    if (fs.existsSync(vhDir)) {
      run('rm -rf ' + vhDir);
    }

    // Remove from main config
    var mainConf = readFileSafe('/usr/local/lsws/conf/httpd_config.conf');

    // Remove virtualhost block
    var vhRegex = new RegExp('\\nvirtualhost ' + name.replace(/\./g, '\\.') + ' \\{[^}]*\\}', 'g');
    mainConf = mainConf.replace(vhRegex, '');

    // Remove listener map
    var mapRegex = new RegExp('\\n\\s*map\\s+' + name.replace(/\./g, '\\.') + '\\s+' + name.replace(/\./g, '\\.'), 'g');
    mainConf = mainConf.replace(mapRegex, '');

    fs.writeFileSync('/usr/local/lsws/conf/httpd_config.conf', mainConf);

    run('systemctl restart lsws');

    res.json({ ok: true, message: 'Website "' + name + '" deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/*─── File Manager ─────────────────────────────────────────────────────────*/

app.get('/api/files', auth, function (req, res) {
  var dir = req.query.path || '/var/www';

  // Security: prevent directory traversal
  var resolved = path.resolve(dir);
  if (!resolved.startsWith('/var/www') && !resolved.startsWith('/usr/local/lsws/Example/html')) {
    return res.status(403).json({ error: 'Access denied: path outside allowed directories' });
  }

  try {
    var items = fs.readdirSync(resolved).map(function (name) {
      var fullPath = path.join(resolved, name);
      try {
        var stat = fs.statSync(fullPath);
        return {
          name: name,
          path: fullPath,
          isDir: stat.isDirectory(),
          size: stat.size,
          modified: stat.mtime,
          permissions: '0' + (stat.mode & parseInt('777', 8)).toString(8)
        };
      } catch (e) {
        return { name: name, path: fullPath, isDir: false, size: 0, error: true };
      }
    });

    // Sort: directories first, then alphabetical
    items.sort(function (a, b) {
      if (a.isDir && !b.isDir) return -1;
      if (!a.isDir && b.isDir) return 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ path: resolved, items: items });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/files/read', auth, function (req, res) {
  var filePath = req.query.path;

  if (!filePath) {
    return res.status(400).json({ error: 'Path required' });
  }

  var resolved = path.resolve(filePath);
  if (!resolved.startsWith('/var/www') && !resolved.startsWith('/usr/local/lsws/Example/html')) {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    var stat = fs.statSync(resolved);
    if (stat.size > 2 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large (max 2MB)' });
    }
    var content = fs.readFileSync(resolved, 'utf8');
    res.json({ path: resolved, content: content });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/files/save', auth, function (req, res) {
  var filePath = req.body.path;
  var content  = req.body.content;

  if (!filePath) {
    return res.status(400).json({ error: 'Path required' });
  }

  var resolved = path.resolve(filePath);
  if (!resolved.startsWith('/var/www') && !resolved.startsWith('/usr/local/lsws/Example/html')) {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    fs.writeFileSync(resolved, content || '');
    res.json({ ok: true, message: 'File saved' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/*─── Domains / DNS (Cloudflare Tunnel) ────────────────────────────────────*/

app.get('/api/tunnel/status', auth, function (req, res) {
  try {
    var confPath = '/etc/cloudflared/config.yml';
    var conf = readFileSafe(confPath);
    var running = false;
    try {
      run('systemctl is-active cloudflared');
      running = true;
    } catch (e) { /* not running */ }

    res.json({
      installed: fs.existsSync('/usr/bin/cloudflared') || fs.existsSync('/usr/local/bin/cloudflared'),
      running: running,
      config: conf
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/*─── Fail2Ban ─────────────────────────────────────────────────────────────*/

app.get('/api/fail2ban/status', auth, function (req, res) {
  try {
    var status = run('fail2ban-client status');
    var jails = [];

    var match = status.match(/Jail list:\s*(.+)/);
    if (match) {
      jails = match[1].split(',').map(function (j) { return j.trim(); }).filter(Boolean);
    }

    var jailDetails = jails.map(function (jail) {
      try {
        var info = run('fail2ban-client status ' + jail);
        var banned = 0;
        var banMatch = info.match(/Currently banned:\s*(\d+)/);
        if (banMatch) banned = parseInt(banMatch[1]);
        return { name: jail, banned: banned };
      } catch (e) {
        return { name: jail, banned: 0 };
      }
    });

    res.json(jailDetails);
  } catch (e) {
    res.json([]);
  }
});

/*─── System Info ──────────────────────────────────────────────────────────*/

app.get('/api/system/processes', auth, function (req, res) {
  try {
    var out = run("ps aux --sort=-%mem | head -20");
    var lines = out.split('\n');
    var processes = lines.slice(1).map(function (line) {
      var parts = line.trim().split(/\s+/);
      return {
        user: parts[0],
        pid: parts[1],
        cpu: parts[2],
        mem: parts[3],
        command: parts.slice(10).join(' ')
      };
    });
    res.json(processes);
  } catch (e) {
    res.json([]);
  }
});

/*─── Catch-all: serve frontend ────────────────────────────────────────────*/

app.get('*', function (req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/*─── Start server ─────────────────────────────────────────────────────────*/

var PORT = config.panelPort || 3000;
app.listen(PORT, '0.0.0.0', function () {
  console.log('LitePanel v2.0 running on port ' + PORT);
});
APPJS

  log_ok "Panel backend created"
}

#── Panel Frontend ────────────────────────────────────────────────────────────
create_panel_frontend() {
  log_step "Creating Panel Frontend"

  mkdir -p "${PANEL_DIR}/public"

  cat > "${PANEL_DIR}/public/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LitePanel</title>
<style>
:root {
  --bg: #0f172a;
  --bg2: #1e293b;
  --bg3: #334155;
  --fg: #e2e8f0;
  --fg2: #94a3b8;
  --accent: #3b82f6;
  --accent2: #2563eb;
  --green: #22c55e;
  --red: #ef4444;
  --orange: #f59e0b;
  --radius: 8px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--fg);
  min-height: 100vh;
}

/* ─── Login ─── */
.login-wrap {
  display: flex; justify-content: center; align-items: center;
  min-height: 100vh; padding: 20px;
}
.login-box {
  background: var(--bg2); padding: 40px; border-radius: 12px;
  width: 100%; max-width: 400px; box-shadow: 0 25px 50px rgba(0,0,0,0.3);
}
.login-box h1 { text-align: center; margin-bottom: 8px; font-size: 28px; }
.login-box p { text-align: center; color: var(--fg2); margin-bottom: 24px; }

input, select, textarea {
  width: 100%; padding: 10px 14px; border-radius: var(--radius);
  border: 1px solid var(--bg3); background: var(--bg); color: var(--fg);
  font-size: 14px; outline: none; margin-bottom: 12px;
}
input:focus, select:focus, textarea:focus { border-color: var(--accent); }

button, .btn {
  padding: 10px 20px; border-radius: var(--radius); border: none;
  background: var(--accent); color: white; font-size: 14px;
  cursor: pointer; font-weight: 600; transition: background 0.2s;
}
button:hover, .btn:hover { background: var(--accent2); }

.btn-sm { padding: 5px 12px; font-size: 12px; }
.btn-red { background: var(--red); }
.btn-red:hover { background: #dc2626; }
.btn-green { background: var(--green); }
.btn-green:hover { background: #16a34a; }
.btn-orange { background: var(--orange); }

/* ─── Layout ─── */
.app { display: flex; min-height: 100vh; }

.sidebar {
  width: 240px; background: var(--bg2); padding: 20px 0;
  border-right: 1px solid var(--bg3); flex-shrink: 0;
}
.sidebar h2 {
  padding: 0 20px 20px; font-size: 20px;
  border-bottom: 1px solid var(--bg3); margin-bottom: 10px;
}
.sidebar a {
  display: block; padding: 12px 20px; color: var(--fg2);
  text-decoration: none; transition: all 0.2s; font-size: 14px;
}
.sidebar a:hover, .sidebar a.active { color: var(--fg); background: var(--bg3); }
.sidebar a .icon { margin-right: 10px; width: 20px; display: inline-block; }

.main { flex: 1; padding: 30px; overflow-x: auto; }

.main h2 {
  font-size: 22px; margin-bottom: 4px;
}
.main .subtitle { color: var(--fg2); margin-bottom: 24px; font-size: 14px; }

/* ─── Cards ─── */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; margin-bottom: 30px; }
.card {
  background: var(--bg2); padding: 20px; border-radius: var(--radius);
  border: 1px solid var(--bg3);
}
.card .label { color: var(--fg2); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
.card .value { font-size: 20px; font-weight: 700; margin-top: 6px; }

/* ─── Tables ─── */
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--bg3); }
th { color: var(--fg2); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; background: var(--bg2); }
td { font-size: 14px; }
tr:hover td { background: var(--bg2); }

/* ─── Status badges ─── */
.badge { padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
.badge-green { background: rgba(34,197,94,0.15); color: var(--green); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); }

/* ─── Alerts ─── */
.alert { padding: 12px 16px; border-radius: var(--radius); margin-bottom: 16px; font-size: 14px; }
.alert-ok { background: rgba(34,197,94,0.1); color: var(--green); border: 1px solid rgba(34,197,94,0.2); }
.alert-err { background: rgba(239,68,68,0.1); color: var(--red); border: 1px solid rgba(239,68,68,0.2); }

/* ─── Flex ─── */
.flex-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; margin-bottom: 16px; }
.flex-row > div { flex: 1; min-width: 150px; }
.flex-row label { display: block; color: var(--fg2); font-size: 12px; margin-bottom: 4px; text-transform: uppercase; }

/* ─── Info box ─── */
.info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 16px; }
.info-item { display: flex; justify-content: space-between; padding: 10px 14px; background: var(--bg2); border-radius: var(--radius); }
.info-item .lbl { color: var(--fg2); }
.info-item .val { font-weight: 600; font-family: monospace; }

/* ─── Responsive ─── */
@media (max-width: 768px) {
  .app { flex-direction: column; }
  .sidebar { width: 100%; display: flex; overflow-x: auto; border-right: none; border-bottom: 1px solid var(--bg3); }
  .sidebar h2 { display: none; }
  .sidebar a { white-space: nowrap; padding: 10px 16px; }
  .main { padding: 20px; }
  .cards { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>
<div id="app"></div>

<script>
(function(){
'use strict';

/*──── API helper ────*/
var api = {
  get: function(url) {
    return fetch(url, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); });
  },
  post: function(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(function(r) { return r.json(); });
  },
  del: function(url) {
    return fetch(url, {
      method: 'DELETE', credentials: 'same-origin'
    }).then(function(r) { return r.json(); });
  }
};

/*──── Router ────*/
function navigate(page) {
  api.get('/api/auth/check').then(function() {
    renderApp(page);
  }).catch(function() {
    renderLogin();
  });
}

/*──── Login Page ────*/
function renderLogin() {
  var app = document.getElementById('app');
  app.innerHTML =
    '<div class="login-wrap"><div class="login-box">' +
    '<h1>⚡ LitePanel</h1><p>Server Control Panel</p>' +
    '<div id="loginMsg"></div>' +
    '<input id="user" type="text" placeholder="Username" autofocus>' +
    '<input id="pass" type="password" placeholder="Password">' +
    '<button onclick="doLogin()" style="width:100%">Sign In</button>' +
    '</div></div>';

  document.getElementById('pass').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') doLogin();
  });
}

window.doLogin = function() {
  var user = document.getElementById('user').value;
  var pass = document.getElementById('pass').value;
  api.post('/api/login', { user: user, pass: pass }).then(function(r) {
    if (r.ok) navigate('dashboard');
    else document.getElementById('loginMsg').innerHTML = '<div class="alert alert-err">' + (r.error || 'Login failed') + '</div>';
  }).catch(function() {
    document.getElementById('loginMsg').innerHTML = '<div class="alert alert-err">Connection error</div>';
  });
};

/*──── App Shell ────*/
function renderApp(page) {
  var app = document.getElementById('app');
  var pages = [
    { id: 'dashboard', icon: '📊', label: 'Dashboard' },
    { id: 'websites',  icon: '🌐', label: 'Websites' },
    { id: 'databases', icon: '🗄️', label: 'Databases' },
    { id: 'files',     icon: '📁', label: 'File Manager' },
    { id: 'services',  icon: '⚙️', label: 'Services' },
    { id: 'security',  icon: '🛡️', label: 'Security' },
  ];

  var nav = pages.map(function(p) {
    return '<a href="#" class="' + (p.id === page ? 'active' : '') + '" onclick="navigateTo(\'' + p.id + '\')">' +
      '<span class="icon">' + p.icon + '</span>' + p.label + '</a>';
  }).join('');

  app.innerHTML =
    '<div class="app">' +
    '<div class="sidebar">' +
    '<h2>⚡ LitePanel</h2>' + nav +
    '<a href="#" onclick="doLogout()" style="margin-top:auto;border-top:1px solid var(--bg3)"><span class="icon">🚪</span>Logout</a>' +
    '</div>' +
    '<div class="main" id="content">Loading...</div>' +
    '</div>';

  var contentEl = document.getElementById('content');
  var pageFn = {
    dashboard: pgDash,
    websites: pgSites,
    databases: pgDb,
    files: pgFiles,
    services: pgSvc,
    security: pgSec,
  };

  if (pageFn[page]) pageFn[page](contentEl);
}

window.navigateTo = function(page) { renderApp(page); };
window.doLogout = function() { api.post('/api/logout').then(function() { renderLogin(); }); };

/*──── Dashboard ────*/
function pgDash(el) {
  api.get('/api/dashboard').then(function(d) {
    el.innerHTML =
      '<h2>Dashboard</h2><p class="subtitle">Server overview</p>' +
      '<div class="cards">' +
        card('Hostname', d.hostname) +
        card('Uptime', d.uptime) +
        card('Load', d.load) +
        card('Memory', d.memory) +
        card('Disk', d.disk) +
        card('OS', d.os) +
        card('Kernel', d.kernel) +
        card('IP', d.ip) +
        card('Websites', d.sites) +
        card('Databases', d.databases) +
      '</div>' +
      '<h2>Quick Access</h2><p class="subtitle">Credentials &amp; links</p>' +
      '<div class="info-grid">' +
        info('Panel URL', 'http://' + d.ip + ':' + d.panelPort) +
        info('Panel Login', d.panelUser + ' / ' + d.panelPass) +
        info('OLS Admin', 'https://' + d.ip + ':' + d.olsAdminPort) +
        info('OLS Login', d.olsAdminUser + ' / ' + d.olsAdminPass) +
        info('phpMyAdmin', 'http://' + d.ip + ':' + d.olsPort + '/phpmyadmin/') +
        info('DB Login', 'root / ' + d.dbRootPass) +
      '</div>';
  });
}

function card(label, value) {
  return '<div class="card"><div class="label">' + label + '</div><div class="value">' + (value || '-') + '</div></div>';
}
function info(label, value) {
  return '<div class="info-item"><span class="lbl">' + label + '</span><span class="val">' + value + '</span></div>';
}

/*──── Websites ────*/
function pgSites(el) {
  api.get('/api/websites').then(function(sites) {
    var rows = sites.map(function(s) {
      return '<tr><td>' + s.name + '</td><td><code>' + s.docRoot + '</code></td>' +
        '<td><button class="btn-sm btn-red" onclick="delSite(\'' + s.name + '\')">Delete</button></td></tr>';
    }).join('');

    el.innerHTML =
      '<h2>Websites</h2><p class="subtitle">Manage virtual hosts</p>' +
      '<div id="siteMsg"></div>' +
      '<div class="flex-row">' +
        '<div><label>Domain</label><input id="newDomain" placeholder="example.com"></div>' +
        '<div><button onclick="addSite()">Create Website</button></div>' +
      '</div>' +
      '<table><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="3" style="color:var(--fg2)">No websites yet</td></tr>') + '</tbody></table>';
  });
}

window.addSite = function() {
  var domain = document.getElementById('newDomain').value.trim();
  if (!domain) return;
  api.post('/api/websites', { domain: domain }).then(function(r) {
    document.getElementById('siteMsg').innerHTML = r.ok ?
      '<div class="alert alert-ok">' + r.message + '</div>' :
      '<div class="alert alert-err">' + r.error + '</div>';
    if (r.ok) setTimeout(function() { navigateTo('websites'); }, 1000);
  });
};

window.delSite = function(name) {
  if (!confirm('Delete website "' + name + '"? This removes the vhost config.')) return;
  api.del('/api/websites/' + name).then(function(r) {
    navigateTo('websites');
  });
};

/*──── Databases ────*/
function pgDb(el) {
  Promise.all([api.get('/api/databases'), api.get('/api/dashboard')]).then(function(res) {
    var d = res[0], info = res[1];
    var rows = (Array.isArray(d) ? d : []).map(function(x) {
      return '<tr><td>' + x + '</td><td><button class="btn-sm btn-red" onclick="dropDb(\'' + x + '\')">Drop</button></td></tr>';
    }).join('');

    el.innerHTML =
      '<h2>Databases</h2><p class="subtitle">MariaDB management</p>' +
      '<div id="dbMsg"></div>' +
      '<div class="flex-row">' +
        '<div><label>Database</label><input id="dbName" placeholder="my_database"></div>' +
        '<div><label>User (optional)</label><input id="dbUser" placeholder="db_user"></div>' +
        '<div><label>Password</label><input id="dbPass" type="password" placeholder="password"></div>' +
        '<div><button onclick="createDb()">Create</button></div>' +
      '</div>' +
      '<table><thead><tr><th>Database</th><th>Actions</th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="2" style="color:var(--fg2)">No databases</td></tr>') + '</tbody></table>' +
      '<div style="margin-top:20px">' +
        '<a href="http://' + info.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-orange">Open phpMyAdmin</a>' +
        ' <span style="color:var(--fg2);font-size:13px">Login: root / ' + info.dbRootPass + '</span>' +
      '</div>';
  });
}

window.createDb = function() {
  var name = document.getElementById('dbName').value.trim();
  var user = document.getElementById('dbUser').value.trim();
  var pass = document.getElementById('dbPass').value;
  if (!name) return;
  api.post('/api/databases', { name: name, user: user, password: pass }).then(function(r) {
    document.getElementById('dbMsg').innerHTML = r.ok ?
      '<div class="alert alert-ok">' + r.message + '</div>' :
      '<div class="alert alert-err">' + r.error + '</div>';
    if (r.ok) setTimeout(function() { navigateTo('databases'); }, 1000);
  });
};

window.dropDb = function(name) {
  if (!confirm('Drop database "' + name + '"? This cannot be undone!')) return;
  api.del('/api/databases/' + name).then(function() { navigateTo('databases'); });
};

/*──── File Manager ────*/
function pgFiles(el) {
  var currentPath = '/var/www';
  loadDir(currentPath);

  function loadDir(dir) {
    currentPath = dir;
    api.get('/api/files?path=' + encodeURIComponent(dir)).then(function(data) {
      var rows = '';

      // Parent directory link
      if (dir !== '/var/www') {
        var parent = dir.split('/').slice(0, -1).join('/') || '/var/www';
        rows += '<tr onclick="fileNav(\'' + parent + '\')" style="cursor:pointer"><td>📁 ..</td><td></td><td></td></tr>';
      }

      rows += data.items.map(function(f) {
        var icon = f.isDir ? '📁' : '📄';
        var click = f.isDir ?
          'onclick="fileNav(\'' + f.path + '\')" style="cursor:pointer"' :
          'onclick="fileEdit(\'' + f.path + '\')" style="cursor:pointer"';
        var size = f.isDir ? '-' : formatSize(f.size);
        return '<tr ' + click + '><td>' + icon + ' ' + f.name + '</td><td>' + size + '</td><td>' + (f.permissions || '') + '</td></tr>';
      }).join('');

      el.innerHTML =
        '<h2>File Manager</h2><p class="subtitle">' + data.path + '</p>' +
        '<div id="fileMsg"></div>' +
        '<table><thead><tr><th>Name</th><th>Size</th><th>Perms</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table>';
    });
  }

  window.fileNav = function(dir) { loadDir(dir); };

  window.fileEdit = function(filepath) {
    api.get('/api/files/read?path=' + encodeURIComponent(filepath)).then(function(data) {
      el.innerHTML =
        '<h2>Edit File</h2><p class="subtitle">' + data.path + '</p>' +
        '<div id="fileMsg"></div>' +
        '<textarea id="fileContent" style="width:100%;height:400px;font-family:monospace;font-size:13px">' +
        escapeHtml(data.content) + '</textarea>' +
        '<div style="margin-top:12px">' +
          '<button onclick="fileSave(\'' + data.path + '\')">💾 Save</button> ' +
          '<button class="btn-red" onclick="fileNav(\'' + data.path.split('/').slice(0,-1).join('/') + '\')">Cancel</button>' +
        '</div>';
    }).catch(function(e) {
      el.innerHTML += '<div class="alert alert-err">Cannot read file</div>';
    });
  };

  window.fileSave = function(filepath) {
    var content = document.getElementById('fileContent').value;
    api.post('/api/files/save', { path: filepath, content: content }).then(function(r) {
      document.getElementById('fileMsg').innerHTML = r.ok ?
        '<div class="alert alert-ok">File saved!</div>' :
        '<div class="alert alert-err">' + r.error + '</div>';
    });
  };
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  var k = 1024;
  var sizes = ['B', 'KB', 'MB', 'GB'];
  var i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/*──── Services ────*/
function pgSvc(el) {
  api.get('/api/services').then(function(svcs) {
    var rows = svcs.map(function(s) {
      var badge = s.running ?
        '<span class="badge badge-green">Running</span>' :
        '<span class="badge badge-red">Stopped</span>';
      return '<tr><td><strong>' + s.name + '</strong></td><td>' + badge + '</td><td>' +
        '<button class="btn-sm btn-green" onclick="svcAction(\'' + s.name + '\',\'start\')">Start</button> ' +
        '<button class="btn-sm btn-red" onclick="svcAction(\'' + s.name + '\',\'stop\')">Stop</button> ' +
        '<button class="btn-sm" onclick="svcAction(\'' + s.name + '\',\'restart\')">Restart</button>' +
        '</td></tr>';
    }).join('');

    el.innerHTML =
      '<h2>Services</h2><p class="subtitle">Manage services</p>' +
      '<div id="svcMsg"></div>' +
      '<table><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>';
  });
}

window.svcAction = function(name, action) {
  api.post('/api/services/' + name + '/' + action).then(function(r) {
    document.getElementById('svcMsg').innerHTML = r.ok ?
      '<div class="alert alert-ok">' + r.message + '</div>' :
      '<div class="alert alert-err">' + r.error + '</div>';
    setTimeout(function() { navigateTo('services'); }, 1500);
  });
};

/*──── Security (Fail2Ban) ────*/
function pgSec(el) {
  api.get('/api/fail2ban/status').then(function(jails) {
    var rows = jails.map(function(j) {
      return '<tr><td>' + j.name + '</td><td>' + j.banned + '</td></tr>';
    }).join('');

    el.innerHTML =
      '<h2>Security</h2><p class="subtitle">Fail2Ban status</p>' +
      '<table><thead><tr><th>Jail</th><th>Currently Banned</th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="2" style="color:var(--fg2)">No jails configured</td></tr>') + '</tbody></table>';
  });
}

/*──── Init ────*/
navigate('dashboard');

})();
</script>
</body>
</html>
HTMLEOF

  log_ok "Panel frontend created"
}

#── Systemd service ───────────────────────────────────────────────────────────
create_systemd_service() {
  log_step "Creating Systemd Service"

  cat > /etc/systemd/system/litepanel.service <<SVCEOF
[Unit]
Description=LitePanel Control Panel
After=network.target mariadb.service lsws.service
Wants=mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
ExecStart=/usr/bin/node ${PANEL_DIR}/app.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable litepanel
  systemctl start litepanel

  log_ok "LitePanel service created and started"
}

#── Fail2Ban ──────────────────────────────────────────────────────────────────
install_fail2ban() {
  log_step "Installing & Configuring Fail2Ban"

  apt-get install -y fail2ban

  # SSH jail
  cat > /etc/fail2ban/jail.local <<'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200
F2BEOF

  systemctl enable fail2ban
  systemctl restart fail2ban

  log_ok "Fail2Ban installed and configured"
}

#── Cloudflare Tunnel (optional) ──────────────────────────────────────────────
install_cloudflared() {
  log_step "Installing Cloudflare Tunnel (cloudflared)"

  if ! command -v cloudflared &> /dev/null; then
    local arch
    arch=$(dpkg --print-architecture)
    wget -q "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}.deb" -O /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb 2>/dev/null || true
    rm -f /tmp/cloudflared.deb
  fi

  if command -v cloudflared &> /dev/null; then
    log_ok "cloudflared installed ($(cloudflared --version 2>/dev/null | head -1))"
    log_info "To set up tunnel, run: cloudflared tunnel login"
  else
    log_warn "cloudflared installation failed — skipping (optional component)"
  fi
}

#── Firewall (UFW) ────────────────────────────────────────────────────────────
configure_firewall() {
  log_step "Configuring Firewall (UFW)"

  ufw --force reset > /dev/null 2>&1
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp    comment 'SSH'
  ufw allow 3000/tcp  comment 'LitePanel'
  ufw allow 7080/tcp  comment 'OLS Admin'
  ufw allow 8088/tcp  comment 'OLS HTTP'
  ufw allow 80/tcp    comment 'HTTP'
  ufw allow 443/tcp   comment 'HTTPS'
  ufw --force enable

  log_ok "Firewall configured"
}

#── Log rotation ──────────────────────────────────────────────────────────────
configure_logrotate() {
  cat > /etc/logrotate.d/litepanel <<'LREOF'
/var/log/litepanel-install.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
}

/usr/local/lsws/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /usr/local/lsws/bin/lswsctrl restart 2>/dev/null || true
    endscript
}
LREOF

  log_ok "Log rotation configured"
}

#── Final verification ────────────────────────────────────────────────────────
verify_installation() {
  log_step "Verifying Installation"

  local errors=0

  # Check services
  for svc in lsws mariadb litepanel fail2ban; do
    if systemctl is-active --quiet "$svc"; then
      log_ok "$svc is running"
    else
      log_error "$svc is NOT running"
      errors=$((errors + 1))
    fi
  done

  # Check DB access
  if mysql -e "CREATE DATABASE IF NOT EXISTS _install_test_; DROP DATABASE _install_test_;" > /dev/null 2>&1; then
    log_ok "MariaDB access verified"
  else
    log_error "MariaDB access FAILED"
    errors=$((errors + 1))
  fi

  # Check phpMyAdmin
  sleep 2
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8088/phpmyadmin/ 2>/dev/null)
  if [[ "$http_code" == "200" ]]; then
    log_ok "phpMyAdmin accessible (HTTP 200)"
  else
    log_warn "phpMyAdmin returned HTTP ${http_code} (may need a moment to start)"
  fi

  # Check panel
  sleep 2
  http_code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/ 2>/dev/null)
  if [[ "$http_code" == "200" ]]; then
    log_ok "LitePanel accessible (HTTP 200)"
  else
    log_error "LitePanel returned HTTP ${http_code}"
    errors=$((errors + 1))
  fi

  return $errors
}

#── Print credentials ─────────────────────────────────────────────────────────
print_credentials() {
  local server_ip
  server_ip=$(hostname -I | awk '{print $1}')

  local panel_user panel_pass db_pass ols_pass
  panel_user=$(jq -r '.panelUser' "$CONFIG_FILE")
  panel_pass=$(jq -r '.panelPass' "$CONFIG_FILE")
  db_pass=$(jq -r '.dbRootPass' "$CONFIG_FILE")
  ols_pass=$(jq -r '.olsAdminPass' "$CONFIG_FILE")

  echo ""
  echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${GREEN}║           LitePanel v2.0 — Installation Complete!           ║${NC}"
  echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${BOLD}  Panel URL:${NC}        http://${server_ip}:3000"
  echo -e "${BOLD}  Panel Login:${NC}      ${panel_user} / ${panel_pass}"
  echo ""
  echo -e "${BOLD}  OLS Admin:${NC}        https://${server_ip}:7080"
  echo -e "${BOLD}  OLS Login:${NC}        admin / ${ols_pass}"
  echo ""
  echo -e "${BOLD}  phpMyAdmin:${NC}       http://${server_ip}:8088/phpmyadmin/"
  echo -e "${BOLD}  DB Login:${NC}         root / ${db_pass}"
  echo ""
  echo -e "${YELLOW}  Config file:${NC}      ${CONFIG_FILE}"
  echo -e "${YELLOW}  Install log:${NC}     ${LOG_FILE}"
  echo ""
  echo -e "${BOLD}  Save these credentials! They are also in ${CONFIG_FILE}${NC}"
  echo ""
}

#── MariaDB Recovery Helper (post-install) ────────────────────────────────────
create_recovery_script() {
  cat > "${PANEL_DIR}/recover-mariadb.sh" <<'RECEOF'
#!/bin/bash
# MariaDB Recovery Script — use if MariaDB won't start or auth breaks
# Usage: bash /opt/litepanel/recover-mariadb.sh

set -euo pipefail

CONFIG="/opt/litepanel/config.json"
DB_PASS=$(node -e "console.log(JSON.parse(require('fs').readFileSync('${CONFIG}','utf8')).dbRootPass)")

echo "=== MariaDB Recovery ==="

# Kill any leftover processes
echo "→ Stopping all MySQL processes..."
systemctl stop mariadb 2>/dev/null || true
sleep 2
pkill -9 mysqld 2>/dev/null || true
pkill -9 mysqld_safe 2>/dev/null || true
pkill -9 mariadbd 2>/dev/null || true
sleep 3

# Clean lock files
echo "→ Cleaning lock files..."
rm -f /var/lib/mysql/aria_log_control
rm -f /var/run/mysqld/mysqld.pid
rm -f /var/lib/mysql/*.pid
mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld
chown -R mysql:mysql /var/lib/mysql

# Safe mode via config file (NOT mysqld_safe!)
echo "→ Starting in safe mode..."
echo -e "[mysqld]\nskip-grant-tables\nskip-networking" > /etc/mysql/conf.d/zzz-recovery.cnf
systemctl start mariadb
sleep 5

# Reset password
echo "→ Resetting root password..."
mysql -u root -e "FLUSH PRIVILEGES; ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_PASS}'; FLUSH PRIVILEGES;"

# Remove recovery config
rm -f /etc/mysql/conf.d/zzz-recovery.cnf

# Restart normally
echo "→ Restarting MariaDB..."
systemctl restart mariadb
sleep 3

# Create .my.cnf
printf "[client]\nuser=root\npassword=%s\n" "$DB_PASS" > /root/.my.cnf
chmod 600 /root/.my.cnf

# Verify
echo ""
echo -n "MariaDB status: "
systemctl is-active --quiet mariadb && echo "✅ RUNNING" || echo "❌ STOPPED"
echo -n "DB access:      "
mysql -e "SELECT 1" -s -N > /dev/null 2>&1 && echo "✅ OK" || echo "❌ FAIL"
echo ""
echo "Done! Password: root / ${DB_PASS}"
RECEOF
  chmod +x "${PANEL_DIR}/recover-mariadb.sh"
  log_ok "Recovery script created: ${PANEL_DIR}/recover-mariadb.sh"
}

#══════════════════════════════════════════════════════════════════════════════
#  MAIN EXECUTION
#══════════════════════════════════════════════════════════════════════════════

main() {
  preflight
  generate_credentials
  install_base
  install_openlitespeed
  configure_openlitespeed
  install_mariadb
  configure_mariadb
  install_phpmyadmin
  install_nodejs
  create_panel_backend
  create_panel_frontend
  create_systemd_service
  install_fail2ban
  install_cloudflared
  configure_firewall
  configure_logrotate
  create_recovery_script
  verify_installation
  print_credentials
}

main "$@"
