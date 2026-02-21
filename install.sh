#!/bin/bash
############################################
# LitePanel Installer v2.1 (Production)
# Fresh Ubuntu 22.04 LTS Only
# REVISED: Full phpMyAdmin fix + hardening
############################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# === LOGGING ===
LOG_FILE="/var/log/litepanel_install.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== LitePanel Install started: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
ADMIN_PASS="admin123"
DB_ROOT_PASS="LP$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20)"
PMA_ADMIN_USER="pma_admin"
PMA_ADMIN_PASS="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20)"
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7;exit}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# Pinned phpMyAdmin version (latest stable 5.2.x branch)
PMA_VERSION="5.2.2"
PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"
PMA_FALLBACK_URL="https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz"

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log()  { echo -e "${G}[✓]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }

# === VALIDATION FUNCTIONS ===
verify_service() {
  local svc="$1"
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    log "$svc is running"
    return 0
  else
    err "$svc is NOT running"
    return 1
  fi
}

verify_command() {
  local cmd="$1"
  local desc="$2"
  if command -v "$cmd" > /dev/null 2>&1; then
    log "$desc: found ($(command -v "$cmd"))"
    return 0
  else
    err "$desc: NOT found"
    return 1
  fi
}

safe_backup() {
  local file="$1"
  if [ -f "$file" ]; then
    cp -f "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
    log "Backup created: ${file}.bak.*"
  fi
}

# === CHECK ROOT ===
if [ "$EUID" -ne 0 ]; then
  err "This script must be run as root!"
  exit 1
fi

# === CHECK OS ===
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "22.04" ]]; then
    warn "Designed for Ubuntu 22.04 LTS. Detected: $PRETTY_NAME"
    read -rp "Continue anyway? (y/n): " cont
    [[ "$cont" != "y" ]] && exit 1
  fi
fi

# === WAIT FOR DPKG LOCK (with timeout) ===
LOCK_WAIT=0
while fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1; do
  if [ $LOCK_WAIT -ge 120 ]; then
    err "dpkg lock held for over 2 minutes. Aborting."
    exit 1
  fi
  warn "Waiting for other package manager to finish... (${LOCK_WAIT}s)"
  sleep 5
  LOCK_WAIT=$((LOCK_WAIT + 5))
done

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.1 (Revised) ║"
echo "  ║   Ubuntu 22.04 LTS                   ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${N}"
sleep 2

########################################
step "Step 1/9: Update System"
########################################
apt-get update -y -qq > /dev/null 2>&1
apt-get upgrade -y -qq > /dev/null 2>&1
log "System updated"

########################################
step "Step 2/9: Install Dependencies"
########################################
apt-get install -y -qq curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release ufw git unzip \
  openssl jq > /dev/null 2>&1
log "Dependencies installed"

########################################
step "Step 3/9: Install OpenLiteSpeed + PHP 8.1"
########################################

CODENAME=$(lsb_release -sc 2>/dev/null || echo "jammy")
REPO_ADDED=0

# ============================================
# METHOD 1: Official LiteSpeed repo script
# ============================================
log "Adding LiteSpeed repository (Method 1: official script)..."
wget -qO /tmp/ls_repo.sh https://repo.litespeed.sh 2>/dev/null
if [ -f /tmp/ls_repo.sh ] && [ -s /tmp/ls_repo.sh ]; then
  bash /tmp/ls_repo.sh > /dev/null 2>&1
  rm -f /tmp/ls_repo.sh
  apt-get update -y -qq > /dev/null 2>&1
fi

if apt-cache show openlitespeed > /dev/null 2>&1; then
  REPO_ADDED=1
  log "LiteSpeed repository added (Method 1)"
fi

# ============================================
# METHOD 2: Manual GPG with signed-by
# ============================================
if [ "$REPO_ADDED" -eq 0 ]; then
  warn "Method 1 failed, trying Method 2 (manual GPG)..."

  wget -qO /tmp/lst_repo.gpg https://rpms.litespeedtech.com/debian/lst_repo.gpg 2>/dev/null
  wget -qO /tmp/lst_debian_repo.gpg https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg 2>/dev/null

  if [ -f /tmp/lst_repo.gpg ] && [ -s /tmp/lst_repo.gpg ]; then
    gpg --dearmor < /tmp/lst_repo.gpg > /usr/share/keyrings/lst-debian.gpg 2>/dev/null
    if [ ! -s /usr/share/keyrings/lst-debian.gpg ]; then
      cp /tmp/lst_repo.gpg /usr/share/keyrings/lst-debian.gpg 2>/dev/null
    fi

    echo "deb [signed-by=/usr/share/keyrings/lst-debian.gpg] http://rpms.litespeedtech.com/debian/ ${CODENAME} main" \
      > /etc/apt/sources.list.d/lst_debian_repo.list
  fi
  rm -f /tmp/lst_repo.gpg /tmp/lst_debian_repo.gpg
  apt-get update -y -qq > /dev/null 2>&1

  if apt-cache show openlitespeed > /dev/null 2>&1; then
    REPO_ADDED=1
    log "LiteSpeed repository added (Method 2)"
  fi
fi

# ============================================
# METHOD 3: Legacy apt-key (deprecated but works)
# ============================================
if [ "$REPO_ADDED" -eq 0 ]; then
  warn "Method 2 failed, trying Method 3 (legacy apt-key)..."

  wget -qO - https://rpms.litespeedtech.com/debian/lst_repo.gpg 2>/dev/null | apt-key add - 2>/dev/null
  wget -qO - https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg 2>/dev/null | apt-key add - 2>/dev/null

  echo "deb http://rpms.litespeedtech.com/debian/ ${CODENAME} main" \
    > /etc/apt/sources.list.d/lst_debian_repo.list

  apt-get update -y -qq > /dev/null 2>&1

  if apt-cache show openlitespeed > /dev/null 2>&1; then
    REPO_ADDED=1
    log "LiteSpeed repository added (Method 3)"
  fi
fi

# ============================================
# FINAL CHECK: Abort if repo failed
# ============================================
if [ "$REPO_ADDED" -eq 0 ]; then
  err "═══════════════════════════════════════════════"
  err "FATAL: Could not add LiteSpeed repository!"
  err "Please run manually:"
  err "  wget -O - https://repo.litespeed.sh | sudo bash"
  err "  apt-get install openlitespeed lsphp81"
  err "Then re-run this installer."
  err "═══════════════════════════════════════════════"
  exit 1
fi

# ============================================
# INSTALL OPENLITESPEED
# ============================================
log "Installing OpenLiteSpeed (this may take 1-2 minutes)..."
apt-get install -y openlitespeed > /tmp/ols_install.log 2>&1
OLS_RC=$?

if [ $OLS_RC -ne 0 ] || [ ! -d "/usr/local/lsws" ]; then
  err "═══════════════════════════════════════════════"
  err "FATAL: OpenLiteSpeed installation failed!"
  err "Exit code: $OLS_RC"
  err "Last 30 lines of install log:"
  echo ""
  tail -30 /tmp/ols_install.log
  echo ""
  err "═══════════════════════════════════════════════"
  exit 1
fi
log "OpenLiteSpeed installed"

# ============================================
# INSTALL PHP 8.1 — REQUIRED packages FIRST
# (FIX: mbstring is CRITICAL for phpMyAdmin)
# ============================================
log "Installing PHP 8.1 (required packages)..."
apt-get install -y lsphp81 lsphp81-common lsphp81-mysql \
  lsphp81-curl lsphp81-mbstring > /tmp/php_install.log 2>&1
PHP_RC=$?

if [ $PHP_RC -ne 0 ]; then
  err "Required PHP packages failed to install!"
  tail -10 /tmp/php_install.log
  exit 1
fi

# Optional PHP extensions (OK if some fail)
# NOTE: lsphp81-iconv does NOT exist as separate package (bundled in common)
apt-get install -y -qq lsphp81-xml lsphp81-zip \
  lsphp81-intl lsphp81-opcache >> /tmp/php_install.log 2>&1

# ============================================
# VERIFY CRITICAL PHP EXTENSIONS
# ============================================
if [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null
  PHP_VER=$(/usr/local/lsws/lsphp81/bin/php -v 2>/dev/null | head -1 | awk '{print $2}')
  log "PHP 8.1 installed ($PHP_VER)"

  # Verify critical extensions required by phpMyAdmin
  REQUIRED_EXTS="mysqli mbstring json session"
  MISSING_EXTS=""
  for ext in $REQUIRED_EXTS; do
    if /usr/local/lsws/lsphp81/bin/php -m 2>/dev/null | grep -qi "^${ext}$"; then
      log "  PHP extension ${ext}: ✓ loaded"
    else
      err "  PHP extension ${ext}: ✗ MISSING"
      MISSING_EXTS="${MISSING_EXTS} ${ext}"
    fi
  done

  if [ -n "$MISSING_EXTS" ]; then
    err "Critical PHP extensions missing:${MISSING_EXTS}"
    err "phpMyAdmin will NOT work without these!"
    warn "Attempting to install missing extensions..."
    for ext in $MISSING_EXTS; do
      apt-get install -y -qq "lsphp81-${ext}" 2>/dev/null
    done
  fi
else
  err "lsphp81 binary not found at /usr/local/lsws/lsphp81/bin/php"
  exit 1
fi

# ============================================
# CONFIGURE OLS
# ============================================
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

if [ ! -f "$OLS_CONF" ]; then
  err "OLS config file not found: $OLS_CONF"
  exit 1
fi

safe_backup "$OLS_CONF"
log "Configuring OpenLiteSpeed..."

# Set admin password
if [ -d "/usr/local/lsws/admin/conf" ]; then
  OLS_HASH=$(printf '%s' "${ADMIN_PASS}" | md5sum | awk '{print $1}')
  echo "admin:${OLS_HASH}" > /usr/local/lsws/admin/conf/htpasswd
  chmod 600 /usr/local/lsws/admin/conf/htpasswd
  log "OLS admin password set"
else
  warn "OLS admin conf directory not found"
fi

# Add lsphp81 extprocessor (only if not already present)
if ! grep -q "extprocessor lsphp81" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'EXTEOF'

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/lsphp81.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
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
EXTEOF
  log "lsphp81 extprocessor added (pcKeepAliveTimeout=15)"
fi

# Add HTTP listener on port 80 (only if not present)
if ! grep -q "listener HTTP" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'LSTEOF'

listener HTTP {
  address                 *:80
  secure                  0
}
LSTEOF
  log "HTTP listener port 80 added"
fi

# Update default lsphp path to lsphp81
sed -i 's|/usr/local/lsws/fcgi-bin/lsphp|/usr/local/lsws/lsphp81/bin/lsphp|g' "$OLS_CONF" 2>/dev/null

# Update Example vhost to use lsphp81
EXAMPLE_VHCONF="/usr/local/lsws/conf/vhosts/Example/vhconf.conf"
if [ -f "$EXAMPLE_VHCONF" ]; then
  safe_backup "$EXAMPLE_VHCONF"
  # Replace any lsapi:lsphp reference with lsapi:lsphp81
  sed -i '/add.*lsapi:lsphp/c\  add                     lsapi:lsphp81 php' "$EXAMPLE_VHCONF"

  # Ensure index.php is in the index files list
  if ! grep -q "index.php" "$EXAMPLE_VHCONF"; then
    sed -i '/indexFiles/s/index.html/index.php, index.html/' "$EXAMPLE_VHCONF"
  fi
  log "Example vhost updated to lsphp81"
fi

systemctl enable lsws > /dev/null 2>&1
systemctl start lsws 2>/dev/null
sleep 2

if verify_service lsws; then
  log "OpenLiteSpeed started successfully"
else
  warn "OpenLiteSpeed failed to start - retrying..."
  systemctl restart lsws 2>/dev/null
  sleep 3
  if ! verify_service lsws; then
    err "OpenLiteSpeed won't start. Check: journalctl -u lsws --no-pager -n 20"
    systemctl status lsws --no-pager 2>&1 | tail -10
  fi
fi

########################################
step "Step 4/9: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Wait for MariaDB to be ready
for i in $(seq 1 20); do
  if mysqladmin ping &>/dev/null; then
    break
  fi
  warn "Waiting for MariaDB to be ready... ($i/20)"
  sleep 2
done

if ! mysqladmin ping &>/dev/null; then
  err "MariaDB failed to start after 40 seconds!"
  systemctl status mariadb --no-pager | tail -10
  exit 1
fi

# ============================================
# DETECT MARIADB SOCKET PATH (used later for PHP config)
# ============================================
MYSQL_SOCKET=$(mysqladmin variables 2>/dev/null | grep -w "socket" | awk '{print $4}')
[ -z "$MYSQL_SOCKET" ] && MYSQL_SOCKET="/var/run/mysqld/mysqld.sock"
log "MariaDB socket detected: $MYSQL_SOCKET"

# ============================================
# FIX: Explicitly set mysql_native_password plugin
# This ensures phpMyAdmin can authenticate via password
# ============================================
log "Securing MariaDB (explicit mysql_native_password)..."

mysql -u root <<SQLEOF 2>/tmp/mariadb_setup.log
-- Switch root to mysql_native_password explicitly
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${DB_ROOT_PASS}');
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';
-- Remove remote root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
-- Create dedicated phpMyAdmin admin user
CREATE USER IF NOT EXISTS '${PMA_ADMIN_USER}'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${PMA_ADMIN_PASS}');
GRANT ALL PRIVILEGES ON *.* TO '${PMA_ADMIN_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQLEOF

MYSQL_SETUP_RC=$?

if [ $MYSQL_SETUP_RC -ne 0 ]; then
  err "MariaDB setup SQL returned error code: $MYSQL_SETUP_RC"
  cat /tmp/mariadb_setup.log
  warn "Trying fallback method..."

  # Fallback: use SET PASSWORD (older syntax)
  mysql -u root -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${DB_ROOT_PASS}');" 2>/dev/null
fi

# ============================================
# VERIFY MariaDB root password authentication works
# ============================================
sleep 1
if mysql -u root -p"${DB_ROOT_PASS}" -e "SELECT 1;" > /dev/null 2>&1; then
  log "MariaDB root password authentication VERIFIED ✓"
else
  err "MariaDB root password authentication FAILED!"
  warn "Attempting alternative fix..."

  # Alternative: connect via unix_socket and force the change
  mysql -u root -e "
    UPDATE mysql.global_priv SET priv=json_set(priv, '$.plugin', 'mysql_native_password', '$.authentication_string', PASSWORD('${DB_ROOT_PASS}')) WHERE User='root' AND Host='localhost';
    FLUSH PRIVILEGES;
  " 2>/dev/null

  sleep 1
  if mysql -u root -p"${DB_ROOT_PASS}" -e "SELECT 1;" > /dev/null 2>&1; then
    log "MariaDB root password authentication VERIFIED (fallback) ✓"
  else
    err "WARNING: Root password auth still failing. phpMyAdmin may not work with root."
    warn "Use dedicated user '${PMA_ADMIN_USER}' instead."
  fi
fi

# Verify dedicated PMA user
if mysql -u "${PMA_ADMIN_USER}" -p"${PMA_ADMIN_PASS}" -e "SELECT 1;" > /dev/null 2>&1; then
  log "Dedicated phpMyAdmin user '${PMA_ADMIN_USER}' VERIFIED ✓"
else
  warn "Dedicated PMA user verification failed - check manually"
fi

log "MariaDB installed & secured"

# ============================================
# FIX: Configure lsphp81 php.ini for correct MySQL socket
# ============================================
LSPHP_INI="/usr/local/lsws/lsphp81/etc/php/8.1/litespeed/php.ini"
if [ -f "$LSPHP_INI" ]; then
  safe_backup "$LSPHP_INI"
  log "Configuring lsphp81 php.ini for MariaDB socket..."

  # Fix mysqli.default_socket
  if grep -q "^mysqli.default_socket" "$LSPHP_INI"; then
    sed -i "s|^mysqli.default_socket.*|mysqli.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  elif grep -q "^;mysqli.default_socket" "$LSPHP_INI"; then
    sed -i "s|^;mysqli.default_socket.*|mysqli.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  else
    echo "mysqli.default_socket = ${MYSQL_SOCKET}" >> "$LSPHP_INI"
  fi

  # Fix pdo_mysql.default_socket
  if grep -q "^pdo_mysql.default_socket" "$LSPHP_INI"; then
    sed -i "s|^pdo_mysql.default_socket.*|pdo_mysql.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  elif grep -q "^;pdo_mysql.default_socket" "$LSPHP_INI"; then
    sed -i "s|^;pdo_mysql.default_socket.*|pdo_mysql.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  else
    echo "pdo_mysql.default_socket = ${MYSQL_SOCKET}" >> "$LSPHP_INI"
  fi

  # Fix mysql.default_socket (legacy)
  if grep -q "^mysql.default_socket" "$LSPHP_INI"; then
    sed -i "s|^mysql.default_socket.*|mysql.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  elif grep -q "^;mysql.default_socket" "$LSPHP_INI"; then
    sed -i "s|^;mysql.default_socket.*|mysql.default_socket = ${MYSQL_SOCKET}|" "$LSPHP_INI"
  fi

  # Verify the change
  CONFIGURED_SOCKET=$(grep "^mysqli.default_socket" "$LSPHP_INI" | awk -F= '{print $2}' | tr -d ' ')
  log "lsphp81 mysqli.default_socket set to: $CONFIGURED_SOCKET"
else
  warn "lsphp81 php.ini not found at $LSPHP_INI"
  # Try alternative paths
  for alt_ini in \
    /usr/local/lsws/lsphp81/etc/php.ini \
    /usr/local/lsws/lsphp81/lib/php.ini; do
    if [ -f "$alt_ini" ]; then
      warn "Found alternative php.ini: $alt_ini"
      echo "mysqli.default_socket = ${MYSQL_SOCKET}" >> "$alt_ini"
      echo "pdo_mysql.default_socket = ${MYSQL_SOCKET}" >> "$alt_ini"
      log "Socket path appended to $alt_ini"
      break
    fi
  done
fi

########################################
step "Step 5/9: Install Node.js 20 LTS"
########################################
if ! command -v node > /dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x 2>/dev/null | bash - > /dev/null 2>&1
  apt-get install -y -qq nodejs > /dev/null 2>&1
fi

if verify_command node "Node.js"; then
  log "Node.js $(node -v 2>/dev/null) installed"
else
  err "Node.js installation failed!"
  err "Manual install: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install nodejs"
  exit 1
fi

########################################
step "Step 6/9: Creating LitePanel App"
########################################
mkdir -p ${PANEL_DIR}/{public/css,public/js}
cd ${PANEL_DIR}

# --- package.json ---
cat > package.json <<'PKGEOF'
{
  "name": "litepanel",
  "version": "2.1.0",
  "private": true,
  "scripts": { "start": "node app.js" },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "bcryptjs": "^2.4.3",
    "multer": "^1.4.5-lts.1"
  }
}
PKGEOF

log "Installing npm dependencies..."
npm install --production > /tmp/npm_install.log 2>&1
NPM_RC=$?

if [ $NPM_RC -ne 0 ]; then
  warn "npm install failed (code $NPM_RC), retrying with legacy-peer-deps..."
  npm install --production --legacy-peer-deps > /tmp/npm_install.log 2>&1
  NPM_RC=$?
fi

if [ $NPM_RC -ne 0 ]; then
  err "npm install failed. Check /tmp/npm_install.log"
  tail -10 /tmp/npm_install.log
  exit 1
fi
log "npm dependencies installed"

# --- config.json ---
HASHED_PASS=$(node -e "console.log(require('bcryptjs').hashSync('${ADMIN_PASS}', 10))" 2>/dev/null)
SESSION_SECRET=$(openssl rand -hex 32)

cat > config.json <<CFGEOF
{
  "adminUser": "${ADMIN_USER}",
  "adminPass": "${HASHED_PASS}",
  "dbRootPass": "${DB_ROOT_PASS}",
  "panelPort": ${PANEL_PORT},
  "sessionSecret": "${SESSION_SECRET}"
}
CFGEOF
chmod 600 config.json
log "config.json created (permissions: 600)"

##############################################
# -------- app.js (Backend) --------
##############################################
cat > app.js <<'APPEOF'
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const multer = require('multer');

const CONFIG_PATH = path.join(__dirname, 'config.json');
let config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const OLS_CONF = '/usr/local/lsws/conf/httpd_config.conf';
const OLS_VHOST_CONF_DIR = '/usr/local/lsws/conf/vhosts';
const OLS_VHOST_DIR = '/usr/local/lsws/vhosts';
const MAX_EDIT_SIZE = 5 * 1024 * 1024;

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: config.sessionSecret, resave: false, saveUninitialized: false,
  cookie: { maxAge: 86400000, httpOnly: true, sameSite: 'strict' }
}));
app.use(express.static(path.join(__dirname, 'public')));

var auth = function(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

function run(cmd, timeout) {
  try { return execSync(cmd, { timeout: timeout || 15000, maxBuffer: 5*1024*1024 }).toString().trim(); }
  catch(e) { return e.stderr ? e.stderr.toString().trim() : e.message; }
}
function svcActive(name) {
  try { execSync('systemctl is-active ' + name, { stdio: 'pipe' }); return true; }
  catch(e) { return false; }
}
function escRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function shellEsc(s) { return s.replace(/'/g, "'\\''"); }

/* === OLS Config Management === */
function readOLSConf() { return fs.readFileSync(OLS_CONF, 'utf8'); }
function writeOLSConf(content) {
  fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak');
  fs.writeFileSync(OLS_CONF, content);
}

function addDomainToOLS(domain) {
  var httpd = readOLSConf();
  if (httpd.includes('virtualhost ' + domain + ' {')) return;

  httpd += '\nvirtualhost ' + domain + ' {\n'
    + '  vhRoot                  ' + OLS_VHOST_DIR + '/' + domain + '\n'
    + '  configFile              ' + OLS_VHOST_CONF_DIR + '/' + domain + '/vhconf.conf\n'
    + '  allowSymbolLink         1\n'
    + '  enableScript            1\n'
    + '  restrained              1\n'
    + '}\n';

  var listenerRe = /(listener\s+HTTP\s*\{[\s\S]*?)(})/;
  if (listenerRe.test(httpd)) {
    httpd = httpd.replace(listenerRe,
      '$1  map                     ' + domain + ' ' + domain + ', www.' + domain + '\n$2');
  } else {
    httpd += '\nlistener HTTP {\n  address                 *:80\n  secure                  0\n'
      + '  map                     ' + domain + ' ' + domain + ', www.' + domain + '\n}\n';
  }
  writeOLSConf(httpd);
}

function removeDomainFromOLS(domain) {
  var httpd = readOLSConf();
  fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak');
  var vhRe = new RegExp('\\n?virtualhost\\s+' + escRegex(domain) + '\\s*\\{[\\s\\S]*?\\}', 'g');
  httpd = httpd.replace(vhRe, '');
  var mapRe = new RegExp('^\\s*map\\s+' + escRegex(domain) + '\\s+.*$', 'gm');
  httpd = httpd.replace(mapRe, '');
  httpd = httpd.replace(/\n{3,}/g, '\n\n');
  fs.writeFileSync(OLS_CONF, httpd);
}

function createVhostFiles(domain) {
  var confDir = path.join(OLS_VHOST_CONF_DIR, domain);
  var docRoot = path.join(OLS_VHOST_DIR, domain, 'html');
  var logDir  = path.join(OLS_VHOST_DIR, domain, 'logs');
  fs.mkdirSync(confDir, { recursive: true });
  fs.mkdirSync(docRoot, { recursive: true });
  fs.mkdirSync(logDir,  { recursive: true });

  var vhConf = 'docRoot                   $VH_ROOT/html\n'
    + 'vhDomain                  ' + domain + '\n'
    + 'vhAliases                 www.' + domain + '\n'
    + 'enableGzip                1\n\n'
    + 'index {\n'
    + '  useServer               0\n'
    + '  indexFiles              index.php, index.html\n'
    + '  autoIndex               0\n'
    + '}\n\n'
    + 'scripthandler {\n'
    + '  add                     lsapi:lsphp81 php\n'
    + '}\n\n'
    + 'accessControl {\n'
    + '  allow                   *\n'
    + '}\n\n'
    + 'rewrite {\n'
    + '  enable                  1\n'
    + '  autoLoadHtaccess        1\n'
    + '}\n';

  fs.writeFileSync(path.join(confDir, 'vhconf.conf'), vhConf);
  fs.writeFileSync(path.join(docRoot, 'index.html'),
    '<!DOCTYPE html>\n<html><head><title>' + domain + '</title></head>\n'
    + '<body><h1>Welcome to ' + domain + '</h1>\n'
    + '<p>Hosted on LitePanel with OpenLiteSpeed</p></body></html>\n');
  try { execSync('chown -R nobody:nogroup ' + path.join(OLS_VHOST_DIR, domain)); } catch(e) {}
  return docRoot;
}

function safeRestartOLS() {
  try {
    execSync('systemctl restart lsws', { timeout: 15000 });
    execSync('sleep 2', { timeout: 5000 });
    try { execSync('systemctl is-active lsws', { stdio: 'pipe' }); }
    catch(e) {
      if (fs.existsSync(OLS_CONF + '.bak')) {
        fs.copyFileSync(OLS_CONF + '.bak', OLS_CONF);
        execSync('systemctl restart lsws', { timeout: 15000 });
      }
      throw new Error('OLS config error, reverted to backup');
    }
  } catch(e) { throw e; }
}

/* === Auth === */
app.post('/api/login', function(req, res) {
  var u = req.body.username, p = req.body.password;
  if (u === config.adminUser && bcrypt.compareSync(p, config.adminPass)) {
    req.session.user = u; res.json({ success: true });
  } else res.status(401).json({ error: 'Invalid credentials' });
});
app.get('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth', function(req, res) { res.json({ authenticated: !!(req.session && req.session.user) }); });

/* === Dashboard === */
app.get('/api/dashboard', auth, function(req, res) {
  var tm = os.totalmem(), fm = os.freemem();
  var disk = { total: 0, used: 0, free: 0 };
  try { var d = run("df -B1 / | tail -1").split(/\s+/); disk = { total: +d[1], used: +d[2], free: +d[3] }; } catch(e) {}
  var cpus = os.cpus();
  res.json({
    hostname: os.hostname(), ip: run("hostname -I | awk '{print $1}'"),
    uptime: os.uptime(),
    cpu: { model: cpus[0] ? cpus[0].model : 'Unknown', cores: cpus.length, load: os.loadavg() },
    memory: { total: tm, used: tm - fm, free: fm }, disk: disk, nodeVersion: process.version
  });
});

/* === Services === */
app.get('/api/services', auth, function(req, res) {
  res.json(['lsws','mariadb','fail2ban','cloudflared'].map(function(s) { return { name: s, active: svcActive(s) }; }));
});
app.post('/api/services/:name/:action', auth, function(req, res) {
  var ok = ['lsws','mariadb','fail2ban','cloudflared'], acts = ['start','stop','restart'];
  if (!ok.includes(req.params.name) || !acts.includes(req.params.action))
    return res.status(400).json({ error: 'Invalid' });
  try { execSync('systemctl ' + req.params.action + ' ' + req.params.name, { timeout: 15000 }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

/* === File Manager === */
app.get('/api/files', auth, function(req, res) {
  var p = path.resolve(req.query.path || '/');
  try {
    var stat = fs.statSync(p);
    if (stat.isDirectory()) {
      var items = [];
      fs.readdirSync(p).forEach(function(name) {
        try {
          var s = fs.statSync(path.join(p, name));
          items.push({ name: name, isDir: s.isDirectory(), size: s.size, modified: s.mtime,
            perms: '0' + (s.mode & parseInt('777', 8)).toString(8) });
        } catch(e) { items.push({ name: name, isDir: false, size: 0, error: true }); }
      });
      res.json({ path: p, items: items });
    } else {
      if (stat.size > MAX_EDIT_SIZE) return res.json({ path: p, size: stat.size, tooLarge: true });
      var buf = Buffer.alloc(Math.min(512, stat.size));
      if (stat.size > 0) { var fd = fs.openSync(p, 'r'); fs.readSync(fd, buf, 0, buf.length, 0); fs.closeSync(fd); }
      if (buf.includes(0)) return res.json({ path: p, size: stat.size, binary: true });
      res.json({ path: p, content: fs.readFileSync(p, 'utf8'), size: stat.size });
    }
  } catch(e) { res.status(404).json({ error: e.message }); }
});
app.put('/api/files', auth, function(req, res) {
  try { fs.writeFileSync(req.body.filePath, req.body.content); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/files', auth, function(req, res) {
  var target = req.query.path;
  if (!target || target === '/') return res.status(400).json({ error: 'Cannot delete root' });
  try { fs.rmSync(target, { recursive: true, force: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
var upload = multer({ dest: '/tmp/uploads/' });
app.post('/api/files/upload', auth, upload.single('file'), function(req, res) {
  try { fs.renameSync(req.file.path, path.join(req.body.path || '/tmp', req.file.originalname)); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/files/mkdir', auth, function(req, res) {
  try { fs.mkdirSync(req.body.path, { recursive: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/files/rename', auth, function(req, res) {
  try { fs.renameSync(req.body.oldPath, req.body.newPath); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/files/download', auth, function(req, res) {
  var fp = req.query.path;
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  try { if (fs.statSync(fp).isDirectory()) return res.status(400).json({ error: 'Cannot download directory' }); res.download(fp); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

/* === Domains === */
app.get('/api/domains', auth, function(req, res) {
  try {
    if (!fs.existsSync(OLS_VHOST_CONF_DIR)) return res.json([]);
    var list = fs.readdirSync(OLS_VHOST_CONF_DIR).filter(function(n) {
      return fs.statSync(path.join(OLS_VHOST_CONF_DIR, n)).isDirectory() && n !== 'Example';
    });
    res.json(list.map(function(name) { return { name: name, docRoot: path.join(OLS_VHOST_DIR, name, 'html') }; }));
  } catch(e) { res.json([]); }
});
app.post('/api/domains', auth, function(req, res) {
  var domain = req.body.domain;
  if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain))
    return res.status(400).json({ error: 'Invalid domain name' });
  try {
    var docRoot = createVhostFiles(domain);
    addDomainToOLS(domain);
    safeRestartOLS();
    res.json({ success: true, domain: domain, docRoot: docRoot });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/domains/:name', auth, function(req, res) {
  var domain = req.params.name;
  if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain))
    return res.status(400).json({ error: 'Invalid domain' });
  try {
    removeDomainFromOLS(domain);
    fs.rmSync(path.join(OLS_VHOST_CONF_DIR, domain), { recursive: true, force: true });
    safeRestartOLS();
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* === Databases === */
app.get('/api/databases', auth, function(req, res) {
  try {
    var out = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e 'SHOW DATABASES;' -s -N 2>/dev/null");
    var skip = ['information_schema','performance_schema','mysql','sys'];
    res.json(out.split('\n').filter(function(d) { return d.trim() && !skip.includes(d.trim()); }));
  } catch(e) { res.json([]); }
});
app.post('/api/databases', auth, function(req, res) {
  var name = req.body.name, user = req.body.user, password = req.body.password;
  if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) return res.status(400).json({ error: 'Invalid DB name' });
  if (user && !/^[a-zA-Z0-9_]+$/.test(user)) return res.status(400).json({ error: 'Invalid username' });
  try {
    var dp = shellEsc(config.dbRootPass);
    run("mysql -u root -p'" + dp + "' -e \"CREATE DATABASE IF NOT EXISTS \\`" + name + "\\`;\" 2>/dev/null");
    if (user && password) {
      var sp = shellEsc(password);
      run("mysql -u root -p'" + dp + "' -e \"CREATE USER IF NOT EXISTS '" + user + "'@'localhost' IDENTIFIED BY '" + sp + "'; GRANT ALL ON \\`" + name + "\\`.* TO '" + user + "'@'localhost'; FLUSH PRIVILEGES;\" 2>/dev/null");
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/databases/:name', auth, function(req, res) {
  if (!/^[a-zA-Z0-9_]+$/.test(req.params.name)) return res.status(400).json({ error: 'Invalid' });
  try {
    run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e \"DROP DATABASE IF EXISTS \\`" + req.params.name + "\\`;\" 2>/dev/null");
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* === Tunnel === */
app.get('/api/tunnel/status', auth, function(req, res) { res.json({ active: svcActive('cloudflared') }); });
app.post('/api/tunnel/setup', auth, function(req, res) {
  var token = req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });
  var safeToken = token.replace(/[;&|`$(){}]/g, '');
  try {
    fs.writeFileSync('/etc/systemd/system/cloudflared.service',
      '[Unit]\nDescription=Cloudflare Tunnel\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/cloudflared tunnel run --token ' + safeToken + '\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n');
    execSync('systemctl daemon-reload && systemctl enable cloudflared && systemctl restart cloudflared', { timeout: 15000 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* === Settings === */
app.post('/api/settings/password', auth, function(req, res) {
  if (!bcrypt.compareSync(req.body.currentPassword, config.adminPass))
    return res.status(401).json({ error: 'Wrong current password' });
  if (!req.body.newPassword || req.body.newPassword.length < 6)
    return res.status(400).json({ error: 'Min 6 characters' });
  config.adminPass = bcrypt.hashSync(req.body.newPassword, 10);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

/* === Terminal === */
app.post('/api/terminal', auth, function(req, res) {
  if (!req.body.command) return res.json({ output: '' });
  try { res.json({ output: run(req.body.command, 30000) }); }
  catch(e) { res.json({ output: e.message }); }
});

app.listen(config.panelPort, '0.0.0.0', function() {
  console.log('LitePanel running on port ' + config.panelPort);
});
APPEOF

##############################################
# -------- public/index.html --------
##############################################
cat > public/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel</title>
<link rel="stylesheet" href="/css/style.css">
</head>
<body>
<div id="loginPage" class="login-page">
  <div class="login-box">
    <h1>🖥️ LitePanel</h1>
    <form id="loginForm">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <button type="submit">Login</button>
      <div id="loginError" class="error"></div>
    </form>
  </div>
</div>
<div id="mainPanel" class="main-panel" style="display:none">
  <button id="mobileToggle" class="mobile-toggle">☰</button>
  <aside class="sidebar" id="sidebar">
    <div class="logo">🖥️ LitePanel</div>
    <nav>
      <a href="#" data-page="dashboard" class="active">📊 Dashboard</a>
      <a href="#" data-page="services">⚙️ Services</a>
      <a href="#" data-page="files">📁 Files</a>
      <a href="#" data-page="domains">🌐 Domains</a>
      <a href="#" data-page="databases">🗃️ Databases</a>
      <a href="#" data-page="tunnel">☁️ Tunnel</a>
      <a href="#" data-page="terminal">💻 Terminal</a>
      <a href="#" data-page="settings">🔧 Settings</a>
    </nav>
    <a href="#" id="logoutBtn" class="logout-btn">🚪 Logout</a>
  </aside>
  <main class="content" id="content"></main>
</div>
<script src="/js/app.js"></script>
</body>
</html>
HTMLEOF

##############################################
# -------- public/css/style.css --------
##############################################
cat > public/css/style.css <<'CSSEOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#1a1d23;color:#e0e0e0}
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0f1117,#1a1d23)}
.login-box{background:#2a2d35;padding:40px;border-radius:12px;width:360px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.login-box h1{text-align:center;color:#4f8cff;margin-bottom:30px;font-size:28px}
.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}
.login-box input:focus{border-color:#4f8cff}
.login-box button{width:100%;padding:12px;background:#4f8cff;border:none;border-radius:8px;color:#fff;font-size:16px;cursor:pointer;font-weight:600}
.login-box button:hover{background:#3a7ae0}
.error{color:#e74c3c;text-align:center;margin-top:10px;font-size:14px}
.main-panel{display:flex;min-height:100vh}
.sidebar{width:220px;background:#12141a;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10;transition:transform .3s}
.sidebar .logo{padding:20px;font-size:20px;font-weight:700;color:#4f8cff;border-bottom:1px solid #2a2d35}
.sidebar nav{flex:1;padding:10px 0;overflow-y:auto}
.sidebar nav a{display:block;padding:12px 20px;color:#8a8d93;text-decoration:none;transition:.2s;font-size:14px}
.sidebar nav a:hover,.sidebar nav a.active{background:#1a1d23;color:#4f8cff;border-right:3px solid #4f8cff}
.logout-btn{padding:15px 20px;color:#e74c3c;text-decoration:none;border-top:1px solid #2a2d35;font-size:14px}
.content{flex:1;margin-left:220px;padding:30px;min-height:100vh}
.mobile-toggle{display:none;position:fixed;top:10px;left:10px;z-index:20;background:#2a2d35;border:none;color:#e0e0e0;font-size:24px;padding:8px 12px;border-radius:8px;cursor:pointer}
@media(max-width:768px){
  .mobile-toggle{display:block}
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .content{margin-left:0;padding:15px;padding-top:55px}
  .stats-grid{grid-template-columns:1fr!important}
  .flex-row{flex-direction:column}
}
.page-title{font-size:24px;margin-bottom:8px}
.page-sub{color:#8a8d93;margin-bottom:25px;font-size:14px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:25px}
.card{background:#2a2d35;padding:20px;border-radius:10px}
.card .label{font-size:12px;color:#8a8d93;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.card .value{font-size:22px;font-weight:700;color:#4f8cff}
.card .sub{font-size:12px;color:#6a6d73;margin-top:4px}
.progress{background:#1a1d23;border-radius:8px;height:8px;margin-top:8px;overflow:hidden}
.progress-bar{height:100%;border-radius:8px;background:#4f8cff;transition:width .3s}
.progress-bar.warn{background:#f39c12}
.progress-bar.danger{background:#e74c3c}
table.tbl{width:100%;border-collapse:collapse;background:#2a2d35;border-radius:10px;overflow:hidden}
.tbl th{background:#1a1d23;padding:12px 16px;text-align:left;font-size:12px;color:#8a8d93;text-transform:uppercase}
.tbl td{padding:12px 16px;border-bottom:1px solid #1a1d23;font-size:14px}
.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;transition:.2s;display:inline-block;text-decoration:none}
.btn:hover{opacity:.85}
.btn-p{background:#4f8cff;color:#fff}
.btn-s{background:#2ecc71;color:#fff}
.btn-d{background:#e74c3c;color:#fff}
.btn-w{background:#f39c12;color:#fff}
.btn-sm{padding:4px 10px;font-size:12px}
.badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600}
.badge-on{background:rgba(46,204,113,.15);color:#2ecc71}
.badge-off{background:rgba(231,76,60,.15);color:#e74c3c}
.form-control{width:100%;padding:10px 14px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}
.form-control:focus{border-color:#4f8cff}
textarea.form-control{min-height:300px;font-family:'Courier New',monospace;font-size:13px;resize:vertical}
.alert{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px}
.alert-ok{background:rgba(46,204,113,.1);border:1px solid #2ecc71;color:#2ecc71}
.alert-err{background:rgba(231,76,60,.1);border:1px solid #e74c3c;color:#e74c3c}
.breadcrumb{display:flex;gap:5px;margin-bottom:15px;flex-wrap:wrap;font-size:14px}
.breadcrumb a{color:#4f8cff;text-decoration:none;cursor:pointer}
.breadcrumb span{color:#6a6d73}
.file-item{display:flex;align-items:center;padding:10px 16px;background:#2a2d35;margin-bottom:2px;cursor:pointer;border-radius:4px;font-size:14px}
.file-item:hover{background:#32353d}
.file-item .icon{margin-right:10px;font-size:16px}
.file-item .name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-item .size{color:#8a8d93;margin-right:10px;min-width:70px;text-align:right;font-size:13px}
.file-item .perms{color:#6a6d73;margin-right:10px;font-family:monospace;font-size:12px}
.file-actions{display:flex;gap:4px}
.terminal-box{background:#0d0d0d;color:#0f0;font-family:'Courier New',monospace;padding:20px;border-radius:10px;min-height:350px;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;font-size:13px}
.term-input{display:flex;gap:10px;margin-top:10px}
.term-input input{flex:1;background:#0d0d0d;border:1px solid #333;color:#0f0;font-family:'Courier New',monospace;padding:10px;border-radius:6px;outline:none}
.flex-row{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:16px}
.mt{margin-top:16px}.mb{margin-bottom:16px}
CSSEOF

##############################################
# -------- public/js/app.js (Frontend) ------
##############################################
cat > public/js/app.js <<'JSEOF'
var api = {
  req: function(url, opt) {
    opt = opt || {};
    var h = {};
    if (!(opt.body instanceof FormData)) h['Content-Type'] = 'application/json';
    return fetch(url, {
      headers: h, method: opt.method || 'GET',
      body: opt.body instanceof FormData ? opt.body : opt.body ? JSON.stringify(opt.body) : undefined
    }).then(function(r) { return r.json(); });
  },
  get: function(u) { return api.req(u); },
  post: function(u, b) { return api.req(u, { method: 'POST', body: b }); },
  put: function(u, b) { return api.req(u, { method: 'PUT', body: b }); },
  del: function(u) { return api.req(u, { method: 'DELETE' }); }
};

var $ = function(id) { return document.getElementById(id); };
function fmtB(b) { if(!b)return '0 B'; var k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k)); return (b/Math.pow(k,i)).toFixed(1)+' '+s[i]; }
function fmtUp(s) { var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return d+'d '+h+'h '+m+'m'; }
function esc(t) { var d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
function pClass(p) { return p>80?'danger':p>60?'warn':''; }

var curPath = '/usr/local/lsws';
var editFile = '';

function checkAuth() {
  api.get('/api/auth').then(function(r) {
    if (r.authenticated) { showPanel(); loadPage('dashboard'); } else showLogin();
  });
}
function showLogin() { $('loginPage').style.display='flex'; $('mainPanel').style.display='none'; }
function showPanel() { $('loginPage').style.display='none'; $('mainPanel').style.display='flex'; }

$('loginForm').addEventListener('submit', function(e) {
  e.preventDefault();
  api.post('/api/login', { username: $('username').value, password: $('password').value }).then(function(r) {
    if (r.success) { showPanel(); loadPage('dashboard'); } else $('loginError').textContent='Invalid credentials';
  });
});
$('logoutBtn').addEventListener('click', function(e) { e.preventDefault(); api.get('/api/logout').then(showLogin); });
$('mobileToggle').addEventListener('click', function() { $('sidebar').classList.toggle('open'); });

document.querySelectorAll('.sidebar nav a').forEach(function(a) {
  a.addEventListener('click', function(e) {
    e.preventDefault();
    document.querySelectorAll('.sidebar nav a').forEach(function(x) { x.classList.remove('active'); });
    a.classList.add('active');
    loadPage(a.dataset.page);
    $('sidebar').classList.remove('open');
  });
});

function loadPage(p) {
  var el = $('content');
  switch(p) {
    case 'dashboard': return pgDash(el);
    case 'services':  return pgSvc(el);
    case 'files':     return pgFiles(el);
    case 'domains':   return pgDom(el);
    case 'databases': return pgDb(el);
    case 'tunnel':    return pgTun(el);
    case 'terminal':  return pgTerm(el);
    case 'settings':  return pgSet(el);
  }
}

function pgDash(el) {
  Promise.all([api.get('/api/dashboard'), api.get('/api/services')]).then(function(res) {
    var d = res[0], s = res[1];
    var mp = Math.round(d.memory.used/d.memory.total*100);
    var dp = d.disk.total ? Math.round(d.disk.used/d.disk.total*100) : 0;
    el.innerHTML = '<h2 class="page-title">📊 Dashboard</h2><p class="page-sub">'+d.hostname+' ('+d.ip+')</p>'
      +'<div class="stats-grid">'
      +'<div class="card"><div class="label">CPU</div><div class="value">'+d.cpu.cores+' Cores</div><div class="sub">Load: '+d.cpu.load.map(function(l){return l.toFixed(2)}).join(', ')+'</div></div>'
      +'<div class="card"><div class="label">Memory</div><div class="value">'+mp+'%</div><div class="progress"><div class="progress-bar '+pClass(mp)+'" style="width:'+mp+'%"></div></div><div class="sub">'+fmtB(d.memory.used)+' / '+fmtB(d.memory.total)+'</div></div>'
      +'<div class="card"><div class="label">Disk</div><div class="value">'+dp+'%</div><div class="progress"><div class="progress-bar '+pClass(dp)+'" style="width:'+dp+'%"></div></div><div class="sub">'+fmtB(d.disk.used)+' / '+fmtB(d.disk.total)+'</div></div>'
      +'<div class="card"><div class="label">Uptime</div><div class="value">'+fmtUp(d.uptime)+'</div><div class="sub">Node '+d.nodeVersion+'</div></div>'
      +'</div><h3 class="mb">Services</h3><table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>'
      +s.map(function(x){return '<tr><td>'+x.name+'</td><td><span class="badge '+(x.active?'badge-on':'badge-off')+'">'+(x.active?'Running':'Stopped')+'</span></td></tr>';}).join('')
      +'</tbody></table>'
      +'<div class="mt"><a href="http://'+d.ip+':7080" target="_blank" class="btn btn-p">OLS Admin</a> <a href="http://'+d.ip+':8088/phpmyadmin/" target="_blank" class="btn btn-w">phpMyAdmin</a></div>';
  });
}

function pgSvc(el) {
  api.get('/api/services').then(function(s) {
    el.innerHTML = '<h2 class="page-title">⚙️ Services</h2><p class="page-sub">Manage services</p><div id="svcMsg"></div>'
      +'<table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'
      +s.map(function(x){
        return '<tr><td><strong>'+x.name+'</strong></td>'
          +'<td><span class="badge '+(x.active?'badge-on':'badge-off')+'">'+(x.active?'Running':'Stopped')+'</span></td>'
          +'<td><button class="btn btn-s btn-sm" data-svc="'+x.name+'" data-act="start" onclick="svcAct(this)">Start</button> '
          +'<button class="btn btn-d btn-sm" data-svc="'+x.name+'" data-act="stop" onclick="svcAct(this)">Stop</button> '
          +'<button class="btn btn-w btn-sm" data-svc="'+x.name+'" data-act="restart" onclick="svcAct(this)">Restart</button></td></tr>';
      }).join('')+'</tbody></table>';
  });
}
window.svcAct = function(btn) {
  var n=btn.dataset.svc, a=btn.dataset.act;
  api.post('/api/services/'+n+'/'+a).then(function(r) {
    $('svcMsg').innerHTML = r.success?'<div class="alert alert-ok">'+n+' '+a+'ed</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
    setTimeout(function(){loadPage('services')},1200);
  });
};

function pgFiles(el, p) {
  if (p !== undefined) curPath = p;
  api.get('/api/files?path='+encodeURIComponent(curPath)).then(function(d) {
    if (d.error) { el.innerHTML='<div class="alert alert-err">'+esc(d.error)+'</div>'; return; }
    if (d.binary) {
      curPath = d.path.substring(0, d.path.lastIndexOf('/'))||'/';
      el.innerHTML='<h2 class="page-title">📄 Binary File</h2><p class="page-sub">'+esc(d.path)+'</p>'
        +'<div class="card"><p>Binary file ('+fmtB(d.size)+') — cannot edit</p>'
        +'<div class="mt"><a href="/api/files/download?path='+encodeURIComponent(d.path)+'" class="btn btn-p" target="_blank">Download</a> '
        +'<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div></div>';
      return;
    }
    if (d.tooLarge) {
      curPath = d.path.substring(0, d.path.lastIndexOf('/'))||'/';
      el.innerHTML='<h2 class="page-title">📄 Large File</h2><p class="page-sub">'+esc(d.path)+'</p>'
        +'<div class="card"><p>File too large to edit ('+fmtB(d.size)+')</p>'
        +'<div class="mt"><a href="/api/files/download?path='+encodeURIComponent(d.path)+'" class="btn btn-p" target="_blank">Download</a> '
        +'<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div></div>';
      return;
    }
    if (d.content !== undefined) {
      editFile = d.path;
      curPath = d.path.substring(0, d.path.lastIndexOf('/'))||'/';
      el.innerHTML='<h2 class="page-title">📝 Edit</h2><p class="page-sub">'+esc(d.path)+' ('+fmtB(d.size)+')</p><div id="fMsg"></div>'
        +'<textarea class="form-control" id="fContent">'+esc(d.content)+'</textarea>'
        +'<div class="mt"><button class="btn btn-p" onclick="saveFile()">💾 Save</button> '
        +'<a href="/api/files/download?path='+encodeURIComponent(d.path)+'" class="btn btn-w" target="_blank">Download</a> '
        +'<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div>';
      return;
    }
    var parts=curPath.split('/').filter(Boolean);
    var bc='<a data-nav="/" onclick="navF(this)">root</a>', bp='';
    parts.forEach(function(x){ bp+='/'+x; bc+=' <span>/</span> <a data-nav="'+encodeURIComponent(bp)+'" onclick="navF(this)">'+esc(x)+'</a>'; });
    var items=(d.items||[]).sort(function(a,b){ return a.isDir===b.isDir?a.name.localeCompare(b.name):(a.isDir?-1:1); });
    var parent=curPath==='/'?'':(curPath.split('/').slice(0,-1).join('/')||'/');
    var html='<h2 class="page-title">📁 File Manager</h2><div class="breadcrumb">'+bc+'</div><div id="fMsg"></div>'
      +'<div class="mb"><button class="btn btn-p" onclick="uploadF()">📤 Upload</button> <button class="btn btn-s" onclick="mkdirF()">📁 New Folder</button></div><div>';
    if (parent) html+='<div class="file-item" data-nav="'+encodeURIComponent(parent)+'" ondblclick="navF(this)"><span class="icon">📁</span><span class="name">..</span><span class="size"></span></div>';
    items.forEach(function(i){
      var fp=(curPath==='/'?'':curPath)+'/'+i.name, enc=encodeURIComponent(fp);
      html+='<div class="file-item" data-nav="'+enc+'" ondblclick="navF(this)">'
        +'<span class="icon">'+(i.isDir?'📁':'📄')+'</span><span class="name">'+esc(i.name)+'</span>'
        +(i.perms?'<span class="perms">'+i.perms+'</span>':'')
        +'<span class="size">'+(i.isDir?'':fmtB(i.size))+'</span>'
        +'<div class="file-actions">'
        +(!i.isDir?'<a href="/api/files/download?path='+enc+'" class="btn btn-p btn-sm" target="_blank" onclick="event.stopPropagation()">⬇</a> ':'')
        +'<button class="btn btn-w btn-sm" data-rn="'+enc+'" onclick="event.stopPropagation();renF(this)">✏️</button> '
        +'<button class="btn btn-d btn-sm" data-del="'+enc+'" onclick="event.stopPropagation();delF(this)">🗑</button>'
        +'</div></div>';
    });
    el.innerHTML=html+'</div>';
  });
}
window.navF = function(el) { var p=el.dataset?el.dataset.nav:el.getAttribute('data-nav'); if(p)pgFiles($('content'),decodeURIComponent(p)); };
window.saveFile = function() {
  api.put('/api/files',{filePath:editFile,content:$('fContent').value}).then(function(r){
    $('fMsg').innerHTML=r.success?'<div class="alert alert-ok">Saved!</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
  });
};
window.delF = function(btn) { var p=decodeURIComponent(btn.dataset.del); if(confirm('Delete '+p+'?'))api.del('/api/files?path='+encodeURIComponent(p)).then(function(){pgFiles($('content'))}); };
window.renF = function(btn) {
  var old=decodeURIComponent(btn.dataset.rn), nm=old.split('/').pop(), nn=prompt('Rename to:',nm);
  if(nn&&nn!==nm){ var dir=old.substring(0,old.lastIndexOf('/')); api.post('/api/files/rename',{oldPath:old,newPath:dir+'/'+nn}).then(function(r){if(r.success)pgFiles($('content'));else alert('Error: '+(r.error||''));}); }
};
window.uploadF = function() {
  var inp=document.createElement('input'); inp.type='file';
  inp.onchange=function(){ var fd=new FormData(); fd.append('file',inp.files[0]); fd.append('path',curPath); api.req('/api/files/upload',{method:'POST',body:fd}).then(function(){pgFiles($('content'))}); };
  inp.click();
};
window.mkdirF = function() { var n=prompt('Folder name:'); if(n)api.post('/api/files/mkdir',{path:curPath+'/'+n}).then(function(){pgFiles($('content'))}); };

function pgDom(el) {
  api.get('/api/domains').then(function(d) {
    el.innerHTML='<h2 class="page-title">🌐 Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div>'
      +'<div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px"><button class="btn btn-p" onclick="addDom()">Add Domain</button></div>'
      +'<table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'
      +d.map(function(x){
        return '<tr><td><strong>'+esc(x.name)+'</strong></td><td><code>'+esc(x.docRoot)+'</code></td>'
          +'<td><button class="btn btn-p btn-sm" data-nav="'+encodeURIComponent(x.docRoot)+'" onclick="navF(this);loadPage(\'files\')">Files</button> '
          +'<button class="btn btn-d btn-sm" data-dom="'+esc(x.name)+'" onclick="delDom(this)">Delete</button></td></tr>';
      }).join('')+(d.length===0?'<tr><td colspan="3" style="text-align:center;color:#8a8d93">No domains yet</td></tr>':'')
      +'</tbody></table>';
  });
}
window.addDom=function(){
  var domain=$('newDom').value.trim(); if(!domain)return;
  api.post('/api/domains',{domain:domain}).then(function(r){
    $('domMsg').innerHTML=r.success?'<div class="alert alert-ok">Domain added!</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
    if(r.success)setTimeout(function(){loadPage('domains')},1200);
  });
};
window.delDom=function(btn){ var n=btn.dataset.dom; if(confirm('Delete domain '+n+'?'))api.del('/api/domains/'+n).then(function(){loadPage('domains')}); };

function pgDb(el) {
  Promise.all([api.get('/api/databases'),api.get('/api/dashboard')]).then(function(res){
    var d=res[0],info=res[1];
    el.innerHTML='<h2 class="page-title">🗃️ Databases</h2><p class="page-sub">MariaDB management</p><div id="dbMsg"></div>'
      +'<div class="flex-row">'
      +'<div><label style="font-size:12px;color:#8a8d93">Database</label><input id="dbName" class="form-control" placeholder="my_db"></div>'
      +'<div><label style="font-size:12px;color:#8a8d93">User (optional)</label><input id="dbUser" class="form-control" placeholder="user"></div>'
      +'<div><label style="font-size:12px;color:#8a8d93">Password</label><input id="dbPass" class="form-control" placeholder="pass" type="password"></div>'
      +'<button class="btn btn-p" onclick="addDb()">Create</button></div>'
      +'<table class="tbl"><thead><tr><th>Database</th><th>Actions</th></tr></thead><tbody>'
      +(Array.isArray(d)?d:[]).map(function(x){return '<tr><td><strong>'+esc(x)+'</strong></td><td><button class="btn btn-d btn-sm" data-db="'+esc(x)+'" onclick="dropDb(this)">Drop</button></td></tr>';}).join('')
      +'</tbody></table><div class="mt"><a href="http://'+info.ip+':8088/phpmyadmin/" target="_blank" class="btn btn-w">Open phpMyAdmin</a></div>';
  });
}
window.addDb=function(){
  api.post('/api/databases',{name:$('dbName').value,user:$('dbUser').value,password:$('dbPass').value}).then(function(r){
    $('dbMsg').innerHTML=r.success?'<div class="alert alert-ok">Created!</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
    if(r.success)setTimeout(function(){loadPage('databases')},1000);
  });
};
window.dropDb=function(btn){ var n=btn.dataset.db; if(confirm('DROP '+n+'?'))api.del('/api/databases/'+n).then(function(){loadPage('databases')}); };

function pgTun(el) {
  api.get('/api/tunnel/status').then(function(s){
    el.innerHTML='<h2 class="page-title">☁️ Cloudflare Tunnel</h2><p class="page-sub">Secure tunnel</p><div id="tunMsg"></div>'
      +'<div class="card mb"><div class="label">Status</div><span class="badge '+(s.active?'badge-on':'badge-off')+'">'+(s.active?'Connected':'Not Connected')+'</span></div>'
      +'<div class="card"><h3 class="mb">Setup Tunnel</h3>'
      +'<p style="color:#8a8d93;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4f8cff">Cloudflare Zero Trust</a><br>2. Create a Tunnel → copy token<br>3. Paste below</p>'
      +'<div class="flex-row"><input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1"><button class="btn btn-p" onclick="setTun()">Connect</button></div></div>';
  });
}
window.setTun=function(){
  api.post('/api/tunnel/setup',{token:$('tunToken').value.trim()}).then(function(r){
    $('tunMsg').innerHTML=r.success?'<div class="alert alert-ok">Connected!</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
    if(r.success)setTimeout(function(){loadPage('tunnel')},2000);
  });
};

function pgTerm(el) {
  el.innerHTML='<h2 class="page-title">💻 Terminal</h2><p class="page-sub">Run commands</p>'
    +'<div class="terminal-box" id="termOut">$ </div>'
    +'<div class="term-input"><input id="termIn" placeholder="Type command..." onkeydown="if(event.key===\'Enter\')runCmd()"><button class="btn btn-p" onclick="runCmd()">Run</button></div>';
  $('termIn').focus();
}
window.runCmd=function(){
  var cmd=$('termIn').value.trim(); if(!cmd)return;
  var out=$('termOut'); out.textContent+=cmd+'\n'; $('termIn').value='';
  api.post('/api/terminal',{command:cmd}).then(function(r){ out.textContent+=(r.output||'')+'\n$ '; out.scrollTop=out.scrollHeight; });
};

function pgSet(el) {
  el.innerHTML='<h2 class="page-title">🔧 Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div>'
    +'<div class="card" style="max-width:400px"><h3 class="mb">Change Password</h3>'
    +'<div class="mb"><label style="font-size:12px;color:#8a8d93">Current Password</label><input type="password" id="curPass" class="form-control"></div>'
    +'<div class="mb"><label style="font-size:12px;color:#8a8d93">New Password</label><input type="password" id="newPass" class="form-control"></div>'
    +'<div class="mb"><label style="font-size:12px;color:#8a8d93">Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>'
    +'<button class="btn btn-p" onclick="chgPass()">Update Password</button></div>';
}
window.chgPass=function(){
  var np=$('newPass').value,cp=$('cfmPass').value;
  if(np!==cp){$('setMsg').innerHTML='<div class="alert alert-err">Passwords don\'t match</div>';return;}
  if(np.length<6){$('setMsg').innerHTML='<div class="alert alert-err">Min 6 characters</div>';return;}
  api.post('/api/settings/password',{currentPassword:$('curPass').value,newPassword:np}).then(function(r){
    $('setMsg').innerHTML=r.success?'<div class="alert alert-ok">Updated!</div>':'<div class="alert alert-err">'+(r.error||'Failed')+'</div>';
  });
};

checkAuth();
JSEOF

log "LitePanel app created"

########################################
step "Step 7/9: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"

# Skip if already installed and working
if [ -f "${PMA_DIR}/index.php" ] && [ -f "${PMA_DIR}/config.inc.php" ]; then
  warn "phpMyAdmin already exists at ${PMA_DIR}, will reconfigure"
fi

mkdir -p "${PMA_DIR}"
cd /tmp

# ============================================
# FIX: Download pinned version first, fallback to latest
# ============================================
PMA_DOWNLOADED=0

log "Downloading phpMyAdmin ${PMA_VERSION}..."
wget -q "${PMA_URL}" -O pma.tar.gz 2>/dev/null
if [ -f pma.tar.gz ] && [ -s pma.tar.gz ]; then
  PMA_DOWNLOADED=1
  log "phpMyAdmin ${PMA_VERSION} downloaded (pinned version)"
else
  warn "Pinned version failed, trying latest..."
  wget -q "${PMA_FALLBACK_URL}" -O pma.tar.gz 2>/dev/null
  if [ -f pma.tar.gz ] && [ -s pma.tar.gz ]; then
    PMA_DOWNLOADED=1
    log "phpMyAdmin latest downloaded (fallback)"
  fi
fi

if [ "$PMA_DOWNLOADED" -eq 1 ]; then
  tar xzf pma.tar.gz 2>/dev/null
  # FIX: Use rsync-like copy to include hidden files, or use find
  if ls -d phpMyAdmin-*/ > /dev/null 2>&1; then
    PMA_EXTRACT_DIR=$(ls -d phpMyAdmin-*/ | head -1)
    # Copy ALL files including hidden ones
    cp -af "${PMA_EXTRACT_DIR}"/* "${PMA_DIR}/" 2>/dev/null
    cp -af "${PMA_EXTRACT_DIR}"/.* "${PMA_DIR}/" 2>/dev/null || true
    rm -rf phpMyAdmin-* pma.tar.gz
  else
    err "phpMyAdmin extraction failed - no phpMyAdmin-* directory found"
    rm -f pma.tar.gz
  fi

  # ============================================
  # FIX: Create phpMyAdmin tmp directory (REQUIRED by 5.x+)
  # ============================================
  mkdir -p "${PMA_DIR}/tmp"

  # ============================================
  # FIX: Generate proper blowfish secret (32+ chars)
  # ============================================
  BLOWFISH=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)

  # ============================================
  # FIX: Complete phpMyAdmin config with:
  #   - 127.0.0.1 (TCP) to bypass socket path issues
  #   - Explicit socket path as fallback
  #   - TempDir set
  #   - Proper security settings
  # ============================================
  cat > ${PMA_DIR}/config.inc.php <<PMAEOF
<?php
/**
 * phpMyAdmin Configuration - Generated by LitePanel Installer
 * Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
 */

\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$cfg['TempDir'] = '${PMA_DIR}/tmp';

/* Server configuration */
\$i = 0;
\$i++;

/* FIX: Use 127.0.0.1 to force TCP connection (bypasses socket path mismatch) */
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '3306';
\$cfg['Servers'][\$i]['socket'] = '${MYSQL_SOCKET}';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['extension'] = 'mysqli';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['compress'] = false;

/* Security settings */
\$cfg['LoginCookieValidity'] = 28800;
\$cfg['LoginCookieStore'] = 0;
\$cfg['LoginCookieDeleteAll'] = true;

/* Upload/Memory limits */
\$cfg['ExecTimeLimit'] = 600;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['MaxRows'] = 100;

/* Disable version check (reduces external requests) */
\$cfg['VersionCheck'] = false;
PMAEOF

  # ============================================
  # FIX: Set correct ownership and permissions
  # ============================================
  chown -R nobody:nogroup "${PMA_DIR}"
  chmod 755 "${PMA_DIR}"
  chmod 644 "${PMA_DIR}/config.inc.php"
  chmod 770 "${PMA_DIR}/tmp"
  chown nobody:nogroup "${PMA_DIR}/tmp"

  log "phpMyAdmin installed and configured"
else
  err "phpMyAdmin download failed from all sources"
fi

# ============================================
# VERIFY phpMyAdmin can connect to MariaDB via PHP
# ============================================
log "Verifying phpMyAdmin PHP→MariaDB connectivity..."

PMA_TEST_SCRIPT=$(mktemp /tmp/pma_test_XXXX.php)
cat > "$PMA_TEST_SCRIPT" <<'PHPTEST'
<?php
// Test 1: Required extensions
$required = ['mysqli', 'mbstring', 'json', 'session'];
$missing = [];
foreach ($required as $ext) {
    if (!extension_loaded($ext)) $missing[] = $ext;
}
if ($missing) {
    echo "FAIL:EXTENSIONS:" . implode(',', $missing);
    exit(1);
}

// Test 2: TCP connection to MariaDB
$conn = @new mysqli('127.0.0.1', 'root', '', '', 3306);
if ($conn->connect_error) {
    echo "FAIL:TCP:" . $conn->connect_error;
    exit(1);
}
$conn->close();

// Test 3: Socket connection to MariaDB
$socket = '/var/run/mysqld/mysqld.sock';
if (file_exists($socket)) {
    $conn2 = @new mysqli('localhost', 'root', '', '', 0, $socket);
    if ($conn2->connect_error) {
        echo "WARN:SOCKET:" . $conn2->connect_error;
    } else {
        $conn2->close();
    }
}

echo "OK";
PHPTEST

PMA_TEST_RESULT=$(/usr/local/lsws/lsphp81/bin/php "$PMA_TEST_SCRIPT" 2>&1)
rm -f "$PMA_TEST_SCRIPT"

case "$PMA_TEST_RESULT" in
  OK*)
    log "phpMyAdmin connectivity test: PASSED ✓"
    ;;
  FAIL:EXTENSIONS:*)
    MISSING=$(echo "$PMA_TEST_RESULT" | cut -d: -f3)
    err "phpMyAdmin test FAILED: Missing PHP extensions: $MISSING"
    warn "Attempting to install missing extensions..."
    for ext in $(echo "$MISSING" | tr ',' ' '); do
      apt-get install -y -qq "lsphp81-${ext}" 2>/dev/null
    done
    ;;
  FAIL:TCP:*)
    ERR_MSG=$(echo "$PMA_TEST_RESULT" | cut -d: -f3-)
    err "phpMyAdmin test FAILED: TCP connection error: $ERR_MSG"
    warn "MariaDB may not be listening on TCP port 3306"
    warn "Check: ss -tlnp | grep 3306"
    ;;
  WARN:SOCKET:*)
    warn "TCP works but socket connection has issues (non-critical with TCP config)"
    ;;
  *)
    warn "phpMyAdmin test returned unexpected result: $PMA_TEST_RESULT"
    ;;
esac

########################################
step "Step 8/9: Install Cloudflared + Fail2Ban"
########################################
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

# Only install if not already present
if ! command -v cloudflared > /dev/null 2>&1; then
  cd /tmp
  if [ "$ARCH" = "arm64" ]; then
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
  else
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
  fi
  wget -q "$CF_URL" -O cloudflared.deb 2>/dev/null
  if [ -f cloudflared.deb ] && [ -s cloudflared.deb ]; then
    dpkg -i cloudflared.deb > /dev/null 2>&1
    rm -f cloudflared.deb
    log "Cloudflared installed"
  else
    err "Cloudflared download failed"
  fi
else
  log "Cloudflared already installed ($(cloudflared --version 2>/dev/null | head -1))"
fi

if ! dpkg -l fail2ban > /dev/null 2>&1; then
  apt-get install -y -qq fail2ban > /dev/null 2>&1
fi
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban 2>/dev/null
log "Fail2Ban installed and enabled"

########################################
step "Step 9/9: Configure Firewall + Start Services"
########################################

# ============================================
# Create systemd service for LitePanel
# ============================================
cat > /etc/systemd/system/litepanel.service <<SVCEOF
[Unit]
Description=LitePanel Control Panel
After=network.target mariadb.service

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=/usr/bin/node app.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable litepanel > /dev/null 2>&1
systemctl restart litepanel

# ============================================
# FIX: UFW - Add rules WITHOUT resetting existing ones
# ============================================
log "Configuring firewall (additive, no reset)..."

ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

REQUIRED_PORTS="22 80 443 ${PANEL_PORT} 7080 8088"
for port in ${REQUIRED_PORTS}; do
  ufw allow "${port}/tcp" > /dev/null 2>&1
done

# Enable only if not already enabled
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable > /dev/null 2>&1
fi
log "Firewall configured (ports: ${REQUIRED_PORTS})"

# ============================================
# SAFE RESTART: Graceful reload instead of hard restart
# ============================================
log "Performing safe service reload..."

# Graceful restart for LSWS (preserves existing connections)
if systemctl is-active --quiet lsws 2>/dev/null; then
  /usr/local/lsws/bin/lswsctrl restart 2>/dev/null || systemctl restart lsws 2>/dev/null
  log "LSWS gracefully restarted"
else
  systemctl start lsws 2>/dev/null
fi

# MariaDB: only restart if we changed config, NOT by default
# (restarting MariaDB can drop active connections)
if systemctl is-active --quiet mariadb 2>/dev/null; then
  log "MariaDB already running (not restarted to preserve connections)"
else
  systemctl start mariadb 2>/dev/null
fi

sleep 3

# ============================================
# SAVE CREDENTIALS
# ============================================
cat > /root/.litepanel_credentials <<CREDEOF
==========================================
  LitePanel Credentials
  Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
==========================================
Panel URL:      http://${SERVER_IP}:${PANEL_PORT}
Panel Login:    ${ADMIN_USER} / ${ADMIN_PASS}

OLS Admin:      http://${SERVER_IP}:7080
OLS Login:      admin / ${ADMIN_PASS}

phpMyAdmin:     http://${SERVER_IP}:8088/phpmyadmin/
DB Root User:   root
DB Root Pass:   ${DB_ROOT_PASS}

phpMyAdmin User: ${PMA_ADMIN_USER}
phpMyAdmin Pass: ${PMA_ADMIN_PASS}
==========================================
CREDEOF
chmod 600 /root/.litepanel_credentials

########################################
# FINAL VERIFICATION
########################################
echo ""
echo -e "${C}╔══════════════════════════════════════════════════╗${N}"
echo -e "${C}║           ✅ Installation Complete!               ║${N}"
echo -e "${C}╠══════════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}                                                  ${C}║${N}"
echo -e "${C}║${N}  LitePanel:    ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:    ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin:   ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}                                                  ${C}║${N}"
echo -e "${C}║${N}  Panel Login:   ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  OLS Admin:     ${Y}admin${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB Root Pass:  ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}  PMA User:      ${Y}${PMA_ADMIN_USER}${N} / ${Y}${PMA_ADMIN_PASS}${N}"
echo -e "${C}║${N}                                                  ${C}║${N}"
echo -e "${C}║${N}  Saved: ${B}/root/.litepanel_credentials${N}"
echo -e "${C}║${N}  Log:   ${B}${LOG_FILE}${N}"
echo -e "${C}║${N}                                                  ${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════════════╝${N}"
echo ""

echo -e "${B}Service Verification:${N}"
ALL_OK=true
for svc in lsws mariadb litepanel fail2ban; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    echo -e "  ${G}[✓]${N} $svc running"
  else
    echo -e "  ${R}[✗]${N} $svc NOT running"
    ALL_OK=false
  fi
done

# Verify phpMyAdmin is accessible
echo ""
echo -e "${B}phpMyAdmin Verification:${N}"
if [ -f "${PMA_DIR}/index.php" ]; then
  echo -e "  ${G}[✓]${N} phpMyAdmin files present"
else
  echo -e "  ${R}[✗]${N} phpMyAdmin files MISSING"
  ALL_OK=false
fi

if [ -f "${PMA_DIR}/config.inc.php" ]; then
  echo -e "  ${G}[✓]${N} config.inc.php present"
else
  echo -e "  ${R}[✗]${N} config.inc.php MISSING"
  ALL_OK=false
fi

if [ -d "${PMA_DIR}/tmp" ] && [ -w "${PMA_DIR}/tmp" ]; then
  echo -e "  ${G}[✓]${N} tmp directory writable"
else
  echo -e "  ${R}[✗]${N} tmp directory issue"
  ALL_OK=false
fi

if mysql -u root -p"${DB_ROOT_PASS}" -e "SELECT 1;" > /dev/null 2>&1; then
  echo -e "  ${G}[✓]${N} MariaDB root password auth works"
else
  echo -e "  ${R}[✗]${N} MariaDB root password auth FAILED"
  ALL_OK=false
fi

if mysql -u "${PMA_ADMIN_USER}" -p"${PMA_ADMIN_PASS}" -e "SELECT 1;" > /dev/null 2>&1; then
  echo -e "  ${G}[✓]${N} Dedicated PMA user '${PMA_ADMIN_USER}' auth works"
else
  echo -e "  ${R}[✗]${N} Dedicated PMA user auth FAILED"
fi

LOADED_EXTS=$(/usr/local/lsws/lsphp81/bin/php -m 2>/dev/null)
for ext in mysqli mbstring json session; do
  if echo "$LOADED_EXTS" | grep -qi "^${ext}$"; then
    echo -e "  ${G}[✓]${N} PHP ext: ${ext}"
  else
    echo -e "  ${R}[✗]${N} PHP ext: ${ext} MISSING"
    ALL_OK=false
  fi
done

echo ""
if [ "$ALL_OK" = true ]; then
  echo -e "${G}ALL CHECKS PASSED! Open http://${SERVER_IP}:${PANEL_PORT} in your browser${N}"
else
  echo -e "${Y}SOME CHECKS FAILED — review output above and check ${LOG_FILE}${N}"
fi

echo ""
echo "=== LitePanel Install completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
