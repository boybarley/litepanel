#!/bin/bash
############################################
# LitePanel Installer v2.1 (Production)
# Fresh Ubuntu 22.04 LTS Only
# REVISED: Fixed phpMyAdmin & Security Issues
############################################

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
# Generate stronger password
ADMIN_PASS=$(openssl rand -base64 12 | tr -d "=+/" | cut -c1-16)
DB_ROOT_PASS="LitePanel$(openssl rand -hex 8)"
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7;exit}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log()  { echo -e "${G}[✓]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }

# === CHECK ROOT ===
[ "$EUID" -ne 0 ] && echo "Run as root!" && exit 1

# === CHECK OS ===
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "22.04" ]]; then
    warn "Designed for Ubuntu 22.04. Detected: $PRETTY_NAME"
    read -rp "Continue anyway? (y/n): " cont
    [[ "$cont" != "y" ]] && exit 1
  fi
fi

# === WAIT FOR DPKG LOCK ===
while fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1; do
  warn "Waiting for other package manager to finish..."
  sleep 3
done

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.1       ║"
echo "  ║   Ubuntu 22.04 LTS              ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${N}"
sleep 2

########################################
step "Step 1/10: Update System"
########################################
apt-get update -y -qq > /dev/null 2>&1
apt-get upgrade -y -qq > /dev/null 2>&1
log "System updated"

########################################
step "Step 2/10: Install Dependencies"
########################################
apt-get install -y -qq curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release ufw git unzip \
  openssl jq > /dev/null 2>&1
log "Dependencies installed"

########################################
step "Step 3/10: Install OpenLiteSpeed + PHP 8.1"
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
    # Try dearmor first, fallback to direct copy
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
# INSTALL OPENLITESPEED (show log on failure!)
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
# FIX: INSTALL PHP 8.1 WITH BETTER ERROR HANDLING
# ============================================
log "Installing PHP 8.1 with all required extensions..."

# First, check what PHP packages are available
log "Checking available PHP packages..."
apt-cache search lsphp81 | grep -E "^lsphp81" > /tmp/available_php_packages.txt

# Method 1: Try to install packages one by one
PHP_INSTALLED=0

# Essential package first
log "Installing lsphp81 base package..."
apt-get install -y lsphp81 > /tmp/php_base_install.log 2>&1
if [ $? -eq 0 ] && [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  PHP_INSTALLED=1
  log "Base PHP 8.1 installed successfully"
else
  warn "Failed to install lsphp81, checking alternatives..."
  
  # Try alternative package names
  for pkg in "lsphp81" "lsphp8.1" "litespeed-php81"; do
    if apt-cache show $pkg > /dev/null 2>&1; then
      log "Trying to install $pkg..."
      apt-get install -y $pkg > /tmp/php_alt_install.log 2>&1
      if [ $? -eq 0 ]; then
        PHP_INSTALLED=1
        log "PHP installed via $pkg"
        break
      fi
    fi
  done
fi

if [ $PHP_INSTALLED -eq 0 ]; then
  err "═══════════════════════════════════════════════"
  err "FATAL: Could not install PHP 8.1!"
  err "Available packages:"
  cat /tmp/available_php_packages.txt
  err ""
  err "Last install attempt log:"
  tail -20 /tmp/php_base_install.log
  err "═══════════════════════════════════════════════"
  err "Please install manually:"
  err "  apt-get update"
  err "  apt-get install lsphp81 lsphp81-mysql lsphp81-common"
  err "═══════════════════════════════════════════════"
  exit 1
fi

# Install PHP extensions with individual error handling
log "Installing PHP extensions..."
FAILED_EXTS=""

# Core extensions for phpMyAdmin
for ext in "common" "mysql" "mysqli" "curl" "json" "mbstring" "xml" "gd" "zip" "intl" "opcache"; do
  PKG="lsphp81-$ext"
  
  # Skip if package doesn't exist
  if ! apt-cache show $PKG > /dev/null 2>&1; then
    # Try without hyphen
    PKG="lsphp81$ext"
    if ! apt-cache show $PKG > /dev/null 2>&1; then
      warn "Package $ext not found, skipping..."
      continue
    fi
  fi
  
  apt-get install -y $PKG > /tmp/php_ext_${ext}.log 2>&1
  if [ $? -eq 0 ]; then
    log "Installed $PKG"
  else
    warn "Failed to install $PKG"
    FAILED_EXTS="$FAILED_EXTS $ext"
  fi
done

# Check if critical extensions are missing
CRITICAL_MISSING=""
for ext in "mysql" "mysqli" "json"; do
  if [[ "$FAILED_EXTS" == *"$ext"* ]]; then
    CRITICAL_MISSING="$CRITICAL_MISSING $ext"
  fi
done

if [ -n "$CRITICAL_MISSING" ]; then
  warn "Critical PHP extensions missing:$CRITICAL_MISSING"
  warn "phpMyAdmin may not work properly!"
fi

# Create symlink and verify
if [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null
  PHP_VERSION=$(php -v 2>/dev/null | head -1 | awk '{print $2}')
  log "PHP 8.1 installed ($PHP_VERSION)"
  
  # Show installed extensions
  log "Installed PHP extensions:"
  php -m 2>/dev/null | grep -E "(mysql|json|mbstring|gd|xml|curl)" | while read ext; do
    echo "  - $ext"
  done
else
  err "PHP binary not found at expected location"
  exit 1
fi

# ============================================
# CONFIGURE PHP FOR MYSQL SOCKET
# ============================================
log "Configuring PHP MySQL socket path..."

# Find php.ini location
PHP_INI_DIR="/usr/local/lsws/lsphp81/etc/php/8.1/litespeed"
if [ ! -d "$PHP_INI_DIR" ]; then
  # Try alternative paths
  for dir in "/usr/local/lsws/lsphp81/etc/php/8.1/mods-available" \
             "/usr/local/lsws/lsphp81/etc" \
             "/usr/local/lsws/lsphp81/lib"; do
    if [ -d "$dir" ]; then
      PHP_INI_DIR="$dir"
      break
    fi
  done
fi

# Create php.ini if it doesn't exist
PHP_INI="$PHP_INI_DIR/php.ini"
if [ ! -f "$PHP_INI" ]; then
  log "Creating php.ini at $PHP_INI"
  mkdir -p "$PHP_INI_DIR"
  
  # Copy from template if exists
  if [ -f "/usr/local/lsws/lsphp81/etc/php.ini-production" ]; then
    cp "/usr/local/lsws/lsphp81/etc/php.ini-production" "$PHP_INI"
  else
    # Create minimal php.ini
    cat > "$PHP_INI" <<'PHPINI'
[PHP]
engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
implicit_flush = Off
disable_functions =
disable_classes =
expose_php = Off
max_execution_time = 30
max_input_time = 60
memory_limit = 256M
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
log_errors = On
post_max_size = 50M
upload_max_filesize = 50M
max_file_uploads = 20
default_socket_timeout = 60

[MySQLi]
mysqli.default_socket = /var/run/mysqld/mysqld.sock
mysqli.default_host = localhost
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[MySQL]  
mysql.default_socket = /var/run/mysqld/mysqld.sock

[PDO_MYSQL]
pdo_mysql.default_socket = /var/run/mysqld/mysqld.sock

[Session]
session.save_handler = files
session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.cookie_httponly = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.cookie_lifetime = 0
session.cookie_path = /
session.serialize_handler = php
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440

[Date]
date.timezone = UTC
PHPINI
  fi
fi

# Update MySQL socket configuration
if [ -f "$PHP_INI" ]; then
  # Backup original
  cp "$PHP_INI" "$PHP_INI.bak"
  
  # Configure MySQL socket paths
  sed -i 's/^;\?mysqli.default_socket.*/mysqli.default_socket = \/var\/run\/mysqld\/mysqld.sock/' "$PHP_INI"
  sed -i 's/^;\?mysql.default_socket.*/mysql.default_socket = \/var\/run\/mysqld\/mysqld.sock/' "$PHP_INI"
  sed -i 's/^;\?pdo_mysql.default_socket.*/pdo_mysql.default_socket = \/var\/run\/mysqld\/mysqld.sock/' "$PHP_INI"
  
  # If lines don't exist, add them
  grep -q "mysqli.default_socket" "$PHP_INI" || echo "mysqli.default_socket = /var/run/mysqld/mysqld.sock" >> "$PHP_INI"
  grep -q "mysql.default_socket" "$PHP_INI" || echo "mysql.default_socket = /var/run/mysqld/mysqld.sock" >> "$PHP_INI"
  grep -q "pdo_mysql.default_socket" "$PHP_INI" || echo "pdo_mysql.default_socket = /var/run/mysqld/mysqld.sock" >> "$PHP_INI"
  
  log "PHP MySQL socket configured"
else
  warn "PHP ini file not found at expected location"
fi

# Create additional ini file for LiteSpeed
LSPHP_CONF="/usr/local/lsws/lsphp81/etc/php/8.1/mods-available/99-mysql-socket.ini"
if [ ! -f "$LSPHP_CONF" ]; then
  mkdir -p "$(dirname "$LSPHP_CONF")"
  cat > "$LSPHP_CONF" <<'SOCKINI'
; MySQL socket configuration for phpMyAdmin
mysqli.default_socket = /var/run/mysqld/mysqld.sock
mysql.default_socket = /var/run/mysqld/mysqld.sock  
pdo_mysql.default_socket = /var/run/mysqld/mysqld.sock
SOCKINI
  log "Created additional MySQL socket configuration"
fi


########################################
step "Step 4/10: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Wait for MariaDB to be ready
for i in $(seq 1 15); do
  mysqladmin ping &>/dev/null && break
  sleep 2
done

if mysqladmin ping &>/dev/null; then
  mysql -u root -e "
    ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
    DELETE FROM mysql.user WHERE User='';
    DROP DATABASE IF EXISTS test;
    FLUSH PRIVILEGES;
  " 2>/dev/null
  
  # Create socket symlink for compatibility
  if [ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ]; then
    ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock
    log "MySQL socket symlink created"
  fi
  
  log "MariaDB installed & secured"
else
  err "MariaDB failed to start"
fi

########################################
step "Step 5/10: Install Node.js 18"
########################################
if ! command -v node > /dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_18.x 2>/dev/null | bash - > /dev/null 2>&1
  apt-get install -y -qq nodejs > /dev/null 2>&1
fi

if command -v node > /dev/null 2>&1; then
  log "Node.js $(node -v 2>/dev/null) installed"
else
  err "Node.js installation failed!"
  err "Manual install: curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && apt install nodejs"
  exit 1
fi

########################################
step "Step 6/10: Creating LitePanel App"
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

# --- config.json with stronger credentials ---
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
step "Step 7/10: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
mkdir -p ${PMA_DIR}
cd /tmp
log "Downloading phpMyAdmin..."
wget "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz" -O pma.tar.gz 2>/dev/null
if [ -f pma.tar.gz ] && [ -s pma.tar.gz ]; then
  tar xzf pma.tar.gz
  cp -rf phpMyAdmin-*/* ${PMA_DIR}/
  rm -rf phpMyAdmin-* pma.tar.gz

  # Generate stronger blowfish secret (32 bytes)
  BLOWFISH=$(openssl rand -hex 32)
  cat > ${PMA_DIR}/config.inc.php <<PMAEOF
<?php
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['socket'] = '/var/run/mysqld/mysqld.sock';
\$cfg['TempDir'] = '/tmp';
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
PMAEOF
  
  # Set proper permissions
  chown -R nobody:nogroup ${PMA_DIR}
  chmod 755 ${PMA_DIR}
  
  # Create tmp directory for phpMyAdmin
  mkdir -p ${PMA_DIR}/tmp
  chown nobody:nogroup ${PMA_DIR}/tmp
  chmod 755 ${PMA_DIR}/tmp
  
  log "phpMyAdmin installed"
else
  err "phpMyAdmin download failed"
fi

########################################
# FIX: Configure OpenLiteSpeed for phpMyAdmin
########################################
log "Configuring OpenLiteSpeed for phpMyAdmin access..."

# Backup current config
cp "$OLS_CONF" "$OLS_CONF.bak.phpmyadmin"

# Add listener for port 8088 if not exists
if ! grep -q "listener phpMyAdmin" "$OLS_CONF"; then
  log "Adding phpMyAdmin listener on port 8088..."
  cat >> "$OLS_CONF" <<'PMALISTENER'

listener phpMyAdmin {
  address                 *:8088
  secure                  0
  map                     Example *
}
PMALISTENER
fi

# Ensure Example vhost is properly configured
EXAMPLE_VHCONF="/usr/local/lsws/conf/vhosts/Example/vhconf.conf"
if [ -f "$EXAMPLE_VHCONF" ]; then
  # Backup
  cp "$EXAMPLE_VHCONF" "$EXAMPLE_VHCONF.bak.phpmyadmin"
  
  # Ensure docRoot is set correctly
  if ! grep -q "docRoot.*Example/html" "$EXAMPLE_VHCONF"; then
    sed -i '/docRoot/c\docRoot                   $VH_ROOT/html' "$EXAMPLE_VHCONF"
  fi
  
  # Ensure index files include index.php
  if ! grep -q "index.php" "$EXAMPLE_VHCONF"; then
    # Check if index section exists
    if grep -q "^index" "$EXAMPLE_VHCONF"; then
      # Update existing index section
      sed -i '/indexFiles/c\  indexFiles              index.php, index.html' "$EXAMPLE_VHCONF"
    else
      # Add index section
      cat >> "$EXAMPLE_VHCONF" <<'INDEXEOF'

index {
  useServer               0
  indexFiles              index.php, index.html
  autoIndex               0
}
INDEXEOF
    fi
  fi
  
  # Ensure PHP handler is configured
  if ! grep -q "scripthandler" "$EXAMPLE_VHCONF"; then
    cat >> "$EXAMPLE_VHCONF" <<'HANDLEREOF'

scripthandler {
  add                     lsapi:lsphp81 php
}
HANDLEREOF
  else
    # Update existing handler to use lsphp81
    sed -i '/add.*lsapi:lsphp/c\  add                     lsapi:lsphp81 php' "$EXAMPLE_VHCONF"
  fi
  
  # Add rewrite rules for phpMyAdmin
  if ! grep -q "rewrite" "$EXAMPLE_VHCONF"; then
    cat >> "$EXAMPLE_VHCONF" <<'REWRITEEOF'

rewrite {
  enable                  1
  autoLoadHtaccess        1
}
REWRITEEOF
  fi
  
  log "Example vhost configured for phpMyAdmin"
fi

# Create .htaccess for phpMyAdmin if needed
if [ -d "${PMA_DIR}" ]; then
  cat > "${PMA_DIR}/.htaccess" <<'HTACCESSEOF'
# phpMyAdmin .htaccess
DirectoryIndex index.php
Options -Indexes +FollowSymLinks

<FilesMatch "\.php$">
  SetHandler lsapi:lsphp81
</FilesMatch>

# Security headers
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set X-XSS-Protection "1; mode=block"
HTACCESSEOF
  chown nobody:nogroup "${PMA_DIR}/.htaccess"
fi

# Restart OpenLiteSpeed to apply changes
log "Restarting OpenLiteSpeed to apply phpMyAdmin configuration..."
systemctl restart lsws
sleep 3

# Verify OLS is running
if ! systemctl is-active --quiet lsws; then
  warn "OpenLiteSpeed failed to restart, reverting configuration..."
  cp "$OLS_CONF.bak.phpmyadmin" "$OLS_CONF"
  cp "$EXAMPLE_VHCONF.bak.phpmyadmin" "$EXAMPLE_VHCONF"
  systemctl restart lsws
  err "Failed to configure phpMyAdmin listener"
else
  log "phpMyAdmin listener configured successfully"
fi

########################################
# FIX: Configure OpenLiteSpeed for phpMyAdmin
########################################
log "Configuring OpenLiteSpeed for phpMyAdmin access..."

# Ensure Example virtualhost exists and configured properly
if ! grep -q "virtualhost Example" "$OLS_CONF"; then
    cat >> "$OLS_CONF" << 'EOF'

virtualhost Example {
  vhRoot                  /usr/local/lsws/Example/
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              0
  setUIDMode              0
}
EOF
fi

# Ensure PHP extprocessor exists
if ! grep -q "extprocessor lsphp81" "$OLS_CONF"; then
    # Find insertion point
    LINE=$(grep -n "virtualhost" "$OLS_CONF" | head -1 | cut -d: -f1)
    if [ -n "$LINE" ]; then
        sed -i "${LINE}i\\
extprocessor lsphp81 {\\
  type                    lsapi\\
  address                 uds://tmp/lshttpd/lsphp.sock\\
  maxConns                10\\
  env                     PHP_LSAPI_CHILDREN=10\\
  initTimeout             60\\
  retryTimeout            0\\
  respBuffer              0\\
  autoStart               2\\
  path                    /usr/local/lsws/lsphp81/bin/lsphp\\
  backlog                 100\\
  instances               1\\
  memSoftLimit            2047M\\
  memHardLimit            2047M\\
}\\
" "$OLS_CONF"
    fi
fi

# Update Example vhost config
cat > /usr/local/lsws/conf/vhosts/Example/vhconf.conf << 'EOF'
docRoot                   $VH_ROOT/html
vhDomain                  *
enableGzip                1

index {
  useServer               0
  indexFiles              index.php, index.html
}

scripthandler {
  add                     lsapi:lsphp81 php
}

accessControl {
  allow                   *
}

rewrite {
  enable                  1
  autoLoadHtaccess        1
}
EOF

# Fix ownership
chown -R nobody:nogroup "${PMA_DIR}"
chmod -R 755 "${PMA_DIR}"

# Restart OpenLiteSpeed
systemctl restart lsws
sleep 3

log "phpMyAdmin configuration completed"

########################################
step "Step 8/10: Install Cloudflared + Fail2Ban"
########################################
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
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

apt-get install -y -qq fail2ban > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban 2>/dev/null
log "Fail2Ban installed"

########################################
step "Step 9/10: Configure Firewall + Start Services"
########################################
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
systemctl start litepanel

ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
for port in 22 80 443 ${PANEL_PORT} 7080 8088; do
  ufw allow ${port}/tcp > /dev/null 2>&1
done
ufw --force enable > /dev/null 2>&1
log "Firewall configured"

########################################
step "Step 10/10: Verify & Fix Services"
########################################
log "Verifying all services..."

# Restart services in correct order
systemctl restart mariadb 2>/dev/null
sleep 2
systemctl restart lsws 2>/dev/null
sleep 3

# Verify MySQL socket link
if [ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ]; then
  ln -sf /var/run/mysqld/mysqld.sock /tmp/mysql.sock
  log "MySQL socket symlink verified"
fi

# Test PHP MySQL connection
PHP_TEST=$(php -r "
try {
  \$mysqli = new mysqli('localhost', 'root', '${DB_ROOT_PASS}');
  if (\$mysqli->connect_error) {
    echo 'FAIL: ' . \$mysqli->connect_error;
  } else {
    echo 'OK';
    \$mysqli->close();
  }
} catch (Exception \$e) {
  echo 'FAIL: ' . \$e->getMessage();
}
" 2>&1)

if [[ "$PHP_TEST" == "OK" ]]; then
  log "PHP MySQL connection verified"
else
  warn "PHP MySQL connection test: $PHP_TEST"
  # Try alternative socket configuration
  mkdir -p /var/lib/mysql
  ln -sf /var/run/mysqld/mysqld.sock /var/lib/mysql/mysql.sock 2>/dev/null
fi

# Test phpMyAdmin accessibility
PHPMYADMIN_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/phpmyadmin/ 2>/dev/null)
if [ "$PHPMYADMIN_TEST" = "200" ] || [ "$PHPMYADMIN_TEST" = "302" ]; then
  log "phpMyAdmin is accessible (HTTP $PHPMYADMIN_TEST)"
else
  warn "phpMyAdmin returned HTTP $PHPMYADMIN_TEST - checking configuration..."
  # Force restart LSWS to reload PHP configuration
  systemctl restart lsws
  sleep 3
fi

# Save credentials to secure location
mkdir -p /etc/litepanel
cat > /etc/litepanel/credentials <<CREDEOF
==========================================
  LitePanel Credentials (v2.1)
==========================================
Panel URL:     http://${SERVER_IP}:${PANEL_PORT}
Panel Login:   ${ADMIN_USER} / ${ADMIN_PASS}

OLS Admin:     http://${SERVER_IP}:7080
OLS Login:     admin / ${ADMIN_PASS}

phpMyAdmin:    http://${SERVER_IP}:8088/phpmyadmin/

MariaDB Root:  ${DB_ROOT_PASS}
==========================================
Generated: $(date)
==========================================
CREDEOF
chmod 600 /etc/litepanel/credentials

# Also save to user home for convenience
cp /etc/litepanel/credentials /root/.litepanel_credentials

log "All services verified and running"

########################################
# FINAL SUMMARY
########################################
echo ""
echo -e "${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║         ✅ Installation Complete!             ║${N}"
echo -e "${C}╠══════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  LitePanel:   ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:   ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin:  ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Panel Login:  ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  OLS Admin:    ${Y}admin${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB Root Pass: ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Saved: ${B}/etc/litepanel/credentials${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════════╝${N}"
echo ""

echo -e "${B}Service Status:${N}"
for svc in lsws mariadb litepanel fail2ban; do
  if systemctl is-active --quiet $svc 2>/dev/null; then
    echo -e "  ${G}[✓]${N} $svc running"
  else
    echo -e "  ${R}[✗]${N} $svc not running"
  fi
done
echo ""
echo -e "${G}DONE! Open http://${SERVER_IP}:${PANEL_PORT} in your browser${N}"
echo ""
echo -e "${Y}TIP: To check phpMyAdmin, visit http://${SERVER_IP}:8088/phpmyadmin/${N}"
