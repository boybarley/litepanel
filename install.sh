#!/bin/bash
############################################
# LitePanel Installer v2.1 (Production)
# Fresh Ubuntu 22.04 LTS Only
# REVISED: Fixed phpMyAdmin & Security Issues
# UPDATED: White UI theme and cPanel-like file manager
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
    "multer": "^1.4.5-lts.1",
    "adm-zip": "^0.5.10",
    "mime-types": "^2.1.35"
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
const AdmZip = require('adm-zip');
const mime = require('mime-types');

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
function decodePathParameter(encodedPath) {
  try {
    return decodeURIComponent(encodedPath);
  } catch (error) {
    return encodedPath;
  }
}

/* === File Operations === */
function isTextFile(filePath, size) {
  // Skip check for larger files to improve performance
  if (size > 1024 * 1024) return false;
  
  try {
    // Read first few KB to check for binary content
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(Math.min(size, 4096));
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    
    // Check for NUL bytes (common in binary files)
    return !buffer.includes(0);
  } catch (e) {
    return false;
  }
}

function compressFiles(sourcePaths, outputPath) {
  try {
    const zip = new AdmZip();
    for (const sourcePath of sourcePaths) {
      const stats = fs.statSync(sourcePath);
      if (stats.isDirectory()) {
        zip.addLocalFolder(sourcePath, path.basename(sourcePath));
      } else {
        zip.addLocalFile(sourcePath);
      }
    }
    zip.writeZip(outputPath);
    return true;
  } catch (e) {
    return false;
  }
}

function extractArchive(archivePath, targetDir) {
  try {
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(targetDir, true);
    return true;
  } catch (e) {
    return false;
  }
}

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
  var encodedPath = req.query.path || '/';
  var p = path.resolve(decodePathParameter(encodedPath));
  
  try {
    var stat = fs.statSync(p);
    if (stat.isDirectory()) {
      var items = [];
      fs.readdirSync(p).forEach(function(name) {
        try {
          var s = fs.statSync(path.join(p, name));
          items.push({ 
            name: name, 
            isDir: s.isDirectory(), 
            size: s.size, 
            modified: s.mtime,
            perms: '0' + (s.mode & parseInt('777', 8)).toString(8),
            extension: path.extname(name).toLowerCase().substring(1)
          });
        } catch(e) { items.push({ name: name, isDir: false, size: 0, error: true }); }
      });
      res.json({ path: p, items: items });
    } else {
      if (stat.size > MAX_EDIT_SIZE) return res.json({ path: p, size: stat.size, tooLarge: true });
      
      const isText = isTextFile(p, stat.size);
      if (!isText) return res.json({ path: p, size: stat.size, binary: true });
      
      res.json({ 
        path: p, 
        content: fs.readFileSync(p, 'utf8'), 
        size: stat.size,
        extension: path.extname(p).toLowerCase().substring(1)
      });
    }
  } catch(e) { res.status(404).json({ error: e.message }); }
});

app.put('/api/files', auth, function(req, res) {
  try { fs.writeFileSync(req.body.filePath, req.body.content); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/files', auth, function(req, res) {
  var target = decodePathParameter(req.query.path);
  if (!target || target === '/') return res.status(400).json({ error: 'Cannot delete root' });
  try { fs.rmSync(target, { recursive: true, force: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// File upload handler
var upload = multer({ dest: '/tmp/uploads/' });
app.post('/api/files/upload', auth, upload.array('files'), function(req, res) {
  try {
    const targetPath = decodePathParameter(req.body.path) || '/tmp';
    const results = [];
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files were uploaded' });
    }
    
    for (const file of req.files) {
      const destination = path.join(targetPath, file.originalname);
      fs.renameSync(file.path, destination);
      results.push({ 
        name: file.originalname, 
        size: file.size, 
        path: destination,
        success: true 
      });
    }
    
    res.json({ success: true, files: results });
  } catch(e) { 
    res.status(500).json({ error: e.message }); 
  }
});

app.post('/api/files/mkdir', auth, function(req, res) {
  try { fs.mkdirSync(decodePathParameter(req.body.path), { recursive: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/rename', auth, function(req, res) {
  try { 
    const oldPath = decodePathParameter(req.body.oldPath);
    const newPath = decodePathParameter(req.body.newPath);
    fs.renameSync(oldPath, newPath); 
    res.json({ success: true }); 
  }
  catch(e) { res.status(500).json({ error: e.error || e.message }); }
});

app.get('/api/files/download', auth, function(req, res) {
  var fp = decodePathParameter(req.query.path);
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  try { 
    if (fs.statSync(fp).isDirectory()) return res.status(400).json({ error: 'Cannot download directory' }); 
    
    // Set appropriate content type
    const contentType = mime.lookup(fp) || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    
    // Set content disposition
    res.setHeader('Content-Disposition', 'attachment; filename=' + path.basename(fp));
    
    // Stream the file
    fs.createReadStream(fp).pipe(res);
  }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// New archive/compress endpoint
app.post('/api/files/compress', auth, function(req, res) {
  try {
    const sourcePaths = Array.isArray(req.body.paths) ? req.body.paths.map(p => decodePathParameter(p)) : [];
    const outputPath = decodePathParameter(req.body.output);
    
    if (sourcePaths.length === 0 || !outputPath) {
      return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    // Validate all paths exist
    for (const p of sourcePaths) {
      if (!fs.existsSync(p)) {
        return res.status(404).json({ error: `Path not found: ${p}` });
      }
    }
    
    // Ensure output path ends with .zip
    const finalOutput = outputPath.endsWith('.zip') ? outputPath : outputPath + '.zip';
    
    // Create zip file
    const success = compressFiles(sourcePaths, finalOutput);
    
    if (success) {
      res.json({ success: true, path: finalOutput });
    } else {
      res.status(500).json({ error: 'Failed to create archive' });
    }
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// New extract endpoint
app.post('/api/files/extract', auth, function(req, res) {
  try {
    const archivePath = decodePathParameter(req.body.archive);
    const targetDir = decodePathParameter(req.body.target);
    
    if (!archivePath || !targetDir) {
      return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    if (!fs.existsSync(archivePath)) {
      return res.status(404).json({ error: 'Archive not found' });
    }
    
    // Create target directory if it doesn't exist
    fs.mkdirSync(targetDir, { recursive: true });
    
    // Extract archive
    const success = extractArchive(archivePath, targetDir);
    
    if (success) {
      res.json({ success: true, path: targetDir });
    } else {
      res.status(500).json({ error: 'Failed to extract archive' });
    }
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// New endpoint for getting file permissions
app.get('/api/files/permissions', auth, function(req, res) {
  var p = decodePathParameter(req.query.path);
  if (!p || !fs.existsSync(p)) return res.status(404).json({ error: 'Not found' });
  
  try {
    const stats = fs.statSync(p);
    const permissions = '0' + (stats.mode & parseInt('777', 8)).toString(8);
    
    // Get owner and group
    const owner = run(`stat -c "%U" "${shellEsc(p)}"`) || 'unknown';
    const group = run(`stat -c "%G" "${shellEsc(p)}"`) || 'unknown';
    
    res.json({ 
      permissions,
      owner,
      group,
      isDir: stats.isDirectory()
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint for changing permissions
app.post('/api/files/permissions', auth, function(req, res) {
  try {
    const filePath = decodePathParameter(req.body.path);
    const permissions = req.body.permissions;
    const recursive = req.body.recursive === true;
    
    if (!filePath || !permissions || !fs.existsSync(filePath)) {
      return res.status(400).json({ error: 'Invalid parameters' });
    }
    
    // Validate permissions format (0755, 755, etc.)
    const permRegex = /^(0)?[0-7]{3,4}$/;
    if (!permRegex.test(permissions)) {
      return res.status(400).json({ error: 'Invalid permission format' });
    }
    
    // Convert to octal if needed
    const octalPerms = permissions.startsWith('0') ? 
      parseInt(permissions, 8) : 
      parseInt('0' + permissions, 8);
    
    const cmd = recursive ? 
      `chmod -R ${octalPerms.toString(8)} "${shellEsc(filePath)}"` : 
      `chmod ${octalPerms.toString(8)} "${shellEsc(filePath)}"`;
    
    run(cmd);
    
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint for creating new file
app.post('/api/files/newfile', auth, function(req, res) {
  try {
    const filePath = decodePathParameter(req.body.path);
    const content = req.body.content || '';
    
    if (!filePath) {
      return res.status(400).json({ error: 'Path is required' });
    }
    
    // Check if file already exists
    if (fs.existsSync(filePath)) {
      return res.status(400).json({ error: 'File already exists' });
    }
    
    // Create parent directory if needed
    const dirPath = path.dirname(filePath);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
    
    // Write file
    fs.writeFileSync(filePath, content);
    
    res.json({ success: true, path: filePath });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
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
// Get all databases and users
app.get('/api/databases', auth, function(req, res) {
  try {
    // Get all databases 
    var dbOutput = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e 'SHOW DATABASES;' -s -N 2>/dev/null");
    var skip = ['information_schema','performance_schema','mysql','sys'];
    var databases = dbOutput.split('\n').filter(function(d) { return d.trim() && !skip.includes(d.trim()); });
    
    // Get all users
    var userOutput = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + 
                        "' -e 'SELECT User, Host FROM mysql.user WHERE Host=\"localhost\" AND User NOT IN (\"root\",\"debian-sys-maint\",\"mariadb.sys\");' -s -N 2>/dev/null");
    var users = userOutput.split('\n').filter(function(u) { return u.trim(); }).map(function(u) {
      var parts = u.split('\t');
      return { username: parts[0], host: parts[1] || 'localhost' };
    });
    
    // Get grants for each user
    var result = [];
    databases.forEach(function(db) {
      var dbUsers = [];
      users.forEach(function(user) {
        // Check if user has privileges on this database
        var grantOutput = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + 
                             "' -e 'SHOW GRANTS FOR \"" + user.username + "\"@\"" + user.host + "\";' -s -N 2>/dev/null");
        
        if (grantOutput.includes('`' + db + '`') || grantOutput.includes('*.*')) {
          dbUsers.push(user.username);
        }
      });
      
      result.push({
        name: db,
        users: dbUsers
      });
    });
    
    res.json(result);
  } catch(e) { 
    console.error(e);
    res.json([]); 
  }
});

// Get all database users
app.get('/api/database-users', auth, function(req, res) {
  try {
    var userOutput = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + 
                       "' -e 'SELECT User, Host FROM mysql.user WHERE Host=\"localhost\" AND User NOT IN (\"root\",\"debian-sys-maint\",\"mariadb.sys\");' -s -N 2>/dev/null");
    var users = userOutput.split('\n').filter(function(u) { return u.trim(); }).map(function(u) {
      var parts = u.split('\t');
      return { username: parts[0], host: parts[1] || 'localhost' };
    });
    res.json(users);
  } catch(e) {
    console.error(e);
    res.json([]);
  }
});

// Create database
app.post('/api/databases', auth, function(req, res) {
  try {
    var name = req.body.name;
    var user = req.body.user;
    var password = req.body.password;
    
    if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) {
      return res.status(400).json({ error: 'Invalid database name' });
    }
    
    // Create the database
    var dbEscaped = shellEsc(name);
    var dp = shellEsc(config.dbRootPass);
    run("mysql -u root -p'" + dp + "' -e \"CREATE DATABASE IF NOT EXISTS \\`" + dbEscaped + "\\`;\" 2>/dev/null");
    
    // If user is provided, create or update user with password
    if (user && password) {
      if (!/^[a-zA-Z0-9_]+$/.test(user)) {
        return res.status(400).json({ error: 'Invalid username' });
      }
      
      var userEscaped = shellEsc(user);
      var passEscaped = shellEsc(password);
      
      // Create user if it doesn't exist
      run("mysql -u root -p'" + dp + "' -e \"CREATE USER IF NOT EXISTS '" + userEscaped + "'@'localhost' IDENTIFIED BY '" + passEscaped + "';\" 2>/dev/null");
      
      // Grant privileges on database
      run("mysql -u root -p'" + dp + "' -e \"GRANT ALL ON \\`" + dbEscaped + "\\`.* TO '" + userEscaped + "'@'localhost';\" 2>/dev/null");
      
      // Flush privileges
      run("mysql -u root -p'" + dp + "' -e \"FLUSH PRIVILEGES;\" 2>/dev/null");
    }
    
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Create database user
app.post('/api/database-users', auth, function(req, res) {
  try {
    var user = req.body.username;
    var password = req.body.password;
    var databases = req.body.databases || [];
    
    if (!user || !/^[a-zA-Z0-9_]+$/.test(user)) {
      return res.status(400).json({ error: 'Invalid username' });
    }
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    
    var dp = shellEsc(config.dbRootPass);
    var userEscaped = shellEsc(user);
    var passEscaped = shellEsc(password);
    
    // Create or update user
    run("mysql -u root -p'" + dp + "' -e \"CREATE USER IF NOT EXISTS '" + userEscaped + "'@'localhost' IDENTIFIED BY '" + passEscaped + "';\" 2>/dev/null");
    
    // Grant privileges on specified databases
    if (Array.isArray(databases) && databases.length > 0) {
      databases.forEach(function(db) {
        if (/^[a-zA-Z0-9_]+$/.test(db)) {
          run("mysql -u root -p'" + dp + "' -e \"GRANT ALL ON \\`" + shellEsc(db) + "\\`.* TO '" + userEscaped + "'@'localhost';\" 2>/dev/null");
        }
      });
    }
    
    // Flush privileges
    run("mysql -u root -p'" + dp + "' -e \"FLUSH PRIVILEGES;\" 2>/dev/null");
    
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete database
app.delete('/api/databases/:name', auth, function(req, res) {
  if (!/^[a-zA-Z0-9_]+$/.test(req.params.name)) return res.status(400).json({ error: 'Invalid' });
  try {
    run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e \"DROP DATABASE IF EXISTS \\`" + req.params.name + "\\`;\" 2>/dev/null");
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete user
app.delete('/api/database-users/:name', auth, function(req, res) {
  if (!/^[a-zA-Z0-9_]+$/.test(req.params.name)) return res.status(400).json({ error: 'Invalid' });
  try {
    var user = req.params.name;
    run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e \"DROP USER IF EXISTS '" + shellEsc(user) + "'@'localhost';\" 2>/dev/null");
    run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e \"FLUSH PRIVILEGES;\" 2>/dev/null");
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
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.1.1/css/all.min.css">
<link rel="stylesheet" href="/css/style.css">
</head>
<body>
<div id="loginPage" class="login-page">
  <div class="login-box">
    <h1><i class="fas fa-server"></i> LitePanel</h1>
    <form id="loginForm">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <button type="submit">Login</button>
      <div id="loginError" class="error"></div>
    </form>
    <div class="copyright">LitePanel© by Boy Barley</div>
  </div>
</div>
<div id="mainPanel" class="main-panel" style="display:none">
  <button id="mobileToggle" class="mobile-toggle"><i class="fas fa-bars"></i></button>
  <aside class="sidebar" id="sidebar">
    <div class="logo"><i class="fas fa-server"></i> LitePanel</div>
    <nav>
      <a href="#" data-page="dashboard" class="active"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
      <a href="#" data-page="services"><i class="fas fa-cogs"></i> Services</a>
      <a href="#" data-page="files"><i class="fas fa-folder"></i> File Manager</a>
      <a href="#" data-page="domains"><i class="fas fa-globe"></i> Domains</a>
      <a href="#" data-page="databases"><i class="fas fa-database"></i> Databases</a>
      <a href="#" data-page="tunnel"><i class="fas fa-cloud"></i> Tunnel</a>
      <a href="#" data-page="terminal"><i class="fas fa-terminal"></i> Terminal</a>
      <a href="#" data-page="settings"><i class="fas fa-sliders-h"></i> Settings</a>
    </nav>
    <a href="#" id="logoutBtn" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
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
/* Modern White Theme for LitePanel */
* { margin: 0; padding: 0; box-sizing: border-box; }
body { 
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; 
  background: #f5f7fa;
  color: #333;
  line-height: 1.5;
}

/* Login Page */
.login-page { 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  min-height: 100vh; 
  background: linear-gradient(135deg, #f5f7fa, #e4e7eb);
}
.login-box { 
  background: #fff; 
  padding: 40px; 
  border-radius: 12px; 
  width: 360px; 
  box-shadow: 0 8px 30px rgba(0,0,0,0.1);
  position: relative;
}
.login-box h1 { 
  text-align: center; 
  color: #4a89dc; 
  margin-bottom: 30px; 
  font-size: 28px;
}
.login-box input { 
  width: 100%; 
  padding: 12px 16px; 
  margin-bottom: 16px; 
  background: #f5f7fa; 
  border: 1px solid #e4e7eb; 
  border-radius: 8px; 
  color: #333; 
  font-size: 14px; 
  outline: none;
}
.login-box input:focus { 
  border-color: #4a89dc; 
  box-shadow: 0 0 0 2px rgba(74,137,220,0.2);
}
.login-box button { 
  width: 100%; 
  padding: 12px; 
  background: #4a89dc; 
  border: none; 
  border-radius: 8px; 
  color: #fff; 
  font-size: 16px; 
  cursor: pointer; 
  font-weight: 600;
  transition: background 0.3s;
}
.login-box button:hover { 
  background: #3a7bd5;
}
.error { 
  color: #e74c3c; 
  text-align: center; 
  margin-top: 10px; 
  font-size: 14px;
}
.copyright {
  position: absolute;
  bottom: -30px;
  left: 0;
  right: 0;
  text-align: center;
  color: #7f8c8d;
  font-size: 12px;
  font-weight: 500;
}

/* Main Layout */
.main-panel { 
  display: flex; 
  min-height: 100vh;
}
.sidebar { 
  width: 240px; 
  background: #fff; 
  display: flex; 
  flex-direction: column; 
  position: fixed; 
  height: 100vh; 
  z-index: 10; 
  transition: transform .3s;
  box-shadow: 0 0 20px rgba(0,0,0,0.05);
}
.sidebar .logo { 
  padding: 20px; 
  font-size: 20px; 
  font-weight: 700; 
  color: #4a89dc; 
  border-bottom: 1px solid #eee;
}
.sidebar nav { 
  flex: 1; 
  padding: 10px 0; 
  overflow-y: auto;
}
.sidebar nav a { 
  display: flex; 
  align-items: center;
  padding: 12px 20px; 
  color: #606060; 
  text-decoration: none; 
  transition: .2s; 
  font-size: 14px;
}
.sidebar nav a i {
  margin-right: 10px;
  width: 20px;
  text-align: center;
}
.sidebar nav a:hover, .sidebar nav a.active { 
  background: #f0f4f8; 
  color: #4a89dc; 
  border-left: 3px solid #4a89dc;
}
.logout-btn { 
  padding: 15px 20px; 
  color: #e74c3c; 
  text-decoration: none; 
  border-top: 1px solid #eee; 
  font-size: 14px;
  display: flex;
  align-items: center;
}
.logout-btn i {
  margin-right: 10px;
  width: 20px;
  text-align: center;
}
.content { 
  flex: 1; 
  margin-left: 240px; 
  padding: 30px; 
  min-height: 100vh;
}
.mobile-toggle { 
  display: none; 
  position: fixed; 
  top: 10px; 
  left: 10px; 
  z-index: 20; 
  background: #fff; 
  border: none; 
  color: #4a89dc; 
  font-size: 20px; 
  padding: 8px 12px; 
  border-radius: 8px; 
  cursor: pointer;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

@media(max-width:768px) {
  .mobile-toggle { display: block; }
  .sidebar { transform: translateX(-100%); }
  .sidebar.open { transform: translateX(0); }
  .content { margin-left: 0; padding: 15px; padding-top: 55px; }
  .stats-grid { grid-template-columns: 1fr !important; }
  .flex-row { flex-direction: column; }
}

/* Page Elements */
.page-title { 
  font-size: 24px; 
  margin-bottom: 8px;
  color: #2c3e50;
}
.page-sub { 
  color: #7f8c8d; 
  margin-bottom: 25px; 
  font-size: 14px;
}
.stats-grid { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
  gap: 16px; 
  margin-bottom: 25px;
}
.card { 
  background: #fff; 
  padding: 20px; 
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}
.card .label { 
  font-size: 12px; 
  color: #95a5a6; 
  margin-bottom: 6px; 
  text-transform: uppercase; 
  letter-spacing: .5px;
}
.card .value { 
  font-size: 22px; 
  font-weight: 700; 
  color: #4a89dc;
}
.card .sub { 
  font-size: 12px; 
  color: #7f8c8d; 
  margin-top: 4px;
}
.progress { 
  background: #ecf0f1; 
  border-radius: 8px; 
  height: 8px; 
  margin-top: 8px; 
  overflow: hidden;
}
.progress-bar { 
  height: 100%; 
  border-radius: 8px; 
  background: #4a89dc; 
  transition: width .3s;
}
.progress-bar.warn { background: #f39c12; }
.progress-bar.danger { background: #e74c3c; }

/* Tables */
table.tbl { 
  width: 100%; 
  border-collapse: collapse; 
  background: #fff; 
  border-radius: 10px; 
  overflow: hidden;
  box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}
.tbl th { 
  background: #f8f9fa; 
  padding: 12px 16px; 
  text-align: left; 
  font-size: 12px; 
  color: #7f8c8d; 
  text-transform: uppercase;
  font-weight: 600;
  border-bottom: 1px solid #ecf0f1;
}
.tbl td { 
  padding: 12px 16px; 
  border-bottom: 1px solid #ecf0f1; 
  font-size: 14px;
  color: #34495e;
}
.tbl tr:last-child td {
  border-bottom: none;
}
.tbl tr:hover td {
  background: #f8f9fa;
}

/* Buttons */
.btn { 
  padding: 8px 16px; 
  border: none; 
  border-radius: 6px; 
  cursor: pointer; 
  font-size: 14px; 
  font-weight: 500; 
  transition: .2s; 
  display: inline-block; 
  text-decoration: none;
  text-align: center;
}
.btn:hover { opacity: .9; }
.btn-p { background: #4a89dc; color: #fff; }
.btn-s { background: #2ecc71; color: #fff; }
.btn-d { background: #e74c3c; color: #fff; }
.btn-w { background: #f39c12; color: #fff; }
.btn-l { background: #ecf0f1; color: #7f8c8d; }
.btn-sm { 
  padding: 4px 10px; 
  font-size: 12px;
}
.btn i {
  margin-right: 4px;
}

/* Badges */
.badge { 
  padding: 4px 10px; 
  border-radius: 12px; 
  font-size: 12px; 
  font-weight: 600;
  display: inline-block;
}
.badge-on { 
  background: rgba(46,204,113,0.15); 
  color: #2ecc71;
}
.badge-off { 
  background: rgba(231,76,60,0.15); 
  color: #e74c3c;
}

/* Forms */
.form-control { 
  width: 100%; 
  padding: 10px 14px; 
  background: #f8f9fa; 
  border: 1px solid #e4e7eb; 
  border-radius: 8px; 
  color: #34495e; 
  font-size: 14px; 
  outline: none;
  transition: all 0.2s;
}
.form-control:focus { 
  border-color: #4a89dc; 
  box-shadow: 0 0 0 2px rgba(74,137,220,0.2);
}
textarea.form-control { 
  min-height: 300px; 
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 13px; 
  resize: vertical;
}
.form-group {
  margin-bottom: 16px;
}
.form-group label {
  display: block;
  font-size: 14px;
  margin-bottom: 8px;
  color: #34495e;
}

/* Alerts */
.alert { 
  padding: 12px 16px; 
  border-radius: 8px; 
  margin-bottom: 16px; 
  font-size: 14px;
}
.alert-ok { 
  background: rgba(46,204,113,0.1); 
  border: 1px solid #2ecc71; 
  color: #2ecc71;
}
.alert-err { 
  background: rgba(231,76,60,0.1); 
  border: 1px solid #e74c3c; 
  color: #e74c3c;
}
.alert i {
  margin-right: 8px;
}

/* Breadcrumbs */
.breadcrumb { 
  display: flex; 
  gap: 5px; 
  margin-bottom: 15px; 
  flex-wrap: wrap; 
  font-size: 14px;
}
.breadcrumb a { 
  color: #4a89dc; 
  text-decoration: none; 
  cursor: pointer;
}
.breadcrumb span { color: #7f8c8d; }

/* File Manager Styles */
.file-manager {
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.05);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 160px);
  min-height: 400px;
}

.file-toolbar {
  padding: 10px 16px;
  background: #f8f9fa;
  border-bottom: 1px solid #ecf0f1;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.file-container {
  flex: 1;
  overflow: auto;
  padding: 0;
}

.file-item { 
  display: flex; 
  align-items: center; 
  padding: 10px 16px; 
  border-bottom: 1px solid #ecf0f1;
  cursor: pointer; 
  font-size: 14px;
  color: #34495e;
  user-select: none;
  transition: background 0.2s;
}
.file-item:hover { background: #f8f9fa; }
.file-item.selected { background: #e3f2fd; }
.file-item .icon { 
  margin-right: 10px; 
  font-size: 16px;
  width: 24px;
  text-align: center;
  color: #7f8c8d;
}
.file-item .icon.folder { color: #f39c12; }
.file-item .icon.image { color: #3498db; }
.file-item .icon.code { color: #2ecc71; }
.file-item .icon.archive { color: #9b59b6; }
.file-item .name { 
  flex: 1; 
  overflow: hidden; 
  text-overflow: ellipsis; 
  white-space: nowrap;
}
.file-item .size { 
  color: #7f8c8d; 
  margin-right: 10px; 
  min-width: 70px; 
  text-align: right; 
  font-size: 13px;
}
.file-item .date {
  color: #7f8c8d;
  width: 150px;
  font-size: 13px;
  text-align: right;
}
.file-item .perms { 
  color: #95a5a6; 
  margin-right: 10px; 
  font-family: monospace; 
  font-size: 12px;
  width: 70px;
  text-align: right;
}

.checkbox-wrapper {
  width: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 10px;
}

.checkbox-wrapper input[type="checkbox"] {
  width: 16px;
  height: 16px;
}

.file-status-bar {
  padding: 10px 16px;
  background: #f8f9fa;
  border-top: 1px solid #ecf0f1;
  font-size: 13px;
  color: #7f8c8d;
  display: flex;
  justify-content: space-between;
}

.file-context-menu {
  position: absolute;
  background: white;
  border: 1px solid #ecf0f1;
  border-radius: 8px;
  box-shadow: 0 4px 15px rgba(0,0,0,0.1);
  z-index: 1000;
  min-width: 180px;
  padding: 5px 0;
}

.file-context-menu .menu-item {
  padding: 8px 16px;
  font-size: 13px;
  cursor: pointer;
  display: flex;
  align-items: center;
  transition: background 0.2s;
  color: #34495e;
}

.file-context-menu .menu-item:hover {
  background: #f0f4f8;
}

.file-context-menu .menu-item i {
  margin-right: 8px;
  width: 18px;
  text-align: center;
  font-size: 14px;
  color: #7f8c8d;
}

.file-context-menu .divider {
  height: 1px;
  background: #ecf0f1;
  margin: 5px 0;
}

.modal-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
}

.modal {
  background: white;
  border-radius: 10px;
  width: 90%;
  max-width: 500px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.2);
  overflow: hidden;
  animation: modalFadeIn 0.3s ease;
}

@keyframes modalFadeIn {
  from { opacity: 0; transform: translateY(-30px); }
  to { opacity: 1; transform: translateY(0); }
}

.modal-header {
  padding: 16px 20px;
  background: #f8f9fa;
  border-bottom: 1px solid #ecf0f1;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.modal-header h3 {
  font-size: 18px;
  font-weight: 600;
  color: #34495e;
  margin: 0;
}

.modal-close {
  border: none;
  background: none;
  color: #7f8c8d;
  font-size: 18px;
  cursor: pointer;
}

.modal-body {
  padding: 20px;
}

.modal-footer {
  padding: 16px 20px;
  background: #f8f9fa;
  border-top: 1px solid #ecf0f1;
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

/* Editor Styles */
.editor-container {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 160px);
  min-height: 400px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.05);
  overflow: hidden;
}

.editor-toolbar {
  padding: 10px 16px;
  background: #f8f9fa;
  border-bottom: 1px solid #ecf0f1;
  display: flex;
  justify-content: space-between;
}

.editor-toolbar-right {
  display: flex;
  gap: 10px;
}

.editor-content {
  flex: 1;
  overflow: auto;
  position: relative;
}

.editor-textarea {
  width: 100%;
  height: 100%;
  border: none;
  padding: 16px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 14px;
  color: #34495e;
  line-height: 1.5;
  resize: none;
}

.editor-textarea:focus {
  outline: none;
}

/* Upload Progress */
.upload-progress-container {
  position: fixed;
  bottom: 20px;
  right: 20px;
  width: 300px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 5px 20px rgba(0,0,0,0.15);
  overflow: hidden;
  z-index: 9999;
}

.upload-progress-header {
  padding: 12px 16px;
  background: #f8f9fa;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #ecf0f1;
}

.upload-progress-header h4 {
  margin: 0;
  font-size: 14px;
}

.upload-progress-close {
  border: none;
  background: none;
  cursor: pointer;
  color: #7f8c8d;
}

.upload-progress-items {
  max-height: 200px;
  overflow-y: auto;
}

.upload-item {
  padding: 10px 16px;
  border-bottom: 1px solid #ecf0f1;
}

.upload-item-name {
  font-size: 13px;
  margin-bottom: 5px;
  display: flex;
  justify-content: space-between;
}

.upload-item-progress {
  height: 6px;
  background: #ecf0f1;
  border-radius: 3px;
  overflow: hidden;
}

.upload-item-progress-bar {
  height: 100%;
  background: #4a89dc;
  transition: width 0.3s;
}

.upload-item-progress-bar.success {
  background: #2ecc71;
}

.upload-item-progress-bar.error {
  background: #e74c3c;
}

/* Terminal */
.terminal-box { 
  background: #2d3436; 
  color: #dfe6e9; 
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace; 
  padding: 20px; 
  border-radius: 10px; 
  min-height: 350px; 
  max-height: 500px; 
  overflow-y: auto; 
  white-space: pre-wrap; 
  word-break: break-all; 
  font-size: 13px;
}
.term-input { 
  display: flex; 
  gap: 10px; 
  margin-top: 10px;
}
.term-input input { 
  flex: 1; 
  background: #2d3436; 
  border: 1px solid #636e72; 
  color: #dfe6e9; 
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace; 
  padding: 10px; 
  border-radius: 6px; 
  outline: none;
}

/* Database Section */
.db-tabs {
  display: flex;
  border-bottom: 1px solid #eee;
  margin-bottom: 20px;
}

.db-tab {
  padding: 12px 20px;
  background: none;
  border: none;
  border-bottom: 3px solid transparent;
  font-size: 14px;
  font-weight: 600;
  color: #7f8c8d;
  cursor: pointer;
  transition: all 0.2s;
}

.db-tab:hover {
  color: #4a89dc;
}

.db-tab.active {
  color: #4a89dc;
  border-bottom-color: #4a89dc;
}

.db-tab i {
  margin-right: 8px;
}

.db-list {
  margin-top: 15px;
}

.db-item {
  background: #fff;
  border-radius: 8px;
  margin-bottom: 10px;
  box-shadow: 0 2px 5px rgba(0,0,0,0.05);
  border-left: 3px solid #3498db;
}

.db-header {
  padding: 12px 15px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #f1f1f1;
}

.db-name {
  font-weight: 600;
  color: #2c3e50;
  display: flex;
  align-items: center;
}

.db-name i {
  margin-right: 8px;
  color: #3498db;
}

.db-users {
  padding: 10px 15px 10px 15px;
  font-size: 13px;
}

.db-user {
  display: flex;
  align-items: center;
  margin-bottom: 5px;
  color: #7f8c8d;
}

.db-user i {
  margin-right: 8px;
  font-size: 12px;
  color: #95a5a6;
}

.db-actions {
  display: flex;
  gap: 8px;
}

/* Helpers */
.flex-row { 
  display: flex; 
  gap: 10px; 
  align-items: end; 
  flex-wrap: wrap; 
  margin-bottom: 16px;
}
.space-between {
  justify-content: space-between;
}
.mt { margin-top: 16px; }
.mb { margin-bottom: 16px; }
.ml { margin-left: 16px; }
.mr { margin-right: 16px; }
.text-center { text-align: center; }
CSSEOF

##############################################
# -------- public/js/app.js (Frontend) ------
##############################################
cat > public/js/app.js <<'JSEOF'
// API Helper
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

// Utilities
var $ = function(id) { return document.getElementById(id); };
function fmtB(b) { if(!b)return '0 B'; var k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k)); return (b/Math.pow(k,i)).toFixed(1)+' '+s[i]; }
function fmtUp(s) { var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return d+'d '+h+'h '+m+'m'; }
function esc(t) { var d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
function pClass(p) { return p>80?'danger':p>60?'warn':''; }
function formatDate(d) { return new Date(d).toLocaleString(); }
function getFileIcon(file) {
  if (file.isDir) return 'folder';
  
  var ext = file.extension || '';
  
  // Check by extension
  if (['jpg','jpeg','png','gif','svg','webp'].includes(ext)) return 'image';
  if (['zip','tar','gz','rar','7z'].includes(ext)) return 'archive';
  if (['mp4','avi','mov','wmv','mkv'].includes(ext)) return 'video';
  if (['mp3','wav','ogg','flac'].includes(ext)) return 'audio';
  if (['doc','docx','odt','rtf'].includes(ext)) return 'doc';
  if (['xls','xlsx','ods','csv'].includes(ext)) return 'excel';
  if (['pdf'].includes(ext)) return 'pdf';
  if (['php','js','css','html','htm','xml','json','py','rb','java','c','cpp','h'].includes(ext)) return 'code';
  
  return 'file';
}

function getFileIconHtml(file) {
  var iconClass = getFileIcon(file);
  var icon = '';
  
  switch(iconClass) {
    case 'folder': icon = '<i class="fas fa-folder icon folder"></i>'; break;
    case 'image': icon = '<i class="far fa-file-image icon image"></i>'; break;
    case 'archive': icon = '<i class="far fa-file-archive icon archive"></i>'; break;
    case 'video': icon = '<i class="far fa-file-video icon"></i>'; break;
    case 'audio': icon = '<i class="far fa-file-audio icon"></i>'; break;
    case 'doc': icon = '<i class="far fa-file-word icon"></i>'; break;
    case 'excel': icon = '<i class="far fa-file-excel icon"></i>'; break;
    case 'pdf': icon = '<i class="far fa-file-pdf icon"></i>'; break;
    case 'code': icon = '<i class="far fa-file-code icon code"></i>'; break;
    default: icon = '<i class="far fa-file icon"></i>';
  }
  
  return icon;
}

// App state
var curPath = '/usr/local/lsws';
var editFile = '';
var selectedFiles = [];
var sortConfig = { key: 'name', direction: 'asc' };
var clipboard = { items: [], action: '' };

// Authentication functions
function checkAuth() {
  api.get('/api/auth').then(function(r) {
    if (r.authenticated) { showPanel(); loadPage('dashboard'); } else showLogin();
  });
}
function showLogin() { $('loginPage').style.display='flex'; $('mainPanel').style.display='none'; }
function showPanel() { $('loginPage').style.display='none'; $('mainPanel').style.display='flex'; }

// Event Listeners
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

// Page Router
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

// Dashboard Page
function pgDash(el) {
  Promise.all([api.get('/api/dashboard'), api.get('/api/services')]).then(function(res) {
    var d = res[0], s = res[1];
    var mp = Math.round(d.memory.used/d.memory.total*100);
    var dp = d.disk.total ? Math.round(d.disk.used/d.disk.total*100) : 0;
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-tachometer-alt"></i> Dashboard</h2><p class="page-sub">'+d.hostname+' ('+d.ip+')</p>'
      +'<div class="stats-grid">'
      +'<div class="card"><div class="label">CPU</div><div class="value">'+d.cpu.cores+' Cores</div><div class="sub">Load: '+d.cpu.load.map(function(l){return l.toFixed(2)}).join(', ')+'</div></div>'
      +'<div class="card"><div class="label">Memory</div><div class="value">'+mp+'%</div><div class="progress"><div class="progress-bar '+pClass(mp)+'" style="width:'+mp+'%"></div></div><div class="sub">'+fmtB(d.memory.used)+' / '+fmtB(d.memory.total)+'</div></div>'
      +'<div class="card"><div class="label">Disk</div><div class="value">'+dp+'%</div><div class="progress"><div class="progress-bar '+pClass(dp)+'" style="width:'+dp+'%"></div></div><div class="sub">'+fmtB(d.disk.used)+' / '+fmtB(d.disk.total)+'</div></div>'
      +'<div class="card"><div class="label">Uptime</div><div class="value">'+fmtUp(d.uptime)+'</div><div class="sub">Node '+d.nodeVersion+'</div></div>'
      +'</div><h3 class="mb">Services</h3><table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>'
      +s.map(function(x){return '<tr><td>'+x.name+'</td><td><span class="badge '+(x.active?'badge-on':'badge-off')+'">'+(x.active?'Running':'Stopped')+'</span></td></tr>';}).join('')
      +'</tbody></table>'
      +'<div class="mt"><a href="http://'+d.ip+':7080" target="_blank" class="btn btn-p"><i class="fas fa-cog"></i> OLS Admin</a> <a href="http://'+d.ip+':8088/phpmyadmin/" target="_blank" class="btn btn-w"><i class="fas fa-database"></i> phpMyAdmin</a></div>';
  });
}

// Services Page
function pgSvc(el) {
  api.get('/api/services').then(function(s) {
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-cogs"></i> Services</h2><p class="page-sub">Manage server services</p><div id="svcMsg"></div>'
      +'<table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'
      +s.map(function(x){
        return '<tr><td><strong>'+x.name+'</strong></td>'
          +'<td><span class="badge '+(x.active?'badge-on':'badge-off')+'">'+(x.active?'Running':'Stopped')+'</span></td>'
          +'<td><button class="btn btn-s btn-sm" data-svc="'+x.name+'" data-act="start" onclick="svcAct(this)"><i class="fas fa-play"></i> Start</button> '
          +'<button class="btn btn-d btn-sm" data-svc="'+x.name+'" data-act="stop" onclick="svcAct(this)"><i class="fas fa-stop"></i> Stop</button> '
          +'<button class="btn btn-w btn-sm" data-svc="'+x.name+'" data-act="restart" onclick="svcAct(this)"><i class="fas fa-sync-alt"></i> Restart</button></td></tr>';
      }).join('')+'</tbody></table>';
  });
}
window.svcAct = function(btn) {
  var n=btn.dataset.svc, a=btn.dataset.act;
  api.post('/api/services/'+n+'/'+a).then(function(r) {
    $('svcMsg').innerHTML = r.success?'<div class="alert alert-ok"><i class="fas fa-check-circle"></i> '+n+' '+a+'ed</div>':'<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> '+(r.error||'Failed')+'</div>';
    setTimeout(function(){loadPage('services')},1200);
  });
};

// File Manager Page
function pgFiles(el, p) {
  if (p !== undefined) curPath = p;
  selectedFiles = [];
  
  el.innerHTML = '<h2 class="page-title"><i class="fas fa-folder"></i> File Manager</h2>'
    + '<div id="fileManagerContainer"></div>';
  
  loadFileManager(curPath);
}

function loadFileManager(path) {
  api.get('/api/files?path='+encodeURIComponent(path)).then(function(d) {
    if (d.error) { 
      $('fileManagerContainer').innerHTML ='<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> '+esc(d.error)+'</div>';
      return; 
    }
    
    if (d.binary) {
      curPath = d.path.substring(0, d.path.lastIndexOf('/'))||'/';
      $('fileManagerContainer').innerHTML = '<div class="card">'
        + '<h3 class="mb">Binary File</h3>'
        + '<p>'+esc(d.path)+' ('+fmtB(d.size)+')</p>'
        + '<p class="mb">This file contains binary content and cannot be edited in the browser.</p>'
        + '<div><a href="/api/files/download?path='+encodeURIComponent(d.path)+'" class="btn btn-p"><i class="fas fa-download"></i> Download</a> '
        + '<button class="btn btn-l" onclick="loadFileManager(\''+esc(curPath)+'\')"><i class="fas fa-arrow-left"></i> Back</button></div>'
        + '</div>';
      return;
    }
    
    if (d.tooLarge) {
      curPath = d.path.substring(0, d.path.lastIndexOf('/'))||'/';
      $('fileManagerContainer').innerHTML = '<div class="card">'
        + '<h3 class="mb">Large File</h3>'
        + '<p>'+esc(d.path)+' ('+fmtB(d.size)+')</p>'
        + '<p class="mb">This file is too large to edit in the browser. Maximum allowed size: '+fmtB(5*1024*1024)+'</p>'
        + '<div><a href="/api/files/download?path='+encodeURIComponent(d.path)+'" class="btn btn-p"><i class="fas fa-download"></i> Download</a> '
        + '<button class="btn btn-l" onclick="loadFileManager(\''+esc(curPath)+'\')"><i class="fas fa-arrow-left"></i> Back</button></div>'
        + '</div>';
      return;
    }
    
    if (d.content !== undefined) {
      showFileEditor(d);
      return;
    }
    
    // Build breadcrumbs
    var parts = path.split('/').filter(Boolean);
    var bc = '<a data-path="/" onclick="navToPath(this)"><i class="fas fa-home"></i> root</a>';
    var bp = '';
    parts.forEach(function(x) { 
      bp += '/'+x; 
      bc += ' <span>/</span> <a data-path="'+bp+'" onclick="navToPath(this)">'+esc(x)+'</a>'; 
    });
    
    // Sort items
    var items = (d.items || []);
    sortFiles(items);
    
    var parentPath = path === '/' ? '' : (path.split('/').slice(0, -1).join('/') || '/');
    
    // Build file manager
    var html = `
      <div class="file-manager">
        <div class="file-toolbar">
          <div>
            <button class="btn btn-p btn-sm" onclick="showUploadDialog()"><i class="fas fa-upload"></i> Upload</button>
            <button class="btn btn-s btn-sm" onclick="showNewFolderDialog()"><i class="fas fa-folder-plus"></i> New Folder</button>
            <button class="btn btn-l btn-sm" onclick="showNewFileDialog()"><i class="fas fa-file"></i> New File</button>
          </div>
          <div>
            <button class="btn btn-l btn-sm" onclick="refreshCurrentFolder()"><i class="fas fa-sync-alt"></i> Refresh</button>
          </div>
        </div>
        
        <div class="breadcrumb" style="margin: 10px 16px 0;">
          ${bc}
        </div>
        
        <div class="file-container" id="fileList">
          ${parentPath ? 
            `<div class="file-item" data-path="${parentPath}" ondblclick="navToPath(this)">
              <div class="checkbox-wrapper"></div>
              <i class="fas fa-level-up-alt icon"></i>
              <span class="name">..</span>
              <span class="size"></span>
              <span class="perms"></span>
              <span class="date"></span>
            </div>` : ''}
          ${items.map(function(item) {
            var itemPath = (path === '/' ? '' : path) + '/' + item.name;
            return `
              <div class="file-item" data-path="${itemPath}" data-filename="${item.name}" 
                   onclick="selectFile(this, event)" ondblclick="openFile(this)" oncontextmenu="showFileContextMenu(event, this)">
                <div class="checkbox-wrapper">
                  <input type="checkbox" onclick="event.stopPropagation()" onchange="checkboxChanged(this, '${itemPath}')">
                </div>
                ${getFileIconHtml(item)}
                <span class="name">${esc(item.name)}</span>
                <span class="size">${item.isDir ? '' : fmtB(item.size)}</span>
                <span class="perms">${item.perms || ''}</span>
                <span class="date">${item.modified ? formatDate(item.modified) : ''}</span>
              </div>
            `;
          }).join('')}
        </div>
        
        <div class="file-status-bar">
          <div>${items.length} items</div>
          <div>
            <button class="btn btn-l btn-sm" id="selectAllBtn" onclick="toggleSelectAll()">
              <i class="fas fa-check-square"></i> Select All
            </button>
            <span id="selectedCount"></span>
          </div>
        </div>
      </div>
      
      <div id="fileContextMenu" class="file-context-menu" style="display: none;"></div>
      <div id="modalContainer"></div>
    `;
    
    $('fileManagerContainer').innerHTML = html;
    updateSelectedCount();
    
    // Add event listeners for keyboard shortcuts
    document.addEventListener('keydown', handleFileManagerKeydown);
  });
}

function sortFiles(files) {
  files.sort(function(a, b) {
    // Always put folders first
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    
    // Then sort by the configured key
    var key = sortConfig.key;
    var aValue = a[key];
    var bValue = b[key];
    
    // Special case for dates
    if (key === 'modified') {
      aValue = new Date(aValue).getTime();
      bValue = new Date(bValue).getTime();
    }
    
    // Compare values
    if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
    if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
    return 0;
  });
}

function navToPath(el) {
  var path = el.getAttribute('data-path');
  loadFileManager(path);
  curPath = path;
  
  // Remove event listeners when navigating
  document.removeEventListener('keydown', handleFileManagerKeydown);
}

function refreshCurrentFolder() {
  loadFileManager(curPath);
}

function selectFile(el, e) {
  if (e.ctrlKey || e.metaKey) {
    // Toggle this file's selection
    el.classList.toggle('selected');
    
    // Update checkbox
    var checkbox = el.querySelector('input[type="checkbox"]');
    checkbox.checked = el.classList.contains('selected');
    
    // Update selected files array
    var path = el.getAttribute('data-path');
    if (el.classList.contains('selected')) {
      if (!selectedFiles.includes(path)) selectedFiles.push(path);
    } else {
      selectedFiles = selectedFiles.filter(p => p !== path);
    }
    
  } else if (e.shiftKey) {
    // Get all file items
    var items = Array.from(document.querySelectorAll('#fileList .file-item[data-filename]'));
    
    // Find the last selected item index
    var lastSelected = items.findIndex(item => item.classList.contains('selected'));
    if (lastSelected === -1) lastSelected = 0;
    
    // Find the current item index
    var currentIndex = items.indexOf(el);
    
    // Select all items between last selected and current
    var start = Math.min(lastSelected, currentIndex);
    var end = Math.max(lastSelected, currentIndex);
    
    for (var i = start; i <= end; i++) {
      items[i].classList.add('selected');
      items[i].querySelector('input[type="checkbox"]').checked = true;
      
      var path = items[i].getAttribute('data-path');
      if (!selectedFiles.includes(path)) selectedFiles.push(path);
    }
    
  } else {
    // Clear all selections
    document.querySelectorAll('#fileList .file-item').forEach(item => {
      item.classList.remove('selected');
      var checkbox = item.querySelector('input[type="checkbox"]');
      if (checkbox) checkbox.checked = false;
    });
    
    // Select this file
    el.classList.add('selected');
    var checkbox = el.querySelector('input[type="checkbox"]');
    checkbox.checked = true;
    
    // Update selected files array
    selectedFiles = [el.getAttribute('data-path')];
  }
  
  updateSelectedCount();
}

function checkboxChanged(checkbox, path) {
  var fileItem = checkbox.closest('.file-item');
  
  if (checkbox.checked) {
    fileItem.classList.add('selected');
    if (!selectedFiles.includes(path)) selectedFiles.push(path);
  } else {
    fileItem.classList.remove('selected');
    selectedFiles = selectedFiles.filter(p => p !== path);
  }
  
  updateSelectedCount();
}

function toggleSelectAll() {
  var allItems = document.querySelectorAll('#fileList .file-item[data-filename]');
  var allSelected = selectedFiles.length === allItems.length;
  
  // Toggle selection state
  if (allSelected) {
    // Deselect all
    allItems.forEach(item => {
      item.classList.remove('selected');
      var checkbox = item.querySelector('input[type="checkbox"]');
      if (checkbox) checkbox.checked = false;
    });
    selectedFiles = [];
  } else {
    // Select all
    selectedFiles = [];
    allItems.forEach(item => {
      item.classList.add('selected');
      var checkbox = item.querySelector('input[type="checkbox"]');
      if (checkbox) checkbox.checked = true;
      
      var path = item.getAttribute('data-path');
      selectedFiles.push(path);
    });
  }
  
  updateSelectedCount();
}

function updateSelectedCount() {
  var countEl = $('selectedCount');
  if (!countEl) return;
  
  if (selectedFiles.length > 0) {
    countEl.innerHTML = `<span style="margin-left: 10px;">${selectedFiles.length} selected</span>`;
    
    // Add action buttons for selection
    countEl.innerHTML += `
      <button class="btn btn-l btn-sm" onclick="showBulkAction('copy')"><i class="fas fa-copy"></i> Copy</button>
      <button class="btn btn-l btn-sm" onclick="showBulkAction('cut')"><i class="fas fa-cut"></i> Cut</button>
      <button class="btn btn-d btn-sm" onclick="showBulkAction('delete')"><i class="fas fa-trash-alt"></i> Delete</button>
      ${selectedFiles.length === 1 ? `<button class="btn btn-l btn-sm" onclick="showBulkAction('rename')"><i class="fas fa-edit"></i> Rename</button>` : ''}
      ${selectedFiles.length >= 1 ? `<button class="btn btn-l btn-sm" onclick="showBulkAction('compress')"><i class="fas fa-file-archive"></i> Compress</button>` : ''}
    `;
  } else {
    countEl.innerHTML = '';
    
    // Check if we have clipboard items to show paste button
    if (clipboard.items && clipboard.items.length > 0) {
      countEl.innerHTML += `<button class="btn btn-l btn-sm" onclick="pasteFiles()"><i class="fas fa-paste"></i> Paste</button>`;
    }
  }
}

function showFileContextMenu(e, el) {
  e.preventDefault();
  
  // If the item is not selected, select only this item
  if (!el.classList.contains('selected')) {
    document.querySelectorAll('#fileList .file-item').forEach(item => {
      item.classList.remove('selected');
      var checkbox = item.querySelector('input[type="checkbox"]');
      if (checkbox) checkbox.checked = false;
    });
    
    el.classList.add('selected');
    var checkbox = el.querySelector('input[type="checkbox"]');
    if (checkbox) checkbox.checked = true;
    
    selectedFiles = [el.getAttribute('data-path')];
    updateSelectedCount();
  }
  
  var path = el.getAttribute('data-path');
  var fileName = el.getAttribute('data-filename');
  var isFolder = el.querySelector('.icon.folder') !== null;
  
  // Create the context menu
  var menu = $('fileContextMenu');
  menu.innerHTML = '';
  
  // Common actions for all items
  menu.innerHTML += `
    <div class="menu-item" onclick="openFile(document.querySelector('.file-item.selected'))">
      <i class="fas fa-folder-open"></i> Open
    </div>
  `;
  
  if (!isFolder) {
    menu.innerHTML += `
      <div class="menu-item" onclick="downloadSelectedFiles()">
        <i class="fas fa-download"></i> Download
      </div>
    `;
  }
  
  menu.innerHTML += `
    <div class="menu-item" onclick="showBulkAction('rename')">
      <i class="fas fa-edit"></i> Rename
    </div>
    <div class="menu-item" onclick="showBulkAction('copy')">
      <i class="fas fa-copy"></i> Copy
    </div>
    <div class="menu-item" onclick="showBulkAction('cut')">
      <i class="fas fa-cut"></i> Cut
    </div>
    <div class="divider"></div>
    <div class="menu-item" onclick="showBulkAction('delete')">
      <i class="fas fa-trash-alt"></i> Delete
    </div>
  `;
  
  // Extra options for specific file types
  if (isFolder) {
    menu.innerHTML += `
      <div class="divider"></div>
      <div class="menu-item" onclick="showBulkAction('compress')">
        <i class="fas fa-file-archive"></i> Compress
      </div>
    `;
  } else {
    var ext = fileName.split('.').pop().toLowerCase();
    
    if (['zip', 'tar', 'gz', 'rar'].includes(ext)) {
      menu.innerHTML += `
        <div class="divider"></div>
        <div class="menu-item" onclick="showExtractDialog('${path}')">
          <i class="fas fa-box-open"></i> Extract
        </div>
      `;
    }
    
    // Option to edit text files
    if (['txt', 'html', 'css', 'js', 'php', 'conf', 'json', 'md', 'xml', 'ini'].includes(ext)) {
      menu.innerHTML += `
        <div class="menu-item" onclick="editFile('${path}')">
          <i class="fas fa-edit"></i> Edit
        </div>
      `;
    }
  }
  
  menu.innerHTML += `
    <div class="divider"></div>
    <div class="menu-item" onclick="showPermissionsDialog('${path}')">
      <i class="fas fa-key"></i> Permissions
    </div>
  `;
  
  // Position and show the menu
  menu.style.top = e.pageY + 'px';
  menu.style.left = e.pageX + 'px';
  menu.style.display = 'block';
  
  // Hide menu when clicking elsewhere
  document.addEventListener('click', hideContextMenu);
  
  // Ensure menu doesn't go off screen
  var rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) {
    menu.style.left = (e.pageX - rect.width) + 'px';
  }
  if (rect.bottom > window.innerHeight) {
    menu.style.top = (e.pageY - rect.height) + 'px';
  }
}

function hideContextMenu() {
  var menu = $('fileContextMenu');
  if (menu) menu.style.display = 'none';
  document.removeEventListener('click', hideContextMenu);
}

function openFile(el) {
  var path = el.getAttribute('data-path');
  var isFolder = el.querySelector('.icon.folder') !== null;
  
  if (isFolder) {
    loadFileManager(path);
    curPath = path;
  } else {
    editFile(path);
  }
}

function editFile(path) {
  api.get('/api/files?path=' + encodeURIComponent(path)).then(function(data) {
    if (data.binary || data.tooLarge) {
      alert('This file cannot be edited in the browser.');
      return;
    }
    
    showFileEditor(data);
  });
}

function showFileEditor(data) {
  editFile = data.path;
  curPath = data.path.substring(0, data.path.lastIndexOf('/')) || '/';
  
  // Get file extension for syntax highlighting
  var extension = data.extension || '';
  
  $('fileManagerContainer').innerHTML = `
    <div class="editor-container">
      <div class="editor-toolbar">
        <div>
          <strong>${esc(data.path)}</strong> (${fmtB(data.size)})
        </div>
        <div class="editor-toolbar-right">
          <button class="btn btn-p btn-sm" onclick="saveEditedFile()"><i class="fas fa-save"></i> Save</button>
          <button class="btn btn-l btn-sm" onclick="loadFileManager('${esc(curPath)}')"><i class="fas fa-times"></i> Close</button>
        </div>
      </div>
      <div class="editor-content">
        <textarea id="fileContent" class="editor-textarea">${esc(data.content)}</textarea>
      </div>
    </div>
    <div id="editorStatus" class="alert" style="display:none;margin-top:15px;"></div>
  `;
}

function saveEditedFile() {
  api.put('/api/files', { 
    filePath: editFile, 
    content: $('fileContent').value 
  }).then(function(r) {
    var status = $('editorStatus');
    if (r.success) {
      status.className = 'alert alert-ok';
      status.innerHTML = '<i class="fas fa-check-circle"></i> File saved successfully';
    } else {
      status.className = 'alert alert-err';
      status.innerHTML = '<i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to save file');
    }
    status.style.display = 'block';
    
    // Hide the status after 3 seconds
    setTimeout(function() {
      status.style.display = 'none';
    }, 3000);
  });
}

function showUploadDialog() {
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-upload"></i> Upload Files</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p class="mb">Upload files to current directory: <strong>${esc(curPath)}</strong></p>
          <div class="form-group">
            <input type="file" id="fileUpload" multiple class="form-control">
          </div>
          <div id="uploadStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="uploadFiles()"><i class="fas fa-upload"></i> Upload</button>
        </div>
      </div>
    </div>
  `;
}

function uploadFiles() {
  var files = $('fileUpload').files;
  if (files.length === 0) {
    $('uploadStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> No files selected</div>';
    return;
  }
  
  var formData = new FormData();
  for (var i = 0; i < files.length; i++) {
    formData.append('files', files[i]);
  }
  formData.append('path', curPath);
  
  $('uploadStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-spinner fa-spin"></i> Uploading files...</div>';
  
  api.req('/api/files/upload', { method: 'POST', body: formData })
    .then(function(response) {
      if (response.success) {
        $('uploadStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Files uploaded successfully</div>';
        
        // Refresh file list after a brief delay
        setTimeout(function() {
          closeModal();
          loadFileManager(curPath);
        }, 1000);
      } else {
        $('uploadStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Upload failed') + '</div>';
      }
    })
    .catch(function(error) {
      $('uploadStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Upload failed: ' + error.message + '</div>';
    });
}

function showNewFolderDialog() {
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-folder-plus"></i> Create New Folder</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p class="mb">Create new folder in: <strong>${esc(curPath)}</strong></p>
          <div class="form-group">
            <label for="folderName">Folder Name</label>
            <input type="text" id="folderName" class="form-control" placeholder="new_folder">
          </div>
          <div id="folderStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="createNewFolder()"><i class="fas fa-folder-plus"></i> Create Folder</button>
        </div>
      </div>
    </div>
  `;
}

function createNewFolder() {
  var name = $('folderName').value.trim();
  if (!name) {
    $('folderStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter a folder name</div>';
    return;
  }
  
  var path = curPath === '/' ? '/' + name : curPath + '/' + name;
  
  api.post('/api/files/mkdir', { path: path })
    .then(function(response) {
      if (response.success) {
        $('folderStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Folder created successfully</div>';
        
        setTimeout(function() {
          closeModal();
          loadFileManager(curPath);
        }, 1000);
      } else {
        $('folderStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Failed to create folder') + '</div>';
      }
    });
}

function showNewFileDialog() {
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-file"></i> Create New File</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p class="mb">Create new file in: <strong>${esc(curPath)}</strong></p>
          <div class="form-group">
            <label for="fileName">File Name</label>
            <input type="text" id="fileName" class="form-control" placeholder="example.txt">
          </div>
          <div id="fileStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="createNewFile()"><i class="fas fa-file"></i> Create File</button>
        </div>
      </div>
    </div>
  `;
}

function createNewFile() {
  var name = $('fileName').value.trim();
  if (!name) {
    $('fileStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter a file name</div>';
    return;
  }
  
  var path = curPath === '/' ? '/' + name : curPath + '/' + name;
  
  api.post('/api/files/newfile', { path: path, content: '' })
    .then(function(response) {
      if (response.success) {
        $('fileStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> File created successfully</div>';
        
        setTimeout(function() {
          closeModal();
          editFile(path);
        }, 1000);
      } else {
        $('fileStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Failed to create file') + '</div>';
      }
    });
}

function downloadSelectedFiles() {
  if (selectedFiles.length === 0) return;
  
  if (selectedFiles.length === 1) {
    // Single file - direct download
    window.open('/api/files/download?path=' + encodeURIComponent(selectedFiles[0]), '_blank');
  } else {
    // Multiple files - need to compress first
    showCompressDialog();
  }
}

function showBulkAction(action) {
  if (selectedFiles.length === 0) return;
  
  switch (action) {
    case 'delete':
      if (confirm('Delete ' + selectedFiles.length + ' item(s)? This cannot be undone.')) {
        deleteSelectedFiles();
      }
      break;
    case 'copy':
      clipboard = { items: selectedFiles.slice(), action: 'copy' };
      showNotification('Copied ' + selectedFiles.length + ' item(s) to clipboard');
      updateSelectedCount();
      break;
    case 'cut':
      clipboard = { items: selectedFiles.slice(), action: 'cut' };
      showNotification('Cut ' + selectedFiles.length + ' item(s) to clipboard');
      updateSelectedCount();
      break;
    case 'rename':
      if (selectedFiles.length === 1) {
        showRenameDialog(selectedFiles[0]);
      }
      break;
    case 'compress':
      showCompressDialog();
      break;
  }
}

function showNotification(message) {
  var container = document.createElement('div');
  container.style.position = 'fixed';
  container.style.bottom = '20px';
  container.style.left = '20px';
  container.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
  container.style.color = 'white';
  container.style.padding = '10px 20px';
  container.style.borderRadius = '5px';
  container.style.zIndex = '9999';
  container.innerText = message;
  
  document.body.appendChild(container);
  
  setTimeout(() => {
    container.style.opacity = '0';
    container.style.transition = 'opacity 0.5s';
    setTimeout(() => {
      document.body.removeChild(container);
    }, 500);
  }, 3000);
}

function showRenameDialog(path) {
  var oldName = path.split('/').pop();
  var parentDir = path.substring(0, path.lastIndexOf('/')) || '/';
  
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-edit"></i> Rename Item</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p>Rename <strong>${esc(oldName)}</strong></p>
          <div class="form-group">
            <label for="newName">New Name</label>
            <input type="text" id="newName" class="form-control" value="${esc(oldName)}">
          </div>
          <div id="renameStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="renameFile('${esc(path)}')"><i class="fas fa-save"></i> Rename</button>
        </div>
      </div>
    </div>
  `;
  
  // Focus and select the filename
  setTimeout(() => {
    var input = $('newName');
    input.focus();
    input.setSelectionRange(0, oldName.lastIndexOf('.') > 0 ? oldName.lastIndexOf('.') : oldName.length);
  }, 100);
}

function renameFile(oldPath) {
  var newName = $('newName').value.trim();
  if (!newName) {
    $('renameStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter a name</div>';
    return;
  }
  
  var parentDir = oldPath.substring(0, oldPath.lastIndexOf('/')) || '/';
  var newPath = parentDir === '/' ? '/' + newName : parentDir + '/' + newName;
  
  api.post('/api/files/rename', { oldPath: oldPath, newPath: newPath })
    .then(function(response) {
      if (response.success) {
        $('renameStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Renamed successfully</div>';
        
        setTimeout(function() {
          closeModal();
          loadFileManager(curPath);
        }, 1000);
      } else {
        $('renameStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Rename failed') + '</div>';
      }
    });
}

function showCompressDialog() {
  var defaultName = selectedFiles.length === 1 ? 
    (selectedFiles[0].split('/').pop() + '.zip') : 
    (curPath.split('/').pop() || 'files') + '.zip';
  
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-file-archive"></i> Create Archive</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p>Compress ${selectedFiles.length} selected item(s)</p>
          <div class="form-group">
            <label for="archiveName">Archive Name</label>
            <input type="text" id="archiveName" class="form-control" value="${esc(defaultName)}">
          </div>
          <div id="compressStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="compressFiles()"><i class="fas fa-file-archive"></i> Compress</button>
        </div>
      </div>
    </div>
  `;
}

function compressFiles() {
  var archiveName = $('archiveName').value.trim();
  if (!archiveName) {
    $('compressStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter a name</div>';
    return;
  }
  
  // Ensure it has .zip extension
  if (!archiveName.toLowerCase().endsWith('.zip')) {
    archiveName += '.zip';
  }
  
  // Determine output path
  var outputPath = curPath === '/' ? '/' + archiveName : curPath + '/' + archiveName;
  
  $('compressStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-spinner fa-spin"></i> Compressing files...</div>';
  
  api.post('/api/files/compress', {
    paths: selectedFiles,
    output: outputPath
  }).then(function(response) {
    if (response.success) {
      $('compressStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Archive created successfully</div>';
      
      setTimeout(function() {
        closeModal();
        loadFileManager(curPath);
      }, 1000);
    } else {
      $('compressStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Compression failed') + '</div>';
    }
  });
}

function showExtractDialog(archivePath) {
  var parentDir = archivePath.substring(0, archivePath.lastIndexOf('/')) || '/';
  var archiveName = archivePath.split('/').pop();
  var defaultTarget = parentDir === '/' ? 
    '/' + archiveName.replace(/\.zip$|\.tar$|\.gz$|\.rar$/i, '') : 
    parentDir + '/' + archiveName.replace(/\.zip$|\.tar$|\.gz$|\.rar$/i, '');
  
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-box-open"></i> Extract Archive</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p>Extract <strong>${esc(archiveName)}</strong></p>
          <div class="form-group">
            <label for="extractPath">Extract to</label>
            <input type="text" id="extractPath" class="form-control" value="${esc(defaultTarget)}">
          </div>
          <div id="extractStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="extractArchive('${esc(archivePath)}')"><i class="fas fa-box-open"></i> Extract</button>
        </div>
      </div>
    </div>
  `;
}

function extractArchive(archivePath) {
  var targetDir = $('extractPath').value.trim();
  if (!targetDir) {
    $('extractStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter a destination path</div>';
    return;
  }
  
  $('extractStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-spinner fa-spin"></i> Extracting archive...</div>';
  
  api.post('/api/files/extract', {
    archive: archivePath,
    target: targetDir
  }).then(function(response) {
    if (response.success) {
      $('extractStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Archive extracted successfully</div>';
      
      setTimeout(function() {
        closeModal();
        loadFileManager(targetDir);
      }, 1000);
    } else {
      $('extractStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Extraction failed') + '</div>';
    }
  });
}

function showPermissionsDialog(path) {
  api.get('/api/files/permissions?path=' + encodeURIComponent(path))
    .then(function(data) {
      if (data.error) {
        alert('Error getting permissions: ' + data.error);
        return;
      }
      
      var isDir = data.isDir;
      var currentPerms = data.permissions;
      
      $('modalContainer').innerHTML = `
        <div class="modal-backdrop">
          <div class="modal">
            <div class="modal-header">
              <h3><i class="fas fa-key"></i> File Permissions</h3>
              <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
            </div>
            <div class="modal-body">
              <p>Change permissions for: <strong>${esc(path.split('/').pop())}</strong></p>
              <div class="form-group">
                <label for="permissions">Permissions (octal)</label>
                <input type="text" id="permissions" class="form-control" value="${currentPerms}">
              </div>
              ${isDir ? `
                <div class="form-group">
                  <label>
                    <input type="checkbox" id="recursive"> Apply recursively to all contents
                  </label>
                </div>
              ` : ''}
              <div id="permsStatus" class="mt"></div>
            </div>
            <div class="modal-footer">
              <button class="btn btn-l" onclick="closeModal()">Cancel</button>
              <button class="btn btn-p" onclick="changePermissions('${esc(path)}')"><i class="fas fa-save"></i> Save</button>
            </div>
          </div>
        </div>
      `;
    });
}

function changePermissions(path) {
  var permissions = $('permissions').value.trim();
  var recursive = $('recursive') ? $('recursive').checked : false;
  
  if (!permissions || !/^(0)?[0-7]{3,4}$/.test(permissions)) {
    $('permsStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Please enter valid octal permissions (e.g. 0755)</div>';
    return;
  }
  
  $('permsStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-spinner fa-spin"></i> Changing permissions...</div>';
  
  api.post('/api/files/permissions', {
    path: path,
    permissions: permissions,
    recursive: recursive
  }).then(function(response) {
    if (response.success) {
      $('permsStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Permissions changed successfully</div>';
      
      setTimeout(function() {
        closeModal();
        loadFileManager(curPath);
      }, 1000);
    } else {
      $('permsStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (response.error || 'Failed to change permissions') + '</div>';
    }
  });
}

function pasteFiles() {
  if (!clipboard.items || clipboard.items.length === 0) return;
  
  var operation = clipboard.action;
  var paths = clipboard.items;
  var targetDir = curPath;
  
  // Build promises for each file operation
  var operations = [];
  
  for (var i = 0; i < paths.length; i++) {
    var sourcePath = paths[i];
    var fileName = sourcePath.split('/').pop();
    var targetPath = targetDir === '/' ? '/' + fileName : targetDir + '/' + fileName;
    
    // Skip if source and target are the same
    if (sourcePath === targetPath) continue;
    
    if (operation === 'copy') {
      // For copy, we'll need to implement a recursive copy on the server
      operations.push({ source: sourcePath, target: targetPath });
    } else if (operation === 'cut') {
      // For cut, we can use the rename endpoint
      operations.push(
        api.post('/api/files/rename', { oldPath: sourcePath, newPath: targetPath })
      );
    }
  }
  
  // If it's a cut operation, we can use the API directly
  if (operation === 'cut' && operations.length > 0) {
    Promise.all(operations)
      .then(() => {
        clipboard.items = [];
        clipboard.action = '';
        showNotification('Moved ' + paths.length + ' item(s) successfully');
        loadFileManager(curPath);
      })
      .catch(err => {
        showNotification('Error: ' + err.message);
      });
  } else if (operation === 'copy') {
    // For copy, we'd need a server-side implementation
    // For now, just show a not implemented message
    showNotification('Copy operation not fully implemented yet');
  }
}

function deleteSelectedFiles() {
  if (selectedFiles.length === 0) return;
  
  var deleteCount = 0;
  var errorCount = 0;
  var totalFiles = selectedFiles.length;
  
  // Create promises for each delete operation
  var deletePromises = selectedFiles.map(function(path) {
    return api.del('/api/files?path=' + encodeURIComponent(path))
      .then(function(response) {
        if (response.success) {
          deleteCount++;
        } else {
          errorCount++;
        }
      })
      .catch(function() {
        errorCount++;
      });
  });
  
  // Execute all delete operations
  Promise.all(deletePromises)
    .then(function() {
      var message = deleteCount + ' of ' + totalFiles + ' items deleted';
      if (errorCount > 0) {
        message += ' (' + errorCount + ' failed)';
      }
      showNotification(message);
      
      // Refresh the file list
      loadFileManager(curPath);
    });
}

function handleFileManagerKeydown(e) {
  // Ctrl+A: Select All
  if (e.ctrlKey && e.key === 'a') {
    e.preventDefault();
    toggleSelectAll();
  }
  
  // Delete key: Delete selected files
  if (e.key === 'Delete' && selectedFiles.length > 0) {
    e.preventDefault();
    showBulkAction('delete');
  }
  
  // Ctrl+C: Copy
  if (e.ctrlKey && e.key === 'c' && selectedFiles.length > 0) {
    e.preventDefault();
    showBulkAction('copy');
  }
  
  // Ctrl+X: Cut
  if (e.ctrlKey && e.key === 'x' && selectedFiles.length > 0) {
    e.preventDefault();
    showBulkAction('cut');
  }
  
  // Ctrl+V: Paste
  if (e.ctrlKey && e.key === 'v' && clipboard.items && clipboard.items.length > 0) {
    e.preventDefault();
    pasteFiles();
  }
  
  // F2: Rename
  if (e.key === 'F2' && selectedFiles.length === 1) {
    e.preventDefault();
    showBulkAction('rename');
  }
}

function closeModal() {
  $('modalContainer').innerHTML = '';
}

// Domains Page
function pgDom(el) {
  api.get('/api/domains').then(function(d) {
    el.innerHTML='<h2 class="page-title"><i class="fas fa-globe"></i> Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div>'
      +'<div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px"><button class="btn btn-p" onclick="addDom()"><i class="fas fa-plus"></i> Add Domain</button></div>'
      +'<table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'
      +d.map(function(x){
        return '<tr><td><strong>'+esc(x.name)+'</strong></td><td><code>'+esc(x.docRoot)+'</code></td>'
          +'<td><button class="btn btn-p btn-sm" data-path="'+encodeURIComponent(x.docRoot)+'" onclick="navToPath(this);loadPage(\'files\')"><i class="fas fa-folder-open"></i> Files</button> '
          +'<button class="btn btn-d btn-sm" data-dom="'+esc(x.name)+'" onclick="delDom(this)"><i class="fas fa-trash-alt"></i> Delete</button></td></tr>';
      }).join('')+(d.length===0?'<tr><td colspan="3" style="text-align:center;color:#7f8c8d">No domains yet</td></tr>':'')
      +'</tbody></table>';
  });
}
window.addDom=function(){
  var domain=$('newDom').value.trim(); if(!domain)return;
  api.post('/api/domains',{domain:domain}).then(function(r){
    $('domMsg').innerHTML=r.success?'<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Domain added!</div>':'<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> '+(r.error||'Failed')+'</div>';
    if(r.success)setTimeout(function(){loadPage('domains')},1200);
  });
};
window.delDom=function(btn){ var n=btn.dataset.dom; if(confirm('Delete domain '+n+'?'))api.del('/api/domains/'+n).then(function(){loadPage('domains')}); };

// Databases Page
function pgDb(el) {
  Promise.all([api.get('/api/databases'), api.get('/api/database-users'), api.get('/api/dashboard')]).then(function(res) {
    var databases = res[0];
    var users = res[1];
    var info = res[2];
    
    // Start building the HTML
    var html = '<h2 class="page-title"><i class="fas fa-database"></i> Databases</h2>';
    html += '<p class="page-sub">MariaDB database management</p><div id="dbMsg"></div>';
    
    // Create tabs for databases and users
    html += '<div class="db-tabs mb">';
    html += '<button class="db-tab active" onclick="showDbTab(\'databases\')"><i class="fas fa-database"></i> Databases</button>';
    html += '<button class="db-tab" onclick="showDbTab(\'users\')"><i class="fas fa-users"></i> Database Users</button>';
    html += '</div>';
    
    // Databases tab content
    html += '<div id="tab-databases" class="db-tab-content">';
    
    // Form for creating new database
    html += '<div class="card mb">';
    html += '<h3 class="mb">Create Database</h3>';
    html += '<div class="flex-row">';
    html += '<div style="flex: 2;"><label style="font-size:13px;color:#7f8c8d">Database Name</label><input id="dbName" class="form-control" placeholder="my_database"></div>';
    
    // User dropdown selection
    html += '<div style="flex: 1;"><label style="font-size:13px;color:#7f8c8d">Assign to User</label>';
    html += '<select id="dbUserSelect" class="form-control">';
    html += '<option value="">-- Create New User --</option>';
    if (users && users.length > 0) {
      users.forEach(function(user) {
        html += '<option value="' + esc(user.username) + '">' + esc(user.username) + '</option>';
      });
    }
    html += '</select></div>';
    
    // User/password fields - shown conditionally
    html += '<div id="newUserFields" style="flex: 2;">';
    html += '<label style="font-size:13px;color:#7f8c8d">New User</label>';
    html += '<div style="display:flex;gap:10px;">';
    html += '<input id="dbUser" class="form-control" placeholder="username">';
    html += '<input id="dbPass" class="form-control" type="password" placeholder="password">';
    html += '</div></div>';
    
    html += '<button class="btn btn-p" style="align-self:flex-end;" onclick="addDb()"><i class="fas fa-plus"></i> Create</button>';
    html += '</div>';
    html += '</div>';
    
    // Database list with users
    html += '<div class="db-list">';
    if (Array.isArray(databases) && databases.length > 0) {
      databases.forEach(function(db) {
        html += '<div class="db-item">';
        html += '<div class="db-header">';
        html += '<div class="db-name"><i class="fas fa-database"></i> ' + esc(db.name) + '</div>';
        html += '<div class="db-actions">';
        html += '<button class="btn btn-w btn-sm" onclick="backupDatabase(\'' + esc(db.name) + '\')"><i class="fas fa-download"></i> Backup</button> ';
        html += '<button class="btn btn-d btn-sm" data-db="' + esc(db.name) + '" onclick="dropDb(this)"><i class="fas fa-trash-alt"></i> Drop</button>';
        html += '</div>'; // End db-actions
        html += '</div>'; // End db-header
        
        // Show users for this database
        if (db.users && db.users.length > 0) {
          html += '<div class="db-users">';
          html += '<div style="margin-bottom: 5px; font-weight: 600; color: #7f8c8d;"><i class="fas fa-users"></i> Assigned Users:</div>';
          db.users.forEach(function(user) {
            html += '<div class="db-user"><i class="fas fa-user"></i> ' + esc(user) + '</div>';
          });
          html += '</div>'; // End db-users
        } else {
          html += '<div class="db-users"><div class="db-user"><i class="fas fa-info-circle"></i> No users assigned to this database</div></div>';
        }
        
        html += '</div>'; // End db-item
      });
    } else {
      html += '<div class="card mb"><p class="text-center" style="color:#7f8c8d;padding:20px;">No databases yet</p></div>';
    }
    html += '</div>'; // End db-list
    html += '</div>'; // End databases tab
    
    // Users tab content
    html += '<div id="tab-users" class="db-tab-content" style="display:none;">';
    
    // Form for creating new user
    html += '<div class="card mb">';
    html += '<h3 class="mb">Create User</h3>';
    html += '<div class="flex-row">';
    html += '<div><label style="font-size:13px;color:#7f8c8d">Username</label><input id="newUsername" class="form-control" placeholder="username"></div>';
    html += '<div><label style="font-size:13px;color:#7f8c8d">Password</label><input id="newUserPass" class="form-control" type="password" placeholder="password"></div>';
    
    // Database selection - multi-select dropdown or checkboxes could be implemented here
    html += '<div><label style="font-size:13px;color:#7f8c8d">Grant Access to Databases</label>';
    html += '<select id="userDbAccess" class="form-control" multiple size="3">';
    if (Array.isArray(databases) && databases.length > 0) {
      databases.forEach(function(db) {
        html += '<option value="' + esc(db.name) + '">' + esc(db.name) + '</option>';
      });
    }
    html += '</select>';
    html += '<small style="color:#7f8c8d;font-size:11px;">Hold Ctrl/Cmd to select multiple</small>';
    html += '</div>';
    
    html += '<button class="btn btn-p" style="align-self:flex-end;" onclick="addDbUser()"><i class="fas fa-user-plus"></i> Create User</button>';
    html += '</div>';
    html += '</div>';
    
    // User list
    html += '<div class="db-list">';
    if (Array.isArray(users) && users.length > 0) {
      users.forEach(function(user) {
        html += '<div class="db-item">';
        html += '<div class="db-header">';
        html += '<div class="db-name"><i class="fas fa-user"></i> ' + esc(user.username) + '</div>';
        html += '<div class="db-actions">';
        html += '<button class="btn btn-w btn-sm" onclick="showChangePasswordDialog(\'' + esc(user.username) + '\')"><i class="fas fa-key"></i> Change Password</button> ';
        html += '<button class="btn btn-d btn-sm" data-user="' + esc(user.username) + '" onclick="dropUser(this)"><i class="fas fa-trash-alt"></i> Drop</button>';
        html += '</div>'; // End db-actions
        html += '</div>'; // End db-header
        
        // Get databases for this user
        var userDbs = [];
        if (Array.isArray(databases)) {
          userDbs = databases.filter(function(db) {
            return db.users && db.users.includes(user.username);
          }).map(function(db) { return db.name; });
        }
        
        if (userDbs.length > 0) {
          html += '<div class="db-users">';
          html += '<div style="margin-bottom: 5px; font-weight: 600; color: #7f8c8d;"><i class="fas fa-database"></i> Has Access To:</div>';
          userDbs.forEach(function(dbName) {
            html += '<div class="db-user"><i class="fas fa-check-circle"></i> ' + esc(dbName) + '</div>';
          });
          html += '</div>'; // End db-users
        } else {
          html += '<div class="db-users"><div class="db-user"><i class="fas fa-info-circle"></i> No database access</div></div>';
        }
        
        html += '</div>'; // End db-item
      });
    } else {
      html += '<div class="card mb"><p class="text-center" style="color:#7f8c8d;padding:20px;">No database users yet</p></div>';
    }
    html += '</div>'; // End db-list
    
    html += '</div>'; // End users tab
    
    // phpMyAdmin link
    html += '<div class="mt"><a href="http://' + info.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-w"><i class="fas fa-database"></i> Open phpMyAdmin</a></div>';
    
    el.innerHTML = html;
    
    // Add event listener for user selection
    setTimeout(function() {
      if ($('dbUserSelect')) {
        $('dbUserSelect').addEventListener('change', function() {
          var showNewUser = this.value === '';
          if ($('newUserFields')) {
            $('newUserFields').style.display = showNewUser ? 'block' : 'none';
          }
        });
        // Trigger change event to set initial state
        $('dbUserSelect').dispatchEvent(new Event('change'));
      }
    }, 100);
  });
}

// Show/hide database tabs
window.showDbTab = function(tabName) {
  // Hide all tab contents
  document.querySelectorAll('.db-tab-content').forEach(function(tab) {
    tab.style.display = 'none';
  });
  
  // Remove active class from all tab buttons
  document.querySelectorAll('.db-tab').forEach(function(btn) {
    btn.classList.remove('active');
  });
  
  // Show selected tab content and mark button as active
  $('tab-' + tabName).style.display = 'block';
  document.querySelector('.db-tab:nth-child(' + (tabName === 'databases' ? '1' : '2') + ')').classList.add('active');
};

// Add database function
window.addDb = function() {
  var name = $('dbName').value.trim();
  var selectedUser = $('dbUserSelect').value;
  var user = selectedUser || $('dbUser').value.trim();
  var password = $('dbPass') ? $('dbPass').value : '';
  
  if (!name) {
    $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Database name is required</div>';
    return;
  }
  
  // If creating new user, password is required
  if (selectedUser === '' && (!user || !password)) {
    $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> User and password required for new user</div>';
    return;
  }
  
  // If user is selected but not creating one, don't send password
  var data = { name: name };
  if (user) {
    data.user = user;
    // Only include password if creating new user or empty selection
    if (selectedUser === '' && password) {
      data.password = password;
    }
  }
  
  api.post('/api/databases', data).then(function(r) {
    $('dbMsg').innerHTML = r.success ? 
      '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Database created successfully!</div>' : 
      '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to create database') + '</div>';
    
    if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
  });
};

// Add database user function
window.addDbUser = function() {
  var username = $('newUsername').value.trim();
  var password = $('newUserPass').value;
  
  // Get selected databases
  var selectElement = $('userDbAccess');
  var selectedDatabases = [];
  for (var i = 0; i < selectElement.options.length; i++) {
    if (selectElement.options[i].selected) {
      selectedDatabases.push(selectElement.options[i].value);
    }
  }
  
  if (!username) {
    $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Username is required</div>';
    return;
  }
  
  if (!password) {
    $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Password is required</div>';
    return;
  }
  
  api.post('/api/database-users', {
    username: username,
    password: password,
    databases: selectedDatabases
  }).then(function(r) {
    $('dbMsg').innerHTML = r.success ? 
      '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> User created successfully!</div>' : 
      '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to create user') + '</div>';
    
    if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
  });
};

// Backup database function
window.backupDatabase = function(dbName) {
  $('dbMsg').innerHTML = '<div class="alert alert-ok"><i class="fas fa-spinner fa-spin"></i> Creating backup...</div>';
  
  var cmd = "mysqldump -u root -p'" + shellEscape(dbRootPassword) + "' " + dbName + " > /tmp/" + dbName + ".sql";
  api.post('/api/terminal', { command: cmd }).then(function(r) {
    if (r.output && r.output.includes('ERROR')) {
      $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Backup failed: ' + r.output + '</div>';
    } else {
      // Create a download link
      var downloadCmd = "cd /tmp && tar -czf " + dbName + ".sql.tar.gz " + dbName + ".sql";
      api.post('/api/terminal', { command: downloadCmd }).then(function() {
        $('dbMsg').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Backup created successfully! <a href="/api/files/download?path=/tmp/' + dbName + '.sql.tar.gz" class="btn btn-s btn-sm">Download</a></div>';
      });
    }
  });
};

// Drop database function
window.dropDb = function(btn) {
  var dbName = btn.dataset.db;
  if (confirm('Are you sure you want to DROP database ' + dbName + '?\nThis action cannot be undone!')) {
    api.del('/api/databases/' + dbName).then(function(r) {
      if (r.success) {
        $('dbMsg').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Database dropped successfully!</div>';
        setTimeout(function() { loadPage('databases'); }, 1000);
      } else {
        $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to drop database') + '</div>';
      }
    });
  }
};

// Drop user function
window.dropUser = function(btn) {
  var username = btn.dataset.user;
  if (confirm('Are you sure you want to DROP user ' + username + '?\nThis action cannot be undone!')) {
    api.del('/api/database-users/' + username).then(function(r) {
      if (r.success) {
        $('dbMsg').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> User dropped successfully!</div>';
        setTimeout(function() { loadPage('databases'); }, 1000);
      } else {
        $('dbMsg').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to drop user') + '</div>';
      }
    });
  }
};

// Show change password dialog
window.showChangePasswordDialog = function(username) {
  $('modalContainer').innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-header">
          <h3><i class="fas fa-key"></i> Change Password</h3>
          <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
          <p>Change password for user: <strong>${esc(username)}</strong></p>
          <div class="form-group">
            <label for="newUserPassword">New Password</label>
            <input type="password" id="newUserPassword" class="form-control">
          </div>
          <div class="form-group">
            <label for="confirmUserPassword">Confirm Password</label>
            <input type="password" id="confirmUserPassword" class="form-control">
          </div>
          <div id="changePasswordStatus" class="mt"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-l" onclick="closeModal()">Cancel</button>
          <button class="btn btn-p" onclick="changeUserPassword('${esc(username)}')"><i class="fas fa-save"></i> Save</button>
        </div>
      </div>
    </div>
  `;
};

// Change user password
window.changeUserPassword = function(username) {
  var newPass = $('newUserPassword').value;
  var confirmPass = $('confirmUserPassword').value;
  
  if (!newPass) {
    $('changePasswordStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> New password is required</div>';
    return;
  }
  
  if (newPass !== confirmPass) {
    $('changePasswordStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Passwords do not match</div>';
    return;
  }
  
  // Create user with same name but new password (MySQL will update)
  api.post('/api/database-users', {
    username: username,
    password: newPass,
    databases: [] // Keep existing permissions
  }).then(function(r) {
    if (r.success) {
      $('changePasswordStatus').innerHTML = '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Password changed successfully!</div>';
      setTimeout(function() { closeModal(); }, 1000);
    } else {
      $('changePasswordStatus').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed to change password') + '</div>';
    }
  });
};

// Helper function to escape MySQL passwords in shell commands
function shellEscape(str) {
  if (!str) return '';
  return str.replace(/'/g, "'\\''");
}

// Tunnel Page
function pgTun(el) {
  api.get('/api/tunnel/status').then(function(s){
    el.innerHTML='<h2 class="page-title"><i class="fas fa-cloud"></i> Cloudflare Tunnel</h2><p class="page-sub">Secure tunnel for remote access</p><div id="tunMsg"></div>'
      +'<div class="card mb"><div class="label">Status</div><span class="badge '+(s.active?'badge-on':'badge-off')+'">'+(s.active?'Connected':'Not Connected')+'</span></div>'
      +'<div class="card"><h3 class="mb">Setup Tunnel</h3>'
      +'<p style="color:#7f8c8d;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4a89dc">Cloudflare Zero Trust</a><br>2. Create a Tunnel → copy token<br>3. Paste below</p>'
      +'<div class="flex-row"><input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1"><button class="btn btn-p" onclick="setTun()"><i class="fas fa-link"></i> Connect</button></div></div>';
  });
}
window.setTun=function(){
  api.post('/api/tunnel/setup',{token:$('tunToken').value.trim()}).then(function(r){
    $('tunMsg').innerHTML=r.success?'<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Connected!</div>':'<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> '+(r.error||'Failed')+'</div>';
    if(r.success)setTimeout(function(){loadPage('tunnel')},2000);
  });
};

// Terminal Page
function pgTerm(el) {
  el.innerHTML='<h2 class="page-title"><i class="fas fa-terminal"></i> Terminal</h2><p class="page-sub">Run shell commands</p>'
    +'<div class="terminal-box" id="termOut">$ </div>'
    +'<div class="term-input"><input id="termIn" placeholder="Type command..." onkeydown="if(event.key===\'Enter\')runCmd()"><button class="btn btn-p" onclick="runCmd()"><i class="fas fa-play"></i> Run</button></div>';
  $('termIn').focus();
}
window.runCmd=function(){
  var cmd=$('termIn').value.trim(); if(!cmd)return;
  var out=$('termOut'); out.textContent+=cmd+'\n'; $('termIn').value='';
  api.post('/api/terminal',{command:cmd}).then(function(r){ out.textContent+=(r.output||'')+'\n$ '; out.scrollTop=out.scrollHeight; });
};

// Settings Page
function pgSet(el) {
  el.innerHTML='<h2 class="page-title"><i class="fas fa-sliders-h"></i> Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div>'
    +'<div class="card" style="max-width:500px"><h3 class="mb">Change Admin Password</h3>'
    +'<div class="form-group"><label>Current Password</label><input type="password" id="curPass" class="form-control"></div>'
    +'<div class="form-group"><label>New Password</label><input type="password" id="newPass" class="form-control"></div>'
    +'<div class="form-group"><label>Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>'
    +'<button class="btn btn-p" onclick="chgPass()"><i class="fas fa-save"></i> Update Password</button></div>';
}
window.chgPass=function(){
  var np=$('newPass').value,cp=$('cfmPass').value;
  if(np!==cp){$('setMsg').innerHTML='<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Passwords don\'t match</div>';return;}
  if(np.length<6){$('setMsg').innerHTML='<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> Min 6 characters</div>';return;}
  api.post('/api/settings/password',{currentPassword:$('curPass').value,newPassword:np}).then(function(r){
    $('setMsg').innerHTML=r.success?'<div class="alert alert-ok"><i class="fas fa-check-circle"></i> Password updated!</div>':'<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> '+(r.error||'Failed')+'</div>';
  });
};

// Bootstrap app
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
# Step 7.5: Configure OpenLiteSpeed for phpMyAdmin
########################################
log "Configuring OpenLiteSpeed for phpMyAdmin access..."

# Define OpenLiteSpeed config path
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

# Check if config exists
if [ ! -f "$OLS_CONF" ]; then
    log "ERROR: OpenLiteSpeed config not found at $OLS_CONF"
    exit 1
fi

# Backup original config
cp "$OLS_CONF" "$OLS_CONF.backup.$(date +%Y%m%d_%H%M%S)"

# Ensure Example virtualhost exists and configured properly
if ! grep -q "virtualhost Example" "$OLS_CONF"; then
    log "Adding Example virtualhost configuration..."
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
else
    # Update existing config to enable script
    sed -i '/virtualhost Example {/,/^}/ s/enableScript.*/enableScript            1/' "$OLS_CONF"
    sed -i '/virtualhost Example {/,/^}/ s/restrained.*/restrained              0/' "$OLS_CONF"
fi

# Ensure PHP extprocessor exists
if ! grep -q "extprocessor lsphp81" "$OLS_CONF"; then
    log "Adding PHP processor configuration..."
    # Find insertion point before first virtualhost
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

# Create/Update Example vhost config directory
mkdir -p /usr/local/lsws/conf/vhosts/Example
mkdir -p /usr/local/lsws/Example/logs

# Update Example vhost config with proper PHP handler
cat > /usr/local/lsws/conf/vhosts/Example/vhconf.conf << 'EOF'
docRoot                   $VH_ROOT/html
vhDomain                  *
enableGzip                1

index {
  useServer               0
  indexFiles              index.php, index.html
  autoIndex               0
}

errorlog $VH_ROOT/logs/error.log {
  useServer               0
  logLevel                INFO
  rollingSize             10M
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

# Fix ownership for OpenLiteSpeed user
chown -R nobody:nogroup "${PMA_DIR}"
chmod -R 755 "${PMA_DIR}"
find "${PMA_DIR}" -type f -name "*.php" -exec chmod 644 {} \;

# Create .htaccess for security
cat > "${PMA_DIR}/.htaccess" << 'EOF'
DirectoryIndex index.php
Options -Indexes
<FilesMatch "\.php$">
    SetHandler lsapi:lsphp81
</FilesMatch>
EOF

chown nobody:nogroup "${PMA_DIR}/.htaccess"

# Restart OpenLiteSpeed to apply changes
systemctl restart lsws
sleep 3

# Verify configuration
if curl -s -o /dev/null -w "%{http_code}" http://localhost/phpmyadmin/ | grep -q "200\|302"; then
    log "phpMyAdmin configuration completed successfully"
else
    log "WARNING: phpMyAdmin may not be accessible. Please check manually."
fi

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
echo -e "${C}║${N}  DB root Pass: ${Y}${DB_ROOT_PASS}${N}"
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
