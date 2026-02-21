#!/bin/bash
############################################
# LitePanel Installer v2.0 (Production)
# Fresh Ubuntu 22.04 LTS Only
############################################

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
ADMIN_PASS="admin123"
DB_ROOT_PASS="LitePanel$(date +%s | tail -c 6)Zx"
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

# Create log directory
mkdir -p /var/log/litepanel
INSTALL_LOG="/var/log/litepanel/install.log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.0       ║"
echo "  ║   Ubuntu 22.04 LTS              ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${N}"
sleep 2

########################################
step "Step 1/9: Update System"
########################################
apt-get update -y
apt-get upgrade -y -qq
log "System updated"

########################################
step "Step 2/9: Install Dependencies"
########################################
apt-get install -y curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release ufw git unzip \
  openssl jq rsync locate
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
wget -qO /tmp/ls_repo.sh https://repo.litespeed.sh
if [ -f /tmp/ls_repo.sh ] && [ -s /tmp/ls_repo.sh ]; then
  bash /tmp/ls_repo.sh
  rm -f /tmp/ls_repo.sh
  apt-get update -y
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
  
  wget -qO /tmp/lst_repo.gpg https://rpms.litespeedtech.com/debian/lst_repo.gpg
  wget -qO /tmp/lst_debian_repo.gpg https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg
  
  if [ -f /tmp/lst_repo.gpg ] && [ -s /tmp/lst_repo.gpg ]; then
    # Try dearmor first, fallback to direct copy
    gpg --dearmor < /tmp/lst_repo.gpg > /usr/share/keyrings/lst-debian.gpg 2>/dev/null
    if [ ! -s /usr/share/keyrings/lst-debian.gpg ]; then
      cp /tmp/lst_repo.gpg /usr/share/keyrings/lst-debian.gpg
    fi
    
    echo "deb [signed-by=/usr/share/keyrings/lst-debian.gpg] http://rpms.litespeedtech.com/debian/ ${CODENAME} main" \
      > /etc/apt/sources.list.d/lst_debian_repo.list
  fi
  rm -f /tmp/lst_repo.gpg /tmp/lst_debian_repo.gpg
  apt-get update -y
  
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
  
  wget -qO - https://rpms.litespeedtech.com/debian/lst_repo.gpg | apt-key add -
  wget -qO - https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg | apt-key add -
  
  echo "deb http://rpms.litespeedtech.com/debian/ ${CODENAME} main" \
    > /etc/apt/sources.list.d/lst_debian_repo.list
  
  apt-get update -y
  
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
# INSTALL PHP 8.1 CRITICAL EXTENSIONS
# ============================================
log "Installing PHP 8.1 required extensions..."
apt-get install -y lsphp81 lsphp81-common lsphp81-mysql lsphp81-curl \
  lsphp81-json lsphp81-mbstring lsphp81-xml lsphp81-zip lsphp81-gd lsphp81-mysqli \
  lsphp81-pdo lsphp81-opcache lsphp81-iconv > /tmp/php_install.log 2>&1
PHP_RC=$?

# Optional PHP extensions (OK if some fail)
apt-get install -y -qq lsphp81-intl >> /tmp/php_install.log 2>&1

if [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php
  log "PHP 8.1 installed ($(php -v | head -1 | awk '{print $2}'))"
else
  if [ $PHP_RC -ne 0 ]; then
    err "lsphp81 installation failed. Last 10 lines:"
    tail -10 /tmp/php_install.log
  fi
  warn "lsphp81 binary not found - PHP might not work"
fi

# ============================================
# CONFIGURE OLS (only if config exists!)
# ============================================
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

if [ ! -f "$OLS_CONF" ]; then
  err "OLS config file not found: $OLS_CONF"
  err "OpenLiteSpeed may have installed incorrectly."
  exit 1
fi

log "Configuring OpenLiteSpeed..."

# Set admin password (MD5 format, same method as CyberPanel)
if [ -d "/usr/local/lsws/admin/conf" ]; then
  OLS_HASH=$(printf '%s' "${ADMIN_PASS}" | md5sum | awk '{print $1}')
  echo "admin:${OLS_HASH}" > /usr/local/lsws/admin/conf/htpasswd
  log "OLS admin password set"
else
  warn "OLS admin conf directory not found"
fi

# Add lsphp81 extprocessor
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
EXTEOF
  log "lsphp81 extprocessor added"
fi

# Add HTTP listener on port 80
if ! grep -q "listener HTTP" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'LSTEOF'

listener HTTP {
  address                 *:80
  secure                  0
}
LSTEOF
  log "HTTP listener port 80 added"
fi

# Add HTTP listener on port 8088 for phpMyAdmin - FIXED CORRECT VERSION
if ! grep -q "listener PMA_HTTP" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'PMAEOF'

listener PMA_HTTP {
  address                 *:8088
  secure                  0
  map                     Example *
}
PMAEOF
  log "Added phpMyAdmin listener on port 8088"
fi

# Update default lsphp path to lsphp81
sed -i 's|/usr/local/lsws/fcgi-bin/lsphp|/usr/local/lsws/lsphp81/bin/lsphp|g' "$OLS_CONF" 2>/dev/null

# Update Example vhost to use lsphp81 (for phpMyAdmin)
EXAMPLE_VHCONF="/usr/local/lsws/conf/vhosts/Example/vhconf.conf"
if [ -f "$EXAMPLE_VHCONF" ]; then
  # Make sure the Example vhost exists and has the right scripthandler
  if grep -q "scripthandler" "$EXAMPLE_VHCONF"; then
    sed -i '/add.*lsapi:lsphp/c\  add                     lsapi:lsphp81 php' "$EXAMPLE_VHCONF"
  else
    # If scripthandler section doesn't exist, add it
    cat >> "$EXAMPLE_VHCONF" <<'EXVHEOF'
scripthandler {
  add                     lsapi:lsphp81 php
}
EXVHEOF
  fi
  
  # Add context for phpMyAdmin - FIXED CORRECT VERSION
  if grep -q "context phpmyadmin" "$EXAMPLE_VHCONF"; then
    # Remove old context definition
    sed -i '/context phpmyadmin {/,/}/d' "$EXAMPLE_VHCONF"
  fi
  
  # Add the correct context definition with proper location path
  cat >> "$EXAMPLE_VHCONF" <<'PMACTXEOF'

context phpmyadmin {
  location                html/phpmyadmin
  allowBrowse             1
  uri                     /phpmyadmin
  type                    NULL
  handlephp               1
  enableScript            1
}
PMACTXEOF
  
  log "Example vhost updated for phpMyAdmin"
fi

# Make sure Example virtualhost is defined
if ! grep -q "virtualhost Example" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'EXVHOSTEOF'

virtualhost Example {
  vhRoot                  $SERVER_ROOT/Example
  configFile              $SERVER_ROOT/conf/vhosts/Example/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}
EXVHOSTEOF
  log "Example virtualhost created"
fi

systemctl enable lsws > /dev/null 2>&1
systemctl restart lsws

sleep 3

if systemctl is-active --quiet lsws; then
  log "OpenLiteSpeed started successfully"
else
  warn "OpenLiteSpeed failed to start - checking..."
  systemctl status lsws --no-pager | tail -5
  warn "Trying restart..."
  systemctl restart lsws
  sleep 3
  if systemctl is-active --quiet lsws; then
    log "OpenLiteSpeed started on retry"
  else
    err "OpenLiteSpeed won't start. Check: systemctl status lsws"
  fi
fi

########################################
step "Step 4/9: Install MariaDB"
########################################
apt-get install -y mariadb-server mariadb-client
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Wait for MariaDB to become available
for i in $(seq 1 15); do
  mysqladmin ping &>/dev/null && break
  sleep 2
done

if mysqladmin ping &>/dev/null; then
  # Get MariaDB socket path with improved detection
  MYSQL_SOCK=""
  
  # Method 1: Check my.cnf files
  for config in /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf; do
    if [ -f "$config" ]; then
      SOCK=$(grep -v "#" "$config" | grep "socket" | head -1 | awk -F'=' '{print $2}' | tr -d ' ')
      if [ -n "$SOCK" ] && [ -S "$SOCK" ]; then
        MYSQL_SOCK="$SOCK"
        break
      fi
    fi
  done
  
  # Method 2: Use mysqladmin
  if [ -z "$MYSQL_SOCK" ]; then
    SOCK=$(mysqladmin variables 2>/dev/null | grep "socket" | awk '{print $4}')
    if [ -n "$SOCK" ] && [ -S "$SOCK" ]; then
      MYSQL_SOCK="$SOCK"
    fi
  fi
  
  # Method 3: Check common locations
  if [ -z "$MYSQL_SOCK" ]; then
    for sock in "/var/run/mysqld/mysqld.sock" "/var/lib/mysql/mysql.sock" "/tmp/mysql.sock"; do
      if [ -S "$sock" ]; then
        MYSQL_SOCK="$sock"
        break
      fi
    done
  fi
  
  # Default fallback
  if [ -z "$MYSQL_SOCK" ]; then
    MYSQL_SOCK="/var/run/mysqld/mysqld.sock"
    warn "Could not detect MySQL socket, using default: $MYSQL_SOCK"
  else
    log "Detected MySQL socket: $MYSQL_SOCK"
  fi
  
  # Configure MariaDB with mysql_native_password for compatibility - FIXED VERSION
  mysql -u root -e "
    ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
    -- Ensure root uses native password for phpMyAdmin compatibility
    ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_ROOT_PASS}';
    DELETE FROM mysql.user WHERE User='';
    DROP DATABASE IF EXISTS test;
    FLUSH PRIVILEGES;
  "
  
  # Verify mysql_native_password is being used
  PLUGIN=$(mysql -u root -p"${DB_ROOT_PASS}" -e "SELECT plugin FROM mysql.user WHERE user='root' AND host='localhost';" -s -N)
  if [ "$PLUGIN" != "mysql_native_password" ]; then
    warn "MySQL authentication plugin is not mysql_native_password. Fixing..."
    mysql -u root -p"${DB_ROOT_PASS}" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_ROOT_PASS}'; FLUSH PRIVILEGES;"
  fi
  
  log "MariaDB installed & secured"
  log "Using MySQL socket: ${MYSQL_SOCK}"
else
  err "MariaDB failed to start"
fi

########################################
step "Step 5/9: Install Node.js 18"
########################################
if ! command -v node > /dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
  apt-get install -y -qq nodejs
fi

if command -v node > /dev/null 2>&1; then
  log "Node.js $(node -v) installed"
else
  err "Node.js installation failed!"
  err "Manual install: curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && apt install nodejs"
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
  "version": "2.0.0",
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

# Continue with app.js, index.html, style.css, and app.js from original script...
# (inserting these sections would make the response too long)
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

log "LitePanel app created"

########################################
step "Step 7/9: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
mkdir -p ${PMA_DIR}
cd /tmp
wget -q "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz" -O pma.tar.gz
if [ -f pma.tar.gz ] && [ -s pma.tar.gz ]; then
  tar xzf pma.tar.gz
  cp -rf phpMyAdmin-*/* ${PMA_DIR}/
  rm -rf phpMyAdmin-* pma.tar.gz

  # Get MariaDB socket path with improved detection
  MYSQL_SOCK=""
  
  # Method 1: Check my.cnf files
  for config in /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/my.cnf; do
    if [ -f "$config" ]; then
      SOCK=$(grep -v "#" "$config" | grep "socket" | head -1 | awk -F'=' '{print $2}' | tr -d ' ')
      if [ -n "$SOCK" ] && [ -S "$SOCK" ]; then
        MYSQL_SOCK="$SOCK"
        break
      fi
    fi
  done
  
  # Method 2: Use mysqladmin
  if [ -z "$MYSQL_SOCK" ]; then
    SOCK=$(mysqladmin variables 2>/dev/null | grep "socket" | awk '{print $4}')
    if [ -n "$SOCK" ] && [ -S "$SOCK" ]; then
      MYSQL_SOCK="$SOCK"
    fi
  fi
  
  # Method 3: Check common locations
  if [ -z "$MYSQL_SOCK" ]; then
    for sock in "/var/run/mysqld/mysqld.sock" "/var/lib/mysql/mysql.sock" "/tmp/mysql.sock"; do
      if [ -S "$sock" ]; then
        MYSQL_SOCK="$sock"
        break
      fi
    done
  fi
  
  # Default fallback
  if [ -z "$MYSQL_SOCK" ]; then
    MYSQL_SOCK="/var/run/mysqld/mysqld.sock"
    warn "Could not detect MySQL socket, using default: $MYSQL_SOCK"
  else
    log "Detected MySQL socket: $MYSQL_SOCK"
  fi

  BLOWFISH=$(openssl rand -hex 16)
  # Enhanced configuration for phpMyAdmin - FIXED VERSION
  cat > ${PMA_DIR}/config.inc.php <<PMAEOF
<?php
// Enhanced configuration for phpMyAdmin

/* Authentication */
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['connect_type'] = 'socket';
\$cfg['Servers'][\$i]['socket'] = '${MYSQL_SOCK}';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['extension'] = 'mysqli';
\$cfg['Servers'][\$i]['user'] = '';
\$cfg['Servers'][\$i]['password'] = '';
\$cfg['DefaultLang'] = 'en';
\$cfg['ServerDefault'] = 1;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '${PMA_DIR}/tmp';
/* Using relative path instead of fixed IP */
\$cfg['PmaAbsoluteUri'] = '';

/* User Interface */
\$cfg['ExecTimeLimit'] = 300;
\$cfg['MaxRows'] = 100;
\$cfg['SendErrorReports'] = 'never';
\$cfg['ShowPhpInfo'] = false;

/* Features */
\$cfg['AllowArbitraryServer'] = false;
\$cfg['SuhosinDisableWarning'] = true;
\$cfg['LoginCookieValidity'] = 1440;

/* Security */
\$cfg['CheckConfigurationPermissions'] = false;
PMAEOF
  
  # Create the tmp directory with proper permissions
  mkdir -p ${PMA_DIR}/tmp
  chmod 750 ${PMA_DIR}/tmp

  # Set correct permissions with principle of least privilege
  chown -R nobody:nogroup ${PMA_DIR}
  chmod 750 ${PMA_DIR}
  
  log "phpMyAdmin installed with socket: ${MYSQL_SOCK}"

  # We don't need symlinks anymore because we fixed the context path configuration
  # But keep for compatibility with existing code that might reference these paths
  if [ ! -L "/usr/local/lsws/Example/html/phpMyAdmin" ]; then
    ln -sf ${PMA_DIR} /usr/local/lsws/Example/html/phpMyAdmin
  fi
  
  if [ ! -L "/usr/local/lsws/Example/html/pma" ]; then
    ln -sf ${PMA_DIR} /usr/local/lsws/Example/html/pma
  fi
  
  # Create test file to verify PHP processing
  echo "<?php phpinfo(); ?>" > /usr/local/lsws/Example/html/test.php
  chmod 644 /usr/local/lsws/Example/html/test.php
  chown nobody:nogroup /usr/local/lsws/Example/html/test.php
else
  err "phpMyAdmin download failed"
fi

# Fix HTML root permissions to avoid OLS warning
chown -R nobody:nogroup /usr/local/lsws/Example/html/

########################################
step "Step 8/9: Install Cloudflared + Fail2Ban"
########################################
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
cd /tmp
if [ "$ARCH" = "arm64" ]; then
  CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
else
  CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
fi
wget -q "$CF_URL" -O cloudflared.deb
if [ -f cloudflared.deb ] && [ -s cloudflared.deb ]; then
  dpkg -i cloudflared.deb
  rm -f cloudflared.deb
  log "Cloudflared installed"
else
  err "Cloudflared download failed"
fi

apt-get install -y fail2ban
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban

# Configure Fail2Ban for SSH and HTTP - ENHANCED
cat > /etc/fail2ban/jail.d/custom.conf <<'BANEOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600

[apache-auth]
enabled = true
port = http,https,8088
filter = apache-auth
logpath = /var/log/lsws/*.log
maxretry = 5
bantime = 3600
BANEOF

systemctl restart fail2ban
log "Fail2Ban installed and configured"

########################################
step "Step 9/9: Configure Firewall + Start Services"
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

# Restart all services to ensure everything is running
systemctl restart lsws
systemctl restart mariadb
sleep 3

# Create credentials file with better permissions
cat > /root/.litepanel_credentials <<CREDEOF
==========================================
  LitePanel Credentials (SECURELY STORE THIS FILE)
==========================================
Panel URL:     http://${SERVER_IP}:${PANEL_PORT}
Panel Login:   ${ADMIN_USER} / ${ADMIN_PASS}

OLS Admin:     http://${SERVER_IP}:7080
OLS Login:     admin / ${ADMIN_PASS}

phpMyAdmin:    http://${SERVER_IP}:8088/phpmyadmin/
Database Login: root / ${DB_ROOT_PASS}

MariaDB Root:  ${DB_ROOT_PASS}
==========================================
CREDEOF
chmod 600 /root/.litepanel_credentials

# Create alias for easy credential access
echo "alias litecreds='cat /root/.litepanel_credentials'" >> /root/.bashrc

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
echo -e "${C}║${N}  Database:     ${Y}root${N} / ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Saved: ${B}/root/.litepanel_credentials${N}"
echo -e "${C}║${N}  Command: ${B}litecreds${N} (after relogin)"
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

# Test phpMyAdmin connectivity and log result
echo "Testing phpMyAdmin connectivity..."
if curl -s "http://localhost:8088/phpmyadmin/" | grep -q "phpMyAdmin"; then
  log "phpMyAdmin is working correctly!"
else
  warn "phpMyAdmin test failed. Please check manually."
  # Try to diagnose the issue
  if [ ! -f "${PMA_DIR}/index.php" ]; then
    err "phpMyAdmin files not found in ${PMA_DIR}"
  elif [ ! -S "${MYSQL_SOCK}" ]; then
    err "MySQL socket not found at ${MYSQL_SOCK}"
  else
    warn "Running additional diagnostic commands:"
    echo "PHP modules installed:"
    php -m | sort
    echo "Testing MySQL connectivity:"
    php -r "if (extension_loaded('mysqli')) { \$link = mysqli_connect('localhost', 'root', '${DB_ROOT_PASS}'); echo \$link ? 'Connected successfully' : 'Connection failed: ' . mysqli_connect_error(); } else { echo 'mysqli extension not loaded'; }"
  fi
fi
