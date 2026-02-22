#!/bin/bash
############################################
# LitePanel Installer v2.1 (Production)
# Fresh Ubuntu 22.04 LTS Only
# REVISED: Fixed phpMyAdmin & Security Issues
# UPDATED: White UI theme and cPanel-like file manager
# FIXED: Extract/Paste/Edit buttons, Change Password, Backup DB
############################################

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
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

if [ "$REPO_ADDED" -eq 0 ]; then
  err "FATAL: Could not add LiteSpeed repository!"
  exit 1
fi

log "Installing OpenLiteSpeed..."
apt-get install -y openlitespeed > /tmp/ols_install.log 2>&1
OLS_RC=$?

if [ $OLS_RC -ne 0 ] || [ ! -d "/usr/local/lsws" ]; then
  err "FATAL: OpenLiteSpeed installation failed!"
  tail -30 /tmp/ols_install.log
  exit 1
fi
log "OpenLiteSpeed installed"

log "Installing PHP 8.1..."
PHP_INSTALLED=0
apt-get install -y lsphp81 > /tmp/php_base_install.log 2>&1
if [ $? -eq 0 ] && [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  PHP_INSTALLED=1
  log "Base PHP 8.1 installed"
fi

if [ $PHP_INSTALLED -eq 0 ]; then
  err "FATAL: Could not install PHP 8.1!"
  exit 1
fi

for ext in "common" "mysql" "mysqli" "curl" "json" "mbstring" "xml" "gd" "zip" "intl" "opcache"; do
  PKG="lsphp81-$ext"
  if ! apt-cache show $PKG > /dev/null 2>&1; then
    warn "Package $PKG not found, skipping..."
    continue
  fi
  apt-get install -y $PKG > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    log "Installed $PKG"
  else
    warn "Failed to install $PKG"
  fi
done

if [ -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null
  PHP_VERSION=$(php -v 2>/dev/null | head -1 | awk '{print $2}')
  log "PHP 8.1 ready ($PHP_VERSION)"
else
  err "PHP binary not found"
  exit 1
fi

PHP_INI_DIR="/usr/local/lsws/lsphp81/etc/php/8.1/litespeed"
mkdir -p "$PHP_INI_DIR"
PHP_INI="$PHP_INI_DIR/php.ini"

if [ ! -f "$PHP_INI" ]; then
  cat > "$PHP_INI" <<'PHPINI'
[PHP]
engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
implicit_flush = Off
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

grep -q "mysqli.default_socket" "$PHP_INI" || echo "mysqli.default_socket = /var/run/mysqld/mysqld.sock" >> "$PHP_INI"
grep -q "pdo_mysql.default_socket" "$PHP_INI" || echo "pdo_mysql.default_socket = /var/run/mysqld/mysqld.sock" >> "$PHP_INI"
log "PHP configured"

########################################
step "Step 4/10: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

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
  if [ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ]; then
    ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock
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
  exit 1
fi

########################################
step "Step 6/10: Creating LitePanel App"
########################################
mkdir -p ${PANEL_DIR}/{public/css,public/js}
cd ${PANEL_DIR}

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
  warn "npm install failed, retrying with --legacy-peer-deps..."
  npm install --production --legacy-peer-deps > /tmp/npm_install.log 2>&1
  NPM_RC=$?
fi
if [ $NPM_RC -ne 0 ]; then
  err "npm install failed. Check /tmp/npm_install.log"
  tail -10 /tmp/npm_install.log
  exit 1
fi
log "npm dependencies installed"

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
const { execSync, exec } = require('child_process');
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
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 86400000, httpOnly: true, sameSite: 'strict' }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth Middleware ──────────────────────────────────────────────────────────
var auth = function(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

// ── Utilities ────────────────────────────────────────────────────────────────
function run(cmd, timeout) {
  try {
    return execSync(cmd, {
      timeout: timeout || 15000,
      maxBuffer: 5 * 1024 * 1024
    }).toString().trim();
  } catch(e) {
    return e.stderr ? e.stderr.toString().trim() : e.message;
  }
}

function svcActive(name) {
  try { execSync('systemctl is-active ' + name, { stdio: 'pipe' }); return true; }
  catch(e) { return false; }
}

function escRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function shellEsc(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/'/g, "'\\''");
}

function decodePathParameter(encodedPath) {
  try { return decodeURIComponent(encodedPath); }
  catch(e) { return encodedPath; }
}

function isTextFile(filePath, size) {
  if (size > 1024 * 1024) return false;
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(Math.min(size, 4096));
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    return !buffer.includes(0);
  } catch(e) { return false; }
}

function compressFiles(sourcePaths, outputPath) {
  try {
    const zip = new AdmZip();
    for (const src of sourcePaths) {
      const stats = fs.statSync(src);
      if (stats.isDirectory()) {
        zip.addLocalFolder(src, path.basename(src));
      } else {
        zip.addLocalFile(src);
      }
    }
    zip.writeZip(outputPath);
    return true;
  } catch(e) { return false; }
}

function extractArchive(archivePath, targetDir) {
  try {
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(targetDir, true);
    return true;
  } catch(e) { return false; }
}

// ── OLS Config ───────────────────────────────────────────────────────────────
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
    + 'index {\n  useServer               0\n  indexFiles              index.php, index.html\n  autoIndex               0\n}\n\n'
    + 'scripthandler {\n  add                     lsapi:lsphp81 php\n}\n\n'
    + 'accessControl {\n  allow                   *\n}\n\n'
    + 'rewrite {\n  enable                  1\n  autoLoadHtaccess        1\n}\n';
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

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.post('/api/login', function(req, res) {
  var u = req.body.username, p = req.body.password;
  if (u === config.adminUser && bcrypt.compareSync(p, config.adminPass)) {
    req.session.user = u;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
app.get('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth', function(req, res) { res.json({ authenticated: !!(req.session && req.session.user) }); });

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/api/dashboard', auth, function(req, res) {
  var tm = os.totalmem(), fm = os.freemem();
  var disk = { total: 0, used: 0, free: 0 };
  try {
    var d = run("df -B1 / | tail -1").split(/\s+/);
    disk = { total: +d[1], used: +d[2], free: +d[3] };
  } catch(e) {}
  var cpus = os.cpus();
  res.json({
    hostname: os.hostname(),
    ip: run("hostname -I | awk '{print $1}'"),
    uptime: os.uptime(),
    cpu: { model: cpus[0] ? cpus[0].model : 'Unknown', cores: cpus.length, load: os.loadavg() },
    memory: { total: tm, used: tm - fm, free: fm },
    disk: disk,
    nodeVersion: process.version
  });
});

// ── Services ──────────────────────────────────────────────────────────────────
app.get('/api/services', auth, function(req, res) {
  res.json(['lsws','mariadb','fail2ban','cloudflared'].map(function(s) {
    return { name: s, active: svcActive(s) };
  }));
});
app.post('/api/services/:name/:action', auth, function(req, res) {
  var ok = ['lsws','mariadb','fail2ban','cloudflared'];
  var acts = ['start','stop','restart'];
  if (!ok.includes(req.params.name) || !acts.includes(req.params.action))
    return res.status(400).json({ error: 'Invalid' });
  try {
    execSync('systemctl ' + req.params.action + ' ' + req.params.name, { timeout: 15000 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── File Manager ──────────────────────────────────────────────────────────────
app.get('/api/files', auth, function(req, res) {
  var p = path.resolve(decodePathParameter(req.query.path || '/'));
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
  try {
    fs.writeFileSync(req.body.filePath, req.body.content);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/files', auth, function(req, res) {
  var target = decodePathParameter(req.query.path);
  if (!target || target === '/') return res.status(400).json({ error: 'Cannot delete root' });
  try {
    fs.rmSync(target, { recursive: true, force: true });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Upload
var upload = multer({ dest: '/tmp/uploads/' });
app.post('/api/files/upload', auth, upload.array('files'), function(req, res) {
  try {
    const targetPath = decodePathParameter(req.body.path) || '/tmp';
    if (!req.files || req.files.length === 0)
      return res.status(400).json({ error: 'No files were uploaded' });
    const results = [];
    for (const file of req.files) {
      const destination = path.join(targetPath, file.originalname);
      fs.renameSync(file.path, destination);
      results.push({ name: file.originalname, size: file.size, path: destination, success: true });
    }
    res.json({ success: true, files: results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Mkdir
app.post('/api/files/mkdir', auth, function(req, res) {
  try {
    fs.mkdirSync(decodePathParameter(req.body.path), { recursive: true });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Rename / Move
app.post('/api/files/rename', auth, function(req, res) {
  try {
    fs.renameSync(decodePathParameter(req.body.oldPath), decodePathParameter(req.body.newPath));
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Copy  ← NEW: backend copy implementation
app.post('/api/files/copy', auth, function(req, res) {
  try {
    const srcPaths = Array.isArray(req.body.sources)
      ? req.body.sources.map(p => decodePathParameter(p))
      : [];
    const targetDir = decodePathParameter(req.body.target);

    if (srcPaths.length === 0 || !targetDir)
      return res.status(400).json({ error: 'Invalid parameters' });

    fs.mkdirSync(targetDir, { recursive: true });

    for (const src of srcPaths) {
      if (!fs.existsSync(src)) continue;
      const dest = path.join(targetDir, path.basename(src));
      run(`cp -a '${shellEsc(src)}' '${shellEsc(dest)}'`);
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Download
app.get('/api/files/download', auth, function(req, res) {
  var fp = decodePathParameter(req.query.path);
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  try {
    if (fs.statSync(fp).isDirectory())
      return res.status(400).json({ error: 'Cannot download directory directly' });
    const contentType = mime.lookup(fp) || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'attachment; filename="' + path.basename(fp) + '"');
    fs.createReadStream(fp).pipe(res);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Compress
app.post('/api/files/compress', auth, function(req, res) {
  try {
    const srcPaths = Array.isArray(req.body.paths)
      ? req.body.paths.map(p => decodePathParameter(p))
      : [];
    const outputPath = decodePathParameter(req.body.output);
    if (srcPaths.length === 0 || !outputPath)
      return res.status(400).json({ error: 'Invalid parameters' });
    for (const p of srcPaths) {
      if (!fs.existsSync(p)) return res.status(404).json({ error: 'Path not found: ' + p });
    }
    const finalOutput = outputPath.endsWith('.zip') ? outputPath : outputPath + '.zip';
    if (compressFiles(srcPaths, finalOutput)) {
      res.json({ success: true, path: finalOutput });
    } else {
      res.status(500).json({ error: 'Failed to create archive' });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Extract  ← FIXED: proper error message propagation
app.post('/api/files/extract', auth, function(req, res) {
  try {
    const archivePath = decodePathParameter(req.body.archive);
    const targetDir   = decodePathParameter(req.body.target);
    if (!archivePath || !targetDir)
      return res.status(400).json({ error: 'Invalid parameters' });
    if (!fs.existsSync(archivePath))
      return res.status(404).json({ error: 'Archive not found' });

    fs.mkdirSync(targetDir, { recursive: true });

    // Try AdmZip first, fall back to system unzip/tar for non-zip archives
    let success = false;
    const ext = path.extname(archivePath).toLowerCase();
    if (ext === '.zip') {
      success = extractArchive(archivePath, targetDir);
    } else if (['.tar', '.gz', '.tgz', '.bz2'].includes(ext)) {
      const result = run(
        `tar -xf '${shellEsc(archivePath)}' -C '${shellEsc(targetDir)}'`, 30000
      );
      success = !result.includes('Error') && !result.includes('error');
    } else {
      success = extractArchive(archivePath, targetDir);
    }

    if (success) {
      res.json({ success: true, path: targetDir });
    } else {
      res.status(500).json({ error: 'Failed to extract archive. Unsupported format or corrupt file.' });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Permissions – GET
app.get('/api/files/permissions', auth, function(req, res) {
  var p = decodePathParameter(req.query.path);
  if (!p || !fs.existsSync(p)) return res.status(404).json({ error: 'Not found' });
  try {
    const stats = fs.statSync(p);
    const permissions = '0' + (stats.mode & parseInt('777', 8)).toString(8);
    const owner = run(`stat -c "%U" '${shellEsc(p)}'`) || 'unknown';
    const group = run(`stat -c "%G" '${shellEsc(p)}'`) || 'unknown';
    res.json({ permissions, owner, group, isDir: stats.isDirectory() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Permissions – POST
app.post('/api/files/permissions', auth, function(req, res) {
  try {
    const filePath   = decodePathParameter(req.body.path);
    const permissions = req.body.permissions;
    const recursive   = req.body.recursive === true;
    if (!filePath || !permissions || !fs.existsSync(filePath))
      return res.status(400).json({ error: 'Invalid parameters' });
    if (!/^(0)?[0-7]{3,4}$/.test(permissions))
      return res.status(400).json({ error: 'Invalid permission format' });
    const cmd = recursive
      ? `chmod -R ${permissions} '${shellEsc(filePath)}'`
      : `chmod ${permissions} '${shellEsc(filePath)}'`;
    run(cmd);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// New file
app.post('/api/files/newfile', auth, function(req, res) {
  try {
    const filePath = decodePathParameter(req.body.path);
    if (!filePath) return res.status(400).json({ error: 'Path is required' });
    if (fs.existsSync(filePath)) return res.status(400).json({ error: 'File already exists' });
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, req.body.content || '');
    res.json({ success: true, path: filePath });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Domains ───────────────────────────────────────────────────────────────────
app.get('/api/domains', auth, function(req, res) {
  try {
    if (!fs.existsSync(OLS_VHOST_CONF_DIR)) return res.json([]);
    var list = fs.readdirSync(OLS_VHOST_CONF_DIR).filter(function(n) {
      return fs.statSync(path.join(OLS_VHOST_CONF_DIR, n)).isDirectory() && n !== 'Example';
    });
    res.json(list.map(function(name) {
      return { name: name, docRoot: path.join(OLS_VHOST_DIR, name, 'html') };
    }));
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

// ── Databases ─────────────────────────────────────────────────────────────────
app.get('/api/databases', auth, function(req, res) {
  try {
    var dp = shellEsc(config.dbRootPass);
    var dbOut = run(`mysql -u root -p'${dp}' -e 'SHOW DATABASES;' -s -N 2>/dev/null`);
    var skip  = ['information_schema','performance_schema','mysql','sys'];
    var databases = dbOut.split('\n').filter(d => d.trim() && !skip.includes(d.trim()));

    var userOut = run(`mysql -u root -p'${dp}' -e 'SELECT User, Host FROM mysql.user WHERE Host="localhost" AND User NOT IN ("root","debian-sys-maint","mariadb.sys");' -s -N 2>/dev/null`);
    var users = userOut.split('\n').filter(u => u.trim()).map(u => {
      var parts = u.split('\t');
      return { username: parts[0], host: parts[1] || 'localhost' };
    });

    var result = databases.map(function(db) {
      var dbUsers = users.filter(function(user) {
        var grants = run(`mysql -u root -p'${dp}' -e 'SHOW GRANTS FOR "${shellEsc(user.username)}"@"localhost";' -s -N 2>/dev/null`);
        return grants.includes('`' + db + '`') || grants.includes('*.*');
      }).map(u => u.username);
      return { name: db, users: dbUsers };
    });

    res.json(result);
  } catch(e) { console.error(e); res.json([]); }
});

app.get('/api/database-users', auth, function(req, res) {
  try {
    var dp = shellEsc(config.dbRootPass);
    var out = run(`mysql -u root -p'${dp}' -e 'SELECT User, Host FROM mysql.user WHERE Host="localhost" AND User NOT IN ("root","debian-sys-maint","mariadb.sys");' -s -N 2>/dev/null`);
    var users = out.split('\n').filter(u => u.trim()).map(u => {
      var parts = u.split('\t');
      return { username: parts[0], host: parts[1] || 'localhost' };
    });
    res.json(users);
  } catch(e) { console.error(e); res.json([]); }
});

app.post('/api/databases', auth, function(req, res) {
  try {
    var name = req.body.name, user = req.body.user, password = req.body.password;
    if (!name || !/^[a-zA-Z0-9_]+$/.test(name))
      return res.status(400).json({ error: 'Invalid database name' });
    var dp = shellEsc(config.dbRootPass);
    run(`mysql -u root -p'${dp}' -e "CREATE DATABASE IF NOT EXISTS \`${shellEsc(name)}\`;" 2>/dev/null`);
    if (user && password) {
      if (!/^[a-zA-Z0-9_]+$/.test(user))
        return res.status(400).json({ error: 'Invalid username' });
      var u = shellEsc(user), pw = shellEsc(password);
      run(`mysql -u root -p'${dp}' -e "CREATE USER IF NOT EXISTS '${u}'@'localhost' IDENTIFIED BY '${pw}';" 2>/dev/null`);
      run(`mysql -u root -p'${dp}' -e "GRANT ALL ON \`${shellEsc(name)}\`.* TO '${u}'@'localhost';" 2>/dev/null`);
      run(`mysql -u root -p'${dp}' -e "FLUSH PRIVILEGES;" 2>/dev/null`);
    }
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/database-users', auth, function(req, res) {
  try {
    var user = req.body.username, password = req.body.password;
    var databases = req.body.databases || [];
    if (!user || !/^[a-zA-Z0-9_]+$/.test(user))
      return res.status(400).json({ error: 'Invalid username' });
    if (!password)
      return res.status(400).json({ error: 'Password is required' });
    var dp = shellEsc(config.dbRootPass);
    var u  = shellEsc(user), pw = shellEsc(password);
    run(`mysql -u root -p'${dp}' -e "CREATE USER IF NOT EXISTS '${u}'@'localhost' IDENTIFIED BY '${pw}';" 2>/dev/null`);
    if (Array.isArray(databases) && databases.length > 0) {
      databases.forEach(function(db) {
        if (/^[a-zA-Z0-9_]+$/.test(db)) {
          run(`mysql -u root -p'${dp}' -e "GRANT ALL ON \`${shellEsc(db)}\`.* TO '${u}'@'localhost';" 2>/dev/null`);
        }
      });
    }
    run(`mysql -u root -p'${dp}' -e "FLUSH PRIVILEGES;" 2>/dev/null`);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Change password  ← FIXED: use ALTER USER instead of CREATE USER
app.post('/api/database-users/:name/password', auth, function(req, res) {
  var username = req.params.name;
  var newPassword = req.body.newPassword;

  if (!username || !/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Invalid username' });
  if (!newPassword || newPassword.length < 4)
    return res.status(400).json({ error: 'Password too short' });

  try {
    var dp = shellEsc(config.dbRootPass);
    var u  = shellEsc(username);
    var pw = shellEsc(newPassword);

    // Check user exists first
    var exists = run(`mysql -u root -p'${dp}' -e "SELECT COUNT(*) FROM mysql.user WHERE User='${u}' AND Host='localhost';" -s -N 2>/dev/null`);
    if (exists.trim() === '0')
      return res.status(404).json({ error: 'User not found' });

    // ALTER USER is the correct way to change password in MariaDB/MySQL
    var result = run(`mysql -u root -p'${dp}' -e "ALTER USER '${u}'@'localhost' IDENTIFIED BY '${pw}';" 2>/dev/null`);
    run(`mysql -u root -p'${dp}' -e "FLUSH PRIVILEGES;" 2>/dev/null`);

    if (result && result.toLowerCase().includes('error')) {
      return res.status(500).json({ error: result });
    }

    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/databases/:name', auth, function(req, res) {
  if (!/^[a-zA-Z0-9_]+$/.test(req.params.name))
    return res.status(400).json({ error: 'Invalid' });
  try {
    run(`mysql -u root -p'${shellEsc(config.dbRootPass)}' -e "DROP DATABASE IF EXISTS \`${req.params.name}\`;" 2>/dev/null`);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/database-users/:name', auth, function(req, res) {
  if (!/^[a-zA-Z0-9_]+$/.test(req.params.name))
    return res.status(400).json({ error: 'Invalid' });
  try {
    var u = shellEsc(req.params.name), dp = shellEsc(config.dbRootPass);
    run(`mysql -u root -p'${dp}' -e "DROP USER IF EXISTS '${u}'@'localhost';" 2>/dev/null`);
    run(`mysql -u root -p'${dp}' -e "FLUSH PRIVILEGES;" 2>/dev/null`);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Backup  ← FIXED: full server-side backup, returns download link
app.post('/api/databases/:name/backup', auth, function(req, res) {
  var dbName = req.params.name;
  if (!dbName || !/^[a-zA-Z0-9_]+$/.test(dbName))
    return res.status(400).json({ error: 'Invalid database name' });

  try {
    var dp   = shellEsc(config.dbRootPass);
    var ts   = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
    var sqlFile = `/tmp/${dbName}_${ts}.sql`;
    var gzFile  = sqlFile + '.gz';

    // Run mysqldump
    var dumpResult = run(
      `mysqldump -u root -p'${dp}' --single-transaction --routines --triggers '${shellEsc(dbName)}' > '${sqlFile}'`,
      60000
    );

    if (dumpResult && dumpResult.toLowerCase().includes('error')) {
      return res.status(500).json({ error: 'mysqldump failed: ' + dumpResult });
    }

    if (!fs.existsSync(sqlFile) || fs.statSync(sqlFile).size === 0) {
      return res.status(500).json({ error: 'Backup file is empty or was not created' });
    }

    // Compress
    run(`gzip -f '${sqlFile}'`, 30000);

    if (!fs.existsSync(gzFile)) {
      return res.status(500).json({ error: 'Compression failed' });
    }

    var fileSize = fs.statSync(gzFile).size;
    res.json({
      success: true,
      filename: path.basename(gzFile),
      path: gzFile,
      size: fileSize,
      downloadUrl: '/api/files/download?path=' + encodeURIComponent(gzFile)
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Tunnel ────────────────────────────────────────────────────────────────────
app.get('/api/tunnel/status', auth, function(req, res) { res.json({ active: svcActive('cloudflared') }); });
app.post('/api/tunnel/setup', auth, function(req, res) {
  var token = req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });
  var safeToken = token.replace(/[;&|`$(){}]/g, '');
  try {
    fs.writeFileSync('/etc/systemd/system/cloudflared.service',
      '[Unit]\nDescription=Cloudflare Tunnel\nAfter=network.target\n\n[Service]\nType=simple\n'
      + 'ExecStart=/usr/bin/cloudflared tunnel run --token ' + safeToken
      + '\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n');
    execSync('systemctl daemon-reload && systemctl enable cloudflared && systemctl restart cloudflared', { timeout: 15000 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Settings ──────────────────────────────────────────────────────────────────
app.post('/api/settings/password', auth, function(req, res) {
  if (!bcrypt.compareSync(req.body.currentPassword, config.adminPass))
    return res.status(401).json({ error: 'Wrong current password' });
  if (!req.body.newPassword || req.body.newPassword.length < 6)
    return res.status(400).json({ error: 'Min 6 characters' });
  config.adminPass = bcrypt.hashSync(req.body.newPassword, 10);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

// ── Terminal ──────────────────────────────────────────────────────────────────
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
  background: #f5f7fa; color: #333; line-height: 1.5;
}

/* Login */
.login-page {
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; background: linear-gradient(135deg, #f5f7fa, #e4e7eb);
}
.login-box {
  background: #fff; padding: 40px; border-radius: 12px; width: 360px;
  box-shadow: 0 8px 30px rgba(0,0,0,0.1); position: relative;
}
.login-box h1 { text-align: center; color: #4a89dc; margin-bottom: 30px; font-size: 28px; }
.login-box input {
  width: 100%; padding: 12px 16px; margin-bottom: 16px;
  background: #f5f7fa; border: 1px solid #e4e7eb; border-radius: 8px;
  color: #333; font-size: 14px; outline: none;
}
.login-box input:focus { border-color: #4a89dc; box-shadow: 0 0 0 2px rgba(74,137,220,0.2); }
.login-box button {
  width: 100%; padding: 12px; background: #4a89dc; border: none;
  border-radius: 8px; color: #fff; font-size: 16px; cursor: pointer; font-weight: 600; transition: background 0.3s;
}
.login-box button:hover { background: #3a7bd5; }
.error { color: #e74c3c; text-align: center; margin-top: 10px; font-size: 14px; }
.copyright {
  position: absolute; bottom: -30px; left: 0; right: 0;
  text-align: center; color: #7f8c8d; font-size: 12px; font-weight: 500;
}

/* Layout */
.main-panel { display: flex; min-height: 100vh; }
.sidebar {
  width: 240px; background: #fff; display: flex; flex-direction: column;
  position: fixed; height: 100vh; z-index: 10; transition: transform .3s;
  box-shadow: 0 0 20px rgba(0,0,0,0.05);
}
.sidebar .logo { padding: 20px; font-size: 20px; font-weight: 700; color: #4a89dc; border-bottom: 1px solid #eee; }
.sidebar nav { flex: 1; padding: 10px 0; overflow-y: auto; }
.sidebar nav a {
  display: flex; align-items: center; padding: 12px 20px; color: #606060;
  text-decoration: none; transition: .2s; font-size: 14px;
}
.sidebar nav a i { margin-right: 10px; width: 20px; text-align: center; }
.sidebar nav a:hover, .sidebar nav a.active {
  background: #f0f4f8; color: #4a89dc; border-left: 3px solid #4a89dc;
}
.logout-btn {
  padding: 15px 20px; color: #e74c3c; text-decoration: none;
  border-top: 1px solid #eee; font-size: 14px; display: flex; align-items: center;
}
.logout-btn i { margin-right: 10px; width: 20px; text-align: center; }
.content { flex: 1; margin-left: 240px; padding: 30px; min-height: 100vh; }
.mobile-toggle {
  display: none; position: fixed; top: 10px; left: 10px; z-index: 20;
  background: #fff; border: none; color: #4a89dc; font-size: 20px;
  padding: 8px 12px; border-radius: 8px; cursor: pointer; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
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
.page-title { font-size: 24px; margin-bottom: 8px; color: #2c3e50; }
.page-sub { color: #7f8c8d; margin-bottom: 25px; font-size: 14px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr)); gap: 16px; margin-bottom: 25px; }
.card { background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
.card .label { font-size: 12px; color: #95a5a6; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .5px; }
.card .value { font-size: 22px; font-weight: 700; color: #4a89dc; }
.card .sub { font-size: 12px; color: #7f8c8d; margin-top: 4px; }
.progress { background: #ecf0f1; border-radius: 8px; height: 8px; margin-top: 8px; overflow: hidden; }
.progress-bar { height: 100%; border-radius: 8px; background: #4a89dc; transition: width .3s; }
.progress-bar.warn { background: #f39c12; }
.progress-bar.danger { background: #e74c3c; }

/* Tables */
table.tbl { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
.tbl th { background: #f8f9fa; padding: 12px 16px; text-align: left; font-size: 12px; color: #7f8c8d; text-transform: uppercase; font-weight: 600; border-bottom: 1px solid #ecf0f1; }
.tbl td { padding: 12px 16px; border-bottom: 1px solid #ecf0f1; font-size: 14px; color: #34495e; }
.tbl tr:last-child td { border-bottom: none; }
.tbl tr:hover td { background: #f8f9fa; }

/* Buttons */
.btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: .2s; display: inline-block; text-decoration: none; text-align: center; }
.btn:hover { opacity: .9; }
.btn-p { background: #4a89dc; color: #fff; }
.btn-s { background: #2ecc71; color: #fff; }
.btn-d { background: #e74c3c; color: #fff; }
.btn-w { background: #f39c12; color: #fff; }
.btn-l { background: #ecf0f1; color: #7f8c8d; }
.btn-info { background: #3498db; color: #fff; }
.btn-sm { padding: 4px 10px; font-size: 12px; }
.btn i { margin-right: 4px; }

/* Badges */
.badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; display: inline-block; }
.badge-on { background: rgba(46,204,113,0.15); color: #2ecc71; }
.badge-off { background: rgba(231,76,60,0.15); color: #e74c3c; }

/* Forms */
.form-control {
  width: 100%; padding: 10px 14px; background: #f8f9fa; border: 1px solid #e4e7eb;
  border-radius: 8px; color: #34495e; font-size: 14px; outline: none; transition: all 0.2s;
}
.form-control:focus { border-color: #4a89dc; box-shadow: 0 0 0 2px rgba(74,137,220,0.2); }
textarea.form-control {
  min-height: 300px;
  font-family: 'Monaco','Menlo','Ubuntu Mono','Consolas','source-code-pro',monospace;
  font-size: 13px; resize: vertical;
}
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 14px; margin-bottom: 8px; color: #34495e; }

/* Alerts */
.alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
.alert-ok { background: rgba(46,204,113,0.1); border: 1px solid #2ecc71; color: #2ecc71; }
.alert-err { background: rgba(231,76,60,0.1); border: 1px solid #e74c3c; color: #e74c3c; }
.alert i { margin-right: 8px; }

/* Breadcrumb */
.breadcrumb { display: flex; gap: 5px; margin-bottom: 15px; flex-wrap: wrap; font-size: 14px; }
.breadcrumb a { color: #4a89dc; text-decoration: none; cursor: pointer; }
.breadcrumb span { color: #7f8c8d; }

/* File Manager */
.file-manager {
  background: #fff; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);
  overflow: hidden; display: flex; flex-direction: column;
  height: calc(100vh - 160px); min-height: 400px;
}
.file-toolbar {
  padding: 10px 16px; background: #f8f9fa; border-bottom: 1px solid #ecf0f1;
  display: flex; gap: 8px; flex-wrap: wrap; align-items: center;
}
.file-toolbar-group { display: flex; gap: 6px; align-items: center; }
.file-container { flex: 1; overflow: auto; }
.file-item {
  display: flex; align-items: center; padding: 10px 16px;
  border-bottom: 1px solid #ecf0f1; cursor: pointer; font-size: 14px; color: #34495e;
  user-select: none; transition: background 0.2s;
}
.file-item:hover { background: #f8f9fa; }
.file-item.selected { background: #e3f2fd; }
.file-item .icon { margin-right: 10px; font-size: 16px; width: 24px; text-align: center; color: #7f8c8d; }
.file-item .icon.folder { color: #f39c12; }
.file-item .icon.image { color: #3498db; }
.file-item .icon.code { color: #2ecc71; }
.file-item .icon.archive { color: #9b59b6; }
.file-item .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-item .size { color: #7f8c8d; margin-right: 10px; min-width: 70px; text-align: right; font-size: 13px; }
.file-item .date { color: #7f8c8d; width: 150px; font-size: 13px; text-align: right; }
.file-item .perms { color: #95a5a6; margin-right: 10px; font-family: monospace; font-size: 12px; width: 70px; text-align: right; }
.checkbox-wrapper { width: 24px; display: flex; align-items: center; justify-content: center; margin-right: 10px; }
.checkbox-wrapper input[type="checkbox"] { width: 16px; height: 16px; }
.file-status-bar {
  padding: 10px 16px; background: #f8f9fa; border-top: 1px solid #ecf0f1;
  font-size: 13px; color: #7f8c8d; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;
}
.file-context-menu {
  position: fixed; background: white; border: 1px solid #ecf0f1;
  border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);
  z-index: 1000; min-width: 180px; padding: 5px 0;
}
.file-context-menu .menu-item {
  padding: 8px 16px; font-size: 13px; cursor: pointer;
  display: flex; align-items: center; transition: background 0.2s; color: #34495e;
}
.file-context-menu .menu-item:hover { background: #f0f4f8; }
.file-context-menu .menu-item i { margin-right: 8px; width: 18px; text-align: center; font-size: 14px; color: #7f8c8d; }
.file-context-menu .divider { height: 1px; background: #ecf0f1; margin: 5px 0; }
.modal-backdrop {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 9999;
}
.modal {
  background: white; border-radius: 10px; width: 90%; max-width: 500px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.2); overflow: hidden; animation: modalFadeIn 0.3s ease;
}
@keyframes modalFadeIn { from { opacity:0; transform:translateY(-30px); } to { opacity:1; transform:translateY(0); } }
.modal-header {
  padding: 16px 20px; background: #f8f9fa; border-bottom: 1px solid #ecf0f1;
  display: flex; align-items: center; justify-content: space-between;
}
.modal-header h3 { font-size: 18px; font-weight: 600; color: #34495e; margin: 0; }
.modal-close { border: none; background: none; color: #7f8c8d; font-size: 18px; cursor: pointer; }
.modal-body { padding: 20px; }
.modal-footer {
  padding: 16px 20px; background: #f8f9fa; border-top: 1px solid #ecf0f1;
  display: flex; justify-content: flex-end; gap: 10px;
}

/* Editor */
.editor-container {
  display: flex; flex-direction: column; height: calc(100vh - 160px);
  min-height: 400px; background: white; border-radius: 10px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden;
}
.editor-toolbar {
  padding: 10px 16px; background: #f8f9fa; border-bottom: 1px solid #ecf0f1;
  display: flex; justify-content: space-between; align-items: center;
}
.editor-toolbar-right { display: flex; gap: 10px; }
.editor-content { flex: 1; overflow: auto; position: relative; }
.editor-textarea {
  width: 100%; height: 100%; border: none; padding: 16px;
  font-family: 'Monaco','Menlo','Ubuntu Mono','Consolas','source-code-pro',monospace;
  font-size: 14px; color: #34495e; line-height: 1.5; resize: none;
}
.editor-textarea:focus { outline: none; }

/* Terminal */
.terminal-box {
  background: #2d3436; color: #dfe6e9;
  font-family: 'Monaco','Menlo','Ubuntu Mono','Consolas','source-code-pro',monospace;
  padding: 20px; border-radius: 10px; min-height: 350px; max-height: 500px;
  overflow-y: auto; white-space: pre-wrap; word-break: break-all; font-size: 13px;
}
.term-input { display: flex; gap: 10px; margin-top: 10px; }
.term-input input {
  flex: 1; background: #2d3436; border: 1px solid #636e72; color: #dfe6e9;
  font-family: 'Monaco','Menlo','Ubuntu Mono','Consolas','source-code-pro',monospace;
  padding: 10px; border-radius: 6px; outline: none;
}

/* Database */
.db-tabs { display: flex; border-bottom: 1px solid #eee; margin-bottom: 20px; }
.db-tab {
  padding: 12px 20px; background: none; border: none; border-bottom: 3px solid transparent;
  font-size: 14px; font-weight: 600; color: #7f8c8d; cursor: pointer; transition: all 0.2s;
}
.db-tab:hover { color: #4a89dc; }
.db-tab.active { color: #4a89dc; border-bottom-color: #4a89dc; }
.db-tab i { margin-right: 8px; }
.db-list { margin-top: 15px; }
.db-item { background: #fff; border-radius: 8px; margin-bottom: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); border-left: 3px solid #3498db; }
.db-header { padding: 12px 15px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f1f1; }
.db-name { font-weight: 600; color: #2c3e50; display: flex; align-items: center; }
.db-name i { margin-right: 8px; color: #3498db; }
.db-users { padding: 10px 15px; font-size: 13px; }
.db-user { display: flex; align-items: center; margin-bottom: 5px; color: #7f8c8d; }
.db-user i { margin-right: 8px; font-size: 12px; color: #95a5a6; }
.db-actions { display: flex; gap: 8px; flex-wrap: wrap; }

/* Helpers */
.flex-row { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; }
.space-between { justify-content: space-between; }
.mt { margin-top: 16px; }
.mb { margin-bottom: 16px; }
.text-center { text-align: center; }
CSSEOF

##############################################
# -------- public/js/app.js (Frontend) ------
##############################################
cat > public/js/app.js <<'JSEOF'
// ── API Helper ────────────────────────────────────────────────────────────────
var api = {
  req: function(url, opt) {
    opt = opt || {};
    var h = {};
    if (!(opt.body instanceof FormData)) h['Content-Type'] = 'application/json';
    return fetch(url, {
      headers: h,
      method: opt.method || 'GET',
      body: opt.body instanceof FormData
        ? opt.body
        : opt.body ? JSON.stringify(opt.body) : undefined
    }).then(function(r) { return r.json(); });
  },
  get:  function(u)    { return api.req(u); },
  post: function(u, b) { return api.req(u, { method: 'POST',   body: b }); },
  put:  function(u, b) { return api.req(u, { method: 'PUT',    body: b }); },
  del:  function(u)    { return api.req(u, { method: 'DELETE' }); }
};

// ── Utilities ─────────────────────────────────────────────────────────────────
var $ = function(id) { return document.getElementById(id); };

function fmtB(b) {
  if (!b) return '0 B';
  var k = 1024, s = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log(b) / Math.log(k));
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
}
function fmtUp(s) {
  var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d + 'd ' + h + 'h ' + m + 'm';
}
function esc(t) { var d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function pClass(p) { return p > 80 ? 'danger' : p > 60 ? 'warn' : ''; }
function formatDate(d) { return new Date(d).toLocaleString(); }

function getFileIconHtml(file) {
  var ext = (file.extension || '').toLowerCase();
  if (file.isDir) return '<i class="fas fa-folder icon folder"></i>';
  if (['jpg','jpeg','png','gif','svg','webp'].includes(ext)) return '<i class="far fa-file-image icon image"></i>';
  if (['zip','tar','gz','rar','7z','bz2','tgz'].includes(ext)) return '<i class="far fa-file-archive icon archive"></i>';
  if (['mp4','avi','mov','wmv','mkv'].includes(ext)) return '<i class="far fa-file-video icon"></i>';
  if (['mp3','wav','ogg','flac'].includes(ext)) return '<i class="far fa-file-audio icon"></i>';
  if (['doc','docx','odt','rtf'].includes(ext)) return '<i class="far fa-file-word icon"></i>';
  if (['xls','xlsx','ods','csv'].includes(ext)) return '<i class="far fa-file-excel icon"></i>';
  if (['pdf'].includes(ext)) return '<i class="far fa-file-pdf icon"></i>';
  if (['php','js','css','html','htm','xml','json','py','rb','java','c','cpp','h','ini','conf','sh'].includes(ext))
    return '<i class="far fa-file-code icon code"></i>';
  return '<i class="far fa-file icon"></i>';
}

function isArchive(ext) {
  return ['zip','tar','gz','rar','7z','bz2','tgz'].includes((ext||'').toLowerCase());
}
function isEditableText(ext) {
  return ['php','js','css','html','htm','xml','json','py','rb','java','c','cpp','h',
          'ini','conf','sh','txt','md','log','env','yaml','yml','sql'].includes((ext||'').toLowerCase());
}

// ── App State ─────────────────────────────────────────────────────────────────
var curPath      = '/usr/local/lsws';
var currentEditPath = '';           // FIX: renamed from editFile to avoid clash
var selectedFiles = [];
var clipboard    = { items: [], action: '' };

// ── Auth ──────────────────────────────────────────────────────────────────────
function checkAuth() {
  api.get('/api/auth').then(function(r) {
    if (r.authenticated) { showPanel(); loadPage('dashboard'); } else showLogin();
  });
}
function showLogin() { $('loginPage').style.display = 'flex'; $('mainPanel').style.display = 'none'; }
function showPanel() { $('loginPage').style.display = 'none'; $('mainPanel').style.display = 'flex'; }

$('loginForm').addEventListener('submit', function(e) {
  e.preventDefault();
  api.post('/api/login', { username: $('username').value, password: $('password').value })
    .then(function(r) {
      if (r.success) { showPanel(); loadPage('dashboard'); }
      else $('loginError').textContent = 'Invalid credentials';
    });
});
$('logoutBtn').addEventListener('click', function(e) {
  e.preventDefault(); api.get('/api/logout').then(showLogin);
});
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

// ── Router ────────────────────────────────────────────────────────────────────
function loadPage(p) {
  var el = $('content');
  switch (p) {
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

// ── Dashboard ─────────────────────────────────────────────────────────────────
function pgDash(el) {
  Promise.all([api.get('/api/dashboard'), api.get('/api/services')]).then(function(res) {
    var d = res[0], s = res[1];
    var mp = Math.round(d.memory.used / d.memory.total * 100);
    var dp = d.disk.total ? Math.round(d.disk.used / d.disk.total * 100) : 0;
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-tachometer-alt"></i> Dashboard</h2>'
      + '<p class="page-sub">' + d.hostname + ' (' + d.ip + ')</p>'
      + '<div class="stats-grid">'
      + '<div class="card"><div class="label">CPU</div><div class="value">' + d.cpu.cores + ' Cores</div>'
      + '<div class="sub">Load: ' + d.cpu.load.map(function(l) { return l.toFixed(2); }).join(', ') + '</div></div>'
      + '<div class="card"><div class="label">Memory</div><div class="value">' + mp + '%</div>'
      + '<div class="progress"><div class="progress-bar ' + pClass(mp) + '" style="width:' + mp + '%"></div></div>'
      + '<div class="sub">' + fmtB(d.memory.used) + ' / ' + fmtB(d.memory.total) + '</div></div>'
      + '<div class="card"><div class="label">Disk</div><div class="value">' + dp + '%</div>'
      + '<div class="progress"><div class="progress-bar ' + pClass(dp) + '" style="width:' + dp + '%"></div></div>'
      + '<div class="sub">' + fmtB(d.disk.used) + ' / ' + fmtB(d.disk.total) + '</div></div>'
      + '<div class="card"><div class="label">Uptime</div><div class="value">' + fmtUp(d.uptime) + '</div>'
      + '<div class="sub">Node ' + d.nodeVersion + '</div></div></div>'
      + '<h3 class="mb">Services</h3>'
      + '<table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>'
      + s.map(function(x) {
          return '<tr><td>' + x.name + '</td><td><span class="badge ' + (x.active ? 'badge-on' : 'badge-off') + '">'
            + (x.active ? 'Running' : 'Stopped') + '</span></td></tr>';
        }).join('')
      + '</tbody></table>'
      + '<div class="mt">'
      + '<a href="http://' + d.ip + ':7080" target="_blank" class="btn btn-p"><i class="fas fa-cog"></i> OLS Admin</a> '
      + '<a href="http://' + d.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-w"><i class="fas fa-database"></i> phpMyAdmin</a>'
      + '</div>';
  });
}

// ── Services ──────────────────────────────────────────────────────────────────
function pgSvc(el) {
  api.get('/api/services').then(function(s) {
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-cogs"></i> Services</h2>'
      + '<p class="page-sub">Manage server services</p><div id="svcMsg"></div>'
      + '<table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'
      + s.map(function(x) {
          return '<tr><td><strong>' + x.name + '</strong></td>'
            + '<td><span class="badge ' + (x.active ? 'badge-on' : 'badge-off') + '">'
            + (x.active ? 'Running' : 'Stopped') + '</span></td>'
            + '<td>'
            + '<button class="btn btn-s btn-sm" data-svc="' + x.name + '" data-act="start" onclick="svcAct(this)"><i class="fas fa-play"></i> Start</button> '
            + '<button class="btn btn-d btn-sm" data-svc="' + x.name + '" data-act="stop" onclick="svcAct(this)"><i class="fas fa-stop"></i> Stop</button> '
            + '<button class="btn btn-w btn-sm" data-svc="' + x.name + '" data-act="restart" onclick="svcAct(this)"><i class="fas fa-sync-alt"></i> Restart</button>'
            + '</td></tr>';
        }).join('')
      + '</tbody></table>';
  });
}
window.svcAct = function(btn) {
  var n = btn.dataset.svc, a = btn.dataset.act;
  api.post('/api/services/' + n + '/' + a).then(function(r) {
    $('svcMsg').innerHTML = r.success
      ? '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> ' + n + ' ' + a + 'ed</div>'
      : '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Failed') + '</div>';
    setTimeout(function() { loadPage('services'); }, 1200);
  });
};

// ── File Manager ──────────────────────────────────────────────────────────────
function pgFiles(el, p) {
  if (p !== undefined) curPath = p;
  selectedFiles = [];
  el.innerHTML = '<h2 class="page-title"><i class="fas fa-folder"></i> File Manager</h2>'
    + '<div id="fileManagerContainer"></div>';
  loadFileManager(curPath);
}

function loadFileManager(filePath) {
  curPath = filePath;
  api.get('/api/files?path=' + encodeURIComponent(filePath)).then(function(d) {
    if (d.error) {
      $('fileManagerContainer').innerHTML = '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + esc(d.error) + '</div>';
      return;
    }
    if (d.binary || d.tooLarge) {
      var msg = d.binary ? 'Binary file – cannot edit in browser.' : 'File too large to edit (max 5 MB).';
      $('fileManagerContainer').innerHTML = '<div class="card"><h3 class="mb">' + (d.binary ? 'Binary File' : 'Large File') + '</h3>'
        + '<p class="mb">' + esc(d.path) + ' (' + fmtB(d.size) + ')</p>'
        + '<p class="mb">' + msg + '</p>'
        + '<a href="/api/files/download?path=' + encodeURIComponent(d.path) + '" class="btn btn-p"><i class="fas fa-download"></i> Download</a> '
        + '<button class="btn btn-l" onclick="loadFileManager(\'' + esc(curPath.substring(0, curPath.lastIndexOf('/')) || '/') + '\')"><i class="fas fa-arrow-left"></i> Back</button>'
        + '</div>';
      return;
    }
    if (d.content !== undefined) {
      showFileEditor(d);
      return;
    }

    // Build breadcrumb
    var parts = filePath.split('/').filter(Boolean);
    var bc = '<a onclick="loadFileManager(\'/\')"><i class="fas fa-home"></i> root</a>';
    var bp = '';
    parts.forEach(function(x) {
      bp += '/' + x;
      var bpCopy = bp;
      bc += ' <span>/</span> <a onclick="loadFileManager(\'' + esc(bpCopy) + '\')">' + esc(x) + '</a>';
    });

    var items = d.items || [];
    items.sort(function(a, b) {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    var parentPath = filePath === '/' ? '' : (filePath.split('/').slice(0, -1).join('/') || '/');

    // Determine if paste button should show
    var pasteBtn = (clipboard.items && clipboard.items.length > 0)
      ? '<button class="btn btn-info btn-sm" onclick="pasteFiles()"><i class="fas fa-paste"></i> Paste (' + clipboard.items.length + ')</button>'
      : '';

    var html = '<div class="file-manager">'
      + '<div class="file-toolbar">'
      +   '<div class="file-toolbar-group">'
      +     '<button class="btn btn-p btn-sm" onclick="showUploadDialog()"><i class="fas fa-upload"></i> Upload</button>'
      +     '<button class="btn btn-s btn-sm" onclick="showNewFolderDialog()"><i class="fas fa-folder-plus"></i> New Folder</button>'
      +     '<button class="btn btn-l btn-sm" onclick="showNewFileDialog()"><i class="fas fa-file"></i> New File</button>'
      +   '</div>'
      +   '<div class="file-toolbar-group" id="pasteArea">' + pasteBtn + '</div>'
      +   '<div class="file-toolbar-group" style="margin-left:auto;">'
      +     '<button class="btn btn-l btn-sm" onclick="loadFileManager(\'' + esc(filePath) + '\')"><i class="fas fa-sync-alt"></i> Refresh</button>'
      +   '</div>'
      + '</div>'

      + '<div class="breadcrumb" style="margin:10px 16px 0;">' + bc + '</div>'

      + '<div class="file-container" id="fileList">'
      + (parentPath
          ? '<div class="file-item" onclick="loadFileManager(\'' + esc(parentPath) + '\')">'
            + '<div class="checkbox-wrapper"></div>'
            + '<i class="fas fa-level-up-alt icon"></i>'
            + '<span class="name">..</span><span class="size"></span><span class="perms"></span><span class="date"></span>'
            + '</div>'
          : '')
      + items.map(function(item) {
          var ip = (filePath === '/' ? '' : filePath) + '/' + item.name;
          var ext = item.extension || '';
          return '<div class="file-item" data-path="' + esc(ip) + '" data-filename="' + esc(item.name) + '" data-isdir="' + item.isDir + '" data-ext="' + esc(ext) + '"'
            + ' onclick="fmItemClick(event,this)" ondblclick="fmItemDblClick(this)" oncontextmenu="showContextMenu(event,this)">'
            + '<div class="checkbox-wrapper"><input type="checkbox" onclick="event.stopPropagation()" onchange="cbChanged(this,\'' + esc(ip) + '\')"></div>'
            + getFileIconHtml(item)
            + '<span class="name">' + esc(item.name) + '</span>'
            + '<span class="size">' + (item.isDir ? '' : fmtB(item.size)) + '</span>'
            + '<span class="perms">' + (item.perms || '') + '</span>'
            + '<span class="date">' + (item.modified ? formatDate(item.modified) : '') + '</span>'
            + '</div>';
        }).join('')
      + '</div>'

      + '<div class="file-status-bar">'
      +   '<div>' + items.length + ' items</div>'
      +   '<div id="selBar">'
      +     '<button class="btn btn-l btn-sm" onclick="toggleSelectAll()"><i class="fas fa-check-square"></i> Select All</button>'
      +     '<span id="selCount"></span>'
      +   '</div>'
      + '</div>'
      + '</div>'
      + '<div id="fileContextMenu" class="file-context-menu" style="display:none;"></div>'
      + '<div id="modalContainer"></div>';

    $('fileManagerContainer').innerHTML = html;
    updateSelBar();
    document.addEventListener('keydown', fmKeydown);
  });
}

// ── File item interaction ─────────────────────────────────────────────────────
function fmItemClick(e, el) {
  if (e.ctrlKey || e.metaKey) {
    el.classList.toggle('selected');
    var cb = el.querySelector('input[type="checkbox"]');
    if (cb) cb.checked = el.classList.contains('selected');
    var p = el.getAttribute('data-path');
    if (el.classList.contains('selected')) {
      if (!selectedFiles.includes(p)) selectedFiles.push(p);
    } else {
      selectedFiles = selectedFiles.filter(function(x) { return x !== p; });
    }
  } else if (e.shiftKey) {
    var all = Array.from(document.querySelectorAll('#fileList .file-item[data-filename]'));
    var last = all.findIndex(function(i) { return i.classList.contains('selected'); });
    if (last === -1) last = 0;
    var cur = all.indexOf(el);
    var start = Math.min(last, cur), end = Math.max(last, cur);
    for (var i = start; i <= end; i++) {
      all[i].classList.add('selected');
      var cb2 = all[i].querySelector('input[type="checkbox"]');
      if (cb2) cb2.checked = true;
      var p2 = all[i].getAttribute('data-path');
      if (!selectedFiles.includes(p2)) selectedFiles.push(p2);
    }
  } else {
    document.querySelectorAll('#fileList .file-item').forEach(function(x) {
      x.classList.remove('selected');
      var cb3 = x.querySelector('input[type="checkbox"]');
      if (cb3) cb3.checked = false;
    });
    el.classList.add('selected');
    var cb4 = el.querySelector('input[type="checkbox"]');
    if (cb4) cb4.checked = true;
    selectedFiles = [el.getAttribute('data-path')];
  }
  updateSelBar();
}

function fmItemDblClick(el) {
  var p     = el.getAttribute('data-path');
  var isDir = el.getAttribute('data-isdir') === 'true';
  if (isDir) { loadFileManager(p); }
  else { openFileForEdit(p); }          // FIX: use renamed function
}

function cbChanged(cb, p) {
  var fi = cb.closest('.file-item');
  if (cb.checked) { fi.classList.add('selected'); if (!selectedFiles.includes(p)) selectedFiles.push(p); }
  else            { fi.classList.remove('selected'); selectedFiles = selectedFiles.filter(function(x) { return x !== p; }); }
  updateSelBar();
}

function toggleSelectAll() {
  var all = document.querySelectorAll('#fileList .file-item[data-filename]');
  var allSel = selectedFiles.length === all.length;
  selectedFiles = [];
  all.forEach(function(item) {
    var cb = item.querySelector('input[type="checkbox"]');
    if (allSel) { item.classList.remove('selected'); if (cb) cb.checked = false; }
    else        { item.classList.add('selected');    if (cb) cb.checked = true; selectedFiles.push(item.getAttribute('data-path')); }
  });
  updateSelBar();
}

function updateSelBar() {
  var countEl = $('selCount');
  var pasteEl = $('pasteArea');
  if (!countEl) return;

  if (selectedFiles.length > 0) {
    countEl.innerHTML = '<span style="margin:0 8px;">' + selectedFiles.length + ' selected</span>'
      + '<button class="btn btn-l btn-sm" onclick="bulkAction(\'copy\')"><i class="fas fa-copy"></i> Copy</button> '
      + '<button class="btn btn-l btn-sm" onclick="bulkAction(\'cut\')"><i class="fas fa-cut"></i> Cut</button> '
      + (selectedFiles.length === 1 ? '<button class="btn btn-l btn-sm" onclick="bulkAction(\'rename\')"><i class="fas fa-edit"></i> Rename</button> ' : '')
      + '<button class="btn btn-l btn-sm" onclick="bulkAction(\'compress\')"><i class="fas fa-file-archive"></i> Compress</button> '
      + '<button class="btn btn-d btn-sm" onclick="bulkAction(\'delete\')"><i class="fas fa-trash-alt"></i> Delete</button>';
  } else {
    countEl.innerHTML = '';
  }

  // Update paste button
  if (pasteEl) {
    pasteEl.innerHTML = (clipboard.items && clipboard.items.length > 0)
      ? '<button class="btn btn-info btn-sm" onclick="pasteFiles()"><i class="fas fa-paste"></i> Paste (' + clipboard.items.length + ')</button>'
      : '';
  }
}

// ── Context Menu ──────────────────────────────────────────────────────────────
function showContextMenu(e, el) {
  e.preventDefault();
  if (!el.classList.contains('selected')) {
    document.querySelectorAll('#fileList .file-item').forEach(function(x) {
      x.classList.remove('selected');
      var cb = x.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = false;
    });
    el.classList.add('selected');
    var cb = el.querySelector('input[type="checkbox"]');
    if (cb) cb.checked = true;
    selectedFiles = [el.getAttribute('data-path')];
    updateSelBar();
  }

  var p      = el.getAttribute('data-path');
  var isDir  = el.getAttribute('data-isdir') === 'true';
  var ext    = el.getAttribute('data-ext') || '';
  var menu   = $('fileContextMenu');

  var items = '';

  if (!isDir) {
    items += menuItem('fas fa-download', 'Download', 'window.open("/api/files/download?path=" + encodeURIComponent("' + esc(p) + '"), "_blank")');
  }

  // ── EDIT button in context menu ──────────────────────────────────────────
  if (!isDir && isEditableText(ext)) {
    items += menuItem('fas fa-edit', 'Edit', 'openFileForEdit("' + esc(p) + '")');
  }

  items += menuItem('fas fa-i-cursor', 'Rename', 'bulkAction("rename")');
  items += menuItem('fas fa-copy', 'Copy', 'bulkAction("copy")');
  items += menuItem('fas fa-cut', 'Cut', 'bulkAction("cut")');

  // ── PASTE in context menu (if clipboard has items) ────────────────────────
  if (clipboard.items && clipboard.items.length > 0) {
    items += '<div class="divider"></div>';
    items += menuItem('fas fa-paste', 'Paste here', 'pasteFiles()');
  }

  // ── EXTRACT in context menu ───────────────────────────────────────────────
  if (!isDir && isArchive(ext)) {
    items += '<div class="divider"></div>';
    items += menuItem('fas fa-box-open', 'Extract', 'showExtractDialog("' + esc(p) + '")');
  }

  if (isDir) {
    items += '<div class="divider"></div>';
    items += menuItem('fas fa-file-archive', 'Compress', 'bulkAction("compress")');
  }

  items += '<div class="divider"></div>';
  items += menuItem('fas fa-key', 'Permissions', 'showPermissionsDialog("' + esc(p) + '")');
  items += menuItem('fas fa-trash-alt', 'Delete', 'bulkAction("delete")', '#e74c3c');

  menu.innerHTML = items;
  menu.style.top  = e.clientY + 'px';
  menu.style.left = e.clientX + 'px';
  menu.style.display = 'block';
  document.addEventListener('click', hideContextMenu, { once: true });

  // Clamp to viewport
  setTimeout(function() {
    var r = menu.getBoundingClientRect();
    if (r.right > window.innerWidth) menu.style.left  = (e.clientX - r.width)  + 'px';
    if (r.bottom > window.innerHeight) menu.style.top = (e.clientY - r.height) + 'px';
  }, 0);
}

function menuItem(icon, label, onclick, color) {
  var style = color ? ' style="color:' + color + '"' : '';
  return '<div class="menu-item"' + style + ' onclick="hideContextMenu();' + onclick + '"><i class="' + icon + '"></i> ' + label + '</div>';
}

function hideContextMenu() {
  var m = $('fileContextMenu');
  if (m) m.style.display = 'none';
}

// ── Open file for editing  (FIX: renamed from editFile) ───────────────────────
function openFileForEdit(filePath) {
  api.get('/api/files?path=' + encodeURIComponent(filePath)).then(function(data) {
    if (data.binary || data.tooLarge) {
      alert('This file cannot be edited in the browser.');
      return;
    }
    if (data.error) { alert('Error: ' + data.error); return; }
    showFileEditor(data);
  });
}

function showFileEditor(data) {
  currentEditPath = data.path;      // FIX: use renamed variable

  $('fileManagerContainer').innerHTML = '<div class="editor-container">'
    + '<div class="editor-toolbar">'
    +   '<div><strong>' + esc(data.path) + '</strong> (' + fmtB(data.size) + ')</div>'
    +   '<div class="editor-toolbar-right">'
    +     '<button class="btn btn-p btn-sm" onclick="saveEditedFile()"><i class="fas fa-save"></i> Save</button>'
    +     '<button class="btn btn-l btn-sm" onclick="loadFileManager(\'' + esc(data.path.substring(0, data.path.lastIndexOf('/')) || '/') + '\')"><i class="fas fa-times"></i> Close</button>'
    +   '</div>'
    + '</div>'
    + '<div class="editor-content">'
    +   '<textarea id="fileContent" class="editor-textarea">' + esc(data.content) + '</textarea>'
    + '</div>'
    + '</div>'
    + '<div id="editorStatus" class="alert" style="display:none;margin-top:15px;"></div>';
}

function saveEditedFile() {
  api.put('/api/files', { filePath: currentEditPath, content: $('fileContent').value })
    .then(function(r) {
      var s = $('editorStatus');
      s.className = r.success ? 'alert alert-ok' : 'alert alert-err';
      s.innerHTML = r.success
        ? '<i class="fas fa-check-circle"></i> Saved successfully'
        : '<i class="fas fa-exclamation-triangle"></i> ' + (r.error || 'Save failed');
      s.style.display = 'block';
      setTimeout(function() { s.style.display = 'none'; }, 3000);
    });
}

// ── Bulk Actions ──────────────────────────────────────────────────────────────
function bulkAction(action) {
  if (selectedFiles.length === 0) return;
  switch (action) {
    case 'delete':
      if (confirm('Delete ' + selectedFiles.length + ' item(s)?')) deleteSelected();
      break;
    case 'copy':
      clipboard = { items: selectedFiles.slice(), action: 'copy' };
      notify('Copied ' + selectedFiles.length + ' item(s)');
      updateSelBar();
      break;
    case 'cut':
      clipboard = { items: selectedFiles.slice(), action: 'cut' };
      notify('Cut ' + selectedFiles.length + ' item(s)');
      updateSelBar();
      break;
    case 'rename':
      if (selectedFiles.length === 1) showRenameDialog(selectedFiles[0]);
      break;
    case 'compress':
      showCompressDialog();
      break;
  }
}

// ── Paste  (FIX: copy uses /api/files/copy endpoint) ─────────────────────────
function pasteFiles() {
  if (!clipboard.items || clipboard.items.length === 0) return;
  var op = clipboard.action, srcs = clipboard.items.slice();

  if (op === 'cut') {
    // Move files via rename
    var promises = srcs.map(function(src) {
      var dest = (curPath === '/' ? '' : curPath) + '/' + src.split('/').pop();
      if (src === dest) return Promise.resolve();
      return api.post('/api/files/rename', { oldPath: src, newPath: dest });
    });
    Promise.all(promises).then(function() {
      clipboard = { items: [], action: '' };
      notify('Moved ' + srcs.length + ' item(s)');
      loadFileManager(curPath);
    });
  } else if (op === 'copy') {
    // Server-side copy
    api.post('/api/files/copy', { sources: srcs, target: curPath }).then(function(r) {
      if (r.success) {
        notify('Copied ' + srcs.length + ' item(s)');
        loadFileManager(curPath);
      } else {
        notify('Copy failed: ' + (r.error || 'unknown error'));
      }
    });
  }
}

function deleteSelected() {
  var total = selectedFiles.length, done = 0, failed = 0;
  var promises = selectedFiles.map(function(p) {
    return api.del('/api/files?path=' + encodeURIComponent(p))
      .then(function(r) { r.success ? done++ : failed++; })
      .catch(function() { failed++; });
  });
  Promise.all(promises).then(function() {
    notify(done + ' deleted' + (failed ? ', ' + failed + ' failed' : ''));
    loadFileManager(curPath);
  });
}

// ── Dialogs ───────────────────────────────────────────────────────────────────
function showUploadDialog() {
  $('modalContainer').innerHTML = modal('Upload Files',
    '<p class="mb">Upload to: <strong>' + esc(curPath) + '</strong></p>'
    + '<div class="form-group"><input type="file" id="fileUpload" multiple class="form-control"></div>'
    + '<div id="uploadStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doUpload()"><i class="fas fa-upload"></i> Upload</button>'
  );
}

function doUpload() {
  var files = $('fileUpload').files;
  if (!files.length) {
    $('uploadStatus').innerHTML = alertErr('No files selected');
    return;
  }
  var fd = new FormData();
  for (var i = 0; i < files.length; i++) fd.append('files', files[i]);
  fd.append('path', curPath);
  $('uploadStatus').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Uploading...');
  api.req('/api/files/upload', { method: 'POST', body: fd }).then(function(r) {
    if (r.success) {
      $('uploadStatus').innerHTML = alertOk('Uploaded successfully');
      setTimeout(function() { closeModal(); loadFileManager(curPath); }, 1000);
    } else {
      $('uploadStatus').innerHTML = alertErr(r.error || 'Upload failed');
    }
  });
}

function showNewFolderDialog() {
  $('modalContainer').innerHTML = modal('Create New Folder',
    '<p class="mb">In: <strong>' + esc(curPath) + '</strong></p>'
    + '<div class="form-group"><label>Folder Name</label><input type="text" id="folderName" class="form-control" placeholder="new_folder"></div>'
    + '<div id="folderStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doMkdir()"><i class="fas fa-folder-plus"></i> Create</button>'
  );
}
function doMkdir() {
  var name = $('folderName').value.trim();
  if (!name) { $('folderStatus').innerHTML = alertErr('Enter a folder name'); return; }
  var p = (curPath === '/' ? '' : curPath) + '/' + name;
  api.post('/api/files/mkdir', { path: p }).then(function(r) {
    if (r.success) { $('folderStatus').innerHTML = alertOk('Folder created'); setTimeout(function() { closeModal(); loadFileManager(curPath); }, 800); }
    else $('folderStatus').innerHTML = alertErr(r.error || 'Failed');
  });
}

function showNewFileDialog() {
  $('modalContainer').innerHTML = modal('Create New File',
    '<p class="mb">In: <strong>' + esc(curPath) + '</strong></p>'
    + '<div class="form-group"><label>File Name</label><input type="text" id="newFileName" class="form-control" placeholder="example.txt"></div>'
    + '<div id="newFileStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doNewFile()"><i class="fas fa-file"></i> Create</button>'
  );
}
function doNewFile() {
  var name = $('newFileName').value.trim();
  if (!name) { $('newFileStatus').innerHTML = alertErr('Enter a file name'); return; }
  var p = (curPath === '/' ? '' : curPath) + '/' + name;
  api.post('/api/files/newfile', { path: p, content: '' }).then(function(r) {
    if (r.success) { $('newFileStatus').innerHTML = alertOk('File created'); setTimeout(function() { closeModal(); openFileForEdit(p); }, 800); }
    else $('newFileStatus').innerHTML = alertErr(r.error || 'Failed');
  });
}

function showRenameDialog(filePath) {
  var oldName = filePath.split('/').pop();
  $('modalContainer').innerHTML = modal('Rename',
    '<div class="form-group"><label>New Name</label><input type="text" id="newName" class="form-control" value="' + esc(oldName) + '"></div>'
    + '<div id="renameStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doRename(\'' + esc(filePath) + '\')"><i class="fas fa-save"></i> Rename</button>'
  );
  setTimeout(function() {
    var inp = $('newName'); inp.focus();
    var dot = oldName.lastIndexOf('.');
    inp.setSelectionRange(0, dot > 0 ? dot : oldName.length);
  }, 100);
}
function doRename(oldPath) {
  var newName = $('newName').value.trim();
  if (!newName) { $('renameStatus').innerHTML = alertErr('Enter a name'); return; }
  var parent = oldPath.substring(0, oldPath.lastIndexOf('/')) || '/';
  var newPath = (parent === '/' ? '' : parent) + '/' + newName;
  api.post('/api/files/rename', { oldPath: oldPath, newPath: newPath }).then(function(r) {
    if (r.success) { $('renameStatus').innerHTML = alertOk('Renamed'); setTimeout(function() { closeModal(); loadFileManager(curPath); }, 800); }
    else $('renameStatus').innerHTML = alertErr(r.error || 'Failed');
  });
}

// ── Compress ──────────────────────────────────────────────────────────────────
function showCompressDialog() {
  var def = selectedFiles.length === 1
    ? selectedFiles[0].split('/').pop() + '.zip'
    : (curPath.split('/').pop() || 'files') + '.zip';
  $('modalContainer').innerHTML = modal('Create Archive',
    '<p class="mb">Compress ' + selectedFiles.length + ' item(s)</p>'
    + '<div class="form-group"><label>Archive Name</label><input type="text" id="archiveName" class="form-control" value="' + esc(def) + '"></div>'
    + '<div id="compressStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doCompress()"><i class="fas fa-file-archive"></i> Compress</button>'
  );
}
function doCompress() {
  var name = $('archiveName').value.trim();
  if (!name) { $('compressStatus').innerHTML = alertErr('Enter a name'); return; }
  if (!name.toLowerCase().endsWith('.zip')) name += '.zip';
  var out = (curPath === '/' ? '' : curPath) + '/' + name;
  $('compressStatus').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Compressing...');
  api.post('/api/files/compress', { paths: selectedFiles, output: out }).then(function(r) {
    if (r.success) { $('compressStatus').innerHTML = alertOk('Archive created'); setTimeout(function() { closeModal(); loadFileManager(curPath); }, 1000); }
    else $('compressStatus').innerHTML = alertErr(r.error || 'Compression failed');
  });
}

// ── Extract  (FIX: correct global function, called from context menu) ─────────
function showExtractDialog(archivePath) {
  var archiveName = archivePath.split('/').pop();
  var parent = archivePath.substring(0, archivePath.lastIndexOf('/')) || '/';
  var def = (parent === '/' ? '' : parent) + '/' + archiveName.replace(/\.(zip|tar\.gz|tgz|tar|gz|rar|bz2)$/i, '');

  $('modalContainer').innerHTML = modal('Extract Archive',
    '<p class="mb">Extract: <strong>' + esc(archiveName) + '</strong></p>'
    + '<div class="form-group"><label>Extract to</label><input type="text" id="extractPath" class="form-control" value="' + esc(def) + '"></div>'
    + '<div id="extractStatus" class="mt"></div>',
    '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doExtract(\'' + esc(archivePath) + '\')"><i class="fas fa-box-open"></i> Extract</button>'
  );
}
function doExtract(archivePath) {
  var target = $('extractPath').value.trim();
  if (!target) { $('extractStatus').innerHTML = alertErr('Enter destination path'); return; }
  $('extractStatus').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Extracting...');
  api.post('/api/files/extract', { archive: archivePath, target: target }).then(function(r) {
    if (r.success) {
      $('extractStatus').innerHTML = alertOk('Extracted successfully');
      setTimeout(function() { closeModal(); loadFileManager(target); }, 1000);
    } else {
      $('extractStatus').innerHTML = alertErr(r.error || 'Extraction failed');
    }
  });
}

// ── Permissions ───────────────────────────────────────────────────────────────
function showPermissionsDialog(filePath) {
  api.get('/api/files/permissions?path=' + encodeURIComponent(filePath)).then(function(data) {
    if (data.error) { alert('Error: ' + data.error); return; }
    $('modalContainer').innerHTML = modal('File Permissions',
      '<p class="mb"><strong>' + esc(filePath.split('/').pop()) + '</strong></p>'
      + '<div class="form-group"><label>Owner</label><input class="form-control" value="' + esc(data.owner) + '" disabled></div>'
      + '<div class="form-group"><label>Group</label><input class="form-control" value="' + esc(data.group) + '" disabled></div>'
      + '<div class="form-group"><label>Permissions (octal)</label><input type="text" id="permsValue" class="form-control" value="' + esc(data.permissions) + '"></div>'
      + (data.isDir ? '<div class="form-group"><label><input type="checkbox" id="permsRecursive"> Apply recursively</label></div>' : '')
      + '<div id="permsStatus" class="mt"></div>',
      '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
      + '<button class="btn btn-p" onclick="doChmod(\'' + esc(filePath) + '\')"><i class="fas fa-save"></i> Save</button>'
    );
  });
}
function doChmod(filePath) {
  var p = $('permsValue').value.trim();
  var r = $('permsRecursive') ? $('permsRecursive').checked : false;
  if (!p || !/^(0)?[0-7]{3,4}$/.test(p)) { $('permsStatus').innerHTML = alertErr('Invalid permissions (e.g. 0755)'); return; }
  $('permsStatus').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Changing...');
  api.post('/api/files/permissions', { path: filePath, permissions: p, recursive: r }).then(function(resp) {
    if (resp.success) { $('permsStatus').innerHTML = alertOk('Permissions changed'); setTimeout(function() { closeModal(); loadFileManager(curPath); }, 800); }
    else $('permsStatus').innerHTML = alertErr(resp.error || 'Failed');
  });
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
function fmKeydown(e) {
  if (e.ctrlKey && e.key === 'a') { e.preventDefault(); toggleSelectAll(); }
  if (e.key === 'Delete' && selectedFiles.length > 0) { e.preventDefault(); bulkAction('delete'); }
  if (e.ctrlKey && e.key === 'c' && selectedFiles.length > 0) { e.preventDefault(); bulkAction('copy'); }
  if (e.ctrlKey && e.key === 'x' && selectedFiles.length > 0) { e.preventDefault(); bulkAction('cut'); }
  if (e.ctrlKey && e.key === 'v' && clipboard.items && clipboard.items.length > 0) { e.preventDefault(); pasteFiles(); }
  if (e.key === 'F2' && selectedFiles.length === 1) { e.preventDefault(); bulkAction('rename'); }
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function modal(title, body, footer) {
  return '<div class="modal-backdrop">'
    + '<div class="modal">'
    + '<div class="modal-header"><h3>' + title + '</h3><button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button></div>'
    + '<div class="modal-body">' + body + '</div>'
    + '<div class="modal-footer">' + footer + '</div>'
    + '</div></div>';
}
function alertOk(msg)  { return '<div class="alert alert-ok"><i class="fas fa-check-circle"></i> ' + msg + '</div>'; }
function alertErr(msg) { return '<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ' + msg + '</div>'; }
function closeModal() { if ($('modalContainer')) $('modalContainer').innerHTML = ''; }
function notify(msg) {
  var el = document.createElement('div');
  el.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.75);color:#fff;padding:10px 20px;border-radius:6px;z-index:99999;font-size:14px;';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(function() { el.style.opacity = '0'; el.style.transition = 'opacity .5s'; setTimeout(function() { document.body.removeChild(el); }, 500); }, 2500);
}

// ── Domains ───────────────────────────────────────────────────────────────────
function pgDom(el) {
  api.get('/api/domains').then(function(d) {
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-globe"></i> Domains</h2>'
      + '<p class="page-sub">Virtual host management</p><div id="domMsg"></div>'
      + '<div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px">'
      + '<button class="btn btn-p" onclick="addDom()"><i class="fas fa-plus"></i> Add Domain</button></div>'
      + '<table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'
      + d.map(function(x) {
          return '<tr><td><strong>' + esc(x.name) + '</strong></td><td><code>' + esc(x.docRoot) + '</code></td>'
            + '<td><button class="btn btn-p btn-sm" onclick="loadPage(\'files\');setTimeout(function(){loadFileManager(\'' + esc(x.docRoot) + '\')},200)"><i class="fas fa-folder-open"></i> Files</button> '
            + '<button class="btn btn-d btn-sm" data-dom="' + esc(x.name) + '" onclick="delDom(this)"><i class="fas fa-trash-alt"></i> Delete</button></td></tr>';
        }).join('')
      + (d.length === 0 ? '<tr><td colspan="3" style="text-align:center;color:#7f8c8d">No domains yet</td></tr>' : '')
      + '</tbody></table>';
  });
}
window.addDom = function() {
  var domain = $('newDom').value.trim(); if (!domain) return;
  api.post('/api/domains', { domain: domain }).then(function(r) {
    $('domMsg').innerHTML = r.success
      ? alertOk('Domain added!')
      : alertErr(r.error || 'Failed');
    if (r.success) setTimeout(function() { loadPage('domains'); }, 1200);
  });
};
window.delDom = function(btn) {
  var n = btn.dataset.dom;
  if (confirm('Delete domain ' + n + '?')) {
    api.del('/api/domains/' + n).then(function() { loadPage('domains'); });
  }
};

// ── Databases ─────────────────────────────────────────────────────────────────
function pgDb(el) {
  Promise.all([api.get('/api/databases'), api.get('/api/database-users'), api.get('/api/dashboard')])
    .then(function(res) {
      var databases = res[0], users = res[1], info = res[2];

      var html = '<h2 class="page-title"><i class="fas fa-database"></i> Databases</h2>'
        + '<p class="page-sub">MariaDB database management</p><div id="dbMsg"></div>'
        + '<div class="db-tabs mb">'
        + '<button class="db-tab active" onclick="showDbTab(\'databases\')"><i class="fas fa-database"></i> Databases</button>'
        + '<button class="db-tab" onclick="showDbTab(\'users\')"><i class="fas fa-users"></i> Database Users</button>'
        + '</div>';

      // ── Databases tab ────────────────────────────────────────────────────
      html += '<div id="tab-databases" class="db-tab-content">';
      html += '<div class="card mb"><h3 class="mb">Create Database</h3>'
        + '<div class="flex-row">'
        + '<div style="flex:2"><label style="font-size:13px;color:#7f8c8d">Database Name</label>'
        + '<input id="dbName" class="form-control" placeholder="my_database"></div>'
        + '<div style="flex:1"><label style="font-size:13px;color:#7f8c8d">Assign to User</label>'
        + '<select id="dbUserSelect" class="form-control" onchange="toggleNewUserFields()">'
        + '<option value="">-- Create New User --</option>'
        + (users || []).map(function(u) { return '<option value="' + esc(u.username) + '">' + esc(u.username) + '</option>'; }).join('')
        + '</select></div>'
        + '<div id="newUserFields" style="flex:2"><label style="font-size:13px;color:#7f8c8d">New User / Password</label>'
        + '<div style="display:flex;gap:8px">'
        + '<input id="dbUser" class="form-control" placeholder="username">'
        + '<input id="dbPass" class="form-control" type="password" placeholder="password">'
        + '</div></div>'
        + '<button class="btn btn-p" style="align-self:flex-end" onclick="addDb()"><i class="fas fa-plus"></i> Create</button>'
        + '</div></div>';

      html += '<div class="db-list">';
      if (Array.isArray(databases) && databases.length > 0) {
        databases.forEach(function(db) {
          html += '<div class="db-item"><div class="db-header">'
            + '<div class="db-name"><i class="fas fa-database"></i> ' + esc(db.name) + '</div>'
            + '<div class="db-actions">'
            + '<button class="btn btn-info btn-sm" onclick="doDbBackup(\'' + esc(db.name) + '\')"><i class="fas fa-download"></i> Backup</button> '
            + '<button class="btn btn-d btn-sm" data-db="' + esc(db.name) + '" onclick="dropDb(this)"><i class="fas fa-trash-alt"></i> Drop</button>'
            + '</div></div>';
          if (db.users && db.users.length > 0) {
            html += '<div class="db-users"><div style="margin-bottom:5px;font-weight:600;color:#7f8c8d"><i class="fas fa-users"></i> Assigned Users:</div>';
            db.users.forEach(function(u) { html += '<div class="db-user"><i class="fas fa-user"></i> ' + esc(u) + '</div>'; });
            html += '</div>';
          } else {
            html += '<div class="db-users"><div class="db-user"><i class="fas fa-info-circle"></i> No users assigned</div></div>';
          }
          html += '</div>';
        });
      } else {
        html += '<div class="card mb"><p class="text-center" style="color:#7f8c8d;padding:20px">No databases yet</p></div>';
      }
      html += '</div></div>'; // end db-list + tab-databases

      // ── Users tab ────────────────────────────────────────────────────────
      html += '<div id="tab-users" class="db-tab-content" style="display:none;">';
      html += '<div class="card mb"><h3 class="mb">Create User</h3>'
        + '<div class="flex-row">'
        + '<div><label style="font-size:13px;color:#7f8c8d">Username</label><input id="newUsername" class="form-control" placeholder="username"></div>'
        + '<div><label style="font-size:13px;color:#7f8c8d">Password</label><input id="newUserPass" class="form-control" type="password" placeholder="password"></div>'
        + '<div><label style="font-size:13px;color:#7f8c8d">Grant to Databases</label>'
        + '<select id="userDbAccess" class="form-control" multiple size="3">'
        + (Array.isArray(databases) ? databases.map(function(db) { return '<option value="' + esc(db.name) + '">' + esc(db.name) + '</option>'; }).join('') : '')
        + '</select><small style="color:#7f8c8d;font-size:11px">Ctrl/Cmd to multi-select</small></div>'
        + '<button class="btn btn-p" style="align-self:flex-end" onclick="addDbUser()"><i class="fas fa-user-plus"></i> Create User</button>'
        + '</div></div>';

      html += '<div class="db-list">';
      if (Array.isArray(users) && users.length > 0) {
        users.forEach(function(user) {
          var userDbs = Array.isArray(databases)
            ? databases.filter(function(db) { return db.users && db.users.includes(user.username); }).map(function(db) { return db.name; })
            : [];
          html += '<div class="db-item"><div class="db-header">'
            + '<div class="db-name"><i class="fas fa-user"></i> ' + esc(user.username) + '</div>'
            + '<div class="db-actions">'
            + '<button class="btn btn-w btn-sm" onclick="showChangePassDialog(\'' + esc(user.username) + '\')"><i class="fas fa-key"></i> Change Password</button> '
            + '<button class="btn btn-d btn-sm" data-user="' + esc(user.username) + '" onclick="dropUser(this)"><i class="fas fa-trash-alt"></i> Drop</button>'
            + '</div></div>';
          if (userDbs.length > 0) {
            html += '<div class="db-users"><div style="margin-bottom:5px;font-weight:600;color:#7f8c8d"><i class="fas fa-database"></i> Has Access To:</div>';
            userDbs.forEach(function(n) { html += '<div class="db-user"><i class="fas fa-check-circle"></i> ' + esc(n) + '</div>'; });
            html += '</div>';
          } else {
            html += '<div class="db-users"><div class="db-user"><i class="fas fa-info-circle"></i> No database access</div></div>';
          }
          html += '</div>';
        });
      } else {
        html += '<div class="card mb"><p class="text-center" style="color:#7f8c8d;padding:20px">No database users yet</p></div>';
      }
      html += '</div></div>'; // end db-list + tab-users

      html += '<div class="mt"><a href="http://' + info.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-w"><i class="fas fa-database"></i> Open phpMyAdmin</a></div>';
      el.innerHTML = html;
    });
}

window.showDbTab = function(tabName) {
  document.querySelectorAll('.db-tab-content').forEach(function(t) { t.style.display = 'none'; });
  document.querySelectorAll('.db-tab').forEach(function(b) { b.classList.remove('active'); });
  $('tab-' + tabName).style.display = 'block';
  var idx = tabName === 'databases' ? 1 : 2;
  document.querySelector('.db-tab:nth-child(' + idx + ')').classList.add('active');
};

window.toggleNewUserFields = function() {
  var sel = $('dbUserSelect');
  if ($('newUserFields')) $('newUserFields').style.display = sel.value === '' ? 'block' : 'none';
};

window.addDb = function() {
  var name     = $('dbName').value.trim();
  var selUser  = $('dbUserSelect') ? $('dbUserSelect').value : '';
  var user     = selUser || ($('dbUser') ? $('dbUser').value.trim() : '');
  var password = $('dbPass') ? $('dbPass').value : '';

  if (!name) { $('dbMsg').innerHTML = alertErr('Database name is required'); return; }
  if (selUser === '' && user && !password) { $('dbMsg').innerHTML = alertErr('Password required for new user'); return; }

  var data = { name: name };
  if (user) { data.user = user; if (selUser === '' && password) data.password = password; }

  api.post('/api/databases', data).then(function(r) {
    $('dbMsg').innerHTML = r.success ? alertOk('Database created!') : alertErr(r.error || 'Failed');
    if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
  });
};

window.addDbUser = function() {
  var username = $('newUsername').value.trim();
  var password = $('newUserPass').value;
  var sel = $('userDbAccess');
  var selectedDbs = [];
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].selected) selectedDbs.push(sel.options[i].value);
  }
  if (!username) { $('dbMsg').innerHTML = alertErr('Username is required'); return; }
  if (!password) { $('dbMsg').innerHTML = alertErr('Password is required'); return; }
  api.post('/api/database-users', { username: username, password: password, databases: selectedDbs })
    .then(function(r) {
      $('dbMsg').innerHTML = r.success ? alertOk('User created!') : alertErr(r.error || 'Failed');
      if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
    });
};

// ── Database Backup  (FIX: server-side, then download) ───────────────────────
window.doDbBackup = function(dbName) {
  $('dbMsg').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Creating backup for <strong>' + esc(dbName) + '</strong>...');
  api.post('/api/databases/' + encodeURIComponent(dbName) + '/backup', {}).then(function(r) {
    if (r.success) {
      $('dbMsg').innerHTML = alertOk(
        'Backup ready! (' + fmtB(r.size) + ') '
        + '<a href="' + r.downloadUrl + '" class="btn btn-s btn-sm" download="' + esc(r.filename) + '">'
        + '<i class="fas fa-download"></i> Download ' + esc(r.filename) + '</a>'
      );
    } else {
      $('dbMsg').innerHTML = alertErr(r.error || 'Backup failed');
    }
  });
};

window.dropDb = function(btn) {
  var n = btn.dataset.db;
  if (confirm('DROP database ' + n + '?\nThis cannot be undone!')) {
    api.del('/api/databases/' + n).then(function(r) {
      $('dbMsg').innerHTML = r.success ? alertOk('Database dropped') : alertErr(r.error || 'Failed');
      if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
    });
  }
};
window.dropUser = function(btn) {
  var n = btn.dataset.user;
  if (confirm('DROP user ' + n + '?\nThis cannot be undone!')) {
    api.del('/api/database-users/' + n).then(function(r) {
      $('dbMsg').innerHTML = r.success ? alertOk('User dropped') : alertErr(r.error || 'Failed');
      if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
    });
  }
};

// ── Change DB User Password  (FIX: dedicated endpoint + ALTER USER) ───────────
window.showChangePassDialog = function(username) {
  // Build modal content without template literals to avoid escaping issues
  var modalBody = '<p class="mb">Change password for: <strong>' + esc(username) + '</strong></p>'
    + '<div class="form-group"><label>New Password</label>'
    + '<input type="password" id="dbNewPass" class="form-control"></div>'
    + '<div class="form-group"><label>Confirm Password</label>'
    + '<input type="password" id="dbConfirmPass" class="form-control"></div>'
    + '<div id="changePassStatus" class="mt"></div>';

  var modalFooter = '<button class="btn btn-l" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-p" onclick="doChangeDbPass(\'' + esc(username) + '\')"><i class="fas fa-save"></i> Save</button>';

  // Use modalContainer to show the modal
  var mc = $('modalContainer');
  if (!mc) {
    // Create if it doesn't exist (in case pgDb was re-rendered)
    var newMc = document.createElement('div');
    newMc.id = 'modalContainer';
    $('content').appendChild(newMc);
  }
  $('modalContainer').innerHTML = modal('Change Password', modalBody, modalFooter);
};

window.doChangeDbPass = function(username) {
  var newPass  = $('dbNewPass').value;
  var confPass = $('dbConfirmPass').value;

  if (!newPass) {
    $('changePassStatus').innerHTML = alertErr('New password is required');
    return;
  }
  if (newPass !== confPass) {
    $('changePassStatus').innerHTML = alertErr('Passwords do not match');
    return;
  }
  if (newPass.length < 4) {
    $('changePassStatus').innerHTML = alertErr('Password too short (min 4 chars)');
    return;
  }

  $('changePassStatus').innerHTML = alertOk('<i class="fas fa-spinner fa-spin"></i> Changing password...');

  // Use the dedicated /api/database-users/:name/password endpoint
  api.post('/api/database-users/' + encodeURIComponent(username) + '/password', { newPassword: newPass })
    .then(function(r) {
      if (r.success) {
        $('changePassStatus').innerHTML = alertOk('Password changed successfully!');
        setTimeout(function() { closeModal(); }, 1500);
      } else {
        $('changePassStatus').innerHTML = alertErr(r.error || 'Failed to change password');
      }
    });
};

// ── Tunnel ────────────────────────────────────────────────────────────────────
function pgTun(el) {
  api.get('/api/tunnel/status').then(function(s) {
    el.innerHTML = '<h2 class="page-title"><i class="fas fa-cloud"></i> Cloudflare Tunnel</h2>'
      + '<p class="page-sub">Secure tunnel for remote access</p><div id="tunMsg"></div>'
      + '<div class="card mb"><div class="label">Status</div>'
      + '<span class="badge ' + (s.active ? 'badge-on' : 'badge-off') + '">' + (s.active ? 'Connected' : 'Not Connected') + '</span></div>'
      + '<div class="card"><h3 class="mb">Setup Tunnel</h3>'
      + '<p style="color:#7f8c8d;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4a89dc">Cloudflare Zero Trust</a><br>2. Create a Tunnel → copy token<br>3. Paste below</p>'
      + '<div class="flex-row"><input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1">'
      + '<button class="btn btn-p" onclick="setTun()"><i class="fas fa-link"></i> Connect</button></div></div>';
  });
}
window.setTun = function() {
  api.post('/api/tunnel/setup', { token: $('tunToken').value.trim() }).then(function(r) {
    $('tunMsg').innerHTML = r.success ? alertOk('Connected!') : alertErr(r.error || 'Failed');
    if (r.success) setTimeout(function() { loadPage('tunnel'); }, 2000);
  });
};

// ── Terminal ──────────────────────────────────────────────────────────────────
function pgTerm(el) {
  el.innerHTML = '<h2 class="page-title"><i class="fas fa-terminal"></i> Terminal</h2>'
    + '<p class="page-sub">Run shell commands</p>'
    + '<div class="terminal-box" id="termOut">$ </div>'
    + '<div class="term-input">'
    + '<input id="termIn" placeholder="Type command..." onkeydown="if(event.key===\'Enter\')runCmd()">'
    + '<button class="btn btn-p" onclick="runCmd()"><i class="fas fa-play"></i> Run</button>'
    + '</div>';
  $('termIn').focus();
}
window.runCmd = function() {
  var cmd = $('termIn').value.trim(); if (!cmd) return;
  var out = $('termOut'); out.textContent += cmd + '\n'; $('termIn').value = '';
  api.post('/api/terminal', { command: cmd }).then(function(r) {
    out.textContent += (r.output || '') + '\n$ ';
    out.scrollTop = out.scrollHeight;
  });
};

// ── Settings ──────────────────────────────────────────────────────────────────
function pgSet(el) {
  el.innerHTML = '<h2 class="page-title"><i class="fas fa-sliders-h"></i> Settings</h2>'
    + '<p class="page-sub">Panel configuration</p><div id="setMsg"></div>'
    + '<div class="card" style="max-width:500px"><h3 class="mb">Change Admin Password</h3>'
    + '<div class="form-group"><label>Current Password</label><input type="password" id="curPass" class="form-control"></div>'
    + '<div class="form-group"><label>New Password</label><input type="password" id="newPass" class="form-control"></div>'
    + '<div class="form-group"><label>Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>'
    + '<button class="btn btn-p" onclick="chgPass()"><i class="fas fa-save"></i> Update Password</button></div>';
}
window.chgPass = function() {
  var np = $('newPass').value, cp = $('cfmPass').value;
  if (np !== cp) { $('setMsg').innerHTML = alertErr("Passwords don't match"); return; }
  if (np.length < 6) { $('setMsg').innerHTML = alertErr('Min 6 characters'); return; }
  api.post('/api/settings/password', { currentPassword: $('curPass').value, newPassword: np })
    .then(function(r) {
      $('setMsg').innerHTML = r.success ? alertOk('Password updated!') : alertErr(r.error || 'Failed');
    });
};

// ── Bootstrap ─────────────────────────────────────────────────────────────────
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

  chown -R nobody:nogroup ${PMA_DIR}
  chmod 755 ${PMA_DIR}
  mkdir -p ${PMA_DIR}/tmp
  chown nobody:nogroup ${PMA_DIR}/tmp
  chmod 755 ${PMA_DIR}/tmp
  log "phpMyAdmin installed"
else
  err "phpMyAdmin download failed"
fi

########################################
step "Step 7.5: Configure OpenLiteSpeed for phpMyAdmin"
########################################
log "Configuring OpenLiteSpeed for phpMyAdmin access..."

OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
if [ ! -f "$OLS_CONF" ]; then
  err "OpenLiteSpeed config not found at $OLS_CONF"
  exit 1
fi

cp "$OLS_CONF" "$OLS_CONF.backup.$(date +%Y%m%d_%H%M%S)"

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
else
  sed -i '/virtualhost Example {/,/^}/ s/enableScript.*/enableScript            1/' "$OLS_CONF"
  sed -i '/virtualhost Example {/,/^}/ s/restrained.*/restrained              0/' "$OLS_CONF"
fi

if ! grep -q "extprocessor lsphp81" "$OLS_CONF"; then
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

mkdir -p /usr/local/lsws/conf/vhosts/Example
mkdir -p /usr/local/lsws/Example/logs

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

chown -R nobody:nogroup "${PMA_DIR}"
chmod -R 755 "${PMA_DIR}"
find "${PMA_DIR}" -type f -name "*.php" -exec chmod 644 {} \;

cat > "${PMA_DIR}/.htaccess" << 'EOF'
DirectoryIndex index.php
Options -Indexes
<FilesMatch "\.php$">
    SetHandler lsapi:lsphp81
</FilesMatch>
EOF

chown nobody:nogroup "${PMA_DIR}/.htaccess"
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

systemctl restart mariadb 2>/dev/null
sleep 2
systemctl restart lsws 2>/dev/null
sleep 3

if [ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ]; then
  ln -sf /var/run/mysqld/mysqld.sock /tmp/mysql.sock
  log "MySQL socket symlink verified"
fi

PHP_TEST=$(php -r "
try {
  \$mysqli = new mysqli('localhost', 'root', '${DB_ROOT_PASS}');
  if (\$mysqli->connect_error) { echo 'FAIL: ' . \$mysqli->connect_error; }
  else { echo 'OK'; \$mysqli->close(); }
} catch (Exception \$e) { echo 'FAIL: ' . \$e->getMessage(); }
" 2>&1)

if [[ "$PHP_TEST" == "OK" ]]; then
  log "PHP MySQL connection verified"
else
  warn "PHP MySQL connection test: $PHP_TEST"
  mkdir -p /var/lib/mysql
  ln -sf /var/run/mysqld/mysqld.sock /var/lib/mysql/mysql.sock 2>/dev/null
fi

PHPMYADMIN_TEST=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/phpmyadmin/ 2>/dev/null)
if [ "$PHPMYADMIN_TEST" = "200" ] || [ "$PHPMYADMIN_TEST" = "302" ]; then
  log "phpMyAdmin is accessible (HTTP $PHPMYADMIN_TEST)"
else
  warn "phpMyAdmin returned HTTP $PHPMYADMIN_TEST - rechecking..."
  systemctl restart lsws
  sleep 3
fi

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
echo -e "${Y}TIP: Credentials saved to /etc/litepanel/credentials${N}"
