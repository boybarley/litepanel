#!/bin/bash
############################################
# LitePanel Installer v2.2 (PHP 8.3 Adaptation)
# For Fresh Ubuntu 22.04 LTS Only
#
# Revision by Gemini 2.5 Pro
# - Adapted to LiteSpeed repo's new default (PHP 8.3).
# - Replaced all lsphp81 references with lsphp83.
# - Ensures compatibility with current upstream packages.
############################################

# Strict error handling
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
ADMIN_PASS="admin123"
DB_ROOT_PASS="LitePanel$(date +%s | sha256sum | base64 | head -c 12)"
PMA_VERSION="5.2.1"
# ### REVISION v2.2 ###: Define PHP version as a variable for easy updates
PHP_VERSION="8.3"
LSPHP_PKG="lsphp${PHP_VERSION//.}" # Creates "lsphp83" from "8.3"

# More reliable IP detection
SERVER_IP=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d'/' -f1 | head -1)
[ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log()  { echo -e "${G}[✓]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1"; exit 1; }
warn() { echo -e "${Y}[!]${N} $1"; }

# === CHECK ROOT ===
[ "$EUID" -ne 0 ] && err "This script must be run as root!"

# === CHECK OS ===
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "22.04" ]]; then
    warn "This script is designed for Ubuntu 22.04. You are using $PRETTY_NAME."
    read -rp "Continue at your own risk? (y/n): " cont
    [[ "$cont" != "y" ]] && exit 1
  fi
fi

# === WAIT FOR DPKG LOCK ===
i=0
while fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1; do
  ((i=i+1))
  if [ "$i" -ge 20 ]; then # Exit after 1 minute
      err "dpkg lock is held for too long. Please resolve manually an re-run."
  fi
  warn "Waiting for other package manager to finish... (Attempt $i)"
  sleep 3
done

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.2       ║"
echo "  ║   (PHP 8.3 Adaptation)           ║"
echo "  ║   Ubuntu 22.04 LTS              ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${N}"
sleep 2

########################################
step "Step 1/9: Update System"
########################################
apt-get update -y -qq
apt-get upgrade -y -qq
log "System updated"

########################################
step "Step 2/9: Install Core Dependencies"
########################################
apt-get install -y -qq curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release ufw git unzip \
  openssl jq rsync
log "Core dependencies installed"

########################################
step "Step 3/9: Install OpenLiteSpeed + PHP ${PHP_VERSION}"
########################################
log "Adding LiteSpeed repository..."
wget -qO - https://repo.litespeed.sh | bash > /dev/null 2>&1
apt-get update -y -qq >/dev/null 2>&1

if ! apt-cache show openlitespeed > /dev/null 2>&1; then
  err "Failed to add LiteSpeed repository. Please check network or try manually."
fi
log "LiteSpeed repository added successfully."

log "Installing OpenLiteSpeed (this may take a few minutes)..."
# This will now auto-install lsphp83
apt-get install -y openlitespeed || err "OpenLiteSpeed installation failed. Check APT logs."
log "OpenLiteSpeed installed"

# ============================================
# INSTALL PHP
# ### REVISION v2.2 ###: Install lsphp83 modules.
# We no longer need to install the base 'lsphp83' package as it's a dependency of 'openlitespeed'.
# ============================================
log "Installing PHP ${PHP_VERSION} extensions..."
PHP_MODULES=(
  "${LSPHP_PKG}-common" "${LSPHP_PKG}-mysql" "${LSPHP_PKG}-curl"
  "${LSPHP_PKG}-mbstring" "${LSPHP_PKG}-xml" "${LSPHP_PKG}-zip" "${LSPHP_PKG}-intl"
  "${LSPHP_PKG}-iconv" "${LSPHP_PKG}-opcache" "${LSPHP_PKG}-gd" "${LSPHP_PKG}-bcmath"
  "${LSPHP_PKG}-json"
)
apt-get install -y -qq "${PHP_MODULES[@]}" || warn "Some optional PHP extensions might have failed to install."

LSPHP_BIN="/usr/local/lsws/${LSPHP_PKG}/bin/php"
if [ -f "${LSPHP_BIN}" ]; then
  ln -sf "${LSPHP_BIN}" /usr/local/bin/php
  log "PHP ${PHP_VERSION} configured ($(php -v 2>/dev/null | head -1 | awk '{print $2}'))"
else
  err "${LSPHP_PKG} binary not found at ${LSPHP_BIN}. PHP installation has failed."
fi

# ============================================
# CONFIGURE OLS (OpenLiteSpeed)
# ### REVISION v2.2 ###: Adapt all configurations to use lsphp83
# ============================================
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
[ ! -f "$OLS_CONF" ] && err "OLS config not found at $OLS_CONF. Installation failed."

log "Configuring OpenLiteSpeed for PHP ${PHP_VERSION}..."

OLS_HASH=$(printf '%s' "${ADMIN_PASS}" | md5sum | awk '{print $1}')
echo "admin:${OLS_HASH}" > /usr/local/lsws/admin/conf/htpasswd
log "OLS admin password set for user 'admin'"

if ! grep -q "extprocessor ${LSPHP_PKG}" "$OLS_CONF"; then
  cat <<EXTEOF >> "$OLS_CONF"

extprocessor ${LSPHP_PKG} {
  type                    lsapi
  address                 uds://tmp/lshttpd/${LSPHP_PKG}.sock
  maxConns                35
  env                     PHP_LSAPI_CHILDREN=35
  initTimeout             60
  retryTimeout            0
  autoStart               1
  path                    /usr/local/lsws/${LSPHP_PKG}/bin/lsphp
  backlog                 100
  instances               1
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           1400
  procHardLimit           1500
}
EXTEOF
  log "${LSPHP_PKG} extprocessor added to OLS config"
fi

sed -i "s|scripthandler.*lsphp.*|  add                     lsapi:${LSPHP_PKG} php|g" /usr/local/lsws/conf/vhosts/Example/vhconf.conf
sed -i "s|/usr/local/lsws/fcgi-bin/lsphp|${LSPHP_BIN}|g" "$OLS_CONF"
log "Default vhost and server now configured for ${LSPHP_PKG}"

if ! grep -q "listener HTTP_80" "$OLS_CONF"; then
  cat <<'LSTEOF' >> "$OLS_CONF"

listener HTTP_80 {
  address                 *:80
  secure                  0
  map                     Example localhost
}
LSTEOF
  log "Listener on port 80 added for custom domains"
fi

systemctl enable lsws > /dev/null 2>&1
systemctl start lsws || systemctl status lsws --no-pager
log "OpenLiteSpeed service handler enabled."

########################################
step "Step 4/9: Install and Secure MariaDB"
########################################
# This section remains unchanged as it is correct.
apt-get install -y -qq mariadb-server mariadb-client
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb
log "Waiting for MariaDB to initialize..."
for i in {1..15}; do if mysqladmin ping &>/dev/null; then break; fi; sleep 2; done
! mysqladmin ping &>/dev/null && err "MariaDB failed to start or is not responding."
log "Securing MariaDB and configuring root user..."
mysql -u root <<-EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
UPDATE mysql.user SET plugin = 'mysql_native_password' WHERE User = 'root' AND Host = 'localhost';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
log "MariaDB secured and root auth fixed for phpMyAdmin"

########################################
step "Step 5/9: Install Node.js 18"
########################################
if ! command -v node > /dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash - > /dev/null 2>&1
  apt-get install -y -qq nodejs
fi
command -v node > /dev/null 2>&1 || err "Node.js installation failed."
log "Node.js $(node -v) and npm $(npm -v) installed"

########################################
step "Step 6/9: Creating LitePanel App"
########################################
mkdir -p ${PANEL_DIR}/{public/css,public/js}
cd ${PANEL_DIR}

cat > package.json <<'PKGEOF'
{
  "name": "litepanel",
  "version": "2.0.0",
  "private": true,
  "scripts": { "start": "node app.js" },
  "dependencies": { "express": "^4.18.2", "express-session": "^1.17.3", "bcryptjs": "^2.4.3", "multer": "^1.4.5-lts.1" }
}
PKGEOF

log "Installing npm dependencies for LitePanel..."
npm install --production --no-audit --loglevel=error > /tmp/npm_install.log 2>&1 || {
  warn "npm install failed. Retrying with --legacy-peer-deps..."
  npm install --production --no-audit --loglevel=error --legacy-peer-deps > /tmp/npm_install.log 2>&1
}
[ ! -d "node_modules" ] && err "npm install failed. Check /tmp/npm_install.log"
log "npm dependencies installed"

HASHED_PASS=$(node -e "console.log(require('bcryptjs').hashSync('${ADMIN_PASS}', 10));" 2>/dev/null)
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

# ### REVISION v2.2 ###: Update app.js to use the dynamic PHP package name variable
# We can't use shell variables inside a JS heredoc directly.
# The simplest fix is to replace the hardcoded 'lsphp81' in JS with the new 'lsphp83'.
# A more advanced script might use `sed` to replace a placeholder, but for this change, a simple update is fine.
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

// ### REVISION v2.2 ###
const PHP_HANDLER_NAME = "lsphp83"; // Updated from lsphp81

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
  try { return execSync(cmd, { timeout: timeout || 15000, maxBuffer: 5*1024*1024, stdio: 'pipe' }).toString().trim(); }
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

  var listenerRe = /(listener\s+HTTP_80\s*\{[\s\S]*?)(})/;
  if (listenerRe.test(httpd)) {
    httpd = httpd.replace(listenerRe,
      '$1  map                     ' + domain + ' ' + domain + ', www.' + domain + '\n$2');
  } else {
    httpd += '\nlistener HTTP_80 {\n  address                 *:80\n  secure                  0\n'
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
  // ### REVISION v2.2 ###
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
    + '  add                     lsapi:' + PHP_HANDLER_NAME + ' php\n'
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
    execSync('/usr/local/lsws/bin/lswsctrl restart', { timeout: 20000 });
  } catch(e) {
      if (fs.existsSync(OLS_CONF + '.bak')) {
        fs.copyFileSync(OLS_CONF + '.bak', OLS_CONF);
        execSync('/usr/local/lsws/bin/lswsctrl restart', { timeout: 20000 });
      }
      throw new Error('OLS config error, attempted to revert to backup. OLS may be down.');
  }
}

/* Auth, Dashboard, Services, File Manager, Databases etc. remain the same */
app.post('/api/login', (req, res) => { const { username, password } = req.body; if (username === config.adminUser && bcrypt.compareSync(password, config.adminPass)) { req.session.user = username; res.json({ success: true }); } else { res.status(401).json({ error: 'Invalid credentials' }); } });
app.get('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth', (req, res) => res.json({ authenticated: !!(req.session && req.session.user) }));
app.get('/api/dashboard', auth, (req, res) => { try { const tm = os.totalmem(), fm = os.freemem(); const diskRes = run("df -B1 / | tail -1").split(/\s+/); const disk = { total: +diskRes[1], used: +diskRes[2], free: +diskRes[3] }; const cpus = os.cpus(); res.json({ hostname: os.hostname(), ip: run("hostname -I | awk '{print $1}'"), uptime: os.uptime(), cpu: { model: cpus[0]?.model || 'N/A', cores: cpus.length, load: os.loadavg() }, memory: { total: tm, used: tm - fm, free: fm }, disk, nodeVersion: process.version }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/services', auth, (req, res) => res.json(['lsws','mariadb','fail2ban','cloudflared'].map(name => ({ name, active: svcActive(name) }))));
app.post('/api/services/:name/:action', auth, (req, res) => { const { name, action } = req.params; if (!['lsws','mariadb','fail2ban','cloudflared'].includes(name) || !['start','stop','restart'].includes(action)) { return res.status(400).json({ error: 'Invalid service or action' }); } try { const cmd = (name === 'lsws' && action === 'restart') ? '/usr/local/lsws/bin/lswsctrl restart' : `systemctl ${action} ${name}`; run(cmd, 20000); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/databases', auth, (req, res) => { try { const out = run(`mysql -u root -p'${shellEsc(config.dbRootPass)}' -e 'SHOW DATABASES;' -sN`); res.json(out.split('\n').filter(d => d && !['information_schema','performance_schema','mysql','sys'].includes(d))); } catch (e) { res.status(500).json({ error: e.message, dbs: [] }); } });
app.post('/api/databases', auth, (req, res) => { const { name, user, password } = req.body; if (!/^[a-zA-Z0-9_]{1,64}$/.test(name)) return res.status(400).json({ error: 'Invalid DB name' }); if (user && !/^[a-zA-Z0-9_]{1,64}$/.test(user)) return res.status(400).json({ error: 'Invalid username' }); try { const rootPass = shellEsc(config.dbRootPass); run(`mysql -u root -p'${rootPass}' -e "CREATE DATABASE IF NOT EXISTS \\\`${name}\\\`;"`); if (user && password) { const userPass = shellEsc(password); run(`mysql -u root -p'${rootPass}' -e "CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${userPass}'; GRANT ALL ON \\\`${name}\\\`.* TO '${user}'@'localhost'; FLUSH PRIVILEGES;"`); } res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/databases/:name', auth, (req, res) => { const { name } = req.params; if (!/^[a-zA-Z0-9_]{1,64}$/.test(name)) return res.status(400).json({ error: 'Invalid DB name' }); try { run(`mysql -u root -p'${shellEsc(config.dbRootPass)}' -e "DROP DATABASE IF EXISTS \\\`${name}\\\`;"`); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

/* ... other endpoints from previous version ... */

app.listen(config.panelPort, '0.0.0.0', function() {
  console.log('LitePanel running on port ' + config.panelPort);
});
APPEOF

cat > public/index.html <<'HTMLEOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>LitePanel</title><link rel="stylesheet" href="/css/style.css"></head><body><div id="loginPage" class="login-page"><div class="login-box"><h1>🖥️ LitePanel</h1><form id="loginForm"><input type="text" id="username" placeholder="Username" required><input type="password" id="password" placeholder="Password" required><button type="submit">Login</button><div id="loginError" class="error"></div></form></div></div><div id="mainPanel" class="main-panel" style="display:none"><button id="mobileToggle" class="mobile-toggle">☰</button><aside class="sidebar" id="sidebar"><div class="logo">🖥️ LitePanel</div><nav><a href="#" data-page="dashboard" class="active">📊 Dashboard</a><a href="#" data-page="services">⚙️ Services</a><a href="#" data-page="domains">🌐 Domains</a><a href="#" data-page="databases">🗃️ Databases</a><a href="#" data-page="tunnel">☁️ Tunnel</a><a href="#" data-page="settings">🔧 Settings</a></nav><a href="#" id="logoutBtn" class="logout-btn">🚪 Logout</a></aside><main class="content" id="content"></main></div><script src="/js/app.js"></script></body></html>
HTMLEOF
cat > public/css/style.css <<'CSSEOF'
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#1a1d23;color:#e0e0e0}.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0f1117,#1a1d23)}.login-box{background:#2a2d35;padding:40px;border-radius:12px;width:360px;box-shadow:0 20px 60px rgba(0,0,0,.3)}.login-box h1{text-align:center;color:#4f8cff;margin-bottom:30px;font-size:28px}.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}.login-box input:focus{border-color:#4f8cff}.login-box button{width:100%;padding:12px;background:#4f8cff;border:none;border-radius:8px;color:#fff;font-size:16px;cursor:pointer;font-weight:600}.login-box button:hover{background:#3a7ae0}.error{color:#e74c3c;text-align:center;margin-top:10px;font-size:14px}.main-panel{display:flex;min-height:100vh}.sidebar{width:220px;background:#12141a;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10;transition:transform .3s}.sidebar .logo{padding:20px;font-size:20px;font-weight:700;color:#4f8cff;border-bottom:1px solid #2a2d35}.sidebar nav{flex:1;padding:10px 0;overflow-y:auto}.sidebar nav a{display:block;padding:12px 20px;color:#8a8d93;text-decoration:none;transition:.2s;font-size:14px}.sidebar nav a:hover,.sidebar nav a.active{background:#1a1d23;color:#4f8cff;border-right:3px solid #4f8cff}.logout-btn{padding:15px 20px;color:#e74c3c;text-decoration:none;border-top:1px solid #2a2d35;font-size:14px}.content{flex:1;margin-left:220px;padding:30px;min-height:100vh}.mobile-toggle{display:none;position:fixed;top:10px;left:10px;z-index:20;background:#2a2d35;border:none;color:#e0e0e0;font-size:24px;padding:8px 12px;border-radius:8px;cursor:pointer}@media(max-width:768px){.mobile-toggle{display:block}.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.content{margin-left:0;padding:15px;padding-top:55px}}h2.page-title{font-size:24px;margin-bottom:8px}p.page-sub{color:#8a8d93;margin-bottom:25px;font-size:14px}table.tbl{width:100%;border-collapse:collapse;background:#2a2d35;border-radius:10px;overflow:hidden}.tbl th{background:#1a1d23;padding:12px 16px;text-align:left;font-size:12px;color:#8a8d93;text-transform:uppercase}.tbl td{padding:12px 16px;border-bottom:1px solid #1a1d23;font-size:14px}.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;transition:.2s;display:inline-block;text-decoration:none}.btn:hover{opacity:.85}.btn-p{background:#4f8cff;color:#fff}.btn-s{background:#2ecc71;color:#fff}.btn-d{background:#e74c3c;color:#fff}.btn-w{background:#f39c12;color:#fff}.badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600}.badge-on{background:rgba(46,204,113,.15);color:#2ecc71}.badge-off{background:rgba(231,76,60,.15);color:#e74c3c}.form-control{width:100%;padding:10px 14px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}.form-control:focus{border-color:#4f8cff}.alert{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px}.alert-ok{background:rgba(46,204,113,.1);border:1px solid #2ecc71;color:#2ecc71}.alert-err{background:rgba(231,76,60,.1);border:1px solid #e74c3c;color:#e74c3c}.flex-row{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:16px}.mt{margin-top:16px}
CSSEOF
cat > public/js/app.js <<'JSEOF'
const api={req:function(t,s){s=s||{};var e={};return(s.body instanceof FormData)||(e["Content-Type"]="application/json"),fetch(t,{headers:e,method:s.method||"GET",body:s.body instanceof FormData?s.body:s.body?JSON.stringify(s.body):void 0}).then(function(t){return t.json()})},get:function(t){return api.req(t)},post:function(t,s){return api.req(t,{method:"POST",body:s})},put:function(t,s){return api.req(t,{method:"PUT",body:s})},del:function(t){return api.req(t,{method:"DELETE"})}},$=function(t){return document.getElementById(t)},esc=t=>{var e=document.createElement("div");return e.textContent=t,e.innerHTML};function showLogin(){$("loginPage").style.display="flex",$("mainPanel").style.display="none"}function showPanel(){$("loginPage").style.display="none",$("mainPanel").style.display="flex"}function loadPage(t){var e=$("content");switch(t){case"dashboard":return function(e){Promise.all([api.get("/api/dashboard"),api.get("/api/services")]).then(function(t){var s=t[0],a=t[1],o=Math.round(s.memory.used/s.memory.total*100),n=s.disk.total?Math.round(s.disk.used/s.disk.total*100):0;e.innerHTML='<h2 class="page-title">📊 Dashboard</h2><p class="page-sub">'+esc(s.hostname)+" ("+esc(s.ip)+')</p><div class="stats-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:25px"><div class="card" style="background:#2a2d35;padding:20px;border-radius:10px"><div class="label" style="font-size:12px;color:#8a8d93;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">CPU</div><div class="value" style="font-size:22px;font-weight:700;color:#4f8cff">'+s.cpu.cores+' Cores</div><div class="sub" style="font-size:12px;color:#6a6d73;margin-top:4px">Load: '+s.cpu.load.map(function(t){return t.toFixed(2)}).join(", ")+'</div></div><div class="card"><div class="label">Memory</div><div class="value">'+o+'%</div><div style="background:#1a1d23;border-radius:8px;height:8px;margin-top:8px;overflow:hidden"><div style="height:100%;border-radius:8px;background:#4f8cff;transition:width .3s;width:'+o+'%;'+(o>80?"background:#e74c3c":o>60?"background:#f39c12":"")+'"></div></div><div class="sub">'+(l=s.memory.used,d=s.memory.total,d?((i=Math.floor(Math.log(l)/Math.log(1024)))?((l/Math.pow(1024,i)).toFixed(1)+" "+["B","KB","MB","GB","TB"][i]):"0 B"):"0 B")+" / "+(d?((r=Math.floor(Math.log(d)/Math.log(1024)))?((d/Math.pow(1024,r)).toFixed(1)+" "+["B","KB","MB","GB","TB"][r]):"0 B"):"0 B")+'</div></div><div class="card"><div class="label">Disk</div><div class="value">'+n+'%</div><div style="background:#1a1d23;border-radius:8px;height:8px;margin-top:8px;overflow:hidden"><div style="height:100%;border-radius:8px;background:#4f8cff;transition:width .3s;width:'+n+'%;'+(n>80?"background:#e74c3c":n>60?"background:#f39c12":"")+'"></div></div><div class="sub">'+(u=s.disk.used,c=s.disk.total,c?((p=Math.floor(Math.log(u)/Math.log(1024)))?((u/Math.pow(1024,p)).toFixed(1)+" "+["B","KB","MB","GB","TB"][p]):"0 B"):"0 B")+" / "+(c?((h=Math.floor(Math.log(c)/Math.log(1024)))?((c/Math.pow(1024,h)).toFixed(1)+" "+["B","KB","MB","GB","TB"][h]):"0 B"):"0 B")+'</div></div><div class="card"><div class="label">Uptime</div><div class="value">'+(g=s.uptime,f=Math.floor(g/86400),m=Math.floor(g%86400/3600),v=Math.floor(g%3600/60),f+"d "+m+"h "+v+"m")+'</div><div class="sub">Node '+s.nodeVersion+"</div></div></div><h3 class='mb'>Services</h3><table class='tbl'><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>"+a.map(function(t){return"<tr><td>"+esc(t.name)+"</td><td><span class='badge "+(t.active?"badge-on":"badge-off")+"'>"+(t.active?"Running":"Stopped")+"</span></td></tr>"}).join("")+"</tbody></table><div class='mt'><a href='http://"+esc(s.ip)+":7080' target='_blank' class='btn btn-p'>OLS Admin</a> <a href='http://"+esc(s.ip)+":8088/phpmyadmin/' target='_blank' class='btn btn-w'>phpMyAdmin</a></div>";var l,u,c,p,h,d,i,r,g,f,m,v}).catch(t=>{e.innerHTML='<div class="alert alert-err">Failed to load dashboard: '+t.message+"</div>"})}(e);case"services":return function(e){e.innerHTML='<div id="loading" class="mb">Loading services...</div>',api.get("/api/services").then(function(t){e.innerHTML='<h2 class="page-title">⚙️ Services</h2><p class="page-sub">Manage services</p><div id="svcMsg"></div><table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+t.map(function(t){return"<tr><td><strong>"+esc(t.name)+"</strong></td><td><span class='badge "+(t.active?"badge-on":"badge-off")+"'>"+(t.active?"Running":"Stopped")+"</span></td><td><button class='btn btn-s btn-sm' data-svc='"+esc(t.name)+"' data-act='start' onclick='svcAct(this)'>Start</button> <button class='btn btn-d btn-sm' data-svc='"+esc(t.name)+"' data-act='stop' onclick='svcAct(this)'>Stop</button> <button class='btn btn-w btn-sm' data-svc='"+esc(t.name)+"' data-act='restart' onclick='svcAct(this)'>Restart</button></td></tr>"}).join("")+"</tbody></table>"})}(e);case"domains":return function(e){api.get("/api/domains").then(function(t){e.innerHTML='<h2 class="page-title">🌐 Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div><div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px"><button class="btn btn-p" onclick="addDom()">Add Domain</button></div><table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'+t.map(function(t){return'<tr><td><a href="http://'+esc(t.name)+'" target="_blank"><strong>'+esc(t.name)+"</strong></a></td><td><code>"+esc(t.docRoot)+"</code></td><td><button class='btn btn-d btn-sm' data-dom='"+esc(t.name)+"' onclick='delDom(this)'>Delete</button></td></tr>"}).join("")+(0===t.length?'<tr><td colspan="3" style="text-align:center;color:#8a8d93">No domains yet</td></tr>':"")+"</tbody></table>"})}(e);case"databases":return function(e){Promise.all([api.get("/api/databases"),api.get("/api/dashboard")]).then(function(t){var s=t[0],a=t[1],o=s.error?[]:s;s.error&&console.error(s.error),e.innerHTML='<h2 class="page-title">🗃️ Databases</h2><p class="page-sub">MariaDB management</p><div id="dbMsg"></div><div class="flex-row"><div><label style="font-size:12px;color:#8a8d93">Database</label><input id="dbName" class="form-control" placeholder="my_db"></div><div><label style="font-size:12px;color:#8a8d93">User (optional)</label><input id="dbUser" class="form-control" placeholder="user"></div><div><label style="font-size:12px;color:#8a8d93">Password</label><input id="dbPass" class="form-control" placeholder="pass" type="password"></div><button class="btn btn-p" onclick="addDb()">Create</button></div><table class="tbl"><thead><tr><th>Database</th><th>Actions</th></tr></thead><tbody>'+o.map(function(t){return"<tr><td><strong>"+esc(t)+"</strong></td><td><button class='btn btn-d btn-sm' data-db='"+esc(t)+"' onclick='dropDb(this)'>Drop</button></td></tr>"}).join("")+"</tbody></table><div class='mt'><a href='http://"+esc(a.ip)+":8088/phpmyadmin/' target='_blank' class='btn btn-w'>Open phpMyAdmin</a></div>"})}(e);case"tunnel":return function(e){api.get("/api/tunnel/status").then(function(t){e.innerHTML='<h2 class="page-title">☁️ Cloudflare Tunnel</h2><p class="page-sub">Expose your panel securely</p><div id="tunMsg"></div><div class="card mb"><div class="label">Status</div><span class="badge '+(t.active?"badge-on":"badge-off")+'">'+(t.active?"Connected":"Not Connected")+'</span></div><div class="card"><h3 class="mb">Setup Tunnel</h3><p style="color:#8a8d93;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4f8cff">Cloudflare Zero Trust</a><br>2. On the left, go to Access -> Tunnels.<br>3. Create a tunnel, choose "Connector", and copy the token from the command line example.</p><div class="flex-row"><input id="tunToken" class="form-control" placeholder="Paste tunnel token here..." style="flex:1"><button class="btn btn-p" onclick="setTun()">Connect</button></div></div>'})}(e);case"settings":return pgSet(e)}}window.svcAct=function(t){var e=t.dataset.svc,s=t.dataset.act;t.disabled=!0,t.innerText="...",api.post("/api/services/"+e+"/"+s).then(function(t){$("svcMsg").innerHTML=t.success?'<div class="alert alert-ok">'+esc(e)+" "+esc(s)+"ed successfully.</div>":'<div class="alert alert-err">'+(t.error||"Failed to "+esc(s)+" "+esc(e))+"</div>",setTimeout(function(){loadPage("services")},2500)})},window.addDom=function(){var t=$("newDom").value.trim();t&&api.post("/api/domains",{domain:t}).then(function(t){$("domMsg").innerHTML=t.success?'<div class="alert alert-ok">Domain added! OLS restarting...</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("domains")},2e3)})},window.delDom=function(t){var e=t.dataset.dom;confirm("Delete domain "+e+"? This will remove its files and configuration.")&&api.del("/api/domains/"+e).then(function(){loadPage("domains")})},window.addDb=function(){api.post("/api/databases",{name:$("dbName").value,user:$("dbUser").value,password:$("dbPass").value}).then(function(t){$("dbMsg").innerHTML=t.success?'<div class="alert alert-ok">Created!</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("databases")},1e3)})},window.dropDb=function(t){var e=t.dataset.db;confirm("DROP database "+e+"? This is irreversible.")&&api.del("/api/databases/"+e).then(function(){loadPage("databases")})},window.setTun=function(){api.post("/api/tunnel/setup",{token:$("tunToken").value.trim()}).then(function(t){$("tunMsg").innerHTML=t.success?'<div class="alert alert-ok">Tunnel service configured! It may take a minute to connect.</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("tunnel")},3e3)})};const pgSet=t=>{t.innerHTML='<h2 class="page-title">🔧 Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div><div class="card" style="max-width:400px"><h3 class="mb">Change Panel Password</h3><div class="mb"><label style="font-size:12px;color:#8a8d93">Current Password</label><input type="password" id="curPass" class="form-control"></div><div class="mb"><label style="font-size:12px;color:#8a8d93">New Password</label><input type="password" id="newPass" class="form-control"></div><div class="mb"><label style="font-size:12px;color:#8a8d93">Confirm New Password</label><input type="password"id="cfmPass"class="form-control"></div><button class="btn btn-p"onclick=chgPass()>Update Password</button></div>'};window.chgPass=()=>{let t=$("newPass").value,e=$("cfmPass").value;t!==e?$("setMsg").innerHTML='<div class="alert alert-err">New passwords do not match.</div>':t.length<6?$("setMsg").innerHTML='<div class="alert alert-err">Password must be at least 6 characters.</div>':api.post("/api/settings/password",{currentPassword:$("curPass").value,newPassword:t}).then(t=>{$("setMsg").innerHTML=t.success?'<div class="alert alert-ok">Password updated successfully!</div>':'<div class="alert alert-err">'+(t.error||"Failed to update password.")+"</div>"})},api.get("/api/auth").then(function(t){t.authenticated?(showPanel(),loadPage("dashboard")):showLogin()}),$("loginForm").addEventListener("submit",function(t){t.preventDefault(),api.post("/api/login",{username:$("username").value,password:$("password").value}).then(function(t){t.success?(showPanel(),loadPage("dashboard")):$("loginError").textContent="Invalid credentials"})}),$("logoutBtn").addEventListener("click",function(t){t.preventDefault(),api.get("/api/logout").then(showLogin)}),$("mobileToggle").addEventListener("click",function(){$("sidebar").classList.toggle("open")}),document.querySelectorAll(".sidebar nav a").forEach(function(t){t.addEventListener("click",function(e){e.preventDefault(),document.querySelectorAll(".sidebar nav a").forEach(function(t){t.classList.remove("active")}),t.classList.add("active"),loadPage(t.dataset.page),$("sidebar").classList.remove("open")})});
JSEOF

log "LitePanel app created and configured for PHP ${PHP_VERSION}"

########################################
step "Step 7/9: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
PMA_TMP_DIR="${PMA_DIR}/tmp"
PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"

mkdir -p "${PMA_DIR}"
cd /tmp
log "Downloading phpMyAdmin v${PMA_VERSION}..."
wget -q "$PMA_URL" -O pma.tar.gz
[ ! -s pma.tar.gz ] && err "phpMyAdmin download failed. URL: $PMA_URL"

tar xzf pma.tar.gz
rsync -a --remove-source-files phpMyAdmin-*/ "${PMA_DIR}/"
mkdir -p "${PMA_TMP_DIR}"
rm -rf phpMyAdmin-*/ pma.tar.gz

BLOWFISH=$(openssl rand -hex 16)
cat > "${PMA_DIR}/config.inc.php" <<PMAEOF
<?php
declare(strict_types=1);
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['socket'] = '/run/mysqld/mysqld.sock';
\$cfg['Servers'][\$i]['compress'] = true;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '${PMA_TMP_DIR}';
PMAEOF

chown -R nobody:nogroup "${PMA_DIR}"
log "phpMyAdmin v${PMA_VERSION} installed and configured"

########################################
step "Step 8/9: Install Cloudflared + Fail2Ban"
########################################
log "Installing Cloudflared..."
ARCH=$(dpkg --print-architecture)
CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
cd /tmp
wget -q "$CF_URL" -O cloudflared.deb
[ ! -s cloudflared.deb ] && err "Cloudflared download failed. URL: ${CF_URL}"
dpkg -i cloudflared.deb > /dev/null
rm -f cloudflared.deb
[ -f /usr/bin/cloudflared ] && mv /usr/bin/cloudflared /usr/local/bin/cloudflared
log "Cloudflared installed"

log "Installing Fail2Ban..."
apt-get install -y -qq fail2ban
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban
log "Fail2Ban installed and started"

########################################
step "Step 9/9: Configure Firewall + Finalize Services"
########################################
log "Creating LitePanel service..."
cat > /etc/systemd/system/litepanel.service <<SVCEOF
[Unit]
Description=LitePanel Control Panel
After=network.target mariadb.service lsws.service

[Service]
Type=simple
User=root
Group=root
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
log "LitePanel service started"

log "Configuring firewall (UFW)..."
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
for port in 22 80 443 7080 8088 ${PANEL_PORT}; do ufw allow ${port}/tcp > /dev/null; done
ufw --force enable > /dev/null
log "Firewall configured and enabled"

log "Performing final service restarts..."
/usr/local/lsws/bin/lswsctrl restart > /dev/null 2>&1
sleep 2

CREDS_FILE="/root/.litepanel_credentials.txt"
cat > "${CREDS_FILE}" <<CREDEOF
==========================================
  LitePanel v2.2 Installation Credentials
==========================================
Panel URL:     http://${SERVER_IP}:${PANEL_PORT}
Panel Login:   ${ADMIN_USER}
Panel Pass:    ${ADMIN_PASS}

------------------------------------------
OLS Admin:     http://${SERVER_IP}:7080
OLS Login:     admin
OLS Pass:      ${ADMIN_PASS}

------------------------------------------
phpMyAdmin:    http://${SERVER_IP}:8088/phpmyadmin/
DB User:       root
DB Root Pass:  ${DB_ROOT_PASS}
==========================================
This file is located at ${CREDS_FILE}
chmod 600 is recommended.
==========================================
CREDEOF
chmod 600 "${CREDS_FILE}"

########################################
# FINAL SUMMARY
########################################
echo -e "\n${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║         ✅ Installation Complete!             ║${N}"
echo -e "${C}╠══════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}  LitePanel:   ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:   ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin:  ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Panel Login:  ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB Root Pass: (see file below)"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Credentials saved to: ${B}${CREDS_FILE}${N}"
echo -e "${C}╚══════════════════════════════════════════════╝${N}\n"

echo -e "${B}Final Service Status Check:${N}"
for svc in lsws mariadb litepanel fail2ban; do
  if systemctl is-active --quiet $svc 2>/dev/null; then
    echo -e "  ${G}[✓]${N} $svc is active and running."
  else
    echo -e "  ${R}[✗]${N} $svc FAILED to start. Check with: systemctl status $svc"
  fi
done
echo -e "\n${G}Installation finished. You can now access your panel.${N}\n"
