#!/bin/bash
############################################
# LitePanel Installer v2.0 (FIXED)
# Fresh Ubuntu 22.04 LTS Only
# Fixes: OLS config, PHP extprocessor,
#   listener, vhost, file manager, security
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

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.0       ║"
echo "  ║   Ubuntu 22.04 LTS (Fixed)       ║"
echo "  ╚══════════════════════════════════╝"
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
wget -O - https://rpms.litespeedtech.com/debian/lst_repo.gpg 2>/dev/null | \
  gpg --dearmor -o /usr/share/keyrings/lst-debian.gpg 2>/dev/null

echo "deb [signed-by=/usr/share/keyrings/lst-debian.gpg] http://rpms.litespeedtech.com/debian/ \
$(lsb_release -sc) main" > /etc/apt/sources.list.d/lst_debian_repo.list

apt-get update -y -qq > /dev/null 2>&1
apt-get install -y -qq openlitespeed lsphp81 lsphp81-common lsphp81-mysql \
  lsphp81-curl lsphp81-mbstring lsphp81-xml lsphp81-zip lsphp81-intl \
  lsphp81-iconv lsphp81-opcache > /dev/null 2>&1

ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null

# ---- FIX #1: OLS Admin Password (MD5 format, like CyberPanel) ----
OLS_HASH=$(printf '%s' "${ADMIN_PASS}" | md5sum | awk '{print $1}')
echo "admin:${OLS_HASH}" > /usr/local/lsws/admin/conf/htpasswd
log "OLS admin password set (MD5 format)"

# ---- FIX #2: Add lsphp81 extprocessor to httpd_config.conf ----
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

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

# ---- FIX #3: Add HTTP listener on port 80 ----
if ! grep -q "listener HTTP" "$OLS_CONF"; then
  cat >> "$OLS_CONF" <<'LSTEOF'

listener HTTP {
  address                 *:80
  secure                  0
}
LSTEOF
  log "HTTP listener port 80 added"
fi

# ---- FIX #7: Update Example vhost to use lsphp81 (for phpMyAdmin) ----
EXAMPLE_VHCONF="/usr/local/lsws/conf/vhosts/Example/vhconf.conf"
if [ -f "$EXAMPLE_VHCONF" ]; then
  # Replace any lsphp scripthandler line with lsphp81
  sed -i '/add.*lsapi:lsphp/c\  add                     lsapi:lsphp81 php' "$EXAMPLE_VHCONF"
  log "Example vhost updated to lsphp81"
fi

# ---- FIX #11: Update default lsphp extprocessor path ----
sed -i 's|/usr/local/lsws/fcgi-bin/lsphp|/usr/local/lsws/lsphp81/bin/lsphp|g' "$OLS_CONF" 2>/dev/null

systemctl enable lsws > /dev/null 2>&1
systemctl start lsws
log "OpenLiteSpeed + PHP 8.1 installed & configured"

########################################
step "Step 4/9: Install MariaDB"
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
  log "MariaDB installed & secured"
else
  err "MariaDB failed to start"
fi

########################################
step "Step 5/9: Install Node.js 18"
########################################
curl -fsSL https://deb.nodesource.com/setup_18.x 2>/dev/null | bash - > /dev/null 2>&1
apt-get install -y -qq nodejs > /dev/null 2>&1
log "Node.js $(node -v 2>/dev/null || echo 'unknown') installed"

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

npm install --production > /dev/null 2>&1
if [ $? -ne 0 ]; then
  warn "npm install retry with legacy-peer-deps..."
  npm install --production --legacy-peer-deps > /dev/null 2>&1
fi

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

##############################################
# -------- app.js (Backend - FIXED) --------
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

/* ---- Config ---- */
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

const auth = (req, res, next) => {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

/* ---- Helpers ---- */
function run(cmd, timeout) {
  try {
    return execSync(cmd, { timeout: timeout || 15000, maxBuffer: 5*1024*1024 }).toString().trim();
  } catch(e) { return e.stderr ? e.stderr.toString().trim() : e.message; }
}

function svcActive(name) {
  try { execSync('systemctl is-active ' + name, { stdio: 'pipe' }); return true; }
  catch(e) { return false; }
}

function escRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function shellEsc(s) { return s.replace(/'/g, "'\\''"); }

/* ==================================================
   FIX #4,5,6,10: OLS Config Management
   Proper vhost format + line-safe regex + backup
   ================================================== */

function readOLSConf() { return fs.readFileSync(OLS_CONF, 'utf8'); }

function writeOLSConf(content) {
  fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak');
  fs.writeFileSync(OLS_CONF, content);
}

function addDomainToOLS(domain) {
  let httpd = readOLSConf();
  if (httpd.includes('virtualhost ' + domain + ' {')) return;

  // Append virtualhost block
  httpd += '\nvirtualhost ' + domain + ' {\n'
    + '  vhRoot                  ' + OLS_VHOST_DIR + '/' + domain + '\n'
    + '  configFile              ' + OLS_VHOST_CONF_DIR + '/' + domain + '/vhconf.conf\n'
    + '  allowSymbolLink         1\n'
    + '  enableScript            1\n'
    + '  restrained              1\n'
    + '}\n';

  // Add map to HTTP listener (port 80)
  // FIX #6: target HTTP listener, not Default (8088)
  var listenerRe = /(listener\s+HTTP\s*\{[\s\S]*?)(})/;
  if (listenerRe.test(httpd)) {
    httpd = httpd.replace(listenerRe,
      '$1  map                     ' + domain + ' ' + domain + ', www.' + domain + '\n$2');
  } else {
    // Fallback: create HTTP listener with map
    httpd += '\nlistener HTTP {\n  address                 *:80\n  secure                  0\n'
      + '  map                     ' + domain + ' ' + domain + ', www.' + domain + '\n}\n';
  }

  writeOLSConf(httpd);
}

function removeDomainFromOLS(domain) {
  let httpd = readOLSConf();
  fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak');

  // FIX #5: Use [\s\S]*? for multiline match (not [^}] which fails on newlines)
  var vhRe = new RegExp('\\n?virtualhost\\s+' + escRegex(domain) + '\\s*\\{[\\s\\S]*?\\}', 'g');
  httpd = httpd.replace(vhRe, '');

  // Remove map entries for this domain
  var mapRe = new RegExp('^\\s*map\\s+' + escRegex(domain) + '\\s+.*$', 'gm');
  httpd = httpd.replace(mapRe, '');

  // Clean up excess blank lines
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

  // FIX #4: Proper OLS vhconf.conf format (studied from CyberPanel)
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

// FIX #10: Safe restart with config validation & rollback
function safeRestartOLS() {
  try {
    execSync('systemctl restart lsws', { timeout: 15000 });
    execSync('sleep 2', { timeout: 5000 });
    try {
      execSync('systemctl is-active lsws', { stdio: 'pipe' });
    } catch(e) {
      // OLS failed → restore backup
      if (fs.existsSync(OLS_CONF + '.bak')) {
        fs.copyFileSync(OLS_CONF + '.bak', OLS_CONF);
        execSync('systemctl restart lsws', { timeout: 15000 });
      }
      throw new Error('OLS config error, reverted to backup');
    }
  } catch(e) { throw e; }
}

/* ---- Auth Routes ---- */
app.post('/api/login', function(req, res) {
  var u = req.body.username, p = req.body.password;
  if (u === config.adminUser && bcrypt.compareSync(p, config.adminPass)) {
    req.session.user = u;
    res.json({ success: true });
  } else { res.status(401).json({ error: 'Invalid credentials' }); }
});
app.get('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth', function(req, res) { res.json({ authenticated: !!(req.session && req.session.user) }); });

/* ---- Dashboard ---- */
app.get('/api/dashboard', auth, function(req, res) {
  var tm = os.totalmem(), fm = os.freemem();
  var disk = { total: 0, used: 0, free: 0 };
  try { var d = run("df -B1 / | tail -1").split(/\s+/); disk = { total: +d[1], used: +d[2], free: +d[3] }; } catch(e) {}
  var cpus = os.cpus();
  res.json({
    hostname: os.hostname(), ip: run("hostname -I | awk '{print $1}'"),
    uptime: os.uptime(),
    cpu: { model: cpus[0] ? cpus[0].model : 'Unknown', cores: cpus.length, load: os.loadavg() },
    memory: { total: tm, used: tm - fm, free: fm },
    disk: disk, nodeVersion: process.version
  });
});

/* ---- Services ---- */
app.get('/api/services', auth, function(req, res) {
  var svcs = ['lsws','mariadb','fail2ban','cloudflared'];
  res.json(svcs.map(function(s) { return { name: s, active: svcActive(s) }; }));
});
app.post('/api/services/:name/:action', auth, function(req, res) {
  var ok = ['lsws','mariadb','fail2ban','cloudflared'];
  var acts = ['start','stop','restart'];
  if (!ok.includes(req.params.name) || !acts.includes(req.params.action))
    return res.status(400).json({ error: 'Invalid' });
  try { execSync('systemctl ' + req.params.action + ' ' + req.params.name, { timeout: 15000 }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

/* ---- File Manager (FIX #8,12,13) ---- */
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
      // FIX #12: Check file size and binary before reading
      if (stat.size > MAX_EDIT_SIZE) return res.json({ path: p, size: stat.size, tooLarge: true });
      var buf = Buffer.alloc(Math.min(512, stat.size));
      var fd = fs.openSync(p, 'r');
      fs.readSync(fd, buf, 0, buf.length, 0);
      fs.closeSync(fd);
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
  try {
    var destDir = req.body.path || '/tmp';
    fs.renameSync(req.file.path, path.join(destDir, req.file.originalname));
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/mkdir', auth, function(req, res) {
  try { fs.mkdirSync(req.body.path, { recursive: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// FIX #13: Add rename & download
app.post('/api/files/rename', auth, function(req, res) {
  try { fs.renameSync(req.body.oldPath, req.body.newPath); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/download', auth, function(req, res) {
  var fp = req.query.path;
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  try {
    if (fs.statSync(fp).isDirectory()) return res.status(400).json({ error: 'Cannot download directory' });
    res.download(fp);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ---- Domains (FIX #4,5,6,10) ---- */
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
  if (domain === 'Example') return res.status(400).json({ error: 'Reserved name' });
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

/* ---- Databases (FIX #9) ---- */
app.get('/api/databases', auth, function(req, res) {
  try {
    var out = run("mysql -u root -p'" + shellEsc(config.dbRootPass) + "' -e 'SHOW DATABASES;' -s -N 2>/dev/null");
    var skip = ['information_schema','performance_schema','mysql','sys'];
    res.json(out.split('\n').filter(function(d) { return d.trim() && !skip.includes(d.trim()); }));
  } catch(e) { res.json([]); }
});

app.post('/api/databases', auth, function(req, res) {
  var name = req.body.name, user = req.body.user, password = req.body.password;
  // FIX #9: strict validation to prevent SQL injection
  if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) return res.status(400).json({ error: 'Invalid DB name (a-z, 0-9, _ only)' });
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

/* ---- Tunnel ---- */
app.get('/api/tunnel/status', auth, function(req, res) {
  res.json({ active: svcActive('cloudflared') });
});
app.post('/api/tunnel/setup', auth, function(req, res) {
  var token = req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });
  var safeToken = token.replace(/[;&|`$(){}]/g, '');
  try {
    if (!fs.existsSync('/usr/bin/cloudflared')) {
      run('wget -q "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb" -O /tmp/cf.deb && dpkg -i /tmp/cf.deb && rm -f /tmp/cf.deb', 30000);
    }
    fs.writeFileSync('/etc/systemd/system/cloudflared.service',
      '[Unit]\nDescription=Cloudflare Tunnel\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/cloudflared tunnel run --token ' + safeToken + '\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n');
    execSync('systemctl daemon-reload && systemctl enable cloudflared && systemctl restart cloudflared', { timeout: 15000 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ---- Settings ---- */
app.post('/api/settings/password', auth, function(req, res) {
  if (!bcrypt.compareSync(req.body.currentPassword, config.adminPass))
    return res.status(401).json({ error: 'Wrong current password' });
  if (!req.body.newPassword || req.body.newPassword.length < 6)
    return res.status(400).json({ error: 'Min 6 characters' });
  config.adminPass = bcrypt.hashSync(req.body.newPassword, 10);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

/* ---- Terminal ---- */
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
# -------- public/css/style.css (FIX #14) ---
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
# ---- public/js/app.js (Frontend FIXED) ----
##############################################
cat > public/js/app.js <<'JSEOF'
/* ---- API Helper ---- */
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
function fmtB(b) {
  if (!b) return '0 B';
  var k = 1024, s = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log(b) / Math.log(k));
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
}
function fmtUp(s) {
  var d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  return d + 'd ' + h + 'h ' + m + 'm';
}
function esc(t) { var d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function pClass(p) { return p > 80 ? 'danger' : p > 60 ? 'warn' : ''; }

/* ---- State ---- */
var curPath = '/usr/local/lsws';
var editFile = '';

/* ---- Auth ---- */
function checkAuth() {
  api.get('/api/auth').then(function(r) {
    if (r.authenticated) { showPanel(); loadPage('dashboard'); }
    else showLogin();
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
$('logoutBtn').addEventListener('click', function(e) { e.preventDefault(); api.get('/api/logout').then(showLogin); });

/* ---- Mobile Toggle (FIX #14) ---- */
$('mobileToggle').addEventListener('click', function() {
  $('sidebar').classList.toggle('open');
});

/* ---- Navigation ---- */
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

/* ======== Dashboard ======== */
function pgDash(el) {
  Promise.all([api.get('/api/dashboard'), api.get('/api/services')]).then(function(res) {
    var d = res[0], s = res[1];
    var mp = Math.round(d.memory.used / d.memory.total * 100);
    var dp = d.disk.total ? Math.round(d.disk.used / d.disk.total * 100) : 0;
    el.innerHTML = '<h2 class="page-title">📊 Dashboard</h2><p class="page-sub">' + d.hostname + ' (' + d.ip + ')</p>'
      + '<div class="stats-grid">'
      + '<div class="card"><div class="label">CPU</div><div class="value">' + d.cpu.cores + ' Cores</div><div class="sub">Load: ' + d.cpu.load.map(function(l){ return l.toFixed(2); }).join(', ') + '</div></div>'
      + '<div class="card"><div class="label">Memory</div><div class="value">' + mp + '%</div><div class="progress"><div class="progress-bar ' + pClass(mp) + '" style="width:' + mp + '%"></div></div><div class="sub">' + fmtB(d.memory.used) + ' / ' + fmtB(d.memory.total) + '</div></div>'
      + '<div class="card"><div class="label">Disk</div><div class="value">' + dp + '%</div><div class="progress"><div class="progress-bar ' + pClass(dp) + '" style="width:' + dp + '%"></div></div><div class="sub">' + fmtB(d.disk.used) + ' / ' + fmtB(d.disk.total) + '</div></div>'
      + '<div class="card"><div class="label">Uptime</div><div class="value">' + fmtUp(d.uptime) + '</div><div class="sub">Node ' + d.nodeVersion + '</div></div>'
      + '</div>'
      + '<h3 class="mb">Services</h3>'
      + '<table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>'
      + s.map(function(x) { return '<tr><td>' + x.name + '</td><td><span class="badge ' + (x.active ? 'badge-on' : 'badge-off') + '">' + (x.active ? 'Running' : 'Stopped') + '</span></td></tr>'; }).join('')
      + '</tbody></table>'
      + '<div class="mt"><a href="http://' + d.ip + ':7080" target="_blank" class="btn btn-p">OLS Admin</a> <a href="http://' + d.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-w">phpMyAdmin</a></div>';
  });
}

/* ======== Services ======== */
function pgSvc(el) {
  api.get('/api/services').then(function(s) {
    el.innerHTML = '<h2 class="page-title">⚙️ Services</h2><p class="page-sub">Manage services</p><div id="svcMsg"></div>'
      + '<table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'
      + s.map(function(x) {
        return '<tr><td><strong>' + x.name + '</strong></td>'
          + '<td><span class="badge ' + (x.active ? 'badge-on' : 'badge-off') + '">' + (x.active ? 'Running' : 'Stopped') + '</span></td>'
          + '<td><button class="btn btn-s btn-sm" data-svc="' + x.name + '" data-act="start" onclick="svcAct(this)">Start</button> '
          + '<button class="btn btn-d btn-sm" data-svc="' + x.name + '" data-act="stop" onclick="svcAct(this)">Stop</button> '
          + '<button class="btn btn-w btn-sm" data-svc="' + x.name + '" data-act="restart" onclick="svcAct(this)">Restart</button></td></tr>';
      }).join('')
      + '</tbody></table>';
  });
}
window.svcAct = function(btn) {
  var n = btn.dataset.svc, a = btn.dataset.act;
  api.post('/api/services/' + n + '/' + a).then(function(r) {
    $('svcMsg').innerHTML = r.success
      ? '<div class="alert alert-ok">' + n + ' ' + a + 'ed</div>'
      : '<div class="alert alert-err">' + (r.error || 'Failed') + '</div>';
    setTimeout(function() { loadPage('services'); }, 1200);
  });
};

/* ======== File Manager (FIX #8: data attributes, no inline path strings) ======== */
function pgFiles(el, p) {
  if (p !== undefined) curPath = p;
  api.get('/api/files?path=' + encodeURIComponent(curPath)).then(function(d) {
    if (d.error) { el.innerHTML = '<div class="alert alert-err">' + esc(d.error) + '</div>'; return; }

    // Binary file
    if (d.binary) {
      el.innerHTML = '<h2 class="page-title">📄 Binary File</h2><p class="page-sub">' + esc(d.path) + '</p>'
        + '<div class="card"><p>Binary file (' + fmtB(d.size) + ') — cannot edit</p>'
        + '<div class="mt"><a href="/api/files/download?path=' + encodeURIComponent(d.path) + '" class="btn btn-p" target="_blank">Download</a> '
        + '<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div></div>';
      curPath = d.path.substring(0, d.path.lastIndexOf('/')) || '/';
      return;
    }

    // Too large
    if (d.tooLarge) {
      el.innerHTML = '<h2 class="page-title">📄 Large File</h2><p class="page-sub">' + esc(d.path) + '</p>'
        + '<div class="card"><p>File too large to edit (' + fmtB(d.size) + ')</p>'
        + '<div class="mt"><a href="/api/files/download?path=' + encodeURIComponent(d.path) + '" class="btn btn-p" target="_blank">Download</a> '
        + '<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div></div>';
      curPath = d.path.substring(0, d.path.lastIndexOf('/')) || '/';
      return;
    }

    // Text file editor
    if (d.content !== undefined) {
      editFile = d.path;
      curPath = d.path.substring(0, d.path.lastIndexOf('/')) || '/';
      el.innerHTML = '<h2 class="page-title">📝 Edit File</h2><p class="page-sub">' + esc(d.path) + ' (' + fmtB(d.size) + ')</p><div id="fMsg"></div>'
        + '<textarea class="form-control" id="fContent">' + esc(d.content) + '</textarea>'
        + '<div class="mt"><button class="btn btn-p" onclick="saveFile()">💾 Save</button> '
        + '<a href="/api/files/download?path=' + encodeURIComponent(d.path) + '" class="btn btn-w" target="_blank">Download</a> '
        + '<button class="btn btn-d" onclick="pgFiles($(\'content\'))">Back</button></div>';
      return;
    }

    // Directory listing
    var parts = curPath.split('/').filter(Boolean);
    var bc = '<a data-nav="/" onclick="navF(this)">root</a>';
    var bp = '';
    parts.forEach(function(x) {
      bp += '/' + x;
      bc += ' <span>/</span> <a data-nav="' + encodeURIComponent(bp) + '" onclick="navF(this)">' + esc(x) + '</a>';
    });

    var items = (d.items || []).sort(function(a, b) {
      return a.isDir === b.isDir ? a.name.localeCompare(b.name) : (a.isDir ? -1 : 1);
    });
    var parent = curPath === '/' ? '' : (curPath.split('/').slice(0, -1).join('/') || '/');

    var html = '<h2 class="page-title">📁 File Manager</h2>'
      + '<div class="breadcrumb">' + bc + '</div><div id="fMsg"></div>'
      + '<div class="mb">'
      + '<button class="btn btn-p" onclick="uploadF()">📤 Upload</button> '
      + '<button class="btn btn-s" onclick="mkdirF()">📁 New Folder</button>'
      + '</div><div>';

    if (parent) {
      html += '<div class="file-item" data-nav="' + encodeURIComponent(parent) + '" ondblclick="navF(this)">'
        + '<span class="icon">📁</span><span class="name">..</span><span class="size"></span></div>';
    }

    // FIX #8: Use data attributes for paths, no inline string concatenation
    items.forEach(function(i) {
      var fullPath = (curPath === '/' ? '' : curPath) + '/' + i.name;
      var enc = encodeURIComponent(fullPath);
      html += '<div class="file-item" data-nav="' + enc + '" ondblclick="navF(this)">'
        + '<span class="icon">' + (i.isDir ? '📁' : '📄') + '</span>'
        + '<span class="name">' + esc(i.name) + '</span>'
        + (i.perms ? '<span class="perms">' + i.perms + '</span>' : '')
        + '<span class="size">' + (i.isDir ? '' : fmtB(i.size)) + '</span>'
        + '<div class="file-actions">'
        + (!i.isDir ? '<a href="/api/files/download?path=' + enc + '" class="btn btn-p btn-sm" target="_blank" onclick="event.stopPropagation()">⬇</a> ' : '')
        + '<button class="btn btn-w btn-sm" data-rn="' + enc + '" onclick="event.stopPropagation();renF(this)">✏️</button> '
        + '<button class="btn btn-d btn-sm" data-del="' + enc + '" onclick="event.stopPropagation();delF(this)">🗑</button>'
        + '</div></div>';
    });

    html += '</div>';
    el.innerHTML = html;
  });
}

// FIX #8: Safe navigation using data attributes
window.navF = function(el) {
  var p = el.dataset ? el.dataset.nav : el.getAttribute('data-nav');
  if (p) pgFiles($('content'), decodeURIComponent(p));
};

window.saveFile = function() {
  api.put('/api/files', { filePath: editFile, content: $('fContent').value }).then(function(r) {
    $('fMsg').innerHTML = r.success ? '<div class="alert alert-ok">Saved!</div>' : '<div class="alert alert-err">' + (r.error||'Failed') + '</div>';
  });
};

window.delF = function(btn) {
  var p = decodeURIComponent(btn.dataset.del);
  if (confirm('Delete ' + p + '?')) {
    api.del('/api/files?path=' + encodeURIComponent(p)).then(function() { pgFiles($('content')); });
  }
};

window.renF = function(btn) {
  var oldPath = decodeURIComponent(btn.dataset.rn);
  var oldName = oldPath.split('/').pop();
  var newName = prompt('Rename to:', oldName);
  if (newName && newName !== oldName) {
    var dir = oldPath.substring(0, oldPath.lastIndexOf('/'));
    api.post('/api/files/rename', { oldPath: oldPath, newPath: dir + '/' + newName }).then(function(r) {
      if (r.success) pgFiles($('content'));
      else alert('Rename failed: ' + (r.error || ''));
    });
  }
};

window.uploadF = function() {
  var inp = document.createElement('input'); inp.type = 'file';
  inp.onchange = function() {
    var fd = new FormData();
    fd.append('file', inp.files[0]);
    fd.append('path', curPath);
    api.req('/api/files/upload', { method: 'POST', body: fd }).then(function() { pgFiles($('content')); });
  };
  inp.click();
};

window.mkdirF = function() {
  var n = prompt('Folder name:');
  if (n) api.post('/api/files/mkdir', { path: curPath + '/' + n }).then(function() { pgFiles($('content')); });
};

/* ======== Domains ======== */
function pgDom(el) {
  api.get('/api/domains').then(function(d) {
    el.innerHTML = '<h2 class="page-title">🌐 Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div>'
      + '<div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px">'
      + '<button class="btn btn-p" onclick="addDom()">Add Domain</button></div>'
      + '<table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'
      + d.map(function(x) {
        var encDoc = encodeURIComponent(x.docRoot);
        return '<tr><td><strong>' + esc(x.name) + '</strong></td><td><code>' + esc(x.docRoot) + '</code></td>'
          + '<td><button class="btn btn-p btn-sm" data-nav="' + encDoc + '" onclick="navF(this);loadPage(\'files\')">Files</button> '
          + '<button class="btn btn-d btn-sm" data-dom="' + esc(x.name) + '" onclick="delDom(this)">Delete</button></td></tr>';
      }).join('')
      + (d.length === 0 ? '<tr><td colspan="3" style="text-align:center;color:#8a8d93">No domains yet</td></tr>' : '')
      + '</tbody></table>';
  });
}

window.addDom = function() {
  var domain = $('newDom').value.trim();
  if (!domain) return;
  api.post('/api/domains', { domain: domain }).then(function(r) {
    $('domMsg').innerHTML = r.success ? '<div class="alert alert-ok">Domain added! OLS restarted.</div>' : '<div class="alert alert-err">' + (r.error||'Failed') + '</div>';
    if (r.success) setTimeout(function() { loadPage('domains'); }, 1200);
  });
};

window.delDom = function(btn) {
  var n = btn.dataset.dom;
  if (confirm('Delete domain ' + n + '?')) {
    api.del('/api/domains/' + n).then(function(r) {
      if (r.success) loadPage('domains');
      else alert('Error: ' + (r.error || ''));
    });
  }
};

/* ======== Databases ======== */
function pgDb(el) {
  Promise.all([api.get('/api/databases'), api.get('/api/dashboard')]).then(function(res) {
    var d = res[0], info = res[1];
    el.innerHTML = '<h2 class="page-title">🗃️ Databases</h2><p class="page-sub">MariaDB management</p><div id="dbMsg"></div>'
      + '<div class="flex-row">'
      + '<div><label style="font-size:12px;color:#8a8d93">Database</label><input id="dbName" class="form-control" placeholder="my_db"></div>'
      + '<div><label style="font-size:12px;color:#8a8d93">User (optional)</label><input id="dbUser" class="form-control" placeholder="user"></div>'
      + '<div><label style="font-size:12px;color:#8a8d93">Password</label><input id="dbPass" class="form-control" placeholder="pass" type="password"></div>'
      + '<button class="btn btn-p" onclick="addDb()">Create</button></div>'
      + '<table class="tbl"><thead><tr><th>Database</th><th>Actions</th></tr></thead><tbody>'
      + (Array.isArray(d) ? d : []).map(function(x) {
        return '<tr><td><strong>' + esc(x) + '</strong></td><td><button class="btn btn-d btn-sm" data-db="' + esc(x) + '" onclick="dropDb(this)">Drop</button></td></tr>';
      }).join('')
      + '</tbody></table>'
      + '<div class="mt"><a href="http://' + info.ip + ':8088/phpmyadmin/" target="_blank" class="btn btn-w">Open phpMyAdmin</a></div>';
  });
}

window.addDb = function() {
  api.post('/api/databases', { name: $('dbName').value, user: $('dbUser').value, password: $('dbPass').value }).then(function(r) {
    $('dbMsg').innerHTML = r.success ? '<div class="alert alert-ok">Database created!</div>' : '<div class="alert alert-err">' + (r.error||'Failed') + '</div>';
    if (r.success) setTimeout(function() { loadPage('databases'); }, 1000);
  });
};

window.dropDb = function(btn) {
  var n = btn.dataset.db;
  if (confirm('DROP database ' + n + '? This cannot be undone!')) {
    api.del('/api/databases/' + n).then(function() { loadPage('databases'); });
  }
};

/* ======== Tunnel ======== */
function pgTun(el) {
  api.get('/api/tunnel/status').then(function(s) {
    el.innerHTML = '<h2 class="page-title">☁️ Cloudflare Tunnel</h2><p class="page-sub">Secure tunnel to your server</p><div id="tunMsg"></div>'
      + '<div class="card mb"><div class="label">Status</div><span class="badge ' + (s.active ? 'badge-on' : 'badge-off') + '">' + (s.active ? 'Connected' : 'Not Connected') + '</span></div>'
      + '<div class="card"><h3 class="mb">Setup Tunnel</h3>'
      + '<p style="color:#8a8d93;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4f8cff">Cloudflare Zero Trust</a><br>2. Create a Tunnel → copy token<br>3. Paste below</p>'
      + '<div class="flex-row"><input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1"><button class="btn btn-p" onclick="setTun()">Connect</button></div></div>';
  });
}
window.setTun = function() {
  api.post('/api/tunnel/setup', { token: $('tunToken').value.trim() }).then(function(r) {
    $('tunMsg').innerHTML = r.success ? '<div class="alert alert-ok">Tunnel connected!</div>' : '<div class="alert alert-err">' + (r.error||'Failed') + '</div>';
    if (r.success) setTimeout(function() { loadPage('tunnel'); }, 2000);
  });
};

/* ======== Terminal ======== */
function pgTerm(el) {
  el.innerHTML = '<h2 class="page-title">💻 Terminal</h2><p class="page-sub">Run commands on server</p>'
    + '<div class="terminal-box" id="termOut">$ </div>'
    + '<div class="term-input"><input id="termIn" placeholder="Type command..." onkeydown="if(event.key===\'Enter\')runCmd()"><button class="btn btn-p" onclick="runCmd()">Run</button></div>';
  $('termIn').focus();
}
window.runCmd = function() {
  var cmd = $('termIn').value.trim(); if (!cmd) return;
  var out = $('termOut');
  out.textContent += cmd + '\n';
  $('termIn').value = '';
  api.post('/api/terminal', { command: cmd }).then(function(r) {
    out.textContent += (r.output || '') + '\n$ ';
    out.scrollTop = out.scrollHeight;
  });
};

/* ======== Settings ======== */
function pgSet(el) {
  el.innerHTML = '<h2 class="page-title">🔧 Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div>'
    + '<div class="card" style="max-width:400px"><h3 class="mb">Change Password</h3>'
    + '<div class="mb"><label style="font-size:12px;color:#8a8d93">Current Password</label><input type="password" id="curPass" class="form-control"></div>'
    + '<div class="mb"><label style="font-size:12px;color:#8a8d93">New Password</label><input type="password" id="newPass" class="form-control"></div>'
    + '<div class="mb"><label style="font-size:12px;color:#8a8d93">Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>'
    + '<button class="btn btn-p" onclick="chgPass()">Update Password</button></div>';
}
window.chgPass = function() {
  var np = $('newPass').value, cp = $('cfmPass').value;
  if (np !== cp) { $('setMsg').innerHTML = '<div class="alert alert-err">Passwords don\'t match</div>'; return; }
  if (np.length < 6) { $('setMsg').innerHTML = '<div class="alert alert-err">Min 6 characters</div>'; return; }
  api.post('/api/settings/password', { currentPassword: $('curPass').value, newPassword: np }).then(function(r) {
    $('setMsg').innerHTML = r.success ? '<div class="alert alert-ok">Password updated!</div>' : '<div class="alert alert-err">' + (r.error||'Failed') + '</div>';
  });
};

/* ---- Init ---- */
checkAuth();
JSEOF

log "LitePanel app created"

########################################
step "Step 7/9: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
mkdir -p ${PMA_DIR}
cd /tmp
wget -q "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz" -O pma.tar.gz 2>/dev/null
if [ -f pma.tar.gz ] && [ -s pma.tar.gz ]; then
  tar xzf pma.tar.gz
  cp -rf phpMyAdmin-*/* ${PMA_DIR}/
  rm -rf phpMyAdmin-* pma.tar.gz

  BLOWFISH=$(openssl rand -hex 16)
  cat > ${PMA_DIR}/config.inc.php <<PMAEOF
<?php
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
PMAEOF

  chown -R nobody:nogroup ${PMA_DIR}
  log "phpMyAdmin installed"
else
  err "phpMyAdmin download failed (install manually later)"
fi

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
wget -q "$CF_URL" -O cloudflared.deb 2>/dev/null
if [ -f cloudflared.deb ] && [ -s cloudflared.deb ]; then
  dpkg -i cloudflared.deb > /dev/null 2>&1
  rm -f cloudflared.deb
  log "Cloudflared installed"
else
  err "Cloudflared download failed (install manually later)"
fi

apt-get install -y -qq fail2ban > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban 2>/dev/null
log "Fail2Ban installed"

########################################
step "Step 9/9: Configure Firewall + Start Services"
########################################

# Systemd service for LitePanel
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

# Firewall
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow 22/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw allow ${PANEL_PORT}/tcp > /dev/null 2>&1
ufw allow 7080/tcp > /dev/null 2>&1
ufw allow 8088/tcp > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1
log "Firewall configured"

# Restart OLS with new config
systemctl restart lsws 2>/dev/null
systemctl restart mariadb 2>/dev/null

sleep 3

# Save credentials
cat > /root/.litepanel_credentials <<CREDEOF
==========================================
  LitePanel Credentials
==========================================
Panel URL:     http://${SERVER_IP}:${PANEL_PORT}
Panel Login:   ${ADMIN_USER} / ${ADMIN_PASS}

OLS Admin:     http://${SERVER_IP}:7080
OLS Login:     admin / ${ADMIN_PASS}

phpMyAdmin:    http://${SERVER_IP}:8088/phpmyadmin/

MariaDB Root:  ${DB_ROOT_PASS}
==========================================
CREDEOF
chmod 600 /root/.litepanel_credentials

########################################
# FINAL SUMMARY
########################################
echo ""
echo -e "${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║         ✅ Installation Complete!             ║${N}"
echo -e "${C}╠══════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  LitePanel:  ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:  ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin: ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}  Websites:   ${G}http://${SERVER_IP}:80${N} (port 80)"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Panel Login: ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  OLS Admin:   ${Y}admin${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB Root Pass: ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  Credentials: ${B}/root/.litepanel_credentials${N}"
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
