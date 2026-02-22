#!/bin/bash
############################################
# LitePanel Installer v1.1
# Fresh Ubuntu 22.04 LTS Only
# by Boy Barley
# www.boybarley.com
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

[ "$EUID" -ne 0 ] && echo "Run as root!" && exit 1

if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "22.04" ]]; then
    warn "Designed for Ubuntu 22.04. Detected: $PRETTY_NAME"
    read -rp "Continue anyway? (y/n): " cont
    [[ "$cont" != "y" ]] && exit 1
  fi
fi

while fuser /var/lib/dpkg/lock-frontend > /dev/null 2>&1; do
  warn "Waiting for other package manager to finish..."
  sleep 3
done

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v1.1.      ║"
echo "  ║   Ubuntu 22.04 LTS               ║"
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

log "Adding LiteSpeed repository..."
wget -qO /tmp/ls_repo.sh https://repo.litespeed.sh 2>/dev/null
if [ -f /tmp/ls_repo.sh ] && [ -s /tmp/ls_repo.sh ]; then
  bash /tmp/ls_repo.sh > /dev/null 2>&1
  rm -f /tmp/ls_repo.sh
  apt-get update -y -qq > /dev/null 2>&1
fi
if apt-cache show openlitespeed > /dev/null 2>&1; then
  REPO_ADDED=1; log "LiteSpeed repo added (Method 1)"
fi

if [ "$REPO_ADDED" -eq 0 ]; then
  warn "Trying Method 2..."
  wget -qO /tmp/lst_repo.gpg https://rpms.litespeedtech.com/debian/lst_repo.gpg 2>/dev/null
  if [ -f /tmp/lst_repo.gpg ] && [ -s /tmp/lst_repo.gpg ]; then
    gpg --dearmor < /tmp/lst_repo.gpg > /usr/share/keyrings/lst-debian.gpg 2>/dev/null
    [ ! -s /usr/share/keyrings/lst-debian.gpg ] && cp /tmp/lst_repo.gpg /usr/share/keyrings/lst-debian.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/lst-debian.gpg] http://rpms.litespeedtech.com/debian/ ${CODENAME} main" \
      > /etc/apt/sources.list.d/lst_debian_repo.list
  fi
  rm -f /tmp/lst_repo.gpg
  apt-get update -y -qq > /dev/null 2>&1
  apt-cache show openlitespeed > /dev/null 2>&1 && REPO_ADDED=1 && log "LiteSpeed repo added (Method 2)"
fi

if [ "$REPO_ADDED" -eq 0 ]; then
  warn "Trying Method 3 (legacy)..."
  wget -qO - https://rpms.litespeedtech.com/debian/lst_repo.gpg 2>/dev/null | apt-key add - 2>/dev/null
  echo "deb http://rpms.litespeedtech.com/debian/ ${CODENAME} main" > /etc/apt/sources.list.d/lst_debian_repo.list
  apt-get update -y -qq > /dev/null 2>&1
  apt-cache show openlitespeed > /dev/null 2>&1 && REPO_ADDED=1 && log "LiteSpeed repo added (Method 3)"
fi

[ "$REPO_ADDED" -eq 0 ] && err "FATAL: Cannot add LiteSpeed repo!" && exit 1

log "Installing OpenLiteSpeed..."
apt-get install -y openlitespeed > /tmp/ols_install.log 2>&1
if [ $? -ne 0 ] || [ ! -d "/usr/local/lsws" ]; then
  err "FATAL: OLS install failed!"; tail -30 /tmp/ols_install.log; exit 1
fi
log "OpenLiteSpeed installed"

log "Installing PHP 8.1..."
apt-get install -y lsphp81 > /tmp/php_base.log 2>&1
if [ $? -ne 0 ] || [ ! -f "/usr/local/lsws/lsphp81/bin/php" ]; then
  err "FATAL: PHP 8.1 install failed!"; tail -20 /tmp/php_base.log; exit 1
fi

for ext in common mysql mysqli curl json mbstring xml gd zip intl opcache; do
  apt-get install -y lsphp81-${ext} > /dev/null 2>&1 && log "  lsphp81-${ext} installed" || warn "  lsphp81-${ext} not available"
done

ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null
log "PHP $(php -v 2>/dev/null | head -1 | awk '{print $2}') ready"

PHP_INI_DIR="/usr/local/lsws/lsphp81/etc/php/8.1/litespeed"
mkdir -p "$PHP_INI_DIR"
PHP_INI="$PHP_INI_DIR/php.ini"
cat > "$PHP_INI" <<'PHPINI'
[PHP]
engine = On
expose_php = Off
max_execution_time = 30
memory_limit = 256M
post_max_size = 50M
upload_max_filesize = 50M
display_errors = Off
log_errors = On
[MySQLi]
mysqli.default_socket = /var/run/mysqld/mysqld.sock
[MySQL]
mysql.default_socket = /var/run/mysqld/mysqld.sock
[PDO_MYSQL]
pdo_mysql.default_socket = /var/run/mysqld/mysqld.sock
[Session]
session.save_path = "/tmp"
session.cookie_httponly = 1
[Date]
date.timezone = UTC
PHPINI
log "PHP configured"

########################################
step "Step 4/10: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

for i in $(seq 1 15); do mysqladmin ping &>/dev/null && break; sleep 2; done

if mysqladmin ping &>/dev/null; then
  mysql -u root <<SQLEOF 2>/dev/null
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQLEOF
  [ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ] && ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock
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
command -v node > /dev/null 2>&1 && log "Node.js $(node -v) installed" || { err "Node.js failed!"; exit 1; }

########################################
step "Step 6/10: Creating LitePanel App"
########################################
mkdir -p ${PANEL_DIR}/{public/css,public/js}
cd ${PANEL_DIR}

cat > package.json <<'PKGEOF'
{
  "name": "litepanel",
  "version": "2.2.0",
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
if [ $? -ne 0 ]; then
  warn "Retrying with --legacy-peer-deps..."
  npm install --production --legacy-peer-deps > /tmp/npm_install.log 2>&1
  [ $? -ne 0 ] && err "npm install failed" && tail -10 /tmp/npm_install.log && exit 1
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

# ============================================================
# app.js
# ============================================================
cat > app.js <<'APPEOF'
'use strict';
const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const { execSync } = require('child_process');
const fs         = require('fs');
const path       = require('path');
const os         = require('os');
const multer     = require('multer');
const AdmZip     = require('adm-zip');
const mime       = require('mime-types');

const CONFIG_PATH      = path.join(__dirname, 'config.json');
let   config           = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

const OLS_CONF          = '/usr/local/lsws/conf/httpd_config.conf';
const OLS_VHOST_CONF_DIR = '/usr/local/lsws/conf/vhosts';
const OLS_VHOST_DIR      = '/usr/local/lsws/vhosts';
const MAX_EDIT_SIZE      = 5 * 1024 * 1024;

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: config.sessionSecret,
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 86400000, httpOnly: true, sameSite: 'strict' }
}));
app.use(express.static(path.join(__dirname, 'public')));

/* ── Middleware ─────────────────────────────────────────────────────────── */
const auth = (req, res, next) =>
  (req.session && req.session.user) ? next() : res.status(401).json({ error: 'Unauthorized' });

/* ── Helpers ────────────────────────────────────────────────────────────── */
function run(cmd, timeout) {
  try {
    return execSync(cmd, { timeout: timeout || 15000, maxBuffer: 10 * 1024 * 1024 }).toString().trim();
  } catch(e) {
    return (e.stderr ? e.stderr.toString() : e.message).trim();
  }
}

function svcActive(name) {
  try { execSync(`systemctl is-active ${name}`, { stdio: 'pipe' }); return true; }
  catch(e) { return false; }
}

/* Shell-escape single argument for use inside single-quoted shell strings */
function sq(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/'/g, "'\\''");
}

/* Build a safe mysql command */
function mysqlCmd(sql) {
  const dp = sq(config.dbRootPass);
  return `mysql -u root -p'${dp}' -e ${JSON.stringify(sql)} 2>&1`;
}

function decodeP(s) {
  try { return decodeURIComponent(s); } catch(e) { return s; }
}

function isText(filePath, size) {
  if (size > 1024 * 1024) return false;
  try {
    const fd  = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(Math.min(size, 8192));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    return !buf.includes(0);
  } catch(e) { return false; }
}

function zipFiles(sources, output) {
  try {
    const zip = new AdmZip();
    for (const src of sources) {
      const st = fs.statSync(src);
      if (st.isDirectory()) zip.addLocalFolder(src, path.basename(src));
      else zip.addLocalFile(src);
    }
    zip.writeZip(output);
    return true;
  } catch(e) { console.error('zip error:', e.message); return false; }
}

function unzipFile(archivePath, targetDir) {
  try {
    const zip = new AdmZip(archivePath);
    zip.extractAllTo(targetDir, true);
    return true;
  } catch(e) { console.error('unzip error:', e.message); return false; }
}

function escR(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/* ── OLS Config ─────────────────────────────────────────────────────────── */
function readOLS()          { return fs.readFileSync(OLS_CONF, 'utf8'); }
function writeOLS(content)  { fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak'); fs.writeFileSync(OLS_CONF, content); }

function addVhostToOLS(domain) {
  let httpd = readOLS();
  if (httpd.includes(`virtualhost ${domain} {`)) return;
  httpd += `\nvirtualhost ${domain} {\n`
    + `  vhRoot                  ${OLS_VHOST_DIR}/${domain}\n`
    + `  configFile              ${OLS_VHOST_CONF_DIR}/${domain}/vhconf.conf\n`
    + `  allowSymbolLink         1\n  enableScript            1\n  restrained              1\n}\n`;
  // add map to listener
  const lRe = /(listener\s+HTTP\s*\{[\s\S]*?)(})/;
  if (lRe.test(httpd)) {
    httpd = httpd.replace(lRe, `$1  map                     ${domain} ${domain}, www.${domain}\n$2`);
  } else {
    httpd += `\nlistener HTTP {\n  address                 *:80\n  secure                  0\n  map                     ${domain} ${domain}, www.${domain}\n}\n`;
  }
  writeOLS(httpd);
}

function removeVhostFromOLS(domain) {
  let httpd = readOLS();
  fs.copyFileSync(OLS_CONF, OLS_CONF + '.bak');
  httpd = httpd.replace(new RegExp(`\\n?virtualhost\\s+${escR(domain)}\\s*\\{[\\s\\S]*?\\}`, 'g'), '');
  httpd = httpd.replace(new RegExp(`^\\s*map\\s+${escR(domain)}\\s+.*$`, 'gm'), '');
  httpd = httpd.replace(/\n{3,}/g, '\n\n');
  fs.writeFileSync(OLS_CONF, httpd);
}

function createVhostFiles(domain, docRootOverride) {
  const confDir = path.join(OLS_VHOST_CONF_DIR, domain);
  const docRoot = docRootOverride || path.join(OLS_VHOST_DIR, domain, 'html');
  const logDir  = path.join(OLS_VHOST_DIR, domain, 'logs');
  fs.mkdirSync(confDir, { recursive: true });
  fs.mkdirSync(docRoot, { recursive: true });
  fs.mkdirSync(logDir,  { recursive: true });

  const vhConf = `docRoot                   ${docRoot}\n`
    + `vhDomain                  ${domain}\n`
    + `vhAliases                 www.${domain}\n`
    + `enableGzip                1\n\n`
    + `index {\n  useServer               0\n  indexFiles              index.php, index.html\n  autoIndex               0\n}\n\n`
    + `scripthandler {\n  add                     lsapi:lsphp81 php\n}\n\n`
    + `accessControl {\n  allow                   *\n}\n\n`
    + `rewrite {\n  enable                  1\n  autoLoadHtaccess        1\n}\n`;

  fs.writeFileSync(path.join(confDir, 'vhconf.conf'), vhConf);
  fs.writeFileSync(path.join(docRoot, 'index.html'),
    `<!DOCTYPE html>\n<html><head><title>${domain}</title></head>\n<body><h1>Welcome to ${domain}</h1></body></html>\n`);
  try { execSync(`chown -R nobody:nogroup ${path.join(OLS_VHOST_DIR, domain)}`); } catch(e) {}
  return docRoot;
}

function safeRestartOLS() {
  execSync('systemctl restart lsws', { timeout: 15000 });
  execSync('sleep 2', { timeout: 5000 });
  try { execSync('systemctl is-active lsws', { stdio: 'pipe' }); }
  catch(e) {
    if (fs.existsSync(OLS_CONF + '.bak')) {
      fs.copyFileSync(OLS_CONF + '.bak', OLS_CONF);
      execSync('systemctl restart lsws', { timeout: 15000 });
    }
    throw new Error('OLS config error, reverted');
  }
}

/* ── Auth ───────────────────────────────────────────────────────────────── */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === config.adminUser && bcrypt.compareSync(password, config.adminPass)) {
    req.session.user = username;
    res.json({ success: true });
  } else res.status(401).json({ error: 'Invalid credentials' });
});
app.get('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth',   (req, res) => res.json({ authenticated: !!(req.session && req.session.user) }));

/* ── Dashboard ──────────────────────────────────────────────────────────── */
app.get('/api/dashboard', auth, (req, res) => {
  const tm = os.totalmem(), fm = os.freemem();
  let disk = { total: 0, used: 0, free: 0 };
  try { const d = run("df -B1 / | tail -1").split(/\s+/); disk = { total: +d[1], used: +d[2], free: +d[3] }; } catch(e) {}
  const cpus = os.cpus();
  res.json({
    hostname: os.hostname(), ip: run("hostname -I | awk '{print $1}'"),
    uptime: os.uptime(),
    cpu: { model: cpus[0]?.model || 'Unknown', cores: cpus.length, load: os.loadavg() },
    memory: { total: tm, used: tm - fm, free: fm }, disk, nodeVersion: process.version
  });
});

/* ── Services ───────────────────────────────────────────────────────────── */
app.get('/api/services', auth, (req, res) =>
  res.json(['lsws','mariadb','fail2ban','cloudflared'].map(s => ({ name: s, active: svcActive(s) })))
);
app.post('/api/services/:name/:action', auth, (req, res) => {
  const allowed = ['lsws','mariadb','fail2ban','cloudflared'];
  const acts    = ['start','stop','restart'];
  if (!allowed.includes(req.params.name) || !acts.includes(req.params.action))
    return res.status(400).json({ error: 'Invalid' });
  try { execSync(`systemctl ${req.params.action} ${req.params.name}`, { timeout: 15000 }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── File Manager ───────────────────────────────────────────────────────── */
app.get('/api/files', auth, (req, res) => {
  const p = path.resolve(decodeP(req.query.path || '/'));
  try {
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      const items = [];
      for (const name of fs.readdirSync(p)) {
        try {
          const s = fs.statSync(path.join(p, name));
          items.push({ name, isDir: s.isDirectory(), size: s.size, modified: s.mtime,
            perms: '0' + (s.mode & 0o777).toString(8), extension: path.extname(name).toLowerCase().slice(1) });
        } catch(e) { items.push({ name, isDir: false, size: 0, error: true }); }
      }
      res.json({ path: p, items });
    } else {
      if (stat.size > MAX_EDIT_SIZE) return res.json({ path: p, size: stat.size, tooLarge: true });
      if (!isText(p, stat.size))     return res.json({ path: p, size: stat.size, binary: true });
      res.json({ path: p, content: fs.readFileSync(p, 'utf8'), size: stat.size,
        extension: path.extname(p).toLowerCase().slice(1) });
    }
  } catch(e) { res.status(404).json({ error: e.message }); }
});

app.put('/api/files', auth, (req, res) => {
  try { fs.writeFileSync(req.body.filePath, req.body.content); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/files', auth, (req, res) => {
  const target = decodeP(req.query.path);
  if (!target || target === '/') return res.status(400).json({ error: 'Cannot delete root' });
  try { fs.rmSync(target, { recursive: true, force: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

const upload = multer({ dest: '/tmp/uploads/' });
app.post('/api/files/upload', auth, upload.array('files'), (req, res) => {
  try {
    const targetPath = decodeP(req.body.path) || '/tmp';
    if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files uploaded' });
    const results = [];
    for (const file of req.files) {
      const dest = path.join(targetPath, file.originalname);
      fs.renameSync(file.path, dest);
      results.push({ name: file.originalname, size: file.size, success: true });
    }
    res.json({ success: true, files: results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/mkdir', auth, (req, res) => {
  try { fs.mkdirSync(decodeP(req.body.path), { recursive: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/newfile', auth, (req, res) => {
  try {
    const fp = decodeP(req.body.path);
    if (!fp) return res.status(400).json({ error: 'Path required' });
    if (fs.existsSync(fp)) return res.status(400).json({ error: 'File already exists' });
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, req.body.content || '');
    res.json({ success: true, path: fp });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/rename', auth, (req, res) => {
  try { fs.renameSync(decodeP(req.body.oldPath), decodeP(req.body.newPath)); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

/* Copy – recursive, handles name conflicts */
app.post('/api/files/copy', auth, (req, res) => {
  try {
    const sources   = (req.body.sources || []).map(decodeP);
    const targetDir = decodeP(req.body.target);
    if (!sources.length || !targetDir) return res.status(400).json({ error: 'Invalid params' });
    fs.mkdirSync(targetDir, { recursive: true });
    let copied = 0;
    for (const src of sources) {
      if (!fs.existsSync(src)) continue;
      const dest = path.join(targetDir, path.basename(src));
      const result = run(`cp -a '${sq(src)}' '${sq(dest)}'`);
      if (result && result.toLowerCase().includes('error')) throw new Error(result);
      copied++;
    }
    res.json({ success: true, copied });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/download', auth, (req, res) => {
  const fp = decodeP(req.query.path);
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: 'Not found' });
  try {
    if (fs.statSync(fp).isDirectory()) return res.status(400).json({ error: 'Cannot download directory' });
    res.setHeader('Content-Type', mime.lookup(fp) || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(fp)}"`);
    fs.createReadStream(fp).pipe(res);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/compress', auth, (req, res) => {
  try {
    const sources = (req.body.paths || []).map(decodeP);
    let   output  = decodeP(req.body.output);
    if (!sources.length || !output) return res.status(400).json({ error: 'Invalid params' });
    for (const p of sources) { if (!fs.existsSync(p)) return res.status(404).json({ error: `Not found: ${p}` }); }
    if (!output.endsWith('.zip')) output += '.zip';
    if (zipFiles(sources, output)) res.json({ success: true, path: output });
    else res.status(500).json({ error: 'Compression failed' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/extract', auth, (req, res) => {
  try {
    const archivePath = decodeP(req.body.archive);
    const targetDir   = decodeP(req.body.target);
    if (!archivePath || !targetDir) return res.status(400).json({ error: 'Invalid params' });
    if (!fs.existsSync(archivePath)) return res.status(404).json({ error: 'Archive not found' });
    fs.mkdirSync(targetDir, { recursive: true });
    const ext = path.extname(archivePath).toLowerCase();
    let ok = false;
    if (ext === '.zip') {
      ok = unzipFile(archivePath, targetDir);
    } else if (['.gz','.bz2','.tgz','.tar','.xz'].includes(ext)) {
      const r = run(`tar -xf '${sq(archivePath)}' -C '${sq(targetDir)}'`, 60000);
      ok = !(r && r.toLowerCase().includes('error'));
    } else {
      ok = unzipFile(archivePath, targetDir);
    }
    if (ok) res.json({ success: true, path: targetDir });
    else res.status(500).json({ error: 'Extraction failed – unsupported format or corrupt archive' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files/permissions', auth, (req, res) => {
  const p = decodeP(req.query.path);
  if (!p || !fs.existsSync(p)) return res.status(404).json({ error: 'Not found' });
  try {
    const st    = fs.statSync(p);
    const perms = '0' + (st.mode & 0o777).toString(8);
    const owner = run(`stat -c "%U" '${sq(p)}'`) || 'unknown';
    const group = run(`stat -c "%G" '${sq(p)}'`) || 'unknown';
    res.json({ permissions: perms, owner, group, isDir: st.isDirectory() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/files/permissions', auth, (req, res) => {
  try {
    const fp   = decodeP(req.body.path);
    const perm = req.body.permissions;
    const rec  = req.body.recursive === true;
    if (!fp || !perm || !fs.existsSync(fp)) return res.status(400).json({ error: 'Invalid params' });
    if (!/^(0)?[0-7]{3,4}$/.test(perm))    return res.status(400).json({ error: 'Invalid permission format' });
    run(`chmod ${rec ? '-R ' : ''}${perm} '${sq(fp)}'`);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Domains ────────────────────────────────────────────────────────────── */
const DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

app.get('/api/domains', auth, (req, res) => {
  try {
    if (!fs.existsSync(OLS_VHOST_CONF_DIR)) return res.json([]);
    const list = fs.readdirSync(OLS_VHOST_CONF_DIR).filter(n => {
      try { return fs.statSync(path.join(OLS_VHOST_CONF_DIR, n)).isDirectory() && n !== 'Example'; }
      catch(e) { return false; }
    });
    res.json(list.map(name => ({
      name,
      docRoot: path.join(OLS_VHOST_DIR, name, 'html'),
      isSubdomain: name.split('.').length > 2
    })));
  } catch(e) { res.json([]); }
});

app.post('/api/domains', auth, (req, res) => {
  const domain = (req.body.domain || '').trim().toLowerCase();
  if (!domain || !DOMAIN_RE.test(domain)) return res.status(400).json({ error: 'Invalid domain name' });
  try {
    const docRoot = createVhostFiles(domain);
    addVhostToOLS(domain);
    safeRestartOLS();
    res.json({ success: true, domain, docRoot });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Add subdomain – docRoot can be custom or defaults to OLS_VHOST_DIR/subdomain/html */
app.post('/api/domains/subdomain', auth, (req, res) => {
  const subdomain  = (req.body.subdomain || '').trim().toLowerCase();   // e.g. sub.example.com
  const parentDomain = (req.body.parent || '').trim().toLowerCase();     // e.g. example.com
  const customDocRoot = req.body.docRoot ? req.body.docRoot.trim() : ''; // optional

  if (!subdomain || !DOMAIN_RE.test(subdomain))
    return res.status(400).json({ error: 'Invalid subdomain' });
  if (!parentDomain || !DOMAIN_RE.test(parentDomain))
    return res.status(400).json({ error: 'Invalid parent domain' });
  if (!subdomain.endsWith('.' + parentDomain))
    return res.status(400).json({ error: `Subdomain must end with .${parentDomain}` });

  try {
    const docRoot = createVhostFiles(subdomain, customDocRoot || null);
    addVhostToOLS(subdomain);
    safeRestartOLS();
    res.json({ success: true, subdomain, docRoot });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/domains/:name', auth, (req, res) => {
  const domain = req.params.name;
  if (!domain || !DOMAIN_RE.test(domain)) return res.status(400).json({ error: 'Invalid domain' });
  try {
    removeVhostFromOLS(domain);
    fs.rmSync(path.join(OLS_VHOST_CONF_DIR, domain), { recursive: true, force: true });
    safeRestartOLS();
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Databases ──────────────────────────────────────────────────────────── */
const DB_RE   = /^[a-zA-Z0-9_]{1,64}$/;
const USER_RE = /^[a-zA-Z0-9_]{1,32}$/;

/* Helper: run a single SQL statement safely via mysql CLI */
function sqlExec(sql) {
  const dp  = sq(config.dbRootPass);
  const cmd = `mysql -u root -p'${dp}' -s -N -e '${sq(sql)}' 2>&1`;
  return run(cmd);
}

function sqlExecRaw(sql) {
  /* For SQL containing backticks or complex quoting, write to temp file */
  const tmp = `/tmp/lp_sql_${Date.now()}.sql`;
  fs.writeFileSync(tmp, sql, 'utf8');
  const dp  = sq(config.dbRootPass);
  const out = run(`mysql -u root -p'${dp}' 2>&1 < '${sq(tmp)}'`);
  try { fs.unlinkSync(tmp); } catch(e) {}
  return out;
}

app.get('/api/databases', auth, (req, res) => {
  try {
    const skip = new Set(['information_schema','performance_schema','mysql','sys']);
    const dbOut = sqlExec('SHOW DATABASES');
    const databases = dbOut.split('\n').map(d => d.trim()).filter(d => d && !skip.has(d));

    const userOut = sqlExec(
      "SELECT User FROM mysql.user WHERE Host='localhost' AND User NOT IN ('root','debian-sys-maint','mariadb.sys')"
    );
    const users = userOut.split('\n').map(u => u.trim()).filter(Boolean);

    const result = databases.map(db => {
      const dbUsers = users.filter(u => {
        const g = sqlExec(`SHOW GRANTS FOR '${sq(u)}'@'localhost'`);
        return g.includes(`\`${db}\``) || g.includes('*.*');
      });
      return { name: db, users: dbUsers };
    });
    res.json(result);
  } catch(e) { console.error(e); res.json([]); }
});

app.get('/api/database-users', auth, (req, res) => {
  try {
    const out = sqlExec(
      "SELECT User, Host FROM mysql.user WHERE Host='localhost' AND User NOT IN ('root','debian-sys-maint','mariadb.sys')"
    );
    const users = out.split('\n').map(line => {
      const parts = line.trim().split('\t');
      return parts[0] ? { username: parts[0], host: parts[1] || 'localhost' } : null;
    }).filter(Boolean);
    res.json(users);
  } catch(e) { console.error(e); res.json([]); }
});

/* Create database  ── FIXED: uses temp-file SQL to avoid quoting issues */
app.post('/api/databases', auth, (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const user = (req.body.user || '').trim();
    const pass = (req.body.password || '').trim();

    if (!name || !DB_RE.test(name))
      return res.status(400).json({ error: 'Invalid database name (letters, numbers, underscore only)' });

    // Build SQL block
    let sql = `CREATE DATABASE IF NOT EXISTS \`${name}\`;\n`;

    if (user) {
      if (!USER_RE.test(user))
        return res.status(400).json({ error: 'Invalid username (letters, numbers, underscore only)' });
      if (!pass)
        return res.status(400).json({ error: 'Password is required when assigning a user' });

      // Use CREATE USER IF NOT EXISTS + update password separately (covers existing users)
      sql += `CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${pass}';\n`;
      sql += `ALTER USER '${user}'@'localhost' IDENTIFIED BY '${pass}';\n`;
      sql += `GRANT ALL PRIVILEGES ON \`${name}\`.* TO '${user}'@'localhost';\n`;
      sql += `FLUSH PRIVILEGES;\n`;
    }

    const result = sqlExecRaw(sql);

    // Check for real errors (ignore warnings)
    if (result && /ERROR\s+\d+/i.test(result)) {
      return res.status(500).json({ error: result });
    }

    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Create user only */
app.post('/api/database-users', auth, (req, res) => {
  try {
    const user = (req.body.username || '').trim();
    const pass = (req.body.password || '').trim();
    const dbs  = Array.isArray(req.body.databases) ? req.body.databases : [];

    if (!user || !USER_RE.test(user)) return res.status(400).json({ error: 'Invalid username' });
    if (!pass)                         return res.status(400).json({ error: 'Password is required' });

    let sql = `CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${pass}';\n`;
    sql    += `ALTER USER '${user}'@'localhost' IDENTIFIED BY '${pass}';\n`;
    for (const db of dbs) {
      if (DB_RE.test(db)) sql += `GRANT ALL PRIVILEGES ON \`${db}\`.* TO '${user}'@'localhost';\n`;
    }
    sql += `FLUSH PRIVILEGES;\n`;

    const result = sqlExecRaw(sql);
    if (result && /ERROR\s+\d+/i.test(result)) return res.status(500).json({ error: result });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Change DB user password – uses ALTER USER (correct for MariaDB/MySQL) */
app.post('/api/database-users/:name/password', auth, (req, res) => {
  const user = req.params.name;
  const pass = (req.body.newPassword || '').trim();
  if (!user || !USER_RE.test(user)) return res.status(400).json({ error: 'Invalid username' });
  if (!pass || pass.length < 4)     return res.status(400).json({ error: 'Password too short (min 4)' });
  try {
    const exists = sqlExec(`SELECT COUNT(*) FROM mysql.user WHERE User='${sq(user)}' AND Host='localhost'`);
    if (exists.trim() === '0') return res.status(404).json({ error: 'User not found' });

    const sql = `ALTER USER '${user}'@'localhost' IDENTIFIED BY '${pass}';\nFLUSH PRIVILEGES;\n`;
    const r   = sqlExecRaw(sql);
    if (r && /ERROR\s+\d+/i.test(r)) return res.status(500).json({ error: r });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/databases/:name', auth, (req, res) => {
  if (!DB_RE.test(req.params.name)) return res.status(400).json({ error: 'Invalid' });
  try {
    const r = sqlExecRaw(`DROP DATABASE IF EXISTS \`${req.params.name}\`;\n`);
    if (r && /ERROR\s+\d+/i.test(r)) return res.status(500).json({ error: r });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/database-users/:name', auth, (req, res) => {
  if (!USER_RE.test(req.params.name)) return res.status(400).json({ error: 'Invalid' });
  try {
    const r = sqlExecRaw(`DROP USER IF EXISTS '${req.params.name}'@'localhost';\nFLUSH PRIVILEGES;\n`);
    if (r && /ERROR\s+\d+/i.test(r)) return res.status(500).json({ error: r });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* Database Backup */
app.post('/api/databases/:name/backup', auth, (req, res) => {
  const dbName = req.params.name;
  if (!DB_RE.test(dbName)) return res.status(400).json({ error: 'Invalid database name' });
  try {
    const ts      = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
    const sqlFile = `/tmp/${dbName}_${ts}.sql`;
    const gzFile  = sqlFile + '.gz';
    const dp      = sq(config.dbRootPass);

    const dumpOut = run(
      `mysqldump -u root -p'${dp}' --single-transaction --routines --triggers '${sq(dbName)}' > '${sq(sqlFile)}'`,
      120000
    );
    if (dumpOut && /ERROR\s+\d+/i.test(dumpOut)) return res.status(500).json({ error: `mysqldump: ${dumpOut}` });
    if (!fs.existsSync(sqlFile) || fs.statSync(sqlFile).size === 0)
      return res.status(500).json({ error: 'Backup file empty or missing' });

    run(`gzip -f '${sq(sqlFile)}'`, 30000);
    if (!fs.existsSync(gzFile)) return res.status(500).json({ error: 'gzip compression failed' });

    res.json({ success: true, filename: path.basename(gzFile), path: gzFile,
      size: fs.statSync(gzFile).size,
      downloadUrl: '/api/files/download?path=' + encodeURIComponent(gzFile) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Tunnel ─────────────────────────────────────────────────────────────── */
app.get('/api/tunnel/status', auth, (req, res) => res.json({ active: svcActive('cloudflared') }));
app.post('/api/tunnel/setup', auth, (req, res) => {
  const token = req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });
  const safeToken = token.replace(/[;&|`$(){}]/g, '');
  try {
    fs.writeFileSync('/etc/systemd/system/cloudflared.service',
      `[Unit]\nDescription=Cloudflare Tunnel\nAfter=network.target\n\n`
      + `[Service]\nType=simple\nExecStart=/usr/bin/cloudflared tunnel run --token ${safeToken}\n`
      + `Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n`);
    execSync('systemctl daemon-reload && systemctl enable cloudflared && systemctl restart cloudflared', { timeout: 15000 });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

/* ── Settings ───────────────────────────────────────────────────────────── */
app.post('/api/settings/password', auth, (req, res) => {
  if (!bcrypt.compareSync(req.body.currentPassword, config.adminPass))
    return res.status(401).json({ error: 'Wrong current password' });
  if (!req.body.newPassword || req.body.newPassword.length < 6)
    return res.status(400).json({ error: 'Min 6 characters' });
  config.adminPass = bcrypt.hashSync(req.body.newPassword, 10);
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

/* ── Terminal ───────────────────────────────────────────────────────────── */
app.post('/api/terminal', auth, (req, res) => {
  if (!req.body.command) return res.json({ output: '' });
  try { res.json({ output: run(req.body.command, 30000) }); }
  catch(e) { res.json({ output: e.message }); }
});

app.listen(config.panelPort, '0.0.0.0', () =>
  console.log(`LitePanel v2.2 running on port ${config.panelPort}`)
);
APPEOF

# ============================================================
# public/index.html
# ============================================================
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

# ============================================================
# public/css/style.css
# ============================================================
cat > public/css/style.css <<'CSSEOF'
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#f5f7fa;color:#333;line-height:1.5}

/* Login */
.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#f5f7fa,#e4e7eb)}
.login-box{background:#fff;padding:40px;border-radius:12px;width:360px;box-shadow:0 8px 30px rgba(0,0,0,0.1);position:relative}
.login-box h1{text-align:center;color:#4a89dc;margin-bottom:30px;font-size:28px}
.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#f5f7fa;border:1px solid #e4e7eb;border-radius:8px;color:#333;font-size:14px;outline:none}
.login-box input:focus{border-color:#4a89dc;box-shadow:0 0 0 2px rgba(74,137,220,0.2)}
.login-box button{width:100%;padding:12px;background:#4a89dc;border:none;border-radius:8px;color:#fff;font-size:16px;cursor:pointer;font-weight:600;transition:background .3s}
.login-box button:hover{background:#3a7bd5}
.error{color:#e74c3c;text-align:center;margin-top:10px;font-size:14px}
.copyright{position:absolute;bottom:-30px;left:0;right:0;text-align:center;color:#7f8c8d;font-size:12px}

/* Layout */
.main-panel{display:flex;min-height:100vh}
.sidebar{width:240px;background:#fff;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10;transition:transform .3s;box-shadow:0 0 20px rgba(0,0,0,0.05)}
.sidebar .logo{padding:20px;font-size:20px;font-weight:700;color:#4a89dc;border-bottom:1px solid #eee}
.sidebar nav{flex:1;padding:10px 0;overflow-y:auto}
.sidebar nav a{display:flex;align-items:center;padding:12px 20px;color:#606060;text-decoration:none;transition:.2s;font-size:14px}
.sidebar nav a i{margin-right:10px;width:20px;text-align:center}
.sidebar nav a:hover,.sidebar nav a.active{background:#f0f4f8;color:#4a89dc;border-left:3px solid #4a89dc}
.logout-btn{padding:15px 20px;color:#e74c3c;text-decoration:none;border-top:1px solid #eee;font-size:14px;display:flex;align-items:center}
.logout-btn i{margin-right:10px;width:20px;text-align:center}
.content{flex:1;margin-left:240px;padding:30px;min-height:100vh}
.mobile-toggle{display:none;position:fixed;top:10px;left:10px;z-index:20;background:#fff;border:none;color:#4a89dc;font-size:20px;padding:8px 12px;border-radius:8px;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
@media(max-width:768px){
  .mobile-toggle{display:block}
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .content{margin-left:0;padding:15px;padding-top:55px}
  .stats-grid{grid-template-columns:1fr!important}
}

/* Common */
.page-title{font-size:24px;margin-bottom:8px;color:#2c3e50}
.page-sub{color:#7f8c8d;margin-bottom:25px;font-size:14px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:25px}
.card{background:#fff;padding:20px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05)}
.card .label{font-size:12px;color:#95a5a6;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.card .value{font-size:22px;font-weight:700;color:#4a89dc}
.card .sub{font-size:12px;color:#7f8c8d;margin-top:4px}
.progress{background:#ecf0f1;border-radius:8px;height:8px;margin-top:8px;overflow:hidden}
.progress-bar{height:100%;border-radius:8px;background:#4a89dc;transition:width .3s}
.progress-bar.warn{background:#f39c12}
.progress-bar.danger{background:#e74c3c}

/* Tables */
table.tbl{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.05)}
.tbl th{background:#f8f9fa;padding:12px 16px;text-align:left;font-size:12px;color:#7f8c8d;text-transform:uppercase;font-weight:600;border-bottom:1px solid #ecf0f1}
.tbl td{padding:12px 16px;border-bottom:1px solid #ecf0f1;font-size:14px;color:#34495e}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:#f8f9fa}

/* Buttons */
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500;transition:.2s;display:inline-flex;align-items:center;gap:5px;text-decoration:none;text-align:center;white-space:nowrap}
.btn:hover{opacity:.88}
.btn-p{background:#4a89dc;color:#fff}
.btn-s{background:#2ecc71;color:#fff}
.btn-d{background:#e74c3c;color:#fff}
.btn-w{background:#f39c12;color:#fff}
.btn-l{background:#ecf0f1;color:#555}
.btn-info{background:#3498db;color:#fff}
.btn-purple{background:#9b59b6;color:#fff}
.btn-sm{padding:4px 10px;font-size:12px}

/* Badges */
.badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600;display:inline-block}
.badge-on{background:rgba(46,204,113,0.15);color:#27ae60}
.badge-off{background:rgba(231,76,60,0.15);color:#e74c3c}
.badge-sub{background:rgba(155,89,182,0.15);color:#9b59b6}

/* Forms */
.form-control{width:100%;padding:10px 14px;background:#f8f9fa;border:1px solid #e4e7eb;border-radius:8px;color:#34495e;font-size:14px;outline:none;transition:all .2s}
.form-control:focus{border-color:#4a89dc;box-shadow:0 0 0 2px rgba(74,137,220,0.2)}
textarea.form-control{min-height:300px;font-family:'Monaco','Menlo','Ubuntu Mono','Consolas',monospace;font-size:13px;resize:vertical}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:14px;margin-bottom:8px;color:#34495e}

/* Alerts */
.alert{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.alert-ok{background:rgba(46,204,113,0.1);border:1px solid #2ecc71;color:#27ae60}
.alert-err{background:rgba(231,76,60,0.1);border:1px solid #e74c3c;color:#e74c3c}

/* Breadcrumb */
.breadcrumb{display:flex;gap:5px;padding:10px 16px 0;flex-wrap:wrap;font-size:14px}
.breadcrumb a{color:#4a89dc;text-decoration:none;cursor:pointer}
.breadcrumb a:hover{text-decoration:underline}
.breadcrumb span{color:#7f8c8d}

/* File Manager */
.file-manager{background:#fff;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);overflow:hidden;display:flex;flex-direction:column;height:calc(100vh - 160px);min-height:400px}
.file-toolbar{padding:10px 16px;background:#f8f9fa;border-bottom:1px solid #ecf0f1;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.file-toolbar-group{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.file-container{flex:1;overflow:auto}
.file-item{display:flex;align-items:center;padding:9px 16px;border-bottom:1px solid #ecf0f1;cursor:pointer;font-size:14px;color:#34495e;user-select:none;transition:background .15s}
.file-item:last-child{border-bottom:none}
.file-item:hover{background:#f8f9fa}
.file-item.selected{background:#e8f4fd}
.file-icon{margin-right:10px;font-size:16px;width:22px;text-align:center;color:#95a5a6;flex-shrink:0}
.file-icon.fi-folder{color:#f39c12}
.file-icon.fi-image{color:#3498db}
.file-icon.fi-code{color:#2ecc71}
.file-icon.fi-archive{color:#9b59b6}
.file-icon.fi-pdf{color:#e74c3c}
.file-item .fname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-item .fsize{color:#95a5a6;min-width:70px;text-align:right;font-size:12px;margin-right:8px}
.file-item .fperms{color:#bdc3c7;font-family:monospace;font-size:11px;width:60px;text-align:right;margin-right:8px}
.file-item .fdate{color:#95a5a6;width:140px;font-size:12px;text-align:right}
.cb-wrap{width:22px;display:flex;align-items:center;justify-content:center;margin-right:8px;flex-shrink:0}
.cb-wrap input{width:15px;height:15px;cursor:pointer}
.file-status-bar{padding:8px 16px;background:#f8f9fa;border-top:1px solid #ecf0f1;font-size:13px;color:#7f8c8d;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;min-height:42px}
.sel-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap}

/* Context Menu */
.ctx-menu{position:fixed;background:#fff;border:1px solid #e0e0e0;border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,0.12);z-index:10000;min-width:180px;padding:4px 0;animation:ctxIn .12s ease}
@keyframes ctxIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.ctx-item{padding:8px 16px;font-size:13px;cursor:pointer;display:flex;align-items:center;gap:10px;color:#34495e;transition:background .15s}
.ctx-item:hover{background:#f0f4f8}
.ctx-item i{width:16px;text-align:center;color:#7f8c8d;font-size:13px}
.ctx-item.danger{color:#e74c3c}
.ctx-item.danger i{color:#e74c3c}
.ctx-sep{height:1px;background:#ecf0f1;margin:3px 0}

/* Modal */
.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;z-index:9999;padding:16px}
.modal{background:#fff;border-radius:12px;width:100%;max-width:480px;box-shadow:0 12px 40px rgba(0,0,0,0.18);overflow:hidden;animation:mIn .2s ease}
.modal.wide{max-width:620px}
@keyframes mIn{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
.modal-hdr{padding:16px 20px;background:#f8f9fa;border-bottom:1px solid #ecf0f1;display:flex;align-items:center;justify-content:space-between}
.modal-hdr h3{font-size:17px;font-weight:600;color:#2c3e50;margin:0}
.modal-close{border:none;background:none;color:#95a5a6;font-size:18px;cursor:pointer;line-height:1;padding:2px}
.modal-close:hover{color:#555}
.modal-body{padding:20px}
.modal-ftr{padding:14px 20px;background:#f8f9fa;border-top:1px solid #ecf0f1;display:flex;justify-content:flex-end;gap:10px}

/* Editor */
.editor-wrap{display:flex;flex-direction:column;height:calc(100vh - 160px);min-height:400px;background:#fff;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.05);overflow:hidden}
.editor-hdr{padding:10px 16px;background:#f8f9fa;border-bottom:1px solid #ecf0f1;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.editor-path{font-size:13px;color:#555;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:60%}
.editor-hdr-right{display:flex;gap:8px;flex-shrink:0}
.editor-body{flex:1;overflow:auto}
.editor-ta{width:100%;height:100%;border:none;padding:16px;font-family:'Monaco','Menlo','Ubuntu Mono','Consolas',monospace;font-size:13px;color:#34495e;line-height:1.6;resize:none;outline:none}

/* Terminal */
.terminal-box{background:#1e272e;color:#dfe6e9;font-family:'Monaco','Menlo','Ubuntu Mono','Consolas',monospace;padding:16px;border-radius:10px;min-height:300px;max-height:480px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;font-size:13px;line-height:1.5}
.term-input{display:flex;gap:8px;margin-top:10px}
.term-input input{flex:1;background:#1e272e;border:1px solid #636e72;color:#dfe6e9;font-family:'Monaco','Menlo','Ubuntu Mono','Consolas',monospace;padding:10px;border-radius:6px;outline:none;font-size:13px}

/* Database */
.db-tabs{display:flex;border-bottom:2px solid #ecf0f1;margin-bottom:20px}
.db-tab{padding:10px 20px;background:none;border:none;border-bottom:3px solid transparent;font-size:14px;font-weight:600;color:#7f8c8d;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px;margin-bottom:-2px}
.db-tab:hover{color:#4a89dc}
.db-tab.active{color:#4a89dc;border-bottom-color:#4a89dc}
.db-list{display:flex;flex-direction:column;gap:10px}
.db-item{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.06);border-left:4px solid #3498db;overflow:hidden}
.db-item.user-item{border-left-color:#9b59b6}
.db-hdr{padding:12px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #f5f5f5}
.db-title{font-weight:600;color:#2c3e50;display:flex;align-items:center;gap:8px;font-size:15px}
.db-actions{display:flex;gap:6px;flex-wrap:wrap}
.db-body{padding:10px 16px 12px;font-size:13px}
.db-tag{display:inline-flex;align-items:center;gap:5px;background:#f0f4f8;border-radius:20px;padding:3px 10px;margin:3px;font-size:12px;color:#34495e}

/* Domain */
.dom-tabs{display:flex;border-bottom:2px solid #ecf0f1;margin-bottom:20px}
.dom-tab{padding:10px 20px;background:none;border:none;border-bottom:3px solid transparent;font-size:14px;font-weight:600;color:#7f8c8d;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px;margin-bottom:-2px}
.dom-tab:hover{color:#4a89dc}
.dom-tab.active{color:#4a89dc;border-bottom-color:#4a89dc}

/* Helpers */
.flex-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:16px}
.mt{margin-top:16px}
.mb{margin-bottom:16px}
.mt-sm{margin-top:8px}
.text-muted{color:#95a5a6;font-size:13px}
.text-center{text-align:center}
CSSEOF

# ============================================================
# public/js/app.js
# ============================================================
cat > public/js/app.js <<'JSEOF'
'use strict';
/* ── API ─────────────────────────────────────────────────────────────────── */
const api = {
  _r(url, opt = {}) {
    const h = {};
    if (!(opt.body instanceof FormData)) h['Content-Type'] = 'application/json';
    return fetch(url, {
      headers: h, method: opt.method || 'GET',
      body: opt.body instanceof FormData ? opt.body : opt.body ? JSON.stringify(opt.body) : undefined
    }).then(r => r.json());
  },
  get:  (u)    => api._r(u),
  post: (u, b) => api._r(u, { method: 'POST',   body: b }),
  put:  (u, b) => api._r(u, { method: 'PUT',    body: b }),
  del:  (u)    => api._r(u, { method: 'DELETE' })
};

/* ── Utils ───────────────────────────────────────────────────────────────── */
const $  = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qsa = sel => document.querySelectorAll(sel);

function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function fmtB(b) {
  if (!b) return '0 B';
  const k = 1024, u = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log(b) / Math.log(k));
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + u[i];
}
function fmtUp(s) {
  return Math.floor(s/86400)+'d '+Math.floor(s%86400/3600)+'h '+Math.floor(s%3600/60)+'m';
}
function pClass(p) { return p > 80 ? 'danger' : p > 60 ? 'warn' : ''; }
function fmtDate(d) { return new Date(d).toLocaleString(); }

/* File icon helper */
const ARCHIVE_EXT = new Set(['zip','tar','gz','rar','7z','bz2','tgz','xz']);
const TEXT_EXT    = new Set(['php','js','ts','css','html','htm','xml','json','yaml','yml',
                              'py','rb','java','c','cpp','h','sh','bash','ini','conf',
                              'env','txt','md','log','sql','htaccess']);
function isArchiveExt(ext) { return ARCHIVE_EXT.has((ext||'').toLowerCase()); }
function isTextExt(ext)    { return TEXT_EXT.has((ext||'').toLowerCase()); }

function fileIcon(file) {
  if (file.isDir) return '<i class="fas fa-folder file-icon fi-folder"></i>';
  const e = (file.extension||'').toLowerCase();
  if (['jpg','jpeg','png','gif','svg','webp','ico'].includes(e)) return '<i class="far fa-file-image file-icon fi-image"></i>';
  if (ARCHIVE_EXT.has(e))  return '<i class="far fa-file-archive file-icon fi-archive"></i>';
  if (['mp4','avi','mov','mkv','webm'].includes(e)) return '<i class="far fa-file-video file-icon"></i>';
  if (['mp3','wav','ogg','flac'].includes(e))       return '<i class="far fa-file-audio file-icon"></i>';
  if (['pdf'].includes(e))                          return '<i class="far fa-file-pdf file-icon fi-pdf"></i>';
  if (['doc','docx','odt'].includes(e))             return '<i class="far fa-file-word file-icon"></i>';
  if (['xls','xlsx','csv'].includes(e))             return '<i class="far fa-file-excel file-icon"></i>';
  if (TEXT_EXT.has(e))                              return '<i class="far fa-file-code file-icon fi-code"></i>';
  return '<i class="far fa-file file-icon"></i>';
}

/* ── App State ───────────────────────────────────────────────────────────── */
let curPath         = '/usr/local/lsws';
let curEditPath     = '';
let selectedFiles   = [];
let clipboard       = { items: [], action: '' };

/* ── Auth ────────────────────────────────────────────────────────────────── */
function checkAuth() {
  api.get('/api/auth').then(r => {
    if (r.authenticated) { showPanel(); loadPage('dashboard'); } else showLogin();
  });
}
const showLogin = () => { $('loginPage').style.display='flex'; $('mainPanel').style.display='none'; };
const showPanel = () => { $('loginPage').style.display='none'; $('mainPanel').style.display='flex'; };

$('loginForm').addEventListener('submit', e => {
  e.preventDefault();
  api.post('/api/login', { username: $('username').value, password: $('password').value })
    .then(r => { if (r.success) { showPanel(); loadPage('dashboard'); } else $('loginError').textContent='Invalid credentials'; });
});
$('logoutBtn').addEventListener('click', e => { e.preventDefault(); api.get('/api/logout').then(showLogin); });
$('mobileToggle').addEventListener('click', () => $('sidebar').classList.toggle('open'));
qsa('.sidebar nav a').forEach(a => a.addEventListener('click', e => {
  e.preventDefault();
  qsa('.sidebar nav a').forEach(x => x.classList.remove('active'));
  a.classList.add('active');
  loadPage(a.dataset.page);
  $('sidebar').classList.remove('open');
}));

/* ── Router ──────────────────────────────────────────────────────────────── */
function loadPage(p) {
  const el = $('content');
  ({ dashboard: pgDash, services: pgSvc, files: pgFiles,
     domains: pgDom, databases: pgDb, tunnel: pgTun,
     terminal: pgTerm, settings: pgSet }[p] || pgDash)(el);
}

/* ── Dashboard ───────────────────────────────────────────────────────────── */
function pgDash(el) {
  Promise.all([api.get('/api/dashboard'), api.get('/api/services')]).then(([d, s]) => {
    const mp = Math.round(d.memory.used / d.memory.total * 100);
    const dp = d.disk.total ? Math.round(d.disk.used / d.disk.total * 100) : 0;
    el.innerHTML = `
      <h2 class="page-title"><i class="fas fa-tachometer-alt"></i> Dashboard</h2>
      <p class="page-sub">${esc(d.hostname)} (${esc(d.ip)})</p>
      <div class="stats-grid">
        <div class="card"><div class="label">CPU</div><div class="value">${d.cpu.cores} Cores</div>
          <div class="sub">Load: ${d.cpu.load.map(l=>l.toFixed(2)).join(', ')}</div></div>
        <div class="card"><div class="label">Memory</div><div class="value">${mp}%</div>
          <div class="progress"><div class="progress-bar ${pClass(mp)}" style="width:${mp}%"></div></div>
          <div class="sub">${fmtB(d.memory.used)} / ${fmtB(d.memory.total)}</div></div>
        <div class="card"><div class="label">Disk</div><div class="value">${dp}%</div>
          <div class="progress"><div class="progress-bar ${pClass(dp)}" style="width:${dp}%"></div></div>
          <div class="sub">${fmtB(d.disk.used)} / ${fmtB(d.disk.total)}</div></div>
        <div class="card"><div class="label">Uptime</div><div class="value">${fmtUp(d.uptime)}</div>
          <div class="sub">Node ${esc(d.nodeVersion)}</div></div>
      </div>
      <h3 class="mb">Services</h3>
      <table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>
        ${s.map(x=>`<tr><td><strong>${x.name}</strong></td>
          <td><span class="badge ${x.active?'badge-on':'badge-off'}">${x.active?'Running':'Stopped'}</span></td></tr>`).join('')}
      </tbody></table>
      <div class="mt">
        <a href="http://${d.ip}:7080" target="_blank" class="btn btn-p"><i class="fas fa-cog"></i> OLS Admin</a>&nbsp;
        <a href="http://${d.ip}:8088/phpmyadmin/" target="_blank" class="btn btn-w"><i class="fas fa-database"></i> phpMyAdmin</a>
      </div>`;
  });
}

/* ── Services ────────────────────────────────────────────────────────────── */
function pgSvc(el) {
  api.get('/api/services').then(s => {
    el.innerHTML = `<h2 class="page-title"><i class="fas fa-cogs"></i> Services</h2>
      <p class="page-sub">Manage server services</p><div id="svcMsg"></div>
      <table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>
      ${s.map(x=>`<tr><td><strong>${x.name}</strong></td>
        <td><span class="badge ${x.active?'badge-on':'badge-off'}">${x.active?'Running':'Stopped'}</span></td>
        <td>
          <button class="btn btn-s btn-sm" onclick="svcAct('${x.name}','start')"><i class="fas fa-play"></i> Start</button>
          <button class="btn btn-d btn-sm" onclick="svcAct('${x.name}','stop')"><i class="fas fa-stop"></i> Stop</button>
          <button class="btn btn-w btn-sm" onclick="svcAct('${x.name}','restart')"><i class="fas fa-sync-alt"></i> Restart</button>
        </td></tr>`).join('')}
      </tbody></table>`;
  });
}
window.svcAct = (n, a) => api.post(`/api/services/${n}/${a}`).then(r => {
  $('svcMsg').innerHTML = r.success ? aOk(`${n} ${a}ed`) : aErr(r.error||'Failed');
  setTimeout(() => loadPage('services'), 1200);
});

/* ═══════════════════════════════════════════════════════════════════════════
   FILE MANAGER
   ═══════════════════════════════════════════════════════════════════════════ */
function pgFiles(el) { el.innerHTML = `<h2 class="page-title"><i class="fas fa-folder"></i> File Manager</h2><div id="fmRoot"></div>`; loadFM(curPath); }

function loadFM(p) {
  curPath = p;
  selectedFiles = [];
  api.get('/api/files?path=' + encodeURIComponent(p)).then(d => {
    const root = $('fmRoot'); if (!root) return;

    /* ── special views ── */
    if (d.error)   { root.innerHTML = aErr(esc(d.error)); return; }
    if (d.binary || d.tooLarge) {
      const msg = d.binary ? 'Binary file – cannot edit in browser.' : 'File too large to edit (max 5 MB).';
      const back = p.substring(0, p.lastIndexOf('/')) || '/';
      root.innerHTML = `<div class="card"><h3 class="mb">${d.binary?'Binary':'Large'} File</h3>
        <p class="mb">${esc(d.path)} (${fmtB(d.size)})</p><p class="mb">${msg}</p>
        <a href="/api/files/download?path=${encodeURIComponent(d.path)}" class="btn btn-p"><i class="fas fa-download"></i> Download</a>
        <button class="btn btn-l" onclick="loadFM('${esc(back)}')"><i class="fas fa-arrow-left"></i> Back</button></div>`;
      return;
    }
    if (d.content !== undefined) { showEditor(d); return; }

    /* ── directory view ── */
    const items = (d.items || []).sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    const parent = p === '/' ? '' : p.split('/').slice(0,-1).join('/') || '/';

    /* breadcrumb */
    const parts = p.split('/').filter(Boolean);
    let bc = `<a onclick="loadFM('/')" style="cursor:pointer"><i class="fas fa-home"></i></a>`;
    let bp = '';
    parts.forEach(x => { bp += '/'+x; const bpc=bp; bc += ` <span>/</span> <a onclick="loadFM('${esc(bpc)}')" style="cursor:pointer">${esc(x)}</a>`; });

    /* toolbar paste button */
    const pasteBtn = clipboard.items.length
      ? `<button class="btn btn-info btn-sm" onclick="fmPaste()"><i class="fas fa-paste"></i> Paste (${clipboard.items.length})</button>`
      : '';

    root.innerHTML = `
      <div class="file-manager">
        <div class="file-toolbar">
          <div class="file-toolbar-group">
            <button class="btn btn-p btn-sm" onclick="showUpload()"><i class="fas fa-upload"></i> Upload</button>
            <button class="btn btn-s btn-sm" onclick="showMkdir()"><i class="fas fa-folder-plus"></i> New Folder</button>
            <button class="btn btn-l btn-sm" onclick="showNewFile()"><i class="fas fa-file"></i> New File</button>
          </div>
          <div class="file-toolbar-group" id="fmPasteArea">${pasteBtn}</div>
          <div class="file-toolbar-group" style="margin-left:auto">
            <button class="btn btn-l btn-sm" onclick="loadFM(curPath)"><i class="fas fa-sync-alt"></i> Refresh</button>
          </div>
        </div>
        <div class="breadcrumb">${bc}</div>
        <div class="file-container" id="fmList">
          ${parent ? `<div class="file-item" onclick="loadFM('${esc(parent)}')">
            <div class="cb-wrap"></div><i class="fas fa-level-up-alt file-icon"></i>
            <span class="fname">..</span><span class="fsize"></span><span class="fperms"></span><span class="fdate"></span></div>` : ''}
          ${items.map(item => {
            const ip  = (p === '/' ? '' : p) + '/' + item.name;
            const ext = (item.extension||'').toLowerCase();
            return `<div class="file-item" data-path="${esc(ip)}" data-name="${esc(item.name)}"
                data-isdir="${item.isDir}" data-ext="${esc(ext)}"
                onclick="fmClick(event,this)" ondblclick="fmDblClick(this)"
                oncontextmenu="fmCtx(event,this)">
              <div class="cb-wrap"><input type="checkbox" onclick="event.stopPropagation()" onchange="fmCb(this,'${esc(ip)}')"></div>
              ${fileIcon(item)}
              <span class="fname">${esc(item.name)}</span>
              <span class="fsize">${item.isDir ? '' : fmtB(item.size)}</span>
              <span class="fperms">${item.perms||''}</span>
              <span class="fdate">${item.modified ? fmtDate(item.modified) : ''}</span>
            </div>`;
          }).join('')}
        </div>
        <div class="file-status-bar">
          <div>${items.length} items</div>
          <div class="sel-actions" id="fmSelBar">
            <button class="btn btn-l btn-sm" onclick="fmSelAll()"><i class="fas fa-check-square"></i> Select All</button>
          </div>
        </div>
      </div>
      <div id="fmCtxMenu" class="ctx-menu" style="display:none"></div>
      <div id="fmModal"></div>`;

    document.addEventListener('keydown', fmKey);
    updateSelBar();
  });
}

/* ── Selection ───────────────────────────────────────────────────────────── */
function fmClick(e, el) {
  const p = el.dataset.path;
  if (e.ctrlKey || e.metaKey) {
    el.classList.toggle('selected');
    const cb = el.querySelector('input'); if (cb) cb.checked = el.classList.contains('selected');
    el.classList.contains('selected') ? selectedFiles.push(p) : (selectedFiles = selectedFiles.filter(x => x !== p));
  } else if (e.shiftKey) {
    const all  = [...qsa('#fmList .file-item[data-name]')];
    const last = all.findIndex(i => i.classList.contains('selected'));
    const cur  = all.indexOf(el);
    const lo = Math.min(last < 0 ? cur : last, cur), hi = Math.max(last < 0 ? cur : last, cur);
    all.slice(lo, hi+1).forEach(i => {
      i.classList.add('selected');
      const cb = i.querySelector('input'); if (cb) cb.checked = true;
      if (!selectedFiles.includes(i.dataset.path)) selectedFiles.push(i.dataset.path);
    });
  } else {
    qsa('#fmList .file-item').forEach(i => { i.classList.remove('selected'); const cb = i.querySelector('input'); if(cb) cb.checked=false; });
    el.classList.add('selected');
    const cb = el.querySelector('input'); if(cb) cb.checked=true;
    selectedFiles = [p];
  }
  updateSelBar();
}

function fmCb(cb, p) {
  const fi = cb.closest('.file-item');
  if (cb.checked) { fi.classList.add('selected'); if (!selectedFiles.includes(p)) selectedFiles.push(p); }
  else            { fi.classList.remove('selected'); selectedFiles = selectedFiles.filter(x => x !== p); }
  updateSelBar();
}

function fmSelAll() {
  const all = qsa('#fmList .file-item[data-name]');
  const allSel = selectedFiles.length === all.length;
  selectedFiles = [];
  all.forEach(i => {
    const cb = i.querySelector('input');
    if (allSel) { i.classList.remove('selected'); if(cb) cb.checked=false; }
    else        { i.classList.add('selected');    if(cb) cb.checked=true; selectedFiles.push(i.dataset.path); }
  });
  updateSelBar();
}

function updateSelBar() {
  const bar    = $('fmSelBar');
  const paEl   = $('fmPasteArea');
  if (!bar) return;

  let html = `<button class="btn btn-l btn-sm" onclick="fmSelAll()"><i class="fas fa-check-square"></i> Select All</button>`;

  if (selectedFiles.length > 0) {
    html += `<span class="text-muted">${selectedFiles.length} selected</span>`;
    html += `<button class="btn btn-l btn-sm" onclick="fmBulk('copy')"><i class="fas fa-copy"></i> Copy</button>`;
    html += `<button class="btn btn-l btn-sm" onclick="fmBulk('cut')"><i class="fas fa-cut"></i> Cut</button>`;
    if (selectedFiles.length === 1) {
      html += `<button class="btn btn-l btn-sm" onclick="fmBulk('rename')"><i class="fas fa-i-cursor"></i> Rename</button>`;
      /* ── EXTRACT button: show when exactly 1 archive is selected ── */
      const selEl = qs('#fmList .file-item.selected');
      if (selEl && isArchiveExt(selEl.dataset.ext)) {
        html += `<button class="btn btn-purple btn-sm" onclick="showExtract('${esc(selEl.dataset.path)}')"><i class="fas fa-box-open"></i> Extract</button>`;
      }
      /* ── EDIT button: show for text files ── */
      if (selEl && !JSON.parse(selEl.dataset.isdir) && isTextExt(selEl.dataset.ext)) {
        html += `<button class="btn btn-info btn-sm" onclick="fmEdit('${esc(selEl.dataset.path)}')"><i class="fas fa-edit"></i> Edit</button>`;
      }
    }
    /* ── COMPRESS always shown when ≥1 selected ── */
    html += `<button class="btn btn-l btn-sm" onclick="fmBulk('compress')"><i class="fas fa-file-archive"></i> Compress</button>`;
    html += `<button class="btn btn-d btn-sm" onclick="fmBulk('delete')"><i class="fas fa-trash-alt"></i> Delete</button>`;
  }

  bar.innerHTML = html;

  /* paste area */
  if (paEl) {
    paEl.innerHTML = clipboard.items.length
      ? `<button class="btn btn-info btn-sm" onclick="fmPaste()"><i class="fas fa-paste"></i> Paste (${clipboard.items.length})</button>`
      : '';
  }
}

/* ── Double-click ────────────────────────────────────────────────────────── */
function fmDblClick(el) {
  const p = el.dataset.path, isDir = el.dataset.isdir === 'true';
  if (isDir) loadFM(p); else fmEdit(p);
}

/* ── Context menu ────────────────────────────────────────────────────────── */
function fmCtx(e, el) {
  e.preventDefault();
  if (!el.classList.contains('selected')) {
    qsa('#fmList .file-item').forEach(i => { i.classList.remove('selected'); const cb=i.querySelector('input');if(cb)cb.checked=false; });
    el.classList.add('selected'); const cb=el.querySelector('input');if(cb)cb.checked=true;
    selectedFiles = [el.dataset.path]; updateSelBar();
  }
  const p = el.dataset.path, ext = el.dataset.ext || '', isDir = el.dataset.isdir === 'true';
  let items = '';
  if (!isDir) items += ctxI('fas fa-download','Download', `window.open('/api/files/download?path='+encodeURIComponent('${esc(p)}'),'_blank')`);
  if (!isDir && isTextExt(ext)) items += ctxI('fas fa-edit','Edit', `fmEdit('${esc(p)}')`);
  items += ctxI('fas fa-i-cursor','Rename', `fmBulk('rename')`);
  items += ctxI('fas fa-copy','Copy',  `fmBulk('copy')`);
  items += ctxI('fas fa-cut','Cut',   `fmBulk('cut')`);
  if (clipboard.items.length) { items += `<div class="ctx-sep"></div>`; items += ctxI('fas fa-paste','Paste here', `fmPaste()`); }
  /* ── EXTRACT in context menu ── */
  if (!isDir && isArchiveExt(ext)) { items += `<div class="ctx-sep"></div>`; items += ctxI('fas fa-box-open','Extract', `showExtract('${esc(p)}')`); }
  items += ctxI('fas fa-file-archive','Compress', `fmBulk('compress')`);
  items += `<div class="ctx-sep"></div>`;
  items += ctxI('fas fa-key','Permissions', `showPerms('${esc(p)}')`);
  items += ctxI('fas fa-trash-alt','Delete', `fmBulk('delete')`, true);

  const menu = $('fmCtxMenu');
  menu.innerHTML = items; menu.style.display = 'block';
  menu.style.top = e.clientY + 'px'; menu.style.left = e.clientX + 'px';
  document.addEventListener('click', hideCtx, { once: true });
  setTimeout(() => {
    const r = menu.getBoundingClientRect();
    if (r.right  > window.innerWidth)  menu.style.left = (e.clientX - r.width)  + 'px';
    if (r.bottom > window.innerHeight) menu.style.top  = (e.clientY - r.height) + 'px';
  }, 0);
}
function ctxI(icon, label, onclick, danger=false) {
  return `<div class="ctx-item${danger?' danger':''}" onclick="hideCtx();${onclick}"><i class="${icon}"></i>${label}</div>`;
}
const hideCtx = () => { const m=$('fmCtxMenu'); if(m) m.style.display='none'; };

/* ── File open/edit ──────────────────────────────────────────────────────── */
function fmEdit(fp) {
  api.get('/api/files?path=' + encodeURIComponent(fp)).then(d => {
    if (d.binary || d.tooLarge) { alert('Cannot edit this file in browser.'); return; }
    if (d.error) { alert('Error: ' + d.error); return; }
    showEditor(d);
  });
}

function showEditor(d) {
  curEditPath = d.path;
  $('fmRoot').innerHTML = `
    <div class="editor-wrap">
      <div class="editor-hdr">
        <span class="editor-path" title="${esc(d.path)}">${esc(d.path)}</span>
        <div class="editor-hdr-right">
          <span style="font-size:12px;color:#95a5a6">${fmtB(d.size)}</span>
          <button class="btn btn-p btn-sm" onclick="saveFile()"><i class="fas fa-save"></i> Save</button>
          <button class="btn btn-l btn-sm" onclick="loadFM('${esc(d.path.substring(0,d.path.lastIndexOf('/'))||'/')}')"><i class="fas fa-times"></i> Close</button>
        </div>
      </div>
      <div class="editor-body"><textarea id="edTa" class="editor-ta">${esc(d.content)}</textarea></div>
    </div>
    <div id="edStatus" style="margin-top:12px"></div>`;
}

window.saveFile = () => {
  api.put('/api/files', { filePath: curEditPath, content: $('edTa').value }).then(r => {
    $('edStatus').innerHTML = r.success ? aOk('Saved') : aErr(r.error||'Save failed');
    setTimeout(() => { const s=$('edStatus'); if(s) s.innerHTML=''; }, 3000);
  });
};

/* ── Bulk actions ────────────────────────────────────────────────────────── */
function fmBulk(action) {
  if (!selectedFiles.length) return;
  if (action === 'delete') { if (confirm(`Delete ${selectedFiles.length} item(s)?`)) fmDelete(); return; }
  if (action === 'copy')   { clipboard = { items: [...selectedFiles], action: 'copy' }; fmNotify(`Copied ${selectedFiles.length} item(s)`); updateSelBar(); return; }
  if (action === 'cut')    { clipboard = { items: [...selectedFiles], action: 'cut'  }; fmNotify(`Cut ${selectedFiles.length} item(s)`); updateSelBar(); return; }
  if (action === 'rename') { if (selectedFiles.length===1) showRename(selectedFiles[0]); return; }
  if (action === 'compress') { showCompress(); return; }
}

/* ── Paste  ───────────────────────────────────────────────────────────────── */
function fmPaste() {
  if (!clipboard.items.length) return;
  const { items, action } = clipboard;

  if (action === 'cut') {
    // rename each item to target directory
    const moves = items.map(src => {
      const dest = (curPath === '/' ? '' : curPath) + '/' + src.split('/').pop();
      if (src === dest) return Promise.resolve({ ok: true });
      return api.post('/api/files/rename', { oldPath: src, newPath: dest })
        .then(r => ({ ok: r.success, err: r.error }))
        .catch(e => ({ ok: false, err: e.message }));
    });
    Promise.all(moves).then(results => {
      const failed = results.filter(r => !r.ok);
      clipboard = { items: [], action: '' };
      if (failed.length) fmNotify(`Move done. ${failed.length} error(s): ${failed[0].err}`);
      else fmNotify(`Moved ${items.length} item(s)`);
      loadFM(curPath);
    });
  } else if (action === 'copy') {
    api.post('/api/files/copy', { sources: items, target: curPath }).then(r => {
      if (r.success) { fmNotify(`Copied ${r.copied||items.length} item(s)`); loadFM(curPath); }
      else { fmNotify('Copy failed: ' + (r.error||'unknown')); }
    });
  }
}

function fmDelete() {
  let done = 0, fail = 0;
  const proms = selectedFiles.map(p =>
    api.del('/api/files?path=' + encodeURIComponent(p))
      .then(r => r.success ? done++ : fail++)
      .catch(() => fail++)
  );
  Promise.all(proms).then(() => { fmNotify(`${done} deleted${fail ? ', '+fail+' failed' : ''}`); loadFM(curPath); });
}

/* ── Keyboard shortcuts ──────────────────────────────────────────────────── */
function fmKey(e) {
  if (!$('fmList')) return;
  if (e.ctrlKey && e.key==='a') { e.preventDefault(); fmSelAll(); }
  if (e.key==='Delete' && selectedFiles.length) { e.preventDefault(); fmBulk('delete'); }
  if (e.ctrlKey && e.key==='c' && selectedFiles.length) { e.preventDefault(); fmBulk('copy'); }
  if (e.ctrlKey && e.key==='x' && selectedFiles.length) { e.preventDefault(); fmBulk('cut'); }
  if (e.ctrlKey && e.key==='v' && clipboard.items.length) { e.preventDefault(); fmPaste(); }
  if (e.key==='F2' && selectedFiles.length===1) { e.preventDefault(); fmBulk('rename'); }
}

/* ── Modals ──────────────────────────────────────────────────────────────── */
const mkModal = (title, body, footer, wide=false) =>
  `<div class="modal-backdrop" onclick="if(event.target===this)closeModal()">
    <div class="modal${wide?' wide':''}">
      <div class="modal-hdr"><h3>${title}</h3><button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button></div>
      <div class="modal-body">${body}</div>
      <div class="modal-ftr">${footer}</div>
    </div></div>`;

window.closeModal = () => { const m=$('fmModal'); if(m) m.innerHTML=''; };

function showUpload() {
  $('fmModal').innerHTML = mkModal('Upload Files',
    `<p class="mb">To: <code>${esc(curPath)}</code></p>
     <div class="form-group"><input type="file" id="fUpInput" multiple class="form-control"></div>
     <div id="fUpStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-p" onclick="doUpload()"><i class="fas fa-upload"></i> Upload</button>`);
}
window.doUpload = () => {
  const files = $('fUpInput').files;
  if (!files.length) { $('fUpStatus').innerHTML = aErr('No files selected'); return; }
  const fd = new FormData();
  for (const f of files) fd.append('files', f);
  fd.append('path', curPath);
  $('fUpStatus').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Uploading...');
  api._r('/api/files/upload', { method:'POST', body: fd }).then(r => {
    if (r.success) { $('fUpStatus').innerHTML = aOk('Uploaded!'); setTimeout(() => { closeModal(); loadFM(curPath); }, 800); }
    else $('fUpStatus').innerHTML = aErr(r.error||'Upload failed');
  });
};

function showMkdir() {
  $('fmModal').innerHTML = mkModal('New Folder',
    `<p class="mb">In: <code>${esc(curPath)}</code></p>
     <div class="form-group"><label>Folder Name</label><input type="text" id="fMkName" class="form-control" placeholder="new_folder"></div>
     <div id="fMkStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-p" onclick="doMkdir()"><i class="fas fa-folder-plus"></i> Create</button>`);
  setTimeout(() => $('fMkName') && $('fMkName').focus(), 100);
}
window.doMkdir = () => {
  const name = $('fMkName').value.trim();
  if (!name) { $('fMkStatus').innerHTML = aErr('Enter a name'); return; }
  const p = (curPath==='/'?'':curPath) + '/' + name;
  api.post('/api/files/mkdir', { path: p }).then(r => {
    if (r.success) { $('fMkStatus').innerHTML = aOk('Created!'); setTimeout(() => { closeModal(); loadFM(curPath); }, 700); }
    else $('fMkStatus').innerHTML = aErr(r.error||'Failed');
  });
};

function showNewFile() {
  $('fmModal').innerHTML = mkModal('New File',
    `<p class="mb">In: <code>${esc(curPath)}</code></p>
     <div class="form-group"><label>File Name</label><input type="text" id="fNfName" class="form-control" placeholder="example.txt"></div>
     <div id="fNfStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-p" onclick="doNewFile()"><i class="fas fa-file"></i> Create</button>`);
  setTimeout(() => $('fNfName') && $('fNfName').focus(), 100);
}
window.doNewFile = () => {
  const name = $('fNfName').value.trim();
  if (!name) { $('fNfStatus').innerHTML = aErr('Enter a name'); return; }
  const p = (curPath==='/'?'':curPath) + '/' + name;
  api.post('/api/files/newfile', { path: p, content: '' }).then(r => {
    if (r.success) { $('fNfStatus').innerHTML = aOk('Created!'); setTimeout(() => { closeModal(); fmEdit(p); }, 700); }
    else $('fNfStatus').innerHTML = aErr(r.error||'Failed');
  });
};

function showRename(fp) {
  const old = fp.split('/').pop();
  $('fmModal').innerHTML = mkModal('Rename',
    `<div class="form-group"><label>New Name</label>
     <input type="text" id="fRnName" class="form-control" value="${esc(old)}"></div>
     <div id="fRnStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-p" onclick="doRename('${esc(fp)}')"><i class="fas fa-save"></i> Rename</button>`);
  setTimeout(() => {
    const inp = $('fRnName'); if (!inp) return; inp.focus();
    const dot = old.lastIndexOf('.');
    inp.setSelectionRange(0, dot > 0 ? dot : old.length);
  }, 100);
}
window.doRename = fp => {
  const newName = $('fRnName').value.trim();
  if (!newName) { $('fRnStatus').innerHTML = aErr('Enter a name'); return; }
  const parent  = fp.substring(0, fp.lastIndexOf('/')) || '/';
  const newPath = (parent==='/'?'':parent) + '/' + newName;
  api.post('/api/files/rename', { oldPath: fp, newPath }).then(r => {
    if (r.success) { $('fRnStatus').innerHTML = aOk('Renamed!'); setTimeout(() => { closeModal(); loadFM(curPath); }, 700); }
    else $('fRnStatus').innerHTML = aErr(r.error||'Failed');
  });
};

/* ── Compress (same UX as Extract) ──────────────────────────────────────── */
function showCompress() {
  const def = selectedFiles.length === 1
    ? selectedFiles[0].split('/').pop() + '.zip'
    : (curPath.split('/').pop()||'files') + '.zip';
  $('fmModal').innerHTML = mkModal('Compress to Archive',
    `<p class="mb">Compress <strong>${selectedFiles.length}</strong> item(s)</p>
     <div class="form-group"><label>Archive Name (.zip)</label>
     <input type="text" id="fCpName" class="form-control" value="${esc(def)}"></div>
     <div id="fCpStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-p" onclick="doCompress()"><i class="fas fa-file-archive"></i> Compress</button>`);
  setTimeout(() => $('fCpName') && $('fCpName').focus(), 100);
}
window.doCompress = () => {
  let name = $('fCpName').value.trim();
  if (!name) { $('fCpStatus').innerHTML = aErr('Enter a name'); return; }
  if (!name.toLowerCase().endsWith('.zip')) name += '.zip';
  const out = (curPath==='/'?'':curPath) + '/' + name;
  $('fCpStatus').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Compressing...');
  api.post('/api/files/compress', { paths: selectedFiles, output: out }).then(r => {
    if (r.success) { $('fCpStatus').innerHTML = aOk('Archive created!'); setTimeout(() => { closeModal(); loadFM(curPath); }, 900); }
    else $('fCpStatus').innerHTML = aErr(r.error||'Failed');
  });
};

/* ── Extract (same UX as Compress) ──────────────────────────────────────── */
function showExtract(archivePath) {
  const archiveName = archivePath.split('/').pop();
  const parent      = archivePath.substring(0, archivePath.lastIndexOf('/')) || '/';
  const defTarget   = (parent==='/'?'':parent) + '/' + archiveName.replace(/\.(zip|tar\.gz|tgz|tar|gz|bz2|rar|xz)$/i,'');

  $('fmModal').innerHTML = mkModal('Extract Archive',
    `<p class="mb">Archive: <strong>${esc(archiveName)}</strong></p>
     <div class="form-group"><label>Extract to (full path)</label>
     <input type="text" id="fExPath" class="form-control" value="${esc(defTarget)}"></div>
     <div id="fExStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
     <button class="btn btn-purple" onclick="doExtract('${esc(archivePath)}')"><i class="fas fa-box-open"></i> Extract</button>`);
  setTimeout(() => $('fExPath') && $('fExPath').focus(), 100);
}

window.doExtract = archivePath => {
  const target = $('fExPath').value.trim();
  if (!target) { $('fExStatus').innerHTML = aErr('Enter destination path'); return; }
  $('fExStatus').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Extracting...');
  api.post('/api/files/extract', { archive: archivePath, target }).then(r => {
    if (r.success) { $('fExStatus').innerHTML = aOk('Extracted successfully!'); setTimeout(() => { closeModal(); loadFM(target); }, 900); }
    else $('fExStatus').innerHTML = aErr(r.error||'Extraction failed');
  });
};

function showPerms(fp) {
  api.get('/api/files/permissions?path=' + encodeURIComponent(fp)).then(d => {
    if (d.error) { alert('Error: '+d.error); return; }
    $('fmModal').innerHTML = mkModal('Permissions',
      `<p class="mb"><strong>${esc(fp.split('/').pop())}</strong></p>
       <div class="form-group"><label>Owner</label><input class="form-control" value="${esc(d.owner)}" disabled></div>
       <div class="form-group"><label>Group</label><input class="form-control" value="${esc(d.group)}" disabled></div>
       <div class="form-group"><label>Permissions (octal, e.g. 0755)</label>
       <input type="text" id="fPmVal" class="form-control" value="${esc(d.permissions)}"></div>
       ${d.isDir ? `<div class="form-group"><label><input type="checkbox" id="fPmRec"> Apply recursively</label></div>` : ''}
       <div id="fPmStatus" class="mt-sm"></div>`,
      `<button class="btn btn-l" onclick="closeModal()">Cancel</button>
       <button class="btn btn-p" onclick="doPerms('${esc(fp)}')"><i class="fas fa-save"></i> Save</button>`);
  });
}
window.doPerms = fp => {
  const perm = $('fPmVal').value.trim();
  const rec  = $('fPmRec') ? $('fPmRec').checked : false;
  if (!perm || !/^(0)?[0-7]{3,4}$/.test(perm)) { $('fPmStatus').innerHTML = aErr('Invalid format (e.g. 0755)'); return; }
  $('fPmStatus').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Changing...');
  api.post('/api/files/permissions', { path: fp, permissions: perm, recursive: rec }).then(r => {
    if (r.success) { $('fPmStatus').innerHTML = aOk('Done!'); setTimeout(() => { closeModal(); loadFM(curPath); }, 700); }
    else $('fPmStatus').innerHTML = aErr(r.error||'Failed');
  });
};

function fmNotify(msg) {
  const el = document.createElement('div');
  el.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:rgba(44,62,80,0.9);color:#fff;padding:10px 22px;border-radius:8px;z-index:99999;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,.2)';
  el.textContent = msg; document.body.appendChild(el);
  setTimeout(() => { el.style.transition='opacity .5s'; el.style.opacity='0'; setTimeout(() => el.remove(), 500); }, 2500);
}

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAINS  (with Subdomain tab)
   ═══════════════════════════════════════════════════════════════════════════ */
function pgDom(el) {
  api.get('/api/domains').then(domains => {
    const mainDomains = domains.filter(d => d.name.split('.').length === 2 ||
      (d.name.split('.').length === 3 && d.name.split('.')[0] !== 'www'));

    // separate subdomains (more than 2 parts and not in main list)
    const subDomains = domains.filter(d => !mainDomains.find(m => m.name === d.name));

    el.innerHTML = `
      <h2 class="page-title"><i class="fas fa-globe"></i> Domains</h2>
      <p class="page-sub">Virtual host management</p>
      <div id="domMsg"></div>
      <div class="dom-tabs mb">
        <button class="dom-tab active" onclick="domTab('main')"><i class="fas fa-globe"></i> Domains</button>
        <button class="dom-tab" onclick="domTab('sub')"><i class="fas fa-sitemap"></i> Subdomains</button>
      </div>

      <!-- MAIN DOMAINS TAB -->
      <div id="tab-main">
        <div class="card mb">
          <h3 class="mb">Add Domain</h3>
          <div class="flex-row">
            <div style="flex:1"><label class="text-muted">Domain Name</label>
              <input type="text" id="newDom" class="form-control" placeholder="example.com"></div>
            <button class="btn btn-p" style="align-self:flex-end" onclick="addDomain()"><i class="fas fa-plus"></i> Add Domain</button>
          </div>
        </div>
        <table class="tbl">
          <thead><tr><th>Domain</th><th>Doc Root</th><th>Type</th><th>Actions</th></tr></thead>
          <tbody>
            ${domains.length === 0
              ? `<tr><td colspan="4" class="text-center text-muted" style="padding:20px">No domains yet</td></tr>`
              : domains.map(d => `
                <tr>
                  <td><strong>${esc(d.name)}</strong></td>
                  <td><code style="font-size:12px">${esc(d.docRoot)}</code></td>
                  <td>${d.isSubdomain
                    ? '<span class="badge badge-sub">Subdomain</span>'
                    : '<span class="badge badge-on">Main</span>'}</td>
                  <td>
                    <button class="btn btn-p btn-sm" onclick="domFiles('${esc(d.docRoot)}')"><i class="fas fa-folder-open"></i> Files</button>
                    <button class="btn btn-d btn-sm" onclick="delDomain('${esc(d.name)}')"><i class="fas fa-trash-alt"></i> Delete</button>
                  </td>
                </tr>`).join('')}
          </tbody>
        </table>
      </div>

      <!-- SUBDOMAINS TAB -->
      <div id="tab-sub" style="display:none">
        <div class="card mb">
          <h3 class="mb">Add Subdomain</h3>
          <div class="flex-row">
            <div style="flex:1">
              <label class="text-muted">Subdomain (full, e.g. blog.example.com)</label>
              <input type="text" id="newSub" class="form-control" placeholder="blog.example.com">
            </div>
            <div style="flex:1">
              <label class="text-muted">Parent Domain</label>
              <select id="subParent" class="form-control">
                <option value="">-- Select parent domain --</option>
                ${domains.filter(d => !d.isSubdomain).map(d =>
                  `<option value="${esc(d.name)}">${esc(d.name)}</option>`
                ).join('')}
              </select>
            </div>
            <div style="flex:1">
              <label class="text-muted">Custom Doc Root (optional)</label>
              <input type="text" id="subDocRoot" class="form-control" placeholder="Leave blank for default">
            </div>
            <button class="btn btn-p" style="align-self:flex-end" onclick="addSubdomain()"><i class="fas fa-plus"></i> Add Subdomain</button>
          </div>
          <p class="text-muted mt-sm"><i class="fas fa-info-circle"></i> DNS: Point your subdomain A record to this server's IP address.</p>
        </div>

        ${subDomains.length > 0 ? `
          <table class="tbl">
            <thead><tr><th>Subdomain</th><th>Doc Root</th><th>Actions</th></tr></thead>
            <tbody>
              ${subDomains.map(d => `
                <tr>
                  <td><strong>${esc(d.name)}</strong></td>
                  <td><code style="font-size:12px">${esc(d.docRoot)}</code></td>
                  <td>
                    <button class="btn btn-p btn-sm" onclick="domFiles('${esc(d.docRoot)}')"><i class="fas fa-folder-open"></i> Files</button>
                    <button class="btn btn-d btn-sm" onclick="delDomain('${esc(d.name)}')"><i class="fas fa-trash-alt"></i> Delete</button>
                  </td>
                </tr>`).join('')}
            </tbody>
          </table>` : `<div class="card"><p class="text-center text-muted" style="padding:20px">No subdomains yet</p></div>`}
      </div>`;
  });
}

window.domTab = tab => {
  qsa('.dom-tab').forEach(b => b.classList.remove('active'));
  qs(`.dom-tab:nth-child(${tab==='main'?1:2})`).classList.add('active');
  $('tab-main').style.display = tab==='main' ? 'block' : 'none';
  $('tab-sub').style.display  = tab==='sub'  ? 'block' : 'none';
};

window.addDomain = () => {
  const domain = $('newDom').value.trim();
  if (!domain) return;
  api.post('/api/domains', { domain }).then(r => {
    $('domMsg').innerHTML = r.success ? aOk(`Domain <strong>${esc(domain)}</strong> added!`) : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('domains'), 1200);
  });
};

window.addSubdomain = () => {
  const subdomain = $('newSub').value.trim().toLowerCase();
  const parent    = $('subParent').value;
  const docRoot   = $('subDocRoot').value.trim();

  if (!subdomain) { $('domMsg').innerHTML = aErr('Enter subdomain'); return; }
  if (!parent)    { $('domMsg').innerHTML = aErr('Select parent domain'); return; }
  if (!subdomain.endsWith('.' + parent)) {
    $('domMsg').innerHTML = aErr(`Subdomain must end with .${parent} — e.g. blog.${parent}`);
    return;
  }

  api.post('/api/domains/subdomain', { subdomain, parent, docRoot: docRoot || '' }).then(r => {
    $('domMsg').innerHTML = r.success
      ? aOk(`Subdomain <strong>${esc(subdomain)}</strong> added! <span class="text-muted">→ ${esc(r.docRoot)}</span>`)
      : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('domains'), 1500);
  });
};

window.delDomain = name => {
  if (!confirm(`Delete domain/subdomain "${name}"?\nFiles in doc root will NOT be deleted.`)) return;
  api.del('/api/domains/' + name).then(r => {
    $('domMsg').innerHTML = r.success ? aOk('Deleted') : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('domains'), 1000);
  });
};

window.domFiles = docRoot => {
  loadPage('files');
  setTimeout(() => loadFM(docRoot), 200);
};

/* ═══════════════════════════════════════════════════════════════════════════
   DATABASES
   ═══════════════════════════════════════════════════════════════════════════ */
function pgDb(el) {
  Promise.all([api.get('/api/databases'), api.get('/api/database-users'), api.get('/api/dashboard')])
    .then(([databases, users, info]) => {
      el.innerHTML = `
        <h2 class="page-title"><i class="fas fa-database"></i> Databases</h2>
        <p class="page-sub">MariaDB database management</p>
        <div id="dbMsg"></div>
        <div class="db-tabs mb">
          <button class="db-tab active" onclick="dbTab('dbs')"><i class="fas fa-database"></i> Databases</button>
          <button class="db-tab" onclick="dbTab('users')"><i class="fas fa-users"></i> DB Users</button>
        </div>

        <!-- DATABASES TAB -->
        <div id="tab-dbs">
          <div class="card mb">
            <h3 class="mb">Create Database</h3>
            <div class="flex-row">
              <div style="flex:2">
                <label class="text-muted">Database Name</label>
                <input id="dbName" class="form-control" placeholder="my_database"
                  oninput="this.value=this.value.replace(/[^a-zA-Z0-9_]/g,'')">
              </div>
              <div style="flex:1">
                <label class="text-muted">Assign User</label>
                <select id="dbUserSel" class="form-control" onchange="toggleDbUserFields()">
                  <option value="">-- New user --</option>
                  ${users.map(u => `<option value="${esc(u.username)}">${esc(u.username)}</option>`).join('')}
                </select>
              </div>
              <div id="dbNewUserWrap" style="flex:2">
                <label class="text-muted">New Username / Password</label>
                <div style="display:flex;gap:8px">
                  <input id="dbUser" class="form-control" placeholder="username"
                    oninput="this.value=this.value.replace(/[^a-zA-Z0-9_]/g,'')">
                  <input id="dbPass" class="form-control" type="password" placeholder="password">
                </div>
              </div>
              <button class="btn btn-p" style="align-self:flex-end" onclick="createDb()">
                <i class="fas fa-plus"></i> Create
              </button>
            </div>
          </div>

          <div class="db-list">
            ${databases.length === 0
              ? `<div class="card"><p class="text-center text-muted" style="padding:20px">No databases yet</p></div>`
              : databases.map(db => `
                  <div class="db-item">
                    <div class="db-hdr">
                      <div class="db-title"><i class="fas fa-database" style="color:#3498db"></i>${esc(db.name)}</div>
                      <div class="db-actions">
                        <button class="btn btn-info btn-sm" onclick="dbBackup('${esc(db.name)}')"><i class="fas fa-download"></i> Backup</button>
                        <button class="btn btn-d btn-sm" onclick="dbDrop('${esc(db.name)}')"><i class="fas fa-trash-alt"></i> Drop</button>
                      </div>
                    </div>
                    <div class="db-body">
                      ${db.users.length
                        ? db.users.map(u => `<span class="db-tag"><i class="fas fa-user" style="font-size:11px"></i>${esc(u)}</span>`).join('')
                        : `<span class="text-muted"><i class="fas fa-info-circle"></i> No users assigned</span>`}
                    </div>
                  </div>`).join('')}
          </div>
        </div>

        <!-- USERS TAB -->
        <div id="tab-users" style="display:none">
          <div class="card mb">
            <h3 class="mb">Create DB User</h3>
            <div class="flex-row">
              <div>
                <label class="text-muted">Username</label>
                <input id="nuName" class="form-control" placeholder="username"
                  oninput="this.value=this.value.replace(/[^a-zA-Z0-9_]/g,'')">
              </div>
              <div>
                <label class="text-muted">Password</label>
                <input id="nuPass" class="form-control" type="password" placeholder="password">
              </div>
              <div>
                <label class="text-muted">Grant to Databases</label>
                <select id="nuDbs" class="form-control" multiple size="4">
                  ${databases.map(db => `<option value="${esc(db.name)}">${esc(db.name)}</option>`).join('')}
                </select>
                <small class="text-muted">Ctrl/Cmd to select multiple</small>
              </div>
              <button class="btn btn-p" style="align-self:flex-end" onclick="createDbUser()">
                <i class="fas fa-user-plus"></i> Create
              </button>
            </div>
          </div>

          <div class="db-list">
            ${users.length === 0
              ? `<div class="card"><p class="text-center text-muted" style="padding:20px">No DB users yet</p></div>`
              : users.map(u => {
                  const uDbs = databases.filter(db => db.users.includes(u.username)).map(db => db.name);
                  return `
                    <div class="db-item user-item">
                      <div class="db-hdr">
                        <div class="db-title"><i class="fas fa-user" style="color:#9b59b6"></i>${esc(u.username)}
                          <small class="text-muted">@localhost</small></div>
                        <div class="db-actions">
                          <button class="btn btn-w btn-sm" onclick="showChgPass('${esc(u.username)}')">
                            <i class="fas fa-key"></i> Change Password</button>
                          <button class="btn btn-d btn-sm" onclick="dbDropUser('${esc(u.username)}')">
                            <i class="fas fa-trash-alt"></i> Drop</button>
                        </div>
                      </div>
                      <div class="db-body">
                        ${uDbs.length
                          ? uDbs.map(n => `<span class="db-tag"><i class="fas fa-database" style="font-size:11px"></i>${esc(n)}</span>`).join('')
                          : `<span class="text-muted"><i class="fas fa-info-circle"></i> No database access</span>`}
                      </div>
                    </div>`;
                }).join('')}
          </div>
        </div>

        <div class="mt">
          <a href="http://${info.ip}:8088/phpmyadmin/" target="_blank" class="btn btn-w">
            <i class="fas fa-database"></i> Open phpMyAdmin</a>
        </div>`;
    });
}

window.dbTab = tab => {
  qsa('.db-tab').forEach(b => b.classList.remove('active'));
  qs(`.db-tab:nth-child(${tab==='dbs'?1:2})`).classList.add('active');
  $('tab-dbs').style.display   = tab==='dbs'   ? 'block' : 'none';
  $('tab-users').style.display = tab==='users'  ? 'block' : 'none';
};

window.toggleDbUserFields = () => {
  const sel = $('dbUserSel');
  const wrap = $('dbNewUserWrap');
  if (wrap) wrap.style.display = sel.value === '' ? 'block' : 'none';
};

/* Create database – FIXED */
window.createDb = () => {
  const name    = ($('dbName').value || '').trim();
  const selUser = $('dbUserSel').value;                          // existing user or ''
  const newUser = selUser === '' ? ($('dbUser').value || '').trim() : selUser;
  const newPass = selUser === '' ? ($('dbPass') ? $('dbPass').value : '') : '';

  if (!name) { $('dbMsg').innerHTML = aErr('Database name is required'); return; }
  if (!/^[a-zA-Z0-9_]{1,64}$/.test(name)) { $('dbMsg').innerHTML = aErr('Only letters, numbers, underscore allowed'); return; }

  // Only validate user/pass when creating a new user
  if (selUser === '') {
    // User field can be empty (create DB without user is OK)
    if (newUser && !newPass) { $('dbMsg').innerHTML = aErr('Password required for new user'); return; }
    if (newUser && !/^[a-zA-Z0-9_]{1,32}$/.test(newUser)) { $('dbMsg').innerHTML = aErr('Invalid username format'); return; }
  }

  const payload = { name };
  if (selUser) {
    // assign existing user – send user but no password so backend just grants
    payload.user = selUser;
  } else if (newUser && newPass) {
    payload.user = newUser;
    payload.password = newPass;
  }

  $('dbMsg').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Creating database...');
  api.post('/api/databases', payload).then(r => {
    $('dbMsg').innerHTML = r.success ? aOk('Database created successfully!') : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('databases'), 1200);
  });
};

window.createDbUser = () => {
  const username = ($('nuName').value || '').trim();
  const password = $('nuPass').value;
  const sel      = $('nuDbs');
  const dbs      = [...sel.options].filter(o => o.selected).map(o => o.value);

  if (!username) { $('dbMsg').innerHTML = aErr('Username is required'); return; }
  if (!password) { $('dbMsg').innerHTML = aErr('Password is required'); return; }
  if (!/^[a-zA-Z0-9_]{1,32}$/.test(username)) { $('dbMsg').innerHTML = aErr('Invalid username format'); return; }

  $('dbMsg').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Creating user...');
  api.post('/api/database-users', { username, password, databases: dbs }).then(r => {
    $('dbMsg').innerHTML = r.success ? aOk('User created!') : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('databases'), 1200);
  });
};

/* Backup */
window.dbBackup = dbName => {
  $('dbMsg').innerHTML = aOk(`<i class="fas fa-spinner fa-spin"></i> Creating backup for <strong>${esc(dbName)}</strong>...`);
  api.post(`/api/databases/${encodeURIComponent(dbName)}/backup`, {}).then(r => {
    $('dbMsg').innerHTML = r.success
      ? aOk(`Backup ready! (${fmtB(r.size)}) <a href="${r.downloadUrl}" class="btn btn-s btn-sm" download="${esc(r.filename)}"><i class="fas fa-download"></i> Download ${esc(r.filename)}</a>`)
      : aErr(r.error||'Backup failed');
  });
};

/* Drop DB */
window.dbDrop = name => {
  if (!confirm(`DROP database "${name}"?\nThis CANNOT be undone!`)) return;
  api.del('/api/databases/' + name).then(r => {
    $('dbMsg').innerHTML = r.success ? aOk('Database dropped') : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('databases'), 1000);
  });
};

/* Drop user */
window.dbDropUser = name => {
  if (!confirm(`DROP user "${name}"?\nThis CANNOT be undone!`)) return;
  api.del('/api/database-users/' + name).then(r => {
    $('dbMsg').innerHTML = r.success ? aOk('User dropped') : aErr(r.error||'Failed');
    if (r.success) setTimeout(() => loadPage('databases'), 1000);
  });
};

/* Change password – FIXED: dedicated endpoint */
window.showChgPass = username => {
  // Inject modal into content area (not fmModal which may not exist)
  const mc = document.createElement('div');
  mc.id = 'dbModal';
  mc.innerHTML = mkModal('Change DB User Password',
    `<p class="mb">User: <strong>${esc(username)}</strong></p>
     <div class="form-group"><label>New Password</label>
     <input type="password" id="cpNewPass" class="form-control" autocomplete="new-password"></div>
     <div class="form-group"><label>Confirm Password</label>
     <input type="password" id="cpConPass" class="form-control" autocomplete="new-password"></div>
     <div id="cpStatus" class="mt-sm"></div>`,
    `<button class="btn btn-l" onclick="closeDbModal()">Cancel</button>
     <button class="btn btn-p" onclick="doChgPass('${esc(username)}')"><i class="fas fa-save"></i> Save</button>`);
  $('content').appendChild(mc);
  setTimeout(() => $('cpNewPass') && $('cpNewPass').focus(), 100);
};

window.closeDbModal = () => { const m=$('dbModal'); if(m) m.remove(); };

window.doChgPass = username => {
  const np = $('cpNewPass').value, cp = $('cpConPass').value;
  if (!np)      { $('cpStatus').innerHTML = aErr('Password is required'); return; }
  if (np !== cp){ $('cpStatus').innerHTML = aErr('Passwords do not match'); return; }
  if (np.length < 4){ $('cpStatus').innerHTML = aErr('Min 4 characters'); return; }
  $('cpStatus').innerHTML = aOk('<i class="fas fa-spinner fa-spin"></i> Changing...');
  api.post(`/api/database-users/${encodeURIComponent(username)}/password`, { newPassword: np }).then(r => {
    if (r.success) { $('cpStatus').innerHTML = aOk('Password changed!'); setTimeout(() => closeDbModal(), 1200); }
    else $('cpStatus').innerHTML = aErr(r.error||'Failed');
  });
};

/* ── Tunnel ──────────────────────────────────────────────────────────────── */
function pgTun(el) {
  api.get('/api/tunnel/status').then(s => {
    el.innerHTML = `<h2 class="page-title"><i class="fas fa-cloud"></i> Cloudflare Tunnel</h2>
      <p class="page-sub">Secure tunnel for remote access</p><div id="tunMsg"></div>
      <div class="card mb">
        <div class="label">Status</div>
        <span class="badge ${s.active?'badge-on':'badge-off'}">${s.active?'Connected':'Not Connected'}</span>
      </div>
      <div class="card">
        <h3 class="mb">Setup Tunnel</h3>
        <p class="text-muted mb">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4a89dc">Cloudflare Zero Trust</a><br>
           2. Networks → Tunnels → Create a tunnel → copy token<br>
           3. Paste the token below</p>
        <div class="flex-row">
          <input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1">
          <button class="btn btn-p" onclick="setTun()"><i class="fas fa-link"></i> Connect</button>
        </div>
      </div>`;
  });
}
window.setTun = () => api.post('/api/tunnel/setup', { token: $('tunToken').value.trim() }).then(r => {
  $('tunMsg').innerHTML = r.success ? aOk('Connected!') : aErr(r.error||'Failed');
  if (r.success) setTimeout(() => loadPage('tunnel'), 2000);
});

/* ── Terminal ────────────────────────────────────────────────────────────── */
function pgTerm(el) {
  el.innerHTML = `<h2 class="page-title"><i class="fas fa-terminal"></i> Terminal</h2>
    <p class="page-sub">Run shell commands on the server</p>
    <div class="terminal-box" id="termOut">$ </div>
    <div class="term-input">
      <input id="termIn" placeholder="Type command and press Enter..." onkeydown="if(event.key==='Enter')runCmd()">
      <button class="btn btn-p" onclick="runCmd()"><i class="fas fa-play"></i> Run</button>
    </div>`;
  $('termIn').focus();
}
window.runCmd = () => {
  const cmd = $('termIn').value.trim(); if (!cmd) return;
  const out = $('termOut'); out.textContent += cmd + '\n'; $('termIn').value = '';
  api.post('/api/terminal', { command: cmd }).then(r => {
    out.textContent += (r.output || '') + '\n$ '; out.scrollTop = out.scrollHeight;
  });
};

/* ── Settings ────────────────────────────────────────────────────────────── */
function pgSet(el) {
  el.innerHTML = `<h2 class="page-title"><i class="fas fa-sliders-h"></i> Settings</h2>
    <p class="page-sub">Panel configuration</p><div id="setMsg"></div>
    <div class="card" style="max-width:480px">
      <h3 class="mb">Change Admin Password</h3>
      <div class="form-group"><label>Current Password</label><input type="password" id="curPass" class="form-control"></div>
      <div class="form-group"><label>New Password (min 6)</label><input type="password" id="newPass" class="form-control"></div>
      <div class="form-group"><label>Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>
      <button class="btn btn-p" onclick="chgPass()"><i class="fas fa-save"></i> Update Password</button>
    </div>`;
}
window.chgPass = () => {
  const np = $('newPass').value, cp = $('cfmPass').value;
  if (np !== cp) { $('setMsg').innerHTML = aErr("Passwords don't match"); return; }
  if (np.length < 6) { $('setMsg').innerHTML = aErr('Min 6 characters'); return; }
  api.post('/api/settings/password', { currentPassword: $('curPass').value, newPassword: np })
    .then(r => { $('setMsg').innerHTML = r.success ? aOk('Password updated!') : aErr(r.error||'Failed'); });
};

/* ── Shared Alert Helpers ────────────────────────────────────────────────── */
function aOk(msg)  { return `<div class="alert alert-ok"><i class="fas fa-check-circle"></i> ${msg}</div>`; }
function aErr(msg) { return `<div class="alert alert-err"><i class="fas fa-exclamation-triangle"></i> ${msg}</div>`; }

/* ── Bootstrap ───────────────────────────────────────────────────────────── */
checkAuth();
JSEOF

log "LitePanel v2.2 app files created"

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
\$i = 0; \$i++;
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
step "Step 7.5: Configure OLS for phpMyAdmin"
########################################
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"
[ ! -f "$OLS_CONF" ] && err "OLS config not found!" && exit 1

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

mkdir -p /usr/local/lsws/conf/vhosts/Example /usr/local/lsws/Example/logs

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
systemctl restart lsws && sleep 3
log "OLS phpMyAdmin config done"

########################################
step "Step 8/10: Install Cloudflared + Fail2Ban"
########################################
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
cd /tmp
CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
wget -q "$CF_URL" -O cloudflared.deb 2>/dev/null
if [ -f cloudflared.deb ] && [ -s cloudflared.deb ]; then
  dpkg -i cloudflared.deb > /dev/null 2>&1 && log "Cloudflared installed" || err "Cloudflared dpkg failed"
  rm -f cloudflared.deb
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
Description=LitePanel Control Panel v2.2
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
step "Step 10/10: Verify Services"
########################################
systemctl restart mariadb 2>/dev/null && sleep 2
systemctl restart lsws    2>/dev/null && sleep 3

[ -S "/var/run/mysqld/mysqld.sock" ] && [ ! -S "/tmp/mysql.sock" ] && ln -sf /var/run/mysqld/mysqld.sock /tmp/mysql.sock

PHP_TEST=$(php -r "
try {
  \$m = new mysqli('localhost','root','${DB_ROOT_PASS}');
  echo \$m->connect_error ? 'FAIL:'.\$m->connect_error : 'OK';
  \$m->close();
} catch(Exception \$e){ echo 'FAIL:'.\$e->getMessage(); }
" 2>&1)
[[ "$PHP_TEST" == "OK" ]] && log "PHP→MySQL OK" || warn "PHP→MySQL: $PHP_TEST"

PMA_HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/phpmyadmin/ 2>/dev/null)
[ "$PMA_HTTP" = "200" ] || [ "$PMA_HTTP" = "302" ] && log "phpMyAdmin OK (HTTP $PMA_HTTP)" || warn "phpMyAdmin HTTP $PMA_HTTP"

mkdir -p /etc/litepanel
cat > /etc/litepanel/credentials <<CREDEOF
==========================================
  LitePanel v2.2 Credentials
==========================================
Panel URL:    http://${SERVER_IP}:${PANEL_PORT}
Panel Login:  ${ADMIN_USER} / ${ADMIN_PASS}
OLS Admin:    http://${SERVER_IP}:7080  (admin / ${ADMIN_PASS})
phpMyAdmin:   http://${SERVER_IP}:8088/phpmyadmin/
MariaDB root: ${DB_ROOT_PASS}
Generated:    $(date)
==========================================
CREDEOF
chmod 600 /etc/litepanel/credentials
cp /etc/litepanel/credentials /root/.litepanel_credentials

########################################
# SUMMARY
########################################
echo ""
echo -e "${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║      ✅ LitePanel v1.1 Installed!            ║${N}"
echo -e "${C}╠══════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}  Panel:      ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:  ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin: ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}  Login:      ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB root:    ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}  Saved:      ${B}/etc/litepanel/credentials${N}"
echo -e "${C}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${B}Service Status:${N}"
for svc in lsws mariadb litepanel fail2ban; do
  systemctl is-active --quiet $svc 2>/dev/null \
    && echo -e "  ${G}[✓]${N} $svc" \
    || echo -e "  ${R}[✗]${N} $svc NOT running"
done
echo ""
echo -e "${G}Open http://${SERVER_IP}:${PANEL_PORT} in your browser${N}"
