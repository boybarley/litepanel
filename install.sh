#!/bin/bash
############################################
# LitePanel Installer v2.0
# Fresh Ubuntu 22.04 LTS Only
############################################

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
ADMIN_USER="admin"
ADMIN_PASS="admin123"
DB_ROOT_PASS="LitePanel$(date +%s | tail -c 6)!"
SERVER_IP=$(hostname -I | awk '{print $1}')

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log() { echo -e "${G}[✓]${N} $1"; }
err() { echo -e "${R}[✗]${N} $1"; }

# === CHECK ROOT ===
[ "$EUID" -ne 0 ] && echo "Run as root!" && exit 1

clear
echo -e "${C}"
echo "  ╔══════════════════════════════╗"
echo "  ║   LitePanel Installer v2.0   ║"
echo "  ║   Ubuntu 22.04 LTS           ║"
echo "  ╚══════════════════════════════╝"
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

# Set OLS Admin Password
ENCRYPT_PASS=$(/usr/local/lsws/lsphp81/bin/php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_BCRYPT);" 2>/dev/null)
if [ -n "$ENCRYPT_PASS" ]; then
  echo "admin:${ENCRYPT_PASS}" > /usr/local/lsws/admin/conf/htpasswd
fi

# Configure PHP 8.1 in OLS
sed -i 's|lsphp74|lsphp81|g' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null
sed -i 's|lsphp80|lsphp81|g' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null

systemctl enable lsws > /dev/null 2>&1
systemctl start lsws
log "OpenLiteSpeed + PHP 8.1 installed"

########################################
step "Step 4/9: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Wait for MariaDB ready
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
  err "MariaDB failed to start - will retry later"
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

# --- app.js (Backend) ---
cat > app.js <<'APPEOF'
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const multer = require('multer');

const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: config.sessionSecret, resave: false, saveUninitialized: false, cookie: { maxAge: 86400000 } }));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => { if (req.session && req.session.user) return next(); res.status(401).json({ error: 'Unauthorized' }); };

function run(cmd) { try { return execSync(cmd, { timeout: 15000, maxBuffer: 2*1024*1024 }).toString().trim(); } catch(e) { return e.stderr ? e.stderr.toString() : e.message; } }
function svcActive(name) { try { execSync(`systemctl is-active ${name}`, { stdio: 'pipe' }); return true; } catch(e) { return false; } }

// Auth routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === config.adminUser && bcrypt.compareSync(password, config.adminPass)) {
    req.session.user = username;
    res.json({ success: true });
  } else { res.status(401).json({ error: 'Invalid credentials' }); }
});
app.get('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth', (req, res) => { res.json({ authenticated: !!(req.session && req.session.user) }); });

// Dashboard
app.get('/api/dashboard', auth, (req, res) => {
  const totalMem = os.totalmem(), freeMem = os.freemem();
  let disk = { total: 0, used: 0, free: 0 };
  try { const d = run("df -B1 / | tail -1").split(/\s+/); disk = { total: +d[1], used: +d[2], free: +d[3] }; } catch(e) {}
  res.json({
    hostname: os.hostname(), ip: run("hostname -I | awk '{print $1}'"),
    uptime: os.uptime(), cpu: { model: os.cpus()[0].model, cores: os.cpus().length, load: os.loadavg() },
    memory: { total: totalMem, used: totalMem - freeMem, free: freeMem },
    disk, nodeVersion: process.version
  });
});

// Services
app.get('/api/services', auth, (req, res) => {
  res.json(['lsws','mariadb','fail2ban','cloudflared'].map(s => ({ name: s, active: svcActive(s) })));
});
app.post('/api/services/:name/:action', auth, (req, res) => {
  const ok = ['lsws','mariadb','fail2ban','cloudflared'];
  const acts = ['start','stop','restart'];
  if (!ok.includes(req.params.name) || !acts.includes(req.params.action)) return res.status(400).json({ error: 'Invalid' });
  try { execSync(`systemctl ${req.params.action} ${req.params.name}`, { timeout: 10000 }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// File Manager
app.get('/api/files', auth, (req, res) => {
  const p = path.resolve(req.query.path || '/');
  try {
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      const items = fs.readdirSync(p).map(name => {
        try { const s = fs.statSync(path.join(p, name)); return { name, isDir: s.isDirectory(), size: s.size, modified: s.mtime }; }
        catch(e) { return { name, isDir: false, size: 0, error: true }; }
      });
      res.json({ path: p, items });
    } else {
      res.json({ path: p, content: fs.readFileSync(p, 'utf8'), size: stat.size });
    }
  } catch(e) { res.status(404).json({ error: e.message }); }
});
app.put('/api/files', auth, (req, res) => {
  try { fs.writeFileSync(req.body.filePath, req.body.content); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/files', auth, (req, res) => {
  try { fs.rmSync(req.query.path, { recursive: true, force: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
const upload = multer({ dest: '/tmp/uploads/' });
app.post('/api/files/upload', auth, upload.single('file'), (req, res) => {
  try { fs.renameSync(req.file.path, path.join(req.body.path || '/tmp', req.file.originalname)); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/files/mkdir', auth, (req, res) => {
  try { fs.mkdirSync(req.body.path, { recursive: true }); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Domains
app.get('/api/domains', auth, (req, res) => {
  const d = '/usr/local/lsws/conf/vhosts';
  try {
    const list = fs.existsSync(d) ? fs.readdirSync(d).filter(n => fs.statSync(path.join(d,n)).isDirectory()) : [];
    res.json(list.map(name => ({ name, docRoot: `/usr/local/lsws/vhosts/${name}/html` })));
  } catch(e) { res.json([]); }
});
app.post('/api/domains', auth, (req, res) => {
  const { domain } = req.body;
  if (!domain || !/^[a-zA-Z0-9.-]+$/.test(domain)) return res.status(400).json({ error: 'Invalid domain' });
  try {
    const confDir = `/usr/local/lsws/conf/vhosts/${domain}`;
    const docRoot = `/usr/local/lsws/vhosts/${domain}/html`;
    fs.mkdirSync(confDir, { recursive: true });
    fs.mkdirSync(docRoot, { recursive: true });
    fs.writeFileSync(`${confDir}/vhconf.conf`, `docRoot ${docRoot}\nvhDomain ${domain}\nvhAliases www.${domain}\nenableGzip 1\n\nindex {\n  useServer 0\n  indexFiles index.php,index.html\n}\n\nscripthandler {\n  add lsapi:lsphp81 php\n}\n\naccessControl {\n  allow *\n}\n\nrewrite {\n  enable 1\n  autoLoadHtaccess 1\n}\n`);
    let httpd = fs.readFileSync('/usr/local/lsws/conf/httpd_config.conf', 'utf8');
    if (!httpd.includes(`virtualhost ${domain}`)) {
      httpd += `\nvirtualhost ${domain} {\n  vhRoot /usr/local/lsws/vhosts/${domain}\n  configFile ${confDir}/vhconf.conf\n  allowSymbolLink 1\n  enableScript 1\n  restrained 1\n}\n`;
      httpd = httpd.replace(/(listener Default\s*\{[^}]*)(})/, `$1  map ${domain} ${domain}\n$2`);
      fs.writeFileSync('/usr/local/lsws/conf/httpd_config.conf', httpd);
    }
    fs.writeFileSync(`${docRoot}/index.html`, `<!DOCTYPE html><html><body><h1>${domain}</h1><p>Hosted on LitePanel</p></body></html>`);
    execSync('chown -R nobody:nogroup ' + docRoot);
    execSync('systemctl restart lsws');
    res.json({ success: true, domain, docRoot });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/domains/:name', auth, (req, res) => {
  try {
    const d = req.params.name;
    fs.rmSync(`/usr/local/lsws/conf/vhosts/${d}`, { recursive: true, force: true });
    let httpd = fs.readFileSync('/usr/local/lsws/conf/httpd_config.conf', 'utf8');
    httpd = httpd.replace(new RegExp(`\\nvirtualhost ${d.replace(/\./g,'\\.')} \\{[^}]+\\}`, 'g'), '');
    httpd = httpd.replace(new RegExp(`\\s*map\\s+${d.replace(/\./g,'\\.')}.*`, 'g'), '');
    fs.writeFileSync('/usr/local/lsws/conf/httpd_config.conf', httpd);
    execSync('systemctl restart lsws');
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Databases
app.get('/api/databases', auth, (req, res) => {
  try {
    const out = run(`mysql -u root -p'${config.dbRootPass}' -e "SHOW DATABASES;" -s -N 2>/dev/null`);
    const skip = ['information_schema','performance_schema','mysql','sys'];
    res.json(out.split('\n').filter(d => d && !skip.includes(d)));
  } catch(e) { res.json([]); }
});
app.post('/api/databases', auth, (req, res) => {
  const { name, user, password } = req.body;
  if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) return res.status(400).json({ error: 'Invalid name' });
  try {
    run(`mysql -u root -p'${config.dbRootPass}' -e "CREATE DATABASE IF NOT EXISTS \\\`${name}\\\`;" 2>/dev/null`);
    if (user && password) run(`mysql -u root -p'${config.dbRootPass}' -e "CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${password}'; GRANT ALL ON \\\`${name}\\\`.* TO '${user}'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null`);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/databases/:name', auth, (req, res) => {
  try { run(`mysql -u root -p'${config.dbRootPass}' -e "DROP DATABASE IF EXISTS \\\`${req.params.name}\\\`;" 2>/dev/null`); res.json({ success: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Tunnel
app.get('/api/tunnel/status', auth, (req, res) => {
  res.json({ active: svcActive('cloudflared') });
});
app.post('/api/tunnel/setup', auth, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    fs.writeFileSync('/etc/systemd/system/cloudflared.service',
      `[Unit]\nDescription=Cloudflare Tunnel\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/bin/cloudflared tunnel run --token ${token}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n`);
    execSync('systemctl daemon-reload && systemctl enable cloudflared && systemctl restart cloudflared');
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Settings
app.post('/api/settings/password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!bcrypt.compareSync(currentPassword, config.adminPass)) return res.status(401).json({ error: 'Wrong password' });
  config.adminPass = bcrypt.hashSync(newPassword, 10);
  fs.writeFileSync(path.join(__dirname, 'config.json'), JSON.stringify(config, null, 2));
  res.json({ success: true });
});

// Terminal
app.post('/api/terminal', auth, (req, res) => {
  try { res.json({ output: run(req.body.command) }); }
  catch(e) { res.json({ output: e.message }); }
});

app.listen(config.panelPort, '0.0.0.0', () => console.log(`LitePanel running on port ${config.panelPort}`));
APPEOF

# --- public/index.html ---
cat > public/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  <aside class="sidebar">
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

# --- public/css/style.css ---
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
.sidebar{width:220px;background:#12141a;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10}
.sidebar .logo{padding:20px;font-size:20px;font-weight:700;color:#4f8cff;border-bottom:1px solid #2a2d35}
.sidebar nav{flex:1;padding:10px 0;overflow-y:auto}
.sidebar nav a{display:block;padding:12px 20px;color:#8a8d93;text-decoration:none;transition:.2s;font-size:14px}
.sidebar nav a:hover,.sidebar nav a.active{background:#1a1d23;color:#4f8cff;border-right:3px solid #4f8cff}
.logout-btn{padding:15px 20px;color:#e74c3c;text-decoration:none;border-top:1px solid #2a2d35;font-size:14px}
.content{flex:1;margin-left:220px;padding:30px;min-height:100vh}
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
.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;transition:.2s;display:inline-block}
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
.breadcrumb a{color:#4f8cff;text-decoration:none}
.breadcrumb span{color:#6a6d73}
.file-item{display:flex;align-items:center;padding:10px 16px;background:#2a2d35;margin-bottom:2px;cursor:pointer;border-radius:4px;font-size:14px}
.file-item:hover{background:#32353d}
.file-item .icon{margin-right:10px;font-size:16px}
.file-item .name{flex:1}
.file-item .size{color:#8a8d93;margin-right:16px;min-width:70px;text-align:right;font-size:13px}
.terminal-box{background:#0d0d0d;color:#0f0;font-family:'Courier New',monospace;padding:20px;border-radius:10px;min-height:350px;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;font-size:13px}
.term-input{display:flex;gap:10px;margin-top:10px}
.term-input input{flex:1;background:#0d0d0d;border:1px solid #333;color:#0f0;font-family:'Courier New',monospace;padding:10px;border-radius:6px;outline:none}
.flex-row{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:16px}
.mt{margin-top:16px}.mb{margin-bottom:16px}
CSSEOF

# --- public/js/app.js (Frontend) ---
cat > public/js/app.js <<'JSEOF'
const api = {
  async req(url, opt = {}) {
    const h = {}; if (!(opt.body instanceof FormData)) h['Content-Type'] = 'application/json';
    const r = await fetch(url, { headers: h, ...opt, body: opt.body instanceof FormData ? opt.body : opt.body ? JSON.stringify(opt.body) : undefined });
    return r.json();
  },
  get: u => api.req(u),
  post: (u, b) => api.req(u, { method: 'POST', body: b }),
  put: (u, b) => api.req(u, { method: 'PUT', body: b }),
  del: u => api.req(u, { method: 'DELETE' })
};

const $ = id => document.getElementById(id);
const fmtB = b => { if (!b) return '0 B'; const k = 1024, s = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log(b)/Math.log(k)); return (b/Math.pow(k,i)).toFixed(1)+' '+s[i]; };
const fmtUp = s => { const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return d+'d '+h+'h '+m+'m'; };
const esc = t => { const d=document.createElement('div'); d.textContent=t; return d.innerHTML; };
const pClass = p => p>80?'danger':p>60?'warn':'';

let curPath = '/usr/local/lsws';
let editFile = '';

async function checkAuth() {
  const r = await api.get('/api/auth');
  if (r.authenticated) { showPanel(); loadPage('dashboard'); } else showLogin();
}
function showLogin() { $('loginPage').style.display='flex'; $('mainPanel').style.display='none'; }
function showPanel() { $('loginPage').style.display='none'; $('mainPanel').style.display='flex'; }

$('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const r = await api.post('/api/login', { username: $('username').value, password: $('password').value });
  if (r.success) { showPanel(); loadPage('dashboard'); } else $('loginError').textContent='Invalid credentials';
});
$('logoutBtn').addEventListener('click', async e => { e.preventDefault(); await api.get('/api/logout'); showLogin(); });

document.querySelectorAll('.sidebar nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.sidebar nav a').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    loadPage(a.dataset.page);
  });
});

async function loadPage(p) {
  const el = $('content');
  switch(p) {
    case 'dashboard': return pgDash(el);
    case 'services': return pgSvc(el);
    case 'files': return pgFiles(el);
    case 'domains': return pgDom(el);
    case 'databases': return pgDb(el);
    case 'tunnel': return pgTun(el);
    case 'terminal': return pgTerm(el);
    case 'settings': return pgSet(el);
  }
}

// Dashboard
async function pgDash(el) {
  const d = await api.get('/api/dashboard');
  const s = await api.get('/api/services');
  const mp = Math.round(d.memory.used/d.memory.total*100);
  const dp = d.disk.total ? Math.round(d.disk.used/d.disk.total*100) : 0;
  el.innerHTML = `<h2 class="page-title">📊 Dashboard</h2><p class="page-sub">${d.hostname} (${d.ip})</p>
  <div class="stats-grid">
    <div class="card"><div class="label">CPU</div><div class="value">${d.cpu.cores} Cores</div><div class="sub">Load: ${d.cpu.load.map(l=>l.toFixed(2)).join(', ')}</div></div>
    <div class="card"><div class="label">Memory</div><div class="value">${mp}%</div><div class="progress"><div class="progress-bar ${pClass(mp)}" style="width:${mp}%"></div></div><div class="sub">${fmtB(d.memory.used)} / ${fmtB(d.memory.total)}</div></div>
    <div class="card"><div class="label">Disk</div><div class="value">${dp}%</div><div class="progress"><div class="progress-bar ${pClass(dp)}" style="width:${dp}%"></div></div><div class="sub">${fmtB(d.disk.used)} / ${fmtB(d.disk.total)}</div></div>
    <div class="card"><div class="label">Uptime</div><div class="value">${fmtUp(d.uptime)}</div><div class="sub">Node ${d.nodeVersion}</div></div>
  </div>
  <h3 class="mb">Services</h3>
  <table class="tbl"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>
  ${s.map(x=>`<tr><td>${x.name}</td><td><span class="badge ${x.active?'badge-on':'badge-off'}">${x.active?'Running':'Stopped'}</span></td></tr>`).join('')}
  </tbody></table>
  <div class="mt"><a href="http://${d.ip}:7080" target="_blank" class="btn btn-p">OLS Admin</a> <a href="http://${d.ip}:8088/phpmyadmin/" target="_blank" class="btn btn-w">phpMyAdmin</a></div>`;
}

// Services
async function pgSvc(el) {
  const s = await api.get('/api/services');
  el.innerHTML = `<h2 class="page-title">⚙️ Services</h2><p class="page-sub">Manage services</p><div id="svcMsg"></div>
  <table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>
  ${s.map(x=>`<tr><td><strong>${x.name}</strong></td><td><span class="badge ${x.active?'badge-on':'badge-off'}">${x.active?'Running':'Stopped'}</span></td>
  <td><button class="btn btn-s btn-sm" onclick="svcAct('${x.name}','start')">Start</button> <button class="btn btn-d btn-sm" onclick="svcAct('${x.name}','stop')">Stop</button> <button class="btn btn-w btn-sm" onclick="svcAct('${x.name}','restart')">Restart</button></td></tr>`).join('')}
  </tbody></table>`;
}
window.svcAct = async (n, a) => {
  const r = await api.post(`/api/services/${n}/${a}`);
  $('svcMsg').innerHTML = r.success ? `<div class="alert alert-ok">${n} ${a}ed</div>` : `<div class="alert alert-err">${r.error}</div>`;
  setTimeout(() => loadPage('services'), 1200);
};

// Files
async function pgFiles(el, p) {
  if (p) curPath = p;
  const d = await api.get('/api/files?path=' + encodeURIComponent(curPath));
  if (d.error) { el.innerHTML = `<div class="alert alert-err">${d.error}</div>`; return; }
  if (d.content !== undefined) {
    editFile = d.path;
    el.innerHTML = `<h2 class="page-title">📝 Edit File</h2><p class="page-sub">${esc(d.path)}</p><div id="fMsg"></div>
    <textarea class="form-control" id="fContent">${esc(d.content)}</textarea>
    <div class="mt"><button class="btn btn-p" onclick="saveF()">Save</button> <button class="btn btn-d" onclick="pgFiles($('content'),'${curPath.replace(/'/g,"\\'")}')">Back</button></div>`;
    return;
  }
  const parts = curPath.split('/').filter(Boolean);
  let bc = '<a href="#" onclick="pgFiles($(\'content\'),\'/\')">root</a>';
  let bp = '';
  parts.forEach(x => { bp += '/'+x; bc += ` <span>/</span> <a href="#" onclick="pgFiles($('content'),'${bp}')">${x}</a>`; });
  const items = (d.items||[]).sort((a,b) => a.isDir===b.isDir ? a.name.localeCompare(b.name) : a.isDir?-1:1);
  const parent = curPath === '/' ? '' : curPath.split('/').slice(0,-1).join('/')||'/';
  el.innerHTML = `<h2 class="page-title">📁 File Manager</h2><div class="breadcrumb">${bc}</div><div id="fMsg"></div>
  <div class="mb"><button class="btn btn-p" onclick="uploadF()">Upload</button> <button class="btn btn-s" onclick="mkdirF()">New Folder</button></div>
  <div>${parent ? `<div class="file-item" ondblclick="pgFiles($('content'),'${parent}')"><span class="icon">📁</span><span class="name">..</span><span class="size"></span></div>` : ''}
  ${items.map(i => `<div class="file-item" ondblclick="pgFiles($('content'),'${curPath==='/'?'':curPath}/${i.name}')">
    <span class="icon">${i.isDir?'📁':'📄'}</span><span class="name">${esc(i.name)}</span><span class="size">${i.isDir?'':fmtB(i.size)}</span>
    <button class="btn btn-d btn-sm" onclick="event.stopPropagation();delF('${curPath==='/'?'':curPath}/${i.name}')">Del</button>
  </div>`).join('')}</div>`;
}
window.saveF = async () => {
  const r = await api.put('/api/files', { filePath: editFile, content: $('fContent').value });
  $('fMsg').innerHTML = r.success ? '<div class="alert alert-ok">Saved!</div>' : `<div class="alert alert-err">${r.error}</div>`;
};
window.delF = async p => { if (confirm('Delete '+p+'?')) { await api.del('/api/files?path='+encodeURIComponent(p)); pgFiles($('content')); } };
window.uploadF = () => {
  const inp = document.createElement('input'); inp.type='file';
  inp.onchange = async () => { const fd = new FormData(); fd.append('file',inp.files[0]); fd.append('path',curPath); await api.req('/api/files/upload',{method:'POST',body:fd}); pgFiles($('content')); };
  inp.click();
};
window.mkdirF = () => { const n=prompt('Folder name:'); if(n) api.post('/api/files/mkdir',{path:curPath+'/'+n}).then(()=>pgFiles($('content'))); };

// Domains
async function pgDom(el) {
  const d = await api.get('/api/domains');
  el.innerHTML = `<h2 class="page-title">🌐 Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div>
  <div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px">
  <button class="btn btn-p" onclick="addDom()">Add Domain</button></div>
  <table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>
  ${d.map(x=>`<tr><td><strong>${x.name}</strong></td><td><code>${x.docRoot}</code></td>
  <td><button class="btn btn-p btn-sm" onclick="pgFiles($('content'),'${x.docRoot}')">Files</button> <button class="btn btn-d btn-sm" onclick="delDom('${x.name}')">Delete</button></td></tr>`).join('')}
  ${d.length===0?'<tr><td colspan="3" style="text-align:center;color:#8a8d93">No domains</td></tr>':''}
  </tbody></table>`;
}
window.addDom = async () => {
  const r = await api.post('/api/domains', { domain: $('newDom').value.trim() });
  $('domMsg').innerHTML = r.success ? '<div class="alert alert-ok">Domain added!</div>' : `<div class="alert alert-err">${r.error}</div>`;
  if (r.success) setTimeout(() => loadPage('domains'), 1000);
};
window.delDom = async n => { if(confirm('Delete '+n+'?')) { await api.del('/api/domains/'+n); loadPage('domains'); } };

// Databases
async function pgDb(el) {
  const d = await api.get('/api/databases');
  const info = await api.get('/api/dashboard');
  el.innerHTML = `<h2 class="page-title">🗃️ Databases</h2><p class="page-sub">MariaDB management</p><div id="dbMsg"></div>
  <div class="flex-row">
    <div><label style="font-size:12px;color:#8a8d93">Database</label><input id="dbName" class="form-control" placeholder="my_db"></div>
    <div><label style="font-size:12px;color:#8a8d93">User</label><input id="dbUser" class="form-control" placeholder="user"></div>
    <div><label style="font-size:12px;color:#8a8d93">Password</label><input id="dbPass" class="form-control" placeholder="pass"></div>
    <button class="btn btn-p" onclick="addDb()">Create</button>
  </div>
  <table class="tbl"><thead><tr><th>Database</th><th>Actions</th></tr></thead><tbody>
  ${(Array.isArray(d)?d:[]).map(x=>`<tr><td><strong>${x}</strong></td><td><button class="btn btn-d btn-sm" onclick="dropDb('${x}')">Drop</button></td></tr>`).join('')}
  </tbody></table>
  <div class="mt"><a href="http://${info.ip}:8088/phpmyadmin/" target="_blank" class="btn btn-w">Open phpMyAdmin</a></div>`;
}
window.addDb = async () => {
  const r = await api.post('/api/databases', { name:$('dbName').value, user:$('dbUser').value, password:$('dbPass').value });
  $('dbMsg').innerHTML = r.success ? '<div class="alert alert-ok">Created!</div>' : `<div class="alert alert-err">${r.error}</div>`;
  if (r.success) setTimeout(()=>loadPage('databases'),1000);
};
window.dropDb = async n => { if(confirm('DROP '+n+'?')) { await api.del('/api/databases/'+n); loadPage('databases'); } };

// Tunnel
async function pgTun(el) {
  const s = await api.get('/api/tunnel/status');
  el.innerHTML = `<h2 class="page-title">☁️ Cloudflare Tunnel</h2><p class="page-sub">Secure tunnel to your server</p><div id="tunMsg"></div>
  <div class="card mb"><div class="label">Status</div><span class="badge ${s.active?'badge-on':'badge-off'}">${s.active?'Connected':'Not Connected'}</span></div>
  <div class="card"><h3 class="mb">Setup Tunnel</h3>
  <p style="color:#8a8d93;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4f8cff">Cloudflare Zero Trust</a><br>2. Create a Tunnel → copy token<br>3. Paste below</p>
  <div class="flex-row"><input id="tunToken" class="form-control" placeholder="Tunnel token..." style="flex:1"><button class="btn btn-p" onclick="setTun()">Connect</button></div></div>`;
}
window.setTun = async () => {
  const r = await api.post('/api/tunnel/setup', { token: $('tunToken').value.trim() });
  $('tunMsg').innerHTML = r.success ? '<div class="alert alert-ok">Connected!</div>' : `<div class="alert alert-err">${r.error}</div>`;
  if (r.success) setTimeout(()=>loadPage('tunnel'),2000);
};

// Terminal
function pgTerm(el) {
  el.innerHTML = `<h2 class="page-title">💻 Terminal</h2><p class="page-sub">Run commands on server</p>
  <div class="terminal-box" id="termOut">$ </div>
  <div class="term-input"><input id="termIn" placeholder="Type command..." onkeydown="if(event.key==='Enter')runCmd()"><button class="btn btn-p" onclick="runCmd()">Run</button></div>`;
  $('termIn').focus();
}
window.runCmd = async () => {
  const cmd = $('termIn').value.trim(); if(!cmd) return;
  const out = $('termOut');
  out.textContent += cmd + '\n';
  $('termIn').value = '';
  const r = await api.post('/api/terminal', { command: cmd });
  out.textContent += (r.output||'') + '\n$ ';
  out.scrollTop = out.scrollHeight;
};

// Settings
function pgSet(el) {
  el.innerHTML = `<h2 class="page-title">🔧 Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div>
  <div class="card" style="max-width:400px"><h3 class="mb">Change Password</h3>
  <div class="mb"><label style="font-size:12px;color:#8a8d93">Current Password</label><input type="password" id="curPass" class="form-control"></div>
  <div class="mb"><label style="font-size:12px;color:#8a8d93">New Password</label><input type="password" id="newPass" class="form-control"></div>
  <div class="mb"><label style="font-size:12px;color:#8a8d93">Confirm Password</label><input type="password" id="cfmPass" class="form-control"></div>
  <button class="btn btn-p" onclick="chgPass()">Update</button></div>`;
}
window.chgPass = async () => {
  const np=$('newPass').value, cp=$('cfmPass').value;
  if(np!==cp) { $('setMsg').innerHTML='<div class="alert alert-err">Passwords dont match</div>'; return; }
  if(np.length<6) { $('setMsg').innerHTML='<div class="alert alert-err">Min 6 characters</div>'; return; }
  const r = await api.post('/api/settings/password', { currentPassword:$('curPass').value, newPassword:np });
  $('setMsg').innerHTML = r.success ? '<div class="alert alert-ok">Updated!</div>' : `<div class="alert alert-err">${r.error}</div>`;
};

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
if [ -f pma.tar.gz ]; then
  tar xzf pma.tar.gz
  cp -rf phpMyAdmin-*/* ${PMA_DIR}/
  rm -rf phpMyAdmin-* pma.tar.gz

  cat > ${PMA_DIR}/config.inc.php <<PMAEOF
<?php
\$cfg['blowfish_secret'] = '$(openssl rand -hex 16)';
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
# Cloudflared
cd /tmp
wget -q "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb" -O cloudflared.deb 2>/dev/null
if [ -f cloudflared.deb ]; then
  dpkg -i cloudflared.deb > /dev/null 2>&1
  rm -f cloudflared.deb
  log "Cloudflared installed"
else
  err "Cloudflared download failed (install manually later)"
fi

# Fail2Ban
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
Description=LitePanel
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

# Restart services
systemctl restart lsws 2>/dev/null
systemctl restart mariadb 2>/dev/null

# Wait and verify
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
echo -e "${C}╔══════════════════════════════════════════╗${N}"
echo -e "${C}║      ✅ Installation Complete!           ║${N}"
echo -e "${C}╠══════════════════════════════════════════╣${N}"
echo -e "${C}║${N}                                          ${C}║${N}"
echo -e "${C}║${N}  LitePanel:  ${G}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "${C}║${N}  OLS Admin:  ${G}http://${SERVER_IP}:7080${N}"
echo -e "${C}║${N}  phpMyAdmin: ${G}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo -e "${C}║${N}                                          ${C}║${N}"
echo -e "${C}║${N}  Panel Login: ${Y}${ADMIN_USER}${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  OLS Admin:   ${Y}admin${N} / ${Y}${ADMIN_PASS}${N}"
echo -e "${C}║${N}  DB Root Pass: ${Y}${DB_ROOT_PASS}${N}"
echo -e "${C}║${N}                                          ${C}║${N}"
echo -e "${C}║${N}  Credentials: ${B}/root/.litepanel_credentials${N}"
echo -e "${C}║${N}                                          ${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════╝${N}"
echo ""

# Verify services
echo -e "${B}Service Status:${N}"
for svc in lsws mariadb litepanel fail2ban; do
  if systemctl is-active --quiet $svc 2>/dev/null; then
    echo -e "  ${G}[✓]${N} $svc running"
  else
    echo -e "  ${R}[✗]${N} $svc not running"
  fi
done
echo ""
echo -e "${G}DONE! Open http://${SERVER_IP}:${PANEL_PORT} in browser${N}"
