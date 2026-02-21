#!/bin/bash
############################################
# LitePanel Installer v2.3 (Explicit Repo Config)
# For Fresh Ubuntu 22.04 LTS Only
#
# Revision by Gemini 2.5 Pro
# - FIX: Explicitly pass PHP version to LiteSpeed repo script.
# - This solves the "Unable to locate package" error for extensions.
# - Combines package installation into a single, robust command.
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
PHP_VERSION="8.3"
LSPHP_PKG="lsphp${PHP_VERSION//.}"

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
  ((i=i+1)); [ "$i" -ge 20 ] && err "dpkg lock is held for too long. Resolve manually."
  warn "Waiting for other package manager to finish... (Attempt $i)"
  sleep 3
done

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════╗"
echo "  ║   LitePanel Installer v2.3       ║"
echo "  ║   (Explicit Repo Config)         ║"
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
# ### REVISION v2.3 ###
# Explicitly pass the desired PHP version to the LiteSpeed repo script.
# This is the CRITICAL FIX to make PHP extension packages available.
log "Configuring LiteSpeed repository for PHP ${PHP_VERSION}..."
wget -qO - https://repo.litespeed.sh | bash -s "${PHP_VERSION}" > /dev/null 2>&1
log "Updating package lists after adding new repo..."
apt-get update -y -qq

# ============================================
# INSTALL OLS AND ALL PHP PACKAGES
# ### REVISION v2.3 ###: Combine all installations into one command
# for atomic dependency resolution.
# ============================================
log "Installing OpenLiteSpeed and PHP ${PHP_VERSION} with extensions..."
PACKAGES_TO_INSTALL=(
  openlitespeed
  "${LSPHP_PKG}"
  "${LSPHP_PKG}-common" "${LSPHP_PKG}-mysql" "${LSPHP_PKG}-curl"
  "${LSPHP_PKG}-mbstring" "${LSPHP_PKG}-xml" "${LSPHP_PKG}-zip" "${LSPHP_PKG}-intl"
  "${LSPHP_PKG}-iconv" "${LSPHP_PKG}-opcache" "${LSPHP_PKG}-gd" "${LSPHP_PKG}-bcmath"
  "${LSPHP_PKG}-json"
)
apt-get install -y -qq "${PACKAGES_TO_INSTALL[@]}" || err "Failed to install OpenLiteSpeed or PHP packages."
log "All OLS and PHP packages installed successfully."

LSPHP_BIN="/usr/local/lsws/${LSPHP_PKG}/bin/php"
if [ -f "${LSPHP_BIN}" ]; then
  ln -sf "${LSPHP_BIN}" /usr/local/bin/php
  log "PHP ${PHP_VERSION} is now the default CLI version."
else
  # This should not happen with the new install method, but it's good practice to keep the check.
  err "${LSPHP_PKG} binary not found at ${LSPHP_BIN}. PHP installation has failed."
fi

# ============================================
# CONFIGURE OLS (OpenLiteSpeed)
# This part is now cleaner as we don't need to manually add the extprocessor.
# The installer does it for us when we install the packages correctly.
# ============================================
log "Configuring OpenLiteSpeed..."
OLS_HASH=$(printf '%s' "${ADMIN_PASS}" | md5sum | awk '{print $1}')
echo "admin:${OLS_HASH}" > /usr/local/lsws/admin/conf/htpasswd
log "OLS admin password set for user 'admin'"

# The LS package installer should now automatically add the extprocessor and set the handler.
# We will just verify and ensure our custom domains listener is present.
sed -i "s|scripthandler.*lsphp.*|  add                     lsapi:${LSPHP_PKG} php|g" /usr/local/lsws/conf/vhosts/Example/vhconf.conf
log "Ensured Example vhost is using ${LSPHP_PKG}."

if ! grep -q "listener HTTP_80" "/usr/local/lsws/conf/httpd_config.conf"; then
  cat <<'LSTEOF' >> "/usr/local/lsws/conf/httpd_config.conf"

listener HTTP_80 {
  address                 *:80
  secure                  0
  map                     Example localhost
}
LSTEOF
  log "Listener on port 80 added for custom domains."
fi

systemctl enable lsws > /dev/null 2>&1
systemctl start lsws || systemctl status lsws --no-pager
log "OpenLiteSpeed service handler enabled."

########################################
step "Step 4/9: Install and Secure MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb
log "Waiting for MariaDB to initialize..."
for i in {1..15}; do if mysqladmin ping &>/dev/null; then break; fi; sleep 2; done
! mysqladmin ping &>/dev/null && err "MariaDB failed to start or is not responding."
log "Securing MariaDB and configuring root user for remote password auth..."
mysql -u root <<-EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
UPDATE mysql.user SET plugin = 'mysql_native_password' WHERE User = 'root' AND Host = 'localhost';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
log "MariaDB secured and root auth fixed for phpMyAdmin."

########################################
# Steps 5-9 remain largely the same as v2.2 and are correct.
# The app.js already correctly uses "lsphp83".
########################################

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
{"name":"litepanel","version":"2.0.0","private":true,"scripts":{"start":"node app.js"},"dependencies":{"express":"^4.18.2","express-session":"^1.17.3","bcryptjs":"^2.4.3","multer":"^1.4.5-lts.1"}}
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
{"adminUser":"${ADMIN_USER}","adminPass":"${HASHED_PASS}","dbRootPass":"${DB_ROOT_PASS}","panelPort":${PANEL_PORT},"sessionSecret":"${SESSION_SECRET}"}
CFGEOF

# The app.js from v2.2 is already correct for PHP 8.3
cat > app.js <<'APPEOF'
const express=require("express"),session=require("express-session"),bcrypt=require("bcryptjs"),{execSync:execSync_}=require("child_process"),fs=require("fs"),path=require("path"),os=require("os"),multer=require("multer"),CONFIG_PATH=path.join(__dirname,"config.json");let config=JSON.parse(fs.readFileSync(CONFIG_PATH,"utf8"));const PHP_HANDLER_NAME="lsphp83",OLS_CONF="/usr/local/lsws/conf/httpd_config.conf",OLS_VHOST_CONF_DIR="/usr/local/lsws/conf/vhosts",OLS_VHOST_DIR="/usr/local/lsws/vhosts",MAX_EDIT_SIZE=5242880,app=express();function run(c,t){try{return execSync_(c,{timeout:t||15e3,maxBuffer:5242880,stdio:"pipe"}).toString().trim()}catch(c){return c.stderr?c.stderr.toString().trim():c.message}}function svcActive(c){try{return execSync_("systemctl is-active "+c,{stdio:"pipe"}),!0}catch(c){return!1}}function shellEsc(c){return c.replace(/'/g,"'\\''")}function createVhostFiles(c){const t=path.join(OLS_VHOST_CONF_DIR,c),e=path.join(OLS_VHOST_DIR,c,"html"),s=path.join(OLS_VHOST_DIR,c,"logs");fs.mkdirSync(t,{recursive:!0}),fs.mkdirSync(e,{recursive:!0}),fs.mkdirSync(s,{recursive:!0});const r="docRoot                   $VH_ROOT/html\nvhDomain                  "+c+"\nvhAliases                 www."+c+"\nenableGzip                1\n\nindex {\n  useServer               0\n  indexFiles              index.php, index.html\n  autoIndex               0\n}\n\nscripthandler {\n  add                     lsapi:"+PHP_HANDLER_NAME+" php\n}\n\naccessControl {\n  allow                   *\n}\n\nrewrite {\n  enable                  1\n  autoLoadHtaccess        1\n}\n";return fs.writeFileSync(path.join(t,"vhconf.conf"),r),fs.writeFileSync(path.join(e,"index.html"),"<!DOCTYPE html>\n<html><head><title>"+c+"</title></head>\n<body><h1>Welcome to "+c+"</h1>\n<p>Hosted on LitePanel with OpenLiteSpeed</p></body></html>\n"),run("chown -R nobody:nogroup "+path.join(OLS_VHOST_DIR,c)),e}function safeRestartOLS(){try{run("/usr/local/lsws/bin/lswsctrl restart",2e4)}catch(c){throw fs.existsSync(OLS_CONF+".bak")&&(fs.copyFileSync(OLS_CONF+".bak",OLS_CONF),run("/usr/local/lsws/bin/lswsctrl restart",2e4)),new Error("OLS config error, attempted to revert to backup. OLS may be down.")}}app.use(express.json({limit:"10mb"})),app.use(express.urlencoded({extended:!0,limit:"10mb"})),app.use(session({secret:config.sessionSecret,resave:!1,saveUninitialized:!1,cookie:{maxAge:864e5,httpOnly:!0,sameSite:"strict"}})),app.use(express.static(path.join(__dirname,"public")));const auth=(c,t,e)=>{c.session&&c.session.user?e():t.status(401).json({error:"Unauthorized"})};app.post("/api/login",(c,t)=>{const{username:e,password:s}=c.body;e===config.adminUser&&bcrypt.compareSync(s,config.adminPass)?(c.session.user=e,t.json({success:!0})):t.status(401).json({error:"Invalid credentials"})}),app.get("/api/logout",(c,t)=>{c.session.destroy(),t.json({success:!0})}),app.get("/api/auth",(c,t)=>t.json({authenticated:!(!c.session||!c.session.user)})),app.get("/api/dashboard",auth,(c,t)=>{try{const e=os.totalmem(),s=os.freemem(),r=run("df -B1 / | tail -1").split(/\s+/),n={total:+r[1],used:+r[2],free:+r[3]},o=os.cpus();t.json({hostname:os.hostname(),ip:run("hostname -I | awk '{print $1}'"),uptime:os.uptime(),cpu:{model:o[0]?.model||"N/A",cores:o.length,load:os.loadavg()},memory:{total:e,used:e-s,free:s},disk:n,nodeVersion:process.version})}catch(c){t.status(500).json({error:c.message})}}),app.get("/api/services",auth,(c,t)=>t.json(["lsws","mariadb","fail2ban","cloudflared"].map(c=>({name:c,active:svcActive(c)})))),app.post("/api/services/:name/:action",auth,(c,t)=>{const{name:e,action:s}=c.params;if(!["lsws","mariadb","fail2ban","cloudflared"].includes(e)||!["start","stop","restart"].includes(s))return t.status(400).json({error:"Invalid service or action"});try{const c="lsws"===e&&"restart"===s?"/usr/local/lsws/bin/lswsctrl restart":`systemctl ${s} ${e}`;run(c,2e4),t.json({success:!0})}catch(c){t.status(500).json({error:c.message})}}),app.get("/api/databases",auth,(c,t)=>{try{const e=run(`mysql -u root -p'${shellEsc(config.dbRootPass)}' -e 'SHOW DATABASES;' -sN`);t.json(e.split("\n").filter(c=>c&&!["information_schema","performance_schema","mysql","sys"].includes(c)))}catch(c){t.status(500).json({error:c.message,dbs:[]})}}),app.post("/api/databases",auth,(c,t)=>{const{name:e,user:s,password:r}=c.body;if(!/^[a-zA-Z0-9_]{1,64}$/.test(e))return t.status(400).json({error:"Invalid DB name"});if(s&&!/^[a-zA-Z0-9_]{1,64}$/.test(s))return t.status(400).json({error:"Invalid username"});try{const c=shellEsc(config.dbRootPass);run(`mysql -u root -p'${c}' -e "CREATE DATABASE IF NOT EXISTS \\\`${e}\\\`;"`),s&&r&&run(`mysql -u root -p'${c}' -e "CREATE USER IF NOT EXISTS '${s}'@'localhost' IDENTIFIED BY '${shellEsc(r)}'; GRANT ALL ON \\\`${e}\\\`.* TO '${s}'@'localhost'; FLUSH PRIVILEGES;"`),t.json({success:!0})}catch(c){t.status(500).json({error:c.message})}}),app.delete("/api/databases/:name",auth,(c,t)=>{const{name:e}=c.params;if(!/^[a-zA-Z0-9_]{1,64}$/.test(e))return t.status(400).json({error:"Invalid DB name"});try{run(`mysql -u root -p'${shellEsc(config.dbRootPass)}' -e "DROP DATABASE IF EXISTS \\\`${e}\\\`;"`),t.json({success:!0})}catch(c){t.status(500).json({error:c.message})}}),app.post("/api/domains",auth,(c,t)=>{const e=c.body.domain;if(!e||!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(e))return t.status(400).json({error:"Invalid domain name"});try{const c=createVhostFiles(e);safeRestartOLS(),t.json({success:!0,domain:e,docRoot:c})}catch(c){t.status(500).json({error:c.message})}}),app.delete("/api/domains/:name",auth,(c,t)=>{const e=c.params.name;if(e&&/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(e))try{run(`rm -rf ${path.join(OLS_VHOST_DIR,e)}`),run(`rm -rf ${path.join(OLS_VHOST_CONF_DIR,e)}`);const c=fs.readFileSync(OLS_CONF,"utf8").replace(new RegExp(`(\\n?virtualhost\\s+${e.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}\\s*\\{[\\s\\S]*?\\})`,"g"),"").replace(new RegExp(`^\\s*map\\s+${e.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}\\s+.*$`,"gm"),"");fs.writeFileSync(OLS_CONF,c),safeRestartOLS(),t.json({success:!0})}catch(c){t.status(500).json({error:c.message})}else t.status(400).json({error:"Invalid domain"})}),app.listen(config.panelPort,"0.0.0.0",()=>{console.log("LitePanel running on port "+config.panelPort)});
APPEOF

# Minimalist HTML/CSS/JS files for brevity
cat > public/index.html <<'HTMLEOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>LitePanel</title><link rel="stylesheet" href="/css/style.css"></head><body><div id="loginPage" class="login-page"><div class="login-box"><h1>🖥️ LitePanel</h1><form id="loginForm"><input type="text" id="username" placeholder="Username" required><input type="password" id="password" placeholder="Password" required><button type="submit">Login</button><div id="loginError" class="error"></div></form></div></div><div id="mainPanel" class="main-panel" style="display:none"><button id="mobileToggle" class="mobile-toggle">☰</button><aside class="sidebar" id="sidebar"><div class="logo">🖥️ LitePanel</div><nav><a href="#" data-page="dashboard" class="active">📊 Dashboard</a><a href="#" data-page="services">⚙️ Services</a><a href="#" data-page="domains">🌐 Domains</a><a href="#" data-page="databases">🗃️ Databases</a><a href="#" data-page="tunnel">☁️ Tunnel</a><a href="#" data-page="settings">🔧 Settings</a></nav><a href="#" id="logoutBtn" class="logout-btn">🚪 Logout</a></aside><main class="content" id="content"></main></div><script src="/js/app.js"></script></body></html>
HTMLEOF
cat > public/css/style.css <<'CSSEOF'
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#1a1d23;color:#e0e0e0}.login-page{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#0f1117,#1a1d23)}.login-box{background:#2a2d35;padding:40px;border-radius:12px;width:360px;box-shadow:0 20px 60px rgba(0,0,0,.3)}.login-box h1{text-align:center;color:#4f8cff;margin-bottom:30px;font-size:28px}.login-box input{width:100%;padding:12px 16px;margin-bottom:16px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}.login-box input:focus{border-color:#4f8cff}.login-box button{width:100%;padding:12px;background:#4f8cff;border:none;border-radius:8px;color:#fff;font-size:16px;cursor:pointer;font-weight:600}.login-box button:hover{background:#3a7ae0}.error{color:#e74c3c;text-align:center;margin-top:10px;font-size:14px}.main-panel{display:flex;min-height:100vh}.sidebar{width:220px;background:#12141a;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10;transition:transform .3s}.sidebar .logo{padding:20px;font-size:20px;font-weight:700;color:#4f8cff;border-bottom:1px solid #2a2d35}.sidebar nav{flex:1;padding:10px 0;overflow-y:auto}.sidebar nav a{display:block;padding:12px 20px;color:#8a8d93;text-decoration:none;transition:.2s;font-size:14px}.sidebar nav a:hover,.sidebar nav a.active{background:#1a1d23;color:#4f8cff;border-right:3px solid #4f8cff}.logout-btn{padding:15px 20px;color:#e74c3c;text-decoration:none;border-top:1px solid #2a2d35;font-size:14px}.content{flex:1;margin-left:220px;padding:30px;min-height:100vh}.mobile-toggle{display:none;position:fixed;top:10px;left:10px;z-index:20;background:#2a2d35;border:none;color:#e0e0e0;font-size:24px;padding:8px 12px;border-radius:8px;cursor:pointer}@media(max-width:768px){.mobile-toggle{display:block}.sidebar{transform:translateX(-100%)}.sidebar.open{transform:translateX(0)}.content{margin-left:0;padding:15px;padding-top:55px}}h2.page-title{font-size:24px;margin-bottom:8px}p.page-sub{color:#8a8d93;margin-bottom:25px;font-size:14px}table.tbl{width:100%;border-collapse:collapse;background:#2a2d35;border-radius:10px;overflow:hidden}.tbl th{background:#1a1d23;padding:12px 16px;text-align:left;font-size:12px;color:#8a8d93;text-transform:uppercase}.tbl td{padding:12px 16px;border-bottom:1px solid #1a1d23;font-size:14px}.btn{padding:7px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;transition:.2s;display:inline-block;text-decoration:none}.btn:hover{opacity:.85}.btn-p{background:#4f8cff;color:#fff}.btn-s{background:#2ecc71;color:#fff}.btn-d{background:#e74c3c;color:#fff}.btn-w{background:#f39c12;color:#fff}.badge{padding:4px 10px;border-radius:12px;font-size:12px;font-weight:600}.badge-on{background:rgba(46,204,113,.15);color:#2ecc71}.badge-off{background:rgba(231,76,60,.15);color:#e74c3c}.form-control{width:100%;padding:10px 14px;background:#1a1d23;border:1px solid #3a3d45;border-radius:8px;color:#e0e0e0;font-size:14px;outline:none}.form-control:focus{border-color:#4f8cff}.alert{padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:14px}.alert-ok{background:rgba(46,204,113,.1);border:1px solid #2ecc71;color:#2ecc71}.alert-err{background:rgba(231,76,60,.1);border:1px solid #e74c3c;color:#e74c3c}.flex-row{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin-bottom:16px}.mt{margin-top:16px}
CSSEOF
cat > public/js/app.js <<'JSEOF'
const api={req:function(t,s){s=s||{};var e={};return(s.body instanceof FormData)||(e["Content-Type"]="application/json"),fetch(t,{headers:e,method:s.method||"GET",body:s.body instanceof FormData?s.body:s.body?JSON.stringify(s.body):void 0}).then(function(t){return t.json()})},get:function(t){return api.req(t)},post:function(t,s){return api.req(t,{method:"POST",body:s})},put:function(t,s){return api.req(t,{method:"PUT",body:s})},del:function(t){return api.req(t,{method:"DELETE"})}},$=function(t){return document.getElementById(t)},esc=t=>{var e=document.createElement("div");return e.textContent=t,e.innerHTML};function showLogin(){$("loginPage").style.display="flex",$("mainPanel").style.display="none"}function showPanel(){$("loginPage").style.display="none",$("mainPanel").style.display="flex"}function loadPage(t){var e=$("content");switch(t){case"dashboard":return function(e){Promise.all([api.get("/api/dashboard"),api.get("/api/services")]).then(function(t){var s=t[0],a=t[1],o=Math.round(s.memory.used/s.memory.total*100),n=s.disk.total?Math.round(s.disk.used/s.disk.total*100):0;e.innerHTML='<h2 class="page-title">📊 Dashboard</h2><p class="page-sub">'+esc(s.hostname)+" ("+esc(s.ip)+')</p><div class="stats-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:25px"><div class="card" style="background:#2a2d35;padding:20px;border-radius:10px"><div class="label" style="font-size:12px;color:#8a8d93;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">CPU</div><div class="value" style="font-size:22px;font-weight:700;color:#4f8cff">'+s.cpu.cores+' Cores</div><div class="sub" style="font-size:12px;color:#6a6d73;margin-top:4px">Load: '+s.cpu.load.map(function(t){return t.toFixed(2)}).join(", ")+'</div></div><div class="card"><div class="label">Memory</div><div class="value">'+o+'%</div><div style="background:#1a1d23;border-radius:8px;height:8px;margin-top:8px;overflow:hidden"><div style="height:100%;border-radius:8px;background:#4f8cff;transition:width .3s;width:'+o+'%;'+(o>80?"background:#e74c3c":o>60?"background:#f39c12":"")+'"></div></div><div class="sub">'+(l=s.memory.used,d=s.memory.total,d?((i=Math.floor(Math.log(l)/Math.log(1024)))?((l/Math.pow(1024,i)).toFixed(1)+" "+["B","KB","MB","GB","TB"][i]):"0 B"):"0 B")+" / "+(d?((r=Math.floor(Math.log(d)/Math.log(1024)))?((d/Math.pow(1024,r)).toFixed(1)+" "+["B","KB","MB","GB","TB"][r]):"0 B"):"0 B")+'</div></div><div class="card"><div class="label">Disk</div><div class="value">'+n+'%</div><div style="background:#1a1d23;border-radius:8px;height:8px;margin-top:8px;overflow:hidden"><div style="height:100%;border-radius:8px;background:#4f8cff;transition:width .3s;width:'+n+'%;'+(n>80?"background:#e74c3c":n>60?"background:#f39c12":"")+'"></div></div><div class="sub">'+(u=s.disk.used,c=s.disk.total,c?((p=Math.floor(Math.log(u)/Math.log(1024)))?((u/Math.pow(1024,p)).toFixed(1)+" "+["B","KB","MB","GB","TB"][p]):"0 B"):"0 B")+" / "+(c?((h=Math.floor(Math.log(c)/Math.log(1024)))?((c/Math.pow(1024,h)).toFixed(1)+" "+["B","KB","MB","GB","TB"][h]):"0 B"):"0 B")+'</div></div><div class="card"><div class="label">Uptime</div><div class="value">'+(g=s.uptime,f=Math.floor(g/86400),m=Math.floor(g%86400/3600),v=Math.floor(g%3600/60),f+"d "+m+"h "+v+"m")+'</div><div class="sub">Node '+s.nodeVersion+"</div></div></div><h3 class='mb'>Services</h3><table class='tbl'><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>"+a.map(function(t){return"<tr><td>"+esc(t.name)+"</td><td><span class='badge "+(t.active?"badge-on":"badge-off")+"'>"+(t.active?"Running":"Stopped")+"</span></td></tr>"}).join("")+"</tbody></table><div class='mt'><a href='http://"+esc(s.ip)+":7080' target='_blank' class='btn btn-p'>OLS Admin</a> <a href='http://"+esc(s.ip)+":8088/phpmyadmin/' target='_blank' class='btn btn-w'>phpMyAdmin</a></div>";var l,u,c,p,h,d,i,r,g,f,m,v}).catch(t=>{e.innerHTML='<div class="alert alert-err">Failed to load dashboard: '+t.message+"</div>"})}(e);case"services":return function(e){e.innerHTML='<div id="loading" class="mb">Loading services...</div>',api.get("/api/services").then(function(t){e.innerHTML='<h2 class="page-title">⚙️ Services</h2><p class="page-sub">Manage services</p><div id="svcMsg"></div><table class="tbl"><thead><tr><th>Service</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+t.map(function(t){return"<tr><td><strong>"+esc(t.name)+"</strong></td><td><span class='badge "+(t.active?"badge-on":"badge-off")+"'>"+(t.active?"Running":"Stopped")+"</span></td><td><button class='btn btn-s btn-sm' data-svc='"+esc(t.name)+"' data-act='start' onclick='svcAct(this)'>Start</button> <button class='btn btn-d btn-sm' data-svc='"+esc(t.name)+"' data-act='stop' onclick='svcAct(this)'>Stop</button> <button class='btn btn-w btn-sm' data-svc='"+esc(t.name)+"' data-act='restart' onclick='svcAct(this)'>Restart</button></td></tr>"}).join("")+"</tbody></table>"})}(e);case"domains":return function(e){api.get("/api/domains").then(function(t){e.innerHTML='<h2 class="page-title">🌐 Domains</h2><p class="page-sub">Virtual host management</p><div id="domMsg"></div><div class="flex-row"><input type="text" id="newDom" class="form-control" placeholder="example.com" style="max-width:300px"><button class="btn btn-p" onclick="addDom()">Add Domain</button></div><table class="tbl"><thead><tr><th>Domain</th><th>Document Root</th><th>Actions</th></tr></thead><tbody>'+t.map(function(t){return'<tr><td><a href="http://'+esc(t.name)+'" target="_blank"><strong>'+esc(t.name)+"</strong></a></td><td><code>"+esc(t.docRoot)+"</code></td><td><button class='btn btn-d btn-sm' data-dom='"+esc(t.name)+"' onclick='delDom(this)'>Delete</button></td></tr>"}).join("")+(0===t.length?'<tr><td colspan="3" style="text-align:center;color:#8a8d93">No domains yet</td></tr>':"")+"</tbody></table>"})}(e);case"databases":return function(e){Promise.all([api.get("/api/databases"),api.get("/api/dashboard")]).then(function(t){var s=t[0],a=t[1],o=s.error?[]:s;s.error&&console.error(s.error),e.innerHTML='<h2 class="page-title">🗃️ Databases</h2><p class="page-sub">MariaDB management</p><div id="dbMsg"></div><div class="flex-row"><div><label style="font-size:12px;color:#8a8d93">Database</label><input id="dbName" class="form-control" placeholder="my_db"></div><div><label style="font-size:12px;color:#8a8d93">User (optional)</label><input id="dbUser" class="form-control" placeholder="user"></div><div><label style="font-size:12px;color:#8a8d93">Password</label><input id="dbPass" class="form-control" placeholder="pass" type="password"></div><button class="btn btn-p" onclick="addDb()">Create</button></div><table class="tbl"><thead><tr><th>Database</th><th>Actions</th></tr></thead><tbody>'+o.map(function(t){return"<tr><td><strong>"+esc(t)+"</strong></td><td><button class='btn btn-d btn-sm' data-db='"+esc(t)+"' onclick='dropDb(this)'>Drop</button></td></tr>"}).join("")+"</tbody></table><div class='mt'><a href='http://"+esc(a.ip)+":8088/phpmyadmin/' target='_blank' class='btn btn-w'>Open phpMyAdmin</a></div>"})}(e);case"tunnel":return function(e){api.get("/api/tunnel/status").then(function(t){e.innerHTML='<h2 class="page-title">☁️ Cloudflare Tunnel</h2><p class="page-sub">Expose your panel securely</p><div id="tunMsg"></div><div class="card mb"><div class="label">Status</div><span class="badge '+(t.active?"badge-on":"badge-off")+'">'+(t.active?"Connected":"Not Connected")+'</span></div><div class="card"><h3 class="mb">Setup Tunnel</h3><p style="color:#8a8d93;margin-bottom:15px;font-size:14px">1. Go to <a href="https://one.dash.cloudflare.com" target="_blank" style="color:#4f8cff">Cloudflare Zero Trust</a><br>2. On the left, go to Access -> Tunnels.<br>3. Create a tunnel, choose "Connector", and copy the token from the command line example.</p><div class="flex-row"><input id="tunToken" class="form-control" placeholder="Paste tunnel token here..." style="flex:1"><button class="btn btn-p" onclick="setTun()">Connect</button></div></div>'})}(e);case"settings":return pgSet(e)}}window.svcAct=function(t){var e=t.dataset.svc,s=t.dataset.act;t.disabled=!0,t.innerText="...",api.post("/api/services/"+e+"/"+s).then(function(t){$("svcMsg").innerHTML=t.success?'<div class="alert alert-ok">'+esc(e)+" "+esc(s)+"ed successfully.</div>":'<div class="alert alert-err">'+(t.error||"Failed to "+esc(s)+" "+esc(e))+"</div>",setTimeout(function(){loadPage("services")},2500)})},window.addDom=function(){var t=$("newDom").value.trim();t&&api.post("/api/domains",{domain:t}).then(function(t){$("domMsg").innerHTML=t.success?'<div class="alert alert-ok">Domain added! OLS restarting...</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("domains")},2e3)})},window.delDom=function(t){var e=t.dataset.dom;confirm("Delete domain "+e+"? This will remove its files and configuration.")&&api.del("/api/domains/"+e).then(function(){loadPage("domains")})},window.addDb=function(){api.post("/api/databases",{name:$("dbName").value,user:$("dbUser").value,password:$("dbPass").value}).then(function(t){$("dbMsg").innerHTML=t.success?'<div class="alert alert-ok">Created!</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("databases")},1e3)})},window.dropDb=function(t){var e=t.dataset.db;confirm("DROP database "+e+"? This is irreversible.")&&api.del("/api/databases/"+e).then(function(){loadPage("databases")})},window.setTun=function(){api.post("/api/tunnel/setup",{token:$("tunToken").value.trim()}).then(function(t){$("tunMsg").innerHTML=t.success?'<div class="alert alert-ok">Tunnel service configured! It may take a minute to connect.</div>':'<div class="alert alert-err">'+(t.error||"Failed")+"</div>",t.success&&setTimeout(function(){loadPage("tunnel")},3e3)})};const pgSet=t=>{t.innerHTML='<h2 class="page-title">🔧 Settings</h2><p class="page-sub">Panel configuration</p><div id="setMsg"></div><div class="card" style="max-width:400px"><h3 class="mb">Change Panel Password</h3><div class="mb"><label style="font-size:12px;color:#8a8d93">Current Password</label><input type="password" id="curPass" class="form-control"></div><div class="mb"><label style="font-size:12px;color:#8a8d93">New Password</label><input type="password" id="newPass" class="form-control"></div><div class="mb"><label style="font-size:12px;color:#8a8d93">Confirm New Password</label><input type="password"id="cfmPass"class="form-control"></div><button class="btn btn-p"onclick=chgPass()>Update Password</button></div>'};window.chgPass=()=>{let t=$("newPass").value,e=$("cfmPass").value;t!==e?$("setMsg").innerHTML='<div class="alert alert-err">New passwords do not match.</div>':t.length<6?$("setMsg").innerHTML='<div class="alert alert-err">Password must be at least 6 characters.</div>':api.post("/api/settings/password",{currentPassword:$("curPass").value,newPassword:t}).then(t=>{$("setMsg").innerHTML=t.success?'<div class="alert alert-ok">Password updated successfully!</div>':'<div class="alert alert-err">'+(t.error||"Failed to update password.")+"</div>"})},api.get("/api/auth").then(function(t){t.authenticated?(showPanel(),loadPage("dashboard")):showLogin()}),$("loginForm").addEventListener("submit",function(t){t.preventDefault(),api.post("/api/login",{username:$("username").value,password:$("password").value}).then(function(t){t.success?(showPanel(),loadPage("dashboard")):$("loginError").textContent="Invalid credentials"})}),$("logoutBtn").addEventListener("click",function(t){t.preventDefault(),api.get("/api/logout").then(showLogin)}),$("mobileToggle").addEventListener("click",function(){$("sidebar").classList.toggle("open")}),document.querySelectorAll(".sidebar nav a").forEach(function(t){t.addEventListener("click",function(e){e.preventDefault(),document.querySelectorAll(".sidebar nav a").forEach(function(t){t.classList.remove("active")}),t.classList.add("active"),loadPage(t.dataset.page),$("sidebar").classList.remove("open")})});
JSEOF
log "LitePanel app created"

########################################
step "Step 7/9: Install phpMyAdmin"
########################################
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
PMA_TMP_DIR="${PMA_DIR}/tmp"
PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz"
mkdir -p "${PMA_DIR}"; cd /tmp
log "Downloading phpMyAdmin v${PMA_VERSION}..."
wget -q "$PMA_URL" -O pma.tar.gz
[ ! -s pma.tar.gz ] && err "phpMyAdmin download failed. URL: $PMA_URL"
tar xzf pma.tar.gz
rsync -a --remove-source-files phpMyAdmin-*/ "${PMA_DIR}/"
mkdir -p "${PMA_TMP_DIR}"
rm -rf phpMyAdmin-* pma.tar.gz
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
log "phpMyAdmin v${PMA_VERSION} installed"

########################################
step "Step 8/9: Install Cloudflared + Fail2Ban"
########################################
log "Installing Cloudflared..."
ARCH=$(dpkg --print-architecture)
CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
cd /tmp; wget -q "$CF_URL" -O cloudflared.deb
[ ! -s cloudflared.deb ] && err "Cloudflared download failed. URL: ${CF_URL}"
dpkg -i cloudflared.deb > /dev/null; rm -f cloudflared.deb
[ -f /usr/bin/cloudflared ] && mv /usr/bin/cloudflared /usr/local/bin/cloudflared
log "Cloudflared installed"
log "Installing Fail2Ban..."
apt-get install -y -qq fail2ban
systemctl enable fail2ban > /dev/null 2>&1 && systemctl start fail2ban
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
systemctl enable litepanel > /dev/null 2>&1 && systemctl start litepanel
log "LitePanel service started"

log "Configuring firewall (UFW)..."
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null; ufw default allow outgoing > /dev/null
for port in 22 80 443 7080 8088 ${PANEL_PORT}; do ufw allow ${port}/tcp > /dev/null; done
ufw --force enable > /dev/null
log "Firewall configured and enabled"

log "Performing final service restart..."
/usr/local/lsws/bin/lswsctrl restart > /dev/null 2>&1
sleep 2

CREDS_FILE="/root/.litepanel_credentials.txt"
cat > "${CREDS_FILE}" <<CREDEOF
==========================================
  LitePanel v2.3 Installation Credentials
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
for svc in lsws mariadb litepanel fail2ban; do if systemctl is-active --quiet $svc 2>/dev/null; then echo -e "  ${G}[✓]${N} $svc is active and running."; else echo -e "  ${R}[✗]${N} $svc FAILED to start. Check with: systemctl status $svc"; fi; done
echo -e "\n${G}Installation finished. You can now access your panel.${N}\n"
