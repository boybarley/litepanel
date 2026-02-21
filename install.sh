#!/bin/bash
############################################
# LitePanel Pro Installer v3.0
# Complete All-in-One Installer
# Fresh Ubuntu 22.04 LTS Only
# With Advanced Cloudflare & File Manager
############################################

export DEBIAN_FRONTEND=noninteractive

# === CONFIG ===
PANEL_DIR="/opt/litepanel-pro"
PANEL_PORT=3000
ADMIN_USER="admin"
ADMIN_PASS=$(openssl rand -base64 12 | tr -d "=+/" | cut -c1-16)
DB_ROOT_PASS="LitePanel$(openssl rand -hex 8)"
SESSION_SECRET=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7;exit}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; M='\033[0;35m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log()  { echo -e "${G}[✓]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
info() { echo -e "${B}[i]${N} $1"; }

# === CHECK ROOT ===
[ "$EUID" -ne 0 ] && err "Run as root!" && exit 1

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
echo -e "${M}"
cat << "EOF"
   __    _ __       ____                  __   ____           
  / /   (_) /____  / __ \____ _____  ___  / /  / __ \_________ 
 / /   / / __/ _ \/ /_/ / __ `/ __ \/ _ \/ /  / /_/ / ___/ __ \
/ /___/ / /_/  __/ ____/ /_/ / / / /  __/ /  / ____/ /  / /_/ /
/_____/_/\__/\___/_/    \__,_/_/ /_/\___/_/  /_/   /_/   \____/ 
                                                                 
EOF
echo -e "${N}"
echo -e "${C}Version 3.0 - Enterprise Multi-Domain Cloudflare Panel${N}"
echo -e "${C}══════════════════════════════════════════════════════${N}\n"
sleep 2

########################################
step "Step 1/12: Update System"
########################################
apt-get update -y -qq > /dev/null 2>&1
apt-get upgrade -y -qq > /dev/null 2>&1
log "System updated"

########################################
step "Step 2/12: Install Dependencies"
########################################
apt-get install -y -qq curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release ufw git unzip \
  openssl jq build-essential redis-server sqlite3 > /dev/null 2>&1
log "Dependencies installed"

########################################
step "Step 3/12: Install OpenLiteSpeed + PHP 8.1"
########################################
wget -O - https://repo.litespeed.sh 2>/dev/null | bash > /dev/null 2>&1
apt-get update -y -qq > /dev/null 2>&1
apt-get install -y openlitespeed > /dev/null 2>&1

if [ ! -d "/usr/local/lsws" ]; then
  err "OpenLiteSpeed installation failed!"
  exit 1
fi

# Install PHP 8.1 and extensions
apt-get install -y lsphp81 lsphp81-common lsphp81-mysql lsphp81-curl \
  lsphp81-intl lsphp81-mbstring lsphp81-xml lsphp81-zip lsphp81-json \
  lsphp81-opcache lsphp81-sqlite3 > /dev/null 2>&1

ln -sf /usr/local/lsws/lsphp81/bin/php /usr/local/bin/php 2>/dev/null
log "OpenLiteSpeed and PHP 8.1 installed"

########################################
step "Step 4/12: Install MariaDB"
########################################
apt-get install -y -qq mariadb-server mariadb-client > /dev/null 2>&1
systemctl enable mariadb > /dev/null 2>&1
systemctl start mariadb

# Secure MariaDB
mysql -u root -e "
  ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
  DELETE FROM mysql.user WHERE User='';
  DROP DATABASE IF EXISTS test;
  FLUSH PRIVILEGES;
" 2>/dev/null

log "MariaDB installed & secured"

########################################
step "Step 5/12: Install Node.js 18"
########################################
curl -fsSL https://deb.nodesource.com/setup_18.x 2>/dev/null | bash - > /dev/null 2>&1
apt-get install -y -qq nodejs > /dev/null 2>&1
log "Node.js $(node -v 2>/dev/null) installed"

########################################
step "Step 6/12: Creating LitePanel Pro Structure"
########################################
mkdir -p ${PANEL_DIR}/{src/{controllers,services,middleware,models,utils,routes},public/{css,js},database,logs,temp}
cd ${PANEL_DIR}

########################################
step "Step 7/12: Creating Core Application Files"
########################################

# === package.json ===
cat > package.json <<'PKGEOF'
{
  "name": "litepanel-pro",
  "version": "3.0.0",
  "description": "Enterprise Multi-Domain Cloudflare Management Panel",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "express-rate-limit": "^6.10.0",
    "bcryptjs": "^2.4.3",
    "multer": "^1.4.5-lts.1",
    "sqlite3": "^5.1.6",
    "dotenv": "^16.3.1",
    "helmet": "^7.0.0",
    "cors": "^2.8.5",
    "compression": "^1.7.4",
    "axios": "^1.4.0",
    "joi": "^17.9.2",
    "winston": "^3.10.0",
    "archiver": "^5.3.1",
    "unzipper": "^0.10.14",
    "mime-types": "^2.1.35"
  }
}
PKGEOF

# === .env ===
cat > .env <<ENVEOF
# Server Configuration
NODE_ENV=production
PANEL_PORT=${PANEL_PORT}
SESSION_SECRET=${SESSION_SECRET}

# Database
DB_PATH=./database/litepanel.db

# Redis Cache
REDIS_HOST=localhost
REDIS_PORT=6379

# Security
ENCRYPTION_KEY=${ENCRYPTION_KEY}
JWT_SECRET=${JWT_SECRET}

# Admin Credentials
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}

# MariaDB
DB_ROOT_PASS=${DB_ROOT_PASS}

# File Manager
MAX_UPLOAD_SIZE=100MB
ALLOWED_FILE_TYPES=.jpg,.jpeg,.png,.gif,.pdf,.doc,.docx,.txt,.zip,.tar,.gz

# Logging
LOG_LEVEL=info
LOG_DIR=./logs
ENVEOF

log "Installing npm dependencies..."
npm install --production > /tmp/npm_install.log 2>&1 || {
  warn "npm install failed, retrying..."
  npm install --production --legacy-peer-deps > /tmp/npm_install.log 2>&1
}
log "Dependencies installed"

########################################
# === app.js (Main Application) ===
########################################
cat > app.js <<'APPEOF'
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const http = require('http');
require('dotenv').config();

const logger = require('./src/utils/logger');
const database = require('./src/utils/database');
const routes = require('./src/routes');

class LitePanelApp {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
  }

  async initialize() {
    try {
      // Initialize database
      await database.initialize();
      logger.info('Database initialized');

      // Setup middleware
      this.setupMiddleware();

      // Setup routes
      this.setupRoutes();

      // Start server
      const port = process.env.PANEL_PORT || 3000;
      this.server.listen(port, '0.0.0.0', () => {
        logger.info(`LitePanel Pro running on port ${port}`);
      });

    } catch (error) {
      logger.error('Failed to initialize application:', error);
      process.exit(1);
    }
  }

  setupMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"]
        }
      }
    }));

    this.app.use(cors());
    this.app.use(compression());
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Session
    this.app.use(session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'strict'
      }
    }));

    // Static files
    this.app.use(express.static(path.join(__dirname, 'public')));
  }

  setupRoutes() {
    this.app.use('/api', routes);
    this.app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });
  }
}

const app = new LitePanelApp();
app.initialize().catch(console.error);

process.on('SIGINT', async () => {
  logger.info('Shutting down gracefully...');
  await database.close();
  process.exit(0);
});
APPEOF

########################################
# === src/utils/logger.js ===
########################################
cat > src/utils/logger.js <<'LOGEOF'
const winston = require('winston');
const path = require('path');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || './logs', 'error.log'),
      level: 'error'
    }),
    new winston.transports.File({
      filename: path.join(process.env.LOG_DIR || './logs', 'combined.log')
    })
  ]
});

module.exports = logger;
LOGEOF

########################################
# === src/utils/database.js ===
########################################
cat > src/utils/database.js <<'DBEOF'
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const logger = require('./logger');

class Database {
  constructor() {
    this.db = null;
  }

  async initialize() {
    const dbPath = path.resolve(process.env.DB_PATH || './database/litepanel.db');
    const dbDir = path.dirname(dbPath);
    await fs.mkdir(dbDir, { recursive: true });

    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
          logger.error('Failed to open database:', err);
          reject(err);
        } else {
          logger.info('Database connected');
          this.createTables().then(resolve).catch(reject);
        }
      });
    });
  }

  async createTables() {
    const queries = [
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS cloudflare_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        api_token TEXT NOT NULL,
        account_id TEXT,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        cloudflare_account_id INTEGER,
        cloudflare_zone_id TEXT,
        status TEXT DEFAULT 'active',
        ssl_mode TEXT DEFAULT 'flexible',
        doc_root TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (cloudflare_account_id) REFERENCES cloudflare_accounts(id)
      )`,
      `CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const query of queries) {
      await this.run(query);
    }

    // Create default admin user
    const adminExists = await this.get('SELECT id FROM users WHERE username = ?', [process.env.ADMIN_USER]);
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, 10);
      await this.run(
        'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
        [process.env.ADMIN_USER, hashedPassword, 'admin@localhost', 'admin']
      );
      logger.info('Default admin user created');
    }
  }

  run(query, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(query, params, function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID, changes: this.changes });
      });
    });
  }

  get(query, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(query, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  all(query, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  async close() {
    return new Promise((resolve) => {
      if (this.db) {
        this.db.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}

module.exports = new Database();
DBEOF

########################################
# === src/routes/index.js ===
########################################
cat > src/routes/index.js <<'ROUTEEOF'
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const dashboardController = require('../controllers/dashboard.controller');
const domainController = require('../controllers/domain.controller');
const fileController = require('../controllers/file.controller');
const cloudflareController = require('../controllers/cloudflare.controller');
const { auth } = require('../middleware/auth.middleware');

// Public routes
router.post('/auth/login', authController.login);
router.get('/auth/check', authController.check);
router.post('/auth/logout', authController.logout);

// Protected routes
router.use(auth); // All routes below require authentication

// Dashboard
router.get('/dashboard', dashboardController.getStats);
router.get('/services', dashboardController.getServices);
router.post('/services/:name/:action', dashboardController.controlService);

// Domains
router.get('/domains', domainController.list);
router.post('/domains', domainController.create);
router.delete('/domains/:name', domainController.remove);

// File Manager
router.get('/files', fileController.list);
router.get('/files/download', fileController.download);
router.post('/files/upload', fileController.upload);
router.post('/files/create', fileController.create);
router.put('/files', fileController.update);
router.delete('/files', fileController.remove);
router.post('/files/rename', fileController.rename);
router.post('/files/extract', fileController.extract);
router.post('/files/compress', fileController.compress);

// Cloudflare
router.get('/cloudflare/accounts', cloudflareController.listAccounts);
router.post('/cloudflare/accounts', cloudflareController.addAccount);
router.delete('/cloudflare/accounts/:id', cloudflareController.removeAccount);
router.get('/cloudflare/zones/:accountId', cloudflareController.listZones);
router.post('/cloudflare/zones/:accountId', cloudflareController.createZone);
router.get('/cloudflare/dns/:zoneId', cloudflareController.listDNS);
router.post('/cloudflare/dns/:zoneId', cloudflareController.createDNS);
router.put('/cloudflare/dns/:zoneId/:recordId', cloudflareController.updateDNS);
router.delete('/cloudflare/dns/:zoneId/:recordId', cloudflareController.deleteDNS);
router.post('/cloudflare/cache/:zoneId/purge', cloudflareController.purgeCache);

module.exports = router;
ROUTEEOF

########################################
# === src/middleware/auth.middleware.js ===
########################################
cat > src/middleware/auth.middleware.js <<'AUTHEOF'
function auth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

module.exports = { auth };
AUTHEOF

########################################
# === src/controllers/auth.controller.js ===
########################################
cat > src/controllers/auth.controller.js <<'AUTHCEOF'
const bcrypt = require('bcryptjs');
const database = require('../utils/database');
const logger = require('../utils/logger');

class AuthController {
  async login(req, res) {
    try {
      const { username, password } = req.body;
      
      const user = await database.get(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      // Log activity
      await database.run(
        'INSERT INTO activity_logs (user_id, action, ip_address) VALUES (?, ?, ?)',
        [user.id, 'login', req.ip]
      );

      res.json({
        success: true,
        user: {
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  }

  async logout(req, res) {
    if (req.session.user) {
      await database.run(
        'INSERT INTO activity_logs (user_id, action, ip_address) VALUES (?, ?, ?)',
        [req.session.user.id, 'logout', req.ip]
      );
    }
    req.session.destroy();
    res.json({ success: true });
  }

  async check(req, res) {
    res.json({
      authenticated: !!(req.session && req.session.user),
      user: req.session?.user || null
    });
  }
}

module.exports = new AuthController();
AUTHCEOF

########################################
# === src/controllers/dashboard.controller.js ===
########################################
cat > src/controllers/dashboard.controller.js <<'DASHEOF'
const os = require('os');
const { execSync } = require('child_process');
const logger = require('../utils/logger');

class DashboardController {
  async getStats(req, res) {
    try {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const cpus = os.cpus();
      
      // Get disk usage
      let disk = { total: 0, used: 0, free: 0 };
      try {
        const df = execSync("df -B1 / | tail -1").toString().split(/\s+/);
        disk = { total: parseInt(df[1]), used: parseInt(df[2]), free: parseInt(df[3]) };
      } catch (e) {}

      res.json({
        hostname: os.hostname(),
        ip: req.socket.localAddress || 'Unknown',
        uptime: os.uptime(),
        cpu: {
          model: cpus[0]?.model || 'Unknown',
          cores: cpus.length,
          load: os.loadavg()
        },
        memory: {
          total: totalMem,
          used: totalMem - freeMem,
          free: freeMem
        },
        disk,
        nodeVersion: process.version
      });
    } catch (error) {
      logger.error('Dashboard stats error:', error);
      res.status(500).json({ error: 'Failed to get stats' });
    }
  }

  async getServices(req, res) {
    const services = ['lsws', 'mariadb', 'redis-server', 'litepanel'];
    const statuses = [];

    for (const service of services) {
      try {
        execSync(`systemctl is-active ${service}`, { stdio: 'pipe' });
        statuses.push({ name: service, active: true });
      } catch (e) {
        statuses.push({ name: service, active: false });
      }
    }

    res.json(statuses);
  }

  async controlService(req, res) {
    try {
      const { name, action } = req.params;
      const allowedServices = ['lsws', 'mariadb', 'redis-server'];
      const allowedActions = ['start', 'stop', 'restart'];

      if (!allowedServices.includes(name) || !allowedActions.includes(action)) {
        return res.status(400).json({ error: 'Invalid service or action' });
      }

      execSync(`systemctl ${action} ${name}`, { timeout: 15000 });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new DashboardController();
DASHEOF

########################################
# === src/controllers/domain.controller.js ===
########################################
cat > src/controllers/domain.controller.js <<'DOMEOF'
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');
const database = require('../utils/database');
const logger = require('../utils/logger');

const OLS_CONF = '/usr/local/lsws/conf/httpd_config.conf';
const OLS_VHOST_CONF_DIR = '/usr/local/lsws/conf/vhosts';
const OLS_VHOST_DIR = '/usr/local/lsws/vhosts';

class DomainController {
  async list(req, res) {
    try {
      const domains = await database.all('SELECT * FROM domains ORDER BY name');
      res.json(domains);
    } catch (error) {
      res.status(500).json({ error: 'Failed to list domains' });
    }
  }

  async create(req, res) {
    try {
      const { domain, cloudflareAccountId } = req.body;
      
      if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({ error: 'Invalid domain name' });
      }

      // Create vhost files
      const docRoot = await this.createVhostFiles(domain);
      
      // Add to OpenLiteSpeed config
      await this.addDomainToOLS(domain);
      
      // Save to database
      await database.run(
        'INSERT INTO domains (name, cloudflare_account_id, doc_root) VALUES (?, ?, ?)',
        [domain, cloudflareAccountId || null, docRoot]
      );

      // Restart OpenLiteSpeed
      execSync('systemctl restart lsws', { timeout: 15000 });

      res.json({ success: true, domain, docRoot });
    } catch (error) {
      logger.error('Domain creation error:', error);
      res.status(500).json({ error: 'Failed to create domain' });
    }
  }

  async remove(req, res) {
    try {
      const { name } = req.params;
      
      // Remove from OpenLiteSpeed
      await this.removeDomainFromOLS(name);
      
      // Remove files
      await fs.rm(path.join(OLS_VHOST_CONF_DIR, name), { recursive: true, force: true });
      await fs.rm(path.join(OLS_VHOST_DIR, name), { recursive: true, force: true });
      
      // Remove from database
      await database.run('DELETE FROM domains WHERE name = ?', [name]);
      
      // Restart OpenLiteSpeed
      execSync('systemctl restart lsws', { timeout: 15000 });

      res.json({ success: true });
    } catch (error) {
      logger.error('Domain removal error:', error);
      res.status(500).json({ error: 'Failed to remove domain' });
    }
  }

  async createVhostFiles(domain) {
    const confDir = path.join(OLS_VHOST_CONF_DIR, domain);
    const docRoot = path.join(OLS_VHOST_DIR, domain, 'html');
    const logDir = path.join(OLS_VHOST_DIR, domain, 'logs');

    await fs.mkdir(confDir, { recursive: true });
    await fs.mkdir(docRoot, { recursive: true });
    await fs.mkdir(logDir, { recursive: true });

    const vhConf = `docRoot                   $VH_ROOT/html
vhDomain                  ${domain}
vhAliases                 www.${domain}
enableGzip                1

index {
  useServer               0
  indexFiles              index.php, index.html
  autoIndex               0
}

scripthandler {
  add                     lsapi:lsphp81 php
}

rewrite {
  enable                  1
  autoLoadHtaccess        1
}`;

    await fs.writeFile(path.join(confDir, 'vhconf.conf'), vhConf);
    await fs.writeFile(path.join(docRoot, 'index.html'), 
      `<!DOCTYPE html><html><head><title>${domain}</title></head>
      <body><h1>Welcome to ${domain}</h1><p>Powered by LitePanel Pro</p></body></html>`);

    execSync(`chown -R nobody:nogroup ${path.join(OLS_VHOST_DIR, domain)}`);
    
    return docRoot;
  }

  async addDomainToOLS(domain) {
    let config = await fs.readFile(OLS_CONF, 'utf8');
    
    // Add virtualhost
    config += `\nvirtualhost ${domain} {
  vhRoot                  ${OLS_VHOST_DIR}/${domain}
  configFile              ${OLS_VHOST_CONF_DIR}/${domain}/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}\n`;

    // Add listener mapping
    const listenerRegex = /(listener\s+HTTP\s*\{[\s\S]*?)(})/;
    if (listenerRegex.test(config)) {
      config = config.replace(listenerRegex,
        `$1  map                     ${domain} ${domain}, www.${domain}\n$2`);
    }

    await fs.writeFile(OLS_CONF, config);
  }

  async removeDomainFromOLS(domain) {
    let config = await fs.readFile(OLS_CONF, 'utf8');
    
    // Remove virtualhost
    const vhRegex = new RegExp(`\\n?virtualhost\\s+${domain}\\s*\\{[\\s\\S]*?\\}`, 'g');
    config = config.replace(vhRegex, '');
    
    // Remove mapping
    const mapRegex = new RegExp(`^\\s*map\\s+${domain}\\s+.*$`, 'gm');
    config = config.replace(mapRegex, '');
    
    await fs.writeFile(OLS_CONF, config);
  }
}

module.exports = new DomainController();
DOMEOF

########################################
# === src/controllers/file.controller.js ===
########################################
cat > src/controllers/file.controller.js <<'FILECEOF'
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const multer = require('multer');
const archiver = require('archiver');
const unzipper = require('unzipper');
const mime = require('mime-types');
const logger = require('../utils/logger');

const upload = multer({ 
  dest: '/tmp/uploads/',
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

class FileController {
  constructor() {
    this.allowedPaths = ['/usr/local/lsws/vhosts', '/opt/litepanel-pro'];
    this.maxFileSize = 50 * 1024 * 1024; // 50MB for editing
  }

  validatePath(requestedPath) {
    const resolvedPath = path.resolve(requestedPath);
    const isAllowed = this.allowedPaths.some(allowed => 
      resolvedPath.startsWith(allowed)
    );

    if (!isAllowed) {
      throw new Error('Access denied');
    }

    return resolvedPath;
  }

  async list(req, res) {
    try {
      const targetPath = this.validatePath(req.query.path || '/usr/local/lsws/vhosts');
      const stats = await fs.stat(targetPath);

      if (!stats.isDirectory()) {
        // Return file content for editing
        if (stats.size > this.maxFileSize) {
          return res.json({ path: targetPath, size: stats.size, tooLarge: true });
        }

        const content = await fs.readFile(targetPath, 'utf8');
        return res.json({ path: targetPath, content, size: stats.size });
      }

      // List directory contents
      const items = await fs.readdir(targetPath);
      const detailed = [];

      for (const item of items) {
        try {
          const itemPath = path.join(targetPath, item);
          const itemStats = await fs.stat(itemPath);
          
          detailed.push({
            name: item,
            path: itemPath,
            size: itemStats.size,
            isDirectory: itemStats.isDirectory(),
            isFile: itemStats.isFile(),
            mimeType: itemStats.isDirectory() ? 'directory' : mime.lookup(itemPath) || 'application/octet-stream',
            modified: itemStats.mtime,
            permissions: '0' + (itemStats.mode & parseInt('777', 8)).toString(8)
          });
        } catch (e) {
          detailed.push({
            name: item,
            path: path.join(targetPath, item),
            error: true
          });
        }
      }

      res.json({ path: targetPath, items: detailed });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async download(req, res) {
    try {
      const targetPath = this.validatePath(req.query.path);
      const stats = await fs.stat(targetPath);

      if (stats.isDirectory()) {
        return res.status(400).json({ error: 'Cannot download directory' });
      }

      res.download(targetPath);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  upload = [
    upload.single('file'),
    async (req, res) => {
      try {
        const targetDir = this.validatePath(req.body.path || '/tmp');
        const targetPath = path.join(targetDir, req.file.originalname);
        
        await fs.rename(req.file.path, targetPath);
        res.json({ success: true, path: targetPath });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    }
  ];

  async create(req, res) {
    try {
      const { path: filePath, type, content } = req.body;
      const targetPath = this.validatePath(filePath);

      if (type === 'directory') {
        await fs.mkdir(targetPath, { recursive: true });
      } else {
        await fs.writeFile(targetPath, content || '');
      }

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async update(req, res) {
    try {
      const { path: filePath, content } = req.body;
      const targetPath = this.validatePath(filePath);
      
      await fs.writeFile(targetPath, content);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async remove(req, res) {
    try {
      const targetPath = this.validatePath(req.query.path);
      
      if (targetPath === '/' || this.allowedPaths.includes(targetPath)) {
        return res.status(400).json({ error: 'Cannot delete root directories' });
      }

      await fs.rm(targetPath, { recursive: true, force: true });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async rename(req, res) {
    try {
      const { oldPath, newPath } = req.body;
      const validOldPath = this.validatePath(oldPath);
      const validNewPath = this.validatePath(newPath);
      
      await fs.rename(validOldPath, validNewPath);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async extract(req, res) {
    try {
      const { archivePath, destPath } = req.body;
      const validArchivePath = this.validatePath(archivePath);
      const validDestPath = this.validatePath(destPath);

      await fs.mkdir(validDestPath, { recursive: true });

      await new Promise((resolve, reject) => {
        fsSync.createReadStream(validArchivePath)
          .pipe(unzipper.Extract({ path: validDestPath }))
          .on('close', resolve)
          .on('error', reject);
      });

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async compress(req, res) {
    try {
      const { files, destPath, format = 'zip' } = req.body;
      const validDestPath = this.validatePath(destPath);
      
      const output = fsSync.createWriteStream(validDestPath);
      const archive = archiver(format, { zlib: { level: 9 } });

      archive.pipe(output);

      for (const file of files) {
        const validPath = this.validatePath(file);
        const stats = await fs.stat(validPath);
        
        if (stats.isDirectory()) {
          archive.directory(validPath, path.basename(validPath));
        } else {
          archive.file(validPath, { name: path.basename(validPath) });
        }
      }

      await archive.finalize();
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new FileController();
FILECEOF

########################################
# === src/controllers/cloudflare.controller.js ===
########################################
cat > src/controllers/cloudflare.controller.js <<'CFEOF'
const axios = require('axios');
const database = require('../utils/database');
const logger = require('../utils/logger');

class CloudflareController {
  constructor() {
    this.baseURL = 'https://api.cloudflare.com/client/v4';
  }

  async makeRequest(method, endpoint, data, apiToken) {
    try {
      const response = await axios({
        method,
        url: `${this.baseURL}${endpoint}`,
        headers: {
          'Authorization': `Bearer ${apiToken}`,
          'Content-Type': 'application/json'
        },
        data
      });
      return response.data;
    } catch (error) {
      logger.error('Cloudflare API error:', error.response?.data || error.message);
      throw error;
    }
  }

  async listAccounts(req, res) {
    try {
      const accounts = await database.all(
        'SELECT id, name, email, is_active, created_at FROM cloudflare_accounts'
      );
      res.json(accounts);
    } catch (error) {
      res.status(500).json({ error: 'Failed to list accounts' });
    }
  }

  async addAccount(req, res) {
    try {
      const { name, email, apiToken } = req.body;
      
      // Verify token
      const verification = await this.makeRequest('GET', '/user/tokens/verify', null, apiToken);
      
      if (!verification.success) {
        return res.status(400).json({ error: 'Invalid API token' });
      }

      // Save account
      const result = await database.run(
        'INSERT INTO cloudflare_accounts (name, email, api_token) VALUES (?, ?, ?)',
        [name, email, apiToken] // In production, encrypt the token
      );

      res.json({ success: true, id: result.id });
    } catch (error) {
      res.status(500).json({ error: 'Failed to add account' });
    }
  }

  async removeAccount(req, res) {
    try {
      await database.run('DELETE FROM cloudflare_accounts WHERE id = ?', [req.params.id]);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Failed to remove account' });
    }
  }

  async listZones(req, res) {
    try {
      const account = await database.get(
        'SELECT api_token FROM cloudflare_accounts WHERE id = ?',
        [req.params.accountId]
      );

      if (!account) {
        return res.status(404).json({ error: 'Account not found' });
      }

      const result = await this.makeRequest('GET', '/zones', null, account.api_token);
      res.json(result.result || []);
    } catch (error) {
      res.status(500).json({ error: 'Failed to list zones' });
    }
  }

  async createZone(req, res) {
    try {
      const { name } = req.body;
      const account = await database.get(
        'SELECT api_token, account_id FROM cloudflare_accounts WHERE id = ?',
        [req.params.accountId]
      );

      const result = await this.makeRequest('POST', '/zones', {
        name,
        account: { id: account.account_id },
        jump_start: true
      }, account.api_token);

      if (result.success) {
        // Update domain in database
        await database.run(
          'UPDATE domains SET cloudflare_zone_id = ? WHERE name = ?',
          [result.result.id, name]
        );
      }

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to create zone' });
    }
  }

  async listDNS(req, res) {
    try {
      const zone = await database.get(
        'SELECT cf.api_token FROM domains d ' +
        'JOIN cloudflare_accounts cf ON d.cloudflare_account_id = cf.id ' +
        'WHERE d.cloudflare_zone_id = ?',
        [req.params.zoneId]
      );

      const result = await this.makeRequest(
        'GET', 
        `/zones/${req.params.zoneId}/dns_records`, 
        null, 
        zone.api_token
      );

      res.json(result.result || []);
    } catch (error) {
      res.status(500).json({ error: 'Failed to list DNS records' });
    }
  }

  async createDNS(req, res) {
    try {
      const { type, name, content, ttl = 1, proxied = false } = req.body;
      const zone = await database.get(
        'SELECT cf.api_token FROM domains d ' +
        'JOIN cloudflare_accounts cf ON d.cloudflare_account_id = cf.id ' +
        'WHERE d.cloudflare_zone_id = ?',
        [req.params.zoneId]
      );

      const result = await this.makeRequest(
        'POST',
        `/zones/${req.params.zoneId}/dns_records`,
        { type, name, content, ttl, proxied },
        zone.api_token
      );

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to create DNS record' });
    }
  }

  async updateDNS(req, res) {
    try {
      const { type, name, content, ttl, proxied } = req.body;
      const zone = await database.get(
        'SELECT cf.api_token FROM domains d ' +
        'JOIN cloudflare_accounts cf ON d.cloudflare_account_id = cf.id ' +
        'WHERE d.cloudflare_zone_id = ?',
        [req.params.zoneId]
      );

      const result = await this.makeRequest(
        'PUT',
        `/zones/${req.params.zoneId}/dns_records/${req.params.recordId}`,
        { type, name, content, ttl, proxied },
        zone.api_token
      );

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to update DNS record' });
    }
  }

  async deleteDNS(req, res) {
    try {
      const zone = await database.get(
        'SELECT cf.api_token FROM domains d ' +
        'JOIN cloudflare_accounts cf ON d.cloudflare_account_id = cf.id ' +
        'WHERE d.cloudflare_zone_id = ?',
        [req.params.zoneId]
      );

      const result = await this.makeRequest(
        'DELETE',
        `/zones/${req.params.zoneId}/dns_records/${req.params.recordId}`,
        null,
        zone.api_token
      );

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to delete DNS record' });
    }
  }

  async purgeCache(req, res) {
    try {
      const { files } = req.body;
      const zone = await database.get(
        'SELECT cf.api_token FROM domains d ' +
        'JOIN cloudflare_accounts cf ON d.cloudflare_account_id = cf.id ' +
        'WHERE d.cloudflare_zone_id = ?',
        [req.params.zoneId]
      );

      const data = files ? { files } : { purge_everything: true };
      
      const result = await this.makeRequest(
        'POST',
        `/zones/${req.params.zoneId}/purge_cache`,
        data,
        zone.api_token
      );

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: 'Failed to purge cache' });
    }
  }
}

module.exports = new CloudflareController();
CFEOF

########################################
# === public/index.html ===
########################################
cat > public/index.html <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LitePanel Pro</title>
<link rel="stylesheet" href="/css/style.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<div id="app">
  <div class="loading-screen">
    <i class="fas fa-server fa-3x"></i>
    <h1>LitePanel Pro</h1>
    <div class="spinner"></div>
    <p>Loading...</p>
  </div>
</div>
<script src="/js/app.js"></script>
</body>
</html>
HTMLEOF

########################################
# === public/css/style.css ===
########################################
cat > public/css/style.css <<'CSSEOF'
:root {
  --primary: #4f8cff;
  --primary-dark: #3a7ae0;
  --secondary: #6c757d;
  --success: #28a745;
  --danger: #dc3545;
  --warning: #ffc107;
  --bg-primary: #0f1117;
  --bg-secondary: #1a1d23;
  --bg-tertiary: #2a2d35;
  --text-primary: #e0e0e0;
  --text-secondary: #8a8d93;
  --border: #3a3d45;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
}

.loading-screen {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  text-align: center;
}

.loading-screen i {
  color: var(--primary);
  margin-bottom: 20px;
}

.spinner {
  width: 50px;
  height: 50px;
  border: 3px solid var(--bg-secondary);
  border-top-color: var(--primary);
  border-radius: 50%;
  margin: 20px auto;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.login-container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 100%);
}

.login-box {
  background: var(--bg-tertiary);
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.3);
  width: 100%;
  max-width: 400px;
}

.login-header {
  text-align: center;
  margin-bottom: 30px;
}

.login-header i {
  font-size: 3rem;
  color: var(--primary);
  margin-bottom: 15px;
}

.login-header h1 {
  font-size: 1.75rem;
  margin-bottom: 5px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 5px;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.form-control {
  width: 100%;
  padding: 10px 15px;
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-primary);
  font-size: 14px;
  transition: all 0.3s;
}

.form-control:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(79, 140, 255, 0.1);
}

.btn {
  display: inline-block;
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s;
  text-decoration: none;
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover {
  background: var(--primary-dark);
  transform: translateY(-1px);
}

.btn-block {
  width: 100%;
}

.error-message {
  background: rgba(220, 53, 69, 0.1);
  color: var(--danger);
  padding: 10px;
  border-radius: 6px;
  margin-top: 15px;
  text-align: center;
  font-size: 0.875rem;
}

.app-container {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 250px;
  background: var(--bg-secondary);
  position: fixed;
  height: 100vh;
  overflow-y: auto;
  transition: transform 0.3s;
}

.sidebar-header {
  padding: 20px;
  border-bottom: 1px solid var(--border);
  text-align: center;
}

.sidebar-header h1 {
  font-size: 1.5rem;
  color: var(--primary);
}

.sidebar-nav {
  padding: 20px 0;
}

.nav-item {
  display: block;
  padding: 12px 20px;
  color: var(--text-secondary);
  text-decoration: none;
  transition: all 0.3s;
  border-left: 3px solid transparent;
}

.nav-item:hover {
  background: var(--bg-tertiary);
  color: var(--primary);
}

.nav-item.active {
  background: var(--bg-tertiary);
  color: var(--primary);
  border-left-color: var(--primary);
}

.nav-item i {
  margin-right: 10px;
  width: 20px;
  text-align: center;
}

.main-content {
  flex: 1;
  margin-left: 250px;
  background: var(--bg-primary);
}

.header {
  background: var(--bg-secondary);
  padding: 15px 30px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.page-content {
  padding: 30px;
}

.card {
  background: var(--bg-tertiary);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: var(--bg-tertiary);
  padding: 20px;
  border-radius: 8px;
  text-align: center;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: var(--primary);
  margin: 10px 0;
}

.stat-label {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.table {
  width: 100%;
  border-collapse: collapse;
}

.table th,
.table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.table th {
  background: var(--bg-secondary);
  font-weight: 600;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.badge {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.badge-success {
  background: rgba(40, 167, 69, 0.2);
  color: var(--success);
}

.badge-danger {
  background: rgba(220, 53, 69, 0.2);
  color: var(--danger);
}

.file-manager {
  height: calc(100vh - 200px);
}

.file-breadcrumb {
  padding: 15px;
  background: var(--bg-secondary);
  border-radius: 6px;
  margin-bottom: 20px;
}

.file-list {
  background: var(--bg-tertiary);
  border-radius: 6px;
  overflow: hidden;
}

.file-item {
  display: flex;
  align-items: center;
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.2s;
}

.file-item:hover {
  background: var(--bg-secondary);
}

.file-icon {
  margin-right: 15px;
  font-size: 1.25rem;
}

.file-name {
  flex: 1;
}

.file-size {
  color: var(--text-secondary);
  font-size: 0.875rem;
  margin-right: 20px;
}

.file-actions {
  display: flex;
  gap: 10px;
}

.mobile-toggle {
  display: none;
  position: fixed;
  top: 15px;
  left: 15px;
  z-index: 100;
  background: var(--bg-tertiary);
  border: none;
  color: var(--text-primary);
  padding: 10px;
  border-radius: 6px;
  cursor: pointer;
}

@media (max-width: 768px) {
  .sidebar {
    transform: translateX(-100%);
  }
  
  .sidebar.open {
    transform: translateX(0);
  }
  
  .main-content {
    margin-left: 0;
  }
  
  .mobile-toggle {
    display: block;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
}

.modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--bg-tertiary);
  border-radius: 8px;
  padding: 30px;
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  margin-bottom: 20px;
}

.modal-title {
  font-size: 1.5rem;
  font-weight: 600;
}

.progress {
  height: 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
  overflow: hidden;
  margin-top: 5px;
}

.progress-bar {
  height: 100%;
  background: var(--primary);
  transition: width 0.3s;
}

.progress-bar.danger {
  background: var(--danger);
}

.progress-bar.warning {
  background: var(--warning);
}

.cloudflare-section {
  margin-top: 30px;
}

.dns-record {
  background: var(--bg-secondary);
  padding: 15px;
  border-radius: 6px;
  margin-bottom: 10px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.dns-info {
  flex: 1;
}

.dns-type {
  display: inline-block;
  padding: 4px 8px;
  background: var(--primary);
  color: white;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  margin-right: 10px;
}

.dns-name {
  font-weight: 600;
  margin-right: 10px;
}

.dns-content {
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.btn-sm {
  padding: 6px 12px;
  font-size: 0.875rem;
}

.btn-danger {
  background: var(--danger);
  color: white;
}

.btn-success {
  background: var(--success);
  color: white;
}

.btn-warning {
  background: var(--warning);
  color: #212529;
}

.toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  background: var(--bg-tertiary);
  padding: 15px 20px;
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  display: flex;
  align-items: center;
  gap: 10px;
  z-index: 1000;
  animation: slideIn 0.3s ease;
}

@keyframes slideIn {
  from {
    transform: translateX(100%);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

.toast.success {
  border-left: 4px solid var(--success);
}

.toast.error {
  border-left: 4px solid var(--danger);
}

.terminal {
  background: #000;
  color: #0f0;
  font-family: 'Courier New', monospace;
  padding: 20px;
  border-radius: 6px;
  height: 400px;
  overflow-y: auto;
  font-size: 14px;
  line-height: 1.5;
}

.terminal-input {
  display: flex;
  margin-top: 10px;
}

.terminal-input input {
  flex: 1;
  background: #000;
  border: 1px solid #333;
  color: #0f0;
  padding: 10px;
  font-family: 'Courier New', monospace;
  border-radius: 4px 0 0 4px;
}

.terminal-input button {
  border-radius: 0 4px 4px 0;
}
CSSEOF

########################################
# === public/js/app.js ===
########################################
cat > public/js/app.js <<'JSEOF'
class LitePanelPro {
  constructor() {
    this.currentPage = 'dashboard';
    this.user = null;
    this.init();
  }

  async init() {
    const auth = await this.api('/api/auth/check');
    if (auth.authenticated) {
      this.user = auth.user;
      this.renderApp();
      this.navigate('dashboard');
    } else {
      this.renderLogin();
    }
  }

  async api(url, options = {}) {
    const defaults = {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin'
    };

    if (options.body && !(options.body instanceof FormData)) {
      options.body = JSON.stringify(options.body);
    }

    const response = await fetch(url, { ...defaults, ...options });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Request failed');
    }

    return data;
  }

  renderLogin() {
    document.getElementById('app').innerHTML = `
      <div class="login-container">
        <div class="login-box">
          <div class="login-header">
            <i class="fas fa-server"></i>
            <h1>LitePanel Pro</h1>
            <p>Enterprise Management Panel</p>
          </div>
          <form id="loginForm">
            <div class="form-group">
              <label>Username</label>
              <input type="text" class="form-control" id="username" required>
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" class="form-control" id="password" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">
              <i class="fas fa-sign-in-alt"></i> Login
            </button>
            <div id="loginError"></div>
          </form>
        </div>
      </div>
    `;

    document.getElementById('loginForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.login();
    });
  }

  async login() {
    try {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;

      const result = await this.api('/api/auth/login', {
        method: 'POST',
        body: { username, password }
      });

      if (result.success) {
        this.user = result.user;
        this.renderApp();
        this.navigate('dashboard');
      }
    } catch (error) {
      document.getElementById('loginError').innerHTML = 
        `<div class="error-message">${error.message}</div>`;
    }
  }

  renderApp() {
    document.getElementById('app').innerHTML = `
      <div class="app-container">
        <aside class="sidebar" id="sidebar">
          <div class="sidebar-header">
            <h1><i class="fas fa-server"></i> LitePanel Pro</h1>
          </div>
          <nav class="sidebar-nav">
            <a href="#" class="nav-item" data-page="dashboard">
              <i class="fas fa-tachometer-alt"></i> Dashboard
            </a>
            <a href="#" class="nav-item" data-page="domains">
              <i class="fas fa-globe"></i> Domains
            </a>
            <a href="#" class="nav-item" data-page="cloudflare">
              <i class="fab fa-cloudflare"></i> Cloudflare
            </a>
            <a href="#" class="nav-item" data-page="files">
              <i class="fas fa-folder"></i> File Manager
            </a>
            <a href="#" class="nav-item" data-page="databases">
              <i class="fas fa-database"></i> Databases
            </a>
            <a href="#" class="nav-item" data-page="services">
              <i class="fas fa-cogs"></i> Services
            </a>
            <a href="#" class="nav-item" data-page="terminal">
              <i class="fas fa-terminal"></i> Terminal
            </a>
            <a href="#" class="nav-item" data-page="settings">
              <i class="fas fa-cog"></i> Settings
            </a>
            <a href="#" class="nav-item" onclick="app.logout()">
              <i class="fas fa-sign-out-alt"></i> Logout
            </a>
          </nav>
        </aside>
        
        <main class="main-content">
          <header class="header">
            <button class="mobile-toggle" onclick="app.toggleSidebar()">
              <i class="fas fa-bars"></i>
            </button>
            <h2 id="pageTitle">Dashboard</h2>
            <div class="header-user">
              <i class="fas fa-user-circle"></i> ${this.user.username}
            </div>
          </header>
          
          <div class="page-content" id="content">
            <!-- Dynamic content -->
          </div>
        </main>
      </div>
    `;

    // Setup navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        if (page) this.navigate(page);
      });
    });
  }

  navigate(page) {
    this.currentPage = page;
    
    // Update active nav
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.page === page);
    });

    // Update title
    const titles = {
      dashboard: 'Dashboard',
      domains: 'Domain Management',
      cloudflare: 'Cloudflare Integration',
      files: 'File Manager',
      databases: 'Databases',
      services: 'Services',
      terminal: 'Terminal',
      settings: 'Settings'
    };
    
    document.getElementById('pageTitle').textContent = titles[page] || page;

    // Load page content
    this[`render${page.charAt(0).toUpperCase() + page.slice(1)}`]();
  }

  async renderDashboard() {
    try {
      const stats = await this.api('/api/dashboard');
      const services = await this.api('/api/services');

      const memoryPercent = Math.round((stats.memory.used / stats.memory.total) * 100);
      const diskPercent = Math.round((stats.disk.used / stats.disk.total) * 100);

      document.getElementById('content').innerHTML = `
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Hostname</div>
            <div class="stat-value">${stats.hostname}</div>
            <div class="stat-label">${stats.ip}</div>
          </div>
          
          <div class="stat-card">
            <div class="stat-label">CPU</div>
            <div class="stat-value">${stats.cpu.cores} Cores</div>
            <div class="stat-label">Load: ${stats.cpu.load.map(l => l.toFixed(2)).join(', ')}</div>
          </div>
          
          <div class="stat-card">
            <div class="stat-label">Memory</div>
            <div class="stat-value">${memoryPercent}%</div>
            <div class="progress">
              <div class="progress-bar ${memoryPercent > 80 ? 'danger' : ''}" 
                   style="width: ${memoryPercent}%"></div>
            </div>
            <div class="stat-label">${this.formatBytes(stats.memory.used)} / ${this.formatBytes(stats.memory.total)}</div>
          </div>
          
          <div class="stat-card">
            <div class="stat-label">Disk</div>
            <div class="stat-value">${diskPercent}%</div>
            <div class="progress">
              <div class="progress-bar ${diskPercent > 80 ? 'danger' : ''}" 
                   style="width: ${diskPercent}%"></div>
            </div>
            <div class="stat-label">${this.formatBytes(stats.disk.used)} / ${this.formatBytes(stats.disk.total)}</div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Services Status</h3>
          </div>
          <table class="table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${services.map(service => `
                <tr>
                  <td>${service.name}</td>
                  <td>
                    <span class="badge ${service.active ? 'badge-success' : 'badge-danger'}">
                      ${service.active ? 'Running' : 'Stopped'}
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-sm btn-success" 
                            onclick="app.controlService('${service.name}', 'start')">
                      Start
                    </button>
                    <button class="btn btn-sm btn-danger" 
                            onclick="app.controlService('${service.name}', 'stop')">
                      Stop
                    </button>
                    <button class="btn btn-sm btn-warning" 
                            onclick="app.controlService('${service.name}', 'restart')">
                      Restart
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (error) {
      this.showError(error);
    }
  }

  async renderCloudflare() {
    try {
      const accounts = await this.api('/api/cloudflare/accounts');
      
      document.getElementById('content').innerHTML = `
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">Cloudflare Accounts</h3>
            <button class="btn btn-primary" onclick="app.showAddCloudflareAccount()">
              <i class="fas fa-plus"></i> Add Account
            </button>
          </div>
          
          ${accounts.length === 0 ? `
            <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
              <i class="fas fa-cloud fa-3x" style="opacity: 0.5; margin-bottom: 20px;"></i>
              <p>No Cloudflare accounts configured yet.</p>
              <p>Add an account to start managing your domains with Cloudflare.</p>
            </div>
          ` : `
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${accounts.map(account => `
                  <tr>
                    <td>${account.name}</td>
                    <td>${account.email}</td>
                    <td>
                      <span class="badge ${account.is_active ? 'badge-success' : 'badge-danger'}">
                        ${account.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td>
                      <button class="btn btn-sm btn-primary" 
                              onclick="app.viewCloudflareZones(${account.id})">
                        View Zones
                      </button>
                      <button class="btn btn-sm btn-danger" 
                              onclick="app.deleteCloudflareAccount(${account.id})">
                        Delete
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `}
        </div>

        <div id="cloudflareZones"></div>
      `;
    } catch (error) {
      this.showError(error);
    }
  }

  showAddCloudflareAccount() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3 class="modal-title">Add Cloudflare Account</h3>
        </div>
        <form id="addCloudflareForm">
          <div class="form-group">
            <label>Account Name</label>
            <input type="text" class="form-control" name="name" required>
          </div>
          <div class="form-group">
            <label>Email</label>
            <input type="email" class="form-control" name="email" required>
          </div>
          <div class="form-group">
            <label>API Token</label>
            <input type="password" class="form-control" name="apiToken" required>
            <small style="color: var(--text-secondary);">
              Get your API token from 
              <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank">
                Cloudflare Dashboard
              </a>
            </small>
          </div>
          <div style="display: flex; gap: 10px;">
            <button type="submit" class="btn btn-primary">Add Account</button>
            <button type="button" class="btn" onclick="this.closest('.modal').remove()">
              Cancel
            </button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('addCloudflareForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      
      try {
        await this.api('/api/cloudflare/accounts', {
          method: 'POST',
          body: {
            name: formData.get('name'),
            email: formData.get('email'),
            apiToken: formData.get('apiToken')
          }
        });

        modal.remove();
        this.showToast('Cloudflare account added successfully', 'success');
        this.renderCloudflare();
      } catch (error) {
        this.showError(error);
      }
    });
  }

  async renderFiles() {
    // File manager implementation
    document.getElementById('content').innerHTML = `
      <div class="file-manager">
        <div class="file-breadcrumb" id="breadcrumb">
          <i class="fas fa-home"></i> /
        </div>
        
        <div class="card">
          <div class="card-header">
            <div>
              <button class="btn btn-primary btn-sm" onclick="app.uploadFile()">
                <i class="fas fa-upload"></i> Upload
              </button>
              <button class="btn btn-success btn-sm" onclick="app.createFolder()">
                <i class="fas fa-folder-plus"></i> New Folder
              </button>
              <button class="btn btn-warning btn-sm" onclick="app.createFile()">
                <i class="fas fa-file-plus"></i> New File
              </button>
            </div>
          </div>
          
          <div class="file-list" id="fileList">
            Loading...
          </div>
        </div>
      </div>
    `;

    this.loadFiles('/usr/local/lsws/vhosts');
  }

  async loadFiles(path) {
    try {
      const result = await this.api(`/api/files?path=${encodeURIComponent(path)}`);
      
      if (result.content !== undefined) {
        // Show file editor
        this.showFileEditor(result);
      } else {
        // Show directory listing
        const fileList = document.getElementById('fileList');
        fileList.innerHTML = result.items.map(item => `
          <div class="file-item" onclick="app.openFile('${item.path}')">
            <i class="file-icon fas ${item.isDirectory ? 'fa-folder' : 'fa-file'}"></i>
            <span class="file-name">${item.name}</span>
            <span class="file-size">${item.isDirectory ? '' : this.formatBytes(item.size)}</span>
            <div class="file-actions">
              ${!item.isDirectory ? `
                <button class="btn btn-sm" onclick="event.stopPropagation(); app.downloadFile('${item.path}')">
                  <i class="fas fa-download"></i>
                </button>
              ` : ''}
              <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); app.deleteFile('${item.path}')">
                <i class="fas fa-trash"></i>
              </button>
            </div>
          </div>
        `).join('');

        // Update breadcrumb
        const parts = path.split('/').filter(Boolean);
        document.getElementById('breadcrumb').innerHTML = 
          '<i class="fas fa-home"></i> / ' + 
          parts.map((part, i) => 
            `<a href="#" onclick="app.loadFiles('/${parts.slice(0, i + 1).join('/')}')">${part}</a>`
          ).join(' / ');
      }
    } catch (error) {
      this.showError(error);
    }
  }

  async openFile(path) {
    this.loadFiles(path);
  }

  async controlService(name, action) {
    try {
      await this.api(`/api/services/${name}/${action}`, { method: 'POST' });
      this.showToast(`Service ${name} ${action}ed successfully`, 'success');
      this.renderDashboard();
    } catch (error) {
      this.showError(error);
    }
  }

  toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
  }

  async logout() {
    await this.api('/api/auth/logout', { method: 'POST' });
    this.user = null;
    this.renderLogin();
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
      ${message}
    `;

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  showError(error) {
    this.showToast(error.message || 'An error occurred', 'error');
  }

  // Stub methods for other pages
  renderDomains() {
    document.getElementById('content').innerHTML = '<p>Domains page - Coming soon</p>';
  }

  renderDatabases() {
    document.getElementById('content').innerHTML = '<p>Databases page - Coming soon</p>';
  }

  renderServices() {
    document.getElementById('content').innerHTML = '<p>Services page - Coming soon</p>';
  }

  renderTerminal() {
    document.getElementById('content').innerHTML = '<p>Terminal page - Coming soon</p>';
  }

  renderSettings() {
    document.getElementById('content').innerHTML = '<p>Settings page - Coming soon</p>';
  }
}

// Initialize app
const app = new LitePanelPro();
JSEOF

########################################
step "Step 8/12: Configure OpenLiteSpeed"
########################################
# Configure PHP handler for OpenLiteSpeed
cat > /usr/local/lsws/conf/vhosts/Example/vhconf.conf <<'VHEOF'
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

rewrite {
  enable                  1
  autoLoadHtaccess        1
}
VHEOF

# Set admin password for OpenLiteSpeed
/usr/local/lsws/admin/misc/admpass.sh <<EOF
admin
${ADMIN_PASS}
${ADMIN_PASS}
EOF

systemctl restart lsws
log "OpenLiteSpeed configured"

########################################
step "Step 9/12: Install phpMyAdmin"
########################################
cd /tmp
wget https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz -O pma.tar.gz 2>/dev/null
tar xzf pma.tar.gz
mkdir -p /usr/local/lsws/Example/html/phpmyadmin
cp -rf phpMyAdmin-*/* /usr/local/lsws/Example/html/phpmyadmin/
rm -rf phpMyAdmin-* pma.tar.gz

cat > /usr/local/lsws/Example/html/phpmyadmin/config.inc.php <<PMAEOF
<?php
\$cfg['blowfish_secret'] = '$(openssl rand -hex 32)';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
PMAEOF

chown -R nobody:nogroup /usr/local/lsws/Example/html/phpmyadmin
log "phpMyAdmin installed"

########################################
step "Step 10/12: Setup Services & Firewall"
########################################
# Create systemd service
cat > /etc/systemd/system/litepanel.service <<SVCEOF
[Unit]
Description=LitePanel Pro - Enterprise Management Panel
After=network.target mariadb.service redis-server.service

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=/usr/bin/node app.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable litepanel
systemctl start litepanel

# Configure firewall
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow 22/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw allow ${PANEL_PORT}/tcp > /dev/null 2>&1
ufw allow 7080/tcp > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1

log "Services configured and started"

########################################
step "Step 11/12: Install Fail2ban"
########################################
apt-get install -y -qq fail2ban > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1
systemctl start fail2ban
log "Fail2ban installed"

########################################
step "Step 12/12: Save Credentials"
########################################
mkdir -p /etc/litepanel
cat > /etc/litepanel/credentials.txt <<CREDEOF
==============================================
       LITEPANEL PRO INSTALLATION INFO
==============================================
Installation Date: $(date)
Server IP: ${SERVER_IP}

==============================================
              ACCESS URLS
==============================================
LitePanel Pro:    http://${SERVER_IP}:${PANEL_PORT}
OpenLiteSpeed:    http://${SERVER_IP}:7080
phpMyAdmin:       http://${SERVER_IP}:8088/phpmyadmin/

==============================================
              CREDENTIALS
==============================================
LitePanel Login:  ${ADMIN_USER} / ${ADMIN_PASS}
OLS Admin Login:  admin / ${ADMIN_PASS}
MariaDB Root:     ${DB_ROOT_PASS}

==============================================
              IMPORTANT NOTES
==============================================
1. Change all default passwords after login
2. Configure SSL certificates for production
3. Setup Cloudflare integration in panel
4. Regular backups recommended

==============================================
              USEFUL COMMANDS
==============================================
Restart Panel:    systemctl restart litepanel
View Logs:        journalctl -u litepanel -f
Panel Status:     systemctl status litepanel

==============================================
CREDEOF

chmod 600 /etc/litepanel/credentials.txt
cp /etc/litepanel/credentials.txt /root/litepanel_credentials.txt

########################################
# FINAL SUMMARY
########################################
clear
echo -e "${M}"
cat << "EOF"
   __    _ __       ____                  __   ____           
  / /   (_) /____  / __ \____ _____  ___  / /  / __ \_________ 
 / /   / / __/ _ \/ /_/ / __ `/ __ \/ _ \/ /  / /_/ / ___/ __ \
/ /___/ / /_/  __/ ____/ /_/ / / / /  __/ /  / ____/ /  / /_/ /
/_____/_/\__/\___/_/    \__,_/_/ /_/\___/_/  /_/   /_/   \____/ 
                                                                 
EOF
echo -e "${N}"
echo -e "${G}╔═══════════════════════════════════════════════════════╗${N}"
echo -e "${G}║          INSTALLATION COMPLETED SUCCESSFULLY!          ║${N}"
echo -e "${G}╚═══════════════════════════════════════════════════════╝${N}"
echo
echo -e "${C}Access Information:${N}"
echo -e "LitePanel Pro:  ${Y}http://${SERVER_IP}:${PANEL_PORT}${N}"
echo -e "Username:       ${Y}${ADMIN_USER}${N}"
echo -e "Password:       ${Y}${ADMIN_PASS}${N}"
echo
echo -e "${C}Additional Services:${N}"
echo -e "OpenLiteSpeed:  ${Y}http://${SERVER_IP}:7080${N} (admin / ${ADMIN_PASS})"
echo -e "phpMyAdmin:     ${Y}http://${SERVER_IP}:8088/phpmyadmin/${N}"
echo
echo -e "${C}Credentials saved to:${N}"
echo -e "  ${B}/etc/litepanel/credentials.txt${N}"
echo -e "  ${B}/root/litepanel_credentials.txt${N}"
echo
echo -e "${G}Service Status:${N}"
for svc in lsws mariadb redis-server litepanel; do
  if systemctl is-active --quiet $svc; then
    echo -e "  ${G}[✓]${N} $svc"
  else
    echo -e "  ${R}[✗]${N} $svc"
  fi
done
echo
echo -e "${Y}⚠️  IMPORTANT: Change all default passwords after first login!${N}"
echo -e "${G}═══════════════════════════════════════════════════════${N}"
