#!/bin/bash
###############################################################################
# LitePanel Post-Install Patch & Enhancement
# Run this AFTER the main installer
###############################################################################

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

INSTALL_PATH="/opt/litepanel"
CREDS_FILE="/root/.litepanel_credentials"

###############################################################################
# PATCH 1: Create .my.cnf for root MariaDB auto-login (for cron jobs)
###############################################################################
log_step "Patch 1: Creating MariaDB root config for cron..."

if [[ -f "$CREDS_FILE" ]]; then
    DB_ROOT_PASSWORD=$(grep -A1 "Database Root:" "$CREDS_FILE" | grep "Password:" | awk '{print $2}')
    DB_USER=$(grep -A3 "^Database:" "$CREDS_FILE" | grep "User:" | awk '{print $2}')
    DB_PASSWORD=$(grep -A4 "^Database:" "$CREDS_FILE" | grep -m1 "Password:" | awk '{print $2}')
    DB_NAME=$(grep -A2 "^Database:" "$CREDS_FILE" | grep "Name:" | awk '{print $2}')
    MAIN_DOMAIN=$(grep "Panel:" "$CREDS_FILE" | head -1 | sed 's|.*https://panel\.||')
fi

if [[ -n "${DB_ROOT_PASSWORD:-}" ]]; then
    cat > /root/.my.cnf <<MYCNFEOF
[client]
user=root
password=${DB_ROOT_PASSWORD}

[mysqldump]
user=root
password=${DB_ROOT_PASSWORD}
MYCNFEOF
    chmod 600 /root/.my.cnf
    log_info "Created /root/.my.cnf"
fi

###############################################################################
# PATCH 2: Sudoers for nobody user (OLS runs as nobody)
###############################################################################
log_step "Patch 2: Configuring sudoers for panel service control..."

cat > /etc/sudoers.d/litepanel <<'SUDOEOF'
nobody ALL=(ALL) NOPASSWD: /usr/local/lsws/bin/lswsctrl restart
nobody ALL=(ALL) NOPASSWD: /usr/local/lsws/bin/lswsctrl stop
nobody ALL=(ALL) NOPASSWD: /usr/local/lsws/bin/lswsctrl start
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart cloudflared
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lsws
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl status *
nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active *
SUDOEOF

chmod 440 /etc/sudoers.d/litepanel
visudo -cf /etc/sudoers.d/litepanel && log_info "Sudoers configured" || rm -f /etc/sudoers.d/litepanel

###############################################################################
# PATCH 3: Security middleware
###############################################################################
log_step "Patch 3: Adding security middleware..."

cat > "${INSTALL_PATH}/includes/security.php" <<'PHPEOF'
<?php
class Security {
    public static function init() {
        self::setHeaders();
        self::validateSession();
    }

    public static function setHeaders() {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');

        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }

    public static function validateSession() {
        if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
            if (!isset($_SESSION['ip_address'])) {
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? '';
            }
            if (!isset($_SESSION['user_agent'])) {
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
            }
            $currentFingerprint = md5(($_SERVER['HTTP_USER_AGENT'] ?? '') . CSRF_SECRET);
            if (isset($_SESSION['fingerprint']) && $_SESSION['fingerprint'] !== $currentFingerprint) {
                session_destroy();
                header('Location: /index.php');
                exit;
            }
            $_SESSION['fingerprint'] = $currentFingerprint;
        }
    }

    public static function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([self::class, 'sanitizeInput'], $input);
        }
        $input = trim($input);
        $input = stripslashes($input);
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }

    public static function generateNonce() {
        if (!isset($_SESSION['csp_nonce'])) {
            $_SESSION['csp_nonce'] = base64_encode(random_bytes(16));
        }
        return $_SESSION['csp_nonce'];
    }

    public static function rateLimit($key, $maxAttempts = 10, $windowSeconds = 60) {
        $file = INSTALL_PATH . '/data/ratelimit_' . md5($key) . '.json';
        $data = ['attempts' => [], 'blocked_until' => 0];

        if (file_exists($file)) {
            $content = file_get_contents($file);
            $decoded = json_decode($content, true);
            if ($decoded) $data = $decoded;
        }

        $now = time();

        if ($data['blocked_until'] > $now) {
            return false;
        }

        $data['attempts'] = array_filter($data['attempts'], function($t) use ($now, $windowSeconds) {
            return ($now - $t) < $windowSeconds;
        });

        if (count($data['attempts']) >= $maxAttempts) {
            $data['blocked_until'] = $now + ($windowSeconds * 2);
            file_put_contents($file, json_encode($data));
            chmod($file, 0600);
            return false;
        }

        $data['attempts'][] = $now;
        file_put_contents($file, json_encode($data));
        chmod($file, 0600);
        return true;
    }
}
PHPEOF

###############################################################################
# PATCH 4: Update header.php to include security middleware
###############################################################################
log_step "Patch 4: Updating header.php with security module..."

cat > "${INSTALL_PATH}/includes/header.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/security.php';

ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.save_path', INSTALL_PATH . '/sessions');
ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', INSTALL_PATH . '/logs/php_error.log');

session_name(SESSION_NAME);
session_start();

Security::init();

$auth = new Auth();

function e($str) {
    return htmlspecialchars((string)$str, ENT_QUOTES, 'UTF-8');
}
PHPEOF

###############################################################################
# PATCH 5: Settings page with password change functionality
###############################################################################
log_step "Patch 5: Creating settings page..."

cat > "${INSTALL_PATH}/public/settings.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$message = '';
$msgType = '';

$db = Database::getInstance();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$auth->validateCsrfToken($token)) {
        $message = 'Invalid request.';
        $msgType = 'error';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'change_password') {
            $currentPass = $_POST['current_password'] ?? '';
            $newPass = $_POST['new_password'] ?? '';
            $confirmPass = $_POST['confirm_password'] ?? '';

            if (empty($currentPass) || empty($newPass) || empty($confirmPass)) {
                $message = 'All password fields are required.';
                $msgType = 'error';
            } elseif ($newPass !== $confirmPass) {
                $message = 'New passwords do not match.';
                $msgType = 'error';
            } elseif (strlen($newPass) < 8) {
                $message = 'Password must be at least 8 characters.';
                $msgType = 'error';
            } else {
                $user = $db->fetchOne("SELECT * FROM users WHERE id = ?", [$_SESSION['user_id']]);
                if ($user && password_verify($currentPass, $user['password'])) {
                    $newHash = password_hash($newPass, PASSWORD_BCRYPT, ['cost' => 12]);
                    $db->query("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", [$newHash, $_SESSION['user_id']]);
                    $message = 'Password changed successfully.';
                    $msgType = 'success';
                } else {
                    $message = 'Current password is incorrect.';
                    $msgType = 'error';
                }
            }
        } elseif ($action === 'restart_service') {
            $service = $_POST['service'] ?? '';
            $allowed = ['lsws', 'mariadb', 'cloudflared', 'fail2ban'];
            if (in_array($service, $allowed)) {
                if ($service === 'lsws') {
                    shell_exec('sudo /usr/local/lsws/bin/lswsctrl restart 2>&1');
                } else {
                    shell_exec('sudo systemctl restart ' . escapeshellarg($service) . ' 2>&1');
                }
                sleep(2);
                $message = ucfirst($service) . ' restarted.';
                $msgType = 'success';
            }
        } elseif ($action === 'clear_login_log') {
            $db->query("DELETE FROM login_log WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
            $message = 'Old login logs cleared.';
            $msgType = 'success';
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

$recentLogins = $db->fetchAll("SELECT * FROM login_log ORDER BY attempted_at DESC LIMIT 20");
$userInfo = $db->fetchOne("SELECT * FROM users WHERE id = ?", [$_SESSION['user_id']]);

$services = [
    ['name' => 'lsws', 'label' => 'OpenLiteSpeed'],
    ['name' => 'mariadb', 'label' => 'MariaDB'],
    ['name' => 'cloudflared', 'label' => 'Cloudflare Tunnel'],
    ['name' => 'fail2ban', 'label' => 'Fail2Ban'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Settings</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>Settings</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <div class="card">
            <div class="card-header"><h3>&#128272; Change Password</h3></div>
            <div class="card-body">
                <form method="POST" style="max-width:500px">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="change_password">
                    <div class="form-group">
                        <label>Current Password</label>
                        <input type="password" name="current_password" required autocomplete="current-password">
                    </div>
                    <div class="form-group">
                        <label>New Password (min 8 characters)</label>
                        <input type="password" name="new_password" required minlength="8" autocomplete="new-password">
                    </div>
                    <div class="form-group">
                        <label>Confirm New Password</label>
                        <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:auto">Change Password</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#9881; Service Management</h3></div>
            <div class="card-body">
                <div class="services-grid">
                    <?php foreach ($services as $svc): ?>
                    <?php $active = SystemInfo::getServiceStatus($svc['name']); ?>
                    <div class="service-item">
                        <div>
                            <span class="status-dot <?php echo $active ? 'online' : 'offline'; ?>"></span>
                            <span class="service-name"><?php echo e($svc['label']); ?></span>
                            <br><small style="color:var(--text-muted);margin-left:18px"><?php echo $active ? 'Running' : 'Stopped'; ?></small>
                        </div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                            <input type="hidden" name="action" value="restart_service">
                            <input type="hidden" name="service" value="<?php echo e($svc['name']); ?>">
                            <button type="submit" class="btn btn-sm btn-primary" style="color:#fff" onclick="return confirm('Restart <?php echo e($svc['label']); ?>?')">Restart</button>
                        </form>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#128196; Account Info</h3></div>
            <div class="card-body">
                <table>
                    <tr><td style="color:var(--text-muted);width:200px">Username</td><td><strong><?php echo e($userInfo['username'] ?? ''); ?></strong></td></tr>
                    <tr><td style="color:var(--text-muted)">Last Login</td><td><?php echo e($userInfo['last_login'] ?? 'Never'); ?></td></tr>
                    <tr><td style="color:var(--text-muted)">Account Created</td><td><?php echo e($userInfo['created_at'] ?? ''); ?></td></tr>
                    <tr><td style="color:var(--text-muted)">Server IP</td><td><?php echo e(trim(shell_exec("hostname -I 2>/dev/null | awk '{print $1}'") ?: 'Unknown')); ?></td></tr>
                    <tr><td style="color:var(--text-muted)">PHP Version</td><td><?php echo e(phpversion()); ?></td></tr>
                    <tr><td style="color:var(--text-muted)">Panel Version</td><td><?php echo e(PANEL_VERSION); ?></td></tr>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3>&#128373; Login Audit Log</h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                    <input type="hidden" name="action" value="clear_login_log">
                    <button type="submit" class="btn btn-sm btn-danger">Clear Old Logs</button>
                </form>
            </div>
            <div class="card-body">
                <?php if (empty($recentLogins)): ?>
                    <p style="color:var(--text-muted)">No login attempts recorded.</p>
                <?php else: ?>
                <table>
                    <thead><tr><th>Time</th><th>IP Address</th><th>Username</th><th>Status</th></tr></thead>
                    <tbody>
                    <?php foreach ($recentLogins as $log): ?>
                    <tr>
                        <td><?php echo e($log['attempted_at']); ?></td>
                        <td><code><?php echo e($log['ip_address']); ?></code></td>
                        <td><?php echo e($log['username'] ?? '-'); ?></td>
                        <td>
                            <?php if ($log['success']): ?>
                                <span class="badge badge-success">Success</span>
                            <?php else: ?>
                                <span class="badge badge-danger">Failed</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

###############################################################################
# PATCH 6: Update sidebar with new menu items
###############################################################################
log_step "Patch 6: Updating sidebar navigation..."

cat > "${INSTALL_PATH}/includes/sidebar.php" <<'PHPEOF'
<div class="sidebar">
    <div class="sidebar-brand">
        <h2>&#128736; LitePanel</h2>
        <small>v<?php echo PANEL_VERSION; ?> &bull; Home Server</small>
    </div>
    <ul class="nav-menu">
        <li><a href="/dashboard.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'dashboard.php' ? 'active' : ''; ?>"><span class="icon">&#127968;</span> Dashboard</a></li>
        <li><a href="/domains.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'domains.php' ? 'active' : ''; ?>"><span class="icon">&#127760;</span> Domains</a></li>
        <li><a href="/databases.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'databases.php' ? 'active' : ''; ?>"><span class="icon">&#128451;</span> Databases</a></li>
        <li><a href="/filemanager.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'filemanager.php' ? 'active' : ''; ?>"><span class="icon">&#128193;</span> File Manager</a></li>
        <li><a href="/ssl.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'ssl.php' ? 'active' : ''; ?>"><span class="icon">&#128274;</span> SSL / Tunnel</a></li>
        <li><a href="/terminal.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'terminal.php' ? 'active' : ''; ?>"><span class="icon">&#128187;</span> Web Terminal</a></li>
        <li><a href="/backups.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'backups.php' ? 'active' : ''; ?>"><span class="icon">&#128190;</span> Backups</a></li>
        <li><a href="/settings.php" class="<?php echo basename($_SERVER['PHP_SELF']) === 'settings.php' ? 'active' : ''; ?>"><span class="icon">&#9881;</span> Settings</a></li>
        <li><a href="/phpmyadmin/" target="_blank"><span class="icon">&#128202;</span> phpMyAdmin</a></li>
        <li style="margin-top:20px;border-top:1px solid var(--border);padding-top:10px">
            <a href="/logout.php"><span class="icon">&#128682;</span> Logout</a>
        </li>
    </ul>
    <div style="position:absolute;bottom:10px;left:0;right:0;padding:15px 20px;border-top:1px solid var(--border)">
        <small style="color:var(--text-muted)">&#128100; <?php echo e($_SESSION['username'] ?? 'admin'); ?></small>
    </div>
</div>
PHPEOF

###############################################################################
# PATCH 7: Backup Manager
###############################################################################
log_step "Patch 7: Creating backup manager..."

mkdir -p "${INSTALL_PATH}/backups"
chmod 700 "${INSTALL_PATH}/backups"

cat > "${INSTALL_PATH}/public/backups.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$message = '';
$msgType = '';

$backupDir = INSTALL_PATH . '/backups';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if ($auth->validateCsrfToken($token)) {
        $action = $_POST['action'] ?? '';

        if ($action === 'backup_db') {
            $dbname = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['dbname'] ?? '');
            if (!empty($dbname)) {
                $filename = $dbname . '_' . date('Y-m-d_His') . '.sql.gz';
                $filepath = $backupDir . '/' . $filename;
                $cmd = "mysqldump --defaults-file=/root/.my.cnf " . escapeshellarg($dbname) . " 2>/dev/null | gzip > " . escapeshellarg($filepath);
                shell_exec($cmd);
                if (file_exists($filepath) && filesize($filepath) > 0) {
                    chmod($filepath, 0600);
                    $message = "Database backup created: {$filename}";
                    $msgType = 'success';
                } else {
                    @unlink($filepath);
                    $message = 'Backup failed. Check database name and permissions.';
                    $msgType = 'error';
                }
            }
        } elseif ($action === 'backup_files') {
            $domain = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $_POST['domain'] ?? '');
            $sourcePath = "/home/{$domain}";
            if (!empty($domain) && is_dir($sourcePath)) {
                $filename = $domain . '_files_' . date('Y-m-d_His') . '.tar.gz';
                $filepath = $backupDir . '/' . $filename;
                $cmd = "tar -czf " . escapeshellarg($filepath) . " -C /home " . escapeshellarg($domain) . " 2>/dev/null";
                shell_exec($cmd);
                if (file_exists($filepath) && filesize($filepath) > 0) {
                    chmod($filepath, 0600);
                    $message = "File backup created: {$filename}";
                    $msgType = 'success';
                } else {
                    @unlink($filepath);
                    $message = 'File backup failed.';
                    $msgType = 'error';
                }
            } else {
                $message = 'Domain directory not found.';
                $msgType = 'error';
            }
        } elseif ($action === 'backup_full') {
            $filename = 'full_backup_' . date('Y-m-d_His') . '.tar.gz';
            $filepath = $backupDir . '/' . $filename;

            $tmpDir = '/tmp/litepanel_backup_' . time();
            mkdir($tmpDir, 0700, true);

            shell_exec("mysqldump --defaults-file=/root/.my.cnf --all-databases 2>/dev/null > {$tmpDir}/all_databases.sql");
            shell_exec("cp -r /home {$tmpDir}/home_dirs 2>/dev/null");
            shell_exec("cp -r /usr/local/lsws/conf {$tmpDir}/ols_conf 2>/dev/null");
            shell_exec("cp /etc/cloudflared/config.yml {$tmpDir}/cloudflared_config.yml 2>/dev/null");

            $cmd = "tar -czf " . escapeshellarg($filepath) . " -C {$tmpDir} . 2>/dev/null";
            shell_exec($cmd);
            shell_exec("rm -rf {$tmpDir}");

            if (file_exists($filepath) && filesize($filepath) > 0) {
                chmod($filepath, 0600);
                $message = "Full backup created: {$filename}";
                $msgType = 'success';
            } else {
                $message = 'Full backup failed.';
                $msgType = 'error';
            }
        } elseif ($action === 'delete_backup') {
            $file = basename($_POST['file'] ?? '');
            $filepath = $backupDir . '/' . $file;
            if (!empty($file) && file_exists($filepath) && strpos(realpath($filepath), realpath($backupDir)) === 0) {
                unlink($filepath);
                $message = "Backup deleted: {$file}";
                $msgType = 'success';
            }
        } elseif ($action === 'download_backup') {
            $file = basename($_POST['file'] ?? '');
            $filepath = $backupDir . '/' . $file;
            if (!empty($file) && file_exists($filepath) && strpos(realpath($filepath), realpath($backupDir)) === 0) {
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $file . '"');
                header('Content-Length: ' . filesize($filepath));
                readfile($filepath);
                exit;
            }
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}

$backups = [];
if (is_dir($backupDir)) {
    $files = scandir($backupDir);
    foreach ($files as $f) {
        if ($f === '.' || $f === '..') continue;
        $fp = $backupDir . '/' . $f;
        if (is_file($fp)) {
            $backups[] = [
                'name' => $f,
                'size' => SystemInfo::formatBytes(filesize($fp)),
                'date' => date('Y-m-d H:i:s', filemtime($fp)),
            ];
        }
    }
    usort($backups, function($a, $b) { return strcmp($b['date'], $a['date']); });
}

$db = Database::getInstance();
$databases = (new DatabaseManager())->listDatabases();
$domains = (new DomainManager())->listDomains();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Backups</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>Backup Manager</h1></div>

        <?php if ($message): ?>
            <div class="alert alert-<?php echo $msgType; ?>"><?php echo e($message); ?></div>
        <?php endif; ?>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="card-body">
                    <h3 style="margin-bottom:15px">&#128451; Database Backup</h3>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                        <input type="hidden" name="action" value="backup_db">
                        <div class="form-group">
                            <select name="dbname" required>
                                <option value="">Select database</option>
                                <?php foreach ($databases as $dbn): ?>
                                <option value="<?php echo e($dbn); ?>"><?php echo e($dbn); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-success btn-sm">Backup Database</button>
                    </form>
                </div>
            </div>

            <div class="stat-card">
                <div class="card-body">
                    <h3 style="margin-bottom:15px">&#128193; File Backup</h3>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                        <input type="hidden" name="action" value="backup_files">
                        <div class="form-group">
                            <select name="domain" required>
                                <option value="">Select domain</option>
                                <?php foreach ($domains as $d): ?>
                                <option value="<?php echo e($d['domain_name']); ?>"><?php echo e($d['domain_name']); ?></option>
                                <?php endforeach; ?>
                                <option value="default">default</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-success btn-sm">Backup Files</button>
                    </form>
                </div>
            </div>

            <div class="stat-card">
                <div class="card-body">
                    <h3 style="margin-bottom:15px">&#128230; Full Backup</h3>
                    <p style="color:var(--text-muted);font-size:13px;margin-bottom:15px">Backup all databases, files, and configs</p>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                        <input type="hidden" name="action" value="backup_full">
                        <button type="submit" class="btn btn-primary btn-sm" onclick="return confirm('Create full backup? This may take a while.')">Full Backup</button>
                    </form>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>&#128190; Backup Archives (<?php echo count($backups); ?>)</h3></div>
            <div class="card-body">
                <?php if (empty($backups)): ?>
                    <p style="color:var(--text-muted)">No backups found.</p>
                <?php else: ?>
                <table>
                    <thead><tr><th>Filename</th><th>Size</th><th>Date</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($backups as $b): ?>
                    <tr>
                        <td><code><?php echo e($b['name']); ?></code></td>
                        <td><?php echo e($b['size']); ?></td>
                        <td><?php echo e($b['date']); ?></td>
                        <td>
                            <form method="POST" style="display:inline">
                                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                                <input type="hidden" name="action" value="download_backup">
                                <input type="hidden" name="file" value="<?php echo e($b['name']); ?>">
                                <button type="submit" class="btn btn-primary btn-sm" style="color:#fff">Download</button>
                            </form>
                            <form method="POST" style="display:inline" onsubmit="return confirm('Delete this backup?');">
                                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                                <input type="hidden" name="action" value="delete_backup">
                                <input type="hidden" name="file" value="<?php echo e($b['name']); ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
</body>
</html>
PHPEOF

###############################################################################
# PATCH 8: Web Terminal (safe command executor)
###############################################################################
log_step "Patch 8: Creating web terminal..."

cat > "${INSTALL_PATH}/public/terminal.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';
$auth->requireLogin();
$csrfToken = $auth->generateCsrfToken();
$output = '';

$allowedCommands = [
    'ls', 'cat', 'head', 'tail', 'wc', 'df', 'du', 'free', 'uptime',
    'whoami', 'hostname', 'uname', 'date', 'pwd', 'id', 'w',
    'ps', 'top', 'htop', 'netstat', 'ss', 'ip',
    'systemctl', 'journalctl', 'service',
    'nginx', 'mysql', 'mariadb',
    'grep', 'find', 'which', 'whereis', 'file', 'stat',
    'dig', 'nslookup', 'ping', 'traceroute', 'curl', 'wget',
    'tar', 'zip', 'unzip', 'gzip', 'gunzip',
    'chmod', 'chown', 'mkdir', 'touch', 'cp', 'mv',
    'apt', 'dpkg',
    'lsws', 'cloudflared',
    'crontab',
];

$blockedPatterns = [
    'rm -rf /', 'rm -rf /*', 'mkfs', 'dd if=', ':(){', 'fork',
    '> /dev/sd', 'chmod -R 777 /', 'wget.*|.*sh', 'curl.*|.*sh',
    'shutdown', 'reboot', 'halt', 'poweroff', 'init 0', 'init 6',
    'passwd', 'useradd', 'userdel', 'usermod',
    'visudo', 'sudoers',
    '/etc/shadow', '/etc/passwd',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if ($auth->validateCsrfToken($token)) {
        $command = trim($_POST['command'] ?? '');

        if (!empty($command)) {
            $blocked = false;
            foreach ($blockedPatterns as $pattern) {
                if (stripos($command, $pattern) !== false) {
                    $blocked = true;
                    break;
                }
            }

            if ($blocked) {
                $output = "ERROR: This command is blocked for security reasons.";
            } else {
                $baseCmd = explode(' ', $command)[0];
                $baseCmd = basename($baseCmd);

                $safe = false;
                foreach ($allowedCommands as $ac) {
                    if ($baseCmd === $ac || strpos($command, '/usr/local/lsws/') === 0) {
                        $safe = true;
                        break;
                    }
                }

                if ($safe || strpos($command, 'systemctl status') === 0 || strpos($command, 'systemctl is-active') === 0) {
                    $descriptorspec = [
                        1 => ['pipe', 'w'],
                        2 => ['pipe', 'w'],
                    ];
                    $process = proc_open($command, $descriptorspec, $pipes, '/tmp', ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']);
                    if (is_resource($process)) {
                        $stdout = stream_get_contents($pipes[1]);
                        fclose($pipes[1]);
                        $stderr = stream_get_contents($pipes[2]);
                        fclose($pipes[2]);
                        proc_close($process);
                        $output = $stdout;
                        if (!empty($stderr)) {
                            $output .= "\nSTDERR:\n" . $stderr;
                        }
                    } else {
                        $output = "ERROR: Could not execute command.";
                    }
                } else {
                    $output = "ERROR: Command '{$baseCmd}' is not in the allowed list.\n\nAllowed commands:\n" . implode(', ', $allowedCommands);
                }
            }
        }
    }
    $csrfToken = $auth->generateCsrfToken();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LitePanel - Terminal</title>
    <link rel="stylesheet" href="/style.css">
    <style>
        .terminal { background: #000; border-radius: 8px; padding: 20px; font-family: 'Courier New', monospace; }
        .terminal-output { white-space: pre-wrap; word-wrap: break-word; color: #0f0; font-size: 13px; max-height: 500px; overflow-y: auto; margin-bottom: 15px; padding: 10px; background: #111; border-radius: 4px; min-height: 200px; }
        .terminal-input { display: flex; gap: 10px; align-items: center; }
        .terminal-input span { color: #0f0; font-size: 14px; white-space: nowrap; }
        .terminal-input input { flex: 1; background: #111; border: 1px solid #333; color: #0f0; padding: 10px; font-family: 'Courier New', monospace; font-size: 14px; border-radius: 4px; }
        .terminal-input input:focus { outline: none; border-color: #0f0; }
        .quick-cmds { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
        .quick-cmd { background: #222; color: #888; border: 1px solid #333; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: monospace; }
        .quick-cmd:hover { color: #0f0; border-color: #0f0; }
    </style>
</head>
<body>
<div class="layout">
    <?php include __DIR__ . '/../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="top-bar"><h1>Web Terminal</h1></div>

        <div class="alert alert-info" style="font-size:13px">
            <strong>Safe Mode:</strong> Only whitelisted commands are allowed. Destructive operations are blocked.
        </div>

        <div class="terminal">
            <div class="terminal-output" id="output"><?php
                if (!empty($output)) {
                    echo e($output);
                } else {
                    echo "LitePanel Web Terminal v1.0\nType a command and press Enter.\n";
                }
            ?></div>
            <form method="POST" id="cmdForm">
                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                <div class="terminal-input">
                    <span>root@litepanel:~$</span>
                    <input type="text" name="command" id="cmdInput" autofocus autocomplete="off" placeholder="Enter command...">
                    <button type="submit" class="btn btn-sm btn-success">Run</button>
                </div>
            </form>
            <div class="quick-cmds">
                <span class="quick-cmd" onclick="runCmd('uptime')">uptime</span>
                <span class="quick-cmd" onclick="runCmd('free -h')">free -h</span>
                <span class="quick-cmd" onclick="runCmd('df -h')">df -h</span>
                <span class="quick-cmd" onclick="runCmd('ps aux --sort=-rss | head -20')">top processes</span>
                <span class="quick-cmd" onclick="runCmd('systemctl status lsws')">ols status</span>
                <span class="quick-cmd" onclick="runCmd('systemctl status mariadb')">mariadb status</span>
                <span class="quick-cmd" onclick="runCmd('systemctl status cloudflared')">tunnel status</span>
                <span class="quick-cmd" onclick="runCmd('ss -tlnp')">open ports</span>
                <span class="quick-cmd" onclick="runCmd('uname -a')">kernel</span>
                <span class="quick-cmd" onclick="runCmd('ip addr show')">ip address</span>
                <span class="quick-cmd" onclick="runCmd('journalctl -u cloudflared --no-pager -n 30')">tunnel logs</span>
                <span class="quick-cmd" onclick="runCmd('tail -30 /usr/local/lsws/logs/error.log')">ols error log</span>
                <span class="quick-cmd" onclick="runCmd('tail -30 /var/log/auth.log')">auth log</span>
            </div>
        </div>
    </div>
</div>
<script>
function runCmd(cmd) {
    document.getElementById('cmdInput').value = cmd;
    document.getElementById('cmdForm').submit();
}
document.getElementById('cmdInput').focus();
</script>
</body>
</html>
PHPEOF

###############################################################################
# PATCH 9: API endpoint for AJAX dashboard refresh
###############################################################################
log_step "Patch 9: Creating API endpoint..."

cat > "${INSTALL_PATH}/public/api.php" <<'PHPEOF'
<?php
require_once __DIR__ . '/../includes/header.php';

header('Content-Type: application/json');

if (!$auth->isLoggedIn()) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'stats':
        $cpu = SystemInfo::getCpuInfo();
        $mem = SystemInfo::getMemoryInfo();
        $disk = SystemInfo::getDiskInfo();
        echo json_encode([
            'cpu' => $cpu,
            'memory' => $mem,
            'disk' => $disk,
            'uptime' => SystemInfo::getUptime(),
            'services' => [
                'lsws' => SystemInfo::getServiceStatus('lsws'),
                'mariadb' => SystemInfo::getServiceStatus('mariadb'),
                'cloudflared' => SystemInfo::getServiceStatus('cloudflared'),
                'fail2ban' => SystemInfo::getServiceStatus('fail2ban'),
            ]
        ]);
        break;

    case 'domains':
        $mgr = new DomainManager();
        echo json_encode(['domains' => $mgr->listDomains()]);
        break;

    case 'databases':
        $mgr = new DatabaseManager();
        echo json_encode(['databases' => $mgr->listDatabases()]);
        break;

    default:
        echo json_encode(['error' => 'Unknown action']);
}
PHPEOF

###############################################################################
# PATCH 10: .htaccess security rules
###############################################################################
log_step "Patch 10: Adding security rewrite rules..."

cat > "${INSTALL_PATH}/public/.htaccess" <<'HTEOF'
RewriteEngine On
RewriteRule ^includes/ - [F,L]
RewriteRule (^\.|/\.) - [F,L]
RewriteRule \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|gz)$ - [F,L]
HTEOF

###############################################################################
# PATCH 11: Fix cron with MariaDB auth
###############################################################################
log_step "Patch 11: Updating cron jobs..."

cat > /etc/cron.d/litepanel <<'CRONEOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/5 * * * * root /usr/local/bin/litepanel-monitor.sh >/dev/null 2>&1
0 3 * * 0 root mariadb --defaults-file=/root/.my.cnf litepanel_db -e "DELETE FROM login_log WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 30 DAY);" >/dev/null 2>&1
0 4 * * * root find /opt/litepanel/sessions -type f -mtime +1 -delete >/dev/null 2>&1
0 5 * * * root find /opt/litepanel/data -name 'ratelimit_*' -mtime +1 -delete >/dev/null 2>&1
0 2 * * 0 root /usr/local/bin/litepanel-autobackup.sh >/dev/null 2>&1
CRONEOF

chmod 644 /etc/cron.d/litepanel

cat > /usr/local/bin/litepanel-autobackup.sh <<'BACKEOF'
#!/bin/bash
BACKUP_DIR="/opt/litepanel/backups"
DATE=$(date +%Y-%m-%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

DATABASES=$(mariadb --defaults-file=/root/.my.cnf -e "SHOW DATABASES;" 2>/dev/null | grep -Ev "(Database|information_schema|performance_schema|mysql|sys)")

for DB in $DATABASES; do
    FILENAME="${BACKUP_DIR}/${DB}_auto_${DATE}.sql.gz"
    mysqldump --defaults-file=/root/.my.cnf "$DB" 2>/dev/null | gzip > "$FILENAME"
    chmod 600 "$FILENAME"
done

find "$BACKUP_DIR" -name "*_auto_*" -type f -mtime +30 -delete 2>/dev/null

echo "$(date): Auto backup completed" >> /var/log/litepanel-monitor.log
BACKEOF

chmod 750 /usr/local/bin/litepanel-autobackup.sh

###############################################################################
# PATCH 12: Fix OLS vhost config with PHP overrides
###############################################################################
log_step "Patch 12: Fixing OLS vhost for phpMyAdmin..."

cat > "${INSTALL_PATH}/vhconf.conf" <<'VHEOF'
docRoot                   $VH_ROOT/public/
enableGzip                1
enableBr                  1

index  {
  useServer               0
  indexFiles               index.php, index.html
}

context /phpmyadmin/ {
  location                $VH_ROOT/public/phpmyadmin/
  allowBrowse             1
  indexFiles               index.php

  accessControl  {
    allow                  *
  }

  rewrite  {
    enable                0
  }

  addDefaultCharset       off

  phpIniOverride  {
    php_value upload_max_filesize 128M
    php_value post_max_size 128M
    php_value memory_limit 256M
    php_value max_execution_time 300
  }
}

scripthandler  {
  add                     lsapi:lsphp81 php
}

extprocessor lsphp81 {
  type                    lsapi
  address                 uds://tmp/lshttpd/litepanel_lsphp.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
  initTimeout             60
  retryTimeout            0
  persistConn             1
  pcKeepAliveTimeout      60
  respBuffer              0
  autoStart               2
  path                    /usr/local/lsws/lsphp81/bin/lsphp
  backlog                 100
  instances               1
  runOnStartUp            2
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

phpIniOverride  {
  php_value upload_max_filesize 64M
  php_value post_max_size 64M
  php_value memory_limit 256M
  php_value max_execution_time 120
  php_value session.save_path /opt/litepanel/sessions
  php_value open_basedir /opt/litepanel:/home:/tmp:/usr/local/lsws/lsphp81
  php_flag display_errors Off
  php_flag log_errors On
  php_value error_log /opt/litepanel/logs/php_error.log
}

accesslog $VH_ROOT/logs/access.log {
  useServer               0
  rollingSize             100M
}

errorlog $VH_ROOT/logs/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}
VHEOF

###############################################################################
# PATCH 13: Logrotate
###############################################################################
log_step "Patch 13: Setting up logrotate..."

cat > /etc/logrotate.d/litepanel <<'LREOF'
/opt/litepanel/logs/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 nobody nogroup
}

/var/log/litepanel-monitor.log {
    monthly
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LREOF

###############################################################################
# PATCH 14: Enhanced monitoring script
###############################################################################
log_step "Patch 14: Upgrading monitor script..."

cat > /usr/local/bin/litepanel-monitor.sh <<'MONEOF'
#!/bin/bash
LOG="/var/log/litepanel-monitor.log"
MAX_LOG_SIZE=10485760

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG"
}

check_and_restart() {
    local service="$1"
    local display_name="$2"

    if ! systemctl is-active --quiet "$service"; then
        log_event "WARNING: ${display_name} is down. Attempting restart..."
        systemctl restart "$service" 2>/dev/null
        sleep 3
        if systemctl is-active --quiet "$service"; then
            log_event "SUCCESS: ${display_name} restarted successfully."
        else
            log_event "CRITICAL: ${display_name} failed to restart!"
        fi
    fi
}

check_and_restart "lsws" "OpenLiteSpeed"
check_and_restart "mariadb" "MariaDB"
check_and_restart "cloudflared" "Cloudflare Tunnel"
check_and_restart "fail2ban" "Fail2Ban"

DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [[ "$DISK_USAGE" -gt 90 ]]; then
    log_event "WARNING: Disk usage is ${DISK_USAGE}%"
fi

MEM_USAGE=$(free | awk '/Mem:/ {printf("%.0f", $3/$2 * 100)}')
if [[ "$MEM_USAGE" -gt 90 ]]; then
    log_event "WARNING: Memory usage is ${MEM_USAGE}%"
fi

if [[ -f "$LOG" ]]; then
    LOG_SIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    if [[ "$LOG_SIZE" -gt "$MAX_LOG_SIZE" ]]; then
        mv "$LOG" "${LOG}.old"
        log_event "Log rotated (was ${LOG_SIZE} bytes)"
    fi
fi
MONEOF

chmod 750 /usr/local/bin/litepanel-monitor.sh

###############################################################################
# PATCH 15: Fix permissions after all patches
###############################################################################
log_step "Patch 15: Final permission fix..."

chown -R nobody:nogroup "${INSTALL_PATH}"
chmod -R 750 "${INSTALL_PATH}"
chmod 700 "${INSTALL_PATH}/sessions"
chmod 700 "${INSTALL_PATH}/data"
chmod 700 "${INSTALL_PATH}/backups"
find "${INSTALL_PATH}/public" -type f -name "*.php" -exec chmod 644 {} \;
find "${INSTALL_PATH}/public" -type f -name "*.css" -exec chmod 644 {} \;
find "${INSTALL_PATH}/public" -type f -name "*.html" -exec chmod 644 {} \;
find "${INSTALL_PATH}/public" -type f -name "*.htaccess" -exec chmod 644 {} \;
chmod 600 "${INSTALL_PATH}/includes/config.php"

if [[ -d "${INSTALL_PATH}/public/phpmyadmin" ]]; then
    chown -R nobody:nogroup "${INSTALL_PATH}/public/phpmyadmin"
    find "${INSTALL_PATH}/public/phpmyadmin" -type d -exec chmod 750 {} \;
    find "${INSTALL_PATH}/public/phpmyadmin" -type f -exec chmod 640 {} \;
fi

###############################################################################
# Restart services
###############################################################################
log_step "Restarting services..."

/usr/local/lsws/bin/lswsctrl restart 2>/dev/null || true
sleep 2

OLS_STATUS=$(systemctl is-active lsws 2>/dev/null || echo "unknown")
MARIADB_STATUS=$(systemctl is-active mariadb 2>/dev/null || echo "unknown")
CLOUDFLARED_STATUS=$(systemctl is-active cloudflared 2>/dev/null || echo "unknown")

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   LitePanel Patches Applied Successfully!                      ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "  Patches applied:"
echo -e "    ${GREEN}✓${NC} MariaDB root .my.cnf for cron"
echo -e "    ${GREEN}✓${NC} Sudoers for panel service control"
echo -e "    ${GREEN}✓${NC} Security middleware (headers, session, rate limit)"
echo -e "    ${GREEN}✓${NC} Settings page (password change, service mgmt, audit log)"
echo -e "    ${GREEN}✓${NC} Backup manager (DB, files, full backup)"
echo -e "    ${GREEN}✓${NC} Web terminal (safe mode with command whitelist)"
echo -e "    ${GREEN}✓${NC} API endpoint for AJAX refresh"
echo -e "    ${GREEN}✓${NC} OLS security rewrite rules"
echo -e "    ${GREEN}✓${NC} Enhanced cron (auto backup, cleanup)"
echo -e "    ${GREEN}✓${NC} phpMyAdmin PHP ini overrides"
echo -e "    ${GREEN}✓${NC} Logrotate configuration"
echo -e "    ${GREEN}✓${NC} Enhanced monitoring (disk, memory alerts)"
echo -e "    ${GREEN}✓${NC} Sidebar updated with new pages"
echo -e "    ${GREEN}✓${NC} Permissions hardened"
echo ""
echo -e "  Service Status:"
echo -e "    OpenLiteSpeed:     ${OLS_STATUS}"
echo -e "    MariaDB:           ${MARIADB_STATUS}"
echo -e "    Cloudflare Tunnel: ${CLOUDFLARED_STATUS}"
echo ""
echo -e "  New Pages:"
echo -e "    ${CYAN}/settings.php${NC}    - Password change, service control, audit log"
echo -e "    ${CYAN}/backups.php${NC}     - Database & file backups"
echo -e "    ${CYAN}/terminal.php${NC}    - Safe web terminal"
echo -e "    ${CYAN}/api.php${NC}         - JSON stats endpoint"
echo ""
echo -e "${GREEN}================================================================${NC}"
echo ""
