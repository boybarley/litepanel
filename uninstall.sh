#!/bin/bash
############################################
# LitePanel Uninstaller v1.1
# Removes LitePanel completely from Ubuntu 22.04
# Safe: does NOT remove LSWS, MariaDB, Fail2Ban, Cloudflared
############################################

export DEBIAN_FRONTEND=noninteractive

# === COLORS ===
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }
log()  { echo -e "${G}[✓]${N} $1"; }
err()  { echo -e "${R}[✗]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
info() { echo -e "${B}[i]${N} $1"; }

# === CHECK ROOT ===
[ "$EUID" -ne 0 ] && echo "Run as root!" && exit 1

# === PANEL CONFIG ===
PANEL_DIR="/opt/litepanel"
PANEL_PORT=3000
SERVICE_NAME="litepanel"
CREDENTIALS_FILE="/etc/litepanel/credentials"
CREDENTIALS_DIR="/etc/litepanel"
ROOT_CRED="/root/.litepanel_credentials"
PMA_DIR="/usr/local/lsws/Example/html/phpmyadmin"
OLS_VHOST_CONF_DIR="/usr/local/lsws/conf/vhosts"
OLS_VHOST_DIR="/usr/local/lsws/vhosts"
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

clear
echo -e "${R}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║      LitePanel Uninstaller v1.1              ║"
echo "  ║      This will REMOVE LitePanel completely   ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${N}"

echo -e "${Y}The following will be REMOVED:${N}"
echo "  • LitePanel service & app files (/opt/litepanel)"
echo "  • phpMyAdmin (/usr/local/lsws/Example/html/phpmyadmin)"
echo "  • LitePanel systemd service"
echo "  • Saved credentials (/etc/litepanel)"
echo "  • UFW rules for port ${PANEL_PORT}"
echo "  • All virtual hosts created via LitePanel"
echo "  • OLS httpd_config.conf vhost entries"
echo ""
echo -e "${G}The following will be KEPT (untouched):${N}"
echo "  • OpenLiteSpeed (LSWS)"
echo "  • MariaDB / MySQL"
echo "  • Fail2Ban"
echo "  • Cloudflared"
echo "  • Node.js"
echo "  • UFW rules for ports 22, 80, 443, 7080, 8088"
echo ""

# === CONFIRMATION ===
echo -e "${R}WARNING: This action cannot be undone!${N}"
echo ""
read -rp "Type 'yes' to confirm uninstall: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo -e "${G}Uninstall cancelled. No changes made.${N}"
  exit 0
fi

echo ""
read -rp "Also remove all virtual host FOLDERS (website files)? [y/N]: " REMOVE_VHOST_FILES
REMOVE_VHOST_FILES="${REMOVE_VHOST_FILES,,}"

echo ""
read -rp "Also remove all LitePanel-created DATABASES & DB USERS? [y/N]: " REMOVE_DB
REMOVE_DB="${REMOVE_DB,,}"

echo ""
echo -e "${Y}Starting uninstall in 3 seconds... (Ctrl+C to abort)${N}"
sleep 3

########################################
step "Step 1/9: Stop & Disable LitePanel Service"
########################################
if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
  systemctl stop ${SERVICE_NAME} 2>/dev/null
  log "LitePanel service stopped"
else
  info "LitePanel service was not running"
fi

if systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
  systemctl disable ${SERVICE_NAME} 2>/dev/null
  log "LitePanel service disabled"
fi

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [ -f "$SERVICE_FILE" ]; then
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload 2>/dev/null
  log "Service file removed: $SERVICE_FILE"
else
  info "Service file not found (already removed?)"
fi

########################################
step "Step 2/9: Remove LitePanel App Directory"
########################################
if [ -d "$PANEL_DIR" ]; then
  # Backup config.json first (contains DB root password)
  if [ -f "$PANEL_DIR/config.json" ]; then
    mkdir -p /tmp/litepanel_backup
    cp "$PANEL_DIR/config.json" /tmp/litepanel_backup/config.json.bak
    log "Config backed up to /tmp/litepanel_backup/config.json.bak"
  fi
  rm -rf "$PANEL_DIR"
  log "Removed: $PANEL_DIR"
else
  info "Panel directory not found: $PANEL_DIR"
fi

########################################
step "Step 3/9: Remove phpMyAdmin"
########################################
if [ -d "$PMA_DIR" ]; then
  rm -rf "$PMA_DIR"
  log "Removed phpMyAdmin: $PMA_DIR"
else
  info "phpMyAdmin not found: $PMA_DIR"
fi

# Remove phpMyAdmin parent html dir if empty
PMA_HTML_DIR="/usr/local/lsws/Example/html"
if [ -d "$PMA_HTML_DIR" ] && [ -z "$(ls -A "$PMA_HTML_DIR" 2>/dev/null)" ]; then
  rm -rf "$PMA_HTML_DIR"
  log "Removed empty html dir: $PMA_HTML_DIR"
fi

########################################
step "Step 4/9: Clean OpenLiteSpeed Virtual Host Configs"
########################################

# Collect all vhost names that were created by LitePanel
VHOST_LIST=()
if [ -d "$OLS_VHOST_CONF_DIR" ]; then
  while IFS= read -r -d '' dir; do
    name=$(basename "$dir")
    [ "$name" = "Example" ] && continue
    VHOST_LIST+=("$name")
  done < <(find "$OLS_VHOST_CONF_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
fi

if [ ${#VHOST_LIST[@]} -gt 0 ]; then
  info "Found ${#VHOST_LIST[@]} virtual host(s) to clean:"
  for vh in "${VHOST_LIST[@]}"; do
    echo "    • $vh"
  done

  # Remove vhost config directories
  for vh in "${VHOST_LIST[@]}"; do
    CONF_DIR="$OLS_VHOST_CONF_DIR/$vh"
    if [ -d "$CONF_DIR" ]; then
      rm -rf "$CONF_DIR"
      log "Removed vhost config: $CONF_DIR"
    fi
  done

  # Remove vhost entries from httpd_config.conf
  if [ -f "$OLS_CONF" ]; then
    cp "$OLS_CONF" "$OLS_CONF.uninstall_bak.$(date +%Y%m%d_%H%M%S)"
    log "OLS config backed up"

    for vh in "${VHOST_LIST[@]}"; do
      # Remove virtualhost block
      python3 - "$OLS_CONF" "$vh" <<'PYEOF' 2>/dev/null
import sys, re
conf_path = sys.argv[1]
domain    = sys.argv[2]
with open(conf_path, 'r') as f:
    content = f.read()
# remove virtualhost block
pattern = r'\n?virtualhost\s+' + re.escape(domain) + r'\s*\{[^}]*\}'
content = re.sub(pattern, '', content)
# remove map lines
content = re.sub(r'^\s*map\s+' + re.escape(domain) + r'\s+.*$', '', content, flags=re.MULTILINE)
# collapse excess newlines
content = re.sub(r'\n{3,}', '\n\n', content)
with open(conf_path, 'w') as f:
    f.write(content)
PYEOF
      log "Removed OLS config entries for: $vh"
    done
  else
    warn "OLS config not found: $OLS_CONF"
  fi

  # Optionally remove vhost document root folders
  if [ "$REMOVE_VHOST_FILES" = "y" ]; then
    for vh in "${VHOST_LIST[@]}"; do
      VHOST_DIR="$OLS_VHOST_DIR/$vh"
      if [ -d "$VHOST_DIR" ]; then
        rm -rf "$VHOST_DIR"
        log "Removed vhost files: $VHOST_DIR"
      fi
    done
  else
    info "Keeping vhost file folders (user chose to keep)"
    for vh in "${VHOST_LIST[@]}"; do
      VHOST_DIR="$OLS_VHOST_DIR/$vh"
      [ -d "$VHOST_DIR" ] && info "  Kept: $VHOST_DIR"
    done
  fi

  # Restart OLS to apply config changes
  if systemctl is-active --quiet lsws 2>/dev/null; then
    systemctl restart lsws 2>/dev/null && log "OLS restarted to apply config changes" || warn "OLS restart failed"
  fi
else
  info "No LitePanel virtual hosts found"
fi

# Clean OLS Example vhost config (phpMyAdmin related)
EXAMPLE_CONF="$OLS_VHOST_CONF_DIR/Example/vhconf.conf"
if [ -f "$EXAMPLE_CONF" ]; then
  rm -f "$EXAMPLE_CONF"
  log "Removed Example vhost config"
fi

########################################
step "Step 5/9: Remove LitePanel Databases & Users (Optional)"
########################################
if [ "$REMOVE_DB" = "y" ]; then
  # Try to read DB root password from backup
  DB_ROOT_PASS=""

  if [ -f "/tmp/litepanel_backup/config.json.bak" ]; then
    DB_ROOT_PASS=$(python3 -c "import json,sys; d=json.load(open('/tmp/litepanel_backup/config.json.bak')); print(d.get('dbRootPass',''))" 2>/dev/null)
  fi

  if [ -z "$DB_ROOT_PASS" ] && [ -f "$CREDENTIALS_FILE" ]; then
    DB_ROOT_PASS=$(grep "MariaDB root:" "$CREDENTIALS_FILE" 2>/dev/null | awk '{print $NF}')
  fi

  if [ -z "$DB_ROOT_PASS" ] && [ -f "$ROOT_CRED" ]; then
    DB_ROOT_PASS=$(grep "MariaDB root:" "$ROOT_CRED" 2>/dev/null | awk '{print $NF}')
  fi

  if [ -z "$DB_ROOT_PASS" ]; then
    warn "Cannot read DB root password automatically."
    read -rsp "Enter MariaDB root password (leave blank to skip DB cleanup): " DB_ROOT_PASS
    echo ""
  fi

  if [ -n "$DB_ROOT_PASS" ] && mysqladmin -u root -p"${DB_ROOT_PASS}" ping &>/dev/null 2>&1; then
    log "Connected to MariaDB"

    # Get list of non-system databases
    SKIP_DBS="information_schema performance_schema mysql sys"
    DB_LIST=$(mysql -u root -p"${DB_ROOT_PASS}" -s -N -e "SHOW DATABASES;" 2>/dev/null)

    DROP_COUNT=0
    for db in $DB_LIST; do
      skip=0
      for sys_db in $SKIP_DBS; do
        [ "$db" = "$sys_db" ] && skip=1 && break
      done
      [ $skip -eq 1 ] && continue

      mysql -u root -p"${DB_ROOT_PASS}" -e "DROP DATABASE IF EXISTS \`${db}\`;" 2>/dev/null
      log "Dropped database: $db"
      DROP_COUNT=$((DROP_COUNT + 1))
    done

    # Get list of non-system users
    USER_LIST=$(mysql -u root -p"${DB_ROOT_PASS}" -s -N \
      -e "SELECT User FROM mysql.user WHERE Host='localhost' AND User NOT IN ('root','debian-sys-maint','mariadb.sys');" 2>/dev/null)

    DROP_USER_COUNT=0
    for user in $USER_LIST; do
      mysql -u root -p"${DB_ROOT_PASS}" -e "DROP USER IF EXISTS '${user}'@'localhost';" 2>/dev/null
      log "Dropped user: $user"
      DROP_USER_COUNT=$((DROP_USER_COUNT + 1))
    done

    mysql -u root -p"${DB_ROOT_PASS}" -e "FLUSH PRIVILEGES;" 2>/dev/null
    log "Dropped $DROP_COUNT database(s) and $DROP_USER_COUNT user(s)"
  else
    warn "Could not connect to MariaDB – skipping database cleanup"
  fi
else
  info "Keeping all databases and DB users (user chose to keep)"
fi

########################################
step "Step 6/9: Remove Credentials & Config Files"
########################################
if [ -f "$ROOT_CRED" ]; then
  rm -f "$ROOT_CRED"
  log "Removed: $ROOT_CRED"
fi

if [ -d "$CREDENTIALS_DIR" ]; then
  rm -rf "$CREDENTIALS_DIR"
  log "Removed: $CREDENTIALS_DIR"
fi

# Remove temp backup
rm -rf /tmp/litepanel_backup 2>/dev/null

# Remove temp SQL files if any
rm -f /tmp/lp_sql_*.sql 2>/dev/null
rm -f /tmp/*.sql /tmp/*.sql.gz 2>/dev/null

log "Credentials and temp files cleaned"

########################################
step "Step 7/9: Remove UFW Rule for Panel Port"
########################################
if command -v ufw > /dev/null 2>&1 && ufw status | grep -q "active"; then
  ufw delete allow ${PANEL_PORT}/tcp > /dev/null 2>&1
  log "Removed UFW rule for port ${PANEL_PORT}"
  info "Kept UFW rules for: 22, 80, 443, 7080, 8088"
else
  info "UFW not active – skipping firewall cleanup"
fi

########################################
step "Step 8/9: Remove MySQL Socket Symlinks (LitePanel-created)"
########################################
if [ -L "/tmp/mysql.sock" ]; then
  rm -f /tmp/mysql.sock
  log "Removed /tmp/mysql.sock symlink"
fi

if [ -L "/var/lib/mysql/mysql.sock" ]; then
  # Only remove if it's a symlink (not a real socket)
  rm -f /var/lib/mysql/mysql.sock
  log "Removed /var/lib/mysql/mysql.sock symlink"
fi

########################################
step "Step 9/9: Final Verification"
########################################
echo ""
echo -e "${B}Checking what remains:${N}"

# LitePanel service
if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
  err "LitePanel service still running!"
else
  log "LitePanel service: removed"
fi

# App files
if [ -d "$PANEL_DIR" ]; then
  err "Panel directory still exists: $PANEL_DIR"
else
  log "Panel directory: removed"
fi

# phpMyAdmin
if [ -d "$PMA_DIR" ]; then
  err "phpMyAdmin still exists: $PMA_DIR"
else
  log "phpMyAdmin: removed"
fi

# Credentials
if [ -f "$ROOT_CRED" ] || [ -d "$CREDENTIALS_DIR" ]; then
  err "Credentials files still exist"
else
  log "Credentials: removed"
fi

# Services that should still be running
echo ""
echo -e "${B}Services status (should still be running):${N}"
for svc in lsws mariadb fail2ban; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    log "$svc: running ✓"
  else
    warn "$svc: NOT running (was it running before?)"
  fi
done

# cloudflared might be optional
if systemctl is-active --quiet cloudflared 2>/dev/null; then
  log "cloudflared: running ✓"
else
  info "cloudflared: not running (OK if not configured)"
fi

########################################
# SUMMARY
########################################
echo ""
echo -e "${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║      ✅ LitePanel Uninstall Complete!        ║${N}"
echo -e "${C}╠══════════════════════════════════════════════╣${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  ${G}Removed:${N}                                    ${C}║${N}"
echo -e "${C}║${N}  • LitePanel app & service                   ${C}║${N}"
echo -e "${C}║${N}  • phpMyAdmin                                 ${C}║${N}"
echo -e "${C}║${N}  • Virtual host configs (OLS entries)         ${C}║${N}"
echo -e "${C}║${N}  • Credentials & temp files                   ${C}║${N}"
echo -e "${C}║${N}  • UFW rule port ${PANEL_PORT}                         ${C}║${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}║${N}  ${Y}Preserved:${N}                                  ${C}║${N}"
echo -e "${C}║${N}  • OpenLiteSpeed (LSWS)                       ${C}║${N}"
echo -e "${C}║${N}  • MariaDB                                    ${C}║${N}"
echo -e "${C}║${N}  • Fail2Ban                                   ${C}║${N}"
echo -e "${C}║${N}  • Cloudflared                                ${C}║${N}"
echo -e "${C}║${N}  • Node.js                                    ${C}║${N}"
echo -e "${C}║${N}  • UFW rules (22, 80, 443, 7080, 8088)        ${C}║${N}"
echo -e "${C}║${N}                                              ${C}║${N}"
if [ "$REMOVE_VHOST_FILES" = "y" ]; then
echo -e "${C}║${N}  ${R}Deleted:${N} vhost website file folders         ${C}║${N}"
else
echo -e "${C}║${N}  ${G}Kept:${N} vhost website file folders            ${C}║${N}"
fi
if [ "$REMOVE_DB" = "y" ]; then
echo -e "${C}║${N}  ${R}Deleted:${N} LitePanel databases & DB users     ${C}║${N}"
else
echo -e "${C}║${N}  ${G}Kept:${N} All databases & DB users              ${C}║${N}"
fi
echo -e "${C}║${N}                                              ${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════════╝${N}"
echo ""
echo -e "${G}LitePanel has been successfully uninstalled.${N}"
echo ""
