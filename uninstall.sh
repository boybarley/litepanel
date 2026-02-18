#!/bin/bash
###############################################################################
# LitePanel Uninstaller
###############################################################################
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}WARNING: This will remove LitePanel completely!${NC}"
echo "This will NOT remove:"
echo "  - OpenLiteSpeed"
echo "  - MariaDB & databases"
echo "  - Cloudflared"
echo ""
read -rp "Are you sure? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo -e "${RED}Removing LitePanel...${NC}"

# Remove panel files
rm -rf /opt/litepanel

# Remove cron
rm -f /etc/cron.d/litepanel

# Remove monitor script
rm -f /usr/local/bin/litepanel-monitor.sh
rm -f /usr/local/bin/litepanel-autobackup.sh

# Remove sudoers
rm -f /etc/sudoers.d/litepanel

# Remove logrotate
rm -f /etc/logrotate.d/litepanel

echo -e "${GREEN}LitePanel removed.${NC}"
echo "MariaDB databases are preserved."
echo "To fully remove everything:"
echo "  apt remove openlitespeed mariadb-server cloudflared fail2ban"
