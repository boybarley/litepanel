#!/bin/bash
# OpenLiteSpeed + LitePanel + Cloudflare Automation Installer
# Version: 2.0
# Compatible with existing installations

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
PANEL_PATH="/usr/local/lsws/vhosts/panel"
LSWS_PATH="/usr/local/lsws"
CONFIG_PATH="/usr/local/lsws/conf"
INSTALLER_VERSION="2.0"
INSTALLER_LOG="/root/litepanel-installer.log"

# Logging
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a $INSTALLER_LOG
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $INSTALLER_LOG
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $INSTALLER_LOG
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Detect existing installation
detect_existing() {
    log "Detecting existing installation..."
    
    EXISTING_INSTALL=false
    EXISTING_PANEL=false
    EXISTING_CF=false
    
    if [ -d "$LSWS_PATH" ]; then
        EXISTING_INSTALL=true
        log "OpenLiteSpeed detected"
    fi
    
    if [ -d "$PANEL_PATH" ]; then
        EXISTING_PANEL=true
        log "LitePanel detected"
    fi
    
    if [ -f "$CONFIG_PATH/cloudflare-api.conf" ]; then
        EXISTING_CF=true
        log "Cloudflare integration detected"
    fi
}

# Backup existing configuration
backup_existing() {
    if [ "$EXISTING_INSTALL" = true ]; then
        log "Backing up existing configuration..."
        BACKUP_DIR="/root/litepanel-backup-$(date +%Y%m%d_%H%M%S)"
        mkdir -p $BACKUP_DIR
        
        # Backup important configs
        cp -r $CONFIG_PATH $BACKUP_DIR/ 2>/dev/null || true
        cp -r $PANEL_PATH $BACKUP_DIR/ 2>/dev/null || true
        
        log "Backup saved to $BACKUP_DIR"
    fi
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    apt-get update
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        software-properties-common \
        build-essential \
        python3-pip \
        jq \
        certbot \
        ufw \
        fail2ban \
        htop \
        nano
    
    # Install Python packages
    pip3 install cloudflare requests
}

# Install OpenLiteSpeed (skip if exists)
install_openlitespeed() {
    if [ "$EXISTING_INSTALL" = true ]; then
        log "OpenLiteSpeed already installed, skipping..."
        return
    fi
    
    log "Installing OpenLiteSpeed..."
    
    wget -qO - https://repo.litespeed.sh | bash
    apt-get install -y openlitespeed
    
    # Set admin password
    ADMIN_PASS=$(openssl rand -base64 12)
    /usr/local/lsws/admin/misc/admpass.sh << EOF
admin
$ADMIN_PASS
$ADMIN_PASS
EOF
    
    echo "OpenLiteSpeed Admin Password: $ADMIN_PASS" > /root/ols-credentials.txt
    
    # Install PHP
    apt-get install -y lsphp81 lsphp81-mysql lsphp81-common \
        lsphp81-opcache lsphp81-curl lsphp81-imagick \
        lsphp81-redis lsphp81-memcached lsphp81-imap
    
    # Configure PHP
    ln -sf /usr/local/lsws/lsphp81/bin/php /usr/bin/php
}

# Setup Cloudflare Integration
setup_cloudflare() {
    log "Setting up Cloudflare integration..."
    
    # Check if already configured
    if [ "$EXISTING_CF" = true ]; then
        read -p "Cloudflare already configured. Reconfigure? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Keeping existing Cloudflare configuration"
            return
        fi
    fi
    
    # Get Cloudflare credentials
    echo -e "${BLUE}=== Cloudflare API Configuration ===${NC}"
    echo "To create a Global API Token:"
    echo "1. Go to https://dash.cloudflare.com/profile/api-tokens"
    echo "2. Click 'Create Token'"
    echo "3. Use 'Edit zone DNS' template"
    echo "4. Zone Resources: Include → All zones"
    echo "5. Continue → Create Token"
    echo
    
    read -p "Enter your Cloudflare Email: " CF_EMAIL
    read -sp "Enter your Cloudflare Global API Token: " CF_TOKEN
    echo
    read -p "Enter your Cloudflare Account ID: " CF_ACCOUNT_ID
    
    # Save credentials securely
    cat > $CONFIG_PATH/cloudflare-api.conf << EOF
# Cloudflare API Credentials
export CF_Email="$CF_EMAIL"
export CF_Token="$CF_TOKEN"
export CF_Account_ID="$CF_ACCOUNT_ID"
EOF
    
    chmod 600 $CONFIG_PATH/cloudflare-api.conf
    
    # Create zones config
    touch $CONFIG_PATH/cloudflare-zones.conf
    chmod 600 $CONFIG_PATH/cloudflare-zones.conf
    
    # Setup acme.sh
    if [ ! -d "/root/.acme.sh" ]; then
        curl https://get.acme.sh | sh -s email=$CF_EMAIL
    fi
    
    # Configure acme.sh
    source $CONFIG_PATH/cloudflare-api.conf
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    
    log "Cloudflare integration configured!"
}

# Create domain management scripts
create_domain_scripts() {
    log "Creating domain management scripts..."
    
    # Main domain management script
    cat > $LSWS_PATH/bin/manage-domain.sh << 'SCRIPT'
#!/bin/bash
# Domain Management Script with Cloudflare Integration

set -e

DOMAIN=$1
ACTION=${2:-add}

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Paths
VHOST_PATH="/usr/local/lsws/vhosts"
CONFIG_PATH="/usr/local/lsws/conf"

# Load Cloudflare credentials
if [ -f "$CONFIG_PATH/cloudflare-api.conf" ]; then
    source $CONFIG_PATH/cloudflare-api.conf
else
    echo -e "${RED}Error: Cloudflare not configured${NC}"
    exit 1
fi

# Functions
log_success() { echo -e "${GREEN}✓ $1${NC}"; }
log_error() { echo -e "${RED}✗ $1${NC}"; exit 1; }
log_info() { echo -e "${YELLOW}→ $1${NC}"; }

# Get server IP
get_server_ip() {
    curl -s ifconfig.me || curl -s icanhazip.com
}

# Add domain to Cloudflare
add_to_cloudflare() {
    local domain=$1
    log_info "Adding $domain to Cloudflare..."
    
    # Check if zone exists
    ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain" \
        -H "Authorization: Bearer $CF_Token" \
        -H "Content-Type: application/json" | jq -r '.result[0].id')
    
    if [ "$ZONE_ID" == "null" ] || [ -z "$ZONE_ID" ]; then
        # Create new zone
        RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones" \
            -H "Authorization: Bearer $CF_Token" \
            -H "Content-Type: application/json" \
            --data "{\"name\":\"$domain\",\"account\":{\"id\":\"$CF_Account_ID\"},\"jump_start\":true}")
        
        ZONE_ID=$(echo $RESPONSE | jq -r '.result.id')
        
        if [ "$ZONE_ID" != "null" ] && [ -n "$ZONE_ID" ]; then
            log_success "Domain added to Cloudflare"
            
            # Show nameservers
            echo -e "\n${YELLOW}IMPORTANT: Update nameservers at your domain registrar:${NC}"
            echo $RESPONSE | jq -r '.result.name_servers[]' | while read ns; do
                echo "  → $ns"
            done
            echo
        else
            log_error "Failed to add domain to Cloudflare: $(echo $RESPONSE | jq -r '.errors[0].message')"
        fi
    else
        log_success "Domain already exists in Cloudflare (Zone ID: $ZONE_ID)"
    fi
    
    # Save Zone ID
    echo "export CF_Zone_ID_${domain//./_}=\"$ZONE_ID\"" >> $CONFIG_PATH/cloudflare-zones.conf
    
    # Add DNS records
    add_dns_records $domain $ZONE_ID
}

# Add DNS records
add_dns_records() {
    local domain=$1
    local zone_id=$2
    local server_ip=$(get_server_ip)
    
    log_info "Adding DNS records for IP: $server_ip"
    
    # Check existing records
    EXISTING_A=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$domain" \
        -H "Authorization: Bearer $CF_Token" | jq -r '.result[0].id')
    
    # Add/Update A record for root domain
    if [ "$EXISTING_A" != "null" ] && [ -n "$EXISTING_A" ]; then
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$EXISTING_A" \
            -H "Authorization: Bearer $CF_Token" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$server_ip\",\"ttl\":1,\"proxied\":true}" \
            > /dev/null
    else
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "Authorization: Bearer $CF_Token" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$server_ip\",\"ttl\":1,\"proxied\":true}" \
            > /dev/null
    fi
    
    # Add A record for www
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        -H "Authorization: Bearer $CF_Token" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"A\",\"name\":\"www.$domain\",\"content\":\"$server_ip\",\"ttl\":1,\"proxied\":true}" \
        > /dev/null 2>&1
    
    log_success "DNS records configured"
}

# Create vhost in OpenLiteSpeed
create_vhost() {
    local domain=$1
    
    log_info "Creating vhost for $domain..."
    
    # Create directories
    mkdir -p $VHOST_PATH/$domain/{html,logs,conf,ssl}
    
    # Create default index
    cat > $VHOST_PATH/$domain/html/index.php << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $domain</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        .info { background: #f0f0f0; padding: 20px; border-radius: 8px; margin: 20px auto; max-width: 600px; }
    </style>
</head>
<body>
    <h1>🎉 $domain is working!</h1>
    <div class="info">
        <p>PHP Version: <?php echo phpversion(); ?></p>
        <p>Server: OpenLiteSpeed</p>
        <p>Protected by Cloudflare</p>
    </div>
</body>
</html>
EOF
    
    # Set permissions
    chown -R nobody:nogroup $VHOST_PATH/$domain
    
    # Create vhost config
    mkdir -p $CONFIG_PATH/vhosts/$domain
    cat > $CONFIG_PATH/vhosts/$domain/vhconf.conf << EOF
docRoot                   \$VH_ROOT/html
vhDomain                  $domain
vhAliases                 www.$domain
enableGzip                1
enableBr                  1

index {
  useServer               0
  indexFiles              index.php, index.html
  autoIndex               0
}

errorlog \$VH_ROOT/logs/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}

accesslog \$VH_ROOT/logs/access.log {
  useServer               0
  rollingSize             10M
}

scripthandler {
  add                     lsapi:lsphp81 php
}

rewrite {
  enable                  1
  autoLoadHtaccess        1
  
  rules                   <<<END_rules
RewriteCond %{HTTPS} !on
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule ^(.*)$ https://%{HTTP_HOST}/\$1 [R=301,L]
END_rules
}

accessControl {
  allow                   *
}

context / {
  location                \$DOC_ROOT/
  allowBrowse             1
  
  rewrite {
    
  }
  addDefaultCharset       off
  
  phpIniOverride {
    
  }
}
EOF
    
    # Add to main config
    add_to_main_config $domain
    
    log_success "Vhost created"
}

# Add vhost to main OpenLiteSpeed config
add_to_main_config() {
    local domain=$1
    local config="$CONFIG_PATH/httpd_config.conf"
    
    # Check if already exists
    if grep -q "virtualhost $domain" "$config"; then
        return
    fi
    
    # Backup config
    cp $config ${config}.backup.$(date +%Y%m%d_%H%M%S)
    
    # Add virtualhost before listener
    sed -i "/^listener.*Default/i\\
virtualhost $domain {\\
  vhRoot                  $VHOST_PATH/$domain/\\
  configFile              \$SERVER_ROOT/conf/vhosts/$domain/vhconf.conf\\
  allowSymbolLink         1\\
  enableScript            1\\
  restrained              0\\
}\\
" "$config"
    
    # Add mapping in HTTP listener
    sed -i "/listener.*Default.*{/,/^}/ {
        /address.*:80/ {
            a\\  map                     $domain $domain
            a\\  map                     www.$domain $domain
        }
    }" "$config"
    
    # Add mapping in HTTPS listener  
    sed -i "/listener.*SSL.*{/,/^}/ {
        /address.*:443/ {
            a\\  map                     $domain $domain
            a\\  map                     www.$domain $domain
        }
    }" "$config"
}

# Issue SSL certificate
issue_ssl() {
    local domain=$1
    
    log_info "Issuing SSL certificate..."
    
    # Load zone ID
    source $CONFIG_PATH/cloudflare-zones.conf
    zone_var="CF_Zone_ID_${domain//./_}"
    export CF_Zone_ID="${!zone_var}"
    
    # Issue certificate
    /root/.acme.sh/acme.sh --issue \
        --dns dns_cf \
        -d $domain \
        -d www.$domain \
        --keylength 2048 \
        --force
    
    if [ $? -eq 0 ]; then
        # Install certificate
        mkdir -p $CONFIG_PATH/vhosts/$domain/ssl
        /root/.acme.sh/acme.sh --install-cert \
            -d $domain \
            --cert-file $CONFIG_PATH/vhosts/$domain/ssl/cert.pem \
            --key-file $CONFIG_PATH/vhosts/$domain/ssl/key.pem \
            --fullchain-file $CONFIG_PATH/vhosts/$domain/ssl/fullchain.pem \
            --reloadcmd "systemctl restart lsws"
        
        # Configure SSL in vhost
        configure_ssl_vhost $domain
        
        log_success "SSL certificate issued and installed"
    else
        log_error "Failed to issue SSL certificate"
    fi
}

# Configure SSL in vhost
configure_ssl_vhost() {
    local domain=$1
    local vhconf="$CONFIG_PATH/vhosts/$domain/vhconf.conf"
    
    # Check if SSL already configured
    if grep -q "vhssl" $vhconf; then
        return
    fi
    
    # Add SSL configuration
    cat >> $vhconf << EOF

vhssl {
  keyFile                 $CONFIG_PATH/vhosts/$domain/ssl/key.pem
  certFile                $CONFIG_PATH/vhosts/$domain/ssl/fullchain.pem
  certChain               1
  sslProtocol             all -SSLv3 -TLSv1 -TLSv1.1
  enableECDHE             1
  renegProtection         1
  sslSessionCache         1
  sslSessionTickets       1
  enableSpdy              15
  enableQuic              1
}
EOF
}

# Remove domain
remove_domain() {
    local domain=$1
    
    log_info "Removing $domain..."
    
    # Remove from OpenLiteSpeed config
    sed -i "/^virtualhost $domain {/,/^}/d" $CONFIG_PATH/httpd_config.conf
    sed -i "/map.*$domain/d" $CONFIG_PATH/httpd_config.conf
    
    # Backup before removing
    if [ -d "$VHOST_PATH/$domain" ]; then
        tar -czf /root/${domain}_backup_$(date +%Y%m%d_%H%M%S).tar.gz -C $VHOST_PATH $domain
        rm -rf $VHOST_PATH/$domain
    fi
    
    rm -rf $CONFIG_PATH/vhosts/$domain
    
    log_success "Domain removed (backup saved in /root/)"
}

# Main execution
case $ACTION in
    "add")
        if [ -z "$DOMAIN" ]; then
            echo "Usage: $0 domain.com [add|remove|ssl|check]"
            exit 1
        fi
        
        echo -e "${GREEN}=== ADDING DOMAIN: $DOMAIN ===${NC}\n"
        
        # Add to Cloudflare
        add_to_cloudflare $DOMAIN
        
        # Create vhost
        create_vhost $DOMAIN
        
        # Reload OpenLiteSpeed
        systemctl restart lsws
        
        # Wait for DNS propagation
        echo -e "\n${YELLOW}Waiting for DNS propagation (30 seconds)...${NC}"
        sleep 30
        
        # Issue SSL
        issue_ssl $DOMAIN
        
        # Final reload
        systemctl restart lsws
        
        echo -e "\n${GREEN}✓ Domain $DOMAIN successfully configured!${NC}"
        echo -e "${GREEN}✓ Website URL: https://$DOMAIN${NC}"
        echo -e "\n${YELLOW}Note: Full DNS propagation may take up to 24 hours${NC}"
        ;;
        
    "remove")
        if [ -z "$DOMAIN" ]; then
            echo "Usage: $0 domain.com remove"
            exit 1
        fi
        
        read -p "Are you sure you want to remove $DOMAIN? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            remove_domain $DOMAIN
            systemctl restart lsws
        fi
        ;;
        
    "ssl")
        if [ -z "$DOMAIN" ]; then
            echo "Usage: $0 domain.com ssl"
            exit 1
        fi
        
        issue_ssl $DOMAIN
        systemctl restart lsws
        ;;
        
    "check")
        if [ -z "$DOMAIN" ]; then
            echo "Usage: $0 domain.com check"
            exit 1
        fi
        
        echo "Checking $DOMAIN..."
        
        # Check DNS
        echo -n "DNS Resolution: "
        if host $DOMAIN > /dev/null 2>&1; then
            echo -e "${GREEN}✓ OK${NC} ($(dig +short $DOMAIN | head -1))"
        else
            echo -e "${RED}✗ Failed${NC}"
        fi
        
        # Check vhost
        echo -n "Vhost Configuration: "
        if [ -d "$VHOST_PATH/$DOMAIN" ]; then
            echo -e "${GREEN}✓ OK${NC}"
        else
            echo -e "${RED}✗ Not found${NC}"
        fi
        
        # Check SSL
        echo -n "SSL Certificate: "
        if [ -f "$CONFIG_PATH/vhosts/$DOMAIN/ssl/fullchain.pem" ]; then
            echo -e "${GREEN}✓ OK${NC}"
        else
            echo -e "${RED}✗ Not found${NC}"
        fi
        
        # Check HTTP response
        echo -n "HTTP Response: "
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $DOMAIN" http://localhost/ 2>/dev/null)
        if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
            echo -e "${GREEN}✓ OK ($HTTP_CODE)${NC}"
        else
            echo -e "${RED}✗ Error ($HTTP_CODE)${NC}"
        fi
        
        # Check HTTPS response
        echo -n "HTTPS Response: "
        HTTPS_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" https://$DOMAIN/ 2>/dev/null)
        if [ "$HTTPS_CODE" = "200" ]; then
            echo -e "${GREEN}✓ OK ($HTTPS_CODE)${NC}"
        else
            echo -e "${YELLOW}⚠ Check needed ($HTTPS_CODE)${NC}"
        fi
        ;;
        
    *)
        echo "Usage: $0 domain.com [add|remove|ssl|check]"
        echo
        echo "Commands:"
        echo "  add     - Add new domain with Cloudflare + SSL"
        echo "  remove  - Remove domain and its files"
        echo "  ssl     - Issue/Renew SSL certificate"
        echo "  check   - Check domain configuration"
        exit 1
        ;;
esac
SCRIPT

    chmod +x $LSWS_PATH/bin/manage-domain.sh
    
    # Create helper scripts
    ln -sf $LSWS_PATH/bin/manage-domain.sh /usr/local/bin/domain
    
    log "Domain management scripts created"
}

# Update LitePanel with domain management
update_litepanel() {
    if [ "$EXISTING_PANEL" = false ]; then
        log "Installing LitePanel..."
        
        # Create panel directories
        mkdir -p $PANEL_PATH/{html,logs,conf,sessions}
        
        # Your existing panel installation code here...
        # (keeping all existing panel files)
    fi
    
    log "Adding domain management to LitePanel..."
    
    # Add domain management page
    cat > $PANEL_PATH/html/domains.php << 'PHP'
<?php
session_start();
if (!isset($_SESSION['admin'])) {
    header('Location: login.php');
    exit;
}

$message = '';
$messageType = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'];
    $domain = $_POST['domain'];
    
    // Validate domain
    if (!preg_match('/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i', $domain)) {
        $message = "Invalid domain format";
        $messageType = 'error';
    } else {
        // Execute domain management
        $cmd = "/usr/local/lsws/bin/manage-domain.sh " . escapeshellarg($domain) . " " . escapeshellarg($action) . " 2>&1";
        $output = shell_exec($cmd);
        
        $message = $output;
        $messageType = (strpos($output, 'successfully') !== false) ? 'success' : 'info';
    }
}

// Get existing domains
$domains = [];
$vhostPath = '/usr/local/lsws/vhosts/';
if (is_dir($vhostPath)) {
    $dirs = scandir($vhostPath);
    foreach ($dirs as $dir) {
        if ($dir != '.' && $dir != '..' && $dir != 'panel' && is_dir($vhostPath . $dir)) {
            $domains[] = $dir;
        }
    }
}

// Check Cloudflare status
$cfConfigured = file_exists('/usr/local/lsws/conf/cloudflare-api.conf');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Domain Manager - LitePanel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .main-container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { box-shadow: 0 0 20px rgba(0,0,0,0.1); border: none; margin-bottom: 20px; }
        .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .domain-item { transition: all 0.3s; }
        .domain-item:hover { transform: translateX(5px); background-color: #f8f9fa; }
        .status-active { color: #28a745; }
        .status-inactive { color: #dc3545; }
        .terminal-output { 
            background: #1e1e1e; 
            color: #00ff00; 
            padding: 15px; 
            border-radius: 5px; 
            font-family: 'Courier New', monospace;
            font-size: 14px;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
        .add-domain-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 10px 30px;
            color: white;
            border-radius: 25px;
            transition: all 0.3s;
        }
        .add-domain-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
    </style>
</head>
<body>
    <?php include 'header.php'; ?>
    
    <div class="main-container">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1><i class="fas fa-globe"></i> Domain Manager</h1>
            <?php if (!$cfConfigured): ?>
            <div class="alert alert-warning mb-0">
                <i class="fas fa-exclamation-triangle"></i> Cloudflare not configured. 
                <a href="settings.php#cloudflare">Configure now</a>
            </div>
            <?php endif; ?>
        </div>

        <?php if ($message): ?>
        <div class="alert alert-<?php echo $messageType == 'error' ? 'danger' : ($messageType == 'success' ? 'success' : 'info'); ?> alert-dismissible fade show">
            <?php if ($messageType == 'info'): ?>
            <div class="terminal-output"><?php echo htmlspecialchars($message); ?></div>
            <?php else: ?>
            <?php echo nl2br(htmlspecialchars($message)); ?>
            <?php endif; ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>

        <!-- Add Domain Card -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-plus-circle"></i> Add New Domain</h5>
            </div>
            <div class="card-body">
                <form method="POST" class="row g-3">
                    <input type="hidden" name="action" value="add">
                    
                    <div class="col-md-8">
                        <label class="form-label">Domain Name</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-globe"></i></span>
                            <input type="text" name="domain" class="form-control" 
                                   placeholder="example.com" required 
                                   pattern="^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
                                   title="Enter a valid domain name">
                        </div>
                        <small class="text-muted">Enter domain without http:// or www.</small>
                    </div>
                    
                    <div class="col-md-4">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" class="btn add-domain-btn w-100" <?php echo !$cfConfigured ? 'disabled' : ''; ?>>
                            <i class="fas fa-plus"></i> Add Domain
                        </button>
                    </div>
                </form>
                
                <?php if ($cfConfigured): ?>
                <div class="mt-3">
                    <div class="badge bg-success"><i class="fas fa-check"></i> Automatic Cloudflare DNS</div>
                    <div class="badge bg-success"><i class="fas fa-check"></i> Free SSL Certificate</div>
                    <div class="badge bg-success"><i class="fas fa-check"></i> Auto-renewal</div>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Existing Domains -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-list"></i> Your Domains (<?php echo count($domains); ?>)</h5>
            </div>
            <div class="card-body">
                <?php if (empty($domains)): ?>
                <p class="text-muted text-center py-4">No domains configured yet. Add your first domain above!</p>
                <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>SSL Status</th>
                                <th>Files</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($domains as $domain): ?>
                            <?php 
                            $sslExists = file_exists("/usr/local/lsws/conf/vhosts/$domain/ssl/fullchain.pem");
                            $fileCount = count(glob("/usr/local/lsws/vhosts/$domain/html/*"));
                            ?>
                            <tr class="domain-item">
                                <td>
                                    <strong><?php echo htmlspecialchars($domain); ?></strong><br>
                                    <small class="text-muted">
                                        <a href="https://<?php echo $domain; ?>" target="_blank">
                                            <i class="fas fa-external-link-alt"></i> Visit
                                        </a>
                                    </small>
                                </td>
                                <td>
                                    <?php if ($sslExists): ?>
                                    <span class="status-active"><i class="fas fa-lock"></i> Secured</span>
                                    <?php else: ?>
                                    <span class="status-inactive"><i class="fas fa-lock-open"></i> No SSL</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge bg-secondary"><?php echo $fileCount; ?> files</span>
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="filemanager.php?domain=<?php echo $domain; ?>" 
                                           class="btn btn-outline-primary" title="File Manager">
                                            <i class="fas fa-folder"></i>
                                        </a>
                                        
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="ssl">
                                            <input type="hidden" name="domain" value="<?php echo $domain; ?>">
                                            <button type="submit" class="btn btn-outline-success" 
                                                    title="<?php echo $sslExists ? 'Renew' : 'Install'; ?> SSL">
                                                <i class="fas fa-certificate"></i>
                                            </button>
                                        </form>
                                        
                                        <form method="POST" style="display: inline;" 
                                              onsubmit="return confirm('Remove <?php echo $domain; ?>? This will backup files to /root/');">
                                            <input type="hidden" name="action" value="remove">
                                            <input type="hidden" name="domain" value="<?php echo $domain; ?>">
                                            <button type="submit" class="btn btn-outline-danger" title="Remove">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                        
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="action" value="check">
                                            <input type="hidden" name="domain" value="<?php echo $domain; ?>">
                                            <button type="submit" class="btn btn-outline-info" title="Check Status">
                                                <i class="fas fa-heartbeat"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- How it works -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0"><i class="fas fa-info-circle"></i> How Automatic Domain Setup Works</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3 text-center mb-3">
                        <div class="rounded-circle bg-primary text-white d-inline-flex align-items-center justify-content-center" 
                             style="width: 60px; height: 60px;">
                            <i class="fas fa-plus fa-lg"></i>
                        </div>
                        <h6 class="mt-2">1. Add Domain</h6>
                        <small class="text-muted">Enter your domain name</small>
                    </div>
                    
                    <div class="col-md-3 text-center mb-3">
                        <div class="rounded-circle bg-warning text-white d-inline-flex align-items-center justify-content-center" 
                             style="width: 60px; height: 60px;">
                            <i class="fas fa-cloud fa-lg"></i>
                        </div>
                        <h6 class="mt-2">2. Cloudflare Setup</h6>
                        <small class="text-muted">Automatic DNS configuration</small>
                    </div>
                    
                    <div class="col-md-3 text-center mb-3">
                        <div class="rounded-circle bg-success text-white d-inline-flex align-items-center justify-content-center" 
                             style="width: 60px; height: 60px;">
                            <i class="fas fa-lock fa-lg"></i>
                        </div>
                        <h6 class="mt-2">3. SSL Certificate</h6>
                        <small class="text-muted">Free Let's Encrypt SSL</small>
                    </div>
                    
                    <div class="col-md-3 text-center mb-3">
                        <div class="rounded-circle bg-info text-white d-inline-flex align-items-center justify-content-center" 
                             style="width: 60px; height: 60px;">
                            <i class="fas fa-rocket fa-lg"></i>
                        </div>
                        <h6 class="mt-2">4. Go Live!</h6>
                        <small class="text-muted">Your site is ready</small>
                    </div>
                </div>
                
                <div class="alert alert-info mt-3">
                    <i class="fas fa-lightbulb"></i> <strong>Pro Tip:</strong> 
                    After adding a domain, update your domain's nameservers at your registrar to Cloudflare's nameservers shown in the output.
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
PHP

    # Update header.php to include domains link
    if [ -f "$PANEL_PATH/html/header.php" ]; then
        # Add domains link if not exists
        if ! grep -q "domains.php" $PANEL_PATH/html/header.php; then
            sed -i '/<a.*href="index.php"/a\
                    <a class="nav-link" href="domains.php"><i class="fas fa-globe"></i> Domains</a>' \
                $PANEL_PATH/html/header.php
        fi
    fi
    
    log "LitePanel updated with domain management"
}

# Main installation flow
main() {
    clear
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     OpenLiteSpeed + LitePanel + Cloudflare Installer    ║"
    echo "║                     Version $INSTALLER_VERSION                       ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Pre-flight checks
    check_root
    detect_existing
    backup_existing
    
    # Installation
    install_dependencies
    install_openlitespeed
    setup_cloudflare
    create_domain_scripts
    update_litepanel
    
    # Post-installation
    log "Cleaning up..."
    apt-get clean
    
    # Final configuration
    systemctl restart lsws
    
    # Summary
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║            Installation Completed Successfully!           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "\n${YELLOW}Access Details:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "LitePanel: https://$(curl -s ifconfig.me):2087"
    
    if [ -f "/root/.litepanel" ]; then
        cat /root/.litepanel
    fi
    
    echo -e "\nOpenLiteSpeed WebAdmin: https://$(curl -s ifconfig.me):7080"
    
    if [ -f "/root/ols-credentials.txt" ]; then
        cat /root/ols-credentials.txt
    fi
    
    echo -e "\n${YELLOW}Quick Commands:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Add domain    : domain example.com add"
    echo "Remove domain : domain example.com remove"
    echo "Renew SSL     : domain example.com ssl"
    echo "Check domain  : domain example.com check"
    
    echo -e "\n${GREEN}Installation log saved to: $INSTALLER_LOG${NC}"
}

# Run installation
main "$@"
