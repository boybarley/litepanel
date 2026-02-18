# 🛠️ LitePanel by BoyBarley

**Lightweight Home Server Control Panel** for Ubuntu 22.04

Built with OpenLiteSpeed + MariaDB + PHP Native + Cloudflare Tunnel

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![OS](https://img.shields.io/badge/OS-Ubuntu%2022.04-orange.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)

## Features

- 🖥️ **Dashboard** — CPU, RAM, Disk, Service monitoring
- 🌐 **Domain Manager** — Add/remove domains with auto vhost
- 🗄️ **Database Manager** — Create/drop databases & users
- 📁 **File Manager** — Browse, edit, delete files
- 💻 **Web Terminal** — Safe command execution
- 💾 **Backup Manager** — DB, files, full backup
- 🔒 **SSL/TLS** — Automatic via Cloudflare Tunnel
- 🛡️ **Zero Trust Ready** — Cloudflare Access integration
- 📊 **phpMyAdmin** — Database GUI

## Requirements

- Ubuntu 22.04 LTS (fresh install recommended)
- Root access
- Cloudflare account with:
  - API Token (Zone:DNS:Edit + Account:Tunnel:Edit)
  - Domain added to Cloudflare

## Quick Install

```bash
wget -O install.sh https://raw.githubusercontent.com/boybarley/litepanel/main/install.sh && chmod +x install.sh && sudo bash install.sh
```

## Step-by-Step Install

```bash
# Download installer
wget https://raw.githubusercontent.com/boybarley/litepanel/main/install.sh

# Make executable
chmod +x install.sh

# Run installer
sudo bash install.sh

# After install completes, run patch for extra features
wget https://raw.githubusercontent.com/boybarley/litepanel/main/patch.sh
chmod +x patch.sh
sudo bash patch.sh
```

## What You'll Need During Install

The installer will ask for:
1. **Cloudflare Email** — your CF account email
2. **Cloudflare API Token** — with DNS and Tunnel permissions
3. **Main Domain** — e.g., `example.com`

## Access URLs

After installation:

| Service | URL |
|---------|-----|
| Panel | `https://panel.yourdomain.com` |
| Website | `https://yourdomain.com` |
| phpMyAdmin | `https://db.yourdomain.com` |

## Default Ports (Internal Only)

| Port | Service |
|------|---------|
| 2087 | Panel |
| 8080 | Web |
| 22 | SSH (only open port) |

> ⚠️ No ports are exposed publicly. All access goes through Cloudflare Tunnel.

## Security

- UFW firewall (only SSH open)
- Fail2Ban SSH protection
- CSRF protection
- Bcrypt password hashing
- Rate-limited login
- Session fingerprinting
- Security headers
- Root SSH disabled

## Zero Trust Setup

After installation, secure your panel with Cloudflare Access:

1. Go to [Cloudflare Zero Trust](https://one.dash.cloudflare.com)
2. Navigate to **Access → Applications**
3. Add **Self-hosted** application
4. Set domain: `panel.yourdomain.com`
5. Add policy: Allow → Emails → your@email.com

## Uninstall

```bash
wget https://raw.githubusercontent.com/boybarley/litepanel/main/uninstall.sh
chmod +x uninstall.sh
sudo bash uninstall.sh
```

## Credentials

After installation, credentials are saved to:
```
/root/.litepanel_credentials
```

⚠️ **Save credentials and delete this file!**

## License

MIT License — free to use, modify, and distribute.

## Contributing

Pull requests welcome. For major changes, open an issue first.
