# 🛠️ LitePanel by Boy Barley

**Lightweight Home Server Control Panel** for Ubuntu 22.04 & Cloudflare

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

Cara Mendapatkan Cloudflare API Token dan Tunnel Token
1. Mendapatkan Cloudflare API Token (untuk Multi-Domain Management)
Cloudflare API Token diperlukan untuk manajemen domain dan DNS dari panel:

Login ke Cloudflare Dashboard

Buka https://dash.cloudflare.com/ dan login
Akses Halaman API Tokens

Klik ikon profil di pojok kanan atas
Pilih "My Profile"
Pilih tab "API Tokens" di sidebar
Buat API Token Baru

Klik tombol "Create Token"
Pilih "Create Custom Token"
Beri nama token (misalnya "LitePanel Domain Management")
Atur Izin (Permissions)

Tambahkan izin berikut:
Zone - Zone - Read
Zone - Zone Settings - Edit
Zone - DNS - Edit
Di bagian Zone Resources, pilih "Include - All Zones"
Buat Token

Klik "Continue to Summary"
Review izin dan klik "Create Token"
PENTING: Salin token yang ditampilkan (token hanya ditampilkan satu kali)
Masukkan dalam Panel

Masukkan token ini di halaman Cloudflare pada LitePanel
2. Mendapatkan Cloudflare Tunnel Token
Tunnel Token digunakan untuk membuat koneksi aman dari server ke internet tanpa perlu port forwarding:

Login ke Cloudflare Zero Trust Dashboard

Buka https://one.dash.cloudflare.com/
Login dengan akun Cloudflare Anda
Navigasi ke Tunnels

Di menu sidebar, klik "Access"
Pilih "Tunnels"
Buat Tunnel Baru

Klik tombol "Create a tunnel"
Beri nama tunnel (misal: "LitePanel Server")
Klik "Save tunnel"
Dapatkan Token untuk Instalasi

Pada langkah berikutnya, Anda akan diminta untuk memilih platform
Pilih "Linux" dan kemudian "AMD64" (atau ARM64 jika server Anda ARM)
Token akan ditampilkan dalam perintah instalasi
Salin string token yang ada di antara argumen --token (biasanya string panjang yang dimulai dengan eyJhIjo...)
Masukkan dalam Panel

Masukkan token ini di halaman "Tunnel" pada LitePanel
Klik "Connect" untuk mengaktifkan tunnel
Konfigurasi Routing

Kembali ke dashboard Cloudflare Zero Trust
Di bawah tunnel yang baru dibuat, konfigurasi subdomain dan domain yang ingin Anda gunakan
Arahkan ke localhost dengan port yang sesuai (misalnya: localhost:80 untuk web server)
Setelah kedua token dikonfigurasi, LitePanel Anda akan memiliki akses lengkap untuk mengelola domain dan DNS melalui Cloudflare, serta kemampuan untuk mengakses server dari Internet secara aman melalui Cloudflare Tunnel.
