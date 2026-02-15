# CatRealm Self-Hosted Server 🐱

Welcome to CatRealm Self-Hosted Server! This guide will help you set up and run your own CatRealm chat server.

## 📋 Prerequisites

- **Node.js** v20 or higher - **v24 recommended** ([Download here](https://nodejs.org/))
- **Git** (optional, for cloning the repository)

> **✨ Auto-Install:** The startup scripts can automatically install any missing dependents.
> - **Windows:** Uses winget (requires Windows 10+) and triggers UAC prompt if needed.
> - **Linux/Mac:** Uses nvm if available, otherwise provides manual instructions.

## 🚀 Quick Start

### Windows

1. **Download or clone** this repository
2. **Double-click** `Start.bat`
3. Follow the on-screen instructions
   - If Node.js is missing or outdated, `depinstaller.bat` will launch automatically
   - This uses Windows Package Manager (winget) and requires UAC approval
   - After installation completes, run `Start.bat` again
4. Server will start automatically!

### Linux / macOS

1. **Download or clone** this repository
2. **Make the script executable:**
   ```bash
   chmod +x Start.sh
   ```
3. **Run the script:**
   ```bash
   ./Start.sh
   ```
   - If Node.js is missing or outdated and you have nvm installed, you'll be offered automatic installation
4. Server will start automatically!

## ⚙️ Configuration

### First-Time Setup

When you first run the server, it will:
1. Create a `.env` file from `.env.example` or `.env.win.example`
2. Open it in your default editor
3. Wait for you to configure the settings

### Important Settings

Edit your `.env` file:

```env
# Basic Configuration
PORT=40500
SERVER_URL=http://localhost:40500
SERVER_NAME=My CatRealm Server
SERVER_DESCRIPTION=A cozy self-hosted realm

# Allow new users to register?
REGISTRATION_OPEN=true

# Media upload limits
MEDIA_MAX_MB=20
AVATAR_MAX_MB=10
```

## 🌐 Accessing Your Server

### Locally
- Open your browser to: http://localhost:40500
- Or use the CatRealm Client and connect to: https://localhost:40500 (SSL Must be configured to use the Web App)

### From Other Devices (LAN)
1. Find your computer's IP address
2. Update SERVER_URL in .env to your IP
3. Restart the server
4. Others can connect to: http://YOUR_IP:3001

## 🛠️ Manual Installation

```bash
npm install --omit=dev
cp .env.example .env
# Edit .env with your settings
node src/index.js
```

## 🔧 Troubleshooting

### Node.js Version Issues
- Check your version: `node -v`
- If below v20, upgrade from [nodejs.org](https://nodejs.org/)
- **Recommended:** Install Node.js v24 LTS for best compatibility

### Common Issues
- Port 40500 already in use → Change `PORT` in `.env`
- Can't connect from other devices → Update `SERVER_URL` in `.env` to your IP
- Database errors → Delete `data/` folder and restart (WARNING: loses all data)

---

**Happy hosting! 🐱✨**
