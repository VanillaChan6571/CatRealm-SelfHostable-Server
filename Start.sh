#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================"
echo "  CatRealm Self-Hosted Server Startup"
echo -e "========================================${NC}"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js is not installed!${NC}"
    echo ""

    # Check if nvm is available
    if command -v nvm &> /dev/null || [ -s "$HOME/.nvm/nvm.sh" ]; then
        echo "Would you like to automatically install Node.js 24 via nvm? [y/N]"
        read -p "Install Node.js now? (y/N): " INSTALL_NODE

        if [[ "$INSTALL_NODE" =~ ^[Yy]$ ]]; then
            echo ""
            echo "Installing Node.js 24 via nvm..."
            [ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh"
            nvm install 24
            nvm use 24
            nvm alias default 24

            if [ $? -eq 0 ]; then
                echo ""
                echo -e "${GREEN}[SUCCESS] Node.js 24 installed successfully!${NC}"
                echo ""
                echo "Please RESTART this script for changes to take effect."
                exit 0
            else
                echo ""
                echo -e "${RED}[ERROR] Failed to install Node.js via nvm${NC}"
            fi
        fi
    fi

    echo "Please install Node.js 24 from:"
    echo "https://nodejs.org/"
    echo ""
    echo "Or use nvm: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash"
    echo ""
    exit 1
fi

# Check Node.js version
echo -e "${GREEN}[INFO] Checking Node.js version...${NC}"
NODE_VERSION=$(node -v)
echo "Node.js version: $NODE_VERSION"
echo ""

# Extract major version (remove 'v' prefix)
NODE_MAJOR=$(echo $NODE_VERSION | cut -d'.' -f1 | sed 's/v//')

# Check if version is below 20
if [ "$NODE_MAJOR" -lt 20 ]; then
    echo -e "${YELLOW}[WARNING] Your Node.js version is outdated!${NC}"
    echo ""
    echo "Current version: $NODE_VERSION"
    echo "Recommended version: v24.x or higher"
    echo "Minimum required: v20.x"
    echo ""

    # Check if nvm is available for auto-upgrade
    if command -v nvm &> /dev/null || [ -s "$HOME/.nvm/nvm.sh" ]; then
        echo "Would you like to automatically upgrade to Node.js 24 via nvm? [y/N]"
        read -p "Upgrade Node.js now? (y/N): " UPGRADE_NODE

        if [[ "$UPGRADE_NODE" =~ ^[Yy]$ ]]; then
            echo ""
            echo "Upgrading Node.js to version 24 via nvm..."
            [ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh"
            nvm install 24
            nvm use 24
            nvm alias default 24

            if [ $? -eq 0 ]; then
                echo ""
                echo -e "${GREEN}[SUCCESS] Node.js 24 installed successfully!${NC}"
                echo ""
                echo "Please RESTART this script for changes to take effect."
                exit 0
            else
                echo ""
                echo -e "${YELLOW}[ERROR] Failed to upgrade Node.js via nvm${NC}"
                echo "Press Enter to continue anyway (may cause issues)..."
                read
                echo ""
            fi
        fi
    else
        echo "To upgrade Node.js:"
        echo "  - Download from: https://nodejs.org/"
        echo "  - Or install nvm: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash"
        echo "  - Then run: nvm install 24"
        echo ""
        echo "Press Enter to continue anyway (may cause issues)..."
        read
        echo ""
    fi
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}[WARNING] .env file not found!${NC}"
    echo ""
    if [ -f ".env.example" ]; then
        echo "Creating .env from .env.example..."
        cp .env.example .env
        echo -e "${GREEN}[SUCCESS] Created .env file${NC}"
        echo ""
        echo -e "${YELLOW}IMPORTANT: Please edit .env file with your settings!${NC}"
        echo "Opening .env in default editor..."
        ${EDITOR:-nano} .env
        echo ""
        echo "Press Enter to continue after configuring .env..."
        read
    else
        echo -e "${RED}[ERROR] No .env.example found to create .env from!${NC}"
        echo "Please create a .env file manually."
        echo ""
        exit 1
    fi
fi

# Check if dependencies are installed and complete
NEED_NPM_INSTALL=0
if [ ! -d "node_modules" ]; then
    NEED_NPM_INSTALL=1
else
    node -e "require.resolve('dotenv'); require.resolve('express'); require.resolve('better-sqlite3')" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        NEED_NPM_INSTALL=1
    fi
fi

if [ "$NEED_NPM_INSTALL" -eq 1 ]; then
    echo -e "${GREEN}[INFO] Installing or repairing dependencies...${NC}"
    echo "This may take a few minutes..."
    echo ""
    npm install --omit=dev
    if [ $? -ne 0 ]; then
        echo ""
        echo -e "${RED}[ERROR] Failed to install dependencies!${NC}"
        exit 1
    fi
    echo ""
    echo -e "${GREEN}[SUCCESS] Dependencies installed!${NC}"
    echo ""
fi

# Check if src/index.js exists
if [ ! -f "src/index.js" ]; then
    echo -e "${RED}[ERROR] src/index.js not found!${NC}"
    echo "Make sure you're running this from the CatRealm-SelfHostableServer directory."
    echo ""
    exit 1
fi

echo -e "${CYAN}========================================"
echo "  Starting CatRealm Server..."
echo -e "========================================${NC}"
echo ""
echo "Server will start in 3 seconds..."
sleep 3
echo ""

# Start the server
if [ -x "./scripts/auto-update-start.sh" ]; then
    ./scripts/auto-update-start.sh
else
    node src/index.js
fi

# If server crashes or exits
echo ""
echo -e "${YELLOW}========================================"
echo "  Server Stopped"
echo -e "========================================${NC}"
echo ""
echo "Press Enter to restart, or Ctrl+C to exit..."
read
exec "$0"
