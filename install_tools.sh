#!/usr/bin/env bash

# REX SCAN - Tool Installation Script
# Installs all required external tools for REX SCAN

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              REX SCAN - Tool Installer                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo -e "${GREEN}[✓] Detected macOS${NC}"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
    echo -e "${GREEN}[✓] Detected Debian/Ubuntu Linux${NC}"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
    echo -e "${GREEN}[✓] Detected RedHat/CentOS/Fedora Linux${NC}"
elif [[ -f /etc/arch-release ]]; then
    OS="arch"
    echo -e "${GREEN}[✓] Detected Arch Linux${NC}"
else
    echo -e "${YELLOW}[!] Could not detect OS. Please install tools manually.${NC}"
    echo "Required tools: nmap, exploitdb (searchsploit), gobuster"
    exit 1
fi

# Check if running as root (needed for Linux package managers)
if [[ "$OS" != "macos" ]] && [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}[!] This script should be run with sudo on Linux${NC}"
   echo "Usage: sudo bash install_tools.sh"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install nmap
install_nmap() {
    echo -e "${YELLOW}[*] Installing nmap...${NC}"
    case $OS in
        macos)
            if ! command_exists brew; then
                echo -e "${RED}[✗] Homebrew not found. Install from https://brew.sh${NC}"
                return 1
            fi
            brew install nmap
            ;;
        debian)
            apt-get update
            apt-get install -y nmap
            ;;
        redhat)
            yum install -y nmap
            ;;
        arch)
            pacman -S --noconfirm nmap
            ;;
    esac
    
    if command_exists nmap; then
        echo -e "${GREEN}[✓] nmap installed successfully${NC}"
        nmap --version | head -n 1
        return 0
    else
        echo -e "${RED}[✗] nmap installation failed${NC}"
        return 1
    fi
}

# Function to install exploitdb (searchsploit)
install_exploitdb() {
    echo -e "${YELLOW}[*] Installing exploitdb (searchsploit)...${NC}"
    case $OS in
        macos)
            if ! command_exists brew; then
                echo -e "${RED}[✗] Homebrew not found. Install from https://brew.sh${NC}"
                return 1
            fi
            brew install exploitdb
            ;;
        debian)
            apt-get update
            apt-get install -y exploitdb
            ;;
        redhat)
            # exploitdb not in default repos, install from git
            if ! command_exists git; then
                yum install -y git
            fi
            cd /opt
            git clone https://github.com/offensive-security/exploitdb.git
            ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
            ;;
        arch)
            pacman -S --noconfirm exploitdb
            ;;
    esac
    
    if command_exists searchsploit; then
        echo -e "${GREEN}[✓] searchsploit installed successfully${NC}"
        searchsploit --version 2>/dev/null || echo "searchsploit available"
        return 0
    else
        echo -e "${RED}[✗] searchsploit installation failed${NC}"
        return 1
    fi
}

# Function to install gobuster
install_gobuster() {
    echo -e "${YELLOW}[*] Installing gobuster...${NC}"
    case $OS in
        macos)
            if ! command_exists brew; then
                echo -e "${RED}[✗] Homebrew not found. Install from https://brew.sh${NC}"
                return 1
            fi
            brew install gobuster
            ;;
        debian)
            apt-get update
            apt-get install -y gobuster
            ;;
        redhat)
            # gobuster not in default repos, install via go
            if ! command_exists go; then
                yum install -y golang
            fi
            go install github.com/OJ/gobuster/v3@latest
            ln -sf ~/go/bin/gobuster /usr/local/bin/gobuster 2>/dev/null || true
            ;;
        arch)
            pacman -S --noconfirm gobuster
            ;;
    esac
    
    if command_exists gobuster; then
        echo -e "${GREEN}[✓] gobuster installed successfully${NC}"
        gobuster version 2>/dev/null || echo "gobuster available"
        return 0
    else
        echo -e "${YELLOW}[!] gobuster installation failed (optional tool)${NC}"
        return 1
    fi
}

# Function to install dig (DNS utils)
install_dns_utils() {
    echo -e "${YELLOW}[*] Installing DNS utilities (dig)...${NC}"
    case $OS in
        macos)
            if ! command_exists brew; then
                echo -e "${RED}[✗] Homebrew not found. Install from https://brew.sh${NC}"
                return 1
            fi
            brew install bind
            ;;
        debian)
            apt-get update
            apt-get install -y dnsutils
            ;;
        redhat)
            yum install -y bind-utils
            ;;
        arch)
            pacman -S --noconfirm bind-tools
            ;;
    esac
    
    if command_exists dig; then
        echo -e "${GREEN}[✓] dig installed successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] dig installation failed (optional tool)${NC}"
        return 1
    fi
}

# Main installation flow
echo ""
echo -e "${GREEN}Starting installation of required tools...${NC}"
echo ""

# Track installation status
NMAP_OK=false
EXPLOITDB_OK=false
GOBUSTER_OK=false
DIG_OK=false

# Install nmap (required)
if command_exists nmap; then
    echo -e "${GREEN}[✓] nmap already installed${NC}"
    nmap --version | head -n 1
    NMAP_OK=true
else
    if install_nmap; then
        NMAP_OK=true
    fi
fi

echo ""

# Install exploitdb (required)
if command_exists searchsploit; then
    echo -e "${GREEN}[✓] searchsploit already installed${NC}"
    EXPLOITDB_OK=true
else
    if install_exploitdb; then
        EXPLOITDB_OK=true
    fi
fi

echo ""

# Install gobuster (optional)
if command_exists gobuster; then
    echo -e "${GREEN}[✓] gobuster already installed${NC}"
    GOBUSTER_OK=true
else
    echo -e "${YELLOW}[?] gobuster is optional but recommended for directory enumeration${NC}"
    read -p "Install gobuster? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        if install_gobuster; then
            GOBUSTER_OK=true
        fi
    else
        echo -e "${YELLOW}[!] Skipping gobuster (Python fallback will be used)${NC}"
    fi
fi

echo ""

# Install dig (optional)
if command_exists dig; then
    echo -e "${GREEN}[✓] dig already installed${NC}"
    DIG_OK=true
else
    echo -e "${YELLOW}[?] dig is optional but recommended for DNS enumeration${NC}"
    read -p "Install DNS utilities (dig)? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        if install_dns_utils; then
            DIG_OK=true
        fi
    else
        echo -e "${YELLOW}[!] Skipping dig (dnspython fallback will be used)${NC}"
    fi
fi

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}               Installation Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"

if $NMAP_OK; then
    echo -e "${GREEN}[✓] nmap          - INSTALLED (required)${NC}"
else
    echo -e "${RED}[✗] nmap          - FAILED (required)${NC}"
fi

if $EXPLOITDB_OK; then
    echo -e "${GREEN}[✓] searchsploit  - INSTALLED (required)${NC}"
else
    echo -e "${RED}[✗] searchsploit  - FAILED (required)${NC}"
fi

if $GOBUSTER_OK; then
    echo -e "${GREEN}[✓] gobuster      - INSTALLED (optional)${NC}"
else
    echo -e "${YELLOW}[!] gobuster      - NOT INSTALLED (optional)${NC}"
fi

if $DIG_OK; then
    echo -e "${GREEN}[✓] dig           - INSTALLED (optional)${NC}"
else
    echo -e "${YELLOW}[!] dig           - NOT INSTALLED (optional)${NC}"
fi

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if required tools are installed
if $NMAP_OK && $EXPLOITDB_OK; then
    echo -e "${GREEN}[✓] All required tools are installed!${NC}"
    echo -e "${GREEN}[✓] REX SCAN is ready to use${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Activate virtual environment: source .venv/bin/activate"
    echo "  2. Run a scan: python -m rex_scan --target <IP> --consent"
    exit 0
else
    echo -e "${RED}[✗] Some required tools failed to install${NC}"
    echo ""
    echo "Manual installation instructions:"
    if ! $NMAP_OK; then
        echo "  - nmap: https://nmap.org/download.html"
    fi
    if ! $EXPLOITDB_OK; then
        echo "  - searchsploit: https://www.exploit-db.com/searchsploit"
    fi
    exit 1
fi
