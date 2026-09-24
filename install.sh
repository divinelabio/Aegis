#!/usr/bin/env bash
# ==============================================================================
#  Aegis Web Application Firewall — Unified Universal Installer
#  Usage:
#    git clone https://github.com/divinelabio/aegis.git
#    cd aegis
#    sudo bash install.sh [OPTIONS]
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Colors & Typography (ANSI)
# ------------------------------------------------------------------------------
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ------------------------------------------------------------------------------
# Default Settings
# ------------------------------------------------------------------------------
AEGIS_VERSION="${AEGIS_VERSION:-latest}"
GITHUB_REPO="${AEGIS_REPO:-divinelabio/Aegis}"
DEFAULT_INSTALL_DIR="/opt/aegis"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
PROXY_PORT="${AEGIS_PROXY_PORT:-8080}"
ADMIN_HOST="${AEGIS_ADMIN_HOST:-0.0.0.0}"
ADMIN_PORT="${AEGIS_ADMIN_PORT:-8081}"
ADMIN_USER="${AEGIS_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${AEGIS_ADMIN_PASSWORD:-}"

# Database configurations
POSTGRES_HOST="${AEGIS_CONTROL_DB_HOST:-127.0.0.1}"
POSTGRES_PORT="${AEGIS_CONTROL_DB_PORT:-5432}"
POSTGRES_USER="${AEGIS_CONTROL_DB_USER:-aegis}"
POSTGRES_DB="${AEGIS_CONTROL_DB_NAME:-aegis_control}"
POSTGRES_PASSWORD="${AEGIS_CONTROL_DB_PASSWORD:-}"

CLICKHOUSE_ENABLED=true
CLICKHOUSE_HOST="${AEGIS_ANALYTICS_DB_HOST:-127.0.0.1}"
CLICKHOUSE_PORT="${AEGIS_ANALYTICS_DB_PORT:-9000}"
CLICKHOUSE_USER="${AEGIS_ANALYTICS_DB_USER:-default}"
CLICKHOUSE_DB="${AEGIS_ANALYTICS_DB_NAME:-aegis}"
CLICKHOUSE_PASSWORD="${AEGIS_ANALYTICS_DB_PASSWORD:-}"

JWT_SECRET="${AEGIS_JWT_SECRET:-}"
UPSTREAM_URL="${AEGIS_UPSTREAM_URL:-http://localhost:3000}"
LICENSE_KEY="${AEGIS_LICENSE_KEY:-}"
INSTALL_MODE="${AEGIS_INSTALL_MODE:-}"     # express | interactive
DEPLOY_METHOD="${AEGIS_DEPLOY_METHOD:-}"   # docker | direct
NON_INTERACTIVE=false

# ------------------------------------------------------------------------------
# Logging Functions
# ------------------------------------------------------------------------------
log_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ___    ______ _____ _____ _____ 
   /   |  / ____// ___// ___// ___/ 
  / /| | / __/  / (_ // __/  \__ \  
 / ___ |/ /___  \__ // /___ ___/ /  
/_/  |_/_____/ /___//_____//____/   
   High-Performance Web Application Firewall & Reverse Proxy
EOF
    echo -e "${RESET}"
}

log_step() {
    echo -e "${BLUE}${BOLD}==>${RESET} ${BOLD}$1${RESET}"
}

log_info() {
    echo -e "  ${CYAN}[INFO]${RESET} $1"
}

log_success() {
    echo -e "  ${GREEN}[OK]${RESET} $1"
}

log_warn() {
    echo -e "  ${YELLOW}[WARN]${RESET} ${YELLOW}$1${RESET}"
}

log_error() {
    echo -e "  ${RED}[ERROR]${RESET} ${RED}$1${RESET}" >&2
}

fatal() {
    log_error "$1"
    exit 1
}

# ------------------------------------------------------------------------------
# Helper Utilities
# ------------------------------------------------------------------------------
generate_password() {
    local length="${1:-16}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c "$length"
    else
        head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c "$length"
    fi
}

check_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn | grep -qE ":${port}\b" && return 0 || return 1
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn | grep -qE ":${port}\b" && return 0 || return 1
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i :"$port" >/dev/null 2>&1 && return 0 || return 1
    else
        (timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/${port}") 2>/dev/null && return 0 || return 1
    fi
}

get_public_ip() {
    local ip=""
    ip=$(curl -s4 --max-time 3 https://ifconfig.me 2>/dev/null || true)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || true)
    fi
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    fi
    echo "$ip"
}

ask_user_permission() {
    local prompt_msg="$1"
    local default_val="${2:-Y}"

    if $NON_INTERACTIVE; then
        return 0
    fi

    local response
    read -rp "$prompt_msg [$default_val/$(if [[ "$default_val" == "Y" ]]; then echo "n"; else echo "y"; fi)]: " response </dev/tty || response="$default_val"
    response="${response:-$default_val}"

    if [[ "$response" =~ ^[Yy] ]]; then
        return 0
    else
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "This script must be run as root (or via sudo). Please re-run with: sudo bash $0"
    fi
}

detect_environment() {
    log_step "Detecting system architecture and environment..."

    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    if [[ "$OS" != "linux" ]]; then
        fatal "Aegis automated installer currently supports Linux. Detected: $OS"
    fi

    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) fatal "Unsupported CPU architecture: $ARCH (Only amd64 and arm64 are supported)" ;;
    esac

    log_success "Operating System: Linux (${ARCH})"

    # Check for required basic tools
    for tool in curl tar sudo; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            if ask_user_permission "Required tool '$tool' is missing. Install '$tool' package now?" "Y"; then
                log_info "Installing missing package: $tool..."
                if command -v apt-get >/dev/null 2>&1; then
                    apt-get update -qq && apt-get install -y -qq "$tool" >/dev/null 2>&1
                elif command -v yum >/dev/null 2>&1; then
                    yum install -y -q "$tool" >/dev/null 2>&1
                elif command -v dnf >/dev/null 2>&1; then
                    dnf install -y -q "$tool" >/dev/null 2>&1
                elif command -v apk >/dev/null 2>&1; then
                    apk add --no-cache "$tool" >/dev/null 2>&1
                fi
                log_success "Installed $tool."
            else
                fatal "Cannot continue without required tool: $tool"
            fi
        fi
    done
}

# ------------------------------------------------------------------------------
# Choice: Deployment Method (Docker vs Direct Binary)
# ------------------------------------------------------------------------------
resolve_deploy_method() {
    local docker_available=false
    if command -v docker >/dev/null 2>&1; then
        docker_available=true
    fi

    if [[ -n "$DEPLOY_METHOD" ]]; then
        return 0
    fi

    if $docker_available; then
        log_success "Docker environment detected."
        DEPLOY_METHOD="docker"
    else
        if $NON_INTERACTIVE; then
            log_warn "Docker not detected. Non-interactive mode falling back to direct binary installation."
            DEPLOY_METHOD="direct"
            return 0
        fi

        echo ""
        echo -e "${YELLOW}${BOLD}----------------------------------------------------------------------${RESET}"
        echo -e "${YELLOW}${BOLD}[NOTICE] Docker was not detected on this system.${RESET}"
        echo -e "${YELLOW}${BOLD}----------------------------------------------------------------------${RESET}"
        echo ""
        echo "Please select a deployment method:"
        echo ""
        echo -e "  ${BOLD}[1] Install Docker automatically and deploy Aegis (Recommended)${RESET}"
        echo -e "      ${DIM}Installs official Docker engine & Compose, then boots the isolated stack.${RESET}"
        echo ""
        echo -e "  ${BOLD}[2] Install Aegis directly as a native systemd service (Direct Binary)${RESET}"
        echo -e "      ${DIM}Lightweight bare-metal installation. No containers, zero virtualization overhead.${RESET}"
        echo ""
        echo -e "  ${BOLD}[3] Cancel installation${RESET}"
        echo ""

        read -rp "Enter choice [1-3] (Default: 1): " choice </dev/tty || choice="1"
        choice="${choice:-1}"

        case "$choice" in
            1)
                if ask_user_permission "Proceed with installing Docker Engine from get.docker.com on this system?" "Y"; then
                    log_step "Installing Docker engine..."
                    curl -fsSL https://get.docker.com | sh
                    systemctl enable --now docker
                    DEPLOY_METHOD="docker"
                    log_success "Docker installed and activated."
                else
                    log_warn "Docker installation declined. Falling back to direct binary."
                    DEPLOY_METHOD="direct"
                fi
                ;;
            2)
                DEPLOY_METHOD="direct"
                ;;
            *)
                echo "Installation cancelled."
                exit 0
                ;;
        esac
    fi
}

# ------------------------------------------------------------------------------
# Choice: Installation Mode (Express vs Guided)
# ------------------------------------------------------------------------------
resolve_install_mode() {
    if [[ -n "$INSTALL_MODE" ]]; then
        return 0
    fi

    if $NON_INTERACTIVE; then
        INSTALL_MODE="express"
        return 0
    fi

    echo ""
    echo -e "${CYAN}${BOLD}----------------------------------------------------------------------${RESET}"
    echo -e "${CYAN}${BOLD}Select Installation Mode${RESET}"
    echo -e "${CYAN}${BOLD}----------------------------------------------------------------------${RESET}"
    echo ""
    echo -e "  ${BOLD}[1] Express Setup (Recommended)${RESET}"
    echo -e "      ${DIM}- Automatically generates strong cryptographically random credentials${RESET}"
    echo -e "      ${DIM}- Prompts before installing any missing system services (Postgres/ClickHouse)${RESET}"
    echo -e "      ${DIM}- Fast zero-touch config; prints full credentials summary at completion${RESET}"
    echo ""
    echo -e "  ${BOLD}[2] Guided / Custom Setup${RESET}"
    echo -e "      ${DIM}- Step-by-step interactive configuration${RESET}"
    echo -e "      ${DIM}- Customize admin passwords, ports, upstream target URL, DBs, and license keys${RESET}"
    echo ""

    read -rp "Select mode [1-2] (Default: 1): " mode_choice </dev/tty || mode_choice="1"
    mode_choice="${mode_choice:-1}"

    if [[ "$mode_choice" == "2" ]]; then
        INSTALL_MODE="interactive"
    else
        INSTALL_MODE="express"
    fi
}

# ------------------------------------------------------------------------------
# Direct Mode: Database Resolution with Explicit User Prompts
# ------------------------------------------------------------------------------
resolve_direct_databases() {
    if [[ "$DEPLOY_METHOD" != "direct" ]]; then
        return 0
    fi

    log_step "Checking database requirements for Direct installation..."

    # 1. PostgreSQL (Required for Control Plane)
    local pg_detected=false
    if command -v psql >/dev/null 2>&1 || check_port_in_use 5432; then
        pg_detected=true
    fi

    if $pg_detected; then
        log_success "PostgreSQL service detected on localhost:5432."
    else
        echo ""
        echo -e "${YELLOW}${BOLD}[NOTICE] PostgreSQL is required for the Aegis control plane but was not found on localhost:5432.${RESET}"
        
        if [[ "$INSTALL_MODE" == "express" ]]; then
            if ask_user_permission "Would you like the installer to install and configure PostgreSQL locally on this machine?" "Y"; then
                install_postgresql_local
            else
                echo "Please enter external PostgreSQL connection details:"
                read -rp "  PostgreSQL Host [$POSTGRES_HOST]: " input_pghost </dev/tty; POSTGRES_HOST="${input_pghost:-$POSTGRES_HOST}"
                read -rp "  PostgreSQL Port [$POSTGRES_PORT]: " input_pgport </dev/tty; POSTGRES_PORT="${input_pgport:-$POSTGRES_PORT}"
                read -rp "  PostgreSQL User [$POSTGRES_USER]: " input_pguser </dev/tty; POSTGRES_USER="${input_pguser:-$POSTGRES_USER}"
                read -rp "  PostgreSQL Password: " input_pgpass </dev/tty; POSTGRES_PASSWORD="$input_pgpass"
            fi
        else
            echo "How would you like to configure the PostgreSQL control database?"
            echo "  [1] Install and configure PostgreSQL locally on this machine"
            echo "  [2] Connect to an existing external PostgreSQL database"
            echo "  [3] Cancel installation"
            read -rp "Enter choice [1-3] (Default: 1): " pg_choice </dev/tty || pg_choice="1"
            pg_choice="${pg_choice:-1}"

            case "$pg_choice" in
                1)
                    install_postgresql_local
                    ;;
                2)
                    read -rp "  PostgreSQL Host [$POSTGRES_HOST]: " input_pghost </dev/tty; POSTGRES_HOST="${input_pghost:-$POSTGRES_HOST}"
                    read -rp "  PostgreSQL Port [$POSTGRES_PORT]: " input_pgport </dev/tty; POSTGRES_PORT="${input_pgport:-$POSTGRES_PORT}"
                    read -rp "  PostgreSQL Database [$POSTGRES_DB]: " input_pgdb </dev/tty; POSTGRES_DB="${input_pgdb:-$POSTGRES_DB}"
                    read -rp "  PostgreSQL Username [$POSTGRES_USER]: " input_pguser </dev/tty; POSTGRES_USER="${input_pguser:-$POSTGRES_USER}"
                    read -rp "  PostgreSQL Password: " input_pgpass </dev/tty; POSTGRES_PASSWORD="$input_pgpass"
                    ;;
                *)
                    echo "Installation cancelled."
                    exit 0
                    ;;
            esac
        fi
    fi

    # 2. ClickHouse (Analytics Store)
    local ch_detected=false
    if command -v clickhouse-client >/dev/null 2>&1 || check_port_in_use 9000; then
        ch_detected=true
    fi

    if $ch_detected; then
        log_success "ClickHouse service detected on localhost:9000."
    else
        echo ""
        echo -e "${YELLOW}${BOLD}[NOTICE] ClickHouse was not found on localhost:9000 (used for high-performance traffic analytics).${RESET}"
        
        if [[ "$INSTALL_MODE" == "express" ]]; then
            if ask_user_permission "Would you like the installer to install ClickHouse locally on this machine?" "Y"; then
                install_clickhouse_local
            else
                log_info "ClickHouse installation skipped. Running in core WAF mode (analytics disabled)."
                CLICKHOUSE_ENABLED=false
            fi
        else
            echo "How would you like to configure ClickHouse analytics?"
            echo "  [1] Install and configure ClickHouse locally on this machine"
            echo "  [2] Connect to an existing external ClickHouse database"
            echo "  [3] Disable Analytics (Run Aegis in core WAF mode without ClickHouse)"
            read -rp "Enter choice [1-3] (Default: 1): " ch_choice </dev/tty || ch_choice="1"
            ch_choice="${ch_choice:-1}"

            case "$ch_choice" in
                1)
                    install_clickhouse_local
                    ;;
                2)
                    read -rp "  ClickHouse Host [$CLICKHOUSE_HOST]: " input_chhost </dev/tty; CLICKHOUSE_HOST="${input_chhost:-$CLICKHOUSE_HOST}"
                    read -rp "  ClickHouse Port [$CLICKHOUSE_PORT]: " input_chport </dev/tty; CLICKHOUSE_PORT="${input_chport:-$CLICKHOUSE_PORT}"
                    read -rp "  ClickHouse Database [$CLICKHOUSE_DB]: " input_chdb </dev/tty; CLICKHOUSE_DB="${input_chdb:-$CLICKHOUSE_DB}"
                    read -rp "  ClickHouse Username [$CLICKHOUSE_USER]: " input_chuser </dev/tty; CLICKHOUSE_USER="${input_chuser:-$CLICKHOUSE_USER}"
                    read -rp "  ClickHouse Password: " input_chpass </dev/tty; CLICKHOUSE_PASSWORD="$input_chpass"
                    CLICKHOUSE_ENABLED=true
                    ;;
                *)
                    log_info "Analytics disabled."
                    CLICKHOUSE_ENABLED=false
                    ;;
            esac
        fi
    fi
}

install_postgresql_local() {
    log_step "Installing PostgreSQL locally on host..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq postgresql postgresql-contrib >/dev/null 2>&1
        systemctl enable --now postgresql
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q postgresql-server postgresql-contrib >/dev/null 2>&1
        postgresql-setup --initdb || true
        systemctl enable --now postgresql
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q postgresql-server postgresql-contrib >/dev/null 2>&1
        postgresql-setup --initdb || true
        systemctl enable --now postgresql
    fi

    # Helper to run SQL commands as postgres user universally
    run_as_postgres() {
        local sql="$1"
        if command -v runuser >/dev/null 2>&1; then
            runuser -u postgres -- psql -c "$sql"
        elif command -v sudo >/dev/null 2>&1; then
            sudo -u postgres psql -c "$sql"
        else
            su - postgres -c "psql -c \"$sql\""
        fi
    }

    # Set up user and database
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(generate_password 24)}"
    run_as_postgres "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>/dev/null || \
    run_as_postgres "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>/dev/null || true
    run_as_postgres "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};" 2>/dev/null || true
    run_as_postgres "GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_USER};" 2>/dev/null || true

    POSTGRES_HOST="127.0.0.1"
    POSTGRES_PORT="5432"
    log_success "PostgreSQL installed, user '${POSTGRES_USER}' and database '${POSTGRES_DB}' initialized."
}

install_clickhouse_local() {
    log_step "Installing ClickHouse locally on host..."
    CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-$(generate_password 24)}"
    
    if command -v apt-get >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        curl -fsSL 'https://clickhouse.com/' | sh
        ./clickhouse install -y 2>/dev/null || ./clickhouse install --noninteractive 2>/dev/null || true

        # Ensure ClickHouse user config directory exists and configure password for default user
        mkdir -p /etc/clickhouse-server/users.d
        cat << CH_PASS_EOF > /etc/clickhouse-server/users.d/aegis_user.xml
<clickhouse>
    <users>
        <default>
            <password>${CLICKHOUSE_PASSWORD}</password>
            <networks>
                <ip>::/0</ip>
            </networks>
        </default>
    </users>
</clickhouse>
CH_PASS_EOF
        chown -R clickhouse:clickhouse /etc/clickhouse-server/users.d 2>/dev/null || true

        # Ensure systemd service exists and is enabled
        if [[ ! -f /etc/systemd/system/clickhouse-server.service && ! -f /lib/systemd/system/clickhouse-server.service ]]; then
            cat << 'CH_SVC_EOF' > /etc/systemd/system/clickhouse-server.service
[Unit]
Description=ClickHouse Server (analytics DBMS for big data)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clickhouse
Group=clickhouse
RuntimeDirectory=clickhouse-server
ExecStart=/usr/bin/clickhouse-server --config-file=/etc/clickhouse-server/config.xml --pid-file=/run/clickhouse-server/clickhouse-server.pid
Restart=always
RestartSec=3
LimitNOFILE=500000

[Install]
WantedBy=multi-user.target
CH_SVC_EOF
            systemctl daemon-reload 2>/dev/null || true
        fi

        systemctl enable --now clickhouse-server || clickhouse start || true

        # Verify ClickHouse connectivity and initialize database
        log_info "Verifying ClickHouse connectivity and ensuring database '${CLICKHOUSE_DB}' exists..."
        local ch_ready=false
        for i in {1..20}; do
            if clickhouse-client --password "${CLICKHOUSE_PASSWORD}" --query "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB};" >/dev/null 2>&1; then
                ch_ready=true
                break
            elif clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB};" >/dev/null 2>&1; then
                ch_ready=true
                break
            fi
            sleep 1
        done
        if $ch_ready; then
            log_success "ClickHouse analytics database initialized."
        fi
    fi

    CLICKHOUSE_HOST="127.0.0.1"
    CLICKHOUSE_PORT="9000"
    CLICKHOUSE_ENABLED=true
    log_success "ClickHouse installed, configured, and started."
}

# ------------------------------------------------------------------------------
# Configuration Gathering
# ------------------------------------------------------------------------------
configure_parameters() {
    # If Aegis service is already installed and running, stop it temporarily so ports are freed
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet aegis 2>/dev/null || systemctl is-active --quiet aegis-updater 2>/dev/null; then
            log_info "Stopping existing Aegis services to liberate ports for installation/upgrade..."
            systemctl stop aegis aegis-updater 2>/dev/null || true
        fi
    fi

    # Generate common secrets if empty
    ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(generate_password 16)}"
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(generate_password 24)}"
    CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-$(generate_password 24)}"
    JWT_SECRET="${JWT_SECRET:-$(generate_password 32)}"

    if [[ "$INSTALL_MODE" == "express" ]]; then
        log_step "Configuring Express Mode (Auto-generating secure credentials)..."

        # Validate standard ports; find alternatives if taken
        if check_port_in_use "$PROXY_PORT"; then
            log_warn "Proxy port $PROXY_PORT is already in use. Selecting 8082..."
            PROXY_PORT=8082
        fi
        if check_port_in_use "$ADMIN_PORT"; then
            log_warn "Admin port $ADMIN_PORT is already in use. Selecting 8083..."
            ADMIN_PORT=8083
        fi

        log_success "Configuration and credentials generated successfully."
    else
        log_step "Guided Configuration Wizard"
        echo ""

        # 1. Install Directory
        read -rp "1. Installation Directory [$INSTALL_DIR]: " input_dir </dev/tty
        INSTALL_DIR="${input_dir:-$INSTALL_DIR}"

        # 2. Proxy Port
        while true; do
            read -rp "2. Public Proxy / WAF Port [$PROXY_PORT]: " input_proxy </dev/tty
            input_proxy="${input_proxy:-$PROXY_PORT}"
            if check_port_in_use "$input_proxy"; then
                log_warn "Port $input_proxy is currently in use by another process. Please enter a different port."
            else
                PROXY_PORT="$input_proxy"
                break
            fi
        done

        # 3. Admin Port
        while true; do
            read -rp "3. Admin Management Console Port [$ADMIN_PORT]: " input_admin </dev/tty
            input_admin="${input_admin:-$ADMIN_PORT}"
            if [[ "$input_admin" == "$PROXY_PORT" ]]; then
                log_warn "Admin port cannot be the same as Proxy port ($PROXY_PORT)."
            elif check_port_in_use "$input_admin"; then
                log_warn "Port $input_admin is currently in use by another process. Please enter a different port."
            else
                ADMIN_PORT="$input_admin"
                break
            fi
        done

        # 4. Admin Username & Password
        read -rp "4. Admin Username [$ADMIN_USER]: " input_user </dev/tty
        ADMIN_USER="${input_user:-$ADMIN_USER}"

        read -rp "5. Admin Password (Press Enter to auto-generate a secure password): " input_pass </dev/tty
        if [[ -n "$input_pass" ]]; then
            ADMIN_PASSWORD="$input_pass"
        fi

        # 6. Upstream Protected Application Target
        read -rp "6. Upstream Target Application URL [$UPSTREAM_URL]: " input_upstream </dev/tty
        UPSTREAM_URL="${input_upstream:-$UPSTREAM_URL}"

        # 7. Enterprise License Key (optional)
        read -rp "7. License Key (Optional - leave empty for Community edition): " input_lic </dev/tty
        LICENSE_KEY="${input_lic:-$LICENSE_KEY}"

        echo ""
        echo -e "${CYAN}${BOLD}Configuration Summary:${RESET}"
        echo -e "  - Install Path   : ${INSTALL_DIR}"
        echo -e "  - Deploy Method  : ${DEPLOY_METHOD}"
        echo -e "  - Proxy Port     : ${PROXY_PORT}"
        echo -e "  - Admin Port     : ${ADMIN_PORT}"
        echo -e "  - Admin User     : ${ADMIN_USER}"
        echo -e "  - Upstream Target: ${UPSTREAM_URL}"
        if [[ -n "$LICENSE_KEY" ]]; then
            echo -e "  - License        : ${LICENSE_KEY:0:8}... (Enterprise)"
        else
            echo -e "  - Edition        : Community"
        fi
        echo ""

        if ! ask_user_permission "Proceed with installation using these settings?" "Y"; then
            echo "Installation aborted."
            exit 0
        fi
    fi
}

# ------------------------------------------------------------------------------
# Deployment: Docker Compose
# ------------------------------------------------------------------------------
deploy_docker_stack() {
    log_step "Deploying Aegis stack via Docker Compose..."
    mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
    cd "${INSTALL_DIR}"

    # Write docker-compose.yml
    cat << 'COMPOSE_EOF' > docker-compose.yml
version: '3.8'

services:
  aegis:
    image: ${AEGIS_IMAGE:-ghcr.io/divinelabio/aegis}:${AEGIS_VERSION:-latest}
    container_name: aegis
    restart: unless-stopped
    ports:
      - "${SERVER_PORT:-8080}:8080"
      - "${SERVER_ADMIN_PORT:-8081}:8081"
    environment:
      - AEGIS_ADMIN_PASSWORD=${AEGIS_ADMIN_PASSWORD}
      - AEGIS_CONTROL_DB_PASSWORD=${AEGIS_CONTROL_DB_PASSWORD}
      - AEGIS_ANALYTICS_DB_PASSWORD=${AEGIS_ANALYTICS_DB_PASSWORD}
      - AEGIS_JWT_SECRET=${AEGIS_JWT_SECRET}
      - AEGIS_DEV_MODE=${AEGIS_DEV_MODE:-enterprise}
      - AEGIS_LICENSE_KEY=${AEGIS_LICENSE_KEY:-}
    volumes:
      - ./config.yaml:/var/lib/aegis/config.yaml:ro
      - ./data:/var/lib/aegis/data
      - ./logs:/var/lib/aegis/logs
    depends_on:
      clickhouse:
        condition: service_healthy
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  postgres:
    image: docker.io/library/postgres:16-alpine
    container_name: aegis_postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: aegis_control
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: ${AEGIS_CONTROL_DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis -d aegis_control"]
      interval: 5s
      timeout: 3s
      retries: 10

  clickhouse:
    image: docker.io/clickhouse/clickhouse-server:25.8
    container_name: aegis_clickhouse
    restart: unless-stopped
    environment:
      CLICKHOUSE_DB: aegis
      CLICKHOUSE_USER: default
      CLICKHOUSE_PASSWORD: ${AEGIS_ANALYTICS_DB_PASSWORD}
    volumes:
      - clickhouse_data:/var/lib/clickhouse
    healthcheck:
      test: ["CMD", "clickhouse-client", "--password", "${AEGIS_ANALYTICS_DB_PASSWORD}", "--query", "SELECT 1"]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: docker.io/library/redis:7-alpine
    container_name: aegis_redis
    restart: unless-stopped
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  postgres_data:
  clickhouse_data:
  redis_data:
COMPOSE_EOF

    # Write .env file
    cat << ENV_EOF > .env
SERVER_PORT=${PROXY_PORT}
SERVER_ADMIN_PORT=${ADMIN_PORT}
AEGIS_IMAGE=${AEGIS_IMAGE:-ghcr.io/divinelabio/aegis}
AEGIS_VERSION=${AEGIS_VERSION:-latest}
AEGIS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
AEGIS_CONTROL_DB_PASSWORD=${POSTGRES_PASSWORD}
AEGIS_ANALYTICS_DB_PASSWORD=${CLICKHOUSE_PASSWORD}
AEGIS_JWT_SECRET=${JWT_SECRET}
AEGIS_DEV_MODE=enterprise
AEGIS_LICENSE_KEY=${LICENSE_KEY}
ENV_EOF
    chmod 600 .env

    # Write minimal config.yaml
    cat << CONFIG_EOF > config.yaml
server:
  port: 8080
  admin:
    host: "0.0.0.0"
    port: 8081
    setup_completed: true
    secure_cookies: true

storage:
  control:
    enabled: true
    driver: postgresql
    host: postgres
    port: 5432
    database: aegis_control
    username: aegis
    password_secret_ref: env:AEGIS_CONTROL_DB_PASSWORD
    ssl_mode: disable
  analytics:
    enabled: true
    mode: optional
    host: clickhouse
    port: 9000
    database: aegis
    username: default
    password_secret_ref: env:AEGIS_ANALYTICS_DB_PASSWORD
    secure: false

upstream:
  target: ${UPSTREAM_URL}
CONFIG_EOF

    log_info "Pulling container images and launching services..."
    docker compose pull --quiet
    docker compose up -d

    log_info "Waiting for services to become healthy..."
    local attempts=0
    local max_attempts=30
    while [[ $attempts -lt $max_attempts ]]; do
        if (curl -s "http://127.0.0.1:${ADMIN_PORT}/" >/dev/null 2>&1) || (docker compose ps aegis 2>/dev/null | grep -q "Up"); then
            break
        fi
        sleep 2
        attempts=$((attempts + 1))
    done

    log_success "Docker stack deployed and operational."
}

# ------------------------------------------------------------------------------
# Deployment: Direct Native Binary (Systemd)
# ------------------------------------------------------------------------------
deploy_direct_binary() {
    log_step "Installing Aegis direct binary onto host system..."
    mkdir -p "${INSTALL_DIR}/releases/initial" "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" /etc/aegis /var/lib/aegis
    ln -sfn "${INSTALL_DIR}/releases/initial" "${INSTALL_DIR}/current"

    # Create dedicated system user/group for security isolation
    if ! id -u aegis >/dev/null 2>&1; then
        useradd -r -s /bin/false -d "${INSTALL_DIR}" -M aegis || true
    fi

    local bin_dest="${INSTALL_DIR}/releases/initial/aegis"
    local updater_dest="${INSTALL_DIR}/aegis-updater"
    local ctl_dest="${INSTALL_DIR}/aegisctl"
    local symlink_server="/usr/local/bin/aegis"
    local symlink_updater="/usr/local/bin/aegis-updater"
    local symlink_ctl="/usr/local/bin/aegisctl"

    # Stop existing services and unlink destination binaries to prevent 'Text file busy'
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop aegis aegis-updater 2>/dev/null || true
    fi
    rm -f "$bin_dest" "$updater_dest" "$ctl_dest" 2>/dev/null || true

    # Download or copy binary
    local release_base="https://github.com/${GITHUB_REPO}/releases/latest/download"
    log_info "Downloading or locating Aegis binary (${ARCH})..."
    
    local found_server=false
    if curl -fsSL "${release_base}/aegis-linux-${ARCH}.tar.gz" -o "/tmp/aegis.tar.gz" 2>/dev/null; then
        tar -xzf "/tmp/aegis.tar.gz" -C "${INSTALL_DIR}/releases/initial/"
        rm -f "/tmp/aegis.tar.gz"
        found_server=true
    elif curl -fsSL "${release_base}/aegis-linux-${ARCH}" -o "$bin_dest" 2>/dev/null; then
        found_server=true
    fi

    if ! $found_server; then
        log_warn "Remote binary download skipped. Checking for local binary..."
        local search_paths=(
            "./aegis"
            "./bin/aegis"
            "./bin/linux_${ARCH}/aegis"
            "./bin/linux-${ARCH}/aegis"
            "../bin/aegis"
            "../bin/linux_${ARCH}/aegis"
            "../bin/linux-${ARCH}/aegis"
            "$(dirname "$0")/../aegis"
            "$(dirname "$0")/../bin/aegis"
            "$(dirname "$0")/../bin/linux_${ARCH}/aegis"
            "/home/aegis/aegis-community/bin/linux_${ARCH}/aegis"
            "/home/aegis/aegis-community/aegis"
        )
        for candidate in "${search_paths[@]}"; do
            if [[ -f "$candidate" ]]; then
                log_info "Found local Aegis binary at: $candidate"
                install -m 755 "$candidate" "$bin_dest" 2>/dev/null || cp -f "$candidate" "$bin_dest"
                found_server=true
                break
            fi
        done
    fi

    if [[ ! -f "$bin_dest" ]]; then
        fatal "Aegis binary was not found at '$bin_dest' and could not be downloaded from GitHub releases ($release_base). Please ensure network connectivity to GitHub or place the pre-built 'aegis' binary in the current directory."
    fi

    # Check for or copy aegis-updater
    local search_updater=(
        "./aegis-updater"
        "./bin/aegis-updater"
        "./bin/linux_${ARCH}/aegis-updater"
        "./bin/linux-${ARCH}/aegis-updater"
        "../bin/aegis-updater"
        "../bin/linux_${ARCH}/aegis-updater"
        "$(dirname "$0")/../aegis-updater"
        "$(dirname "$0")/../bin/linux_${ARCH}/aegis-updater"
        "/home/aegis/aegis-community/bin/linux_${ARCH}/aegis-updater"
        "/home/aegis/aegis-community/aegis-updater"
    )
    for candidate_up in "${search_updater[@]}"; do
        if [[ -f "$candidate_up" ]]; then
            install -m 755 "$candidate_up" "$updater_dest" 2>/dev/null || cp -f "$candidate_up" "$updater_dest"
            break
        fi
    done
    if [[ ! -f "$updater_dest" ]]; then
        curl -fsSL "${release_base}/aegis-updater-linux-${ARCH}" -o "$updater_dest" 2>/dev/null || true
    fi

    # Check for or copy aegisctl
    local search_ctl=(
        "./aegisctl"
        "./bin/aegisctl"
        "./bin/linux_${ARCH}/aegisctl"
        "./bin/linux-${ARCH}/aegisctl"
        "../bin/aegisctl"
        "../bin/linux_${ARCH}/aegisctl"
        "$(dirname "$0")/../aegisctl"
        "$(dirname "$0")/../bin/linux_${ARCH}/aegisctl"
        "/home/aegis/aegis-community/bin/linux_${ARCH}/aegisctl"
        "/home/aegis/aegis-community/aegisctl"
    )
    for candidate_ctl in "${search_ctl[@]}"; do
        if [[ -f "$candidate_ctl" ]]; then
            install -m 755 "$candidate_ctl" "$ctl_dest" 2>/dev/null || cp -f "$candidate_ctl" "$ctl_dest"
            break
        fi
    done
    if [[ ! -f "$ctl_dest" ]]; then
        curl -fsSL "${release_base}/aegisctl-linux-${ARCH}" -o "$ctl_dest" 2>/dev/null || true
    fi

    chmod +x "$bin_dest" "$updater_dest" "$ctl_dest" 2>/dev/null || true
    ln -sf "${INSTALL_DIR}/current/aegis" "$symlink_server" 2>/dev/null || true
    ln -sf "$updater_dest" "$symlink_updater" 2>/dev/null || true
    ln -sf "$ctl_dest" "$symlink_ctl" 2>/dev/null || true

    # Grant low port binding capability (80, 443) to aegis
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' "$bin_dest" 2>/dev/null || true
    fi

    # Deploy web administration console assets
    log_info "Deploying web administration console assets..."
    local search_web=(
        "./web"
        "../web"
        "$(dirname "$0")/web"
        "$(dirname "$0")/../web"
        "/home/aegis/aegis-community/web"
    )
    local found_web=false
    for candidate_web in "${search_web[@]}"; do
        if [[ -d "$candidate_web" ]]; then
            log_info "Found web assets at: $candidate_web"
            cp -r "$candidate_web" "${INSTALL_DIR}/"
            found_web=true
            break
        fi
    done
    if ! $found_web; then
        log_warn "Web assets directory was not found in common locations. Admin API will function, but web static files may need to be placed in ${INSTALL_DIR}/web."
    fi

    # Deploy WAF rules (OWASP CRS and custom rules)
    log_info "Deploying WAF rules signatures..."
    local search_rules=(
        "./data/rules"
        "./rules"
        "../data/rules"
        "../rules"
        "$(dirname "$0")/data/rules"
        "$(dirname "$0")/rules"
        "$(dirname "$0")/../data/rules"
        "$(dirname "$0")/../rules"
        "/home/aegis/aegis-community/data/rules"
        "/home/aegis/aegis-community/rules"
    )
    local found_rules=false
    for candidate_rules in "${search_rules[@]}"; do
        if [[ -d "$candidate_rules" ]]; then
            log_info "Found WAF rules at: $candidate_rules"
            mkdir -p "${INSTALL_DIR}/data"
            cp -r "$candidate_rules" "${INSTALL_DIR}/data/"
            ln -sfn "${INSTALL_DIR}/data/rules" "${INSTALL_DIR}/rules" 2>/dev/null || true
            found_rules=true
            break
        fi
    done
    if ! $found_rules; then
        log_warn "WAF rules directory was not found in common locations. Coraza CRS rules may need to be placed in ${INSTALL_DIR}/data/rules."
    fi

    # Set ownership
    chown -R aegis:aegis "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/web" "${INSTALL_DIR}/rules" /var/lib/aegis 2>/dev/null || true
    chown -R root:aegis "${INSTALL_DIR}/releases" "${INSTALL_DIR}/current" 2>/dev/null || true

    # Ensure local PostgreSQL database and credentials match configuration
    if [[ "$POSTGRES_HOST" == "127.0.0.1" || "$POSTGRES_HOST" == "localhost" ]] && command -v psql >/dev/null 2>&1; then
        run_as_postgres() {
            local sql="$1"
            if command -v runuser >/dev/null 2>&1; then
                runuser -u postgres -- psql -c "$sql"
            elif command -v sudo >/dev/null 2>&1; then
                sudo -u postgres psql -c "$sql"
            else
                su - postgres -c "psql -c \"$sql\""
            fi
        }
        run_as_postgres "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>/dev/null || \
        run_as_postgres "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';" 2>/dev/null || true
        run_as_postgres "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};" 2>/dev/null || true
        run_as_postgres "GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_USER};" 2>/dev/null || true
    fi

    # Ensure local ClickHouse database and credentials match configuration
    if $CLICKHOUSE_ENABLED && [[ "$CLICKHOUSE_HOST" == "127.0.0.1" || "$CLICKHOUSE_HOST" == "localhost" ]]; then
        if [[ -d /etc/clickhouse-server ]]; then
            mkdir -p /etc/clickhouse-server/users.d
            cat << CH_PASS_EOF > /etc/clickhouse-server/users.d/aegis_user.xml
<clickhouse>
    <users>
        <default>
            <password>${CLICKHOUSE_PASSWORD}</password>
            <networks>
                <ip>::/0</ip>
            </networks>
        </default>
    </users>
</clickhouse>
CH_PASS_EOF
            chown -R clickhouse:clickhouse /etc/clickhouse-server/users.d 2>/dev/null || true
            systemctl restart clickhouse-server 2>/dev/null || true
            sleep 2
        fi
        (clickhouse-client --password "${CLICKHOUSE_PASSWORD}" --query "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB};" 2>/dev/null || \
         clickhouse-client --query "CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DB};" 2>/dev/null || true)
    fi

    # Write Environment File
    cat << ENV_EOF > /etc/aegis/aegis.env
AEGIS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
AEGIS_CONTROL_DB_PASSWORD=${POSTGRES_PASSWORD}
AEGIS_ANALYTICS_DB_PASSWORD=${CLICKHOUSE_PASSWORD}
AEGIS_JWT_SECRET=${JWT_SECRET}
SERVER_PORT=${PROXY_PORT}
SERVER_ADMIN_PORT=${ADMIN_PORT}
AEGIS_LICENSE_KEY=${LICENSE_KEY}
ENV_EOF
    chmod 600 /etc/aegis/aegis.env

    # Determine secure cookies setting based on admin bind address
    local admin_secure_cookies=false
    if [[ "$ADMIN_HOST" != "127.0.0.1" && "$ADMIN_HOST" != "localhost" ]]; then
        admin_secure_cookies=true
    fi

    # Write Config with updater configuration for in-place upgrades
    cat << CONFIG_EOF > /etc/aegis/config.yaml
server:
  port: ${PROXY_PORT}
  admin:
    host: "${ADMIN_HOST}"
    port: ${ADMIN_PORT}
    setup_completed: true
    secure_cookies: ${admin_secure_cookies}

updater:
  socket_path: /run/aegis/updater.sock

storage:
  control:
    enabled: true
    driver: postgresql
    host: ${POSTGRES_HOST}
    port: ${POSTGRES_PORT}
    database: ${POSTGRES_DB}
    username: ${POSTGRES_USER}
    password_secret_ref: env:AEGIS_CONTROL_DB_PASSWORD
    ssl_mode: disable
  analytics:
    enabled: ${CLICKHOUSE_ENABLED}
    mode: optional
    host: ${CLICKHOUSE_HOST}
    port: ${CLICKHOUSE_PORT}
    database: ${CLICKHOUSE_DB}
    username: ${CLICKHOUSE_USER}
    password_secret_ref: env:AEGIS_ANALYTICS_DB_PASSWORD
    secure: false

upstream:
  target: ${UPSTREAM_URL}
CONFIG_EOF

    # Setup Systemd Services (both aegis-server and aegis-updater)
    if command -v systemctl >/dev/null 2>&1; then
        cat << SYSTEMD_EOF > /etc/systemd/system/aegis.service
[Unit]
Description=Aegis Web Application Firewall & Reverse Proxy
Documentation=https://github.com/${GITHUB_REPO}
After=network.target remote-fs.target
Wants=network-online.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-/etc/aegis/aegis.env
EnvironmentFile=-/etc/aegis/release.env
ExecStart=${INSTALL_DIR}/current/aegis run --config /etc/aegis/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3s
LimitNOFILE=65535
TimeoutStopSec=30s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
RuntimeDirectory=aegis
RuntimeDirectoryMode=0775

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

        cat << UPDATER_EOF > /etc/systemd/system/aegis-updater.service
[Unit]
Description=Aegis Maintenance and In-Place Upgrade Daemon
Documentation=https://github.com/${GITHUB_REPO}
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/aegis-updater serve --config /etc/aegis/config.yaml
Restart=on-failure
RestartSec=5s
RuntimeDirectory=aegis
RuntimeDirectoryMode=0775

[Install]
WantedBy=multi-user.target
        systemctl daemon-reload
        systemctl enable aegis-updater 2>/dev/null || true
        systemctl restart aegis-updater 2>/dev/null || systemctl start aegis-updater || true
        systemctl enable aegis 2>/dev/null || true
        systemctl restart aegis 2>/dev/null || systemctl start aegis || true

        log_info "Waiting for Aegis service to initialize..."
        local attempts=0
        local max_attempts=15
        local started=false
        while [[ $attempts -lt $max_attempts ]]; do
            if systemctl is-active --quiet aegis; then
                started=true
                break
            fi
            sleep 1
            attempts=$((attempts + 1))
        done

        if $started; then
            log_success "Systemd services (aegis & aegis-updater) created, started, and verified active."
        else
            log_warn "Aegis service did not start immediately. Check status with: systemctl status aegis"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Save Credentials & Print Full Summary
# ------------------------------------------------------------------------------
finalize_installation() {
    local creds_file="${INSTALL_DIR}/credentials.txt"
    local public_ip
    public_ip=$(get_public_ip)

    cat << CREDS_EOF > "$creds_file"
================================================================================
 Aegis Web Application Firewall -- Credentials & Access Information
 Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
================================================================================

[1] ADMIN CONSOLE:
  URL          : http://${public_ip}:${ADMIN_PORT} (or http://localhost:${ADMIN_PORT})
  Username     : ${ADMIN_USER}
  Password     : ${ADMIN_PASSWORD}

[2] WAF PROXY & ROUTING:
  Protected URL: http://${public_ip}:${PROXY_PORT} (or http://localhost:${PROXY_PORT})
  Upstream URL : ${UPSTREAM_URL}

[3] DATABASE CREDENTIALS:
  Control Database (PostgreSQL):
    Host       : $(if [[ "$DEPLOY_METHOD" == "docker" ]]; then echo "postgres (internal) / localhost:5432"; else echo "${POSTGRES_HOST}:${POSTGRES_PORT}"; fi)
    Database   : ${POSTGRES_DB}
    Username   : ${POSTGRES_USER}
    Password   : ${POSTGRES_PASSWORD}
  
  Analytics Database (ClickHouse):
    Status     : $(if $CLICKHOUSE_ENABLED; then echo "Enabled"; else echo "Disabled (Core WAF mode)"; fi)
    Host       : $(if [[ "$DEPLOY_METHOD" == "docker" ]]; then echo "clickhouse (internal) / localhost:9000"; else echo "${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"; fi)
    Database   : ${CLICKHOUSE_DB}
    Username   : ${CLICKHOUSE_USER}
    Password   : ${CLICKHOUSE_PASSWORD}

[4] SECURITY & SIGNING KEYS:
  JWT Secret   : ${JWT_SECRET}
  License Key  : $(if [[ -n "$LICENSE_KEY" ]]; then echo "$LICENSE_KEY"; else echo "Community Edition (None)"; fi)

[5] INSTALLATION PATHS:
  Install Dir  : ${INSTALL_DIR}
  Deploy Type  : ${DEPLOY_METHOD}
  Config File  : ${INSTALL_DIR}/config.yaml (or /etc/aegis/config.yaml)
  Env File     : $(if [[ "$DEPLOY_METHOD" == "docker" ]]; then echo "${INSTALL_DIR}/.env"; else echo "/etc/aegis/aegis.env"; fi)

[6] SERVICE COMMANDS:
$(if [[ "$DEPLOY_METHOD" == "docker" ]]; then
    echo "  Status       : cd ${INSTALL_DIR} && docker compose ps"
    echo "  Logs         : cd ${INSTALL_DIR} && docker compose logs -f"
    echo "  Restart      : cd ${INSTALL_DIR} && docker compose restart"
    echo "  Stop         : cd ${INSTALL_DIR} && docker compose down"
else
    echo "  Status       : sudo systemctl status aegis"
    echo "  Logs         : sudo journalctl -u aegis -f"
    echo "  Restart      : sudo systemctl restart aegis"
    echo "  Stop         : sudo systemctl stop aegis"
fi)
================================================================================
CREDS_EOF
    chmod 600 "$creds_file"

    echo ""
    echo -e "${GREEN}${BOLD}======================================================================${RESET}"
    echo -e "${GREEN}${BOLD}   Aegis WAF installation completed successfully                      ${RESET}"
    echo -e "${GREEN}${BOLD}======================================================================${RESET}"
    echo ""
    echo -e "${CYAN}${BOLD}[1] ADMIN CONSOLE${RESET}"
    echo -e "  URL          : ${CYAN}${BOLD}http://${public_ip}:${ADMIN_PORT}${RESET} ${DIM}(or http://localhost:${ADMIN_PORT})${RESET}"
    echo -e "  Username     : ${ADMIN_USER}"
    echo -e "  Password     : ${YELLOW}${BOLD}${ADMIN_PASSWORD}${RESET}"
    echo ""
    echo -e "${CYAN}${BOLD}[2] WAF PROXY & ROUTING${RESET}"
    echo -e "  Proxy URL    : ${CYAN}http://${public_ip}:${PROXY_PORT}${RESET}"
    echo -e "  Upstream     : ${UPSTREAM_URL}"
    echo ""
    echo -e "${CYAN}${BOLD}[3] INTERNAL DATABASE CREDENTIALS${RESET}"
    echo -e "  PostgreSQL Control DB :"
    echo -e "    Host       : $(if [[ "$DEPLOY_METHOD" == "docker" ]]; then echo "postgres:5432 (container)"; else echo "${POSTGRES_HOST}:${POSTGRES_PORT}"; fi)"
    echo -e "    Database   : ${POSTGRES_DB}"
    echo -e "    Username   : ${POSTGRES_USER}"
    echo -e "    Password   : ${YELLOW}${BOLD}${POSTGRES_PASSWORD}${RESET}"
    if $CLICKHOUSE_ENABLED; then
        echo -e "  ClickHouse Analytics  :"
        echo -e "    Host       : $(if [[ "$DEPLOY_METHOD" == "docker" ]]; then echo "clickhouse:9000 (container)"; else echo "${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"; fi)"
        echo -e "    Database   : ${CLICKHOUSE_DB}"
        echo -e "    Username   : ${CLICKHOUSE_USER}"
        echo -e "    Password   : ${YELLOW}${BOLD}${CLICKHOUSE_PASSWORD}${RESET}"
    else
        echo -e "  ClickHouse Analytics  : ${DIM}Disabled (Running in Core WAF Mode)${RESET}"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}[4] SECURITY & SECRETS${RESET}"
    echo -e "  JWT Secret   : ${YELLOW}${BOLD}${JWT_SECRET}${RESET}"
    if [[ -n "$LICENSE_KEY" ]]; then
        echo -e "  License Key  : ${LICENSE_KEY}"
    fi
    echo ""
    echo -e "${CYAN}${BOLD}[5] SYSTEM FILES & CREDENTIALS BACKUP${RESET}"
    echo -e "  Install Path : ${INSTALL_DIR}"
    echo -e "  Secrets File : ${DIM}${creds_file}${RESET} ${DIM}(chmod 600 - safe from unauthorized users)${RESET}"
    echo ""
    echo -e "${CYAN}${BOLD}[6] SERVICE MANAGEMENT${RESET}"
    if [[ "$DEPLOY_METHOD" == "docker" ]]; then
        echo -e "  - Check status : ${CYAN}cd ${INSTALL_DIR} && docker compose ps${RESET}"
        echo -e "  - View logs    : ${CYAN}cd ${INSTALL_DIR} && docker compose logs -f${RESET}"
        echo -e "  - Restart      : ${CYAN}cd ${INSTALL_DIR} && docker compose restart${RESET}"
    else
        echo -e "  - Check status : ${CYAN}sudo systemctl status aegis${RESET}"
        echo -e "  - View logs    : ${CYAN}sudo journalctl -u aegis -f${RESET}"
        echo -e "  - Restart      : ${CYAN}sudo systemctl restart aegis${RESET}"
    fi
    echo -e "${GREEN}${BOLD}======================================================================${RESET}"
    echo ""
}

# ------------------------------------------------------------------------------
# CLI Arguments Parser
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --auto|-y)
                INSTALL_MODE="express"
                NON_INTERACTIVE=true
                shift
                ;;
            --interactive|-i)
                INSTALL_MODE="interactive"
                shift
                ;;
            --docker)
                DEPLOY_METHOD="docker"
                shift
                ;;
            --direct)
                DEPLOY_METHOD="direct"
                shift
                ;;
            --dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --admin-password)
                ADMIN_PASSWORD="$2"
                shift 2
                ;;
            --proxy-port)
                PROXY_PORT="$2"
                shift 2
                ;;
            --admin-port)
                ADMIN_PORT="$2"
                shift 2
                ;;
            --admin-host)
                ADMIN_HOST="$2"
                shift 2
                ;;
            --upstream)
                UPSTREAM_URL="$2"
                shift 2
                ;;
            --license)
                LICENSE_KEY="$2"
                shift 2
                ;;
            --help|-h)
                log_banner
                echo "Usage: sudo bash install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --auto, -y           Run in Express mode (auto-generate passwords, zero prompts)"
                echo "  --interactive, -i    Run in Guided mode (interactive prompt for each parameter)"
                echo "  --docker             Force Docker deployment"
                echo "  --direct             Force Direct binary (systemd) deployment"
                echo "  --dir <path>         Target directory (Default: /opt/aegis)"
                echo "  --admin-password <p> Set custom admin password"
                echo "  --admin-host <host>  Set admin listen host (Default: 0.0.0.0)"
                echo "  --proxy-port <port>  Set custom proxy port (Default: 8080)"
                echo "  --admin-port <port>  Set custom admin port (Default: 8081)"
                echo "  --upstream <url>     Set upstream destination (Default: http://localhost:3000)"
                echo "  --license <key>      Set enterprise license token"
                echo "  --help, -h           Show this help message"
                exit 0
                ;;
            *)
                log_warn "Unknown option: $1"
                shift
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
    parse_args "$@"
    log_banner
    check_root
    detect_environment
    resolve_deploy_method
    resolve_install_mode
    resolve_direct_databases
    configure_parameters

    if [[ "$DEPLOY_METHOD" == "docker" ]]; then
        deploy_docker_stack
    else
        deploy_direct_binary
    fi

    finalize_installation
}

main "$@"
