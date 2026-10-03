#!/usr/bin/env bash
# ==============================================================================
#  Aegis Web Application Firewall — Unified Universal Installer
#  Usage:
#    curl -fsSL https://get.divinelab.io/installAegis.sh | sudo bash
#    or:
#    git clone https://github.com/divinelabio/aegis.git && cd aegis && sudo bash install.sh [OPTIONS]
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
POSTGRES_DB="${AEGIS_CONTROL_DB_NAME:-aegis}"
POSTGRES_PASSWORD="${AEGIS_CONTROL_DB_PASSWORD:-}"

# ClickHouse real-time analytics database (enabled by default)
CLICKHOUSE_ENABLED="${AEGIS_CLICKHOUSE_ENABLED:-true}"
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
 █████  ███████  ██████  ██ ███████ 
██   ██ ██      ██       ██ ██      
███████ █████   ██   ███ ██ ███████ 
██   ██ ██      ██    ██ ██      ██ 
██   ██ ███████  ██████  ██ ███████ 

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

print_docker_install_instructions() {
    echo -e "${CYAN}${BOLD}Please install Docker and Docker Compose first, then re-run this script:${RESET}"
    echo ""
    if command -v apt-get >/dev/null 2>&1; then
        echo -e "  ${YELLOW}sudo apt update && sudo apt install -y docker.io docker-compose-plugin${RESET}"
        echo -e "  ${YELLOW}sudo systemctl enable --now docker${RESET}"
    elif command -v dnf >/dev/null 2>&1; then
        echo -e "  ${YELLOW}sudo dnf install -y docker docker-compose-plugin${RESET}"
        echo -e "  ${YELLOW}sudo systemctl enable --now docker${RESET}"
    elif command -v yum >/dev/null 2>&1; then
        echo -e "  ${YELLOW}sudo yum install -y docker${RESET}"
        echo -e "  ${YELLOW}sudo systemctl enable --now docker${RESET}"
    elif command -v pacman >/dev/null 2>&1; then
        echo -e "  ${YELLOW}sudo pacman -S docker docker-compose${RESET}"
        echo -e "  ${YELLOW}sudo systemctl enable --now docker${RESET}"
    else
        echo -e "  ${YELLOW}Please install Docker Engine and Docker Compose using your system's package manager.${RESET}"
    fi
    echo ""
    echo -e "${DIM}Tip: You can re-run this installer and choose Option 2 to install Aegis directly without Docker.${RESET}"
    echo ""
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
        if [[ "$DEPLOY_METHOD" == "docker" ]] && ! $docker_available; then
            echo ""
            log_error "Docker deployment was selected, but Docker is not installed on this system."
            echo ""
            print_docker_install_instructions
            exit 1
        fi
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
        echo -e "  ${BOLD}[1] Docker Container Stack${RESET}"
        echo -e "      ${DIM}Requires Docker Engine & Docker Compose to be installed on this host.${RESET}"
        echo ""
        echo -e "  ${BOLD}[2] Install Aegis directly as a native systemd service (Direct Binary - Recommended)${RESET}"
        echo -e "      ${DIM}Lightweight bare-metal installation. No containers, zero virtualization overhead.${RESET}"
        echo ""
        echo -e "  ${BOLD}[3] Cancel installation${RESET}"
        echo ""

        read -rp "Enter choice [1-3] (Default: 2): " choice </dev/tty || choice="2"
        choice="${choice:-2}"

        case "$choice" in
            1)
                echo ""
                log_error "Docker is not installed on this system."
                echo ""
                print_docker_install_instructions
                exit 1
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
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable --now postgresql 2>/dev/null || systemctl start postgresql 2>/dev/null || true
        fi
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
    if [[ "$CLICKHOUSE_ENABLED" == "false" ]]; then
        log_info "ClickHouse analytics disabled. Running in Core WAF Mode."
    else
        local ch_detected=false
        if command -v clickhouse-client >/dev/null 2>&1 || check_port_in_use 9000; then
            ch_detected=true
        fi

        if $ch_detected; then
            log_success "ClickHouse service detected on localhost:9000."
        else
            echo ""
            echo -e "${CYAN}${BOLD}[INFO] ClickHouse provides high-performance real-time telemetry and WAF attack analytics.${RESET}"
            
            if [[ "$INSTALL_MODE" == "express" ]]; then
                if ask_user_permission "Would you like the installer to install and configure ClickHouse locally on this machine?" "Y"; then
                    install_clickhouse_local
                    CLICKHOUSE_ENABLED=true
                else
                    log_info "ClickHouse skipped by user choice. Running in Core WAF Mode (analytics disabled)."
                    CLICKHOUSE_ENABLED=false
                fi
            else
                echo "How would you like to configure ClickHouse analytics?"
                echo -e "  ${BOLD}[1] Install and configure ClickHouse locally on this machine (Recommended)${RESET}"
                echo "  [2] Connect to an existing external ClickHouse database"
                echo "  [3] Disable ClickHouse (Run in lightweight Core WAF Mode without analytics)"
                read -rp "Enter choice [1-3] (Default: 1): " ch_choice </dev/tty || ch_choice="1"
                ch_choice="${ch_choice:-1}"

                case "$ch_choice" in
                    1)
                        install_clickhouse_local
                        CLICKHOUSE_ENABLED=true
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
                        log_info "ClickHouse disabled. Running in Core WAF mode."
                        CLICKHOUSE_ENABLED=false
                        ;;
                esac
            fi
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
	getent group aegis >/dev/null || groupadd --system aegis
    log_step "Deploying Aegis stack via Docker Compose..."
    mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
    # Release containers run as the fixed, unprivileged Aegis identity.
    chown -R 65532:65532 "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
    if [[ -d "./data/rules" ]]; then
        cp -r "./data/rules" "${INSTALL_DIR}/data/" 2>/dev/null || true
    fi
    cd "${INSTALL_DIR}"

    # Write docker-compose.yml
    cat << 'COMPOSE_EOF' > docker-compose.yml
version: '3.8'

services:
  aegis:
    image: ${AEGIS_IMAGE:-ghcr.io/divinelabio/aegis:latest}
    container_name: aegis
    hostname: aegis
    restart: unless-stopped
    ports:
      - "${SERVER_PORT:-8080}:8080"
      - "${SERVER_ADMIN_PORT:-8081}:8081"
    group_add:
      - "${AEGIS_UPDATER_GID}"
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
      - ./data/rules:/var/lib/aegis/data/rules:ro
      - ./logs:/var/lib/aegis/logs
      - /run/aegis:/run/aegis
      - /etc/machine-id:/etc/aegis/host-machine-id:ro
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
      POSTGRES_DB: ${AEGIS_CONTROL_DB_NAME:-aegis}
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: ${AEGIS_CONTROL_DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis -d ${AEGIS_CONTROL_DB_NAME:-aegis}"]
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
AEGIS_IMAGE=${AEGIS_IMAGE:-ghcr.io/divinelabio/aegis:${AEGIS_VERSION:-latest}}
AEGIS_VERSION=${AEGIS_VERSION:-latest}
AEGIS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
AEGIS_CONTROL_DB_PASSWORD=${POSTGRES_PASSWORD}
AEGIS_CONTROL_DB_NAME=${POSTGRES_DB}
AEGIS_ANALYTICS_DB_PASSWORD=${CLICKHOUSE_PASSWORD}
AEGIS_JWT_SECRET=${JWT_SECRET}
AEGIS_DEV_MODE=enterprise
AEGIS_LICENSE_KEY=${LICENSE_KEY}
AEGIS_UPDATER_GID=$(getent group aegis | cut -d: -f3)
ENV_EOF
    chmod 600 .env

    # Write minimal config.yaml
    cat << CONFIG_EOF > config.yaml
server:
  port: 8080
  admin:
    host: "0.0.0.0"
    port: 8081
    username: "${ADMIN_USER}"
    setup_completed: true
    secure_cookies: false

updater:
  socket_path: /run/aegis/updater.sock
  mode: docker

storage:
  control:
    enabled: true
    driver: postgresql
    host: postgres
    port: 5432
    database: ${POSTGRES_DB}
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

sections:
  waf_core:
    enabled: true
    mode: blocking
    protection_level: 3
    engine:
      enable_crs: true
      anomaly_threshold: 5
      paranoia_level: 1
      crs_path: data/rules/crs
      crs_setup_path: data/rules/crs-setup.conf

  http_security:
    enabled: true
    protection_level: 3
    security_headers:
      enabled: true
      hsts: "max-age=31536000; includeSubDomains"
      x_frame_options: "DENY"
      x_content_type_options: "nosniff"
    upload_limit:
      enabled: true
      max_body_size: "10MB"
    method_enforcer:
      enabled: true
      mode: "blocklist"
      blocked_methods:
        - TRACE
        - TRACK
        - CONNECT
        - DEBUG

  traffic_control:
    enabled: true
    protection_level: 3
    rate_limit:
      enabled: true
      default_rate: 60
      default_burst: 10
      window: "1m"
      key_by: "ip"
    blacklist:
      enabled: true
CONFIG_EOF

    log_info "Pulling container images and launching services..."
    install_docker_updater
    local docker_archive docker_image
    docker_archive="$(mktemp)"
    download_community_archive "aegis-docker-linux-${ARCH}.tar.gz" "$docker_archive"
    docker load --input "$docker_archive" || fatal "Could not load the Community Docker release."
    rm -f "$docker_archive"
    local docker_version="${AEGIS_VERSION#v}"
    [[ "$docker_version" != "latest" ]] || docker_version="1.0.2"
    docker_image="$(docker image inspect "aegis-community:${docker_version}-${ARCH}" --format '{{.Id}}')" || fatal "Community Docker image is missing."
    [[ "$docker_image" =~ ^sha256:[a-f0-9]{64}$ ]] || fatal "Invalid Community Docker image identity."
    printf '\nAEGIS_IMAGE=%s\n' "$docker_image" >> .env
    cp .env release.env
    chmod 600 release.env
    docker compose --env-file release.env pull --quiet postgres clickhouse
    docker compose --env-file release.env up -d

    log_info "Waiting for services to become healthy..."
    local attempts=0
    local max_attempts=30
    while [[ $attempts -lt $max_attempts ]]; do
        if curl --fail --silent "http://127.0.0.1:${PROXY_PORT}/health/ready" >/dev/null; then
            break
        fi
        sleep 2
        attempts=$((attempts + 1))
    done
	[[ $attempts -lt $max_attempts ]] || fatal "Docker services did not become ready. Check docker compose --env-file release.env logs."

    log_success "Docker stack deployed and operational."
}

# The host updater owns Docker operations; the application receives only its
# restricted socket. Docker's administrative socket is never mounted in Aegis.
community_release_base() {
    local release_version="${AEGIS_VERSION#v}"
    [[ "$release_version" != "latest" ]] || fatal "Resolve the release version before downloading components."
    if [[ -n "${AEGIS_DOWNLOAD_BASE:-}" ]]; then
        printf '%s/releases/%s' "$AEGIS_DOWNLOAD_BASE" "$release_version"
    else
        printf 'https://github.com/%s/releases/download/v%s' "$GITHUB_REPO" "$release_version"
    fi
}

resolve_community_version() {
    if [[ "$AEGIS_VERSION" == "latest" ]]; then
        local metadata
        metadata="$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
            "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")" || fatal "Could not resolve the latest Community release. Set AEGIS_VERSION to a published version to retry."
        AEGIS_VERSION="$(printf '%s' "$metadata" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    fi
    AEGIS_VERSION="${AEGIS_VERSION#v}"
    local semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
    [[ "$AEGIS_VERSION" =~ $semver_pattern ]] || fatal "AEGIS_VERSION must be a full semantic version."
}

# checksums.txt must be copied unchanged from the matching official release.
download_community_archive() {
    local name="$1" destination="$2" release_base checksum_file expected actual
    release_base="$(community_release_base)"
    checksum_file="${destination}.checksums"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        "${release_base}/checksums.txt" -o "$checksum_file" || fatal "Release checksums are unavailable; installation stopped."
    expected="$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1 }' "$checksum_file")"
    [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fatal "Release checksum entry is missing, duplicated, or invalid."
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        "${release_base}/${name}" -o "$destination" || fatal "Could not download the selected complete release."
    actual="$(sha256sum "$destination")"
    [[ "${actual%% *}" == "${expected,,}" ]] || fatal "Release checksum mismatch; installation stopped."
    rm -f "$checksum_file"
}

install_docker_updater() {
    command -v systemctl >/dev/null || fatal "Automatic Docker upgrades require systemd on the host."
    local release_base
    release_base="$(community_release_base)"
    local updater_archive
    updater_archive="$(mktemp -d)"
    download_community_archive "aegis-linux-${ARCH}.tar.gz" "${updater_archive}/release.tar.gz"
    tar -xzf "${updater_archive}/release.tar.gz" -C "$updater_archive"
    [[ -s "${updater_archive}/aegis-updater" ]] || fatal "The host updater is missing from the release package."
    if [[ ! -d "${INSTALL_DIR}/data/rules" && -d "${updater_archive}/data/rules" ]]; then
        cp -r "${updater_archive}/data/rules" "${INSTALL_DIR}/data/"
    fi
    chown -R 65532:65532 "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
    install -m 755 "${updater_archive}/aegis-updater" "${INSTALL_DIR}/aegis-updater"
    mkdir -p /etc/aegis /run/aegis /var/lib/aegis /var/lib/aegis-updater
    chown root:root /var/lib/aegis-updater
    chmod 700 /var/lib/aegis-updater
    chown root:aegis /run/aegis
    chmod 750 /run/aegis
    cp .env "${INSTALL_DIR}/release.env"
    chmod 600 "${INSTALL_DIR}/release.env"
    cat > /etc/aegis/updater.yaml << UPDATER_CONFIG
updater:
  mode: docker
  socket_path: /run/aegis/updater.sock
  state_path: /var/lib/aegis-updater/updater-state.json
  releases_root: ${INSTALL_DIR}/releases
  compose_path: ${INSTALL_DIR}/docker-compose.yml
  compose_service: aegis
  release_env_path: ${INSTALL_DIR}/release.env
  health_url: http://127.0.0.1:${PROXY_PORT}/health
UPDATER_CONFIG
    cat > /etc/systemd/system/aegis-updater.service << UPDATER_SERVICE
[Unit]
Description=Aegis host release updater
After=network-online.target docker.service
Requires=docker.service
[Service]
Type=simple
User=root
Group=aegis
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/aegis-updater serve --config /etc/aegis/updater.yaml
Restart=on-failure
RestartSec=3
UMask=0027
RuntimeDirectory=aegis
RuntimeDirectoryMode=0750
[Install]
WantedBy=multi-user.target
UPDATER_SERVICE
    systemctl daemon-reload
    systemctl enable aegis-updater
    systemctl restart aegis-updater
}

# ------------------------------------------------------------------------------
# Deployment: Direct Native Binary (Systemd)
# ------------------------------------------------------------------------------
deploy_direct_binary() {
    log_step "Installing Aegis direct binary onto host system..."
    local native_release_dir="${INSTALL_DIR}/releases/initial-$(date +%s)-$$"
    mkdir -p "$native_release_dir" "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" /etc/aegis /var/lib/aegis /var/lib/aegis-updater
    chown root:root /var/lib/aegis-updater
    chmod 700 /var/lib/aegis-updater
    if ! id -u aegis >/dev/null 2>&1; then
        useradd -r -s /bin/false -d "${INSTALL_DIR}" -M aegis
    fi
    local bin_dest="${native_release_dir}/aegis"
    local updater_dest="${INSTALL_DIR}/aegis-updater"
    local ctl_dest="${native_release_dir}/aegisctl"
    local symlink_server="/usr/local/bin/aegis"
    local symlink_updater="/usr/local/bin/aegis-updater"
    local symlink_ctl="/usr/local/bin/aegisctl"
    local release_base
    release_base="$(community_release_base)"
    local archive="${native_release_dir}/release.tar.gz"
    download_community_archive "aegis-linux-${ARCH}.tar.gz" "$archive"
    tar -xzf "$archive" -C "$native_release_dir" || fatal "Invalid release archive; the current installation was preserved."
    rm -f "$archive"
    local component
    for component in aegis aegisctl aegis-updater; do
        [[ -s "${native_release_dir}/${component}" ]] || fatal "The release is missing ${component}; the current installation was preserved."
        chmod 755 "${native_release_dir}/${component}"
    done
    local build_info release_version
    build_info="$("$bin_dest" --build-info)" || fatal "Could not inspect the downloaded release."
    release_version="$(printf '%s' "$build_info" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    [[ "${release_version#v}" == "$AEGIS_VERSION" ]] || fatal "The release build version differs from the requested version."
    [[ "$build_info" == *'"community"'* ]] || fatal "Bootstrap installation requires a Community release."
    [[ "$("${native_release_dir}/aegis-updater" version)" == "aegis-updater ${release_version} "* ]] || fatal "The updater version differs from the server."
    [[ "$("$ctl_dest" version)" == *"\"${release_version}\""* ]] || fatal "The CLI version differs from the server."

    # Download and validate every component before touching running services.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop aegis aegis-updater 2>/dev/null || true
    fi
    install -m 755 "${native_release_dir}/aegis-updater" "${updater_dest}.new"
    mv -f "${updater_dest}.new" "$updater_dest"
    ln -s "$native_release_dir" "${INSTALL_DIR}/current.new.$$"
    mv -Tf "${INSTALL_DIR}/current.new.$$" "${INSTALL_DIR}/current"
    ln -sfn "${INSTALL_DIR}/current/aegis" "$symlink_server"
    ln -sfn "$updater_dest" "$symlink_updater"
    ln -sfn "${INSTALL_DIR}/current/aegisctl" "$symlink_ctl"
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

    # Deploy WAF rules
    log_info "Deploying WAF rules..."
    if [[ -d "./data/rules" ]]; then
        mkdir -p "${INSTALL_DIR}/data"
        cp -r "./data/rules" "${INSTALL_DIR}/data/" 2>/dev/null || true
    elif [[ -d "$(dirname "$0")/data/rules" ]]; then
        mkdir -p "${INSTALL_DIR}/data"
        cp -r "$(dirname "$0")/data/rules" "${INSTALL_DIR}/data/" 2>/dev/null || true
    elif [[ -d "${INSTALL_DIR}/current/data/rules" && ! -d "${INSTALL_DIR}/data/rules" ]]; then
        mkdir -p "${INSTALL_DIR}/data"
        cp -r "${INSTALL_DIR}/current/data/rules" "${INSTALL_DIR}/data/" 2>/dev/null || true
    fi

    # Set ownership
    chown -R aegis:aegis "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/web" /var/lib/aegis 2>/dev/null || true
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

    # Default secure_cookies to false for initial HTTP admin access (can be enabled via admin console when TLS is configured)
    local admin_secure_cookies=false

    # Write Config with updater configuration for in-place upgrades
    cat << CONFIG_EOF > /etc/aegis/config.yaml
server:
  port: ${PROXY_PORT}
  admin:
    host: "${ADMIN_HOST}"
    port: ${ADMIN_PORT}
    username: "${ADMIN_USER}"
    setup_completed: true
    secure_cookies: ${admin_secure_cookies}

updater:
  socket_path: /run/aegis/updater.sock
  mode: native
  state_path: /var/lib/aegis-updater/updater-state.json
  releases_root: ${INSTALL_DIR}/releases
  current_link: ${INSTALL_DIR}/current
  service_name: aegis.service
  health_url: http://127.0.0.1:${PROXY_PORT}/health

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

sections:
  waf_core:
    enabled: true
    mode: blocking
    protection_level: 3
    engine:
      enable_crs: true
      anomaly_threshold: 5
      paranoia_level: 1
      crs_path: data/rules/crs
      crs_setup_path: data/rules/crs-setup.conf

  http_security:
    enabled: true
    protection_level: 3
    security_headers:
      enabled: true
      hsts: "max-age=31536000; includeSubDomains"
      x_frame_options: "DENY"
      x_content_type_options: "nosniff"
    upload_limit:
      enabled: true
      max_body_size: "10MB"
    method_enforcer:
      enabled: true
      mode: "blocklist"
      blocked_methods:
        - TRACE
        - TRACK
        - CONNECT
        - DEBUG

  traffic_control:
    enabled: true
    protection_level: 3
    rate_limit:
      enabled: true
      default_rate: 60
      default_burst: 10
      window: "1m"
      key_by: "ip"
    blacklist:
      enabled: true
CONFIG_EOF

    # Setup Systemd Services (both aegis-server and aegis-updater)
    cat > /etc/aegis/updater.yaml << UPDATER_CONFIG
updater:
  socket_path: /run/aegis/updater.sock
  mode: native
  state_path: /var/lib/aegis-updater/updater-state.json
  releases_root: ${INSTALL_DIR}/releases
  current_link: ${INSTALL_DIR}/current
  service_name: aegis.service
  health_url: http://127.0.0.1:${PROXY_PORT}/health
UPDATER_CONFIG
    chmod 600 /etc/aegis/updater.yaml
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
Group=aegis
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/current/aegis-updater serve --config /etc/aegis/updater.yaml
Restart=on-failure
RestartSec=5s
RuntimeDirectory=aegis
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
UPDATER_EOF

        systemctl daemon-reload
        systemctl enable aegis-updater 2>/dev/null || true
        systemctl restart aegis-updater 2>/dev/null || systemctl start aegis-updater || true
        systemctl enable aegis 2>/dev/null || true
        systemctl restart aegis 2>/dev/null || systemctl start aegis || true

        log_info "Waiting for Aegis service to initialize..."
        local attempts=0
        local max_attempts=30
        local started=false
        while [[ $attempts -lt $max_attempts ]]; do
            if systemctl is-active --quiet aegis aegis-updater && curl --fail --silent "http://127.0.0.1:${PROXY_PORT}/health/ready" >/dev/null; then
                started=true
                break
            fi
            sleep 1
            attempts=$((attempts + 1))
        done

        if $started; then
            log_success "Systemd services (aegis & aegis-updater) created, started, and verified active."
        else
            fatal "Aegis services did not become ready. Check systemctl status aegis aegis-updater and journalctl -u aegis."
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
            --no-clickhouse|--disable-clickhouse|--skip-clickhouse)
                CLICKHOUSE_ENABLED=false
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
                echo "  --no-clickhouse      Disable ClickHouse analytics (Run in lightweight Core WAF mode)"
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
    [[ ! -e "${INSTALL_DIR}/current" && ! -L "${INSTALL_DIR}/current" && ! -f /etc/aegis/config.yaml && ! -f "${INSTALL_DIR}/config.yaml" && ! -f "${INSTALL_DIR}/docker-compose.yml" ]] || fatal "An Aegis installation already exists. Use its updater for version or edition changes; the bootstrap installer will not replace its configuration."
    detect_environment
    resolve_community_version
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
