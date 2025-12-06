#!/bin/bash
#
# VPS 一键管理工具箱
# GitHub: https://github.com/your-username/vps-toolkit
# 使用: bash <(curl -sL https://raw.githubusercontent.com/your-username/vps-toolkit/main/vps.sh)
#
# 版本: 1.0.0
#

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="VPS-Toolkit"

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ==================== 输出函数 ====================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

print_line() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_menu_item() {
    echo -e " ${GREEN}$1.${NC} $2"
}

# ==================== 系统检测 ====================
check_root() {
    [[ $EUID -ne 0 ]] && log_error "请以 root 权限运行此脚本" && exit 1
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_NAME=$(cat /etc/redhat-release)
    else
        OS="unknown"
        OS_NAME="Unknown"
    fi
}

detect_arch() {
    case $(uname -m) in
        x86_64|amd64) ARCH="amd64"; ARCH_ALT="x86_64" ;;
        aarch64|arm64) ARCH="arm64"; ARCH_ALT="aarch64" ;;
        armv7l) ARCH="armv7"; ARCH_ALT="armv7l" ;;
        *) log_error "不支持的架构: $(uname -m)" && exit 1 ;;
    esac
}

detect_virt() {
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt 2>/dev/null)
    else
        VIRT="unknown"
    fi
    [[ -z "$VIRT" || "$VIRT" == "none" ]] && VIRT="物理机"
}

# ==================== 包管理 ====================
pkg_install() {
    case $OS in
        ubuntu|debian|linuxmint)
            apt-get install -y "$@" >/dev/null 2>&1
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf install -y "$@" >/dev/null 2>&1
            else
                yum install -y "$@" >/dev/null 2>&1
            fi
            ;;
        alpine)
            apk add --no-cache "$@" >/dev/null 2>&1
            ;;
    esac
}

pkg_update() {
    case $OS in
        ubuntu|debian|linuxmint) apt-get update -y >/dev/null 2>&1 ;;
        centos|rhel|fedora|rocky|almalinux) yum check-update -y >/dev/null 2>&1 || true ;;
        alpine) apk update >/dev/null 2>&1 ;;
    esac
}

pkg_upgrade() {
    log_info "升级系统软件包..."
    case $OS in
        ubuntu|debian|linuxmint) apt-get upgrade -y ;;
        centos|rhel|fedora|rocky|almalinux) yum upgrade -y || dnf upgrade -y ;;
        alpine) apk upgrade ;;
    esac
}

ensure_cmd() {
    local cmd=$1
    local pkg=${2:-$1}
    if ! command -v "$cmd" &>/dev/null; then
        log_info "安装 $pkg..."
        pkg_install "$pkg"
    fi
}

# ==================== 工具函数 ====================
confirm() {
    local prompt="${1:-确认继续？}"
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]: ${NC}")" response
    [[ "$response" =~ ^[Yy]$ ]]
}

random_string() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-16}"
}

random_hex() {
    tr -dc 'a-f0-9' </dev/urandom | head -c "${1:-8}"
}

random_port() {
    shuf -i "${1:-10000}-${2:-65535}" -n 1
}

check_port_available() {
    ! ss -tuln | grep -q ":${1} "
}

get_available_port() {
    local port
    while true; do
        port=$(random_port)
        check_port_available "$port" && echo "$port" && return
    done
}

get_ipv4() {
    curl -s4m5 icanhazip.com 2>/dev/null || curl -s4m5 ipinfo.io/ip 2>/dev/null
}

get_ipv6() {
    curl -s6m5 icanhazip.com 2>/dev/null
}

get_ip_location() {
    local json=$(curl -s "http://ip-api.com/json/${1}?fields=country,city,isp" 2>/dev/null)
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r '"\(.country) \(.city) - \(.isp)"' 2>/dev/null
    else
        echo "$json" | sed 's/.*"country":"\([^"]*\)".*"city":"\([^"]*\)".*"isp":"\([^"]*\)".*/\1 \2 - \3/' 2>/dev/null
    fi
}

press_any_key() {
    echo
    read -n 1 -s -r -p "按任意键继续..."
    echo
}

# ==================== 服务管理 ====================
service_start() { systemctl start "$1" 2>/dev/null || service "$1" start 2>/dev/null; }
service_stop() { systemctl stop "$1" 2>/dev/null || service "$1" stop 2>/dev/null; }
service_restart() { systemctl restart "$1" 2>/dev/null || service "$1" restart 2>/dev/null; }
service_enable() { systemctl enable "$1" >/dev/null 2>&1; }
service_status() { systemctl is-active "$1" 2>/dev/null || echo "inactive"; }

# ==================== 防火墙 ====================
firewall_allow_port() {
    local port=$1 protocol=${2:-tcp}
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        ufw allow "${port}/${protocol}" >/dev/null 2>&1
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-port="${port}/${protocol}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# ==================== 系统信息模块 ====================
show_system_info() {
    clear
    print_line
    echo -e "${CYAN}                系统信息${NC}"
    print_line
    
    echo -e "${YELLOW}【基础信息】${NC}"
    echo -e "  主机名称: ${GREEN}$(hostname)${NC}"
    echo -e "  系统版本: ${GREEN}${OS_NAME}${NC}"
    echo -e "  内核版本: ${GREEN}$(uname -r)${NC}"
    echo -e "  系统架构: ${GREEN}${ARCH_ALT}${NC}"
    echo -e "  虚拟化:   ${GREEN}${VIRT}${NC}"
    echo
    
    echo -e "${YELLOW}【CPU 信息】${NC}"
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(grep -c "processor" /proc/cpuinfo 2>/dev/null)
    echo -e "  CPU型号:  ${GREEN}${cpu_model:-未知}${NC}"
    echo -e "  CPU核心:  ${GREEN}${cpu_cores:-1} 核${NC}"
    echo
    
    echo -e "${YELLOW}【内存信息】${NC}"
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local swap_total=$(free -m | awk '/Swap:/ {print $2}')
    echo -e "  总内存:   ${GREEN}${mem_total} MB${NC}"
    echo -e "  已使用:   ${GREEN}${mem_used} MB${NC}"
    echo -e "  Swap:     ${GREEN}${swap_total} MB${NC}"
    echo
    
    echo -e "${YELLOW}【磁盘信息】${NC}"
    df -h / | awk 'NR==2 {printf "  根分区:   \033[32m总计 %s, 已用 %s (%s)\033[0m\n", $2, $3, $5}'
    echo
    
    echo -e "${YELLOW}【网络信息】${NC}"
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    echo -e "  IPv4:     ${GREEN}${ipv4:-未检测到}${NC}"
    echo -e "  IPv6:     ${GREEN}${ipv6:-未检测到}${NC}"
    [[ -n "$ipv4" ]] && echo -e "  位置:     ${GREEN}$(get_ip_location "$ipv4")${NC}"
    echo
    
    echo -e "${YELLOW}【运行状态】${NC}"
    local uptime_str=$(uptime -p 2>/dev/null || uptime | awk -F'up' '{print $2}' | cut -d',' -f1)
    local load=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    local bbr=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "  运行时间: ${GREEN}${uptime_str}${NC}"
    echo -e "  系统负载: ${GREEN}${load}${NC}"
    echo -e "  TCP拥塞:  ${GREEN}${bbr:-未知}${NC}"
    echo -e "  当前时间: ${GREEN}$(date '+%Y-%m-%d %H:%M:%S %Z')${NC}"
    print_line
}

install_common_tools() {
    clear
    print_line
    echo -e "${CYAN}            安装常用工具${NC}"
    print_line
    
    local tools="curl wget vim git jq unzip tar htop lsof qrencode"
    echo -e "${YELLOW}将安装: ${tools}${NC}"
    echo
    
    if confirm "确认安装？"; then
        pkg_update
        for tool in $tools; do
            echo -ne "  安装 ${tool}... "
            if pkg_install "$tool"; then
                echo -e "${GREEN}✓${NC}"
            else
                echo -e "${RED}✗${NC}"
            fi
        done
        log_success "安装完成"
    fi
}

set_timezone() {
    clear
    print_line
    echo -e "${CYAN}              时区设置${NC}"
    print_line
    
    echo -e "当前时区: ${GREEN}$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo '未知')${NC}"
    echo
    print_menu_item "1" "Asia/Shanghai (中国上海)"
    print_menu_item "2" "Asia/Hong_Kong (中国香港)"
    print_menu_item "3" "Asia/Tokyo (日本东京)"
    print_menu_item "4" "America/Los_Angeles (美国洛杉矶)"
    print_menu_item "5" "自定义输入"
    print_menu_item "0" "返回"
    print_line
    
    read -r -p "请选择 [0-5]: " choice
    local tz=""
    case $choice in
        1) tz="Asia/Shanghai" ;;
        2) tz="Asia/Hong_Kong" ;;
        3) tz="Asia/Tokyo" ;;
        4) tz="America/Los_Angeles" ;;
        5) read -r -p "输入时区: " tz ;;
        0) return ;;
    esac
    
    if [[ -n "$tz" ]]; then
        timedatectl set-timezone "$tz" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
        log_success "时区已设置为 $tz"
    fi
}

manage_swap() {
    clear
    print_line
    echo -e "${CYAN}            Swap 管理${NC}"
    print_line
    
    local swap_total=$(free -m | awk '/Swap:/ {print $2}')
    echo -e "当前 Swap: ${GREEN}${swap_total} MB${NC}"
    echo
    print_menu_item "1" "创建/调整 Swap"
    print_menu_item "2" "删除 Swap"
    print_menu_item "0" "返回"
    print_line
    
    read -r -p "请选择 [0-2]: " choice
    case $choice in
        1)
            read -r -p "Swap 大小 (MB，建议 1024-4096): " size
            [[ ! "$size" =~ ^[0-9]+$ ]] && log_error "无效大小" && return
            swapoff /swapfile 2>/dev/null; rm -f /swapfile
            fallocate -l ${size}M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$size
            chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
            sed -i '/\/swapfile/d' /etc/fstab
            echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            log_success "Swap 已创建: ${size} MB"
            ;;
        2)
            swapoff -a; rm -f /swapfile; sed -i '/\/swapfile/d' /etc/fstab
            log_success "Swap 已删除"
            ;;
    esac
}

system_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}            系统信息与优化${NC}"
        print_line
        print_menu_item "1" "查看系统信息"
        print_menu_item "2" "系统更新"
        print_menu_item "3" "安装常用工具"
        print_menu_item "4" "时区设置"
        print_menu_item "5" "Swap 管理"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-5]: " choice
        case $choice in
            1) show_system_info; press_any_key ;;
            2) pkg_update && pkg_upgrade; log_success "更新完成"; press_any_key ;;
            3) install_common_tools; press_any_key ;;
            4) set_timezone; press_any_key ;;
            5) manage_swap; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== BBR 模块 ====================
check_bbr_status() {
    local algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    local qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
    echo -e "${YELLOW}【当前 BBR 状态】${NC}"
    echo -e "  拥塞控制: ${GREEN}${algo:-未知}${NC}"
    echo -e "  队列算法: ${GREEN}${qdisc:-未知}${NC}"
    echo -e "  内核版本: ${GREEN}$(uname -r)${NC}"
}

enable_bbr() {
    local qdisc=${1:-fq}
    if ! grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        log_error "当前内核不支持 BBR"
        return 1
    fi
    
    cat > /etc/sysctl.d/99-bbr.conf << EOF
net.core.default_qdisc = ${qdisc}
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_fastopen = 3
EOF
    sysctl --system >/dev/null 2>&1
    log_success "BBR + ${qdisc^^} 已启用"
}

install_bbr_v3() {
    clear
    print_line
    echo -e "${CYAN}          安装 BBR v3 内核${NC}"
    print_line
    
    if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
        log_error "仅支持 Debian/Ubuntu"
        return 1
    fi
    
    ensure_cmd jq jq
    ensure_cmd curl curl
    ensure_cmd wget wget
    
    log_info "获取最新版本..."
    local arch_filter=$([[ "$ARCH" == "arm64" ]] && echo "arm64" || echo "x86_64")
    local release_data=$(curl -sL "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases")
    local latest_tag=$(echo "$release_data" | jq -r --arg f "$arch_filter" \
        'map(select(.tag_name | test($f; "i"))) | sort_by(.published_at) | .[-1].tag_name')
    
    [[ -z "$latest_tag" || "$latest_tag" == "null" ]] && log_error "未找到版本" && return 1
    
    echo -e "最新版本: ${GREEN}${latest_tag}${NC}"
    confirm "确认安装？安装后需重启" || return
    
    local urls=$(echo "$release_data" | jq -r --arg t "$latest_tag" \
        '.[] | select(.tag_name == $t) | .assets[].browser_download_url')
    
    rm -f /tmp/linux-*.deb
    for url in $urls; do
        log_info "下载: $(basename $url)"
        wget -q --show-progress "$url" -P /tmp/ || { log_error "下载失败"; return 1; }
    done
    
    dpkg -l | grep "joeyblog" | awk '{print $2}' | xargs -r apt-get remove --purge -y >/dev/null 2>&1
    dpkg -i /tmp/linux-*.deb
    command -v update-grub &>/dev/null && update-grub
    rm -f /tmp/linux-*.deb
    
    log_success "BBR v3 安装完成"
    confirm "立即重启？" && reboot
}

bbr_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}            BBR 网络加速${NC}"
        print_line
        check_bbr_status
        print_line
        print_menu_item "1" "安装 BBR v3 内核"
        print_menu_item "2" "启用 BBR + FQ"
        print_menu_item "3" "启用 BBR + FQ_PIE"
        print_menu_item "4" "启用 BBR + CAKE"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1) install_bbr_v3; press_any_key ;;
            2) enable_bbr fq; press_any_key ;;
            3) enable_bbr fq_pie; press_any_key ;;
            4) enable_bbr cake; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== 安全管理模块 ====================
change_ssh_port() {
    clear
    print_line
    echo -e "${CYAN}          修改 SSH 端口${NC}"
    print_line
    
    local current=$(grep -E "^#?Port " /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
    echo -e "当前端口: ${GREEN}${current:-22}${NC}"
    
    read -r -p "新端口 [1-65535]: " new_port
    [[ ! "$new_port" =~ ^[0-9]+$ ]] && log_error "无效端口" && return
    check_port_available "$new_port" || { log_error "端口已占用"; return; }
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    sed -i "s/^#*Port .*/Port ${new_port}/" /etc/ssh/sshd_config
    grep -q "^Port " /etc/ssh/sshd_config || echo "Port ${new_port}" >> /etc/ssh/sshd_config
    firewall_allow_port "$new_port" tcp
    service_restart sshd || service_restart ssh
    
    log_success "SSH 端口已改为 ${new_port}"
    log_warn "请用新端口重连: ssh -p ${new_port} root@IP"
}

show_port_usage() {
    clear
    print_line
    echo -e "${CYAN}            端口占用查询${NC}"
    print_line
    
    read -r -p "输入端口号 (留空查看全部): " port
    if [[ -n "$port" ]]; then
        echo -e "${YELLOW}端口 ${port} 占用:${NC}"
        ss -tlnp | grep ":${port} " || echo "TCP: 未占用"
        ss -ulnp | grep ":${port} " || echo "UDP: 未占用"
    else
        echo -e "${YELLOW}TCP 监听:${NC}"
        ss -tlnp | head -15
        echo -e "\n${YELLOW}UDP 监听:${NC}"
        ss -ulnp | head -10
    fi
}

install_fail2ban() {
    clear
    print_line
    echo -e "${CYAN}          Fail2ban 管理${NC}"
    print_line
    
    if command -v fail2ban-client &>/dev/null; then
        echo -e "状态: ${GREEN}已安装${NC}"
        fail2ban-client status 2>/dev/null
    else
        echo -e "状态: ${RED}未安装${NC}"
        if confirm "安装 Fail2ban？"; then
            pkg_install fail2ban rsyslog
            service_enable fail2ban
            service_start fail2ban
            
            local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}')
            cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ${ssh_port:-22}
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 300
bantime = 600
EOF
            service_restart fail2ban
            log_success "Fail2ban 已安装并配置"
        fi
    fi
}

security_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}          安全与访问管理${NC}"
        print_line
        print_menu_item "1" "修改 root 密码"
        print_menu_item "2" "修改 SSH 端口"
        print_menu_item "3" "查看端口占用"
        print_menu_item "4" "Fail2ban 管理"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1) passwd root; press_any_key ;;
            2) change_ssh_port; press_any_key ;;
            3) show_port_usage; press_any_key ;;
            4) install_fail2ban; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== Docker 模块 ====================
check_docker() {
    if command -v docker &>/dev/null; then
        echo -e "Docker: ${GREEN}$(docker --version | awk '{print $3}' | tr -d ',')${NC} ($(service_status docker))"
        return 0
    else
        echo -e "Docker: ${RED}未安装${NC}"
        return 1
    fi
}

install_docker() {
    clear
    print_line
    echo -e "${CYAN}            安装 Docker${NC}"
    print_line
    
    command -v docker &>/dev/null && { log_warn "Docker 已安装"; return; }
    
    local country=$(curl -s --max-time 3 ipinfo.io/country 2>/dev/null)
    local use_mirror=$([[ "$country" == "CN" ]] && echo true || echo false)
    
    print_menu_item "1" "官方源 (海外推荐)"
    print_menu_item "2" "国内镜像 (国内推荐)"
    read -r -p "请选择 [1-2]: " choice
    [[ "$choice" == "2" ]] && use_mirror=true
    
    log_info "安装 Docker..."
    pkg_update
    pkg_install curl ca-certificates gnupg
    
    if [[ "$use_mirror" == true ]]; then
        case $OS in
            ubuntu|debian)
                local codename=$(lsb_release -cs 2>/dev/null || grep VERSION_CODENAME /etc/os-release | cut -d= -f2)
                curl -fsSL https://mirrors.aliyun.com/docker-ce/linux/${OS}/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://mirrors.aliyun.com/docker-ce/linux/${OS} ${codename} stable" > /etc/apt/sources.list.d/docker.list
                apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
                ;;
            centos|rhel|rocky|almalinux)
                yum install -y yum-utils
                yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
                yum install -y docker-ce docker-ce-cli containerd.io
                ;;
        esac
    else
        curl -fsSL https://get.docker.com | sh
    fi
    
    service_enable docker
    service_start docker
    
    # 配置镜像加速
    if [[ "$country" == "CN" ]]; then
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << 'EOF'
{"registry-mirrors": ["https://docker.1ms.run", "https://hub.rat.dev"]}
EOF
        service_restart docker
    fi
    
    command -v docker &>/dev/null && log_success "Docker 安装成功" || log_error "安装失败"
}

docker_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}            Docker 管理${NC}"
        print_line
        check_docker
        print_line
        print_menu_item "1" "安装 Docker"
        print_menu_item "2" "查看容器"
        print_menu_item "3" "查看镜像"
        print_menu_item "4" "启动/停止 Docker"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1) install_docker; press_any_key ;;
            2) docker ps -a 2>/dev/null || log_error "Docker 未安装"; press_any_key ;;
            3) docker images 2>/dev/null || log_error "Docker 未安装"; press_any_key ;;
            4)
                if service_status docker | grep -q "active"; then
                    service_stop docker; log_success "Docker 已停止"
                else
                    service_start docker; log_success "Docker 已启动"
                fi
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 面板模块 ====================
panel_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}              面板管理${NC}"
        print_line
        
        # 检查状态
        if command -v 1pctl &>/dev/null || [[ -f /usr/local/bin/1pctl ]]; then
            echo -e "1Panel:  ${GREEN}已安装${NC}"
        else
            echo -e "1Panel:  ${RED}未安装${NC}"
        fi
        
        if [[ -f /www/server/panel/BT-Panel ]]; then
            echo -e "aaPanel: ${GREEN}已安装${NC}"
        else
            echo -e "aaPanel: ${RED}未安装${NC}"
        fi
        
        print_line
        print_menu_item "1" "安装 1Panel"
        print_menu_item "2" "安装 aaPanel"
        print_menu_item "3" "查看 1Panel 信息"
        print_menu_item "4" "查看 aaPanel 信息"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1)
                if confirm "安装 1Panel？"; then
                    curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o /tmp/1panel.sh && bash /tmp/1panel.sh
                fi
                press_any_key
                ;;
            2)
                if confirm "安装 aaPanel？"; then
                    case $OS in
                        ubuntu|debian) wget -O /tmp/aapanel.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh && bash /tmp/aapanel.sh aapanel ;;
                        centos|rhel|rocky) wget -O /tmp/aapanel.sh http://www.aapanel.com/script/install_6.0_en.sh && bash /tmp/aapanel.sh aapanel ;;
                    esac
                fi
                press_any_key
                ;;
            3) 1pctl user-info 2>/dev/null || log_warn "1Panel 未安装"; press_any_key ;;
            4) bt default 2>/dev/null || /etc/init.d/bt default 2>/dev/null || log_warn "aaPanel 未安装"; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== Snell 节点模块 ====================
SNELL_BIN="/usr/local/bin/snell-server"
SNELL_CONF="/etc/snell/config.conf"

check_snell() {
    if [[ -f "$SNELL_BIN" ]]; then
        local ver=$(cat /etc/snell/ver.txt 2>/dev/null || echo "未知")
        echo -e "Snell: ${GREEN}${ver}${NC} ($(service_status snell-server))"
        return 0
    else
        echo -e "Snell: ${RED}未安装${NC}"
        return 1
    fi
}

install_snell() {
    local version=$1
    clear
    print_line
    echo -e "${CYAN}          安装 Snell v${version%%.*}${NC}"
    print_line
    
    [[ -f "$SNELL_BIN" ]] && { log_warn "已安装，请先卸载"; return; }
    
    mkdir -p /etc/snell
    
    # 端口
    local port
    read -r -p "端口 (默认随机): " port
    port=${port:-$(get_available_port)}
    
    # 密钥
    local psk
    read -r -p "密钥 (默认随机): " psk
    psk=${psk:-$(random_string 16)}
    
    # 下载
    ensure_cmd unzip unzip
    local arch_name=$([[ "$ARCH" == "arm64" ]] && echo "aarch64" || echo "amd64")
    local url="https://dl.nssurge.com/snell/snell-server-v${version}-linux-${arch_name}.zip"
    
    log_info "下载 Snell..."
    cd /tmp
    wget -q --show-progress "$url" -O snell.zip || { log_error "下载失败"; return 1; }
    unzip -o snell.zip >/dev/null
    mv snell-server "$SNELL_BIN"
    chmod +x "$SNELL_BIN"
    rm -f snell.zip
    echo "v${version}" > /etc/snell/ver.txt
    
    # 配置
    cat > "$SNELL_CONF" << EOF
[snell-server]
listen = ::0:${port}
psk = ${psk}
ipv6 = false
obfs = off
tfo = true
dns = 1.1.1.1, 8.8.8.8
version = ${version%%.*}
EOF
    
    # 服务
    cat > /etc/systemd/system/snell-server.service << 'EOF'
[Unit]
Description=Snell Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server -c /etc/snell/config.conf
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    service_enable snell-server
    service_start snell-server
    firewall_allow_port "$port" tcp
    
    log_success "Snell 安装成功"
    show_snell_config
}

show_snell_config() {
    [[ ! -f "$SNELL_CONF" ]] && { log_error "未安装"; return; }
    
    local port=$(grep "^listen" "$SNELL_CONF" | awk -F':' '{print $NF}')
    local psk=$(grep "^psk" "$SNELL_CONF" | awk -F'= ' '{print $2}')
    local ver=$(grep "^version" "$SNELL_CONF" | awk -F'= ' '{print $2}')
    local ip=$(get_ipv4)
    
    print_line
    echo -e "${YELLOW}【Snell 节点信息】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${port}${NC}"
    echo -e "  密钥:   ${GREEN}${psk}${NC}"
    echo -e "  版本:   ${GREEN}v${ver}${NC}"
    print_line
    
    local config="Snell = snell, ${ip}, ${port}, psk=${psk}, version=${ver}, tfo=true"
    echo -e "${YELLOW}【Surge/Loon 配置】${NC}"
    echo -e "${CYAN}${config}${NC}"
    print_line
    
    command -v qrencode &>/dev/null && echo "$config" | qrencode -o - -t ANSIUTF8
}

snell_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}          Snell 节点管理${NC}"
        print_line
        check_snell
        print_line
        print_menu_item "1" "安装 Snell v4"
        print_menu_item "2" "安装 Snell v5"
        print_menu_item "3" "查看节点信息"
        print_menu_item "4" "重启服务"
        print_menu_item "5" "卸载 Snell"
        print_line
        print_menu_item "0" "返回"
        print_line
        
        read -r -p "请选择 [0-5]: " choice
        case $choice in
            1) install_snell "4.1.1"; press_any_key ;;
            2) install_snell "5.0.1"; press_any_key ;;
            3) show_snell_config; press_any_key ;;
            4) service_restart snell-server; log_success "已重启"; press_any_key ;;
            5)
                if confirm "确认卸载？"; then
                    service_stop snell-server
                    rm -f /etc/systemd/system/snell-server.service "$SNELL_BIN"
                    rm -rf /etc/snell
                    systemctl daemon-reload
                    log_success "已卸载"
                fi
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== SS2022 + Shadow-TLS 模块 ====================
SS_BIN="/usr/local/bin/ssserver"
STLS_BIN="/usr/local/bin/shadow-tls"
SS_CONF="/etc/shadowsocks/config.json"

check_ss2022() {
    if [[ -f "$SS_BIN" && -f "$STLS_BIN" ]]; then
        echo -e "SS2022+TLS: ${GREEN}已安装${NC} (SS:$(service_status shadowsocks), TLS:$(service_status shadow-tls))"
        return 0
    else
        echo -e "SS2022+TLS: ${RED}未安装${NC}"
        return 1
    fi
}

install_ss2022() {
    clear
    print_line
    echo -e "${CYAN}    安装 SS2022 + Shadow-TLS${NC}"
    print_line
    
    [[ -f "$SS_BIN" ]] && { log_warn "已安装"; return; }
    
    ensure_cmd openssl openssl
    ensure_cmd wget wget
    
    # 配置
    local ss_port tls_port ss_pwd tls_pwd fake_domain
    read -r -p "SS 端口 (默认随机): " ss_port; ss_port=${ss_port:-$(get_available_port)}
    read -r -p "TLS 端口 (默认 443): " tls_port; tls_port=${tls_port:-443}
    read -r -p "SS 密码 (默认随机): " ss_pwd; ss_pwd=${ss_pwd:-$(openssl rand -base64 32)}
    read -r -p "TLS 密码 (默认随机): " tls_pwd; tls_pwd=${tls_pwd:-$(random_string 16)}
    read -r -p "伪装域名 (默认 p11.douyinpic.com): " fake_domain; fake_domain=${fake_domain:-p11.douyinpic.com}
    
    local method="2022-blake3-aes-256-gcm"
    
    # 下载 SS
    log_info "下载 Shadowsocks..."
    local ss_arch=$([[ "$ARCH" == "arm64" ]] && echo "aarch64-unknown-linux-gnu" || echo "x86_64-unknown-linux-gnu")
    cd /tmp
    wget -q --show-progress "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.17.1/shadowsocks-v1.17.1.${ss_arch}.tar.xz" -O ss.tar.xz || { log_error "下载失败"; return 1; }
    tar -xJf ss.tar.xz && mv ssserver "$SS_BIN" && chmod +x "$SS_BIN"
    rm -f ss.tar.xz sslocal ssmanager ssservice ssurl
    
    # 下载 Shadow-TLS
    log_info "下载 Shadow-TLS..."
    local stls_arch=$([[ "$ARCH" == "arm64" ]] && echo "aarch64-unknown-linux-musl" || echo "x86_64-unknown-linux-musl")
    wget -q --show-progress "https://github.com/ihciah/shadow-tls/releases/download/v0.2.25/shadow-tls-${stls_arch}" -O "$STLS_BIN" || { log_error "下载失败"; return 1; }
    chmod +x "$STLS_BIN"
    
    # 配置
    mkdir -p /etc/shadowsocks
    cat > "$SS_CONF" << EOF
{"server":"0.0.0.0","server_port":${ss_port},"password":"${ss_pwd}","method":"${method}","mode":"tcp_and_udp","fast_open":true}
EOF
    cat > /etc/shadowsocks/extra.conf << EOF
TLS_PORT=${tls_port}
TLS_PASSWORD=${tls_pwd}
FAKE_DOMAIN=${fake_domain}
EOF
    
    # 服务
    cat > /etc/systemd/system/shadowsocks.service << EOF
[Unit]
Description=Shadowsocks
After=network.target
[Service]
ExecStart=${SS_BIN} -c ${SS_CONF}
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    
    cat > /etc/systemd/system/shadow-tls.service << EOF
[Unit]
Description=Shadow-TLS
After=network.target
[Service]
ExecStart=${STLS_BIN} --fastopen --v3 --strict server --listen [::]:${tls_port} --server 127.0.0.1:${ss_port} --tls ${fake_domain}:443 --password ${tls_pwd}
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    service_enable shadowsocks
    service_enable shadow-tls
    service_start shadowsocks
    service_start shadow-tls
    firewall_allow_port "$tls_port" tcp
    firewall_allow_port "$ss_port" udp
    
    sleep 2
    log_success "安装成功"
    show_ss2022_config
}

show_ss2022_config() {
    [[ ! -f "$SS_CONF" ]] && { log_error "未安装"; return; }
    
    ensure_cmd jq jq
    local ss_port=$(jq -r '.server_port' "$SS_CONF")
    local ss_pwd=$(jq -r '.password' "$SS_CONF")
    local method=$(jq -r '.method' "$SS_CONF")
    source /etc/shadowsocks/extra.conf 2>/dev/null
    local ip=$(get_ipv4)
    
    print_line
    echo -e "${YELLOW}【SS2022 + Shadow-TLS 节点】${NC}"
    echo -e "  服务器:   ${GREEN}${ip}${NC}"
    echo -e "  TLS端口:  ${GREEN}${TLS_PORT}${NC}"
    echo -e "  SS端口:   ${GREEN}${ss_port}${NC}"
    echo -e "  加密:     ${GREEN}${method}${NC}"
    echo -e "  SS密码:   ${GREEN}${ss_pwd}${NC}"
    echo -e "  TLS密码:  ${GREEN}${TLS_PASSWORD}${NC}"
    echo -e "  伪装域名: ${GREEN}${FAKE_DOMAIN}${NC}"
    print_line
    
    local surge="SS-TLS = ss, ${ip}, ${TLS_PORT}, encrypt-method=${method}, password=${ss_pwd}, shadow-tls-password=${TLS_PASSWORD}, shadow-tls-sni=${FAKE_DOMAIN}, shadow-tls-version=3, udp-relay=true, udp-port=${ss_port}"
    echo -e "${YELLOW}【Surge 配置】${NC}"
    echo -e "${CYAN}${surge}${NC}"
    print_line
    
    local loon="SS-TLS = Shadowsocks,${ip},${TLS_PORT},${method},\"${ss_pwd}\",shadow-tls-password=${TLS_PASSWORD},shadow-tls-sni=${FAKE_DOMAIN},shadow-tls-version=3,udp=true,udp-port=${ss_port}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    command -v qrencode &>/dev/null && echo "$surge" | qrencode -o - -t ANSIUTF8
}

ss2022_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}      SS2022 + Shadow-TLS${NC}"
        print_line
        check_ss2022
        print_line
        print_menu_item "1" "安装"
        print_menu_item "2" "查看节点信息"
        print_menu_item "3" "重启服务"
        print_menu_item "4" "卸载"
        print_line
        print_menu_item "0" "返回"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1) install_ss2022; press_any_key ;;
            2) show_ss2022_config; press_any_key ;;
            3) service_restart shadowsocks; service_restart shadow-tls; log_success "已重启"; press_any_key ;;
            4)
                if confirm "确认卸载？"; then
                    service_stop shadowsocks
                    service_stop shadow-tls
                    rm -f /etc/systemd/system/{shadowsocks,shadow-tls}.service "$SS_BIN" "$STLS_BIN"
                    rm -rf /etc/shadowsocks
                    systemctl daemon-reload
                    log_success "已卸载"
                fi
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== Sing-box 模块 ====================
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/etc/sing-box"
SINGBOX_CONF="${SINGBOX_DIR}/config.json"

check_singbox() {
    if [[ -f "$SINGBOX_BIN" ]]; then
        local ver=$($SINGBOX_BIN version 2>/dev/null | head -1 | awk '{print $NF}')
        echo -e "Sing-box: ${GREEN}${ver:-未知}${NC} ($(service_status sing-box))"
        return 0
    else
        echo -e "Sing-box: ${RED}未安装${NC}"
        return 1
    fi
}

install_singbox_core() {
    ensure_cmd wget wget
    ensure_cmd curl curl
    
    log_info "下载 Sing-box..."
    local ver
    if command -v jq &>/dev/null; then
        ver=$(curl -sL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' | tr -d 'v')
    else
        ver=$(curl -sL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep -o '"tag_name"[^,]*' | head -1 | cut -d'"' -f4 | tr -d 'v')
    fi
    ver=${ver:-1.10.7}
    local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${ARCH}.tar.gz"
    
    cd /tmp
    wget -q --show-progress "$url" -O singbox.tar.gz || { log_error "下载失败"; return 1; }
    tar -xzf singbox.tar.gz && mv sing-box-*/sing-box "$SINGBOX_BIN" && chmod +x "$SINGBOX_BIN"
    rm -rf singbox.tar.gz sing-box-*
    mkdir -p "$SINGBOX_DIR"
    
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=Sing-box
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_success "Sing-box 核心安装完成"
}

install_vless_reality() {
    clear
    print_line
    echo -e "${CYAN}      安装 VLESS + Reality${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    local port uuid sni
    read -r -p "端口 (默认随机): " port; port=${port:-$(get_available_port)}
    read -r -p "UUID (默认随机): " uuid; uuid=${uuid:-$($SINGBOX_BIN generate uuid)}
    read -r -p "SNI (默认 www.apple.com): " sni; sni=${sni:-www.apple.com}
    
    local keys=$($SINGBOX_BIN generate reality-keypair)
    local private_key=$(echo "$keys" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keys" | grep "PublicKey" | awk '{print $2}')
    local short_id=$(random_hex 8)
    
    cat > "$SINGBOX_CONF" << EOF
{"log":{"level":"info"},"inbounds":[{"type":"vless","tag":"vless-reality","listen":"::","listen_port":${port},"users":[{"uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"]}}}],"outbounds":[{"type":"direct","tag":"direct"}]}
EOF
    
    cat > "${SINGBOX_DIR}/reality.conf" << EOF
PORT=${port}
UUID=${uuid}
SNI=${sni}
PUBLIC_KEY=${public_key}
SHORT_ID=${short_id}
EOF
    
    service_enable sing-box
    service_start sing-box
    firewall_allow_port "$port" tcp
    
    sleep 2
    log_success "VLESS Reality 安装成功"
    show_vless_reality
}

show_vless_reality() {
    [[ ! -f "${SINGBOX_DIR}/reality.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/reality.conf"
    local ip=$(get_ipv4)
    
    print_line
    echo -e "${YELLOW}【VLESS Reality 节点】${NC}"
    echo -e "  服务器:   ${GREEN}${ip}${NC}"
    echo -e "  端口:     ${GREEN}${PORT}${NC}"
    echo -e "  UUID:     ${GREEN}${UUID}${NC}"
    echo -e "  SNI:      ${GREEN}${SNI}${NC}"
    echo -e "  公钥:     ${GREEN}${PUBLIC_KEY}${NC}"
    echo -e "  Short ID: ${GREEN}${SHORT_ID}${NC}"
    print_line
    
    local link="vless://${UUID}@${ip}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#VLESS-Reality"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="VLESS-Reality = VLESS,${ip},${PORT},\"${UUID}\",transport=tcp,flow=xtls-rprx-vision,over-tls=true,sni=${SNI},skip-cert-verify=true,public-key=\"${PUBLIC_KEY}\",short-id=${SHORT_ID},udp=true"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    command -v qrencode &>/dev/null && echo "$link" | qrencode -o - -t ANSIUTF8
}

install_hysteria2() {
    clear
    print_line
    echo -e "${CYAN}          安装 Hysteria2${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    ensure_cmd openssl openssl
    
    local port password domain
    read -r -p "端口 (默认随机): " port; port=${port:-$(get_available_port)}
    read -r -p "密码 (默认随机): " password; password=${password:-$(random_string 16)}
    domain="www.bing.com"
    
    # 自签证书
    openssl ecparam -genkey -name prime256v1 -out "${SINGBOX_DIR}/key.pem" 2>/dev/null
    openssl req -new -x509 -days 36500 -key "${SINGBOX_DIR}/key.pem" -out "${SINGBOX_DIR}/cert.pem" -subj "/CN=${domain}" 2>/dev/null
    
    cat > "$SINGBOX_CONF" << EOF
{"log":{"level":"info"},"inbounds":[{"type":"hysteria2","tag":"hy2","listen":"::","listen_port":${port},"users":[{"password":"${password}"}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${SINGBOX_DIR}/cert.pem","key_path":"${SINGBOX_DIR}/key.pem"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
EOF
    
    cat > "${SINGBOX_DIR}/hysteria2.conf" << EOF
PORT=${port}
PASSWORD=${password}
DOMAIN=${domain}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" udp
    
    sleep 2
    log_success "Hysteria2 安装成功"
    show_hysteria2
}

show_hysteria2() {
    [[ ! -f "${SINGBOX_DIR}/hysteria2.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/hysteria2.conf"
    local ip=$(get_ipv4)
    
    print_line
    echo -e "${YELLOW}【Hysteria2 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  密码:   ${GREEN}${PASSWORD}${NC}"
    echo -e "  SNI:    ${GREEN}${DOMAIN}${NC}"
    print_line
    
    local link="hysteria2://${PASSWORD}@${ip}:${PORT}?sni=${DOMAIN}&insecure=true#Hysteria2"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="Hysteria2 = Hysteria2,${ip},${PORT},\"${PASSWORD}\",sni=${DOMAIN},skip-cert-verify=true,udp=true"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    command -v qrencode &>/dev/null && echo "$link" | qrencode -o - -t ANSIUTF8
}

singbox_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}        Sing-box 多协议节点${NC}"
        print_line
        check_singbox
        print_line
        print_menu_item "1" "安装 VLESS + Reality"
        print_menu_item "2" "安装 Hysteria2"
        print_menu_item "3" "查看节点信息"
        print_menu_item "4" "重启服务"
        print_menu_item "5" "卸载"
        print_line
        print_menu_item "0" "返回"
        print_line
        
        read -r -p "请选择 [0-5]: " choice
        case $choice in
            1) install_vless_reality; press_any_key ;;
            2) install_hysteria2; press_any_key ;;
            3)
                [[ -f "${SINGBOX_DIR}/reality.conf" ]] && show_vless_reality
                [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]] && show_hysteria2
                press_any_key
                ;;
            4) service_restart sing-box; log_success "已重启"; press_any_key ;;
            5)
                if confirm "确认卸载？"; then
                    service_stop sing-box
                    rm -f /etc/systemd/system/sing-box.service "$SINGBOX_BIN"
                    rm -rf "$SINGBOX_DIR"
                    systemctl daemon-reload
                    log_success "已卸载"
                fi
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 节点菜单 ====================
proxy_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}              节点搭建${NC}"
        print_line
        print_menu_item "1" "Snell 节点 (v4/v5)"
        print_menu_item "2" "Sing-box 多协议 (Reality/Hy2)"
        print_menu_item "3" "SS2022 + Shadow-TLS"
        print_line
        print_menu_item "4" "查看所有节点"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-4]: " choice
        case $choice in
            1) snell_menu ;;
            2) singbox_menu ;;
            3) ss2022_menu ;;
            4)
                clear
                print_line
                echo -e "${CYAN}          已安装节点信息${NC}"
                print_line
                [[ -f "$SNELL_CONF" ]] && show_snell_config && echo
                [[ -f "$SS_CONF" ]] && show_ss2022_config && echo
                [[ -f "${SINGBOX_DIR}/reality.conf" ]] && show_vless_reality && echo
                [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]] && show_hysteria2 && echo
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 主菜单 ====================
show_main_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}     VPS 一键管理工具箱 v${SCRIPT_VERSION}${NC}"
        print_line
        echo -e " 系统: ${GREEN}${OS_NAME}${NC}"
        echo -e " IP:   ${GREEN}$(get_ipv4 || echo '获取中...')${NC}"
        print_line
        print_menu_item "1" "系统信息与优化"
        print_menu_item "2" "BBR 网络加速"
        print_menu_item "3" "安全与访问管理"
        print_menu_item "4" "节点搭建"
        print_menu_item "5" "Docker 管理"
        print_menu_item "6" "面板管理"
        print_line
        print_menu_item "0" "退出脚本"
        print_line
        
        read -r -p "请选择 [0-6]: " choice
        case $choice in
            1) system_menu ;;
            2) bbr_menu ;;
            3) security_menu ;;
            4) proxy_menu ;;
            5) docker_menu ;;
            6) panel_menu ;;
            0) echo; log_info "再见！"; exit 0 ;;
            *) log_error "无效选项" && sleep 1 ;;
        esac
    done
}

# ==================== 主入口 ====================
main() {
    check_root
    detect_os
    detect_arch
    detect_virt
    show_main_menu
}

main "$@"
