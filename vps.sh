#!/usr/bin/env bash
#
# VPS 一键管理工具箱
# GitHub: https://github.com/your-username/vps-toolkit
# 使用: bash <(curl -sL https://raw.githubusercontent.com/your-username/vps-toolkit/main/vps.sh)
#
# 版本: 1.0.0
#

# 强制设置 PATH - 解决进程替换执行时的环境问题
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH LANG=C.UTF-8

# 定义 clear 函数（兼容没有 ncurses 的系统）
if ! command -v clear &>/dev/null; then
    clear() { printf '\033[2J\033[H'; }
fi

# 检查是否为 root
if [[ $EUID -ne 0 ]]; then
    echo "请以 root 权限运行此脚本"
    exit 1
fi

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

# 生成在线二维码链接
show_qrcode() {
    local content=$1
    # URL 编码
    local encoded=$(echo -n "$content" | sed 's/:/%3A/g; s/\//%2F/g; s/?/%3F/g; s/=/%3D/g; s/&/%26/g; s/@/%40/g; s/#/%23/g; s/ /%20/g')
    local qr_url="https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encoded}"
    echo -e "${YELLOW}【在线二维码】${NC}"
    echo -e "${GREEN}${qr_url}${NC}"
}

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
    local ip=""
    ip=$(curl -s4m8 icanhazip.com 2>/dev/null)
    [[ -z "$ip" ]] && ip=$(curl -s4m8 ipinfo.io/ip 2>/dev/null)
    [[ -z "$ip" ]] && ip=$(curl -s4m8 api.ipify.org 2>/dev/null)
    [[ -z "$ip" ]] && ip=$(curl -s4m8 ifconfig.me 2>/dev/null)
    [[ -z "$ip" ]] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "$ip"
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

system_update_full() {
    clear
    print_line
    echo -e "${CYAN}            系统更新${NC}"
    print_line
    
    echo -e "${YELLOW}将执行以下操作:${NC}"
    echo "  1. 更新软件包列表 (apt update)"
    echo "  2. 升级已安装软件 (apt upgrade)"
    echo "  3. 安装基础依赖 (curl wget sudo unzip socat vnstat nano)"
    echo
    
    if confirm "确认执行？"; then
        log_info "更新软件包列表..."
        pkg_update
        
        log_info "升级已安装软件..."
        pkg_upgrade
        
        log_info "安装基础依赖..."
        local deps="curl wget sudo unzip socat vnstat nano"
        for dep in $deps; do
            echo -ne "  安装 ${dep}... "
            if pkg_install "$dep"; then
                echo -e "${GREEN}✓${NC}"
            else
                echo -e "${YELLOW}跳过${NC}"
            fi
        done
        
        log_success "系统更新完成"
    fi
}

system_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}            系统信息与优化${NC}"
        print_line
        print_menu_item "1" "查看系统信息"
        print_menu_item "2" "系统更新 (更新+安装基础依赖)"
        print_menu_item "3" "安装常用工具"
        print_menu_item "4" "时区设置"
        print_menu_item "5" "Swap 管理"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-5]: " choice
        case $choice in
            1) show_system_info; press_any_key ;;
            2) system_update_full; press_any_key ;;
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

update_bbr_v3() {
    clear
    print_line
    echo -e "${CYAN}          更新 BBR v3 内核${NC}"
    print_line
    
    local current_ver=$(dpkg -l 2>/dev/null | grep "linux-image.*joeyblog" | awk '{print $3}' | head -1)
    if [[ -z "$current_ver" ]]; then
        log_error "未检测到 BBR v3 内核，请先安装"
        return 1
    fi
    
    echo -e "当前版本: ${GREEN}${current_ver}${NC}"
    
    ensure_cmd jq jq
    local arch_filter=$([[ "$ARCH" == "arm64" ]] && echo "arm64" || echo "x86_64")
    local release_data=$(curl -sL "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases")
    local latest_tag=$(echo "$release_data" | jq -r --arg f "$arch_filter" \
        'map(select(.tag_name | test($f; "i"))) | sort_by(.published_at) | .[-1].tag_name')
    
    echo -e "最新版本: ${GREEN}${latest_tag}${NC}"
    
    if [[ "$current_ver" == *"$latest_tag"* ]]; then
        log_success "已是最新版本"
        return
    fi
    
    if confirm "发现新版本，是否更新？"; then
        install_bbr_v3
    fi
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
        print_menu_item "2" "更新 BBR v3 内核"
        print_menu_item "3" "启用 BBR + FQ"
        print_menu_item "4" "启用 BBR + FQ_PIE"
        print_menu_item "5" "启用 BBR + CAKE"
        print_line
        print_menu_item "0" "返回主菜单"
        print_line
        
        read -r -p "请选择 [0-5]: " choice
        case $choice in
            1) install_bbr_v3; press_any_key ;;
            2) update_bbr_v3; press_any_key ;;
            3) enable_bbr fq; press_any_key ;;
            4) enable_bbr fq_pie; press_any_key ;;
            5) enable_bbr cake; press_any_key ;;
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

# ==================== Fail2ban 完整管理 ====================
check_fail2ban_status() {
    if command -v fail2ban-client &>/dev/null; then
        local status=$(service_status fail2ban)
        echo -e "Fail2ban: ${GREEN}已安装${NC} (${status})"
        return 0
    else
        echo -e "Fail2ban: ${RED}未安装${NC}"
        return 1
    fi
}

install_fail2ban_full() {
    clear
    print_line
    echo -e "${CYAN}          安装 Fail2ban${NC}"
    print_line
    
    if command -v fail2ban-client &>/dev/null; then
        log_warn "Fail2ban 已安装"
        return
    fi
    
    log_info "安装 Fail2ban..."
    pkg_update
    pkg_install fail2ban rsyslog
    
    # 确保日志文件存在
    [[ ! -f /var/log/auth.log ]] && touch /var/log/auth.log
    
    # 配置 SSH 防护
    local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport
backend = auto

[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 300
bantime = 3600
EOF
    
    service_enable fail2ban
    service_enable rsyslog
    service_start rsyslog
    service_restart fail2ban
    
    sleep 2
    if service_status fail2ban | grep -q "active"; then
        log_success "Fail2ban 安装成功"
    else
        log_error "Fail2ban 启动失败，请检查日志"
    fi
}

show_fail2ban_status() {
    clear
    print_line
    echo -e "${CYAN}        Fail2ban 运行状态${NC}"
    print_line
    
    if ! command -v fail2ban-client &>/dev/null; then
        log_error "Fail2ban 未安装"
        return
    fi
    
    echo -e "${YELLOW}【服务状态】${NC}"
    systemctl status fail2ban --no-pager 2>/dev/null | head -10
    echo
    
    echo -e "${YELLOW}【监控状态】${NC}"
    fail2ban-client status 2>/dev/null
    echo
    
    echo -e "${YELLOW}【SSH 监控详情】${NC}"
    fail2ban-client status sshd 2>/dev/null || echo "SSH 监控未启用"
}

show_fail2ban_banned() {
    clear
    print_line
    echo -e "${CYAN}        Fail2ban 封禁列表${NC}"
    print_line
    
    if ! command -v fail2ban-client &>/dev/null; then
        log_error "Fail2ban 未安装"
        return
    fi
    
    echo -e "${YELLOW}【当前封禁 IP】${NC}"
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//' | tr ',' ' ')
    
    if [[ -z "$jails" ]]; then
        echo "无活动监控"
        return
    fi
    
    for jail in $jails; do
        echo -e "\n${GREEN}[$jail]${NC}"
        local banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP" | sed 's/.*:\s*//')
        if [[ -n "$banned" && "$banned" != " " ]]; then
            echo "$banned" | tr ' ' '\n' | while read ip; do
                [[ -n "$ip" ]] && echo "  - $ip"
            done
        else
            echo "  无封禁"
        fi
    done
    
    echo
    echo -e "${YELLOW}【手动解封】${NC}"
    read -r -p "输入要解封的 IP (留空跳过): " unban_ip
    if [[ -n "$unban_ip" ]]; then
        for jail in $jails; do
            fail2ban-client set "$jail" unbanip "$unban_ip" 2>/dev/null
        done
        log_success "已解封 $unban_ip"
    fi
}

edit_fail2ban_config() {
    clear
    print_line
    echo -e "${CYAN}        编辑 Fail2ban 配置${NC}"
    print_line
    
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        log_error "配置文件不存在"
        return
    fi
    
    echo -e "${YELLOW}【当前配置】${NC}"
    cat /etc/fail2ban/jail.local
    print_line
    
    echo -e "${YELLOW}【快速修改】${NC}"
    print_menu_item "1" "修改封禁时间"
    print_menu_item "2" "修改最大重试次数"
    print_menu_item "3" "修改检测时间窗口"
    print_menu_item "4" "修改 SSH 端口"
    print_menu_item "5" "使用编辑器编辑"
    print_menu_item "0" "返回"
    print_line
    
    read -r -p "请选择 [0-5]: " choice
    case $choice in
        1)
            read -r -p "封禁时间 (秒，当前默认3600): " bantime
            [[ "$bantime" =~ ^[0-9]+$ ]] && sed -i "s/^bantime = .*/bantime = ${bantime}/" /etc/fail2ban/jail.local
            ;;
        2)
            read -r -p "最大重试次数 (当前默认5): " maxretry
            [[ "$maxretry" =~ ^[0-9]+$ ]] && sed -i "s/^maxretry = .*/maxretry = ${maxretry}/" /etc/fail2ban/jail.local
            ;;
        3)
            read -r -p "检测时间窗口 (秒，当前默认600): " findtime
            [[ "$findtime" =~ ^[0-9]+$ ]] && sed -i "s/^findtime = .*/findtime = ${findtime}/" /etc/fail2ban/jail.local
            ;;
        4)
            read -r -p "SSH 端口: " port
            [[ "$port" =~ ^[0-9]+$ ]] && sed -i "s/^port = .*/port = ${port}/" /etc/fail2ban/jail.local
            ;;
        5)
            if command -v nano &>/dev/null; then
                nano /etc/fail2ban/jail.local
            elif command -v vim &>/dev/null; then
                vim /etc/fail2ban/jail.local
            else
                vi /etc/fail2ban/jail.local
            fi
            ;;
        0) return ;;
    esac
    
    if [[ "$choice" =~ ^[1-4]$ ]]; then
        service_restart fail2ban
        log_success "配置已更新并重启服务"
    fi
}

update_fail2ban() {
    clear
    print_line
    echo -e "${CYAN}          更新 Fail2ban${NC}"
    print_line
    
    if ! command -v fail2ban-client &>/dev/null; then
        log_error "Fail2ban 未安装"
        return
    fi
    
    local current_ver=$(fail2ban-client --version 2>/dev/null | head -1)
    echo -e "当前版本: ${GREEN}${current_ver}${NC}"
    
    if confirm "确认更新 Fail2ban？"; then
        log_info "更新中..."
        pkg_update
        case $OS in
            ubuntu|debian|linuxmint)
                apt-get install --only-upgrade -y fail2ban
                ;;
            centos|rhel|fedora|rocky|almalinux)
                yum update -y fail2ban || dnf update -y fail2ban
                ;;
        esac
        service_restart fail2ban
        local new_ver=$(fail2ban-client --version 2>/dev/null | head -1)
        log_success "更新完成: ${new_ver}"
    fi
}

uninstall_fail2ban() {
    clear
    print_line
    echo -e "${CYAN}          卸载 Fail2ban${NC}"
    print_line
    
    if ! command -v fail2ban-client &>/dev/null; then
        log_error "Fail2ban 未安装"
        return
    fi
    
    if confirm "确认卸载 Fail2ban？"; then
        log_info "卸载中..."
        service_stop fail2ban
        case $OS in
            ubuntu|debian|linuxmint)
                apt-get remove --purge -y fail2ban
                apt-get autoremove -y
                ;;
            centos|rhel|fedora|rocky|almalinux)
                yum remove -y fail2ban || dnf remove -y fail2ban
                ;;
        esac
        rm -rf /etc/fail2ban
        log_success "Fail2ban 已卸载"
    fi
}

fail2ban_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}          Fail2ban 管理${NC}"
        print_line
        check_fail2ban_status
        print_line
        print_menu_item "1" "安装 Fail2ban"
        print_menu_item "2" "查看运行状态"
        print_menu_item "3" "查看封禁列表"
        print_menu_item "4" "编辑配置"
        print_menu_item "5" "重启服务"
        print_menu_item "6" "更新 Fail2ban"
        print_menu_item "7" "卸载 Fail2ban"
        print_line
        print_menu_item "0" "返回"
        print_line
        
        read -r -p "请选择 [0-7]: " choice
        case $choice in
            1) install_fail2ban_full; press_any_key ;;
            2) show_fail2ban_status; press_any_key ;;
            3) show_fail2ban_banned; press_any_key ;;
            4) edit_fail2ban_config; press_any_key ;;
            5) service_restart fail2ban; log_success "已重启"; press_any_key ;;
            6) update_fail2ban; press_any_key ;;
            7) uninstall_fail2ban; press_any_key ;;
            0) return ;;
        esac
    done
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
            4) fail2ban_menu ;;
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
    press_any_key
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
    
    local surge="Snell = snell, ${ip}, ${port}, psk=${psk}, version=${ver}, tfo=true"
    echo -e "${YELLOW}【Surge 配置】${NC}"
    echo -e "${CYAN}${surge}${NC}"
    print_line
    
    local loon="Snell = Snell,${ip},${port},psk=${psk},version=${ver},tfo=true"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
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
            1) install_snell "4.1.1" ;;
            2) install_snell "5.0.1" ;;
            3) clear; show_snell_config; press_any_key ;;
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
    
    show_qrcode "$surge"
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

# ==================== 证书管理模块 ====================
CERT_DIR="/etc/ssl/private"
ACME_HOME="$HOME/.acme.sh"

install_acme() {
    if [[ ! -f "$ACME_HOME/acme.sh" ]]; then
        log_info "安装 acme.sh..."
        curl -sL https://get.acme.sh | sh -s email=admin@example.com
        source "$ACME_HOME/acme.sh.env" 2>/dev/null
    fi
}

# 申请证书 - 支持 Cloudflare DNS 验证
apply_cert_cf() {
    local domain=$1
    
    install_acme
    mkdir -p "$CERT_DIR"
    
    echo -e "${YELLOW}使用 Cloudflare DNS 验证申请证书${NC}"
    echo -e "请准备 Cloudflare API Token (需要 Zone:DNS:Edit 权限)"
    echo
    
    read -r -p "Cloudflare API Token: " cf_token
    [[ -z "$cf_token" ]] && { log_error "Token 不能为空"; return 1; }
    
    export CF_Token="$cf_token"
    
    log_info "申请证书: ${domain}..."
    "$ACME_HOME/acme.sh" --issue --dns dns_cf -d "$domain" --keylength ec-256 --force
    
    if [[ $? -eq 0 ]]; then
        "$ACME_HOME/acme.sh" --install-cert -d "$domain" --ecc \
            --key-file "${CERT_DIR}/${domain}.key" \
            --fullchain-file "${CERT_DIR}/${domain}.crt"
        log_success "证书申请成功"
        return 0
    else
        log_error "证书申请失败"
        return 1
    fi
}

# 申请证书 - HTTP 验证 (需要80端口)
apply_cert_http() {
    local domain=$1
    
    install_acme
    mkdir -p "$CERT_DIR"
    
    # 检查80端口
    if ss -tlnp | grep -q ":80 "; then
        log_warn "80 端口被占用，请先停止占用服务"
        return 1
    fi
    
    log_info "申请证书: ${domain}..."
    "$ACME_HOME/acme.sh" --issue -d "$domain" --standalone --keylength ec-256 --force
    
    if [[ $? -eq 0 ]]; then
        "$ACME_HOME/acme.sh" --install-cert -d "$domain" --ecc \
            --key-file "${CERT_DIR}/${domain}.key" \
            --fullchain-file "${CERT_DIR}/${domain}.crt"
        log_success "证书申请成功"
        return 0
    else
        log_error "证书申请失败"
        return 1
    fi
}

# 选择证书模式
select_tls_mode() {
    local domain_var=$1
    local cert_path_var=$2
    local key_path_var=$3
    local skip_verify_var=$4
    
    echo
    echo -e "${YELLOW}【TLS 证书模式】${NC}"
    print_menu_item "1" "自签证书 (快速，需跳过验证)"
    print_menu_item "2" "真实域名 + Cloudflare DNS 验证 (推荐套CDN)"
    print_menu_item "3" "真实域名 + HTTP 验证 (需80端口)"
    print_line
    
    read -r -p "请选择 [1-3]: " tls_mode
    
    case $tls_mode in
        1)
            read -r -p "伪装域名 (默认 www.bing.com): " domain
            domain=${domain:-www.bing.com}
            
            openssl ecparam -genkey -name prime256v1 -out "${SINGBOX_DIR}/key.pem" 2>/dev/null
            openssl req -new -x509 -days 36500 -key "${SINGBOX_DIR}/key.pem" -out "${SINGBOX_DIR}/cert.pem" -subj "/CN=${domain}" 2>/dev/null
            
            eval "$domain_var='$domain'"
            eval "$cert_path_var='${SINGBOX_DIR}/cert.pem'"
            eval "$key_path_var='${SINGBOX_DIR}/key.pem'"
            eval "$skip_verify_var='true'"
            ;;
        2)
            read -r -p "你的域名 (如 example.com): " domain
            [[ -z "$domain" ]] && { log_error "域名不能为空"; return 1; }
            
            if apply_cert_cf "$domain"; then
                eval "$domain_var='$domain'"
                eval "$cert_path_var='${CERT_DIR}/${domain}.crt'"
                eval "$key_path_var='${CERT_DIR}/${domain}.key'"
                eval "$skip_verify_var='false'"
            else
                return 1
            fi
            ;;
        3)
            read -r -p "你的域名 (需解析到本机IP): " domain
            [[ -z "$domain" ]] && { log_error "域名不能为空"; return 1; }
            
            if apply_cert_http "$domain"; then
                eval "$domain_var='$domain'"
                eval "$cert_path_var='${CERT_DIR}/${domain}.crt'"
                eval "$key_path_var='${CERT_DIR}/${domain}.key'"
                eval "$skip_verify_var='false'"
            else
                return 1
            fi
            ;;
        *)
            log_error "无效选择"
            return 1
            ;;
    esac
    return 0
}

# ==================== Sing-box 模块 ====================
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/etc/sing-box"
SINGBOX_CONF="${SINGBOX_DIR}/config.json"
SINGBOX_INBOUNDS_DIR="${SINGBOX_DIR}/inbounds"

check_singbox() {
    if [[ -f "$SINGBOX_BIN" ]]; then
        local ver=$($SINGBOX_BIN version 2>/dev/null | head -1 | awk '{print $NF}')
        local status=$(service_status sing-box)
        local count=$(find "${SINGBOX_INBOUNDS_DIR}" -name "*.json" ! -name "00_base.json" 2>/dev/null | wc -l)
        echo -e "Sing-box: ${GREEN}${ver:-未知}${NC} (${status}) - ${GREEN}${count}${NC} 个节点"
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
    mkdir -p "$SINGBOX_DIR" "$SINGBOX_INBOUNDS_DIR"
    
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

# 重新生成 config.json（使用 sing-box merge 合并所有配置）
rebuild_singbox_config() {
    mkdir -p "$SINGBOX_INBOUNDS_DIR"
    
    # 创建基础配置（log 和 outbounds）
    cat > "${SINGBOX_INBOUNDS_DIR}/00_base.json" << 'EOF'
{
  "log": {"level": "info", "timestamp": true},
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    
    # 使用 sing-box merge 命令合并配置
    rm -f "$SINGBOX_CONF" 2>/dev/null
    if $SINGBOX_BIN merge "$SINGBOX_CONF" -C "$SINGBOX_INBOUNDS_DIR" 2>/dev/null; then
        return 0
    else
        # 如果 merge 失败，尝试手动合并
        log_warn "sing-box merge 失败，尝试手动合并..."
        ensure_cmd jq jq
        
        local inbounds="[]"
        for f in "${SINGBOX_INBOUNDS_DIR}"/*.json; do
            [[ -f "$f" ]] || continue
            [[ "$(basename "$f")" == "00_base.json" ]] && continue
            # 从 {"inbounds": [...]} 格式中提取 inbounds 数组
            local file_inbounds=$(cat "$f" 2>/dev/null | jq -c '.inbounds // []')
            [[ -n "$file_inbounds" && "$file_inbounds" != "[]" ]] && inbounds=$(echo "$inbounds" | jq --argjson new "$file_inbounds" '. + $new')
        done
        
        cat > "$SINGBOX_CONF" << EOF
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": ${inbounds},
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
        
        if $SINGBOX_BIN check -c "$SINGBOX_CONF" 2>/dev/null; then
            return 0
        else
            log_error "配置验证失败"
            return 1
        fi
    fi
}

# 添加单个 inbound 配置
add_singbox_inbound() {
    local name=$1
    local inbound_json=$2
    
    mkdir -p "$SINGBOX_INBOUNDS_DIR"
    
    # 保存为完整的 inbounds 配置格式（用于 merge）
    cat > "${SINGBOX_INBOUNDS_DIR}/${name}.json" << EOF
{
  "inbounds": [${inbound_json}]
}
EOF
    
    rebuild_singbox_config
}

# 删除单个 inbound 配置
remove_singbox_inbound() {
    local name=$1
    rm -f "${SINGBOX_INBOUNDS_DIR}/${name}.json" 2>/dev/null
    rm -f "${SINGBOX_DIR}/${name}.conf" 2>/dev/null
    
    # 检查是否还有其他节点（排除 00_base.json）
    local count=$(find "${SINGBOX_INBOUNDS_DIR}" -name "*.json" ! -name "00_base.json" 2>/dev/null | wc -l)
    if [[ $count -eq 0 ]]; then
        service_stop sing-box
        rm -f "$SINGBOX_CONF" 2>/dev/null
        rm -f "${SINGBOX_INBOUNDS_DIR}/00_base.json" 2>/dev/null
    else
        rebuild_singbox_config
        service_restart sing-box
    fi
}

install_vless_reality() {
    clear
    print_line
    echo -e "${CYAN}      安装 VLESS + Reality${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    # 检查是否已安装同类型节点
    if [[ -f "${SINGBOX_DIR}/reality.conf" ]]; then
        log_warn "VLESS Reality 已安装"
        confirm "是否重新安装？" || return
    fi
    
    local port uuid sni
    read -r -p "端口 (默认随机): " port; port=${port:-$(get_available_port)}
    read -r -p "UUID (默认随机): " uuid; uuid=${uuid:-$($SINGBOX_BIN generate uuid)}
    read -r -p "SNI (默认 www.apple.com): " sni; sni=${sni:-www.apple.com}
    
    local keys=$($SINGBOX_BIN generate reality-keypair)
    local private_key=$(echo "$keys" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keys" | grep "PublicKey" | awk '{print $2}')
    local short_id=$(random_hex 8)
    
    # 保存 inbound 配置
    local inbound_json=$(cat << EOF
{"type":"vless","tag":"vless-reality","listen":"::","listen_port":${port},"users":[{"uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"]}}}
EOF
)
    add_singbox_inbound "reality" "$inbound_json"
    
    # 保存节点参数
    cat > "${SINGBOX_DIR}/reality.conf" << EOF
PORT=${port}
UUID=${uuid}
SNI=${sni}
PUBLIC_KEY=${public_key}
SHORT_ID=${short_id}
EOF
    
    service_enable sing-box
    service_restart sing-box
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
    
    local loon="VLESS-Reality = VLESS,${ip},${PORT},\"${UUID}\",transport=tcp,flow=xtls-rprx-vision,public-key=\"${PUBLIC_KEY}\",short-id=${SHORT_ID},udp=true,block-quic=true,over-tls=true,sni=${SNI}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
}

install_hysteria2() {
    clear
    print_line
    echo -e "${CYAN}          安装 Hysteria2${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    if [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]]; then
        log_warn "Hysteria2 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port password domain
    read -r -p "端口 (默认随机): " port; port=${port:-$(get_available_port)}
    read -r -p "密码 (默认随机): " password; password=${password:-$(random_string 16)}
    domain="www.bing.com"
    
    # 自签证书（每个协议独立证书）
    local cert_file="${SINGBOX_DIR}/hy2_cert.pem"
    local key_file="${SINGBOX_DIR}/hy2_key.pem"
    openssl ecparam -genkey -name prime256v1 -out "$key_file" 2>/dev/null
    openssl req -new -x509 -days 36500 -key "$key_file" -out "$cert_file" -subj "/CN=${domain}" 2>/dev/null
    
    local inbound_json=$(cat << EOF
{"type":"hysteria2","tag":"hy2","listen":"::","listen_port":${port},"users":[{"password":"${password}"}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${cert_file}","key_path":"${key_file}"}}
EOF
)
    add_singbox_inbound "hysteria2" "$inbound_json"
    
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

install_vmess_ws() {
    clear
    print_line
    echo -e "${CYAN}        安装 VMess + WS + TLS${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    if [[ -f "${SINGBOX_DIR}/vmess-ws.conf" ]]; then
        log_warn "VMess WS 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port uuid path domain cert_path key_path skip_verify
    read -r -p "端口 (默认443): " port; port=${port:-443}
    read -r -p "UUID (默认随机): " uuid; uuid=${uuid:-$($SINGBOX_BIN generate uuid)}
    read -r -p "WS路径 (默认随机): " path; path=${path:-"/$(random_string 8)"}
    
    # 选择证书模式
    select_tls_mode domain cert_path key_path skip_verify || return 1
    
    local inbound_json=$(cat << EOF
{"type":"vmess","tag":"vmess-ws","listen":"::","listen_port":${port},"users":[{"uuid":"${uuid}"}],"transport":{"type":"ws","path":"${path}"},"tls":{"enabled":true,"server_name":"${domain}","certificate_path":"${cert_path}","key_path":"${key_path}"}}
EOF
)
    add_singbox_inbound "vmess-ws" "$inbound_json"
    
    cat > "${SINGBOX_DIR}/vmess-ws.conf" << EOF
PORT=${port}
UUID=${uuid}
PATH=${path}
DOMAIN=${domain}
SKIP_VERIFY=${skip_verify}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" tcp
    
    sleep 2
    log_success "VMess WS TLS 安装成功"
    show_vmess_ws
}

show_vmess_ws() {
    [[ ! -f "${SINGBOX_DIR}/vmess-ws.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/vmess-ws.conf"
    local ip=$(get_ipv4)
    local skip_verify_val=${SKIP_VERIFY:-true}
    
    print_line
    echo -e "${YELLOW}【VMess + WS + TLS 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  UUID:   ${GREEN}${UUID}${NC}"
    echo -e "  路径:   ${GREEN}${PATH}${NC}"
    echo -e "  域名:   ${GREEN}${DOMAIN}${NC}"
    echo -e "  证书:   ${GREEN}$([[ "$skip_verify_val" == "true" ]] && echo "自签" || echo "真实")${NC}"
    print_line
    
    # 如果是真实证书，使用域名作为地址；否则使用IP
    local addr=$([[ "$skip_verify_val" == "false" ]] && echo "$DOMAIN" || echo "$ip")
    
    local vmess_json="{\"v\":\"2\",\"ps\":\"VMess-WS\",\"add\":\"${addr}\",\"port\":\"${PORT}\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"${PATH}\",\"tls\":\"tls\",\"sni\":\"${DOMAIN}\"}"
    local link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="VMess-WS = vmess,${addr},${PORT},aes-128-gcm,\"${UUID}\",transport=ws,path=${PATH},host=${DOMAIN},over-tls=true,sni=${DOMAIN},skip-cert-verify=${skip_verify_val}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
}

install_vless_ws() {
    clear
    print_line
    echo -e "${CYAN}        安装 VLESS + WS + TLS${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    if [[ -f "${SINGBOX_DIR}/vless-ws.conf" ]]; then
        log_warn "VLESS WS 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port uuid path domain cert_path key_path skip_verify
    read -r -p "端口 (默认443): " port; port=${port:-443}
    read -r -p "UUID (默认随机): " uuid; uuid=${uuid:-$($SINGBOX_BIN generate uuid)}
    read -r -p "WS路径 (默认随机): " path; path=${path:-"/$(random_string 8)"}
    
    # 选择证书模式
    select_tls_mode domain cert_path key_path skip_verify || return 1
    
    local inbound_json=$(cat << EOF
{"type":"vless","tag":"vless-ws","listen":"::","listen_port":${port},"users":[{"uuid":"${uuid}"}],"transport":{"type":"ws","path":"${path}"},"tls":{"enabled":true,"server_name":"${domain}","certificate_path":"${cert_path}","key_path":"${key_path}"}}
EOF
)
    add_singbox_inbound "vless-ws" "$inbound_json"
    
    cat > "${SINGBOX_DIR}/vless-ws.conf" << EOF
PORT=${port}
UUID=${uuid}
PATH=${path}
DOMAIN=${domain}
SKIP_VERIFY=${skip_verify}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" tcp
    
    sleep 2
    log_success "VLESS WS TLS 安装成功"
    show_vless_ws
}

show_vless_ws() {
    [[ ! -f "${SINGBOX_DIR}/vless-ws.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/vless-ws.conf"
    local ip=$(get_ipv4)
    local skip_verify_val=${SKIP_VERIFY:-true}
    
    print_line
    echo -e "${YELLOW}【VLESS + WS + TLS 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  UUID:   ${GREEN}${UUID}${NC}"
    echo -e "  路径:   ${GREEN}${PATH}${NC}"
    echo -e "  域名:   ${GREEN}${DOMAIN}${NC}"
    echo -e "  证书:   ${GREEN}$([[ "$skip_verify_val" == "true" ]] && echo "自签" || echo "真实")${NC}"
    print_line
    
    local addr=$([[ "$skip_verify_val" == "false" ]] && echo "$DOMAIN" || echo "$ip")
    
    local link="vless://${UUID}@${addr}:${PORT}?encryption=none&security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${PATH}#VLESS-WS"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="VLESS-WS = VLESS,${addr},${PORT},\"${UUID}\",transport=ws,path=${PATH},host=${DOMAIN},over-tls=true,sni=${DOMAIN},skip-cert-verify=${skip_verify_val}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
}

install_trojan_ws() {
    clear
    print_line
    echo -e "${CYAN}      安装 Trojan + WS + TLS${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    if [[ -f "${SINGBOX_DIR}/trojan-ws.conf" ]]; then
        log_warn "Trojan WS 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port password path domain cert_path key_path skip_verify
    read -r -p "端口 (默认443): " port; port=${port:-443}
    read -r -p "密码 (默认随机): " password; password=${password:-$(random_string 16)}
    read -r -p "WS路径 (默认随机): " path; path=${path:-"/$(random_string 8)"}
    
    # 选择证书模式
    select_tls_mode domain cert_path key_path skip_verify || return 1
    
    local inbound_json=$(cat << EOF
{"type":"trojan","tag":"trojan-ws","listen":"::","listen_port":${port},"users":[{"password":"${password}"}],"transport":{"type":"ws","path":"${path}"},"tls":{"enabled":true,"server_name":"${domain}","certificate_path":"${cert_path}","key_path":"${key_path}"}}
EOF
)
    add_singbox_inbound "trojan-ws" "$inbound_json"
    
    cat > "${SINGBOX_DIR}/trojan-ws.conf" << EOF
PORT=${port}
PASSWORD=${password}
PATH=${path}
DOMAIN=${domain}
SKIP_VERIFY=${skip_verify}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" tcp
    
    sleep 2
    log_success "Trojan WS TLS 安装成功"
    show_trojan_ws
}

show_trojan_ws() {
    [[ ! -f "${SINGBOX_DIR}/trojan-ws.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/trojan-ws.conf"
    local ip=$(get_ipv4)
    local skip_verify_val=${SKIP_VERIFY:-true}
    
    print_line
    echo -e "${YELLOW}【Trojan + WS + TLS 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  密码:   ${GREEN}${PASSWORD}${NC}"
    echo -e "  路径:   ${GREEN}${PATH}${NC}"
    echo -e "  域名:   ${GREEN}${DOMAIN}${NC}"
    echo -e "  证书:   ${GREEN}$([[ "$skip_verify_val" == "true" ]] && echo "自签" || echo "真实")${NC}"
    print_line
    
    local addr=$([[ "$skip_verify_val" == "false" ]] && echo "$DOMAIN" || echo "$ip")
    
    local link="trojan://${PASSWORD}@${addr}:${PORT}?security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=${PATH}#Trojan-WS"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="Trojan-WS = Trojan,${addr},${PORT},\"${PASSWORD}\",transport=ws,path=${PATH},host=${DOMAIN},over-tls=true,sni=${DOMAIN},skip-cert-verify=${skip_verify_val}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
}

install_trojan_http() {
    clear
    print_line
    echo -e "${CYAN}     安装 Trojan + HTTP + TLS${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    if [[ -f "${SINGBOX_DIR}/trojan-http.conf" ]]; then
        log_warn "Trojan HTTP 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port password path domain cert_path key_path skip_verify
    read -r -p "端口 (默认443): " port; port=${port:-443}
    read -r -p "密码 (默认随机): " password; password=${password:-$(random_string 16)}
    read -r -p "HTTP路径 (默认随机): " path; path=${path:-"/$(random_string 8)"}
    
    # 选择证书模式
    select_tls_mode domain cert_path key_path skip_verify || return 1
    
    local inbound_json=$(cat << EOF
{"type":"trojan","tag":"trojan-http","listen":"::","listen_port":${port},"users":[{"password":"${password}"}],"transport":{"type":"http","path":"${path}"},"tls":{"enabled":true,"server_name":"${domain}","certificate_path":"${cert_path}","key_path":"${key_path}"}}
EOF
)
    add_singbox_inbound "trojan-http" "$inbound_json"
    
    cat > "${SINGBOX_DIR}/trojan-http.conf" << EOF
PORT=${port}
PASSWORD=${password}
PATH=${path}
DOMAIN=${domain}
SKIP_VERIFY=${skip_verify}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" tcp
    
    sleep 2
    log_success "Trojan HTTP TLS 安装成功"
    show_trojan_http
}

show_trojan_http() {
    [[ ! -f "${SINGBOX_DIR}/trojan-http.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/trojan-http.conf"
    local ip=$(get_ipv4)
    local skip_verify_val=${SKIP_VERIFY:-true}
    
    print_line
    echo -e "${YELLOW}【Trojan + HTTP + TLS 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  密码:   ${GREEN}${PASSWORD}${NC}"
    echo -e "  路径:   ${GREEN}${PATH}${NC}"
    echo -e "  域名:   ${GREEN}${DOMAIN}${NC}"
    echo -e "  证书:   ${GREEN}$([[ "$skip_verify_val" == "true" ]] && echo "自签" || echo "真实")${NC}"
    print_line
    
    local addr=$([[ "$skip_verify_val" == "false" ]] && echo "$DOMAIN" || echo "$ip")
    
    local link="trojan://${PASSWORD}@${addr}:${PORT}?security=tls&sni=${DOMAIN}&type=http&host=${DOMAIN}&path=${PATH}#Trojan-HTTP"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="Trojan-HTTP = Trojan,${addr},${PORT},\"${PASSWORD}\",transport=http,path=${PATH},host=${DOMAIN},over-tls=true,sni=${DOMAIN},skip-cert-verify=${skip_verify_val}"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
}

install_tuic() {
    clear
    print_line
    echo -e "${CYAN}            安装 TUIC${NC}"
    print_line
    
    [[ ! -f "$SINGBOX_BIN" ]] && install_singbox_core
    
    if [[ -f "${SINGBOX_DIR}/tuic.conf" ]]; then
        log_warn "TUIC 已安装"
        confirm "是否重新安装？" || return
    fi
    
    ensure_cmd openssl openssl
    
    local port uuid password domain
    read -r -p "端口 (默认随机): " port; port=${port:-$(get_available_port)}
    read -r -p "UUID (默认随机): " uuid; uuid=${uuid:-$($SINGBOX_BIN generate uuid)}
    read -r -p "密码 (默认随机): " password; password=${password:-$(random_string 16)}
    domain="www.bing.com"
    
    local cert_file="${SINGBOX_DIR}/tuic_cert.pem"
    local key_file="${SINGBOX_DIR}/tuic_key.pem"
    openssl ecparam -genkey -name prime256v1 -out "$key_file" 2>/dev/null
    openssl req -new -x509 -days 36500 -key "$key_file" -out "$cert_file" -subj "/CN=${domain}" 2>/dev/null
    
    local inbound_json=$(cat << EOF
{"type":"tuic","tag":"tuic","listen":"::","listen_port":${port},"users":[{"uuid":"${uuid}","password":"${password}"}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":"${cert_file}","key_path":"${key_file}"}}
EOF
)
    add_singbox_inbound "tuic" "$inbound_json"
    
    cat > "${SINGBOX_DIR}/tuic.conf" << EOF
PORT=${port}
UUID=${uuid}
PASSWORD=${password}
DOMAIN=${domain}
EOF
    
    service_enable sing-box
    service_restart sing-box
    firewall_allow_port "$port" udp
    
    sleep 2
    log_success "TUIC 安装成功"
    show_tuic
}

show_tuic() {
    [[ ! -f "${SINGBOX_DIR}/tuic.conf" ]] && { log_error "未安装"; return; }
    source "${SINGBOX_DIR}/tuic.conf"
    local ip=$(get_ipv4)
    
    print_line
    echo -e "${YELLOW}【TUIC 节点】${NC}"
    echo -e "  服务器: ${GREEN}${ip}${NC}"
    echo -e "  端口:   ${GREEN}${PORT}${NC}"
    echo -e "  UUID:   ${GREEN}${UUID}${NC}"
    echo -e "  密码:   ${GREEN}${PASSWORD}${NC}"
    print_line
    
    local link="tuic://${UUID}:${PASSWORD}@${ip}:${PORT}?congestion_control=bbr&alpn=h3&sni=${DOMAIN}&udp_relay_mode=native&allow_insecure=1#TUIC"
    echo -e "${YELLOW}【分享链接】${NC}"
    echo -e "${CYAN}${link}${NC}"
    print_line
    
    local loon="TUIC = TUIC,${ip},${PORT},\"${UUID}\",\"${PASSWORD}\",sni=${DOMAIN},skip-cert-verify=true,udp=true"
    echo -e "${YELLOW}【Loon 配置】${NC}"
    echo -e "${CYAN}${loon}${NC}"
    print_line
    
    show_qrcode "$link"
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
    
    show_qrcode "$link"
}

show_all_singbox_nodes() {
    clear
    print_line
    echo -e "${CYAN}        Sing-box 节点信息${NC}"
    print_line
    
    local found=0
    [[ -f "${SINGBOX_DIR}/reality.conf" ]] && { show_vless_reality; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]] && { show_hysteria2; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/vmess-ws.conf" ]] && { show_vmess_ws; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/vless-ws.conf" ]] && { show_vless_ws; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/trojan-ws.conf" ]] && { show_trojan_ws; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/trojan-http.conf" ]] && { show_trojan_http; found=1; echo; }
    [[ -f "${SINGBOX_DIR}/tuic.conf" ]] && { show_tuic; found=1; echo; }
    
    [[ $found -eq 0 ]] && log_warn "未安装任何节点"
}

# 删除 Sing-box 节点
uninstall_singbox_node() {
    clear
    print_line
    echo -e "${CYAN}        删除 Sing-box 节点${NC}"
    print_line
    
    if [[ ! -f "$SINGBOX_BIN" ]]; then
        log_warn "Sing-box 未安装"
        return
    fi
    
    # 列出已安装的节点
    local nodes=()
    local names=()
    
    [[ -f "${SINGBOX_DIR}/reality.conf" ]] && { nodes+=("reality"); names+=("VLESS + Reality"); }
    [[ -f "${SINGBOX_DIR}/vmess-ws.conf" ]] && { nodes+=("vmess-ws"); names+=("VMess + WS + TLS"); }
    [[ -f "${SINGBOX_DIR}/vless-ws.conf" ]] && { nodes+=("vless-ws"); names+=("VLESS + WS + TLS"); }
    [[ -f "${SINGBOX_DIR}/trojan-ws.conf" ]] && { nodes+=("trojan-ws"); names+=("Trojan + WS + TLS"); }
    [[ -f "${SINGBOX_DIR}/trojan-http.conf" ]] && { nodes+=("trojan-http"); names+=("Trojan + HTTP + TLS"); }
    [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]] && { nodes+=("hysteria2"); names+=("Hysteria2"); }
    [[ -f "${SINGBOX_DIR}/tuic.conf" ]] && { nodes+=("tuic"); names+=("TUIC"); }
    
    if [[ ${#nodes[@]} -eq 0 ]]; then
        echo -e "已安装节点: ${YELLOW}无${NC}"
        echo
        if confirm "是否卸载 Sing-box 核心？"; then
            service_stop sing-box
            rm -f /etc/systemd/system/sing-box.service "$SINGBOX_BIN"
            rm -rf "$SINGBOX_DIR"
            systemctl daemon-reload
            log_success "Sing-box 已卸载"
        fi
        return
    fi
    
    echo -e "${YELLOW}已安装的节点 (${#nodes[@]} 个):${NC}"
    for i in "${!nodes[@]}"; do
        print_menu_item "$((i+1))" "${names[$i]}"
    done
    print_line
    print_menu_item "A" "删除全部节点"
    print_menu_item "U" "完全卸载 Sing-box"
    print_menu_item "0" "返回"
    print_line
    
    read -r -p "请选择: " choice
    
    [[ "$choice" == "0" ]] && return
    
    if [[ "$choice" == "A" || "$choice" == "a" ]]; then
        if confirm "确认删除全部节点？"; then
            for node in "${nodes[@]}"; do
                remove_singbox_inbound "$node"
            done
            log_success "已删除全部节点"
        fi
        return
    fi
    
    if [[ "$choice" == "U" || "$choice" == "u" ]]; then
        if confirm "确认完全卸载 Sing-box？"; then
            service_stop sing-box
            rm -f /etc/systemd/system/sing-box.service "$SINGBOX_BIN"
            rm -rf "$SINGBOX_DIR"
            systemctl daemon-reload
            log_success "Sing-box 已完全卸载"
        fi
        return
    fi
    
    # 删除单个节点
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#nodes[@]} ]]; then
        local node_type="${nodes[$((choice-1))]}"
        local node_name="${names[$((choice-1))]}"
        
        if confirm "确认删除 ${node_name}？"; then
            remove_singbox_inbound "$node_type"
            log_success "${node_name} 已删除"
        fi
    else
        log_error "无效选择"
    fi
}

singbox_menu() {
    while true; do
        clear
        print_line
        echo -e "${CYAN}        Sing-box 多协议节点${NC}"
        print_line
        check_singbox
        print_line
        echo -e "${YELLOW}【Reality 系列】${NC}"
        print_menu_item "1" "VLESS + Reality + Vision"
        echo -e "${YELLOW}【TLS 系列】${NC}"
        print_menu_item "2" "VMess + WS + TLS"
        print_menu_item "3" "VLESS + WS + TLS"
        print_menu_item "4" "Trojan + WS + TLS"
        print_menu_item "5" "Trojan + HTTP + TLS"
        echo -e "${YELLOW}【UDP 系列】${NC}"
        print_menu_item "6" "Hysteria2"
        print_menu_item "7" "TUIC"
        print_line
        print_menu_item "8" "查看节点信息"
        print_menu_item "9" "删除节点"
        print_menu_item "10" "重启服务"
        print_line
        print_menu_item "0" "返回"
        print_line
        
        read -r -p "请选择 [0-10]: " choice
        case $choice in
            1) install_vless_reality; press_any_key ;;
            2) install_vmess_ws; press_any_key ;;
            3) install_vless_ws; press_any_key ;;
            4) install_trojan_ws; press_any_key ;;
            5) install_trojan_http; press_any_key ;;
            6) install_hysteria2; press_any_key ;;
            7) install_tuic; press_any_key ;;
            8) show_all_singbox_nodes; press_any_key ;;
            9) uninstall_singbox_node; press_any_key ;;
            10) service_restart sing-box; log_success "已重启"; press_any_key ;;
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
        print_menu_item "2" "Sing-box 多协议"
        echo -e "     ${GREEN}├─${NC} VLESS+Reality, VMess+WS, VLESS+WS"
        echo -e "     ${GREEN}├─${NC} Trojan+WS, Trojan+HTTP, Hysteria2, TUIC"
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
                local found=0
                [[ -f "$SNELL_CONF" ]] && { show_snell_config; found=1; echo; }
                [[ -f "$SS_CONF" ]] && { show_ss2022_config; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/reality.conf" ]] && { show_vless_reality; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/hysteria2.conf" ]] && { show_hysteria2; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/vmess-ws.conf" ]] && { show_vmess_ws; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/vless-ws.conf" ]] && { show_vless_ws; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/trojan-ws.conf" ]] && { show_trojan_ws; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/trojan-http.conf" ]] && { show_trojan_http; found=1; echo; }
                [[ -f "${SINGBOX_DIR}/tuic.conf" ]] && { show_tuic; found=1; echo; }
                [[ $found -eq 0 ]] && log_warn "未安装任何节点"
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
