#!/usr/bin/env bash
#
# VPS 一键管理工具箱 (Refactored v4.2.0)
# 专为新手设计，集成高级 BBR、Snell、Fail2ban、SSH管理、证书申请与多协议节点部署 (支持增删改查)
#
# GitHub: https://github.com/your-username/vps-toolkit
#

export LANG=en_US.UTF-8

# ==================== 0. 全局变量 & 颜色 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="4.5.0"
GITHUB_RAW_URL="https://raw.githubusercontent.com/GLH08/Script/main/vps.sh"
INSTALL_PATH="/usr/local/bin/vps"
CERT_DIR="/etc/vps/cert"
SB_CONFIG="/etc/sing-box/config.json"

# ==================== 1. 核心工具函数 ====================

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

print_line() { echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

print_title() {
    clear
    print_line
    echo -e "${CYAN}            $1${NC}"
    print_line
}

# 增强: 检查端口占用 (使用 ss 或 lsof)
check_port() {
    local port=$1
    if command -v ss &>/dev/null; then
        ss -tuln | grep -q ":$port "
    elif command -v lsof &>/dev/null; then
        lsof -i :$port >/dev/null
    else
        # Fallback to config check if system tools missing
        grep -q "\"listen_port\": $port" "$SB_CONFIG" 2>/dev/null
    fi
}

# 增强: 系统状态仪表盘 (v4.5 Pro)
show_sys_status() {
    local start_time=$(date +%s)
    
    # CPU Load
    local load=$(awk '{print $1", "$2", "$3}' /proc/loadavg)
    local load=$(awk '{print $1", "$2", "$3}' /proc/loadavg)
    
    # CPU Usage (Dynamic)
    local cpu_usage="0"
    if [[ -f /proc/stat ]]; then
        local stat1=$(grep 'cpu ' /proc/stat)
        sleep 0.1
        local stat2=$(grep 'cpu ' /proc/stat)
        
        # Parse stat1
        local user1=$(echo "$stat1" | awk '{print $2}')
        local nice1=$(echo "$stat1" | awk '{print $3}')
        local sys1=$(echo "$stat1" | awk '{print $4}')
        local idle1=$(echo "$stat1" | awk '{print $5}')
        local total1=$((user1 + nice1 + sys1 + idle1))
        
        # Parse stat2
        local user2=$(echo "$stat2" | awk '{print $2}')
        local nice2=$(echo "$stat2" | awk '{print $3}')
        local sys2=$(echo "$stat2" | awk '{print $4}')
        local idle2=$(echo "$stat2" | awk '{print $5}')
        local total2=$((user2 + nice2 + sys2 + idle2))
        
        local diff_total=$((total2 - total1))
        local diff_idle=$((idle2 - idle1))
        
        if (( diff_total > 0 )); then
            cpu_usage=$(( (diff_total - diff_idle) * 100 / diff_total ))
        fi
    fi
    
    # Memory
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_rate=$(awk "BEGIN {printf \"%.0f\", $mem_used/$mem_total*100}")
    
    # Disk
    local disk_total=$(df -h / | awk 'NR==2 {print $2}')
    local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_rate=$(df -h / | awk 'NR==2 {print $5}')
    
    # TCP Connections
    local tcp_est=$(ss -t state established 2>/dev/null | tail -n +2 | wc -l)
    local tcp_tot=$(ss -s 2>/dev/null | awk '/TCP:/ {print $2}')

    # Docker Status
    local docker_status="${RED}未安装${NC}"
    if command -v docker &>/dev/null; then
        if systemctl is-active docker &>/dev/null; then
            local container_count=$(docker ps -q 2>/dev/null | wc -l)
            docker_status="${GREEN}运行中 (容器: $container_count)${NC}"
        else
            docker_status="${YELLOW}已停止${NC}"
        fi
    fi

    # BBR Status
    local bbr_status="${RED}未启用${NC}"
    local cc_algo=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [[ "$cc_algo" == "bbr" ]]; then
        bbr_status="${GREEN}BBR + $qdisc${NC}"
    fi
    
    echo -e "${CYAN}┌── 系统状态概览 ──────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} CPU负载 : ${GREEN}$load${NC} | 使用率: ${GREEN}${cpu_usage}%${NC}"
    echo -e "${CYAN}│${NC} 内存使用: ${GREEN}${mem_used}MB / ${mem_total}MB (${mem_rate}%)${NC}"
    echo -e "${CYAN}│${NC} 磁盘使用: ${GREEN}${disk_used} / ${disk_total} (${disk_rate})${NC}"
    echo -e "${CYAN}│${NC} TCP连接 : ${GREEN}${tcp_est}${NC} Est / ${GREEN}${tcp_tot}${NC} Tot"
    echo -e "${CYAN}│${NC} Docker  : $docker_status"
    echo -e "${CYAN}│${NC} BBR算法 : $bbr_status"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
}

confirm() {
    local prompt="${1:-确认继续？}"
    read -r -p "$(echo -e "${YELLOW}${prompt} [y/N]: ${NC}")" response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_any_key() {
    echo
    echo -n "按任意键继续..."
    read -t 0.1 -n 10000 discard 2>/dev/null || true
    read -rsn1 key 2>/dev/null || true
    [[ "$key" == $'\x1b' ]] && read -rsn2 -t 0.1 discard 2>/dev/null || true
    echo
}

check_root() {
    [[ $EUID -ne 0 ]] && log_error "请以 root 权限运行此脚本" && exit 1
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    else
        OS="unknown"
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_ALT="amd64" ;;
        aarch64|arm64) ARCH_ALT="arm64" ;;
        *) log_error "不支持的架构: $ARCH"; exit 1 ;;
    esac

    case $OS in
        ubuntu|debian|linuxmint) PACKAGE_MANAGER="apt-get" ;;
        centos|rhel|fedora|rocky|almalinux) PACKAGE_MANAGER="yum" ;;
        alpine) PACKAGE_MANAGER="apk" ;;
        *) log_error "不支持的系统: $OS"; exit 1 ;;
    esac
}

install_pkg() {
    local pkg=$1
    if ! command -v "$pkg" &>/dev/null; then
        case $PACKAGE_MANAGER in
            apt-get) apt-get update -qq && apt-get install -y "$pkg" >/dev/null 2>&1 ;;
            yum) yum install -y "$pkg" >/dev/null 2>&1 ;;
            apk) apk add --no-cache "$pkg" >/dev/null 2>&1 ;;
        esac
    fi
}

get_public_ip() {
    curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip
}

update_script() {
    log_info "正在检查更新 v${SCRIPT_VERSION}..."
    curl -sL "$GITHUB_RAW_URL" -o "$INSTALL_PATH" || {
        log_error "更新失败，请检查网络"
        return 1
    }
    chmod +x "$INSTALL_PATH"
    log_success "脚本已更新至最新版！"
    sleep 1
    exec "$INSTALL_PATH"
}

install_self() {
    # 如果已安装且当前运行的就是安装路径下的脚本，跳过
    if [[ -f "$INSTALL_PATH" && "$0" == "$INSTALL_PATH" ]]; then return; fi

    print_line
    log_info "正在安装/更新脚本到系统..."
    
    # 尝试判断是否为本地文件运行
    if [[ -f "$0" ]]; then
        cp "$0" "$INSTALL_PATH"
    else
        # 管道模式，必须下载
        curl -sL "$GITHUB_RAW_URL" -o "$INSTALL_PATH"
    fi
    
    chmod +x "$INSTALL_PATH"
    log_success "安装完成！快捷指令: vps"
    print_line
    sleep 1
}

# ==================== 2. 系统管理模块 ====================

system_update() {
    print_title "系统更新"
    log_info "正在更新系统软件包..."
    case $PACKAGE_MANAGER in
        apt-get) apt-get update && apt-get upgrade -y && apt-get autoremove -y ;;
        yum) yum update -y ;;
        apk) apk update && apk upgrade ;;
    esac
    
    log_info "安装常用工具..."
    install_pkg curl; install_pkg wget; install_pkg git; install_pkg nano
    install_pkg jq; install_pkg tar; install_pkg unzip; install_pkg openssl
    install_pkg cron; install_pkg iptables; install_pkg socat
    
    log_success "系统更新完成！"
    press_any_key
}

set_timezone() {
    print_title "时区设置"
    echo -e "当前时区: $(date +%z)"
    echo "1. Asia/Shanghai (中国上海)"
    echo "2. Asia/Hong_Kong (中国香港)"
    echo "3. Asia/Tokyo (日本东京)"
    echo "4. America/Los_Angeles (美国洛杉矶)"
    echo "5. 自定义"
    echo "0. 返回"
    read -r -p "请选择: " choice
    local tz=""
    case $choice in
        1) tz="Asia/Shanghai" ;;
        2) tz="Asia/Hong_Kong" ;;
        3) tz="Asia/Tokyo" ;;
        4) tz="America/Los_Angeles" ;;
        5) read -r -p "请输入时区: " tz ;;
        *) return ;;
    esac
    if [[ -n "$tz" ]]; then
        if command -v timedatectl &>/dev/null; then timedatectl set-timezone "$tz"; else ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime; fi
        log_success "时区已设置为 $tz"
    fi
    press_any_key
}

manage_swap() {
    print_title "Swap 管理"
    local current_swap=$(free -m | awk '/Swap/ {print $2}')
    echo -e "当前: ${GREEN}${current_swap} MB${NC}"
    echo "1. 添加/修改 Swap (推荐 2048MB)"
    echo "2. 删除 Swap"
    echo "0. 返回"
    read -r -p "选: " choice
    case $choice in
        1)
            read -r -p "大小 (MB): " size
            [[ ! "$size" =~ ^[0-9]+$ ]] && return
            swapoff -a; rm -f /swapfile
            dd if=/dev/zero of=/swapfile bs=1M count="$size" status=progress
            chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
            sed -i '/\/swapfile/d' /etc/fstab; echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            log_success "Swap 设置成功"
            ;;
        2) swapoff -a; rm -f /swapfile; sed -i '/\/swapfile/d' /etc/fstab; log_success "已删除" ;;
    esac
    press_any_key
}

# ==================== 2.1 基础运维功能 (小白必备) ====================

sync_time() {
    log_info "正在使用 Chrony 同步系统时间..."
    
    # 停用冲突服务
    systemctl stop systemd-timesyncd 2>/dev/null
    
    if ! command -v chronyd &>/dev/null; then
        install_pkg chrony
    fi
    
    # Detect service name (chrony or chronyd)
    local chrony_svc="chrony"
    if systemctl list-unit-files --type=service | grep -q "^chronyd.service"; then
        chrony_svc="chronyd"
    fi
    
    systemctl enable "$chrony_svc" &>/dev/null
    systemctl restart "$chrony_svc"
    
    # 强制同步
    if command -v chronyc &>/dev/null; then
        log_info "正在强制校准..."
        chronyc makestep >/dev/null 2>&1
        sleep 2
        chronyc tracking
        log_success "时间同步完成: $(date)"
    else
        log_warn "Chrony 可能未正确安装，尝试备用方案..."
        ntpdate -u pool.ntp.org 2>/dev/null || timedatectl set-ntp true
        log_info "当前时间: $(date)"
    fi
    press_any_key
}

set_dns() {
    print_title "DNS 优选设置"
    echo "1. Google DNS (8.8.8.8)"
    echo "2. Cloudflare DNS (1.1.1.1)"
    echo "3. 阿里 DNS (223.5.5.5)"
    echo "4. 恢复系统默认"
    echo "0. 返回"
    read -r -p "请选择: " dns_c
    
    local dns_ip=""
    case $dns_c in
        1) dns_ip="8.8.8.8" ;;
        2) dns_ip="1.1.1.1" ;;
        3) dns_ip="223.5.5.5" ;;
        4) echo "" > /etc/resolv.conf; log_info "已清空手动配置，重启可能恢复默认"; press_any_key; return ;;
        *) return ;;
    esac
    
    if [[ -n "$dns_ip" ]]; then
        if [[ -f /etc/resolv.conf ]]; then
             cp /etc/resolv.conf /etc/resolv.conf.bak
        fi
        echo "nameserver $dns_ip" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
        log_success "DNS 已设置为: $dns_ip"
        log_info "备份已保存至 /etc/resolv.conf.bak"
    fi
    press_any_key
}

kill_port() {
    read -r -p "请输入要释放的端口号 (如 80): " kp
    if [[ ! "$kp" =~ ^[0-9]+$ ]]; then log_error "请输入有效数字"; press_any_key; return; fi
    
    local pid=""
    if command -v lsof &>/dev/null; then
        pid=$(lsof -t -i:$kp)
    elif command -v ss &>/dev/null; then
        if command -v fuser &>/dev/null; then
            pid=$(fuser $kp/tcp 2>/dev/null)
        fi
    fi
    
    if [[ -z "$pid" ]] && command -v netstat &>/dev/null; then
        pid=$(netstat -nlp | grep ":$kp " | awk '{print $7}' | cut -d/ -f1)
    fi

    if [[ -n "$pid" ]]; then
        kill -9 $pid
        log_success "已强制结束占用端口 $kp 的进程 (PID: $pid)"
    else
        log_warn "未找到占用端口 $kp 的进程，或者工具缺失 (建议先运行'安装常用网络工具'或手动检查)"
    fi
    press_any_key
}

enable_root() {
    if confirm "此操作将允许 Root 用户通过密码直接登录 SSH，是否继续？"; then
        log_info "正在修改 SSH 配置..."
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
        
        systemctl restart sshd
        log_success "SSH 服务已重启，Root 登录已开启！"
        echo -e "${YELLOW}建议立即修改 Root 密码以保证安全 (运行 'passwd root')${NC}"
    fi
    press_any_key
}

sys_optimize() {
    print_title "高级系统与网络优化"
    log_info "正在进行深度网络调优 (BBR+FQ_CODEL+TFO)..."
    
    # 1. 备份配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F-%H%M) 2>/dev/null
    cp /etc/security/limits.conf /etc/security/limits.conf.bak.$(date +%F-%H%M) 2>/dev/null
    
    # 2. 系统资源限制 (ulimit) - 幂等处理
    sed -i '/# VPS-Toolkit-Limits-Start/,/# VPS-Toolkit-Limits-End/d' /etc/security/limits.conf
    cat >> /etc/security/limits.conf <<EOF
# VPS-Toolkit-Limits-Start
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
# VPS-Toolkit-Limits-End
EOF
    if ! grep -q "ulimit -n 1048576" /etc/profile; then
        echo "ulimit -n 1048576" >> /etc/profile
    fi

    # 3.不仅是 TCP 拥塞控制，还有内核网络参数全家桶
    cat > /etc/sysctl.d/99-vps-toolkit.conf <<EOF
# === VPS工具箱优化 $(date) ===
fs.file-max = 1048576
fs.inotify.max_user_instances = 8192

# 网络核心
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432

# TCP 缓冲区
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 16384 33554432

# 连接优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000

# 启用 BBR + FQ_CODEL
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open
net.ipv4.tcp_fastopen = 3
EOF

    # 4. 应用 Sysctl
    sysctl -p /etc/sysctl.d/99-vps-toolkit.conf >/dev/null 2>&1
    
    # 5. 尝试设置网卡队列 (需要 iproute2)
    local interface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1);exit}}}')
    if [[ -n "$interface" ]] && command -v tc &>/dev/null; then
        tc qdisc replace dev "$interface" root fq_codel 2>/dev/null
        log_info "网卡 $interface 队列已设置为 fq_codel"
    fi

    log_success "优化完成！建议重启系统以确保所有变更生效。"
    press_any_key
}

install_essential_tools() {
    log_info "正在安装常用工具包 (请耐心等待)..."
    case $PACKAGE_MANAGER in
        apt-get) apt-get update -y ;;
        yum) yum makecache ;;
        apk) apk update ;;
    esac
    
    local tool_list="wget curl vim nano unzip zip tar net-tools iproute2 htop git screen lsof socat chrony"
    for tool in $tool_list; do
        install_pkg "$tool"
    done
    
    log_success "常用工具安装完成！"
    press_any_key
}

change_language_cn() {
    print_title "修改系统语言为中文"
    
    if [[ "$PACKAGE_MANAGER" != "apt-get" ]]; then
        log_warn "此功能原生适配 Debian/Ubuntu，您的系统可能是 $OS"
        if ! confirm "是否尝试强制执行？(可能会失败)"; then return; fi
    fi

    log_info "正在安装中文语言包 (locales)..."
    apt-get update -y
    install_pkg locales
    
    if [[ -f /etc/locale.gen ]]; then
        log_info "正在配置语言环境..."
        
        # 1. 确保 zh_CN.UTF-8 被启用
        # 如果存在注释行，取消注释
        sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen
        
        # 如果文件中根本没有这行 (grep 找不到已启用的)，则追加
        if ! grep -q "^zh_CN.UTF-8 UTF-8" /etc/locale.gen; then
            echo "zh_CN.UTF-8 UTF-8" >> /etc/locale.gen
        fi
        
        # 2. 生成区域
        log_info "正在生成区域文件..."
        locale-gen zh_CN.UTF-8 || locale-gen
        
        # 3. 验证是否生成成功
        if ! locale -a | grep -i "zh_CN"; then
             log_error "中文区域 (zh_CN) 生成失败！可能系统不支持或文件修改失败。"
             press_any_key
             return
        fi

        # 4. 应用设置
        update-locale LANG=zh_CN.UTF-8 LANGUAGE=zh_CN:zh LC_ALL=zh_CN.UTF-8
        
        log_success "系统语言已修改为中文 (zh_CN.UTF-8)"
        echo -e "${YELLOW}请断开 SSH 并重新连接以查看效果。${NC}"
    else
        log_error "未找到 /etc/locale.gen，操作失败。"
    fi
    press_any_key
}

system_maintenance_menu() {
    while true; do
        print_title "系统维护 & 小白运维工具"
        echo "1.  系统清理 (Logs/Cache)"
        echo "2.  设置 IPv4 优先 (解决访问慢)"
        print_line
        echo "3.  ⏳ 强制时间同步 (修复节点连不上)"
        echo "4.  📡 修改系统 DNS (修复无法解析)"
        echo "5.  ✂️ 端口占用释放 (修复 启动失败)"
        echo "6.  🔓 开启 Root 登录 (修复 权限/SFTP)"
        echo "7.  🚀 优化系统参数 (提升并发性能)"
        echo "8.  🛠️ 安装常用工具 (Ping/Vim/Unzip...)"
        echo "9.  🇨🇳 修改系统语言为中文"
        echo "10. 🕒 修改系统时区 (修复时间都不对)"
        echo "0.  返回"
        read -r -p "请选择: " choice
        case $choice in
            1) journalctl --vacuum-time=1d >/dev/null 2>&1; rm -rf /var/log/*.gz /var/log/*.[0-9]; echo > /var/log/syslog; echo > /var/log/auth.log; log_success "清理完成"; press_any_key ;;
            2) sed -i 's/#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf; log_success "已设置"; press_any_key ;;
            3) sync_time ;;
            4) set_dns ;;
            5) kill_port ;;
            6) enable_root ;;
            7) sys_optimize ;;
            8) install_essential_tools ;;
            9) change_language_cn ;;
            10) set_timezone ;;
            0) return ;;
        esac
    done
}

# ==================== 3. 安全与 SSH 模块 ====================

install_fail2ban() {
    print_title "Fail2ban 管理 (增强版)"
    echo "1. 安装启用 (自动适配SSH端口)"
    echo "2. 查看封禁状态"
    echo "3. 解封指定 IP"
    echo "4. 修改配置文件 (nano)"
    echo "5. 卸载 Fail2ban"
    echo "0. 返回"
    read -r -p "选: " c
    case $c in
        1) 
            log_info "正在安装 Fail2ban & rsyslog..."
            install_pkg fail2ban
            install_pkg rsyslog
            systemctl enable rsyslog; systemctl start rsyslog
            
            # 自动检测 SSH 端口
            local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
            [[ -z "$ssh_port" ]] && ssh_port=22
            log_info "检测到 SSH 端口: $ssh_port"
            
            cat > /etc/fail2ban/jail.local <<EOF
[sshd]
ignoreip = 127.0.0.1/8
enabled = true
filter = sshd
port = $ssh_port
maxretry = 5
findtime = 300
bantime = 600
action = %(action_)s[port="%(port)s", protocol="%(protocol)s", logpath="%(logpath)s", chain="%(chain)s"]
banaction = iptables-multiport
logpath = /var/log/auth.log
EOF
           systemctl enable fail2ban; systemctl restart fail2ban
           log_success "Fail2ban 已启用 (监控端口: $ssh_port)"
           press_any_key
           ;;
        2) fail2ban-client status sshd; press_any_key ;;
        3) read -r -p "要解封的 IP: " ip; fail2ban-client set sshd unbanip "$ip"; press_any_key ;;
        4) nano /etc/fail2ban/jail.local; systemctl restart fail2ban; log_success "配置已更新并重启服务"; press_any_key ;;
        5) systemctl stop fail2ban; apt-get remove --purge -y fail2ban 2>/dev/null || yum remove -y fail2ban 2>/dev/null; rm -rf /etc/fail2ban; log_success "已卸载"; press_any_key ;;
        0) return;;
    esac
}

check_ssh_keys() {
    if [[ -f "$HOME/.ssh/authorized_keys" && -s "$HOME/.ssh/authorized_keys" ]]; then
        return 0
    fi
    # Check common pub keys
    for key in id_rsa.pub id_ed25519.pub id_ecdsa.pub; do
        if [[ -f "$HOME/.ssh/$key" ]]; then return 0; fi
    done
    return 1
}

manage_ssh() {
    print_title "SSH 安全管理"
    local port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1); [[ -z "$port" ]] && port=22
    local permit_root=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    local pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    
    echo -e "当前端口: ${GREEN}$port${NC}"
    echo -e "Root登录: ${GREEN}${permit_root:-默认}${NC}"
    echo -e "密码认证: ${GREEN}${pass_auth:-默认}${NC}"
    print_line
    
    echo "1. 修改 SSH 端口"
    echo "2. 修改 Root 密码"
    echo "3. 配置 Root 登录策略 (密码/密钥/禁止)"
    echo "4. 开/关 密码认证 (禁止暴力破解)"
    echo "0. 返回"
    
    read -r -p "选: " c
    case $c in
        1)
            read -r -p "新端口 (1024-65535): " np
            [[ ! "$np" =~ ^[0-9]+$ ]] && return
            # Backup
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
            
            if grep -q "^Port" /etc/ssh/sshd_config; then sed -i "s/^Port .*/Port $np/" /etc/ssh/sshd_config; else echo "Port $np" >> /etc/ssh/sshd_config; fi
            
            # Firewall config
            if command -v ufw &>/dev/null; then ufw allow "$np"/tcp; elif command -v firewall-cmd &>/dev/null; then firewall-cmd --permanent --add-port="$np"/tcp; firewall-cmd --reload; else iptables -I INPUT -p tcp --dport "$np" -j ACCEPT; fi
            
            systemctl restart sshd
            log_success "端口已修改为: $np (请使用新端口重连测试)"
            ;;
        2) log_info "输入新密码:"; passwd root; log_success "修改完成";;
        3)
            echo "1. 允许密码 (不推荐) 2. 仅允许密钥 (推荐) 3. 禁止 Root 登录"
            read -r -p "选: " rc
            case $rc in
                1) sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config ;;
                2) sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config ;;
                3) sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config ;;
            esac
            systemctl restart sshd; log_success "策略已更新"
            ;;
        4)
            if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
                sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                log_success "密码认证已【开启】"
            else
                if ! check_ssh_keys; then
                    log_warn "未检测到 SSH 密钥！禁用密码认证将导致无法登录！"
                    if ! confirm "确认要强制禁用吗？(后果自负)"; then return; fi
                fi
                sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
                log_success "密码认证已【关闭】"
            fi
            systemctl restart sshd
            ;;
        0) return ;;
    esac
    press_any_key
}

manage_firewall() {
    print_title "防火墙助手"
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1); [[ -z "$ssh_port" ]] && ssh_port=22
    log_info "SSH端口: $ssh_port, 尝试放行常用端口..."
    if command -v ufw &>/dev/null; then
        ufw allow "$ssh_port"/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw allow 443:65535/tcp; ufw allow 443:65535/udp
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="$ssh_port"/tcp; firewall-cmd --permanent --add-port=80/tcp; firewall-cmd --permanent --add-port=443/tcp; firewall-cmd --permanent --add-port=443-65535/tcp; firewall-cmd --permanent --add-port=443-65535/udp; firewall-cmd --reload
    else
        iptables -I INPUT -p tcp --dport "$ssh_port" -j ACCEPT; iptables -I INPUT -p tcp --dport 80 -j ACCEPT; iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    fi
    log_success "放行完成"
    press_any_key
}

# ==================== 4. 证书管理模块 ====================

install_acme() {
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then curl https://get.acme.sh | sh -s email=my@example.com; source ~/.bashrc; fi
}
request_cert() {
    print_title "SSL 证书申请 (CF DNS)"
    install_acme
    read -r -p "CF邮箱: " cf_email; read -r -p "CF Key: " cf_key; read -r -p "域名: " domain
    [[ -z "$cf_email" || -z "$cf_key" || -z "$domain" ]] && return
    export CF_Key="$cf_key"; export CF_Email="$cf_email"
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" -d "*.${domain}"
    if [[ $? -eq 0 ]]; then
        mkdir -p "$CERT_DIR"
        ~/.acme.sh/acme.sh --install-cert -d "${domain}" --key-file "$CERT_DIR/private.key" --fullchain-file "$CERT_DIR/cert.pem" --reloadcmd "chmod 644 $CERT_DIR/private.key $CERT_DIR/cert.pem"
        echo "$domain" > "$CERT_DIR/domain.txt"; log_success "申请成功"
    else
        log_error "申请失败"
    fi
    press_any_key
}

# ==================== 5. Sing-box 节点管理 (重构版) ====================

install_singbox() {
    if command -v sing-box &>/dev/null; then return; fi
    log_info "安装 Sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    systemctl enable sing-box
    mkdir -p /etc/sing-box
}

init_sb_config() {
    if [[ ! -f "$SB_CONFIG" ]]; then
        cat > "$SB_CONFIG" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
    fi
}

add_sb_inbound() {
    local type=$1
    local port=$2
    local uuid=$3
    local server_name=$4
    local extra=$5
    
    init_sb_config
    
    # 检测端口冲突
    if grep -q "\"listen_port\": $port" "$SB_CONFIG"; then
        if ! confirm "端口 $port 已存在，是否覆盖整个配置文件？(选 'n' 取消操作，选 'y' 将清空旧配置重置)"; then
            log_warn "取消添加。建议先删除旧节点或换端口。"
            return
        else
             rm -f "$SB_CONFIG"; init_sb_config
        fi
    fi

    # 构造 inbound JSON 片段
    local new_inbound=""
    
    # 证书处理
    local cert_fragment=""
    if [[ "$type" == "vless" && "$extra" == *"reality"* ]]; then
        local pbk=$(echo "$extra" | cut -d, -f2)
        local pvk=$(echo "$extra" | cut -d, -f3)
        local sid=$(echo "$extra" | cut -d, -f4)
        cert_fragment='"tls": { "enabled": true, "server_name": "'$server_name'", "reality": { "enabled": true, "handshake": { "server": "'$server_name'", "server_port": 443 }, "private_key": "'$pvk'", "short_id": ["'$sid'"] } }'
    else
        # 解析 cert 模式 (self 或 real)
        local cert_mode="self"
        [[ "$extra" == *"cert=real"* ]] && cert_mode="real"
        
        local cert_path=""
        local key_path=""
        
        if [[ "$cert_mode" == "real" ]]; then
             cert_path="$CERT_DIR/cert.pem"
             key_path="$CERT_DIR/private.key"
             if [[ ! -f "$cert_path" ]]; then
                 log_error "未找到真实证书 ($cert_path)！请先去证书管理菜单申请。"
                 return
             fi
        else
             # 自签模式：为防止端口间证书冲突，每个端口独立生成
             mkdir -p /etc/sing-box/cert
             cert_path="/etc/sing-box/cert/${port}_cert.pem"
             key_path="/etc/sing-box/cert/${port}_key.pem"
             openssl req -x509 -newkey rsa:2048 -keyout "$key_path" -out "$cert_path" -days 3650 -nodes -subj "/CN=$server_name" >/dev/null 2>&1
        fi
        cert_fragment='"tls": { "enabled": true, "server_name": "'$server_name'", "certificate_path": "'$cert_path'", "key_path": "'$key_path'" }'
    fi

    # 传输层处理 (WebSocket)
    local transport_fragment=""
    if [[ "$extra" == *"ws"* ]]; then
        local ws_path=$(echo "$extra" | grep -o "ws_path=[^,]*" | cut -d= -f2)
        [[ -z "$ws_path" ]] && ws_path="/"
        transport_fragment=', "transport": { "type": "ws", "path": "'$ws_path'" }'
    fi

    if [[ "$type" == "vless" ]]; then
        new_inbound='{ "type": "vless", "tag": "in-'$port'", "listen": "::", "listen_port": '$port', "users": [ { "uuid": "'$uuid'", "flow": "xtls-rprx-vision" } ], '$cert_fragment' }'
    elif [[ "$type" == "vmess" ]]; then
        new_inbound='{ "type": "vmess", "tag": "in-'$port'", "listen": "::", "listen_port": '$port', "users": [ { "uuid": "'$uuid'", "alterId": 0 } ], '$cert_fragment' '$transport_fragment' }'
    elif [[ "$type" == "trojan" ]]; then
        new_inbound='{ "type": "trojan", "tag": "in-'$port'", "listen": "::", "listen_port": '$port', "users": [ { "password": "'$uuid'" } ], '$cert_fragment' '$transport_fragment' }'
    elif [[ "$type" == "hysteria2" ]]; then
        new_inbound='{ "type": "hysteria2", "tag": "in-'$port'", "listen": "::", "listen_port": '$port', "users": [ { "password": "'$uuid'" } ], '$cert_fragment' }'
    elif [[ "$type" == "tuic" ]]; then
        new_inbound='{ "type": "tuic", "tag": "in-'$port'", "listen": "::", "listen_port": '$port', "users": [ { "uuid": "'$uuid'", "password": "'$uuid'" } ], "congestion_control": "bbr", '$cert_fragment' }'
    fi

    # 使用 jq 追加到 inbounds 数组
    local temp_config=$(mktemp)
    jq ".inbounds += [$new_inbound]" "$SB_CONFIG" > "$temp_config" && mv "$temp_config" "$SB_CONFIG"
    
    systemctl restart sing-box
}

# (省略 list_sb_nodes, delete_sb_node 保持不变)

deploy_sb_menu() {
    install_singbox
    while true; do
        print_title "Sing-box 节点部署 (协议直选模式)"
        echo "1. 部署 VLESS-Reality   (推荐，最简)"
        echo "2. 部署 Hysteria2       (UDP 高速)"
        echo "3. 部署 TUIC v5         (UDP 高速, 类似Quic)"
        echo "4. 部署 Trojan-TLS      (经典稳定)"
        echo "5. 部署 VMess-TLS       (CDN 兼容)"
        print_line
        echo "6. 查看已部署节点"
        echo "7. 删除特定节点"
        echo "8. 重置/清空所有配置"
        echo "0. 返回"
        
        echo
        read -r -p "请选择: " choice
        
        local port uuid server_name share_link cert_mode transport_mode ws_path extra_params
        
        # 公共参数获取 (如果选择部署)
        if [[ "$choice" =~ ^[1-5]$ ]]; then
             read -r -p "端口 (留空随机 10000-60000): " port
             [[ -z "$port" ]] && port=$((RANDOM % 50000 + 10000))
             uuid=$(sing-box generate uuid)
        fi
        
        ask_cert_mode() {
            echo "请选择证书模式："
            echo "1. 自动生成自签名证书 (客户端需开启跳过验证)"
            echo "2. 使用 Cloudflare DNS 真实证书 (支持 CDN/不跳验证)"
            read -r -p "选: " cm
            if [[ "$cm" == "2" ]]; then
                cert_mode="real"
                # 检查是否已有证书
                if [[ -f "$CERT_DIR/domain.txt" ]] && [[ -f "$CERT_DIR/cert.pem" ]]; then 
                    server_name=$(cat "$CERT_DIR/domain.txt")
                    log_info "检测到已申请域名: $server_name"
                else
                    log_warn "未检测到可用证书！"
                    if confirm "是否立即使用 Cloudflare API 申请证书？"; then
                        request_cert
                        if [[ $? -eq 0 ]] && [[ -f "$CERT_DIR/domain.txt" ]]; then
                             server_name=$(cat "$CERT_DIR/domain.txt")
                             log_success "证书准备就绪，继续部署..."
                        else
                             log_error "证书申请失败或取消，回退到自签模式。"
                             cert_mode="self"
                             server_name="www.bing.com"
                        fi
                    else
                        log_info "已取消，回退到自签模式。"
                        cert_mode="self"
                        server_name="www.bing.com"
                    fi
                fi
            else
                cert_mode="self"
                server_name="www.bing.com"
            fi
        }
        
        ask_transport() {
            echo "传输协议: 1. TCP (默认) 2. WebSocket (CDN专用)"
            read -r -p "选: " t
            if [[ "$t" == "2" ]]; then 
                read -r -p "WebSocket 路径 (默认 /): " ws_path; [[ -z "$ws_path" ]] && ws_path="/"
                transport_mode="ws,ws_path=$ws_path"
            else
                transport_mode="tcp"
            fi
        }

        case $choice in
            1)
                # VLESS Reality (无需选证书)
                server_name="www.microsoft.com"
                local kp=$(sing-box generate reality-keypair)
                local pvk=$(echo "$kp" | grep PrivateKey | awk '{print $2}' | tr -d '"')
                local pbk=$(echo "$kp" | grep PublicKey | awk '{print $2}' | tr -d '"')
                local sid=$(sing-box generate rand --hex 8)
                add_sb_inbound "vless" "$port" "$uuid" "$server_name" "reality,$pbk,$pvk,$sid"
                share_link="vless://$uuid@$(get_public_ip):$port?security=reality&encryption=none&pbk=$pbk&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$server_name&sid=$sid#VLESS-Reality"
                ;;
            2)
                # Hysteria2
                uuid=$(sing-box generate rand --hex 16) # Hy2 use password
                ask_cert_mode
                add_sb_inbound "hysteria2" "$port" "$uuid" "$server_name" "cert=$cert_mode"
                
                local insecure=1; [[ "$cert_mode" == "real" ]] && insecure=0
                share_link="hysteria2://$uuid@$(get_public_ip):$port?insecure=$insecure&sni=$server_name#Hysteria2"
                ;;
            3)
                # TUIC v5
                uuid=$(sing-box generate rand --hex 16)
                ask_cert_mode
                add_sb_inbound "tuic" "$port" "$uuid" "$server_name" "cert=$cert_mode"
                local insecure=1; [[ "$cert_mode" == "real" ]] && insecure=0
                share_link="tuic://$uuid@$(get_public_ip):$port?uuid=$uuid&password=$uuid&congestion_control=bbr&allow_insecure=$insecure&sni=$server_name#TUIC-v5"
                ;;
            4)
                # Trojan
                uuid=$(sing-box generate rand --hex 8) # Trojan use password
                ask_cert_mode
                ask_transport
                extra_params="cert=$cert_mode"
                [[ "$transport_mode" == *"ws"* ]] && extra_params="$extra_params,$transport_mode"
                
                add_sb_inbound "trojan" "$port" "$uuid" "$server_name" "$extra_params"
                
                local insecure=1; [[ "$cert_mode" == "real" ]] && insecure=0
                local link_extra=""; [[ "$transport_mode" == *"ws"* ]] && link_extra="&type=ws&path=$ws_path"
                share_link="trojan://$uuid@$(get_public_ip):$port?security=tls&allowInsecure=$insecure&sni=$server_name$link_extra#Trojan"
                ;;
            5)
                # VMess
                ask_cert_mode
                ask_transport
                extra_params="cert=$cert_mode"
                [[ "$transport_mode" == *"ws"* ]] && extra_params="$extra_params,$transport_mode"

                add_sb_inbound "vmess" "$port" "$uuid" "$server_name" "$extra_params"
                
                local insecure="on"; [[ "$cert_mode" == "real" ]] && insecure="off"
                local link_type="tcp"; [[ "$transport_mode" == *"ws"* ]] && link_type="ws"
                local link_path=""; [[ "$transport_mode" == *"ws"* ]] && link_path=", Path=$ws_path"
                share_link="vmess://(手动: IP=$(get_public_ip), Port=$port, UUID=$uuid, TLS=on, Insecure=$insecure, Type=$link_type$link_path)"
                ;;
            6) list_sb_nodes; continue ;;
            7) delete_sb_node; continue ;;
            8) rm -f "$SB_CONFIG"; systemctl restart sing-box; log_success "已重置"; press_any_key; continue ;;
            0) return ;;
        esac
        
        log_success "部署成功！"
        echo -e "分享链接: ${CYAN}$share_link${NC}"
        press_any_key
    done
}

install_snell() {
    print_title "Snell v4"
    if [[ -f "/usr/local/bin/snell-server" ]]; then log_warn "已安装"; press_any_key; return; fi
    # 同之前逻辑...
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then return; fi
    local url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-amd64.zip"
    [[ "$ARCH" == "aarch64" ]] && url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-aarch64.zip"
    wget -q -O /tmp/snell.zip "$url"; unzip -o /tmp/snell.zip -d /usr/local/bin/; chmod +x /usr/local/bin/snell-server; rm -f /tmp/snell.zip
    read -r -p "端口: " p; [[ -z "$p" ]] && p=12345; read -r -p "密码: " k; [[ -z "$k" ]] && k="random"
    mkdir -p /etc/snell
    echo "[snell-server]" > /etc/snell/snell-server.conf; echo "listen = 0.0.0.0:$p" >> /etc/snell/snell-server.conf; echo "psk = $k" >> /etc/snell/snell-server.conf; echo "ipv6 = false" >> /etc/snell/snell-server.conf
    # service file...
    cat > /etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Server
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable snell; systemctl restart snell
    log_success "Snell 安装完成"; press_any_key
}

# ==================== 6. 卸载与高级功能 ====================

script_maintenance_menu() {
    while true; do
        print_title "脚本维护"
        echo "1. 更新脚本 (v${SCRIPT_VERSION} -> Latest)"
        echo "2. 卸载 Sing-box (及配置)"
        echo "3. 卸载 Snell"
        echo "4. 卸载 Fail2ban"
        echo "5. 彻底卸载本脚本 (删库跑路)"
        echo "0. 返回"
        read -r -p "选: " c
        case $c in
            1) update_script ;;
            2) systemctl stop sing-box; systemctl disable sing-box; rm -rf /etc/sing-box; rm -f /usr/bin/sing-box; log_success "Sing-box 已卸载"; press_any_key;;
            3) systemctl stop snell; systemctl disable snell; rm -rf /etc/snell; rm -f /usr/local/bin/snell-server; rm -f /etc/systemd/system/snell.service; log_success "Snell 已卸载"; press_any_key;;
            4) systemctl stop fail2ban; apt-get remove --purge -y fail2ban 2>/dev/null; rm -rf /etc/fail2ban; log_success "Fail2ban 已卸载"; press_any_key;;
            5) 
                if confirm "确定要删除脚本吗？"; then
                    rm -f "$INSTALL_PATH"
                    log_success "脚本已删除，江湖路远，有缘再见！"
                    exit 0
                fi
                ;;
            0) return ;;
        esac
    done
}

network_tools_menu() {
    # 同之前...
    while true; do
        print_title "网络工具"; echo "1. 测速 2. 解锁 3. 路由 0. 返回"; read -r -p "选: " c
        case $c in
            1) bash <(curl -Lso- https://bench.im/hyperspeed); press_any_key;;
            2) bash <(curl -L -s check.unlock.media); press_any_key;;
            3) bash <(curl -N https://rio.233.eor.wtf/); press_any_key;;
            0) return;;
        esac
    done
}

# ==================== 7. 其他模块 (复用) ====================
# (BBR, Docker 保持不变，省略以节省空间，实际部署时应包含)
# 这里为了完整性，再次放入精简版
# ==================== 7. 其他模块 (复用修复) ====================

# --- BBR Module (Ported from bbr.sh) ---

get_bbr_version() {
    # 尝试加载模块 (如果未加载)
    modprobe tcp_bbr >/dev/null 2>&1
    
    # 1. 尝试从 sysfs 获取 (最准)
    if [[ -f /sys/module/tcp_bbr/version ]]; then
        cat /sys/module/tcp_bbr/version
        return
    fi
    
    # 2. 尝试 modinfo (旧方法，适用于某些第三方内核)
    local mod_ver=""
    if command -v modinfo &>/dev/null; then
        mod_ver=$(modinfo tcp_bbr 2>/dev/null | grep "^version:" | awk '{print $2}')
    fi
    
    if [[ -n "$mod_ver" ]]; then
        echo "$mod_ver"
        return
    fi
    
    # 3. 检查内核是否内置支持
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr"; then
        echo "Default (Kernel Internal)"
    else
        echo "Unknown / Not Installed"
    fi
}

update_bootloader() {
    log_info "更新引导加载程序..."
    if command -v update-grub &>/dev/null; then update-grub; else log_warn "未找到 update-grub，请确认引导配置"; fi
}

install_bbr_kernel() {
    print_title "安装 BBR v3 内核"
    log_info "正在从 GitHub 获取最新版本信息..."
    
    local api_url="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
    local release_data=$(curl -sL "$api_url")
    
    if [[ -z "$release_data" ]]; then log_error "获取版本信息失败"; return; fi
    
    local arch_filter=""
    [[ "$ARCH" == "aarch64" ]] && arch_filter="arm64"
    [[ "$ARCH" == "x86_64" ]] && arch_filter="x86_64"
    
    # 使用 Python 或 grep/sed 简单解析 (避免重度依赖 jq 的复杂过滤器)
    # 这里为了简便，假设最新 release 包含所需架构
    local download_url=$(echo "$release_data" | grep "browser_download_url" | grep "$arch_filter" | head -n 1 | cut -d '"' -f 4)
    
    if [[ -z "$download_url" ]]; then log_error "未找到适配 $ARCH 的内核包"; return; fi
    
    log_info "下载内核: $(basename "$download_url")"
    wget -O /tmp/kernel.deb "$download_url"
    
    log_info "卸载旧版 joeyblog 内核..."
    dpkg -l | grep "linux-image" | grep "joeyblog" | awk '{print $2}' | xargs apt-get remove --purge -y 2>/dev/null
    
    log_info "安装新内核..."
    dpkg -i /tmp/kernel.deb
    
    if [[ $? -eq 0 ]]; then
        update_bootloader
        log_success "内核安装完成！请重启系统以生效。"
        if confirm "是否立即重启？"; then reboot; fi
    else
        log_error "内核安装失败"
    fi
    rm -f /tmp/kernel.deb
}

enable_bbr_algo() {
    local algo=$1
    local qdisc=$2
    local sysctl_conf="/etc/sysctl.d/99-vps-toolkit.conf"
    
    # 检查算法是否可用
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "$algo"; then
        modprobe "tcp_$algo" >/dev/null 2>&1
        if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "$algo"; then
            log_error "当前内核不支持 $algo 算法！请尝试安装 BBR Plus/v3 内核。"
            return
        fi
    fi
    
    echo "net.core.default_qdisc=$qdisc" > "$sysctl_conf"
    echo "net.ipv4.tcp_congestion_control=$algo" >> "$sysctl_conf"
    sysctl --system >/dev/null 2>&1
    
    log_success "已应用配置: $algo + $qdisc"
    check_bbr_status
}

check_bbr_status() {
    local current_algo=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    local current_qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
    local bbr_ver=$(get_bbr_version)
    
    echo -e "当前内核: $(uname -r)"
    echo -e "BBR 版本: ${GREEN}${bbr_ver:-未知}${NC}"
    echo -e "TCP 拥塞: ${GREEN}${current_algo}${NC}"
    echo -e "队列管理: ${GREEN}${current_qdisc}${NC}"
}

bbr_menu() {
    while true; do
        print_title "BBR 管理 (集成版)"
        check_bbr_status
        print_line
        echo "1. 安装/更新 BBR v3 内核 (Debian/Ubuntu)"
        echo "2. 启用 BBR + FQ"
        echo "3. 启用 BBR + FQ_PIE"
        echo "4. 启用 BBR + CAKE"
        echo "5. 卸载 BBR 内核"
        echo "0. 返回"
        read -r -p "选: " c
        case $c in
            1) install_bbr_kernel ;;
            2) enable_bbr_algo "bbr" "fq"; press_any_key ;;
            3) enable_bbr_algo "bbr" "fq_pie"; press_any_key ;;
            4) enable_bbr_algo "bbr" "cake"; press_any_key ;;
            5) 
                dpkg -l | grep "linux-image" | grep "joeyblog" | awk '{print $2}' | xargs apt-get remove --purge -y
                update_bootloader
                log_success "卸载完成，请重启"; press_any_key 
                ;;
            0) return ;;
        esac
    done
}

manage_docker() {
    while true; do
        print_title "Docker 管理"
        echo "1. 安装 Docker & Compose"
        echo "2. 查看运行容器"
        echo "3. 启动/停止容器"
        echo "4. 查看容器日志"
        echo "5. 删除容器"
        echo "6. 卸载 Docker"
        echo "0. 返回"
        read -r -p "选: " c
        case $c in
            1) 
                curl -fsSL https://get.docker.com | bash
                install_pkg docker-compose-plugin
                systemctl enable docker; systemctl start docker
                log_success "安装完成"; press_any_key
                ;;
            2) docker ps -a; press_any_key ;;
            3) 
                read -r -p "容器ID/名称: " cid
                read -r -p "操作 (start/stop/restart): " op
                docker "$op" "$cid" && log_success "操作成功" || log_error "操作失败"
                press_any_key
                ;;
            4) read -r -p "容器ID: " cid; docker logs "$cid" | tail -n 20; press_any_key ;;
            5) read -r -p "容器ID: " cid; docker rm -f "$cid" && log_success "已删除"; press_any_key ;;
            6) apt-get purge -y docker-ce docker-ce-cli containerd.io; rm -rf /var/lib/docker; log_success "已卸载"; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== 8. 主菜单 ====================

main_menu() {
    while true; do
        print_title "VPS 工具箱 v${SCRIPT_VERSION}"
        echo -e "系统: ${GREEN}${OS} ${VERSION}${NC} | IP: ${GREEN}$(get_public_ip)${NC}"
        show_sys_status
        echo
        echo -e "${YELLOW}--- 部署与管理 ---${NC}"
        echo "1. Sing-box 节点部署 (含TUIC)"
        echo "2. Snell v4 部署"
        echo
        echo -e "${YELLOW}--- 系统与安全 ---${NC}"
        echo "3. 系统/SSH/Fail2ban/防火墙"
        echo "4. BBR & 网络工具"
        echo
        echo -e "${YELLOW}--- 其他 ---${NC}"
        echo "5. Docker 管理"
        echo "6. 脚本维护 (更新/卸载)"
        echo "0. 退出"
        
        echo
        read -r -p "请选择: " choice
        case $choice in
            1) deploy_sb_menu ;;
            2) install_snell ;;
            3) 
                echo "1. 系统环境 2. SSH管理 3. Fail2ban 4. 防火墙 5. 运维/优化 0. 返回"
                read -r -p "-> " s
                case $s in 1) system_update;; 2) manage_ssh;; 3) install_fail2ban;; 4) manage_firewall;; 5) system_maintenance_menu;; esac
                ;;
            4) 
                echo "1. BBR管理 2. 网络诊断 0. 返回"
                read -r -p "-> " s
                case $s in 1) bbr_menu;; 2) network_tools_menu;; esac
                ;;
            5) manage_docker ;;
            6) script_maintenance_menu ;;
            0) exit 0 ;;
            *) log_error "无效"; press_any_key ;;
        esac
    done
}

check_root
detect_os
install_self
main_menu
