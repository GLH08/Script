#!/usr/bin/env bash
#
# VPS 一键管理工具箱 (Refactored v4.0.0)
# 专为新手设计，集成高级 BBR、Snell、Fail2ban、网络诊断与多协议节点部署
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

SCRIPT_VERSION="4.0.0"
GITHUB_RAW_URL="https://raw.githubusercontent.com/your-username/vps-toolkit/main/vps.sh"
INSTALL_PATH="/usr/local/bin/vps"
LOG_FILE="/var/log/vps_manager.log"

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
        # log_info "正在安装 $pkg..."
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
    log_info "正在检查更新..."
    curl -sL "$GITHUB_RAW_URL" -o "$INSTALL_PATH" || {
        log_error "更新失败，请检查网络"
        return 1
    }
    chmod +x "$INSTALL_PATH"
    log_success "脚本已更新至最新版！"
    sleep 1
    exec "$INSTALL_PATH"
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
    
    log_info "安装常用工具 (curl, wget, git, vim, jq, tar, openssl, iptables)..."
    install_pkg curl
    install_pkg wget
    install_pkg git
    install_pkg vim
    install_pkg jq
    install_pkg tar
    install_pkg unzip
    install_pkg openssl
    install_pkg cron
    install_pkg iptables
    
    log_success "系统更新完成！"
    press_any_key
}

set_timezone() {
    print_title "时区设置"
    echo -e "当前时区: $(date +%z)"
    echo
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
        5) read -r -p "请输入时区 (如 Europe/London): " tz ;;
        *) return ;;
    esac
    
    if [[ -n "$tz" ]]; then
        if command -v timedatectl &>/dev/null; then
            timedatectl set-timezone "$tz"
        else
            ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
        fi
        log_success "时区已设置为 $tz"
    fi
    press_any_key
}

manage_swap() {
    print_title "Swap (虚拟内存) 管理"
    local current_swap=$(free -m | awk '/Swap/ {print $2}')
    echo -e "当前 Swap 大小: ${GREEN}${current_swap} MB${NC}"
    echo
    echo "1. 添加/修改 Swap (推荐 2048MB)"
    echo "2. 删除 Swap"
    echo "0. 返回"
    
    read -r -p "请选择: " choice
    case $choice in
        1)
            read -r -p "请输入 Swap 大小 (MB): " size
            [[ ! "$size" =~ ^[0-9]+$ ]] && log_error "无效数字" && return
            
            swapoff -a
            rm -f /swapfile
            dd if=/dev/zero of=/swapfile bs=1M count="$size" status=progress
            chmod 600 /swapfile
            mkswap /swapfile
            swapon /swapfile
            
            sed -i '/\/swapfile/d' /etc/fstab
            echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            
            log_success "Swap 设置成功！"
            ;;
        2)
            swapoff -a
            rm -f /swapfile
            sed -i '/\/swapfile/d' /etc/fstab
            log_success "Swap 已删除"
            ;;
    esac
    press_any_key
}

system_maintenance_menu() {
    while true; do
        print_title "系统维护工具"
        echo "1. 清理系统日志 (释放空间)"
        echo "2. 设置 IPv4 优先 (解决 Google 验证码)"
        echo "3. 开启/关闭 IPv6"
        echo "0. 返回"
        read -r -p "请选择: " choice
        
        case $choice in
            1)
                log_info "正在清理日志..."
                journalctl --vacuum-time=1d >/dev/null 2>&1
                journalctl --vacuum-size=50M >/dev/null 2>&1
                rm -rf /var/log/*.gz /var/log/*.[0-9]
                echo > /var/log/syslog
                echo > /var/log/auth.log
                log_success "日志清理完成！"
                press_any_key
                ;;
            2)
                sed -i 's/#precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf
                log_success "已设置为 IPv4 优先！"
                press_any_key
                ;;
            3)
                log_info "该功能处于 TODO 状态..."
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 3. 安全防护模块 ====================

install_fail2ban() {
    print_title "Fail2ban 安装与配置"
    if command -v fail2ban-client &>/dev/null; then
        echo -e "Fail2ban 状态: ${GREEN}已安装${NC}"
        fail2ban-client status sshd 2>/dev/null
    else
        echo -e "Fail2ban 状态: ${RED}未安装${NC}"
    fi
    echo
    echo "1. 安装并启用 Fail2ban (SSH防爆破)"
    echo "2. 查看封禁 IP 列表"
    echo "3. 解封指定 IP"
    echo "4. 卸载 Fail2ban"
    echo "0. 返回"
    
    read -r -p "请选择: " choice
    case $choice in
        1)
            log_info "正在安装 Fail2ban..."
            install_pkg fail2ban
            
            # 配置 jail.local
            cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 86400
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
            systemctl enable fail2ban
            systemctl restart fail2ban
            log_success "Fail2ban 已启用！规则: 10分钟内失败5次，封禁24小时。"
            ;;
        2)
            fail2ban-client status sshd
            ;;
        3)
            read -r -p "请输入要解封的 IP: " ip
            fail2ban-client set sshd unbanip "$ip"
            log_success "尝试解封 $ip"
            ;;
        4)
            systemctl stop fail2ban
            systemctl disable fail2ban
            case $PACKAGE_MANAGER in
                apt-get) apt-get remove --purge -y fail2ban ;;
                yum) yum remove -y fail2ban ;;
            esac
            rm -rf /etc/fail2ban
            log_success "Fail2ban 已卸载"
            ;;
        0) return ;;
    esac
    press_any_key
}

manage_firewall() {
    print_title "防火墙端口管理"
    echo "自动检测并放行脚本常用端口 (SSH, Sing-box, Snell, Docker)"
    echo
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
    [[ -z "$ssh_port" ]] && ssh_port=22
    
    log_info "SSH 端口: $ssh_port"
    
    if command -v ufw &>/dev/null; then
        log_info "检测到 UFW，正在添加规则..."
        ufw allow "$ssh_port"/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 8443/tcp
        ufw allow 8443/udp
        # Sing-box 常用端口
        ufw allow 443:65535/tcp
        ufw allow 443:65535/udp
        log_success "UFW 规则已更新 (已放行 443-65535)"
    elif command -v firewall-cmd &>/dev/null; then
        log_info "检测到 Firewalld，正在添加规则..."
        firewall-cmd --permanent --add-port="$ssh_port"/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=443-65535/tcp
        firewall-cmd --permanent --add-port=443-65535/udp
        firewall-cmd --reload
        log_success "Firewalld 规则已更新"
    else
        log_info "检测到 iptables，正在添加规则..."
        iptables -I INPUT -p tcp --dport "$ssh_port" -j ACCEPT
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
        iptables -I INPUT -p udp --dport 8443 -j ACCEPT
        log_success "iptables 规则已更新 (注意: 重启后需手动保存)"
    fi
    press_any_key
}

# ==================== 4. 高级 BBR 模块 ====================

install_bbr_kernel() {
    if [[ "$OS" != "debian" && "$OS" != "ubuntu" ]]; then
         log_error "安装内核仅支持 Debian/Ubuntu 系统"
         return
    fi

    print_title "安装 BBR v3 内核"
    log_info "正在从 GitHub 获取最新内核..."
    
    local api_url="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases/latest"
    local arch_match="x86_64"
    [[ "$ARCH" == "aarch64" ]] && arch_match="arm64"
    
    local download_urls=$(curl -s "$api_url" | grep "browser_download_url" | grep "$arch_match" | cut -d '"' -f 4)
    
    if [[ -z "$download_urls" ]]; then
        log_error "未找到适配该架构的内核文件"
        press_any_key
        return
    fi
    
    mkdir -p /tmp/bbr_kernel
    cd /tmp/bbr_kernel
    rm -f *.deb
    
    for url in $download_urls; do
        log_info "下载: ${url##*/}"
        wget -q --show-progress "$url"
    done
    
    log_info "正在安装内核..."
    dpkg -i *.deb
    
    rm -rf /tmp/bbr_kernel
    
    log_success "内核安装完成！请重启系统以生效。"
    if confirm "是否立即重启？"; then
        reboot
    fi
}

enable_bbr_algo() {
    print_title "配置 BBR 拥塞控制"
    echo "1. 启用 BBR + FQ (推荐)"
    echo "2. 启用 BBR + FQ_PIE"
    echo "3. 启用 BBR + CAKE"
    echo "0. 返回"
    
    read -r -p "请选择: " choice
    local qdisc="fq"
    case $choice in
        1) qdisc="fq" ;;
        2) qdisc="fq_pie" ;;
        3) qdisc="cake" ;;
        0) return ;;
        *) return ;;
    esac
    
    echo "net.core.default_qdisc = $qdisc" > /etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-bbr.conf
    sysctl --system >/dev/null 2>&1
    
    log_success "已应用 BBR + $qdisc"
    press_any_key
}

bbr_menu() {
    while true; do
        local algo=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        local qdisc=$(sysctl net.core.default_qdisc 2>/dev/null | awk '{print $3}')
        
        print_title "BBR 高级管理"
        echo -e "当前状态: 算法=${GREEN}${algo:-未知}${NC} 队列=${GREEN}${qdisc:-未知}${NC}"
        echo
        echo "1. 安装 BBR v3 内核 (仅 Debian/Ubuntu)"
        echo "2. 配置 BBR 算法 (FQ/CAKE)"
        echo "0. 返回主菜单"
        
        read -r -p "请选择: " choice
        case $choice in
            1) install_bbr_kernel ;;
            2) enable_bbr_algo ;;
            0) return ;;
        esac
    done
}

# ==================== 5. Docker 模块 ====================

manage_docker() {
    if ! command -v docker &>/dev/null; then
        print_title "安装 Docker"
        echo "1. 官方源安装 (推荐国外 VPS)"
        echo "2. 国内镜像源安装"
        echo "0. 返回"
        read -r -p "请选择: " choice
        case $choice in
            1) curl -fsSL https://get.docker.com | bash ;;
            2) curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun ;;
            *) return ;;
        esac
        systemctl enable docker; systemctl start docker
        log_success "Docker 安装完成"
        press_any_key
        return
    fi
    
    while true; do
        print_title "Docker 管理"
        echo "1. 容器列表 (活动)"
        echo "2. 容器列表 (所有)"
        echo "3. 启动/停止/重启/删除 容器"
        echo "4. 查看日志"
        echo "0. 返回"
        read -r -p "请选择: " choice
        case $choice in
            1) docker ps; press_any_key ;;
            2) docker ps -a; press_any_key ;;
            3) 
                read -r -p "容器名或ID: " name
                read -r -p "操作 (start/stop/restart/rm): " action
                docker "$action" "$name"
                press_any_key 
                ;;
            4) read -r -p "容器名或ID: " name; docker logs "$name"; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== 6. 节点协议模块 (Sing-box) ====================

install_singbox() {
    if command -v sing-box &>/dev/null; then return; fi
    log_info "正在安装 Sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    systemctl enable sing-box
}

gen_sb_config() {
    local type=$1
    local port=$2
    local uuid=$3
    local server_name=$4
    local extra=$5
    
    mkdir -p /etc/sing-box
    
    cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "$type",
      "tag": "in-0",
      "listen": "::",
      "listen_port": $port,
EOF

    if [[ "$type" == "vless" && "$extra" == *"reality"* ]]; then
        local pbk=$(echo "$extra" | cut -d, -f2)
        local pvk=$(echo "$extra" | cut -d, -f3)
        local sid=$(echo "$extra" | cut -d, -f4)
        cat >> /etc/sing-box/config.json <<EOF
      "users": [ { "uuid": "$uuid", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true, "server_name": "$server_name",
        "reality": { "enabled": true, "handshake": { "server": "$server_name", "server_port": 443 }, "private_key": "$pvk", "short_id": ["$sid"] }
      }
EOF
    elif [[ "$type" == "hysteria2" || "$type" == "vmess" || "$type" == "trojan" ]]; then
        local cert_dir="/etc/sing-box/cert"
        mkdir -p "$cert_dir"
        openssl req -x509 -newkey rsa:2048 -keyout "$cert_dir/private.key" -out "$cert_dir/cert.pem" -days 3650 -nodes -subj "/CN=$server_name" >/dev/null 2>&1
        
        if [[ "$type" == "hysteria2" ]]; then
             cat >> /etc/sing-box/config.json <<EOF
      "users": [ { "password": "$uuid" } ],
EOF
        elif [[ "$type" == "trojan" ]]; then
             cat >> /etc/sing-box/config.json <<EOF
      "users": [ { "password": "$uuid" } ],
EOF
        elif [[ "$type" == "vmess" ]]; then
             cat >> /etc/sing-box/config.json <<EOF
      "users": [ { "uuid": "$uuid", "alterId": 0 } ],
EOF
        fi
        
        cat >> /etc/sing-box/config.json <<EOF
      "tls": { "enabled": true, "certificate_path": "$cert_dir/cert.pem", "key_path": "$cert_dir/private.key" }
EOF
    fi

    cat >> /etc/sing-box/config.json <<EOF
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
}

deploy_sb_node() {
    install_singbox
    print_title "Sing-box 节点部署"
    echo "1. VLESS-Reality-Vision (推荐)"
    echo "2. Hysteria2 (UDP，双向加速)"
    echo "3. Trojan-TLS"
    echo "4. VMess-TLS"
    echo "0. 返回"
    read -r -p "请选择: " choice
    
    local port uuid server_name share_link
    read -r -p "端口 (默认443/8443): " port
    uuid=$(sing-box generate uuid)
    server_name="www.bing.com" 
    
    case $choice in
        1) 
            [[ -z "$port" ]] && port=443
            server_name="www.microsoft.com"
            local kp=$(sing-box generate reality-keypair)
            local pvk=$(echo "$kp" | grep PrivateKey | awk '{print $2}' | tr -d '"')
            local pbk=$(echo "$kp" | grep PublicKey | awk '{print $2}' | tr -d '"')
            local sid=$(sing-box generate rand --hex 8)
            gen_sb_config "vless" "$port" "$uuid" "$server_name" "reality,$pbk,$pvk,$sid"
            share_link="vless://$uuid@$(get_public_ip):$port?security=reality&encryption=none&pbk=$pbk&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$server_name&sid=$sid#VLESS-Reality"
            ;;
        2) 
            [[ -z "$port" ]] && port=8443
            local password=$(sing-box generate rand --hex 16)
            uuid=$password 
            gen_sb_config "hysteria2" "$port" "$password" "$server_name"
            share_link="hysteria2://$password@$(get_public_ip):$port?insecure=1&sni=$server_name#Hysteria2"
            ;;
        3) 
            [[ -z "$port" ]] && port=8443
            local password=$(sing-box generate rand --hex 8)
            uuid=$password
            gen_sb_config "trojan" "$port" "$password" "$server_name"
            share_link="trojan://$password@$(get_public_ip):$port?security=tls&allowInsecure=1&sni=$server_name#Trojan"
            ;;
        4) 
            [[ -z "$port" ]] && port=8443
            gen_sb_config "vmess" "$port" "$uuid" "$server_name"
            share_link="vmess://(请手动添加: IP=$(get_public_ip), Port=$port, UUID=$uuid, TLS=on, AllowInsecure=on)"
            ;;
        *) return ;;
    esac
    
    systemctl restart sing-box
    log_success "部署成功！"
    echo -e "分享链接: ${CYAN}$share_link${NC}"
    log_warn "注意：除 Reality 外，其他协议均使用自签证书，客户端请开启 'Allow Insecure'。"
    press_any_key
}

install_snell() {
    print_title "部署 Snell v4"
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
        log_error "Snell 仅支持 x86_64 和 arm64"
        return
    fi
    log_info "正在下载 Snell v4..."
    local snell_url=""
    if [[ "$ARCH" == "x86_64" ]]; then
        snell_url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-amd64.zip"
    else
        snell_url="https://dl.nssurge.com/snell/snell-server-v4.0.1-linux-aarch64.zip"
    fi
    wget -q -O /tmp/snell.zip "$snell_url"
    unzip -o /tmp/snell.zip -d /usr/local/bin/
    chmod +x /usr/local/bin/snell-server
    rm -f /tmp/snell.zip
    
    read -r -p "设置端口 (默认 12345): " port
    port=${port:-12345}
    read -r -p "设置密钥 (PSK) [回车随机]: " psk
    [[ -z "$psk" ]] && psk=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    
    mkdir -p /etc/snell
    cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = 0.0.0.0:$port
psk = $psk
ipv6 = false
EOF
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
    log_success "Snell 部署成功！"
    echo -e "PSK: ${GREEN}$psk${NC}"
    press_any_key
}

# ==================== 7. 网络诊断工具模块 ====================

network_tools_menu() {
    while true; do
        print_title "网络诊断工具 (第三方集成)"
        echo "1. 三网测速 (Hyperspeed)"
        echo "2. 流媒体解锁检测 (RegionRestrictionCheck)"
        echo "3. 回程路由检测 (NextTrace)"
        echo "0. 返回"
        read -r -p "请选择: " choice
        
        case $choice in
            1)
                bash <(curl -Lso- https://bench.im/hyperspeed)
                press_any_key
                ;;
            2)
                bash <(curl -L -s check.unlock.media)
                press_any_key
                ;;
            3)
                bash <(curl -N https://rio.233.eor.wtf/)
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 8. 主菜单 ====================

main_menu() {
    while true; do
        print_title "VPS 一键管理工具箱 v${SCRIPT_VERSION}"
        echo -e "系统: ${GREEN}${OS} ${VERSION} (${ARCH})${NC}  |  IP: ${GREEN}$(get_public_ip)${NC}"
        echo
        echo -e "${YELLOW}--- 系统与安全 ---${NC}"
        echo "1. 系统环境更新 (更新/时区/Swap)"
        echo "2. 安全防护 (Fail2ban/防火墙端口)"
        echo "3. 高级 BBR 管理 (内核/算法)"
        echo "4. 系统维护 (日志清理/IPv4优先)"
        echo
        echo -e "${YELLOW}--- 节点部署 ---${NC}"
        echo "5. Sing-box 全协议 (Reality/Hy2/Trojan)"
        echo "6. Snell v4 部署 (Surge专用)"
        echo
        echo -e "${YELLOW}--- 网络诊断 ---${NC}"
        echo "7. 网络测速 & 流媒体检测"
        echo
        echo -e "${YELLOW}--- 其他 ---${NC}"
        echo "8. Docker 管理"
        echo "9. 检查脚本更新"
        echo "0. 退出"
        
        echo
        read -r -p "请选择: " choice
        case $choice in
            1) 
                echo "1. 系统更新"; echo "2. 时区设置"; echo "3. Swap管理"; echo "0. 返回"
                read -r -p "-> " sub
                case $sub in 1) system_update;; 2) set_timezone;; 3) manage_swap;; esac 
                ;;
            2)
                echo "1. Fail2ban (防爆破)"; echo "2. 防火墙端口放行"; echo "0. 返回"
                read -r -p "-> " sub
                case $sub in 1) install_fail2ban;; 2) manage_firewall;; esac
                ;;
            3) bbr_menu ;;
            4) system_maintenance_menu ;;
            5) deploy_sb_node ;;
            6) install_snell ;;
            7) network_tools_menu ;;
            8) manage_docker ;;
            9) update_script ;;
            0) exit 0 ;;
            *) log_error "无效选择"; press_any_key ;;
        esac
    done
}

check_root
detect_os
[ -f "$INSTALL_PATH" ] || cp "$0" "$INSTALL_PATH" 2>/dev/null 
main_menu
