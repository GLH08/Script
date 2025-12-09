#!/usr/bin/env bash
#
# VPS 一键管理工具箱 (Refactored)
# 专为新手设计，集成常用功能与多节点部署
#

# ==================== 全局变量 & 颜色 ====================
export LANG=en_US.UTF-8

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="2.1.0"
GITHUB_RAW="https://raw.githubusercontent.com/your-username/vps-toolkit/main"

# ==================== 核心工具函数 ====================

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
    
    # 清空输入缓存 (尝试读取所有待处理的输入，设置极短超时)
    read -t 0.1 -n 10000 discard 2>/dev/null || true
    
    # 读取单个按键
    read -rsn1 key 2>/dev/null || true
    
    # 如果是转义序列(如方向键)，尝试读取剩余部分并丢弃
    if [[ "$key" == $'\x1b' ]]; then
        read -rsn2 -t 0.1 discard 2>/dev/null || true
    fi
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
        log_info "正在安装 $pkg..."
        case $PACKAGE_MANAGER in
            apt-get) apt-get update -qq && apt-get install -y "$pkg" ;;
            yum) yum install -y "$pkg" ;;
            apk) apk add --no-cache "$pkg" ;;
        esac
    fi
}

get_public_ip() {
    curl -s4 icanhazip.com
}

# ==================== 系统管理模块 ====================

system_update() {
    print_title "系统更新"
    log_info "正在更新系统软件包..."
    case $PACKAGE_MANAGER in
        apt-get) apt-get update && apt-get upgrade -y && apt-get autoremove -y ;;
        yum) yum update -y ;;
        apk) apk update && apk upgrade ;;
    esac
    
    log_info "安装常用工具 (curl, wget, git, vim, jq, tar)..."
    install_pkg curl
    install_pkg wget
    install_pkg git
    install_pkg vim
    install_pkg jq
    install_pkg tar
    install_pkg unzip
    
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
    echo "1. 添加/修改 Swap"
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
            
            # 写入 fstab
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

enable_bbr() {
    print_title "BBR 加速管理"
    
    # 简单检查 BBR 状态
    local current_algo=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    echo -e "当前拥塞控制算法: ${GREEN}${current_algo}${NC}"
    
    echo
    echo "1. 开启 BBR"
    echo "0. 返回"
    
    read -r -p "请选择: " choice
    if [[ "$choice" == "1" ]]; then
        echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-bbr.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
        sysctl --system
        log_success "BBR 已开启！"
    fi
    press_any_key
}

# ==================== Docker 模块 ====================

install_docker() {
    if command -v docker &>/dev/null; then
        log_info "Docker 已安装"
        return
    fi
    
    print_title "安装 Docker"
    echo "1. 官方源安装 (推荐国外 VPS)"
    echo "2. 国内镜像源安装 (推荐国内 VPS)"
    echo "0. 返回"
    
    read -r -p "请选择: " choice
    case $choice in
        1) curl -fsSL https://get.docker.com | bash ;;
        2) curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun ;;
        *) return ;;
    esac
    
    systemctl enable docker
    systemctl start docker
    
    # Install Docker Compose
    log_info "正在安装 Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    log_success "Docker 安装完成！"
    press_any_key
}

manage_docker() {
    if ! command -v docker &>/dev/null; then
        install_docker
        return
    fi

    while true; do
        print_title "Docker 管理"
        echo "1. 查看运行中的容器"
        echo "2. 查看所有容器"
        echo "3. 启动容器"
        echo "4. 停止容器"
        echo "5. 重启容器"
        echo "6. 查看容器日志"
        echo "7. 删除容器"
        echo "8. 卸载 Docker"
        echo "0. 返回主菜单"
        
        read -r -p "请选择: " choice
        case $choice in
            1) docker ps; press_any_key ;;
            2) docker ps -a; press_any_key ;;
            3) read -r -p "容器名/ID: " name; docker start "$name"; press_any_key ;;
            4) read -r -p "容器名/ID: " name; docker stop "$name"; press_any_key ;;
            5) read -r -p "容器名/ID: " name; docker restart "$name"; press_any_key ;;
            6) read -r -p "容器名/ID: " name; docker logs "$name"; press_any_key ;;
            7) read -r -p "容器名/ID: " name; docker rm -f "$name"; press_any_key ;;
            8) 
                if confirm "确定要卸载 Docker 吗？"; then
                    apt-get purge -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
                    rm -rf /var/lib/docker
                    log_success "Docker 已卸载"
                fi
                press_any_key
                ;;
            0) return ;;
        esac
    done
}

# ==================== 节点部署模块 ====================

install_singbox() {
    log_info "正在安装 Sing-box..."
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    systemctl enable sing-box
    log_success "Sing-box 安装完成"
}

deploy_singbox_reality() {
    if ! command -v sing-box &>/dev/null; then
        install_singbox
    fi
    
    print_title "部署 Sing-box (VLESS-Reality)"
    
    read -r -p "请输入端口 (默认 443): " port
    port=${port:-443}
    
    # 生成 UUID 和 Keys
    local uuid=$(sing-box generate uuid)
    local key_pair=$(sing-box generate reality-keypair)
    local private_key=$(echo "$key_pair" | grep "PrivateKey" | cut -d: -f2 | tr -d ' "')
    local public_key=$(echo "$key_pair" | grep "PublicKey" | cut -d: -f2 | tr -d ' "')
    local short_id=$(sing-box generate rand --hex 8)
    local server_name="www.microsoft.com"
    
    cat > /etc/sing-box/config.json <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$server_name",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$server_name",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
    
    systemctl restart sing-box
    
    local ip=$(get_public_ip)
    local share_link="vless://$uuid@$ip:$port?security=reality&encryption=none&pbk=$public_key&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$server_name&sid=$short_id#SingBox-Reality"
    
    log_success "部署成功！"
    echo -e "IP: ${GREEN}$ip${NC}"
    echo -e "端口: ${GREEN}$port${NC}"
    echo -e "UUID: ${GREEN}$uuid${NC}"
    echo -e "Public Key: ${GREEN}$public_key${NC}"
    echo -e "Short ID: ${GREEN}$short_id${NC}"
    echo
    echo -e "分享链接: ${CYAN}$share_link${NC}"
    press_any_key
}

install_xray() {
    log_info "正在安装 Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    log_success "Xray 安装完成"
}

deploy_xray_reality() {
    if ! command -v xray &>/dev/null; then
        install_xray
    fi
    
    print_title "部署 Xray (VLESS-Reality)"
    
    read -r -p "请输入端口 (默认 443): " port
    port=${port:-443}
    
    local uuid=$(xray uuid)
    local key_pair=$(xray x25519)
    local private_key=$(echo "$key_pair" | grep "Private" | awk '{print $3}')
    local public_key=$(echo "$key_pair" | grep "Public" | awk '{print $3}')
    local short_id=$(openssl rand -hex 8)
    local server_name="www.microsoft.com"
    
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$server_name:443",
          "xver": 0,
          "serverNames": [
            "$server_name"
          ],
          "privateKey": "$private_key",
          "shortIds": [
            "$short_id"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
    
    systemctl restart xray
    
    local ip=$(get_public_ip)
    local share_link="vless://$uuid@$ip:$port?security=reality&encryption=none&pbk=$public_key&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=$server_name&sid=$short_id#Xray-Reality"
    
    log_success "部署成功！"
    echo -e "IP: ${GREEN}$ip${NC}"
    echo -e "端口: ${GREEN}$port${NC}"
    echo -e "UUID: ${GREEN}$uuid${NC}"
    echo -e "Public Key: ${GREEN}$public_key${NC}"
    echo -e "Short ID: ${GREEN}$short_id${NC}"
    echo
    echo -e "分享链接: ${CYAN}$share_link${NC}"
    press_any_key
}

node_menu() {
    while true; do
        print_title "多节点部署"
        echo "1. 部署 Sing-box (VLESS-Reality)"
        echo "2. 部署 Xray (VLESS-Reality)"
        echo "3. 查看 Sing-box 配置"
        echo "4. 查看 Xray 配置"
        echo "0. 返回主菜单"
        
        read -r -p "请选择: " choice
        case $choice in
            1) deploy_singbox_reality ;;
            2) deploy_xray_reality ;;
            3) cat /etc/sing-box/config.json; press_any_key ;;
            4) cat /usr/local/etc/xray/config.json; press_any_key ;;
            0) return ;;
        esac
    done
}

# ==================== 主菜单 ====================

main_menu() {
    while true; do
        print_title "VPS 一键管理工具箱 v${SCRIPT_VERSION}"
        echo -e "当前系统: ${GREEN}${OS} ${VERSION}${NC}"
        echo -e "IP地址: ${GREEN}$(get_public_ip)${NC}"
        echo
        echo -e "${YELLOW}--- 系统设置 ---${NC}"
        echo "1. 系统更新 & 常用工具"
        echo "2. 时区设置"
        echo "3. Swap 管理"
        echo "4. BBR 加速"
        echo
        echo -e "${YELLOW}--- 应用管理 ---${NC}"
        echo "5. Docker 管理"
        echo "6. 多节点部署 (Sing-box/Xray)"
        echo
        echo -e "${YELLOW}--- 其他 ---${NC}"
        echo "0. 退出脚本"
        
        echo
        read -r -p "请选择 [0-6]: " choice
        case $choice in
            1) system_update ;;
            2) set_timezone ;;
            3) manage_swap ;;
            4) enable_bbr ;;
            5) manage_docker ;;
            6) node_menu ;;
            0) exit 0 ;;
            *) log_error "无效选择"; press_any_key ;;
        esac
    done
}

# ==================== 入口 ====================

check_root
detect_os
main_menu
