#!/usr/bin/env bash
#
# VPS ToolKit v6.0.2 (Ultimate Consolidation)
# 
# 整合功能：
# 1. 基础系统初始化 (Granular)
# 2. 多协议节点部署 (VLESS/Hy2/SS2022/Snell)
# 3. 节点格式导出 (Loon/Sing-box/Standard)
# 4. 开发工具集 (GHCR Creds, Docker, Acme)
#

export LANG=en_US.UTF-8

# ==================== 全局配置 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_VERSION="6.0.2"
GITHUB_RAW_URL="https://raw.githubusercontent.com/GLH08/Script/main/vps.sh"
INSTALL_PATH="/usr/local/bin/vps"
SB_CONFIG="/etc/sing-box/config.json"
CERT_DIR="/etc/vps/cert"
SNELL_CONF="/etc/snell/config.conf"

# ==================== 基础工具 & 防火墙 ====================

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }

print_title() { clear; echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"; echo -e "${CYAN}            $1${NC}"; echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"; }
print_line() { echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"; }

confirm_action() {
    echo; echo -e "${YELLOW}>> $1${NC}"
    read -r -p "确认执行？[y/N]: " response
    [[ "$response" =~ ^[Yy]$ ]] || { log_warn "已取消"; return 1; }
    return 0
}

detect_os() {
    if [[ -f /etc/os-release ]]; then . /etc/os-release; OS=$ID; else OS="unknown"; fi
    case $OS in
        ubuntu|debian) PKG_MGR="apt-get"; INSTALL="apt-get install -y" ;;
        centos|rhel|almalinux|rocky) PKG_MGR="yum"; INSTALL="yum install -y" ;;
        alpine) PKG_MGR="apk"; INSTALL="apk add" ;;
        *) log_error "不支持的系统: $OS"; exit 1 ;;
    esac
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_ALT="amd64" ;;
        aarch64|arm64) ARCH_ALT="aarch64" ;;
        *) log_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

check_root() { [[ $EUID -ne 0 ]] && log_error "请使用 root 权限" && exit 1; }

get_public_ip() { curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip; }

# 增强型防火墙端口开放 (Ported from vasma.sh logic)
allow_port() {
    local port="$1"
    local proto="${2:-tcp}"
    log_info "正在开放防火墙端口: ${port}/${proto}..."
    
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${port}/${proto}"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --zone=public --add-port="${port}/${proto}" --permanent
        firewall-cmd --reload
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT
        # Try to save if persistent package exists
        netfilter-persistent save 2>/dev/null || service iptables save 2>/dev/null
    else
        log_warn "未检测到活跃的防火墙服务 (UFW/Firewalld)，跳过规则添加。"
    fi
}

# ==================== 系统初始化 (Granular) ====================

sys_update() {
    log_info "更新系统软件包..."
    case $PKG_MGR in
        apt-get) apt-get update && apt-get upgrade -y ;;
        yum) yum update -y ;;
        apk) apk update && apk upgrade ;;
    esac
    log_success "系统已更新"
    read -r -p "按任意键返回..."
}

sys_install_tools() {
    log_info "正在安装基础工具..."
    echo "包含: curl, wget, vim, git, socat, rsyslog (系统日志), bsdmainutils (column工具) 等"
    $INSTALL curl wget vim nano unzip zip tar git jq socat chrony iproute2 pass gnupg2 rsyslog bsdmainutils
    systemctl enable --now rsyslog 2>/dev/null
    log_success "工具安装完成"
    read -r -p "按任意键返回..."
}

sys_timezone() {
    log_info "设置时区为 Asia/Shanghai"
    timedatectl set-timezone Asia/Shanghai 2>/dev/null || ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    log_success "时区已设置: $(date)"
    read -r -p "按任意键返回..."
}

sys_swap() {
    local current_swap=$(free -m | awk '/Swap/ {print $2}')
    if [[ "$current_swap" -ne 0 ]]; then
        echo -e "当前 Swap: ${GREEN}${current_swap}MB${NC}"
        if ! confirm_action "Swap 已存在，是否删除并重新创建？"; then return; fi
        swapoff /swapfile 2>/dev/null
        rm -f /swapfile
        sed -i '/\/swapfile/d' /etc/fstab
        echo "旧 Swap 已删除"
    fi

    read -r -p "请输入 Swap 大小 (单位MB，建议 2048): " size
    [[ -z "$size" ]] && size=2048
    if [[ ! "$size" =~ ^[0-9]+$ ]]; then log_error "输入无效"; return; fi

    log_info "正在创建 ${size}MB Swap..."
    dd if=/dev/zero of=/swapfile bs=1M count=$size status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    log_success "Swap 创建完成"
    
    read -r -p "按任意键返回..."
}

menu_system() {
    while true; do
        print_title "系统初始化"
        echo " 1. 更新系统 (Update & Upgrade)"
        echo " 2. 安装必备工具 (Tools)"
        echo " 3. 设置时区 (Asia/Shanghai)"
        echo " 4. 开启虚拟内存 (Swap)"
        echo " 5. 一键执行所有初始化"
        echo " 0. 返回"
        read -r -p "选: " c
        case $c in
            1) sys_update ;;
            2) sys_install_tools ;;
            3) sys_timezone ;;
            4) sys_swap ;;
            5) 
                if confirm_action "执行所有初始化步骤"; then
                    sys_update; sys_install_tools; sys_timezone; sys_swap
                fi
                ;;
            0) return ;;
        esac
    done
}

# ==================== 高级工具集 ====================

# 也就是 setup-docker-credential.sh 的核心逻辑
install_ghcr_creds() {
    print_title "GHCR (Docker) 凭据助手配置"
    log_info "此工具用于配置私有 Docker 镜像仓库 (如 GHCR) 的免密/加密认证。"
    
    if ! confirm_action "安装 Docker Credential Pass ?"; then return; fi
    
    # 1. 依赖已在 init 中安装 (pass, gnupg2)
    # Ensure installed just in case
    $INSTALL pass gnupg2 >/dev/null
    
    # 2. 生成 GPG Key
    if ! gpg --list-secret-keys --with-colons | grep -q "^sec"; then
        log_info "生成无密码 GPG 密钥..."
        cat >/tmp/gpg-batch <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Name-Real: Docker Credential Helper
Name-Email: docker@$(hostname)
Expire-Date: 0
EOF
        gpg --batch --gen-key /tmp/gpg-batch 2>/dev/null
        rm /tmp/gpg-batch
    fi
    
    # 3. Init pass
    local kID=$(gpg --list-secret-keys --with-colons | grep '^sec' | head -n1 | cut -d: -f5)
    if [[ -n "$kID" ]]; then
        pass init "$kID"
    else
        log_error "GPG 密钥生成失败"; return
    fi
    
    # 4. Install Helper
    log_info "下载 docker-credential-pass..."
    local url=$(curl -s https://api.github.com/repos/docker/docker-credential-helpers/releases/latest | jq -r '.assets[] | select(.name|contains("linux-amd64")) | select(.name|contains("pass")) | .browser_download_url')
    if [[ -z "$url" ]]; then log_error "获取下载链接失败"; return; fi
    
    curl -sL "$url" -o /usr/local/bin/docker-credential-pass
    chmod +x /usr/local/bin/docker-credential-pass
    
    # 5. Config Docker
    local dcfg="$HOME/.docker/config.json"
    mkdir -p "$(dirname "$dcfg")"
    [[ ! -f "$dcfg" ]] && echo "{}" > "$dcfg"
    local tmp=$(mktemp)
    jq '.credsStore = "pass"' "$dcfg" > "$tmp" && mv "$tmp" "$dcfg"
    
    log_success "GHCR 凭据助手配置完成！"
    echo -e "${YELLOW}提示: 请运行 'docker login ghcr.io' 登录，凭据将被加密存储。${NC}"
    read -r -p "按任意键返回..."
}

# ==================== 节点部署核心 ====================

install_singbox() {
    if ! command -v sing-box &>/dev/null; then
        log_info "安装 Sing-box..."
        bash <(curl -fsSL https://sing-box.app/deb-install.sh)
        systemctl enable sing-box
    fi
    mkdir -p /etc/sing-box /etc/sing-box/cert
    [[ ! -f "$SB_CONFIG" ]] && echo '{ "log": { "level": "info", "timestamp": true }, "inbounds": [], "outbounds": [ { "type": "direct", "tag": "direct" } ] }' > "$SB_CONFIG"
}

add_sb_inbound() {
    local tag="$1"; local json="$2";
    install_singbox
    if grep -q "\"tag\": \"$tag\"" "$SB_CONFIG"; then log_error "Tag [$tag] 已存在"; return 1; fi
    
    local tmp=$(mktemp)
    jq ".inbounds += [$json]" "$SB_CONFIG" > "$tmp" && mv "$tmp" "$SB_CONFIG"
    if systemctl restart sing-box; then
        log_success "Sing-box 重载成功"
        return 0
    else
        log_error "Sing-box 重载失败，请检查日志"; return 1
    fi
}

acme_cert() {
    local d="$1"
    if [[ ! -f "$CERT_DIR/$d.key" ]]; then
        log_info "申请证书: $d"
        curl https://get.acme.sh | sh
        ~/.acme.sh/acme.sh --issue --standalone -d "$d" --force
        mkdir -p "$CERT_DIR"
        ~/.acme.sh/acme.sh --install-cert -d "$d" --key-file "$CERT_DIR/$d.key" --fullchain-file "$CERT_DIR/$d.pem"
    fi
}

# --- Loon Format Generator ---
gen_loon_vless() {
    local uuid=$1; local ip=$2; local port=$3; local sni=$4; local pbk=$5; local sid=$6; local tag="VLESS-Reality"
    # Format: Tag = VLESS, ip, port, uuid, transport=tcp, flow=vision, public-key=..., short-id=..., udp=true, over-tls=true, sni=..., skip-cert-verify=true
    echo "${tag} = VLESS,${ip},${port},\"${uuid}\",transport=tcp,flow=xtls-rprx-vision,public-key=\"${pbk}\",short-id=${sid},udp=true,over-tls=true,sni=${sni},skip-cert-verify=true"
}

gen_loon_hy2() {
    local pass=$1; local ip=$2; local port=$3; local sni=$4; local tag="Hy2"
    # Format: Tag = Hysteria2, ip, port, password, sni=..., skip-cert-verify=true, udp=true
    echo "${tag} = Hysteria2,${ip},${port},\"${pass}\",sni=${sni},skip-cert-verify=true,udp=true"
}

gen_loon_ss2022() {
    local ip=$1; local pub_port=$2; local method=$3; local key=$4; local stls_pass=$5; local sni=$6; local tag="SS2022"
    # Format: Tag = Shadowsocks, ip, port, method, "key", fast-open=true, udp=true, shadow-tls-password=..., shadow-tls-sni=..., shadow-tls-version=3
    echo "${tag} = Shadowsocks,${ip},${pub_port},${method},\"${key}\",fast-open=true,udp=true,shadow-tls-password=${stls_pass},shadow-tls-sni=${sni},shadow-tls-version=3"
}

# --- Deploy Functions ---

deploy_vless_reality() {
    print_title "部署 VLESS + Reality + Vision"
    read -r -p "端口 [443]: " port; [[ -z "$port" ]] && port=443
    allow_port $port
    
    local uuid=$(sing-box generate uuid)
    local kp=$(sing-box generate reality-keypair)
    local pvk=$(echo "$kp" | grep "Private" | awk '{print $3}')
    local pbk=$(echo "$kp" | grep "Public" | awk '{print $3}')
    local sid=$(sing-box generate rand --hex 8)
    local sni="www.microsoft.com"
    local ip=$(get_public_ip)
    
    local json='{
        "type": "vless", "tag": "vless-reality-'$port'", "listen": "::", "listen_port": '$port',
        "users": [{ "uuid": "'$uuid'", "flow": "xtls-rprx-vision", "name": "u1" }],
        "tls": { "enabled": true, "server_name": "'$sni'", "reality": { "enabled": true, "handshake": { "server": "'$sni'", "server_port": 443 }, "private_key": "'$pvk'", "short_id": ["'$sid'"] } }
    }'
    
    if add_sb_inbound "vless-reality-$port" "$json"; then
        echo; echo -e "${YELLOW}=== Loon 节点配置 ===${NC}"
        gen_loon_vless "$uuid" "$ip" "$port" "$sni" "$pbk" "$sid"
        echo; echo -e "${YELLOW}=== 通用分享链接 ===${NC}"
        echo "vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid&type=tcp#vless-reality"
    fi
    read -r -p "按任意键返回..."
}

deploy_hy2() {
    print_title "部署 Hysteria2"
    read -r -p "端口 [8443]: " port; [[ -z "$port" ]] && port=8443
    read -r -p "密码 [随机]: " pass; [[ -z "$pass" ]] && pass=$(sing-box generate rand --hex 8)
    allow_port $port "udp"
    
    local cert="/etc/sing-box/cert/hy2_$port.pem"
    local key="/etc/sing-box/cert/hy2_$port.key"
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout "$key" -out "$cert" -days 3650 -subj "/CN=bing.com" 2>/dev/null
    local ip=$(get_public_ip)
    
    local json='{
        "type": "hysteria2", "tag": "hy2-'$port'", "listen": "::", "listen_port": '$port',
        "users": [{ "password": "'$pass'" }],
        "tls": { "enabled": true, "certificate_path": "'$cert'", "key_path": "'$key'" }
    }'
    
    if add_sb_inbound "hy2-$port" "$json"; then
         echo; echo -e "${YELLOW}=== Loon 节点配置 ===${NC}"
         gen_loon_hy2 "$pass" "$ip" "$port" "bing.com"
         echo; echo -e "${YELLOW}=== 通用分享链接 ===${NC}"
         echo "hysteria2://$pass@$ip:$port?peer=bing.com&insecure=1&sni=bing.com#hy2-$port"
    fi
    read -r -p "按任意键返回..."
}

deploy_ss2022_stls() {
    print_title "部署 SS2022 + ShadowTLS"
    read -r -p "ShadowTLS 外部端口 [443]: " port_pub; [[ -z "$port_pub" ]] && port_pub=443
    read -r -p "SS 内部端口 [33001]: " port_ss; [[ -z "$port_ss" ]] && port_ss=33001
    allow_port $port_pub
    
    local key=$(sing-box generate rand --base64 32)
    local stls_pass=$(sing-box generate rand --hex 8)
    local method="2022-blake3-aes-256-gcm"
    local sni="www.microsoft.com" # Should specific valid handshake
    local ip=$(get_public_ip)
    
    # SS Inbound
    local json_ss='{ "type": "shadowsocks", "tag": "ss-int-'$port_ss'", "listen": "127.0.0.1", "listen_port": '$port_ss', "method": "'$method'", "password": "'$key'" }'
    
    # STLS Inbound (Need outbound tweak like in v5.1)
    local json_out='{ "type": "direct", "tag": "to-ss-'$port_ss'", "override_address": "127.0.0.1", "override_port": '$port_ss' }'
    if ! grep -q "\"tag\": \"to-ss-$port_ss\"" "$SB_CONFIG"; then
        local tmp=$(mktemp); jq ".outbounds += [$json_out]" "$SB_CONFIG" > "$tmp" && mv "$tmp" "$SB_CONFIG"
    fi
    if ! grep -q "\"tag\": \"ss-int-$port_ss\"" "$SB_CONFIG"; then
        local tmp=$(mktemp); jq ".inbounds += [$json_ss]" "$SB_CONFIG" > "$tmp" && mv "$tmp" "$SB_CONFIG"
    fi
    
    local json_stls='{
        "type": "shadowtls", "tag": "stls-'$port_pub'", "listen": "::", "listen_port": '$port_pub',
        "version": 3, "password": "'$stls_pass'", "users": [{ "password": "'$stls_pass'" }],
        "handshake": { "server": "'$sni'", "server_port": 443 }, "detour": "to-ss-'$port_ss'"
    }'
    
    if add_sb_inbound "stls-$port_pub" "$json_stls"; then
        echo; echo -e "${YELLOW}=== Loon 节点配置 ===${NC}"
        gen_loon_ss2022 "$ip" "$port_pub" "$method" "$key" "$stls_pass" "$sni"
        echo; echo -e "${YELLOW}=== 通用分享链接 ===${NC}"
        echo "ss://$method:$key@$ip:$port_pub?plugin=shadow-tls&plugin-opts=host%3D$sni%3Bpassword%3D$stls_pass%3Bversion%3D3#ss-stls"
    fi
    read -r -p "按任意键返回..."
}

deploy_snell() {
    print_title "部署 Snell"
    echo "1. 安装 Snell v4 (稳定)"; echo "2. 安装 Snell v5 (最新)"; echo "0. 返回"
    read -r -p "选择: " c
    local ver=""
    case $c in
        1) ver="4.1.1" ;;
        2) ver="5.0.1" ;;
        *) return ;;
    esac
    
    local url="https://dl.nssurge.com/snell/snell-server-v${ver}-linux-${ARCH_ALT}.zip"
    wget -O snell.zip "$url" || { log_error "下载失败"; return; }
    unzip -o snell.zip -d /usr/local/bin
    chmod +x /usr/local/bin/snell-server
    
    local port=$((RANDOM % 10000 + 50000))
    local psk=$(sing-box generate rand --hex 16)
    
    allow_port $port "tcp"
    allow_port $port "udp"
    
    cat > /etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell
After=network.target
[Service]
ExecStart=/usr/local/bin/snell-server -l 0.0.0.0:$port -k $psk
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now snell
    
    echo; echo -e "${YELLOW}=== Snell 配置 (Loon/Surge) ===${NC}"
    echo "snell = snell, $(get_public_ip), $port, psk=$psk, version=4, dscp=46"
    read -r -p "按任意键返回..."
}

# ==================== 管理功能 ====================

list_status() {
    print_title "节点状态"
    if [[ -f "$SB_CONFIG" ]]; then
        echo -e "${YELLOW}--- Sing-box Nodes ---${NC}"
        # Parse tags
        local tags=$(jq -r '.inbounds[].tag' "$SB_CONFIG" 2>/dev/null)
        if [[ -n "$tags" ]]; then
            echo "$tags" | while read t; do
                local port=$(jq -r ".inbounds[] | select(.tag==\"$t\") | .listen_port" "$SB_CONFIG")
                echo "- Tag: $t (Port: $port)"
            done
        else
            echo "无 Sing-box 节点"
        fi
    fi
    
    if systemctl is-active snell &>/dev/null; then
        echo -e "${YELLOW}--- Snell Node ---${NC}"
        systemctl status snell | grep "ExecStart" | awk '{print $NF}'
    fi
    echo
    read -r -p "按任意键返回..."
}

uninstall_node() {
    print_title "卸载节点"
    local tags=$(jq -r '.inbounds[].tag' "$SB_CONFIG" 2>/dev/null)
    
    echo "Sing-box 节点列表:"
    local i=1
    local tag_list=""
    if [[ -n "$tags" ]]; then
        for t in $tags; do
            echo " $i. $t"
            tag_list[$i]=$t
            ((i++))
        done
    fi
    echo " 99. 卸载 Snell"
    echo " 0. 返回"
    
    read -r -p "选择卸载对象: " idx
    if [[ "$idx" == "99" ]]; then
         if confirm_action "卸载 Snell"; then
             systemctl stop snell
             systemctl disable snell
             rm /etc/systemd/system/snell.service
             systemctl daemon-reload
             log_success "Snell 已卸载"
         fi
    elif [[ "$idx" -gt 0 && "$idx" -lt "$i" ]]; then
         local t=${tag_list[$idx]}
         if confirm_action "删除 Sing-box 节点 [$t]"; then
             local tmp=$(mktemp)
             jq "del(.inbounds[] | select(.tag == \"$t\"))" "$SB_CONFIG" > "$tmp" && mv "$tmp" "$SB_CONFIG"
             systemctl restart sing-box
             log_success "节点 [$t] 已删除"
         fi
    fi
    read -r -p "按任意键返回..."
}

# --- Legacy/CDN Protocols ---
deploy_ws_tls() {
    print_title "部署 WS + TLS (CDN常用)"
    echo " 1. VLESS + WS + TLS"
    echo " 2. VMess + WS + TLS"
    echo " 3. Trojan + WS + TLS"
    echo " 0. 返回"
    read -r -p "选: " c
    local proto=""
    case $c in
        1) proto="vless" ;;
        2) proto="vmess" ;;
        3) proto="trojan" ;;
        *) return ;;
    esac

    read -r -p "域名 (已解析到本机): " domain
    [[ -z "$domain" ]] && return
    read -r -p "端口 [443]: " port
    [[ -z "$port" ]] && port=443
    
    allow_port $port
    acme_cert "$domain" # Helper to get cert
    
    local uuid=$(sing-box generate uuid)
    local user_part=""
    if [[ "$proto" == "trojan" ]]; then 
        user_part='"users": [{"password": "'$uuid'"}]'
    elif [[ "$proto" == "vmess" ]]; then 
        user_part='"users": [{"uuid": "'$uuid'", "alterId": 0}]'
    else 
        user_part='"users": [{"uuid": "'$uuid'"}]'
    fi
    
    local json='{
        "type": "'$proto'", "tag": "'$proto'-ws-'$port'", "listen": "::", "listen_port": '$port',
        '$user_part',
        "tls": { "enabled": true, "server_name": "'$domain'", "certificate_path": "'$CERT_DIR'/'$domain'.pem", "key_path": "'$CERT_DIR'/'$domain'.key" },
        "transport": { "type": "ws", "path": "/" }
    }'
    
    if add_sb_inbound "$proto-ws-$port" "$json"; then
        echo; echo -e "${YELLOW}=== 通用分享链接 ===${NC}"
        # Simple Logic for link generation (omitted for brevity, can be added if needed)
        echo "已部署。请使用客户端添加 $proto (WS+TLS) 配置。"
        echo "UUID/Password: $uuid"
        echo "Path: /"
    fi
    read -r -p "按任意键返回..."
}

# ==================== Fail2ban 管理 ====================

fail2ban_menu() {
    while true; do
        print_title "Fail2ban 安全中心"
        local status="未运行"
        if systemctl is-active fail2ban &>/dev/null; then status="${GREEN}运行中${NC}"; else status="${RED}停止${NC}"; fi
        echo -e "状态: $status"
        echo
        echo " 1. 安装/重置 Fail2ban (Auto Fix)"
        echo " 2. 查看拦截记录 (Jailed IP)"
        echo " 3. 解封 IP (Unban)"
        echo " 4. 查看日志 (Last 50)"
        echo " 5. 修改配置 (nano jail.local)"
        echo " 0. 返回"
        read -r -p "选: " c
        case $c in
            1) 
                if confirm_action "安装配置 Fail2ban (将自动修复日志依赖)"; then
                    $INSTALL fail2ban rsyslog
                    systemctl enable --now rsyslog
                    
                    # Detect SSH Port
                    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
                    [[ -z "$ssh_port" ]] && ssh_port=22
                    
                    # Write Config
                    cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
findtime = 10m
ignoreip = 127.0.0.1/8
EOF
                    touch /var/log/auth.log
                    systemctl restart fail2ban && systemctl enable fail2ban
                    
                    if systemctl is-active fail2ban &>/dev/null; then
                        log_success "Fail2ban 启动成功 (SSH Port: $ssh_port)"
                    else
                        log_error "启动失败，请检查日志 (选项4)"
                        # Attempt fallback for debian
                        service rsyslog restart
                        systemctl restart fail2ban
                    fi
                fi ;;
            2) fail2ban-client status sshd ;;
            3) 
                read -r -p "输入要解封的IP: " ip
                fail2ban-client set sshd unbanip "$ip" && log_success "已解封" ;;
            4) 
                if [[ -f /var/log/fail2ban.log ]]; then
                    tail -n 50 /var/log/fail2ban.log
                else
                    journalctl -u fail2ban -n 50 --no-pager
                fi ;;
            5) nano /etc/fail2ban/jail.local && systemctl restart fail2ban ;;
            0) return ;;
        esac
        read -r -p "按任意键继续..."
    done
}

menu_nodes() {
    while true; do
        print_title "节点部署"
        echo " 1. VLESS + Reality + Vision (推荐)"
        echo " 2. Hysteria2 (极速/UDP)"
        echo " 3. SS2022 + ShadowTLS (抗封锁)"
        echo " 4. Snell v4/v5 (Loon/Surge专用)"
        echo " 5. Legacy WS+TLS (CDN/兼容)"
        print_line
        echo " 8. 查看配置/状态"
        echo " 9. 卸载节点"
        echo " 0. 返回"
        read -r -p "选: " c
        case $c in
            1) deploy_vless_reality ;;
            2) deploy_hy2 ;;
            3) deploy_ss2022_stls ;;
            4) deploy_snell ;;
            5) deploy_ws_tls ;;
            8) list_status ;;
            9) uninstall_node ;;
            0) return ;;
        esac
    done
}

# ==================== BBR 管理 (Ref: bbr.sh) ====================

sys_optimize_tweaks() {
    print_title "系统参数调优"
    log_info "正在优化系统限制 (Limits) 和内核参数 (Sysctl)..."
    
    # optimize limits.conf
    if ! grep -q "soft nofile 65535" /etc/security/limits.conf; then
        echo "* soft nofile 65535" >> /etc/security/limits.conf
        echo "* hard nofile 65535" >> /etc/security/limits.conf
    fi
    if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
         echo "session required pam_limits.so" >> /etc/pam.d/common-session 2>/dev/null
    fi
    
    # optimize sysctl
    cat > /etc/sysctl.d/99-optimize.conf <<EOF
fs.file-max = 1000000
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 26214400
net.core.wmem_default = 26214400
net.core.somaxconn = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.ip_forward = 1
EOF
    sysctl --system
    log_success "系统优化完成 (文件句柄/TCP参数)"
    echo "建议重启以完全生效"
    read -r -p "按任意键返回..."
}

check_bbr_status() {
    local bbr_ver=$(modinfo tcp_bbr 2>/dev/null | grep "^version" | awk '{print $2}')
    local algo=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    local qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
    
    echo -e "内核模块版本: ${GREEN}${bbr_ver:-未知}${NC}"
    echo -e "当前拥塞控制: ${GREEN}${algo:-未知}${NC}"
    echo -e "当前队列管理: ${GREEN}${qdisc:-未知}${NC}"
}

install_bbr_kernel() {
    log_info "准备安装/更新 BBRv3 内核..."
    # A simplified version of bbr.sh kernel install logic could go here
    # For now, to keep it stable, we can pull the full script or use a simple heuristic
    # Let's use the one-liner recommended by the bbr.sh author or similar
    bash <(curl -L -s https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh)
}

menu_bbr() {
    while true; do
        print_title "BBR 加速管理"
        check_bbr_status
        print_line
        echo " 1. 安装/切换 BBR 内核 (调用外部脚本)"
        echo " 2. 启用 BBR + FQ (推荐)"
        echo " 3. 启用 BBR + CAKE"
        echo " 4. 启用 BBR + FQ_PIE"
        echo " 5. 系统调优 (Limits/Sysctl)"
        echo " 0. 返回"
        read -r -p "选: " c
        case $c in
            1) install_bbr_kernel ;;
            2) 
                if confirm_action "启用 BBR+FQ"; then
                   echo "net.core.default_qdisc=fq" > /etc/sysctl.d/99-bbr.conf
                   echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
                   sysctl --system
                   log_success "已应用 BBR+FQ"
                fi ;;
            3) 
                if confirm_action "启用 BBR+CAKE"; then
                   echo "net.core.default_qdisc=cake" > /etc/sysctl.d/99-bbr.conf
                   echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
                   sysctl --system
                   log_success "已应用 BBR+CAKE"
                fi ;;
            4) 
                if confirm_action "启用 BBR+FQ_PIE"; then
                   echo "net.core.default_qdisc=fq_pie" > /etc/sysctl.d/99-bbr.conf
                   echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
                   sysctl --system
                   log_success "已应用 BBR+FQ_PIE"
                fi ;;
            5) sys_optimize_tweaks ;; # We need to define this or remove
            0) return ;;
        esac
        read -r -p "按任意键继续..."
    done
}

menu_tools() {
    while true; do
        print_title "高级工具"
        echo " 1. 配置 GHCR/Docker 凭据助手"
        echo " 2. Fail2ban 安全管理 (防爆破)"
        echo " 3. 查看端口占用"
        echo " 4. BBR 加速管理"
        echo " 0. 返回"
        read -r -p "选: " c
        case $c in
            1) install_ghcr_creds ;;
            2) fail2ban_menu ;;
            3) 
                print_title "端口占用情况 (TCP/UDP)"
                if command -v column &>/dev/null; then
                    ss -tulpn | grep LISTEN | awk '{print $1, $5, $7}' | column -t
                else
                    ss -tulpn | grep LISTEN
                fi
                echo
                read -r -p "按任意键返回..." ;;
            4) menu_bbr ;;
            0) return ;;
        esac
    done
}

menu_script() {
    print_title "脚本管理"
    echo " 1. 更新脚本 (Update)"
    echo " 2. 卸载脚本 (Uninstall)"
    echo " 0. 返回"
    read -r -p "选: " c
    case $c in
        1) 
            if confirm_action "更新脚本至最新版"; then
                curl -sL "$GITHUB_RAW_URL" -o "$INSTALL_PATH"; chmod +x "$INSTALL_PATH"; exec "$INSTALL_PATH"
            fi ;;
        2) 
            if confirm_action "永久删除脚本"; then rm -f "$INSTALL_PATH"; exit 0; fi ;;
        0) return ;;
    esac
}

main_menu() {
    while true; do
        print_title "VPS ToolKit v${SCRIPT_VERSION}"
        echo -e "System: $OS $ARCH | IP: $(get_public_ip)"
        echo
        echo " 1. 🟢 系统初始化 (Init)"
        echo " 2. 🚀 节点部署 (Deploy)"
        echo " 3. 🔧 高级工具 (Tools)"
        echo " 4. 📜 脚本管理 (Update/Uninstall)"
        echo " 0. 退出"
        echo
        read -r -p "请选择: " c
        case $c in
            1) menu_system ;;
            2) menu_nodes ;;
            3) menu_tools ;;
            4) menu_script ;;
            0) exit 0 ;;
        esac
    done
}

detect_os
check_root
if [[ "$0" != "$INSTALL_PATH" && -f "$0" ]]; then
    cp "$0" "$INSTALL_PATH"; chmod +x "$INSTALL_PATH"
fi

main_menu
