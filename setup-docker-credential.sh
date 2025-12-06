#!/bin/bash

# ==============================================================================
# Docker Credential Helper (pass) 一键安装脚本
#
# 功能:
# 1. 安装 pass 和 GnuPG.
# 2. 自动生成一个无密码的 GPG 密钥用于非交互式环境.
# 3. 自动从 GitHub 下载最新版的 docker-credential-pass.
# 4. 配置 Docker 使用 pass 作为凭据存储.
#
# 使用: curl -sSL <RAW_GIST_URL> | sudo bash
# ==============================================================================

# 设置脚本在出错时立即退出
set -e

# 定义颜色输出，方便阅读
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- 检查运行环境 ---
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}错误: 此脚本需要以 root 权限运行。请使用 'sudo'。${NC}"
  exit 1
fi

echo -e "${GREEN}--- 步骤 1: 安装依赖 (pass, gnupg2, jq) ---${NC}"
apt-get update > /dev/null
apt-get install -y pass gnupg2 jq > /dev/null
echo "依赖安装完成。"

# --- 步骤 2: 自动生成 GPG 密钥 (无密码) ---
echo -e "\n${GREEN}--- 步骤 2: 生成 GPG 密钥 ---${NC}"
# 安全警告：为了实现完全自动化，这里创建了一个没有密码保护的 GPG 密钥。
# 这仍然远比将 Docker 凭据以纯文本存储要安全。
# 密钥文件本身受到 root 用户权限的保护。
echo -e "${YELLOW}警告: 正在生成一个无密码的 GPG 密钥以实现自动化。${NC}"
cat >/tmp/gpg-batch-config <<EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Docker Credential Helper Key
Name-Email: docker-helper@$(hostname)
Expire-Date: 0
EOF

gpg --batch --gen-key /tmp/gpg-batch-config > /dev/null 2>&1
rm /tmp/gpg-batch-config
echo "GPG 密钥已生成。"

# --- 步骤 3: 初始化 pass ---
echo -e "\n${GREEN}--- 步骤 3: 初始化 pass 凭据存储 ---${NC}"
# 获取刚刚生成的 GPG 密钥 ID
GPG_KEY_ID=$(gpg --list-secret-keys --with-colons | grep '^sec' | cut -d: -f5)

if [ -z "$GPG_KEY_ID" ]; then
  echo -e "${RED}错误: 未能找到生成的 GPG 密钥 ID。${NC}"
  exit 1
fi

pass init "$GPG_KEY_ID" > /dev/null
echo "pass 初始化完成。"

# --- 步骤 4: 安装 docker-credential-pass ---
echo -e "\n${GREEN}--- 步骤 4: 下载并安装最新的 docker-credential-pass ---${NC}"
# 自动从 GitHub API 获取最新版本
LATEST_URL=$(curl -s https://api.github.com/repos/docker/docker-credential-helpers/releases/latest | jq -r '.assets[] | select(.name | contains("linux-amd64")) | select(.name | contains("pass")) | .browser_download_url')

if [ -z "$LATEST_URL" ] || [ "$LATEST_URL" == "null" ]; then
    echo -e "${RED}错误: 无法从 GitHub API 获取最新的 docker-credential-pass 下载链接。${NC}"
    exit 1
fi

echo "正在下载: $LATEST_URL"
curl -sL "$LATEST_URL" -o /usr/local/bin/docker-credential-pass
chmod +x /usr/local/bin/docker-credential-pass
echo "docker-credential-pass 安装完成。"

# --- 步骤 5: 配置 Docker ---
echo -e "\n${GREEN}--- 步骤 5: 配置 Docker 使用 pass 作为凭据存储 ---${NC}"
CONFIG_FILE="$HOME/.docker/config.json"
mkdir -p "$(dirname "$CONFIG_FILE")"
# 如果文件不存在则创建，如果存在则使用 jq 更新
touch "$CONFIG_FILE"
# 使用 jq 安全地更新 JSON 文件
jq '.credsStore = "pass"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
echo "Docker 配置已更新。"

# --- 完成 ---
echo -e "\n${GREEN}🎉 全部设置完成！${NC}"
echo -e "现在，当你运行 'docker login' 时，凭据将被安全地加密存储。"
echo -e "如果你之前已经登录过，请先运行 'docker logout ghcr.io'，然后重新登录以使新配置生效。"
