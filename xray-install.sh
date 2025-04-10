#!/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "错误：此脚本必须以 root 用户身份运行。"
    exit 1
fi

# Set strict mode
set -euo pipefail

# --- Configuration ---
XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"

# --- Functions ---

# Function to print messages
log() {
    echo "[*] $1"
}

# Function to print error messages
error() {
    echo "[!] 错误: $1" >&2
    exit 1
}

# Function to install necessary packages
install_deps() {
    log "正在更新软件包列表并安装依赖项 (curl, jq, openssl)..."
    apt-get update -y
    apt-get install -y curl jq openssl || error "无法安装依赖项。"
}

# Function to configure system for IPv4 priority
configure_ipv4_priority() {
    log "正在配置系统以优先使用 IPv4..."
    GAI_CONF="/etc/gai.conf"
    IPV4_PRECEDENCE="precedence ::ffff:0:0/96  100"
    # Check if the file exists, create if not
    if [ ! -f "$GAI_CONF" ]; then
        touch "$GAI_CONF"
        log "已创建 $GAI_CONF 文件。"
    fi
    # Check if the line already exists and is uncommented
    if ! grep -q "^\s*${IPV4_PRECEDENCE}" "$GAI_CONF"; then
        # If the line exists but is commented, uncomment it
        if grep -q "^\s*#\s*${IPV4_PRECEDENCE}" "$GAI_CONF"; then
            sed -i "s|^\s*#\s*${IPV4_PRECEDENCE}|${IPV4_PRECEDENCE}|" "$GAI_CONF"
            log "$GAI_CONF 中已取消注释 IPv4 优先规则。"
        else
            # If the line doesn't exist, add it
            echo "$IPV4_PRECEDENCE" >> "$GAI_CONF"
            log "已将 IPv4 优先规则添加到 $GAI_CONF。"
        fi
    else
        log "$GAI_CONF 中已存在 IPv4 优先规则。"
    fi
}


# Function to enable BBR
enable_bbr() {
    log "正在启用 BBR 拥塞控制..."
    SYSCTL_CONF="/etc/sysctl.conf"
    # Remove existing lines if they exist to avoid duplicates
    sed -i '/net.core.default_qdisc=fq/d' "$SYSCTL_CONF"
    sed -i '/net.ipv4.tcp_congestion_control=bbr/d' "$SYSCTL_CONF"
    # Add the new lines
    echo "net.core.default_qdisc=fq" >> "$SYSCTL_CONF"
    echo "net.ipv4.tcp_congestion_control=bbr" >> "$SYSCTL_CONF"
    # Apply changes
    if sysctl -p > /dev/null 2>&1; then
        log "sysctl 配置已应用。"
    else
       log "警告: sysctl -p 执行时有输出，可能存在非致命错误，请检查。"
    fi

    log "BBR 已启用 (配置已写入 sysctl.conf)。"
    # Verify BBR is running
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log "BBR 启用状态验证成功。"
    else
        log "警告：BBR 可能未成功启用。请检查 'sysctl net.ipv4.tcp_congestion_control' 的输出。"
    fi
     if lsmod | grep -q "bbr"; then
        log "BBR 内核模块已加载。"
    else
        log "警告：BBR 内核模块似乎未加载 (lsmod | grep bbr 未找到)。系统可能需要重启才能完全生效，或者内核不支持 BBR。"
    fi
}

# Function to install Xray
install_xray() {
    log "正在安装 Xray-core..."
    # Use bash -c to ensure the environment is clean and standard
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version 1.8.10 || error "Xray 安装失败。"
    # Check if xray binary exists and is executable
    if ! command -v xray &> /dev/null || ! [ -x "$(command -v xray)" ]; then
        error "xray 命令未找到或不可执行，安装可能未成功。"
    fi
     # Ensure the config directory exists
    mkdir -p /usr/local/etc/xray
    log "Xray 安装成功。"
}

# Function to generate random port
generate_port() {
    # Generate random number between 10000 and 65535
    echo $((RANDOM % (65535 - 10000 + 1) + 10000))
}

# Function to generate UUID
generate_uuid() {
    xray uuid
}

# Function to generate X25519 key pair
generate_keys() {
    xray x25519
}

# Function to generate short ID
generate_short_id() {
    openssl rand -hex 8 # Generate an 8-byte hex string (16 hex chars)
}

# --- Main Execution ---

install_deps
configure_ipv4_priority
enable_bbr
install_xray

# Generate configuration parameters
log "正在生成配置参数..."
PORT=$(generate_port)
UUID=$(generate_uuid)
KEYS_OUTPUT=$(generate_keys)
# Extract private and public keys carefully
PRIVATE_KEY=$(echo "$KEYS_OUTPUT" | grep 'Private key:' | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYS_OUTPUT" | grep 'Public key:' | awk '{print $3}')
SHORT_ID=$(generate_short_id)

# Basic validation of generated keys
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    error "生成密钥对失败。"
fi


log "生成的参数:"
log "  端口 (Port): $PORT"
log "  用户 ID (UUID): $UUID"
log "  私钥 (Private Key): $PRIVATE_KEY"
log "  公钥 (Public Key): $PUBLIC_KEY"
log "  短 ID (Short ID): $SHORT_ID"

# Get user input
log "请输入 Reality 配置所需的信息:"
read -p "  请输入 dest (格式: 域名或IP:端口, 例如 1.1.1.1:443 或 www.bing.com:443): " DEST_INPUT
read -p "  请输入 serverNames (证书的 SAN 域名, 多个用逗号分隔, 例如 example.com 或 www.bing.com,bing.com): " SERVER_NAMES_INPUT

# Validate input (basic check)
if [[ -z "$DEST_INPUT" || -z "$SERVER_NAMES_INPUT" ]]; then
    error "dest 和 serverNames 不能为空。"
fi
# More robust dest validation: check for host and port separated by colon
if ! [[ "$DEST_INPUT" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    error "dest 格式不正确，应为 HOST:PORT，例如 www.bing.com:443。"
fi
DEST_HOST=$(echo "$DEST_INPUT" | cut -d':' -f1)
DEST_PORT=$(echo "$DEST_INPUT" | cut -d':' -f2)
if (( DEST_PORT < 1 || DEST_PORT > 65535 )); then
    error "dest 中的端口号无效。"
fi


# Format serverNames for JSON array using jq
# -R reads raw string, split splits by comma, map processes each element
# select removes empty strings, gsub removes leading/trailing whitespace
SERVER_NAMES_JSON=$(echo "$SERVER_NAMES_INPUT" | jq -R 'split(",") | map(select(length > 0) | gsub("^\\s+|\\s+$"; ""))')
# Check if the resulting JSON array is empty or just "[]"
if [[ -z "$SERVER_NAMES_JSON" || "$SERVER_NAMES_JSON" == "[]" ]]; then
    error "处理后的 serverNames 为空或无效。请确保输入正确的域名，用逗号分隔。"
fi
log "格式化的 serverNames (JSON): $SERVER_NAMES_JSON"

log "正在创建 Xray 配置文件: $XRAY_CONFIG_FILE ..."

# Create JSON configuration using jq
# Use --argjson for numbers/booleans/json, --arg for strings
jq -n \
  --argjson port "$PORT" \
  --arg uuid "$UUID" \
  --arg private_key "$PRIVATE_KEY" \
  --argjson short_ids "[\"$SHORT_ID\"]" \
  --arg dest "$DEST_INPUT" \
  --argjson server_names "$SERVER_NAMES_JSON" \
'{
    "log": {
        "level": "info", # Changed loglevel to level for newer Xray versions consistency
        "access": "/var/log/xray/access.log", # Optional: Add access log
        "error": "/var/log/xray/error.log"   # Optional: Add error log
    },
    "dns": {
        "servers": [
            "https+local://1.1.1.1/dns-query", # Cloudflare DNS over HTTPS
            "localhost" # Use system DNS as fallback
        ],
        "queryStrategy": "UseIPv4" # Prioritize IPv4 for DNS queries
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch", # Use IP for routing decisions if no domain match
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private", # Block private IPs
                    "geoip:cn" # Block IPs geolocated in China
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all", # Block ad domains
                    "geosite:cn" # Block domains geolocated in China
                ],
                "outboundTag": "block"
            }
            # Add more rules if needed
        ]
    },
    "inbounds": [
        {
            "listen": "0.0.0.0", # Listen on all available interfaces
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": $uuid,
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false, # Recommended to set show to false
                    "dest": $dest,
                    "xver": 0, # Use 0 for broad compatibility, unless specific needs dictate otherwise
                    "serverNames": $server_names,
                    "privateKey": $private_key,
                    "shortIds": $short_ids
                    # "publicKey": "...", # Public key is derived from private key, not needed here
                    # "minClientVer": "", # Optional
                    # "maxClientVer": "", # Optional
                    # "maxTimeDiff": 60000, # Optional
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [ "http", "tls", "quic" ],
                "routeOnly": false # Let sniffing determine the outbound for matched domains/IPs
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct", # Primary outbound, respects system preference (IPv4 priority set via gai.conf)
             "settings": {
                 # Default freedom settings are usually fine
             }
        },
        # Removed direct-ipv4 as gai.conf handles preference and queryStrategy=UseIPv4 in DNS
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {}
        }
    ],
     "policy": { # Add basic policy for connection reuse etc.
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 1,
                "downlinkOnly": 1
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    }
}' > "$XRAY_CONFIG_FILE" || error "无法写入 Xray 配置文件。"

# Create log directory if logs are enabled in config
if jq -e '.log.access' "$XRAY_CONFIG_FILE" > /dev/null || jq -e '.log.error' "$XRAY_CONFIG_FILE" > /dev/null; then
    log "创建 Xray 日志目录 /var/log/xray..."
    mkdir -p /var/log/xray
    chown nobody:nogroup /var/log/xray || chown nobody:nobody /var/log/xray # Try common user/group for xray
fi

log "Xray 配置文件创建成功。"

# Restart and enable Xray service
log "正在重新启动并启用 Xray 服务..."
systemctl restart xray || { log "首次启动失败，尝试再次启动..."; sleep 2; systemctl restart xray || error "无法启动 Xray 服务。请检查配置和日志。"; }
systemctl enable xray || error "无法启用 Xray 服务。"

# Check Xray service status
if systemctl is-active --quiet xray; then
    log "Xray 服务已成功启动并设置为开机自启。"
else
    # Provide more detailed error info if possible
    log "错误：Xray 服务未能成功启动。"
    log "请检查配置文件: $XRAY_CONFIG_FILE"
    log "请检查服务状态: systemctl status xray"
    log "请检查服务日志: journalctl -u xray --no-pager -l"
    # Try validating the config file
    log "尝试验证配置文件语法..."
    if xray run -test -config "$XRAY_CONFIG_FILE"; then
        log "配置文件语法验证通过，问题可能在其他方面（如端口冲突、权限）。"
    else
        log "配置文件语法验证失败，请根据上面的错误信息修改配置。"
    fi
    exit 1 # Exit script if service failed to start
fi

# --- Display Connection Info ---
# Try to get public IP (might fail in some environments)
SERVER_IP=$(curl -s -m 5 -4 https://ifconfig.co || curl -s -m 5 -4 https://api.ipify.org || hostname -I | awk '{print $1}')
if [[ -z "$SERVER_IP" ]]; then
    log "警告：无法自动获取公网 IPv4 地址。请手动替换下面的 SERVER_IP。"
    SERVER_IP="YOUR_SERVER_IP" # Placeholder
fi

FIRST_SERVER_NAME=$(echo "$SERVER_NAMES_INPUT" | cut -d ',' -f 1 | xargs) # Get the first serverName for SNI

log "=================================================="
log " Xray 安装和配置完成！"
log "=================================================="
log " 服务器 IP/域名 (用于连接): $SERVER_IP (如果使用域名，请用域名替换此IP)"
log " 端口 (Port): $PORT"
log " 用户 ID (UUID): $UUID"
log " 流控 (Flow): xtls-rprx-vision"
log " 加密 (Encryption): none"
log " 传输协议 (Network): tcp"
log " 伪装类型 (Type): none"
log " 安全类型 (Security): reality"
log " SNI (Server Name Indication / serverName): $FIRST_SERVER_NAME"
log " 公钥 (PublicKey / pbk): $PUBLIC_KEY"
log " 短 ID (Short ID / sid): $SHORT_ID"
log " 指纹 (Fingerprint / fp): chrome (或其他兼容指纹)"
log " 目标地址 (Dest - 服务器配置): $DEST_INPUT"
log "---"
log " VLESS REALITY 链接 (请将 ${SERVER_IP} 替换为你的实际服务器IP或域名):"
log " vless://${UUID}@${SERVER_IP}:${PORT}?security=reality&encryption=none&pbk=${PUBLIC_KEY}&host=${FIRST_SERVER_NAME}&fp=chrome&flow=xtls-rprx-vision&type=tcp&sni=${FIRST_SERVER_NAME}&sid=${SHORT_ID}#Xray_REALITY_${SERVER_IP}"
log "---"
log " Clash (Meta core) 配置片段 (请将 'server:' 字段替换为你的实际服务器IP或域名):"
log " proxies:"
log "   - name: Xray_REALITY_${SERVER_IP}" # You can rename this proxy
log "     server: ${SERVER_IP}"
log "     port: ${PORT}"
log "     type: vless"
log "     uuid: ${UUID}"
log "     tls: true" # REALITY requires TLS layer
log "     udp: true" # Enable UDP relay for VLESS
log "     tfo: false" # TCP Fast Open, default false
log "     servername: ${FIRST_SERVER_NAME}" # SNI, must match one of serverNames in server config
log "     flow: xtls-rprx-vision"
log "     client-fingerprint: chrome" # Fingerprint for TLS handshake (ensure client supports it)
log "     reality-opts:"
log "       public-key: ${PUBLIC_KEY}" # REALITY public key
log "       short-id: ${SHORT_ID}" # REALITY short ID
# log "       # spider-x: ${DEST_INPUT}" # Optional: Specify dest in Clash, format: domain:port. Usually not needed if server configured correctly.
log "     skip-cert-verify: true # Must be true for REALITY"
log "---"
log " 配置文件路径: $XRAY_CONFIG_FILE"
log " 日志文件路径: /var/log/xray/ (如果已启用)"
log " 您可以使用 'systemctl status xray' 查看服务状态。"
log " 您可以使用 'journalctl -u xray' 查看服务日志。"
log " 如果遇到问题，请检查防火墙是否允许端口 $PORT (TCP)。"
log "=================================================="

exit 0