#!/bin/bash
set -e


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

gen_cred() {
    local len=$(( RANDOM % 5 + 8 ))
    local U='ABCDEFGHJKLMNPQRSTUVWXYZ'
    local L='abcdefghijkmnpqrstuvwxyz'
    local D='23456789'
    local S='!@%^*_-=+.'
    local A="${U}${L}${D}${S}"
    local s="${U:RANDOM%${#U}:1}${L:RANDOM%${#L}:1}${D:RANDOM%${#D}:1}${S:RANDOM%${#S}:1}"
    local i
    for (( i=${#s}; i<len; i++ )); do
        s+="${A:RANDOM%${#A}:1}"
    done
    printf '%s' "$s" | fold -w1 | shuf | tr -d '\n'
}

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Xray Viewer + Hysteria2 Deploy${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: Must run as root${NC}"
    exit 1
fi

UNIT_DIR=/etc/systemd/system
DEST=/opt/xray-viewer
FRESH=1
[ -f "$DEST/app.py" ] && FRESH=0
if [ "$FRESH" -eq 0 ]; then
    echo -e "${YELLOW}[*] Existing installation detected - updating (data preserved)${NC}"
fi

PANEL_PORT=""
if [ -f "$UNIT_DIR/xray-viewer.service" ]; then
    PANEL_PORT=$(grep -oE -- '-b 0\.0\.0\.0:[0-9]+' "$UNIT_DIR/xray-viewer.service" | grep -oE '[0-9]+$' | head -n1)
fi
if [ -z "$PANEL_PORT" ]; then
    PANEL_PORT=$((RANDOM % 55000 + 10000))
    echo -e "${YELLOW}[*] Random panel port: ${PANEL_PORT}${NC}"
else
    echo -e "${YELLOW}[*] Existing panel port: ${PANEL_PORT}${NC}"
fi

if [ -f "$DEST/url_prefix" ]; then
    PANEL_PATH=$(cat "$DEST/url_prefix")
    echo -e "${YELLOW}[*] Existing panel path: ${PANEL_PATH}${NC}"
else
    PANEL_PATH="/$(openssl rand -hex 5)"
    echo -e "${YELLOW}[*] Random panel path: ${PANEL_PATH}${NC}"
fi

echo -e "${YELLOW}[*] Installing dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-pip curl unzip ufw openssl >/dev/null 2>&1
pip3 install flask gunicorn --break-system-packages >/dev/null 2>&1 || pip3 install flask gunicorn >/dev/null 2>&1

echo -e "${YELLOW}[*] Installing Xray...${NC}"
if [ ! -x "/usr/local/bin/xray" ]; then
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) >/dev/null 2>&1
fi
XRAY_BIN="/usr/local/bin/xray"

if [ ! -f /usr/local/etc/xray/config.json ]; then
KEYS=$($XRAY_BIN x25519)
REALITY_PRIVATE_KEY=$(echo "$KEYS" | grep -ioE "PrivateKey:[[:space:]]*[A-Za-z0-9+/_-]+" | awk '{print $2}')
if [ -z "$REALITY_PRIVATE_KEY" ]; then
    REALITY_PRIVATE_KEY=$(echo "$KEYS" | grep -iE "Private" | awk '{print $NF}')
fi
REALITY_PUBLIC_KEY=$(echo "$KEYS" | grep -ioE "\(PublicKey\)[[:space:]]*[A-Za-z0-9+/_-]+" | awk '{print $2}')
if [ -z "$REALITY_PUBLIC_KEY" ]; then
    REALITY_PUBLIC_KEY=$(echo "$KEYS" | grep -iE "Public" | awk '{print $NF}')
fi
UUID_ADMIN=$($XRAY_BIN uuid)
SHORT_ID=$(openssl rand -hex 8)
echo -e "${GREEN}[*] Reality keys generated.${NC}"
fi

if [ "$FRESH" -eq 0 ]; then
    eval "$(python3 - <<'PYEOF'
import re, ast, shlex
s = open('/opt/xray-viewer/app.py', encoding='utf-8').read()
u = ast.literal_eval(re.search(r'^USERNAME = (.*)$', s, re.M).group(1))
p = ast.literal_eval(re.search(r'^PASSWORD = (.*)$', s, re.M).group(1))
print('PANEL_USER=%s' % shlex.quote(u))
print('PANEL_PASS=%s' % shlex.quote(p))
PYEOF
)"
    echo -e "${YELLOW}[*] Preserving existing panel credentials${NC}"
else
    PANEL_USER=$(gen_cred)
    PANEL_PASS=$(gen_cred)
fi

if [ ! -x /usr/local/bin/hysteria ]; then
echo -e "${YELLOW}[*] Installing Hysteria2...${NC}"
HYSTERIA_VER=$(curl -sL https://api.github.com/repos/HyNetworks/hysteria/releases/latest | grep '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')
if [ -z "$HYSTERIA_VER" ]; then
    HYSTERIA_VER="app/v2.12.2"
fi
HYSTERIA_ARCH=$(uname -m)
case "$HYSTERIA_ARCH" in
    x86_64)  HY_ARCH="amd64" ;;
    aarch64) HY_ARCH="arm64" ;;
    armv7l)  HY_ARCH="armv7" ;;
    *)       echo -e "${RED}Unsupported arch: $HYSTERIA_ARCH${NC}"; exit 1 ;;
esac
HY_URL="https://github.com/HyNetworks/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${HY_ARCH}"
for attempt in 1 2 3; do
    curl -sL --retry 3 --retry-delay 2 "$HY_URL" -o /usr/local/bin/hysteria || true
    if [ -s /usr/local/bin/hysteria ] && head -c4 /usr/local/bin/hysteria | grep -q $'\x7fELF'; then
        break
    fi
    echo -e "${YELLOW}[*] hysteria download attempt ${attempt} failed, retrying...${NC}"
    sleep 2
done
chmod +x /usr/local/bin/hysteria
fi

getent group hysteria >/dev/null 2>&1 || groupadd -r hysteria
id hysteria >/dev/null 2>&1 || useradd -r -g hysteria -s /bin/false hysteria

mkdir -p /etc/hysteria
if [ ! -f /etc/hysteria/server.crt ]; then
    echo -e "${YELLOW}[*] Generating Hysteria2 self-signed certificate...${NC}"
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout /etc/hysteria/server.key \
        -out /etc/hysteria/server.crt \
        -subj "/CN=www.amazon.com" -days 36500 >/dev/null 2>&1
fi

HY2_STATS_PORT=9999
HY2_STATS_SECRET=$(openssl rand -hex 16)

mkdir -p /opt/xray-viewer
mkdir -p /usr/local/etc/xray
mkdir -p /etc/hysteria/conf.d

if [ ! -f /usr/local/etc/xray/config.json ]; then
echo -e "${YELLOW}[*] Generating Xray config...${NC}"
cat > /usr/local/etc/xray/config.json << XRAYEOF
{
  "log": { "loglevel": "warning", "access": "/dev/null" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_ADMIN}",
            "flow": "xtls-rprx-vision",
            "email": "admin"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.amazon.com:443",
          "xver": 0,
          "serverNames": ["www.amazon.com"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    },
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" },
    { "protocol": "freedom", "tag": "api" }
  ],
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true }
  },
  "api": { "tag": "api", "services": ["StatsService"] },
  "routing": { "rules": [{ "type": "field", "inboundTag": ["api"], "outboundTag": "api" }] }
}
XRAYEOF
fi

if [ ! -f /usr/local/etc/xray/hy2_nodes.json ]; then
echo -e "${YELLOW}[*] Generating hy2_nodes.json (v3)...${NC}"
cat > /usr/local/etc/xray/hy2_nodes.json << HYNODEEOF
[
  {
    "id": "hy2-443",
    "name": "",
    "port": 443,
    "protocol": "Hysteria2",
    "network": "UDP",
    "sni": "www.amazon.com",
    "dest": "www.amazon.com:443",
    "auth": "信任自签证书",
    "enabled": true,
    "cert": "/etc/hysteria/server.crt",
    "key": "/etc/hysteria/server.key",
    "masquerade": "https://www.amazon.com",
    "stats": {
      "listen": "127.0.0.1:${HY2_STATS_PORT}",
      "secret": "${HY2_STATS_SECRET}"
    },
    "users": [
      {
        "name": "admin",
        "password": "${UUID_ADMIN}"
      }
    ]
  }
]
HYNODEEOF
fi

if [ ! -f /usr/local/etc/xray/users.json ]; then
echo -e "${YELLOW}[*] Generating users.json (unified user model)...${NC}"
cat > /usr/local/etc/xray/users.json << USERSEOF
{
  "users": [
    {
      "name": "admin",
      "uuid": "${UUID_ADMIN}",
      "flow": "xtls-rprx-vision",
      "password": "${UUID_ADMIN}",
      "hy2_name": "admin",
      "disabled": false,
      "bindings": [
        { "proto": "vless", "node": 443 },
        { "proto": "hy2", "node": "hy2-443" }
      ]
    }
  ]
}
USERSEOF
fi

if [ ! -f /etc/hysteria/conf.d/hy2-443.yaml ]; then
echo -e "${YELLOW}[*] Generating Hysteria2 node config...${NC}"
cat > /etc/hysteria/conf.d/hy2-443.yaml << HYEOF
listen: :443

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: userpass
  userpass:
    admin: ${UUID_ADMIN}

masquerade:
  type: proxy
  proxy:
    url: https://www.amazon.com
    rewriteHost: true

trafficStats:
  listen: 127.0.0.1:${HY2_STATS_PORT}
  secret: ${HY2_STATS_SECRET}
HYEOF
fi

chown -R hysteria:hysteria /etc/hysteria

[ -f /usr/local/etc/xray/disabled_clients.json ] || echo "[]" > /usr/local/etc/xray/disabled_clients.json
[ -f /usr/local/etc/xray/disabled_inbounds.json ] || echo "[]" > /usr/local/etc/xray/disabled_inbounds.json
[ -f /usr/local/etc/xray/traffic_totals.json ] || echo "{}" > /usr/local/etc/xray/traffic_totals.json
[ -f /usr/local/etc/xray/fwd.json ] || echo "[]" > /usr/local/etc/xray/fwd.json

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/app.py" /opt/xray-viewer/app.py
PANEL_USER="$PANEL_USER" PANEL_PASS="$PANEL_PASS" python3 - <<'PYEOF'
import os, re
p = "/opt/xray-viewer/app.py"
s = open(p, encoding="utf-8").read()
u = os.environ["PANEL_USER"]; pw = os.environ["PANEL_PASS"]
s = re.sub(r'^USERNAME = .*$', 'USERNAME = %r' % u, s, count=1, flags=re.M)
s = re.sub(r'^PASSWORD = .*$', 'PASSWORD = %r' % pw, s, count=1, flags=re.M)
assert ("USERNAME = %r" % u) in s, "USERNAME inject failed"
assert ("PASSWORD = %r" % pw) in s, "PASSWORD inject failed"
open(p, "w", encoding="utf-8").write(s)
print("[*] Panel credentials injected")
PYEOF
cp "$SCRIPT_DIR/traffic_store.py" /opt/xray-viewer/traffic_store.py
echo "${PANEL_PATH}" > /opt/xray-viewer/url_prefix
chmod 644 /opt/xray-viewer/url_prefix

echo -e "${YELLOW}[*] Configuring systemd services...${NC}"

cat > /etc/systemd/system/xray.service << 'XSVCEOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
StartLimitIntervalSec=0

[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment=GOGC=50
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755
ProtectSystem=strict
ReadOnlyPaths=/usr/local/etc/xray
ReadWritePaths=/var/log/xray
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077
SystemCallArchitectures=native
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
XSVCEOF

cat > /etc/systemd/system/xray-viewer.service << XVSVCEOF
[Unit]
Description=Xray Config Viewer
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=/opt/xray-viewer
Environment=MALLOC_ARENA_MAX=2
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/local/bin/gunicorn --chdir /opt/xray-viewer -w 1 --threads 2 --timeout 60 --keep-alive 30 -b 0.0.0.0:${PANEL_PORT} app:app
Restart=always
RestartSec=3
User=root
CPUWeight=50
IOWeight=50
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077
SystemCallArchitectures=native
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
XVSVCEOF

cat > /etc/systemd/system/hysteria-node@.service << 'HSVCEOF'
[Unit]
Description=Hysteria2 Server Node (%i)
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/conf.d/%i.yaml
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=warn
Environment=GOGC=50
Restart=on-failure
RestartSec=2
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/etc/hysteria
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
UMask=0077
SystemCallArchitectures=native
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
HSVCEOF

if systemctl list-unit-files hysteria-server.service >/dev/null 2>&1 && \
   [ -f /etc/systemd/system/hysteria-server.service ]; then
    echo -e "${YELLOW}[*] Legacy hysteria-server.service found, migrating...${NC}"
    systemctl disable --now hysteria-server >/dev/null 2>&1 || true
    mv /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server.service.disabled.bak 2>/dev/null || true
    systemctl daemon-reload || true
fi

echo -e "${YELLOW}[*] Configuring firewall...${NC}"
if [ "$FRESH" -eq 1 ]; then
    ufw --force reset >/dev/null 2>&1
fi
ufw allow 22/tcp >/dev/null 2>&1
ufw allow 443/tcp >/dev/null 2>&1
ufw allow 443/udp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

echo -e "${YELLOW}[*] Starting services...${NC}"
systemctl daemon-reload
systemctl enable --now hysteria-node@hy2-443 >/dev/null 2>&1 || true
systemctl enable --now xray >/dev/null 2>&1 || true
systemctl enable --now xray-viewer >/dev/null 2>&1 || true

for i in 1 2 3 4 5 6 7 8; do
    if systemctl is-active --quiet xray && systemctl is-active --quiet xray-viewer && systemctl is-active --quiet hysteria-node@hy2-443; then break; fi
    sleep 1
done

SERVER_IP=""
for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
  SERVER_IP=$(curl -4 -sL --max-time 8 "$url" 2>/dev/null | tr -d '[:space:]')
  if [ -n "$SERVER_IP" ] && [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    break
  fi
  SERVER_IP=""
done
[ -z "$SERVER_IP" ] && SERVER_IP="YOUR_SERVER_IP"
echo "${SERVER_IP}" > /opt/xray-viewer/server_ip
chmod 644 /opt/xray-viewer/server_ip

apt-get clean >/dev/null 2>&1 || true
apt-get autoremove -y >/dev/null 2>&1 || true

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/limits.conf << 'JDEOF'
[Journal]
SystemMaxUse=100M
RuntimeMaxUse=20M
JDEOF
journalctl --vacuum-size=100M >/dev/null 2>&1 || true
systemctl restart systemd-journald >/dev/null 2>&1 || true
systemctl disable --now tuned >/dev/null 2>&1 || true

echo ""
echo -e "${GREEN}========================================${NC}"
if [ "$FRESH" -eq 1 ]; then echo -e "${GREEN}  Deploy Complete!${NC}"; else echo -e "${GREEN}  Update Complete!${NC}"; fi
echo -e "${GREEN}========================================${NC}"
echo ""

XRAY_STATUS=$(systemctl is-active xray || true)
VIEWER_STATUS=$(systemctl is-active xray-viewer || true)
HYSTERIA_STATUS=$(systemctl is-active hysteria-node@hy2-443 || true)

echo -e "  Xray:             ${XRAY_STATUS}"
echo -e "  Xray Viewer:      ${VIEWER_STATUS}"
echo -e "  Hysteria2 (443):  ${HYSTERIA_STATUS}"
echo ""

if [ "$FRESH" -eq 1 ]; then
echo -e "${GREEN}--- Xray VLESS+Reality 节点 (443) ---${NC}"
echo -e "  Server:     ${SERVER_IP}"
echo -e "  Port:       443"
echo -e "  Network:    tcp / TLS: reality / SNI: www.amazon.com / ShortID: ${SHORT_ID}"
echo -e "  PublicKey:  ${REALITY_PUBLIC_KEY}"
echo ""
echo -e "  [admin]  (vless + hy2 双协议，vless uuid == hy2 密码)"
echo -e "    UUID:   ${UUID_ADMIN}"
echo -e "    Link:   ${YELLOW}vless://${UUID_ADMIN}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&network=tcp&security=reality&sni=www.amazon.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${SHORT_ID}#admin_vless${NC}"
echo -e "    hy2 密码(uuid): ${UUID_ADMIN}"
echo ""

echo -e "${GREEN}--- Hysteria2 节点 (443) ---${NC}"
echo -e "  Server:     ${SERVER_IP} / Port: 443 (UDP) / SNI: www.amazon.com (客户端信任自签证书)"
echo -e "  [admin]  用户名: admin  密码: ${UUID_ADMIN}"
echo ""
else
echo -e "${GREEN}--- 节点配置 ---${NC}"
echo -e "  已保留原有节点/用户配置（UUID、密钥、节点端口均未改动）"
echo ""
fi

echo -e "${GREEN}--- Web Panel (v1.10) ---${NC}"
echo -e "  URL:        http://${SERVER_IP}:${PANEL_PORT}${PANEL_PATH}/login"
echo -e "  Username:   ${PANEL_USER}"
echo -e "  Password:   ${PANEL_PASS}"
echo -e "  Panel Port: ${PANEL_PORT}"
echo -e "  Panel Path: ${PANEL_PATH}"
echo -e "  ${YELLOW}安全提示：面板端口 ${PANEL_PORT} 默认对 Anywhere 开放，请尽快在面板『防火墙』卡片中放行你的固定 IP 并删除 Anywhere 规则。${NC}"
echo -e "  面板功能：系统状态 / vless 节点 / hy2 节点 / 中转 / 用户管理 / 流量统计"
echo ""

echo -e "${YELLOW}  [!] Run these to allow panel access:${NC}"
echo -e "  ufw allow from YOUR_IP to any port ${PANEL_PORT} proto tcp"
echo -e "  ufw reload"
echo ""
