#!/bin/bash
# Hive main-panel deployer (fresh install or in-place update).
# Installs Xray (VLESS/REALITY) + Hysteria2 + the web panel: generates the
# config, a self-signed TLS cert, hashed panel credentials and the systemd
# units. Re-running preserves existing data, port, path and credentials.
# See README.md.
set -e


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Official Hysteria2 (github.com/apernet/hysteria) pinned release + SHA256 of the Linux binaries.
HYSTERIA_VER="app/v2.13.0"
HY_SHA_AMD64="907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
HY_SHA_ARM64="a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"
HY_SHA_ARM="c75aa753fbe1a5263c266244285326ac7fe83617543cea00de2fc4bb79f89db6"

gen_cred() {
    local n="${1:-20}" s=""
    while [ "${#s}" -lt "$n" ]; do
        s="$s$(openssl rand -base64 48 | LC_ALL=C tr -dc 'A-Za-z0-9!@%^*_=+.-')"
    done
    printf '%s' "${s:0:$n}"
}

gen_port() {
    local lo="${1:-10000}" hi="${2:-65000}" r
    r=$(( 0x$(openssl rand -hex 4) ))
    echo $(( lo + r % (hi - lo + 1) ))
}

# Masquerade / REALITY target: pick a random popular site per install so every
# deployment doesn't share the same fingerprint. Override with HIVE_MASQ=example.com
#
# Pool rules (v1.0.5, 50 entries) - every entry below was verified to answer
# TLS 1.3 with ALPN h2 on :443, belongs to a large and long-lived global brand,
# and is NOT filtered from mainland China (a blocked SNI would make the node
# unusable, since the client sends it in the clear).
# Deliberately excluded: Google- and Apple-owned domains (Xray itself warns that
# their shared REALITY fingerprint gets blocked faster), and domains that are
# blocked in CN (wikipedia / netflix / twitter / reddit / ...).
SITES=(
    # big tech, cloud and enterprise software
    www.microsoft.com www.bing.com www.cloudflare.com www.adobe.com www.oracle.com
    www.ibm.com www.cisco.com www.salesforce.com www.sap.com www.atlassian.com
    www.jetbrains.com www.autodesk.com
    # hardware and consumer electronics
    www.intel.com www.nvidia.com www.amd.com www.samsung.com www.sony.com www.lg.com
    www.lenovo.com www.dell.com www.hp.com
    # automotive
    www.tesla.com www.toyota.com www.honda.com www.bmw.com www.mercedes-benz.com
    www.volkswagen.com
    # retail and consumer brands
    www.walmart.com www.target.com www.costco.com www.homedepot.com www.bestbuy.com
    www.ikea.com www.nike.com www.adidas.com
    # travel
    www.booking.com www.airbnb.com www.expedia.com
    # industrial / healthcare
    www.siemens.com www.bosch.com www.philips.com
    # SaaS and developer tools
    www.zoom.us www.mongodb.com www.elastic.co www.gitlab.com www.docker.com
    # payments, marketplaces and gaming
    www.paypal.com www.ebay.com www.stripe.com www.xbox.com
)
MASQ="${HIVE_MASQ:-${SITES[$(gen_port 0 $(( ${#SITES[@]} - 1 )))]}}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Xray Viewer + Hysteria2 Deploy${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: Must run as root${NC}"
    exit 1
fi

RESET_FW=0
for a in "$@"; do [ "$a" = "--reset-firewall" ] && RESET_FW=1; done

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
    PANEL_PORT=$(gen_port 10000 65000)
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

echo -e "${YELLOW}[*] Detecting server IP...${NC}"
SERVER_IP=""
for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
  SERVER_IP=$(curl -4 -sL --max-time 8 "$url" 2>/dev/null | tr -d '[:space:]')
  if [ -n "$SERVER_IP" ] && [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    break
  fi
  SERVER_IP=""
done
[ -z "$SERVER_IP" ] && SERVER_IP="YOUR_SERVER_IP"
echo -e "${YELLOW}[*] Server IP: ${SERVER_IP}${NC}"

mkdir -p "$DEST"
if [ "$FRESH" -eq 1 ] || [ ! -f "$DEST/tls.crt" ]; then
    echo -e "${YELLOW}[*] Generating self-signed TLS certificate for the panel...${NC}"
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$DEST/tls.key" -out "$DEST/tls.crt" \
        -days 3650 -subj "/CN=${SERVER_IP}" \
        -addext "subjectAltName=IP:${SERVER_IP},DNS:localhost" >/dev/null 2>&1 || \
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$DEST/tls.key" -out "$DEST/tls.crt" \
        -days 3650 -subj "/CN=${SERVER_IP}" >/dev/null 2>&1 || true
    chmod 600 "$DEST/tls.key" 2>/dev/null || true
    chmod 644 "$DEST/tls.crt" 2>/dev/null || true
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

if [ "$FRESH" -eq 1 ] || [ ! -f /usr/local/etc/xray/config.json ]; then
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
    PANEL_USER=$(gen_cred 16)
    PANEL_PASS=$(gen_cred 20)
fi
[ -n "$PANEL_USER" ] || PANEL_USER="admin"
[ -n "$PANEL_PASS" ] || PANEL_PASS="$(openssl rand -hex 16)"

if [ ! -x /usr/local/bin/hysteria ]; then
echo -e "${YELLOW}[*] Installing Hysteria2 (apernet/hysteria ${HYSTERIA_VER}, checksum-verified)...${NC}"
HYSTERIA_ARCH=$(uname -m)
case "$HYSTERIA_ARCH" in
    x86_64)  HY_ARCH="amd64"; HY_SHA="${HY_SHA_AMD64}" ;;
    aarch64) HY_ARCH="arm64"; HY_SHA="${HY_SHA_ARM64}" ;;
    armv7l)  HY_ARCH="arm";   HY_SHA="${HY_SHA_ARM}" ;;
    *)       echo -e "${RED}Unsupported arch: $HYSTERIA_ARCH${NC}"; exit 1 ;;
esac
HY_URL="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VER}/hysteria-linux-${HY_ARCH}"
curl --proto '=https' --tlsv1.2 -SfL --retry 3 --retry-delay 2 "$HY_URL" -o /usr/local/bin/hysteria || true
if [ ! -s /usr/local/bin/hysteria ]; then
    echo -e "${RED}[!] Failed to download hysteria.${NC}"; exit 1
fi
HY_ACTUAL=$(sha256sum /usr/local/bin/hysteria | awk '{print $1}')
if [ -z "$HY_SHA" ] || [ "$HY_ACTUAL" != "$HY_SHA" ]; then
    echo -e "${RED}[!] Hysteria checksum mismatch for ${HY_ARCH} (expected '${HY_SHA}', got '${HY_ACTUAL}'). Aborting.${NC}"
    rm -f /usr/local/bin/hysteria
    exit 1
fi
echo -e "${GREEN}[*] Hysteria2 checksum verified (${HY_ARCH}).${NC}"
chmod +x /usr/local/bin/hysteria
fi

getent group hysteria >/dev/null 2>&1 || groupadd -r hysteria
id hysteria >/dev/null 2>&1 || useradd -r -g hysteria -s /bin/false hysteria
getent group xrayconf >/dev/null 2>&1 || groupadd -r xrayconf
getent group hy2main >/dev/null 2>&1 || groupadd -r hy2main
usermod -aG hy2main hysteria 2>/dev/null || true

mkdir -p /etc/hysteria
if [ "$FRESH" -eq 1 ] || [ ! -f /etc/hysteria/server.crt ]; then
    echo -e "${YELLOW}[*] Generating Hysteria2 self-signed certificate...${NC}"
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout /etc/hysteria/server.key \
        -out /etc/hysteria/server.crt \
        -subj "/CN=${MASQ}" -days 36500 >/dev/null 2>&1
fi

HY2_STATS_PORT=9999
HY2_STATS_SECRET=$(openssl rand -hex 16)

mkdir -p /opt/xray-viewer
mkdir -p /usr/local/etc/xray
# The official Xray installer creates /usr/local/etc/xray as 0750 root:xray, but
# xray runs as `nobody` (plus SupplementaryGroups=xrayconf) and cannot even
# traverse a 0750 directory - it died on first start with:
#   open /usr/local/etc/xray/config.json: permission denied
# The directory only needs to be traversable; the json files stay 0640 root:xrayconf.
chmod 755 /usr/local/etc/xray 2>/dev/null || true
mkdir -p /etc/hysteria/conf.d

if [ "$FRESH" -eq 1 ] || [ ! -f /usr/local/etc/xray/config.json ]; then
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
          "dest": "${MASQ}:443",
          "xver": 0,
          "serverNames": ["${MASQ}"],
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

if [ "$FRESH" -eq 1 ] || [ ! -f /usr/local/etc/xray/hy2_nodes.json ]; then
echo -e "${YELLOW}[*] Generating hy2_nodes.json (v3)...${NC}"
cat > /usr/local/etc/xray/hy2_nodes.json << HYNODEEOF
[
  {
    "id": "hy2-443",
    "name": "",
    "port": 443,
    "protocol": "Hysteria2",
    "network": "UDP",
    "sni": "${MASQ}",
    "dest": "${MASQ}:443",
    "auth": "信任自签证书",
    "enabled": true,
    "cert": "/etc/hysteria/server.crt",
    "key": "/etc/hysteria/server.key",
    "masquerade": "https://${MASQ}",
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

if [ "$FRESH" -eq 1 ] || [ ! -f /usr/local/etc/xray/users.json ]; then
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

if [ "$FRESH" -eq 1 ] || [ ! -f /etc/hysteria/conf.d/hy2-443.yaml ]; then
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
    url: https://${MASQ}
    rewriteHost: true

trafficStats:
  listen: 127.0.0.1:${HY2_STATS_PORT}
  secret: ${HY2_STATS_SECRET}
HYEOF
fi

# Reconcile the Hysteria2 node config with hy2_nodes.json (the panel is the
# source of truth) before starting the unit. Two failure modes this avoids:
#   * an empty `auth.userpass:` block - hysteria refuses to start on it
#     ("invalid config: auth.userpass: empty auth userpass") and
#     Restart=on-failure + StartLimitIntervalSec=0 then restart it forever. That
#     is what a node whose last user was unbound leaves behind.
#   * a config that drifted away from hy2_nodes.json (e.g. users exist in the
#     panel but the yaml still has none, or the node was deleted in the panel
#     while its yaml survived).
# Prints the number of real users of the hy2-443 node (0 = nothing to serve).
HY2_USERS=$(python3 - <<'PYEOF'
import json, os, secrets, sys

NODES = '/usr/local/etc/xray/hy2_nodes.json'
CONF = '/etc/hysteria/conf.d/hy2-443.yaml'

def q(v):
    return json.dumps(str(v), ensure_ascii=False)

def yaml_user_count(path):
    n, inside = 0, False
    try:
        for line in open(path, encoding='utf-8'):
            if line.strip() == 'userpass:':
                inside = True
                continue
            if inside:
                if line.startswith('    ') and line.strip():
                    n += 1
                elif line.strip():
                    inside = False
    except Exception:
        return -1
    return n

try:
    nodes = json.load(open(NODES))
except Exception:
    nodes = []
node = next((n for n in nodes if isinstance(n, dict) and n.get('id') == 'hy2-443'), None)
if node is None:
    print(0)
    sys.exit(0)

users = []
for u in (node.get('users') or []):
    name = (u.get('name') or '').strip()
    password = u.get('password') or ''
    if name and password:
        users.append((name, password))

need_write = True
if not users and os.path.exists(CONF) and yaml_user_count(CONF) > 0:
    # No real users: the file only needs to stay valid, so keep an existing
    # placeholder instead of rewriting it on every update.
    need_write = False

if need_write:
    stats = node.get('stats') or {}
    lines = ['listen: :%d' % int(node.get('port') or 443), '', 'tls:',
             '  cert: %s' % (node.get('cert') or '/etc/hysteria/server.crt'),
             '  key: %s' % (node.get('key') or '/etc/hysteria/server.key'), '',
             'auth:', '  type: userpass', '  userpass:']
    for name, password in (users or [('_unused', secrets.token_hex(24))]):
        lines.append('    %s: %s' % (q(name), q(password)))
    lines += ['', 'masquerade:', '  type: proxy', '  proxy:',
              '    url: %s' % q(node.get('masquerade') or 'https://www.microsoft.com'),
              '    rewriteHost: true', '', 'trafficStats:',
              '  listen: %s' % (stats.get('listen') or '127.0.0.1:9999'),
              '  secret: %s' % q(stats.get('secret') or secrets.token_hex(16))]
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    tmp = CONF + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(tmp, CONF)
    os.chmod(CONF, 0o640)

print(len(users))
PYEOF
)

chown -R root:hy2main /etc/hysteria
chmod 750 /etc/hysteria /etc/hysteria/conf.d 2>/dev/null || true
chmod 640 /etc/hysteria/server.key /etc/hysteria/server.crt /etc/hysteria/conf.d/*.yaml 2>/dev/null || true

[ -f /usr/local/etc/xray/disabled_clients.json ] || echo "[]" > /usr/local/etc/xray/disabled_clients.json
[ -f /usr/local/etc/xray/disabled_inbounds.json ] || echo "[]" > /usr/local/etc/xray/disabled_inbounds.json
[ -f /usr/local/etc/xray/traffic_totals.json ] || echo "{}" > /usr/local/etc/xray/traffic_totals.json
[ -f /usr/local/etc/xray/fwd.json ] || echo "[]" > /usr/local/etc/xray/fwd.json
# xray runs as an unprivileged user; keep the config (Reality private key, UUIDs)
# readable only by root and the xrayconf group that xray itself belongs to.
# The containing directory must stay traversable for `nobody` (see the chmod 755
# above) or every start fails with "permission denied".
chmod 755 /usr/local/etc/xray 2>/dev/null || true
chown root:xrayconf /usr/local/etc/xray/*.json 2>/dev/null || true
chmod 640 /usr/local/etc/xray/*.json 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Credentials live OUTSIDE the code, salted+hashed, in /opt/xray-viewer/panel_auth.json.
PANEL_USER="$PANEL_USER" PANEL_PASS="$PANEL_PASS" FRESH="$FRESH" python3 - <<'PYEOF'
import os, json, re, ast, hashlib, secrets
auth = "/opt/xray-viewer/panel_auth.json"
app = "/opt/xray-viewer/app.py"
u = os.environ.get("PANEL_USER") or ""
pw = os.environ.get("PANEL_PASS") or ""
fresh = os.environ.get("FRESH") != "0"
if (not fresh) and (not os.path.exists(auth)) and os.path.exists(app):
    try:
        s = open(app, encoding="utf-8").read()
        mu = re.search(r'^USERNAME = (.*)$', s, re.M)
        mp = re.search(r'^PASSWORD = (.*)$', s, re.M)
        if mu: u = ast.literal_eval(mu.group(1).strip())
        if mp: pw = ast.literal_eval(mp.group(1).strip())
        print("[*] Migrating existing panel credentials to hashed storage")
    except Exception as e:
        print("[!] credential migration skipped:", e)
if not os.path.exists(auth):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000)
    h = "pbkdf2_sha256$200000$%s$%s" % (salt, dk.hex())
    tmp = auth + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"username": u, "password_hash": h}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, auth)
    print("[*] Panel credentials written to panel_auth.json (hashed)")
else:
    print("[*] Preserving existing panel credentials")
PYEOF

cp "$SCRIPT_DIR/app.py" /opt/xray-viewer/app.py
cp "$SCRIPT_DIR/traffic_store.py" /opt/xray-viewer/traffic_store.py
chmod 600 /opt/xray-viewer/panel_auth.json 2>/dev/null || true
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
SupplementaryGroups=xrayconf
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
Environment=HOME=/opt/xray-viewer
Environment=MALLOC_ARENA_MAX=2
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/local/bin/gunicorn --chdir /opt/xray-viewer -w 1 --threads 2 --timeout 60 --keep-alive 30 -b 0.0.0.0:${PANEL_PORT} --certfile /opt/xray-viewer/tls.crt --keyfile /opt/xray-viewer/tls.key app:app
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
SupplementaryGroups=hy2main
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
if [ "$RESET_FW" -eq 1 ]; then
    echo -e "${YELLOW}[*] --reset-firewall given: resetting ufw to a clean state${NC}"
    ufw --force reset >/dev/null 2>&1 || true
fi
# Never lock ourselves out: always allow the SSH port(s) actually in use (config + live session).
SSH_PORTS="22"
if [ -f /etc/ssh/sshd_config ]; then
    P=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [ -n "$P" ] && SSH_PORTS="$SSH_PORTS $P"
fi
if [ -n "$SSH_CONNECTION" ]; then
    P=$(echo "$SSH_CONNECTION" | awk '{print $4}')
    [ -n "$P" ] && SSH_PORTS="$SSH_PORTS $P"
fi
for p in $(echo "$SSH_PORTS" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u); do
    ufw allow "${p}/tcp" >/dev/null 2>&1 || true
done
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 443/udp >/dev/null 2>&1 || true
ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
echo -e "${YELLOW}[*] ufw: panel port ${PANEL_PORT}/tcp allowed (Anywhere); existing rules preserved${NC}"

echo -e "${YELLOW}[*] Starting services...${NC}"
systemctl daemon-reload
if [ "$HY2_USERS" -gt 0 ]; then
    systemctl enable --now hysteria-node@hy2-443 >/dev/null 2>&1 || true
else
    # Nothing to authenticate: keep the unit stopped so it does not restart-loop.
    systemctl disable --now hysteria-node@hy2-443 >/dev/null 2>&1 || true
    echo -e "${YELLOW}[*] hy2-443 has no user bound (or is gone from the panel) - Hysteria2 left stopped; bind a user to it in the panel to start it${NC}"
fi
systemctl enable --now xray >/dev/null 2>&1 || true
systemctl enable --now xray-viewer >/dev/null 2>&1 || true
# restart so an updated unit (ExecStart etc.) actually takes effect on upgrade
[ "$HY2_USERS" -gt 0 ] && systemctl restart hysteria-node@hy2-443 >/dev/null 2>&1 || true
# Reconcile the forwarding (dokodemo) tunnels from fwd.json into the xray config
# before restarting, so a restart never leaves the "fwd-*" inbounds missing.
python3 - <<'PYEOF'
import json, os, re
cfg_path = '/usr/local/etc/xray/config.json'
fwd_path = '/usr/local/etc/xray/fwd.json'
with open(cfg_path) as f:
    cfg = json.load(f)
inbounds = cfg.setdefault('inbounds', [])
keep = [ib for ib in inbounds if not (ib.get('protocol') == 'dokodemo-door' and str(ib.get('tag', '')).startswith('fwd-'))]
fwd = json.load(open(fwd_path)) if os.path.exists(fwd_path) else []
for r in fwd:
    if not r.get('enabled'):
        continue
    lport, tip, tport = r.get('listen_port'), r.get('target_ip', ''), r.get('target_port')
    if not (lport and tip and tport):
        continue
    for proto in ('tcp', 'udp'):
        if (proto == 'tcp' and r.get('tcp')) or (proto == 'udp' and r.get('udp')):
            keep.append({
                'listen': '0.0.0.0',
                'port': int(lport),
                'protocol': 'dokodemo-door',
                'settings': {'address': tip, 'port': int(tport), 'network': proto},
                'tag': 'fwd-' + re.sub(r'[^A-Za-z0-9_.\-]', '-', str(r['id'])) + '-' + proto,
            })
cfg['inbounds'] = keep
with open(cfg_path, 'w') as f:
    json.dump(cfg, f)
PYEOF
systemctl restart xray >/dev/null 2>&1 || true
systemctl restart xray-viewer >/dev/null 2>&1 || true

for i in 1 2 3 4 5 6 7 8; do
    if systemctl is-active --quiet xray && systemctl is-active --quiet xray-viewer; then
        { [ "$HY2_USERS" -eq 0 ] || systemctl is-active --quiet hysteria-node@hy2-443; } && break
    fi
    sleep 1
done

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
if [ "$HY2_USERS" -eq 0 ]; then
    HYSTERIA_STATUS="stopped (no users bound)"
fi

echo -e "  Xray:             ${XRAY_STATUS}"
echo -e "  Xray Viewer:      ${VIEWER_STATUS}"
echo -e "  Hysteria2 (443):  ${HYSTERIA_STATUS}"
echo ""

if [ "$FRESH" -eq 1 ]; then
echo -e "${GREEN}--- Xray VLESS+Reality 节点 (443) ---${NC}"
echo -e "  Server:     ${SERVER_IP}"
echo -e "  Port:       443"
echo -e "  Network:    tcp / TLS: reality / SNI: ${MASQ} / ShortID: ${SHORT_ID}"
echo -e "  PublicKey:  ${REALITY_PUBLIC_KEY}"
echo ""
echo -e "  [admin]  (vless + hy2 双协议，vless uuid == hy2 密码)"
echo -e "    UUID:   ${UUID_ADMIN}"
echo -e "    Link:   ${YELLOW}vless://${UUID_ADMIN}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&network=tcp&security=reality&sni=${MASQ}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${SHORT_ID}#admin_vless${NC}"
echo -e "    hy2 密码(uuid): ${UUID_ADMIN}"
echo ""

echo -e "${GREEN}--- Hysteria2 节点 (443) ---${NC}"
echo -e "  Server:     ${SERVER_IP} / Port: 443 (UDP) / SNI: ${MASQ} (客户端信任自签证书)"
echo -e "  [admin]  用户名: admin  密码: ${UUID_ADMIN}"
echo ""
else
echo -e "${GREEN}--- 节点配置 ---${NC}"
echo -e "  已保留原有节点/用户配置（UUID、密钥、节点端口均未改动）"
echo ""
fi

echo -e "${GREEN}--- Web Panel (v1.0.7) ---${NC}"
echo -e "  URL:        ${YELLOW}https://${SERVER_IP}:${PANEL_PORT}${PANEL_PATH}/login${NC}"
if [ "$FRESH" -eq 1 ]; then
    echo -e "  Username:   ${PANEL_USER}"
    echo -e "  Password:   ${PANEL_PASS}"
else
    echo -e "  Username/Password: 保持不变（见首次安装记录；可在面板内修改）"
fi
echo -e "  Panel Port: ${PANEL_PORT}"
echo -e "  Panel Path: ${PANEL_PATH}"
echo -e "  ${YELLOW}自签证书：浏览器会提示证书不受信任，这是预期的，确认后即可访问。${NC}"
echo -e "  ${YELLOW}安全提示：面板端口 ${PANEL_PORT} 已对 Anywhere 放行，建议尽快在面板『防火墙』卡片中改为只放行你的固定 IP。${NC}"
echo ""
