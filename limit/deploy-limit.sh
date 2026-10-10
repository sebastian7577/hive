#!/bin/bash
# Hive limit (multi-tenant) panel deployer (fresh install or in-place update).
# Creates the non-root `limitpanel` user, the root `limit-helper`, the panel
# files, a self-signed TLS cert and the systemd units. Idempotent: re-running
# keeps the existing tenants, port and certs.
# See README.md.
set -e

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BASE=/opt/limit
DATA=$BASE/data
UNIT_DIR=/etc/systemd/system
FRESH=1
[ -f "$BASE/app.py" ] && FRESH=0
SITES=(www.amazon.com www.microsoft.com www.bing.com www.apple.com www.cloudflare.com www.wikipedia.org www.samsung.com www.icloud.com)
MASQ="${HIVE_MASQ:-${SITES[$(( 0x$(openssl rand -hex 2) % ${#SITES[@]} ))]}}"

echo "[*] ensure deps"
command -v gunicorn >/dev/null 2>&1 || pip3 install flask gunicorn >/dev/null 2>&1 || true
python3 -c "import flask" 2>/dev/null || pip3 install flask >/dev/null 2>&1 || true
getent group hysteria >/dev/null 2>&1 || groupadd -r hysteria
id hysteria >/dev/null 2>&1 || useradd -r -g hysteria -s /usr/sbin/nologin hysteria
getent group limitpanel >/dev/null 2>&1 || groupadd -r limitpanel
id limitpanel >/dev/null 2>&1 || useradd -r -g limitpanel -s /usr/sbin/nologin -d "$BASE" limitpanel
usermod -aG hysteria limitpanel 2>/dev/null || true

IP=$(curl -4 -sL --max-time 8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')

echo "[*] dirs + perms"
mkdir -p "$DATA" "$BASE/xray" "$BASE/hysteria/conf.d"
chown limitpanel:limitpanel "$BASE" "$BASE/xray"
chmod 755 "$BASE" "$BASE/xray"
chown limitpanel:limitpanel "$DATA"
chmod 2770 "$DATA"
chown limitpanel:hysteria "$BASE/hysteria" "$BASE/hysteria/conf.d"
chmod 2750 "$BASE/hysteria" "$BASE/hysteria/conf.d"

echo "[*] app files"
cp "$SCRIPT_DIR/app.py" "$BASE/app.py"
cp "$SCRIPT_DIR/traffic_store.py" "$BASE/traffic_store.py"
cp "$SCRIPT_DIR/base.css" "$BASE/base.css"
chown limitpanel:limitpanel "$BASE/app.py" "$BASE/traffic_store.py" "$BASE/base.css"
chmod 640 "$BASE/app.py" "$BASE/traffic_store.py" "$BASE/base.css"

echo "[*] privileged helper"
cp "$SCRIPT_DIR/limit-helper.py" "$BASE/limit-helper.py"
chown root:root "$BASE/limit-helper.py"
chmod 755 "$BASE/limit-helper.py"

echo "[*] secret key"
if [ ! -f "$BASE/secret_key" ]; then openssl rand -hex 32 > "$BASE/secret_key"; fi
chown limitpanel:limitpanel "$BASE/secret_key"
chmod 600 "$BASE/secret_key"

echo "[*] hysteria self-signed cert"
if [ ! -f "$BASE/hysteria/server.crt" ]; then
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$BASE/hysteria/server.key" -out "$BASE/hysteria/server.crt" \
        -subj "/CN=${MASQ}" -days 36500 >/dev/null 2>&1
fi
chown limitpanel:hysteria "$BASE/hysteria/server.key" "$BASE/hysteria/server.crt" 2>/dev/null || true
chmod 640 "$BASE/hysteria/server.key" "$BASE/hysteria/server.crt" 2>/dev/null || true

echo "[*] panel self-signed TLS cert"
if [ ! -f "$BASE/tls.crt" ]; then
    SAN_IP="${IP:-localhost}"
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$BASE/tls.key" -out "$BASE/tls.crt" \
        -days 3650 -subj "/CN=${SAN_IP}" \
        -addext "subjectAltName=IP:${SAN_IP},DNS:localhost" >/dev/null 2>&1 || \
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$BASE/tls.key" -out "$BASE/tls.crt" \
        -days 3650 -subj "/CN=${SAN_IP}" >/dev/null 2>&1 || true
fi
chown limitpanel:limitpanel "$BASE/tls.key" "$BASE/tls.crt" 2>/dev/null || true
chmod 600 "$BASE/tls.key" 2>/dev/null || true
chmod 644 "$BASE/tls.crt" 2>/dev/null || true

echo "[*] seed tenants.json"
[ -f "$DATA/tenants.json" ] || echo '{"tenants": []}' > "$DATA/tenants.json"
chown limitpanel:limitpanel "$DATA/tenants.json" 2>/dev/null || true
chmod 660 "$DATA/tenants.json" 2>/dev/null || true

echo "[*] migrate away from the shared limit-xray config"
# each tenant now gets its own xray process + config (<tid>.json), written by the panel
rm -f "$BASE/xray/config.json" 2>/dev/null || true

echo "[*] panel port"
if [ -f "$UNIT_DIR/limit-viewer.service" ]; then
    PORT=$(grep -oE -- '-b 0\.0\.0\.0:[0-9]+' "$UNIT_DIR/limit-viewer.service" | grep -oE '[0-9]+$')
fi
if [ -z "$PORT" ]; then
    while :; do
        P=$(( 50000 + 0x$(openssl rand -hex 4) % 10001 ))
        if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "[:.]${P}\$"; then PORT=$P; break; fi
    done
fi
echo "    panel port = $PORT"
echo "$PORT" > "$BASE/panel_port"
chown limitpanel:limitpanel "$BASE/panel_port"
chmod 644 "$BASE/panel_port"

echo "[*] systemd units"
sed "s/__PORT__/${PORT}/" "$SCRIPT_DIR/limit-viewer.service" > "$UNIT_DIR/limit-viewer.service"
cp "$SCRIPT_DIR/limit-xray@.service" "$UNIT_DIR/limit-xray@.service"
cp "$SCRIPT_DIR/limit-hysteria@.service" "$UNIT_DIR/limit-hysteria@.service"
cp "$SCRIPT_DIR/limit-helper.service" "$UNIT_DIR/limit-helper.service"
if [ -f "$UNIT_DIR/limit-xray.service" ]; then
    systemctl disable --now limit-xray >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/limit-xray.service"
fi
systemctl daemon-reload

echo "[*] start services"
systemctl enable --now limit-helper >/dev/null 2>&1 || true
systemctl restart limit-helper
# Master switch: a fresh install starts PAUSED (OFF); an update keeps whatever
# state it had (a paused install stays paused, a running one is restarted).
if [ "$FRESH" -eq 1 ]; then
    echo "[*] fresh install: limit master switch defaults to OFF"
    echo "1" > "$BASE/.paused"
    chmod 644 "$BASE/.paused" 2>/dev/null || true
    systemctl disable limit-viewer >/dev/null 2>&1 || true
    systemctl stop limit-viewer >/dev/null 2>&1 || true
elif [ -f "$BASE/.paused" ]; then
    echo "[*] limit is paused (.paused present): keeping services stopped"
    systemctl stop limit-viewer >/dev/null 2>&1 || true
else
    systemctl enable --now limit-viewer >/dev/null 2>&1 || true
    systemctl restart limit-viewer
fi
sleep 2

echo "[*] firewall: open limit panel port (public)"
ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true

echo "[*] tighten main panel perms (defense in depth)"
chmod 700 /opt/xray-viewer 2>/dev/null || true
chmod 600 /opt/xray-viewer/app.py /opt/xray-viewer/traffic_store.py /opt/xray-viewer/secret_key 2>/dev/null || true
rm -f /usr/local/etc/xray/config.json.bak* 2>/dev/null || true

[ -z "$IP" ] && IP="<SERVER_IP>"

echo ""
echo "=================================================="
echo "  Limit 多租户面板 部署完成"
echo "=================================================="
echo "  limit-helper: $(systemctl is-active limit-helper)"
echo "  limit-xray : $(systemctl is-active limit-xray)"
echo "  limit-viewer: $(systemctl is-active limit-viewer)  (port ${PORT}, user limitpanel)"
echo "  面板地址   : https://${IP}:${PORT}/<租户路径>/login  (自签证书，浏览器会提示不受信任)"
echo "  租户由主面板“limit用户”卡片开通（会生成路径+账号+密码）"
echo "=================================================="

