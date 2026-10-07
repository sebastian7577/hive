#!/bin/bash
set -e

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BASE=/opt/limit
DATA=$BASE/data
UNIT_DIR=/etc/systemd/system

echo "[*] ensure deps"
command -v gunicorn >/dev/null 2>&1 || pip3 install flask gunicorn >/dev/null 2>&1 || true
python3 -c "import flask" 2>/dev/null || pip3 install flask >/dev/null 2>&1 || true
id hysteria >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin hysteria
id limitpanel >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$BASE" limitpanel
usermod -aG hysteria limitpanel 2>/dev/null || true

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
        -subj "/CN=www.amazon.com" -days 36500 >/dev/null 2>&1
fi
chown limitpanel:hysteria "$BASE/hysteria/server.key" "$BASE/hysteria/server.crt" 2>/dev/null || true
chmod 640 "$BASE/hysteria/server.key" "$BASE/hysteria/server.crt" 2>/dev/null || true

echo "[*] seed tenants.json"
[ -f "$DATA/tenants.json" ] || echo '{"tenants": []}' > "$DATA/tenants.json"
chown limitpanel:limitpanel "$DATA/tenants.json" 2>/dev/null || true
chmod 660 "$DATA/tenants.json" 2>/dev/null || true

echo "[*] initial limit-xray config (api only)"
if [ ! -f "$BASE/xray/config.json" ]; then
cat > "$BASE/xray/config.json" <<'XEOF'
{
  "log": {"loglevel": "warning", "access": "/dev/null"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": 10185, "protocol": "dokodemo-door",
     "settings": {"address": "127.0.0.1"}, "tag": "api"}
  ],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"},
    {"protocol": "freedom", "tag": "api"}
  ],
  "stats": {},
  "api": {"tag": "api", "services": ["StatsService"]},
  "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]}
}
XEOF
fi
chmod 644 "$BASE/xray/config.json" 2>/dev/null || true

echo "[*] panel port"
if [ -f "$UNIT_DIR/limit-viewer.service" ]; then
    PORT=$(grep -oE -- '-b 0\.0\.0\.0:[0-9]+' "$UNIT_DIR/limit-viewer.service" | grep -oE '[0-9]+$')
fi
if [ -z "$PORT" ]; then
    while :; do
        P=$(shuf -i 50000-60000 -n 1)
        if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q "[:.]${P}\$"; then PORT=$P; break; fi
    done
fi
echo "    panel port = $PORT"
echo "$PORT" > "$BASE/panel_port"
chown limitpanel:limitpanel "$BASE/panel_port"
chmod 644 "$BASE/panel_port"

echo "[*] systemd units"
sed "s/__PORT__/${PORT}/" "$SCRIPT_DIR/limit-viewer.service" > "$UNIT_DIR/limit-viewer.service"
cp "$SCRIPT_DIR/limit-xray.service" "$UNIT_DIR/limit-xray.service"
cp "$SCRIPT_DIR/limit-hysteria@.service" "$UNIT_DIR/limit-hysteria@.service"
cp "$SCRIPT_DIR/limit-helper.service" "$UNIT_DIR/limit-helper.service"
systemctl daemon-reload

echo "[*] start services"
systemctl enable --now limit-helper >/dev/null 2>&1 || true
systemctl restart limit-helper
systemctl enable --now limit-xray >/dev/null 2>&1 || true
systemctl restart limit-xray
systemctl enable --now limit-viewer >/dev/null 2>&1 || true
systemctl restart limit-viewer
sleep 2

echo "[*] firewall: open limit panel port (public)"
ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true

echo "[*] tighten main panel perms (defense in depth)"
chmod 700 /opt/xray-viewer 2>/dev/null || true
chmod 600 /opt/xray-viewer/app.py /opt/xray-viewer/traffic_store.py /opt/xray-viewer/secret_key 2>/dev/null || true
rm -f /usr/local/etc/xray/config.json.bak* 2>/dev/null || true

IP=$(curl -4 -sL --max-time 8 https://api.ipify.org 2>/dev/null)
[ -z "$IP" ] && IP="<SERVER_IP>"

echo ""
echo "=================================================="
echo "  Limit 多租户面板 部署完成"
echo "=================================================="
echo "  limit-helper: $(systemctl is-active limit-helper)"
echo "  limit-xray : $(systemctl is-active limit-xray)"
echo "  limit-viewer: $(systemctl is-active limit-viewer)  (port ${PORT}, user limitpanel)"
echo "  面板地址   : http://${IP}:${PORT}/<租户路径>/login"
echo "  租户由主面板“limit用户”卡片开通（会生成路径+账号+密码）"
echo "=================================================="

