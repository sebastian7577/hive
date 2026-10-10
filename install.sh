#!/bin/bash
# Hive one-line installer / updater.
# Downloads the repo, runs deploy.sh (main panel) and limit/deploy-limit.sh,
# then installs the `hive` shortcut. Re-running the same command updates in
# place (existing nodes/users/tenants/port/path/credentials are kept).
# First version — see README.md.
set -e

REPO="sebastian7577/hive"
BRANCH="main"
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Hive installer / updater${NC}"
echo -e "${GREEN}========================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: must run as root (use: sudo -i)${NC}"
    exit 1
fi

if [ "$1" = "uninstall" ]; then
    echo -e "${YELLOW}[*] Uninstalling Hive...${NC}"
    systemctl disable --now xray-viewer xray hysteria-node@hy2-443 limit-viewer limit-xray limit-helper >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/{xray,xray-viewer,hysteria-node@,limit-viewer,limit-xray,limit-xray@,limit-hysteria@,limit-helper}.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf /opt/xray-viewer /opt/limit
    rm -f /usr/local/bin/hive
    echo -e "${GREEN}[*] Removed panel files. (xray/hysteria binaries left in place.)${NC}"
    exit 0
fi

# Optional version: `install.sh v1.0.0` installs that tag; no argument = latest (main).
REF_KIND="heads"; REF_NAME="$BRANCH"
case "$1" in
    v[0-9]*) REF_KIND="tags"; REF_NAME="$1" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq curl tar ca-certificates >/dev/null 2>&1 || true

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo -e "${YELLOW}[*] Downloading Hive (${REPO}@${REF_NAME})...${NC}"
curl -fsSL "https://github.com/${REPO}/archive/refs/${REF_KIND}/${REF_NAME}.tar.gz" -o "$TMP/hive.tar.gz"
tar -xzf "$TMP/hive.tar.gz" -C "$TMP"
SRC="$(find "$TMP" -maxdepth 1 -type d -name 'hive-*' | head -n1)"
[ -n "$SRC" ] && [ -f "$SRC/deploy.sh" ] || { echo -e "${RED}Download/extract failed${NC}"; exit 1; }

if [ -f /opt/xray-viewer/app.py ]; then
    echo -e "${YELLOW}[*] Existing install found -> updating (your data is preserved)${NC}"
else
    echo -e "${YELLOW}[*] Fresh install${NC}"
fi

echo -e "${YELLOW}[*] [1/2] Main panel (xray + hysteria2 + web)${NC}"
bash "$SRC/deploy.sh"

echo -e "${YELLOW}[*] [2/2] Limit multi-tenant panel${NC}"
bash "$SRC/limit/deploy-limit.sh"

cat > /usr/local/bin/hive <<EOF
#!/bin/bash
exec bash <(curl -fsSL ${RAW}/install.sh) "\$@"
EOF
chmod +x /usr/local/bin/hive

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Done.${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  Update anytime:  ${YELLOW}hive${NC}"
echo -e "  Uninstall:       ${YELLOW}bash <(curl -fsSL ${RAW}/install.sh) uninstall${NC}"
echo ""
