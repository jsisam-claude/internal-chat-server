#!/bin/sh
# Idempotent installer for the internal chat server on a systemd host.
# Run as root from the repo root:  sh deploy/install.sh [/path/to/web-client]
#
# Layout it produces:
#   /opt/internal-chat/chatserver.py       code (root-owned, read-only)
#   /opt/internal-chat/static/             web client (optional argument)
#   /etc/internal-chat/server.pem          TLS cert+key (self-signed if absent)
#   /var/lib/internal-chat/                data dir (service-owned)
#
# Recommended but not automated here: mount /var/lib/internal-chat from a
# volume with  noexec,nosuid,nodev  so uploads can never execute.
set -eu

APP=/opt/internal-chat
ETC=/etc/internal-chat
DATA=/var/lib/internal-chat
SVCUSER=internal-chat
WEB=${1:-}
CN=${CN:-chat.internal}

# Resolve the web-client path BEFORE cd, or a relative argument would be
# reinterpreted against the repo root below.
[ -n "$WEB" ] && WEB=$(cd "$WEB" && pwd)

cd "$(dirname "$0")/.."

id "$SVCUSER" >/dev/null 2>&1 || \
    useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SVCUSER"

mkdir -p "$APP" "$ETC" "$DATA"
install -m 0644 chatserver.py "$APP/chatserver.py"
# the implementation lives in the internalchat/ package next to the entry point
rm -rf "$APP/internalchat"
mkdir -p "$APP/internalchat"
install -m 0644 internalchat/*.py "$APP/internalchat/"
if [ -n "$WEB" ]; then
    mkdir -p "$APP/static"
    # copy only what the client needs; never dotfiles or repo metadata
    cp "$WEB"/index.html "$WEB"/app.css "$WEB"/favicon.svg "$APP/static/"
    mkdir -p "$APP/static/js"
    cp "$WEB"/js/*.js "$APP/static/js/"
fi

if [ ! -f "$ETC/server.pem" ]; then
    echo "generating self-signed cert for CN=$CN (replace with your CA's)"
    # subjectAltName is REQUIRED — modern clients ignore CN and reject a cert
    # with no SAN even when the CA is explicitly trusted.
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$ETC/server.pem" -out "$ETC/server.pem" \
        -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN" 2>/dev/null
fi
chmod 0600 "$ETC/server.pem"
chown "$SVCUSER:$SVCUSER" "$ETC/server.pem" "$DATA"
chmod 0700 "$DATA"

if [ -d /run/systemd/system ]; then  # systemd present AND running
    install -m 0644 deploy/internal-chat.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable internal-chat
    # restart (not just enable --now) so re-running the installer to upgrade
    # actually loads the new code instead of keeping the old process
    systemctl restart internal-chat
    systemctl --no-pager status internal-chat || true
else
    echo "systemd not found; start manually:"
    echo "  sudo -u $SVCUSER python3 $APP/chatserver.py serve" \
         "--data $DATA --cert $ETC/server.pem --static $APP/static"
fi

echo
echo "next steps:"
echo "  python3 $APP/chatserver.py adduser <name> --data $DATA   # provision users"
echo "  mount $DATA with noexec,nosuid,nodev                     # recommended"
