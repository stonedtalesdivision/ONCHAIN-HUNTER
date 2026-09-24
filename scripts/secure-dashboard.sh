#!/usr/bin/env bash
set -euo pipefail

HOSTNAME="${1:-hunter.texvic.tech}"
SITE_FILE="/etc/nginx/sites-available/${HOSTNAME}"
AUTH_FILE="/etc/nginx/.htpasswd-onchain-hunter"
BACKUP_FILE="${SITE_FILE}.bak.$(date +%Y%m%d%H%M%S)"

if [[ ! -f "$SITE_FILE" ]]; then
  echo "Nginx site file not found: $SITE_FILE"
  exit 1
fi

if ! command -v htpasswd >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2-utils
fi

read -r -p "Admin username [sanjay]: " USERNAME
USERNAME="${USERNAME:-sanjay}"
echo "Create/update the password for $USERNAME:"
htpasswd -cB "$AUTH_FILE" "$USERNAME"
chmod 640 "$AUTH_FILE"
chown root:www-data "$AUTH_FILE"

cp "$SITE_FILE" "$BACKUP_FILE"

if grep -q 'auth_basic_user_file /etc/nginx/.htpasswd-onchain-hunter;' "$SITE_FILE"; then
  echo "ONCHAIN-HUNTER authentication is already configured."
else
  python3 - "$SITE_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
needle = "server {"
insert = '''server {
    auth_basic "ONCHAIN-HUNTER Private";
    auth_basic_user_file /etc/nginx/.htpasswd-onchain-hunter;'''
if needle not in text:
    raise SystemExit("Could not find 'server {' in nginx site config")
path.write_text(text.replace(needle, insert, 1))
PY
fi

nginx -t
systemctl reload nginx

echo
echo "ONCHAIN-HUNTER is now protected by Nginx Basic Authentication."
echo "Backup: $BACKUP_FILE"
echo "Password file: $AUTH_FILE"
echo "Test: https://$HOSTNAME"
