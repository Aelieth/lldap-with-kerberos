#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

# Ensure persistence dirs exist and owned by lldap (matches official exactly)
mkdir -p /data /data/cert /var/lib/krb5kdc
chown -R lldap:lldap /data /var/lib/krb5kdc

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml $CONFIG_FILE
  chown lldap:lldap $CONFIG_FILE
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Config file is not readable. Check the permissions"
  exit 1
fi

echo "> Fixing ownership on /app assets (binaries, static, pkg).."
find /app \! -user lldap -exec chown lldap:lldap '{}' +

echo "> Starting lldap.."
echo ""

exec gosu lldap:lldap /app/lldap "$@"
