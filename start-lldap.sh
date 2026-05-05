#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

# Create required persistent directories (kerberos_manager now owns its own dirs)
mkdir -p /data /data/keytab /data/cert

# Only set ownership on FIRST run (protects persistent keytabs, keycloak files, etc.)
if [ ! -f /data/.lldap_initialized ]; then
  echo "[start-lldap] First run detected — setting ownership on /data"
  chown -R lldap:lldap /data
  touch /data/.lldap_initialized
fi

# Official LLDAP writable check
if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[start-lldap] The /data folder doesn't exist or cannot be written to. Make sure to mount a volume."
  exit 1
fi

# Fixing ownership on /app assets (binaries, static, pkg)
find /app \! -user lldap -exec chown lldap:lldap '{}' +

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

echo "> Starting klldap.."
echo ""

exec gosu lldap:lldap /app/lldap "$@"
