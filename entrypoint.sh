#!/bin/bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

ls -la /
ls -la /data
ls -la /app

# === Required env checks ===
if [ -z "$LLDAP_JWT_SECRET" ]; then
    echo "ERROR: LLDAP_JWT_SECRET is required."
    echo "Please set a strong random secret (32+ characters) via environment variable."
    echo "Example: -e LLDAP_JWT_SECRET=\"$(openssl rand -hex 32)\""
    exit 1
fi
if [ -z "$LLDAP_LDAP_BASE_DN" ]; then
    echo "ERROR: LLDAP_LDAP_BASE_DN is required."
    echo "Example: -e LLDAP_LDAP_BASE_DN=\"dc=homelab,dc=local\""
    exit 1
fi

# === Official LLDAP writable check ===
if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[entrypoint] The /data folder doesn't exist or cannot be written to. Make sure to mount
  a volume or folder to /data to persist data across restarts, and that the current user can
  write to it."
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml $CONFIG_FILE
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Config file is not readable. Check the permissions"
  exit 1;
fi

# === Official permission setup ===
echo "> Setup permissions.."
find /app \! -user lldap -exec chown lldap:lldap '{}' +
find /data \! -user lldap -exec chown lldap:lldap '{}' +

# === Start LLDAP ===
echo "Starting LLDAP..."
exec gosu lldap:lldap /app/lldap "$@" &
LLDAP_PID=$!

echo "Waiting for LLDAP to become ready..."
for i in $(seq 1 60); do
    if /app/lldap healthcheck >/dev/null 2>&1; then
        echo "LLDAP is ready!"
        break
    fi
    sleep 1
done

if [ "$i" -eq 60 ]; then
    echo "ERROR: LLDAP failed to start within 60 seconds."
    exit 1
fi

echo "Starting Kerberos manager..."
/app/kerberos_manager &
KERBEROS_PID=$!

trap 'echo "Shutting down..."; kill $LLDAP_PID $KERBEROS_PID 2>/dev/null || true; wait; exit 0' INT TERM

wait $LLDAP_PID
