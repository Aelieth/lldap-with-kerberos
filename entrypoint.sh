#!/bin/bash
set -euo pipefail

CONFIG_FILE=/data/lldap_config.toml

# === Official LLDAP writable check (exact upstream) ===
if [[ ( ! -w "/data" ) ]] || [[ ( ! -d "/data" ) ]]; then
  echo "[entrypoint] The /data folder doesn't exist or cannot be written to. Make sure to mount
  a volume or folder to /data to persist data across restarts, and that the current user can
  write to it."
  exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Copying the default config to $CONFIG_FILE"
  echo "[entrypoint] Edit this file to configure LLDAP."
  cp /app/lldap_config.docker_template.toml "$CONFIG_FILE"
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "[entrypoint] Config file is not readable. Check the permissions"
  exit 1
fi

# === Official permission setup (exact upstream) ===
echo "> Setup permissions.."
find /app \! -user lldap -exec chown lldap:lldap '{}' +
find /data \! -user lldap -exec chown lldap:lldap '{}' +

# === Required environment variable checks (safe, upstream-style) ===
if [ -z "${LLDAP_JWT_SECRET:-}" ]; then
    echo "ERROR: LLDAP_JWT_SECRET is required."
    echo "Please set a strong random secret (32+ characters) via environment variable."
    echo "Example: -e LLDAP_JWT_SECRET=\"$(openssl rand -hex 32)\""
    exit 1
fi

if [ -z "${LLDAP_LDAP_BASE_DN:-}" ]; then
    echo "ERROR: LLDAP_LDAP_BASE_DN is required."
    echo "Example: -e LLDAP_LDAP_BASE_DN=\"dc=homelab,dc=local\""
    exit 1
fi

# === Change to /data so LLDAP creates server_key (and everything else) inside the persistent volume naturally ===
echo "> Switching to /data so LLDAP creates server_key inside the volume (no manual handling needed)"
cd /data

# === Start LLDAP with gosu (background so we can start kerberos_manager) ===
echo "Starting LLDAP..."
gosu lldap:lldap /app/lldap "$@" &
LLDAP_PID=$!

# === Wait for LLDAP to be healthy ===
echo "Waiting for LLDAP to become ready (up to 60 seconds)..."
for i in $(seq 1 60); do
    if /app/lldap healthcheck >/dev/null 2>&1; then
        echo "LLDAP is ready!"
        break
    fi
    sleep 1
done

if [ "$i" -eq 60 ]; then
    echo "ERROR: LLDAP failed to start within 60 seconds."
    echo "Check logs above for details (likely missing configuration)."
    kill $LLDAP_PID 2>/dev/null || true
    wait $LLDAP_PID 2>/dev/null || true
    exit 1
fi

# === Start Kerberos manager for Keycloak + ticket passthrough to KDE/GNOME ===
echo "Starting Kerberos manager..."
/app/kerberos_manager &
KERBEROS_PID=$!

# === Clean shutdown ===
trap 'echo "Shutting down..."; kill $LLDAP_PID $KERBEROS_PID 2>/dev/null || true; wait; exit 0' INT TERM

# === Wait for primary process (LLDAP) ===
wait $LLDAP_PID
