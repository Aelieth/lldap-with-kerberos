#!/bin/bash
set -euo pipefail

# === Create all required directories (LLDAP + Kerberos) ===
mkdir -p /data /data/cert /var/lib/krb5kdc /var/kerberos/krb5kdc /var/log/krb5
chown -R lldap:lldap /data /var/lib/krb5kdc /var/kerberos /var/log/krb5

# === Required environment variable checks ===
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

# === Early Kerberos realm setup (needed before LLDAP starts for sync) ===
BASE_DN="${LLDAP_LDAP_BASE_DN:-dc=testlab,dc=com}"
REALM_NAME="${LLDAP_KERB_REALM_NAME:-}"
if [ -z "$REALM_NAME" ]; then
    REALM_NAME=$(echo "${BASE_DN}" | sed 's/dc=//g; s/,/\./g' | tr '[:lower:]' '[:upper:]')
fi
REALM_NAME="${REALM_NAME:-TESTLAB.COM}"
export REALM_NAME
echo "Early REALM_NAME set to ${REALM_NAME} (for LLDAP sync)"

# === Config file handling (exact same as original inner entrypoint) ===
CONFIG_FILE=/data/lldap_config.toml
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[entrypoint] Copying the default config to $CONFIG_FILE"
    echo "[entrypoint] Edit this file to configure LLDAP."
    cp /app/lldap_config.docker_template.toml "$CONFIG_FILE"
    chown lldap:lldap "$CONFIG_FILE"
fi

if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "[entrypoint] Config file is not readable. Check the permissions"
    exit 1
fi

echo "> Fixing ownership on /app assets (binaries, static, pkg).."
find /app \! -user lldap -exec chown lldap:lldap '{}' +

echo "> Forcing DB path via env override (reliable even if config parse issues)"
export LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc"

# === Start LLDAP with gosu (in background so we can start kerberos_manager too) ===
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
