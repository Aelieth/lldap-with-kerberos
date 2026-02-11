#!/bin/bash
set -e

mkdir -p /data
chown lldap:lldap /data
mkdir -p /data/keytabs
chown lldap:lldap /data/keytabs
chmod 755 /data/keytabs

# === Required environment variable checks ===
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

# Early Kerberos realm setup (needed before LLDAP starts for sync)
BASE_DN="${LLDAP_LDAP_BASE_DN:-dc=testlab,dc=com}"  # Shared with LLDAP
REALM_NAME="${LLDAP_KERB_REALM_NAME}"  # Allow direct override first
if [ -z "$REALM_NAME" ]; then
    REALM_NAME=$(echo "${BASE_DN}" | sed 's/dc=//g; s/,/\./g' | tr '[:lower:]' '[:upper:]')
fi
REALM_NAME="${REALM_NAME:-TESTLAB.COM}"  # Final fallback
export REALM_NAME
echo "Early REALM_NAME set to ${REALM_NAME} (for LLDAP sync)"

# Start LLDAP (original entrypoint)
echo "Starting LLDAP..."
./docker-entrypoint.sh "$@" &
LLDAP_PID=$!

# Wait for LLDAP to be healthy
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

# Now start Kerberos services
echo "Starting Kerberos manager..."
/app/kerberos_manager &
KERBEROS_PID=$!

# Clean shutdown on signals
trap 'echo "Shutting down..."; kill $LLDAP_PID $KERBEROS_PID 2>/dev/null; wait; exit' INT TERM

# Wait for LLDAP (primary process)
wait $LLDAP_PID
