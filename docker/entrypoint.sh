#!/bin/bash
set -e

# Early Kerberos realm setup (needed before LLDAP starts for sync)
BASE_DN="${LLDAP_LDAP_BASE_DN:-dc=testlab,dc=com}"  # Shared with LLDAP
REALM_NAME="${LLDAP_KERB_REALM_NAME}"  # Allow direct override first
if [ -z "$REALM_NAME" ]; then
    REALM_NAME=$(echo "${BASE_DN}" | sed 's/dc=//g; s/,/\./g' | tr '[:lower:]' '[:upper:]')
fi
REALM_NAME="${REALM_NAME:-TESTLAB.COM}"  # Final fallback
export REALM_NAME
echo "Early REALM_NAME set to ${REALM_NAME} (for LLDAP sync)"

mkdir -p /data
chown lldap:lldap /data

# Start LLDAP
echo "Starting LLDAP..."
./docker-entrypoint.sh "$@" &
LLDAP_PID=$!

# Sleep 1 for head start, then healthcheck
sleep 1
echo "Waiting for LLDAP..."
for i in {1..60}; do
    if /app/lldap healthcheck; then
        echo "LLDAP ready!"
        break
    fi
    sleep 1
done
if [ $i -eq 60 ]; then
    echo "ERROR: LLDAP timeout."
    kill $LLDAP_PID
    exit 1
fi

echo "Starting Kerberos services via kerberos_manager..."
/app/kerberos_manager &
KERBEROS_PID=$!

# Trap shutdown
trap 'echo "Shutting down..."; kill $LLDAP_PID; kill $KERBEROS_PID; exit' INT TERM

# Wait on LLDAP
wait $LLDAP_PID
