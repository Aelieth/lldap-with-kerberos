#!/bin/bash
set -e

KERBEROS_ENABLED="${KERBEROS_ENABLED:-true}"

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

if [ -n "${ENCODE_KEY:-}" ]; then
    echo "ENCODE_KEY detected — starting Kerberos services..."
    /usr/bin/kerberos-start &
    KERBEROS_PID=$!
fi

# Trap shutdown
trap 'echo "Shutting down..."; kill $LLDAP_PID; if [ -n "{ENCODE_KEY:-}" ]; then kill $KERBEROS_PID; /usr/bin/kerberos-start healthcheck; fi; exit' INT TERM

# Wait on LLDAP
wait $LLDAP_PID
