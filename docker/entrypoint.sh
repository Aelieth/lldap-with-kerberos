#!/bin/bash
set -e

KERBEROS_ENABLED="${KERBEROS_ENABLED:-true}"

# Run original LLDAP entrypoint to set up config and start server in background
./docker-entrypoint.sh "$@" &
LLDAP_PID=$!

# Wait for LLDAP to be ready (use built-in healthcheck, timeout 60s for DB upgrades)
echo "Waiting for LLDAP to start..."
for i in {1..60}; do
    if /app/lldap healthcheck > /dev/null 2>&1; then
        echo "LLDAP ready! Exit code: $?"
        break
    fi
    echo "Healthcheck attempt $i failed. Exit code: $?"
    sleep 1
done
if [ $i -eq 60 ]; then
    echo "ERROR: LLDAP timeout—exiting."
    exit 1
fi

# Optional: Check/extend schema with lldap-cli (use env for creds)
if [ "$KERBEROS_ENABLED" = "true" ] && [ "${AUTO_EXTEND_SCHEMA:-true}" = "true" ]; then
    echo "Checking/extending LLDAP schema for Kerberos compat..."
    # Set lldap-cli envs (internal to container)
    export httpUrl="http://localhost:17170"
    export httpAuthEndpoint="/auth/simple/login"
    export httpGraphQlEndpoint="/api/graphql"
    /usr/bin/lldap-cli --user "${LLDAP_LDAP_USER_DN:-admin}" --pass "${LLDAP_LDAP_USER_PASS:-password}" schema attribute user list || true
    /usr/bin/lldap-cli --user "${LLDAP_LDAP_USER_DN:-admin}" --pass "${LLDAP_LDAP_USER_PASS:-password}" schema attribute user add uidNumber INTEGER -e || true
    /usr/bin/lldap-cli --user "${LLDAP_LDAP_USER_DN:-admin}" --pass "${LLDAP_LDAP_USER_PASS:-password}" schema objectclass user add inetOrgPerson || true
fi

# Start Kerberos if enabled
if [ "$KERBEROS_ENABLED" = "true" ]; then
    echo "Starting Kerberos..."
    /usr/bin/start
fi

# Tail logs and wait for signals (clean shutdown)
trap "kill $LLDAP_PID; /usr/bin/start healthcheck; exit" INT TERM
tail -f /var/log/krb5/* &
wait $LLDAP_PID
