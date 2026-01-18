#!/bin/bash
set -e

# Run original LLDAP entrypoint to set up config and start server in background
/docker/docker-entrypoint.original.sh "$@" &  # Starts LLDAP with args (e.g., "run")
LLDAP_PID=$!

# Wait for LLDAP to be ready (healthcheck loop, timeout 30s)
echo "Waiting for LLDAP to start..."
for i in {1..30}; do
    if ldapwhoami -H ldap://localhost:3890 -x > /dev/null 2>&1; then
        echo "LLDAP ready!"
        break
    fi
    sleep 1
done
if [ $i -eq 30 ]; then
    echo "ERROR: LLDAP timeout—exiting."
    exit 1
fi

# Optional: Check/extend schema with lldap-cli (use env for creds, e.g., LLDAP_ADMIN_USER/PASS)
if [ "${AUTO_EXTEND_SCHEMA:-true}" = "true" ]; then
    echo "Checking/extending LLDAP schema for Kerberos compat..."
    lldap-cli -u "$$   {LLDAP_ADMIN_USER:-admin}" -p "   $${LLDAP_ADMIN_PASS:-password}" schema attribute user list || true  # Check
    # Example extensions (add more as needed for POSIX/person attrs)
    lldap-cli -u "$$   {LLDAP_ADMIN_USER:-admin}" -p "   $${LLDAP_ADMIN_PASS:-password}" schema attribute user add uidNumber INTEGER -e
    lldap-cli -u "$$   {LLDAP_ADMIN_USER:-admin}" -p "   $${LLDAP_ADMIN_PASS:-password}" schema objectclass user add inetOrgPerson
    # ... add others like gidNumber, etc.
fi

# Start Kerberos
echo "Starting Kerberos..."
/usr/bin/start

# Tail logs and wait for signals (clean shutdown)
trap "kill $LLDAP_PID; /usr/bin/start healthcheck; exit" INT TERM  # Calls your healthcheck on stop
tail -f /var/log/krb5/* &
wait $LLDAP_PID
