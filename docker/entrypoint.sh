#!/bin/bash
set -e

KERBEROS_ENABLED="${KERBEROS_ENABLED:-true}"  # Bool to toggle Kerberos (optional, default true)
FORCE_UPDATE="${FORCE_UPDATE:-false}"  # Bool to force conf update on env change (optional, default false)
AUTO_EXTEND_SCHEMA="${AUTO_EXTEND_SCHEMA:-true}"  # Bool to auto-add schema entries (optional, default true)
LDAP_URL="${LDAP_URL:-ldap://localhost:3890}"  # LDAP URL (optional, default internal localhost:3890; change for external)
DM_DN="${DM_DN:-${LLDAP_LDAP_USER_DN:-uid=admin,ou=people,dc=testlab,dc=com}}"  # Dir manager DN (optional, mapped from LLDAP)
DM_PASS="${DM_PASS:-${LLDAP_LDAP_USER_PASS:-adminpassword123!}}"  # Dir manager pw (required for auth; mapped from LLDAP)
BASE_DN="${BASE_DN:-${LLDAP_LDAP_BASE_DN:-dc=testlab,dc=com}}"  # Base DN (optional, mapped from LLDAP)
REALM_NAME="${REALM_NAME:-TESTLAB.COM}"  # Kerberos realm (optional, default TESTLAB.COM)
KDC_DN="${KDC_DN:-uid=krbkdc,ou=people,${BASE_DN}}"  # KDC DN (optional, default based on base DN)
ADMIN_DN="${ADMIN_DN:-uid=krbadm,ou=people,${BASE_DN}}"  # Admin DN (optional, default based on base DN)
CONTAINER_DN="${CONTAINER_DN:-cn=kerberos,ou=groups,${BASE_DN}}"  # Container DN (optional, default based on base DN)

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

# Schema setup with ldapadd (from sources' start example, flexible envs)
if [ "$KERBEROS_ENABLED" = "true" ] && [ "${AUTO_EXTEND_SCHEMA:-true}" = "true" ]; then
    echo "Setting up Kerberos entries in LLDAP with ldapadd (per sources)..."
    ldap_url="ldap://localhost:3890"
    # ldap_create_person function from sources
    ldap_create_person() {
        local ldap_url=$1
        local dn=$2
        local sn=$3

        echo "  - Adding user $sn at $dn"
        ldapadd -H $ldap_url -x -D "${DM_DN}" -w "${DM_PASS}" <<EOL
dn: $dn
objectClass: person
objectClass: top
objectClass: inetOrgPerson
objectClass: posixAccount
sn: $sn
cn: $sn
uid: $sn
mail: ${sn}@service.${REALM_NAME,,}
EOL
        status=$?
        if [ $status -ne 0 ] && [ $status -ne 68 ]; then
            echo "WARNING: Failed adding $dn (status $status)—continuing with local fallback."
        fi
    }
    # Individual checks and calls for needed entries (check with ldapsearch, add if not exist)
    for entry in "${CONTAINER_DN}" "${KDC_DN}" "${ADMIN_DN}"; do
        sn=$(echo $entry | cut -d= -f2 | cut -d, -f1)  # Extract sn from DN
        if ldapsearch -H $ldap_url -x -b "$entry" -D "${DM_DN}" -w "${DM_PASS}" > /dev/null 2>&1; then
            echo "Entry $entry exists—skipping add."
        else
            ldap_create_person "$ldap_url" "$entry" "$sn"
        fi
    done
fi

if [ "$KERBEROS_ENABLED" = "true" ]; then
    echo "Starting Kerberos..."
    /usr/bin/start
fi

# Tail logs and wait for signals (clean shutdown)
trap "kill $LLDAP_PID; /usr/bin/start healthcheck; exit" INT TERM
tail -F /var/log/krb5/* &
wait $LLDAP_PID
