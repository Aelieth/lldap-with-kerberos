#!/bin/bash
# Real sync hook from LLDAP password change
# Args: $1 username, $2 obfuscated_pass (base64 of XOR with ENCODE_KEY)

DOCKER_CONTAINER="kerberos-test"
USERNAME="$1"
OBFUSCATED_PASS="$2"
ENCODE_KEY="${ENCODE_KEY}"  # Shared from env
REALM="${REALM_NAME:-TESTLAB.COM}"  # Flexible—env override or fallback
LOG_FILE="/var/log/krb5/sync.log"  # Log inside container

if [ -z "$ENCODE_KEY" ]; then
    echo "ERROR: ENCODE_KEY missing—cannot deobfuscate" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
    exit 1
fi

if [ -z "$OBFUSCATED_PASS" ]; then
    echo "ERROR: No obfuscated password" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
    exit 1
fi

# Deobfuscate with Python
PLAIN_PASS=$(python3 - <<EOF
import sys
import base64

obfuscated = "$OBFUSCATED_PASS"
key = "$ENCODE_KEY".encode('utf-8')
xored = base64.b64decode(obfuscated)

plain = bytes(x ^ key[i % len(key)] for i, x in enumerate(xored))
sys.stdout.buffer.write(plain)
EOF
)

# Log deobf (temp for debug—remove pw echo later!)
# echo "Deobfuscated password: $PLAIN_PASS" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE

echo "Syncing Kerberos principal $USERNAME@$REALM" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE

# Try cpw first (update if exists)
CPW_OUTPUT=$(docker exec $DOCKER_CONTAINER kadmin.local -q "cpw -pw \"$PLAIN_PASS\" $USERNAME@$REALM" 2>&1)
CPW_STATUS=$?
echo "cpw output: $CPW_OUTPUT" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
if [ $CPW_STATUS -eq 0 ] && [[ $CPW_OUTPUT != *"Principal does not exist"* ]]; then
    echo "Success: Principal $USERNAME@$REALM updated via cpw" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
else
    # Fallback to addprinc
    ADD_OUTPUT=$(docker exec $DOCKER_CONTAINER kadmin.local -q "addprinc -pw \"$PLAIN_PASS\" $USERNAME@$REALM" 2>&1)
    ADD_STATUS=$?
    echo "addprinc output: $ADD_OUTPUT" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
    if [ $ADD_STATUS -eq 0 ]; then
        echo "Success: Principal $USERNAME@$REALM created via addprinc" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
    else
        echo "Failed to create/update principal $USERNAME@$REALM" | docker exec -i $DOCKER_CONTAINER tee -a $LOG_FILE
        exit 1
    fi
fi
