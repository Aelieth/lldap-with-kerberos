# Extended from original LLDAP Dockerfile (Alpine 3.21 base for lightweight ARM64/x86_64)
FROM rust:alpine3.21 AS builder

# Install build dependencies (same as original + any extras if needed)
RUN apk add --no-cache musl-dev openssl-dev pkgconfig git libclang-dev clang mold

# Clone and build your fork's LLDAP (in repo, this is the source)
WORKDIR /build
COPY . .
RUN cargo build --release --bin lldap_server --bin lldap_migration_tool

# Build frontend (same as original)
WORKDIR /build/frontend
RUN cargo install wasm-pack
RUN wasm-pack build --target web --out-name wasm --out-dir ./static/pkg

# Runtime stage: Alpine with LLDAP + Kerberos
FROM alpine:3.21
RUN apk add --no-cache tzdata gosu openssl libsasl krb5 krb5-server krb5-libs openldap-clients python3 jq bash procps cyrus-sasl-gssapi \
    && update-ca-certificates  # For CA trusts, Alpine-style

# Copy LLDAP binaries and assets
COPY --from=builder /build/target/release/lldap_server /app/lldap
COPY --from=builder /build/target/release/lldap_migration_tool /app/migration_tool
COPY --from=builder /build/frontend/static /app/frontend/static

# Copy Kerberos scripts (make executable)
COPY docker/kerberos/start /usr/bin/start
COPY docker/kerberos/sync-kerberos-principal /usr/bin/sync-kerberos-principal
RUN chmod +x /usr/bin/start /usr/bin/sync-kerberos-principal

# Bundle lldap-cli (copy from subdir, make executable)
COPY docker/kerberos/lldap-cli /usr/bin/lldap-cli
RUN chmod +x /usr/bin/lldap-cli

# Copy config template (extended if needed, but use original for now)
COPY docker/lldap_config.docker_template.toml /app/lldap_config.docker_template.toml

# Volumes: LLDAP data + Kerberos principals
VOLUME /data
VOLUME /var/krb5kdc

# Ports: LLDAP (LDAP/UI) + Kerberos
EXPOSE 3890/tcp 17170/tcp 88/tcp 88/udp 749/tcp

# ENTRYPOINT wrapper for orchestration
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]
