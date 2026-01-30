# Use Alpine 3.21 for lightweight multi-arch (ARM64/x86_64) support
FROM rust:alpine3.21 AS chef

# Install build deps
RUN apk add --no-cache musl-dev openssl-dev pkgconfig make perl curl gzip krb5-dev

# Create lldap user early (UID/GID 1000 to match official — consistent throughout)
RUN addgroup -g 1000 lldap && adduser -D -H -u 1000 -G lldap -h /app lldap

# Switch to lldap for building (no separate 'app' user needed)
USER lldap
WORKDIR /app

# Install cargo-chef and wasm-pack
RUN RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY --chown=lldap:lldap . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY --chown=lldap:lldap . .
RUN cargo build --release -p lldap -p lldap_migration_tool -p lldap_set_password -p lldap-kerberos
RUN cd app && ./build.sh   # Release frontend build

# Final runtime image
FROM alpine:3.21

# Gosu for privilege drop (update to latest stable — 1.17 as of 2024/2025)
ENV GOSU_VERSION=1.17
RUN apk add --no-cache --virtual .gosu-deps ca-certificates dpkg gnupg \
    && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
    && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${dpkgArch}" \
    && wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${dpkgArch}.asc" \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu \
    && gpgconf --kill all \
    && rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc \
    && apk del --no-network .gosu-deps \
    && chmod +x /usr/local/bin/gosu \
    && gosu nobody true

# Recreate lldap user (in case)
RUN addgroup -g 1000 lldap && adduser -D -H -u 1000 -G lldap lldap

# Runtime deps (Kerberos + LLDAP needs)
RUN apk add --no-cache tzdata bash openssl cyrus-sasl cyrus-sasl-gssapiv2 krb5 krb5-server krb5-libs openldap-clients procps ca-certificates sudo \
    && update-ca-certificates

# Pre-create /data with correct ownership (volume will override, but safe start)
RUN mkdir -p /data/cert /var/lib/krb5kdc && chown lldap:lldap /data/ /data/cert /var/lib/krb5kdc

WORKDIR /app

# Copy binaries and frontend assets
COPY --from=builder --chown=lldap:lldap /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password ./
COPY --from=builder --chown=lldap:lldap /app/app/static /app/app/static
COPY --from=builder --chown=lldap:lldap /app/app/pkg /app/app/pkg
COPY --from=builder --chown=lldap:lldap /app/app/index.html /app/app/index.html
COPY --from=builder --chown=lldap:lldap /app/target/release/kerberos_manager ./

# Copy configs and scripts
COPY --chown=lldap:lldap docker/lldap_config.docker_template.toml ./
COPY --chown=lldap:lldap docker/docker-entrypoint.original.sh ./docker-entrypoint.sh
COPY --chown=lldap:lldap scripts/bootstrap.sh ./
COPY --chown=lldap:lldap kerberos/kerberos_config.template.toml /app/kerberos_config.template.toml
COPY --chown=lldap:lldap kerberos/krb5.template.conf /app/krb5.template.conf
COPY --chown=lldap:lldap kerberos/kdc.template.conf /app/kdc.template.conf

RUN chmod +x ./docker-entrypoint.sh

# Setup sudo for root access to kerberos
COPY docker/sudoers-lldap /etc/sudoers.d/lldap
RUN chmod 0440 /etc/sudoers.d/lldap

# Volumes for persistence
VOLUME /data /var/lib/krb5kdc

# Ports
EXPOSE 3890 17170 88/tcp 88/udp 749/tcp

# Wrapper entrypoint (starts LLDAP + Kerberos)
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown lldap:lldap /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]

HEALTHCHECK CMD ["/app/lldap", "healthcheck"]
