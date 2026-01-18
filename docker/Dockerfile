# Extended from original LLDAP Dockerfile (Alpine 3.21 base)
FROM rust:alpine3.21 AS builder

# Install build deps (aligned with original + git for any cloning)
RUN apk add --no-cache musl-dev openssl-dev pkgconfig make perl curl gzip git clang-dev llvm-dev mold

# User setup (from original)
RUN addgroup --gid 10001 app && adduser --disabled-password --gecos '' --ingroup app --home /app --uid 10001 app

USER app
WORKDIR /app

RUN RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef && rustup target add wasm32-unknown-unknown

# Prepare deps (from original)
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build deps
RUN cargo chef cook --release --recipe-path recipe.json

# Build binaries and frontend
RUN cargo build --release -p lldap -p lldap_migration_tool -p lldap_set_password
RUN cd app && ./build.sh  # Assuming your fork has this

# Runtime stage
FROM alpine:3.21

# Fetch gosu manually (from original—required for privilege drop)
ENV GOSU_VERSION=1.14
RUN apk add --no-cache --virtual .gosu-deps ca-certificates dpkg gnupg \
    && dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" \
    && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch" \
    && wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc" \
    && export GNUPGHOME="$(mktemp -d)" \
    && gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu \
    && gpgconf --kill all \
    && rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc \
    && apk del --no-network .gosu-deps \
    && chmod +x /usr/local/bin/gosu \
    && gosu nobody true

# Install runtime deps + Kerberos (fixed names: cyrus-sasl for libsasl, cyrus-sasl-gssapiv2)
RUN apk add --no-cache tzdata bash openssl cyrus-sasl cyrus-sasl-gssapiv2 krb5 krb5-server krb5-libs openldap-clients python3 jq procps \
    && update-ca-certificates

WORKDIR /app

# Copy LLDAP artifacts (from original + your fork)
COPY --from=builder /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password ./
COPY --from=builder /app/app/static /app/static
COPY --from=builder /app/app/pkg /app/pkg
COPY --from=builder /app/app/index_local.html /app/index.html  # If your fork has this

# Copy configs/scripts
COPY docker/lldap_config.docker_template.toml ./
COPY docker/docker-entrypoint.original.sh ./docker-entrypoint.sh  # Use original as base
COPY scripts/bootstrap.sh ./
COPY docker/kerberos/start /usr/bin/start
COPY docker/kerberos/sync-kerberos-principal /usr/bin/sync-kerberos-principal
COPY docker/kerberos/lldap-cli /usr/bin/lldap-cli
RUN chmod +x /usr/bin/start /usr/bin/sync-kerberos-principal /usr/bin/lldap-cli ./docker-entrypoint.sh

# Volumes/Ports (extended for Kerberos)
VOLUME /data /var/krb5kdc
EXPOSE 3890 17170 88/tcp 88/udp 749/tcp

# Our custom ENTRYPOINT
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]

HEALTHCHECK CMD ["/app/lldap", "healthcheck"]
