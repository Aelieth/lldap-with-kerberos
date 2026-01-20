# Extended from original LLDAP Dockerfile (Alpine 3.21 base for lightweight ARM64/x86_64)
FROM rust:alpine3.21 AS chef

RUN apk add --no-cache musl-dev openssl-dev pkgconfig make perl curl gzip

RUN addgroup --gid 10001 app && adduser --disabled-password --gecos '' --ingroup app --home /app --uid 10001 app
USER app
WORKDIR /app
RUN RUSTFLAGS=-Ctarget-feature=-crt-static cargo install wasm-pack cargo-chef && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY --chown=app:app . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY --chown=app:app . .
RUN cargo build --release -p lldap -p lldap_migration_tool -p lldap_set_password
RUN cd app && ./build.sh

FROM alpine:3.21

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

ENV UID=10001
ENV GID=10001

RUN apk add --no-cache tzdata bash openssl cyrus-sasl cyrus-sasl-gssapiv2 krb5 krb5-server krb5-libs openldap-clients python3 jq procps ca-certificates gettext \
    && update-ca-certificates

WORKDIR /app

COPY --from=builder /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password ./
COPY --from=builder /app/app/static /app/app/static
COPY --from=builder /app/app/pkg /app/app/pkg
COPY --from=builder /app/app/index_local.html /app/app/index.html

COPY docker/lldap_config.docker_template.toml ./
COPY docker/docker-entrypoint.original.sh ./docker-entrypoint.sh
COPY scripts/bootstrap.sh ./
COPY docker/kerberos/start /usr/bin/start
COPY docker/kerberos/sync-kerberos-principal /usr/bin/sync-kerberos-principal
COPY docker/kerberos/lldap-cli /usr/bin/lldap-cli
COPY docker/kerberos/krb5.template.conf /app/krb5.template.conf
COPY docker/kerberos/kdc.template.conf /app/kdc.template.conf
COPY docker/kerberos/kerberos_config.template.toml /app/kerberos_config.template.toml
RUN chmod +x /usr/bin/start /usr/bin/sync-kerberos-principal /usr/bin/lldap-cli ./docker-entrypoint.sh

VOLUME /data /var/lib/krb5kdc

EXPOSE 3890 17170 88/tcp 88/udp 749/tcp

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]

HEALTHCHECK CMD ["/app/lldap", "healthcheck"]
