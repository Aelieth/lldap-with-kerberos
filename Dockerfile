# Use Fedora minimal for builder and runtime (glibc consistency + latest Cargo + reliable bindgen)
FROM registry.fedoraproject.org/fedora-minimal:latest AS chef

# Install build deps (Fedora packages)
RUN microdnf install -y --assumeyes \
    shadow-utils pkgconf openssl-devel gcc make perl curl gzip krb5-devel clang llvm \
    && microdnf clean all

# Create /app directory and lldap user (home = /app)
RUN mkdir -p /app && \
    groupadd -g 1000 lldap && \
    useradd -u 1000 -g lldap -d /app -s /bin/bash lldap && \
    chown -R lldap:lldap /app

USER lldap
WORKDIR /app

# Install latest Rust/Cargo via rustup as lldap user
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Add Cargo to PATH
ENV PATH="/app/.cargo/bin:${PATH}"

# Verify Rust/Cargo
RUN rustc --version && cargo --version

# Install cargo-chef for dependency caching, add wasm target
RUN cargo install cargo-chef && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY --chown=lldap:lldap . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY --chown=lldap:lldap . .
RUN cargo build --release -p lldap -p lldap_migration_tool -p lldap_set_password -p lldap-kerberos
RUN cargo install wasm-pack  # Ensure wasm-pack available for frontend build
RUN cd app && wasm-pack build --target web --release
RUN cd app && gzip -9 -k -f pkg/lldap_app_bg.wasm

# Final runtime image (Fedora-minimal for glibc consistency)
FROM registry.fedoraproject.org/fedora-minimal:latest

# Gosu for privilege drop
ENV GOSU_VERSION=1.17
RUN microdnf install -y --assumeyes ca-certificates dpkg gnupg wget && \
    dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')" && \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${dpkgArch}" && \
    wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${dpkgArch}.asc" && \
    export GNUPGHOME="$(mktemp -d)" && \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 && \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu && \
    gpgconf --kill all && \
    rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc && \
    chmod +x /usr/local/bin/gosu && \
    gosu nobody true && \
    microdnf clean all

# Recreate lldap user
RUN groupadd -g 1000 lldap && \
    useradd -u 1000 -g lldap -d /app -s /bin/bash lldap && \
    chown -R lldap:lldap /app

# Runtime deps (Kerberos + LLDAP needs)
RUN microdnf install -y --assumeyes \
    tzdata bash openssl cyrus-sasl-gssapi krb5-server krb5-libs krb5-workstation openldap-clients procps-ng ca-certificates sudo strace \
    && microdnf clean all

# Pre-create /data with correct ownership
RUN mkdir -p /data/cert /var/kerberos/krb5kdc /var/log/krb5 && \
    chown -R lldap:lldap /data /data/cert /var/kerberos/krb5kdc /var/log/krb5

WORKDIR /app

# Copy binaries and frontend assets
COPY --from=builder --chown=lldap:lldap /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password ./
COPY --from=builder --chown=lldap:lldap /app/app/static /app/app/static
COPY --from=builder --chown=lldap:lldap /app/app/pkg /app/app/pkg
COPY --from=builder --chown=lldap:lldap /app/app/index.html /app/app/index.html
COPY --from=builder --chown=lldap:lldap /app/target/release/kerberos_manager ./

# Copy configs and scripts (all now at root)
COPY --chown=lldap:lldap lldap_config.docker_template.toml ./
COPY --chown=lldap:lldap scripts/bootstrap.sh ./
COPY --chown=lldap:lldap kerberos/kerberos_config.template.toml /app/kerberos_config.template.toml
COPY --chown=lldap:lldap kerberos/krb5.template.conf /app/krb5.template.conf
COPY --chown=lldap:lldap kerberos/kdc.template.conf /app/kdc.template.conf
COPY --chown=lldap:lldap kerberos/kadm5.template.acl /app/kadm5.template.acl
COPY --chown=lldap:lldap kerberos/keycloak_config.template.toml /app/keycloak_config.template.toml

# Our combined wrapper entrypoint (LLDAP + Kerberos manager + Keycloak readiness)
COPY --chown=lldap:lldap entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Setup sudo for kadmin.local (NOPASSWD for kerberos_manager)
COPY sudoers-lldap /etc/sudoers.d/lldap
RUN chmod 0440 /etc/sudoers.d/lldap

# Volumes for persistence
VOLUME /data /var/kerberos/krb5kdc

# Ports (LDAP + HTTP + Kerberos)
EXPOSE 3890 17170 88/tcp 88/udp 749/tcp

# Wrapper entrypoint (starts LLDAP + Kerberos manager)
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run"]

HEALTHCHECK CMD ["/app/lldap", "healthcheck"]
