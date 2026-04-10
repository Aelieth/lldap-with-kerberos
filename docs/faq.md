# Frequently Asked Questions

- [I can't login](#i-cant-log-in)
- [Migrating from SQLite](#migrating-from-sqlite)
- How does KLLDAP compare [with OpenLDAP](#how-does-kllldap-compare-with-openldap)? [With FreeIPA](#how-does-kllldap-compare-with-freeipa)? [With Kanidm](#how-does-kllldap-compare-with-kanidm)?
- [Does KLLDAP support vhosts?](#does-kllldap-support-vhosts)
- [Does KLLDAP provide commercial support contracts?](#does-kllldap-provide-commercial-support-contracts)
- [Is KLLDAP sustainable? Can we depend on it for our infrastructure?](#is-kllldap-sustainable-can-we-depend-on-it-for-our-infrastructure)

## I can't log in!

If you just set up the server, can get to the login page but the password you set isn't working, try the following:

- The config password (`LLDAP_LDAP_USER_PASS`) is only used for the initial admin creation. Changing it later has no effect unless you reset the admin user.
- For Docker: Make sure the `/data` volume is persistent (docker volume or host mount).
- Check that `lldap_config.toml` exists in `/data` (or the working directory). If missing, copy the template and fill in the required values.
- Check that `users.db` (or your chosen database) exists and the container user (UID 10001) has write access to `/data`.
- Restart the container after any config changes.
- Verify `LLDAP_LDAP_BASE_DN` is set (required for Kerberos realm derivation).

## Migrating from SQLite

If you started with an SQLite database and would like to migrate to MySQL/MariaDB or PostgreSQL, check out the [DB migration docs](/docs/database_migration.md). Note that KLLDAP v12 migration also seeds the new `system_config` table and `allowedous`.

## How does KLLDAP compare with OpenLDAP?

[OpenLDAP](https://www.openldap.org) is a full-featured, highly configurable LDAP server. It is very powerful but complex to set up and maintain.

KLLDAP is a lightweight fork focused on simplicity and modern features (integrated MIT Kerberos KDC, admin-controlled OUs, Keycloak federation). It is much easier to run and includes a purpose-built web UI, but it is intentionally less flexible than OpenLDAP.

## How does KLLDAP compare with FreeIPA?

[FreeIPA](http://www.freeipa.org) is a complete identity management solution (LDAP + Kerberos + DNS + more).

KLLDAP is a much lighter alternative: integrated Kerberos KDC + Keycloak federation + OU system in a single small Docker container. It does not include DNS, certificate management, or full policy engines. Perfect for home/lab SSO where you want Kerberos and Keycloak without the full FreeIPA stack.

## How does KLLDAP compare with Kanidm?

[Kanidm](https://kanidm.com) is a modern Rust-based identity platform with OAuth, WebAuthn, and a read-only LDAPS server.

KLLDAP keeps full read-write LDAP support plus an integrated MIT Kerberos KDC and one-click Keycloak federation. It is a direct evolution of the original LLDAP code rather than a from-scratch rewrite.

## Does KLLDAP support vhosts?

KLLDAP does not natively support virtualhosts / multi-tenancy:

- All users share the same base DN.
- Multiple domains can be handled via fully-qualified email addresses as usernames, but permissions and OUs are global.

If you need true multi-tenancy, run multiple isolated KLLDAP instances.

## Does KLLDAP provide commercial support contracts?

No. KLLDAP is a personal hobby project and completely separate fork from the original LLDAP. It is developed on a best-effort basis by one person. There is no commercial support, Discord server, or official community.

## Is KLLDAP sustainable? Can we depend on it for our infrastructure?

KLLDAP is a personal project — a “half-brother” to the original LLDAP. It shares the same foundational LDAP + web UI code but has been heavily modified with Kerberos KDC, OU system, Keycloak federation, and a single-source-of-truth schema.

It is built for my own home/lab use and shared as-is. Bus factor is 1. You are free to use it (AGPL-3.0), but treat it as hobbyist software. Do not rely on it for critical production infrastructure unless you are prepared to maintain or fork it yourself.
