# LLDAP with Kerberos

DISCLAIMER:
WORK IN PROGRESS and my first foray into Rust. Use with optimistic caution!
This is a lightweight LDAP server (LLDAP) with integrated MIT Kerberos KDC, designed for home/lab SSO federation.

This Docker image combines LLDAP 0.6.2 (simple LDAP auth) with a local Kerberos realm, enabling seamless single sign-on for Linux desktops (KDE/Gnome via SSSD), apps such as Nextcloud, and federation with Keycloak.

Based on the original containers-kerberos, heavily customized for LLDAP integration:
- Automatic schema extensions for POSIX attributes (uidNumber, gidNumber, loginShell).
- Kerberos principal sync on user create/password change (revokes old tickets immediately).
- Principal deletion on user delete.
- Configurable realm/domain derived from LDAP base DN.
- Multi-arch support (AMD64/ARM64, tested on ZimaBlade/ZimaOS).

## Features

- Lightweight Alpine-based image.
- Based off of LLDAP for user/group management.
- MIT Kerberos KDC + admin server in one container.
- One-time schema extension for POSIX/Kerberos compatibility.
- Environment-driven config.
- Persistence via volumes (/data for LLDAP, /var/lib/krb5kdc for Kerberos DB).
- In memory obfuscation of PW during user creation
- aes256 encryption between LLDAP and Kerberos

## Quick Start

Run with these common switches (adjust values!):
      
      docker run -d --name lldap-kerberos \
        -p 3890:3890 -p 17170:17170 -p 88:88/tcp -p 88:88/udp -p 749:749/tcp \
        -e LLDAP_JWT_SECRET="SuperSafeJWT1234567890abcdefABCDEF1234" \
        -e LLDAP_KEY_SEED="SuperSafeKeySeed4567890ghijklMNOP1234" \
        -e ENCODE_KEY="my-super-secret-shared-key-123!" \
        -e LLDAP_LDAP_BASE_DN="dc=testlab,dc=com" \
        -e MASTER_PASS="your-strong-master-pass!" \
        -e ADMIN_PASS="your-strong-admin-pass!" \
        -e LLDAP_LDAP_USER_PASS="adminpassword123!" \
        -v /tmp/data:/data -v /tmp/krb5kdc:/var/lib/krb5kdc \
        ghcr.io/aelieth/lldap-with-kerberos:latest

Access UI at http://localhost:17170 (admin / your LLDAP_LDAP_USER_PASS). Realm auto-derives as EXAMPLE.COM.

## Environment Variables

LLDAP vars use LLDAP_ prefix. Kerberos-specific use KERB_ prefix.

| Variable             | Required  | Default                                | Description                                                |
|----------------------|-----------|----------------------------------------|------------------------------------------------------------|
| LLDAP_JWT_SECRET     | Yes       | SuperSafeJWT1234567890abcdefABCDEF1234 | JWT signing secret for LLDAP sessions. 
| LLDAP_LDAP_USER_PASS | Yes       | adminpassword123!                      | Initial admin password (change on first login). 
| LLDAP_LDAP_BASE_DN   | No        | dc=testlab,dc=com                      | LDAP base DN. Used to derive realm/domain. 
| ENCODE_KEY           | Yes       | my-super-secret-shared-key-123!        | Shared secret for password sync between LLDAP and Kerberos. 
| KERB_MASTER_PASS     | Yes       | your-strong-master-pass!               | Kerberos database master password. 
| KERB_ADMIN_PASS      | Yes       | your-strong-admin-pass!                | Password for Kerberos admin principal (admin/admin@REALM). 
| KERB_REALM_NAME      | No        | Derived from BASE_DN                   | Override auto-derived realm. 
| KERB_BASE_DN         | No        | Uses LLDAP_LDAP_BASE_DN                | Override base DN for realm derivation. 
| KERB_KDC_PORT        | No        | 88                                     | Kerberos KDC port. 
| KERB_ADMIN_PORT      | No        | 749                                    | Kerberos admin server port. 
| KERB_TICKET_LIFETIME | No        | 24h                                    | Default ticket lifetime. 
| KERB_RENEW_LIFETIME  | No        | 7d                                     | Ticket renewal lifetime. 

Persisted non-secret config in /data/kerberos_config.toml on first run.

## Volumes

- /data: LLDAP config, users, groups.
- /var/lib/krb5kdc: Kerberos database (critical!).

## Exposed Ports

- 3890: LLDAP LDAP
- 17170: LLDAP Web UI
- 88/tcp+udp: Kerberos KDC
- 749/tcp: Kerberos admin

## License

AGPL-3.0 (matches upstream LLDAP). See LICENSE file.

## Credits

- Base container and LDAP bootstrap logic: RobinR1/containers-kerberos
- LLDAP server: lldap/lldap
- lldap-cli tool: Zepmann/lldap-cli
- Keycloak integration inspiration: keycloak/keycloak

This repository is under active development. Built for home/lab SSO.
