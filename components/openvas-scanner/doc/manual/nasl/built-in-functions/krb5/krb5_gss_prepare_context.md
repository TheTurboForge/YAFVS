<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# krb5_gss_prepare_context

## NAME

**krb5_gss_prepare_context** - Creates the initial ticket request for the krb5 GSS-API library and prepares the context for further use.

## SYNOPSIS

*int* **krb5_gss_prepare_context**(realm: str, kdc: str, host: str, service: str, user: str, password: str);

YAFVS generates and uses a scanner-owned `/tmp/krb5_*.conf` path. Caller-provided `config_path` and `KRB5_CONFIG` values are ignored. The listed arguments are required.

- realm - The realm of the domain.
- kdc - The KDC server to use. Can be a comma separated list of servers. The first server in the list is the primary server.
- host - The host to use for the ticket request. Usually the host where the service is running.
- service - The service to request the ticket for.
- user - The user to request the ticket for.
- password - The password of the user.

## DESCRIPTION

When krb5_gss_prepare_context is called it creates the initial ticket request for the krb5 GSS-API library and prepares the context for further use.

It can be used directly without calling krb5_gss_init first.

## RETURN VALUE

Returns 0 on success otherwise it is an failure.

## EXAMPLES

```c#
login       = string( get_kb_item( "KRB5/login_filled/0" ) );
password    = string( get_kb_item( "KRB5/password_filled/0" ) );
realm = string( get_kb_item( "KRB5/realm_filled/0" ) );
kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
host        = ip_reverse_lookup(); # must be a domain name.

result = krb5_gss_prepare_context(realm: realm, kdc: kdc, host: host, service: 'cifs', user: login, password: passwod);
if (krb5_is_failure(result)) {
	exit(42);
}
```
