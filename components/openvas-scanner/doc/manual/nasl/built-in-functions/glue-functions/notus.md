<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# notus

## NAME

**notus** - Evaluate installed packages against the configured local Notus feed

## SYNOPSIS

*array* **notus**(pkg_list: *str|array*, product: *str*);

## DESCRIPTION

The Rust scanner implementation evaluates the supplied package list against
the configured local Notus product data. It performs no direct Notus HTTP
request. `pkg_list` may be a comma-separated string or an array, and `product`
selects the local product definition.

The function returns dictionaries containing `oid` and `message`. Results can
be reported with **[security_notus(3)](../report-functions/security_notus.md)**.
Use **[notus_error(3)](notus_error.md)** after a null result and
**[notus_type(3)](notus_type.md)** to identify the retained result format.

## RETURN VALUE

An array of Notus result dictionaries, or null when evaluation fails.

## SEE ALSO

**[notus_error(3)](notus_error.md)**,
**[notus_type(3)](notus_type.md)**,
**[security_notus(3)](../report-functions/security_notus.md)**
