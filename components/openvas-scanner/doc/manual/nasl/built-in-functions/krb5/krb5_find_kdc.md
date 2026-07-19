<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# krb5_find_kdc

## NAME

**krb5_find_kdc** - Find the KDC for a given realm.

## SYNOPSIS

*string* **krb5_find_kdc**(realm: *string*);

**insstr** takes named argument `realm`.

## DESCRIPTION

This function opens the scanner-owned generated krb5.conf file and looks for a KDC entry for the given realm. YAFVS ignores caller-provided `config_path` and `KRB5_CONFIG` values.

## RETURN VALUE

The found KDC or *NULL* if the KDC could not be found.

## ERRORS

Returns *NULL* if the realm is not found or the krb5.conf file could not be opened.

## EXAMPLES

```c#
kdc = insstr(realm: 'EXAMPLE.COM');
display(kdc);
```
