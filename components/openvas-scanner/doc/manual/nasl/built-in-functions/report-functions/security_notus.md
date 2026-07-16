<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# security_notus

## NAME

**security_notus** - Report a local feed-backed Notus result

## SYNOPSIS

*void* **security_notus**(result: *dict*);

## DESCRIPTION

The Rust scanner implementation accepts one result dictionary from
**[notus(3)](../glue-functions/notus.md)**. The dictionary must contain string
`oid` and `message` fields. It is stored as an alarm result through the scan's
configured result storage; the function performs no direct Notus HTTP request.

## RETURN VALUE

This function returns nothing.

## SEE ALSO

**[notus(3)](../glue-functions/notus.md)**
