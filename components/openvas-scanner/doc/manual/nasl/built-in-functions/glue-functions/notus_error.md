<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# notus_error

## NAME

**notus_error** - Return the last local Notus evaluation error

## SYNOPSIS

*str* **notus_error**();

## DESCRIPTION

Returns the last error produced by the Rust **[notus(3)](notus.md)** built-in.
The value is cleared after a successful evaluation.

## RETURN VALUE

The last error message, or null when no error is recorded.

## SEE ALSO

**[notus(3)](notus.md)**
