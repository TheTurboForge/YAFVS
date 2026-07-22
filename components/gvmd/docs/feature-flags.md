<!-- TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>. -->

# Feature Flags Overview

## Where the Configuration File Is Located

**gvmd** reads runtime feature flags from:

```
/etc/gvm/gvmd.conf
```

(or system defines as `GVM_SYSCONF_DIR`)

Inside this file, feature flags appear under the `[features]` section.

---

## Example Configuration File Section

```
[features]
enable_openvasd = false
enable_vt_metadata = false
enable_security_intelligence_export = false
enable_jwt_auth = false
```

Each line is optional.
If a line is missing, gvmd does not apply a value from the config file.

---

## Complete Feature Flag Table

| Feature                             | **Build-Time Flag** (decides if feature exists in binary) | **Runtime Environment Variable**            | **Config File Key** (inside `[features]`) |
|-------------------------------------|-----------------------------------------------------------|---------------------------------------------|-------------------------------------------|
| OpenVASd Integration                | `ENABLE_OPENVASD`                                         | `GVMD_ENABLE_OPENVASD`                      | `enable_openvasd`                         |
| VT Metadata Feed                    | Always exists in binary                                   | `GVMD_ENABLE_VT_METADATA`                   | `enable_vt_metadata`                      |
| Security Intelligence Report Export | Always exists in binary                                   | `GVMD_ENABLE_SECURITY_INTELLIGENCE_EXPORT`  | `enable_security_intelligence_export`     |
| JSON web token authentication       | `ENABLE_JWT_AUTH`                                         | `GVMD_ENABLE_JWT_AUTH`                      | `enable_jwt_auth`                         |
---

## Accepted Runtime Values

These values work both in environment variables and in the config file:

**Enable:**
`1`, `true`, `yes`, `on`

**Disable:**
`0`, `false`, `no`, `off`

(Case-insensitive, whitespace ignored.)

---

## How gvmd Decides the Final Value

Order of priority:

1. **Build-time flag** if a feature is not compiled in, it can never be enabled.
2. **Environment variable** overrides config file.
3. **Configuration file** used if no environment variable is set.
4. **Default** feature becomes disabled.

**NOTE**: After changing the config file or environment variables, restart **gvmd** to apply the changes.

## Disabled Commands

When a feature is disabled, gvmd automatically removes related commands from the protocol.

### Security intelligence export disabled - these commands are hidden

```
get_integration_configs
modify_integration_config
```

---
