<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Retired gvmd Restore Contract

This non-executable characterization record preserves the imported manager
semantics that native restore tests must remain anchored to after the raw GMP
`RESTORE` implementation was deleted. It is evidence, not a supported protocol
or a source implementation.

Authority snapshot: product commit `b27fc730`.

- `components/gvmd/src/manage_sql.c` blob
  `755f7abbf6bf22be71bdc105bbfafdcf5ca2b773`
- `components/gvmd/src/manage_sql_port_lists.c` blob
  `cc17f360a5f009c9d1ab752a28210f0ca9820214`
- `components/gvmd/src/gmp.c` blob
  `e0b5fc7a6eeecaac8af5dd98cbbd5770ef28dec8`

The generic command held the users gate, checked the `restore` permission, and
probed these resource families in order: port list, config, alert, filter,
group, credential, override, permission, role, scanner, schedule, target, and
task. A resource-specific transaction either restored the first matching UUID
or failed closed for missing, conflicting, in-use, or trash-dependent state.

## Alert

- `INSERT INTO alert_condition_data`
- `FROM alert_condition_data_trash WHERE alert = %llu;`
- `INSERT INTO alert_event_data`
- `FROM alert_event_data_trash WHERE alert = %llu;`
- `INSERT INTO alert_method_data`
- `FROM alert_method_data_trash WHERE alert = %llu;`
- `UPDATE task_alerts`
- `DELETE FROM alert_condition_data_trash WHERE alert = %llu;`
- `DELETE FROM alert_event_data_trash WHERE alert = %llu;`
- `DELETE FROM alert_method_data_trash WHERE alert = %llu;`

## Credential

- `INSERT INTO credentials`
- `INSERT INTO credentials_data`
- `FROM credentials_trash_data`
- `UPDATE targets_trash_login_data`
- `UPDATE scanners_trash`
- `tags_set_locations ("credential"`
- `DELETE FROM credentials_trash_data`
- `DELETE FROM credentials_trash`

Secret values remained database-internal during the move. Native restore must
not select, return, or log them.

## Task

- `target_location`
- `config_location`
- `schedule_location`
- `scanner_location`
- `alert_location`
- `permissions_set_locations ("task"`
- `tags_set_locations ("task"`
- `INSERT INTO results`
- `FROM results_trash`
- `DELETE FROM results_trash`
- `DELETE FROM report_counts`
- `UPDATE tasks SET hidden = 0`

Native task restore deliberately improves the imported behavior by remapping
result tag links through stable result UUIDs and by not reviving removed
row-level permission semantics. Those divergences remain explicit in the
native tests and public contract.

## Other Families

- Port list restored metadata and ranges, rebound trashed targets, and moved
  tag locations.
- Config restored metadata and preferences, rejected a trashed scanner
  dependency, rebound tasks, and moved tag locations.
- Filter restored metadata and moved permission and tag locations.
- Group, permission, and role restore belonged to product concepts YAFVS has
  removed; their raw fallback is deleted rather than reimplemented.
- Override restored metadata and moved permission and tag locations.
- Scanner restored metadata, rebound tasks, and moved permission and tag
  locations; native scanner restore additionally preserves relay fields.
- Schedule restored metadata, rebound tasks, and moved permission and tag
  locations.
- Target restored metadata and login rows, rejected trashed credential or port
  list dependencies, rebound tasks, and moved permission and tag locations.

The authoritative snapshot remains recoverable from Git history. Changing this
record requires a new independently identified authority or an explicit,
documented YAFVS divergence; it must never be edited merely to make a native
implementation test pass.
