<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Imported gvmd Credential Deletion Characterization

Authority: the YAFVS import of Greenbone `gvmd` at upstream snapshot
`39a51f6`, specifically `manage_sql.c::delete_credential`,
`credential_in_use`, and `trash_credential_in_use`, plus the imported GMP
parser and schema. This artifact records the retained database behavior before
the duplicate C writer and raw `DELETE_CREDENTIAL` transport were removed.

The `credential_in_use` and `trash_credential_in_use` query helpers remain
temporarily because the retained `GET_CREDENTIALS` response uses them to
populate read-side in-use metadata through `SEND_GET_COMMON`. They no longer
own deletion and can leave only when that inherited read response is retired.

## Live Credential Move To Trash

The inherited non-ultimate path:

1. begins one immediate SQL transaction and locks `users`;
2. checks `delete_credential` permission and resolves the live credential;
3. locks the live credential row;
4. rejects use by `targets_login_data`, `scanners`, or live
   `alert_method_data` keys `recipient_credential`, `scp_credential`,
   `smb_credential`, and `pkcs12_credential`;
5. inserts `uuid`, `owner`, `name`, `comment`, `creation_time`,
   `modification_time`, and `type` into `credentials_trash`;
6. copies every `(type, value)` row from `credentials_data` into
   `credentials_trash_data` without interpreting the value;
7. updates `targets_trash_login_data` and `scanners_trash` from
   `credential_location = LOCATION_TABLE` to `LOCATION_TRASH` and replaces the
   live internal id with the new trash internal id;
8. calls `tags_set_locations ("credential", credential, trash_credential,
   LOCATION_TRASH)`;
9. deletes `credentials_data` before `credentials`; and
10. commits atomically.

The imported insert omitted the existing `allow_insecure` column even though
both the live and trash tables contain it. YAFVS deliberately preserves
`allow_insecure` in its lossless metadata move instead of repeating that
omission. Inherited row-level permission-location mutations are intentionally
not retained under YAFVS's trusted scanner-operator team authority model.

## Trashed Credential Permanent Deletion

The inherited ultimate path:

1. resolves the trash credential;
2. rejects use by trash target/scanner references at `LOCATION_TRASH` or by
   trash alert credential keys matching the credential UUID;
3. calls `tags_remove_resource ("credential", credential, LOCATION_TRASH)`;
4. deletes `credentials_trash_data`; and
5. deletes `credentials_trash`.

The YAFVS native hard-delete transaction retains the reference guard, tag-link
cleanup, opaque secret-data deletion, and metadata deletion. It does not
recreate inherited row-level permission orphaning.

## Retired Transport

The inherited public command was `DELETE_CREDENTIAL` with
`credential_id` and `ultimate`. GSA single deletion and gsad generic bulk
deletion both synthesized that raw command. YAFVS native single and sequential
bulk deletion use authenticated HTTP `DELETE /api/v1/credentials/{id}`; the
raw parser, live XML schema command, gsad alias, generic credential bulk
synthesis, and duplicate C lifecycle writer are retired together.
