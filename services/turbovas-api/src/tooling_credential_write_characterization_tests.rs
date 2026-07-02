// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

const CREATE_CREDENTIALS_CSV: &str =
    include_str!("../../../components/gvm-tools/scripts/create-credentials-from-csv.gmp.py");

#[test]
fn inherited_create_credentials_from_csv_resolves_duplicates_and_csv_fields() {
    for required in [
        "gmp.get_credentials(filter_string=\"rows=-1, name=\" + credName)",
        "content = csv.reader(csvFile, delimiter=\",\")",
        "cred_name = row[0]",
        "cred_type = row[1]",
        "userName = row[2]",
        "userPW = row[3]",
        "comment = f\"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}\"",
        "if credential_id(gmp, cred_name):",
        "Credential: {cred_name} exist, not creating...",
        "error_and_exit(f\"Failed to read cred_file: {str(e)} (exit)\")",
        "error_and_exit(\"Credentials file is empty (exit)\")",
    ] {
        assert!(
            CREATE_CREDENTIALS_CSV.contains(required),
            "create-credentials-from-csv missing {required}"
        );
    }
}

#[test]
fn inherited_create_credentials_from_csv_username_password_branch_passes_secret_fields() {
    for required in [
        "if cred_type == \"UP\":",
        "gmp.create_credential(",
        "name=cred_name",
        "credential_type=gmp.types.CredentialType.USERNAME_PASSWORD",
        "login=userName",
        "password=userPW",
        "comment=comment",
    ] {
        assert!(
            CREATE_CREDENTIALS_CSV.contains(required),
            "create-credentials-from-csv UP branch missing {required}"
        );
    }
}

#[test]
fn inherited_create_credentials_from_csv_ssh_branch_reads_private_key_file() {
    for required in [
        "elif cred_type == \"SSH\":",
        "with open(row[4]) as key_file:",
        "key = key_file.read()",
        "credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY",
        "login=userName",
        "key_phrase=userPW",
        "private_key=key",
        "comment=comment",
    ] {
        assert!(
            CREATE_CREDENTIALS_CSV.contains(required),
            "create-credentials-from-csv SSH branch missing {required}"
        );
    }
}

#[test]
fn inherited_create_credentials_from_csv_snmp_and_esx_are_unfinished_ssh_key_copies() {
    for required in [
        "elif cred_type == \"SNMP\":",
        "# Unfinished, copy of UP for now",
        "elif cred_type == \"ESX\":",
        "credential_type=gmp.types.CredentialType.USERNAME_SSH_KEY",
        "key_phrase=userPW",
        "private_key=key",
    ] {
        assert!(
            CREATE_CREDENTIALS_CSV.contains(required),
            "create-credentials-from-csv unfinished SNMP/ESX branch missing {required}"
        );
    }
}
