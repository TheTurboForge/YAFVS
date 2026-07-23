/* Copyright (C) 2009-2021 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file gsad_gmp.h
 * @brief Headers for GSA's GMP communication module.
 */

#ifndef _GSAD_GMP_H
#define _GSAD_GMP_H

#include "gsad_command_response_data.h" /* for gsad_command_response_data_t */
#include "gsad_content_type.h"          /* for content_type */
#include "gsad_http.h"                  /* for gsad_http_connection_t */
#include "gsad_user.h"                  /* for credentials_t */

#include <glib.h>                 /* for gboolean */
#include <gvm/util/serverutils.h> /* for gvm_connection_t */

gsad_http_result_t
exec_gmp_get (gsad_http_connection_t *connection,
              gsad_connection_info_t *con_info,
              gsad_credentials_t *credentials);

gsad_http_result_t
exec_gmp_post (gsad_http_connection_t *connection,
               gsad_connection_info_t *con_info,
               gsad_credentials_t *credentials);

char *
create_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
delete_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
save_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
start_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
stop_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
move_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);

char *
get_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
              gsad_command_response_data_t *);
char *
get_tasks_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
get_tasks_chart_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                     gsad_command_response_data_t *);
char *
export_task_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
export_tasks_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);

char *
delete_report_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
get_report_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);



char *
get_reports_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);

char *
download_ssl_cert (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
download_ca_pub (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
download_key_pub (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);

char *
export_result_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
export_results_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                    gsad_command_response_data_t *);

char *
create_credential_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                       gsad_command_response_data_t *);
char *
save_credential_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                     gsad_command_response_data_t *);

char *
get_aggregate_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);

char *
create_target_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
delete_target_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
save_target_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);

char *
get_config_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
get_configs_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
save_config_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
edit_config_family_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                        gsad_command_response_data_t *);
char *
edit_config_family_all_gmp (gvm_connection_t *, gsad_credentials_t *,
                            params_t *, gsad_command_response_data_t *);
char *
get_config_family_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                       gsad_command_response_data_t *);
char *
save_config_family_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                        gsad_command_response_data_t *);
char *
delete_config_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);

char *
export_preference_file_gmp (gvm_connection_t *, gsad_credentials_t *,
                            params_t *, gsad_command_response_data_t *);
char *
get_slave_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
get_slaves_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
create_slave_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
save_slave_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
delete_slave_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
export_slave_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
export_slaves_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);

char *
get_resource_names_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                        gsad_command_response_data_t *);

char *
sync_feed_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
sync_scap_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
sync_cert_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);


char *
bulk_delete_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
bulk_export_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);

char *
get_settings_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
get_setting_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                 gsad_command_response_data_t *);
char *
save_setting_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
get_info_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
              gsad_command_response_data_t *);
char *
get_info (gvm_connection_t *, gsad_credentials_t *, params_t *, const char *,
          gsad_command_response_data_t *);

char *
save_asset_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
get_assets_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                gsad_command_response_data_t *);
char *
get_asset_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
               gsad_command_response_data_t *);
char *
export_asset_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                  gsad_command_response_data_t *);
char *
export_assets_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
get_assets_chart_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                      gsad_command_response_data_t *);

char *
renew_session_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                   gsad_command_response_data_t *);
char *
change_password_gmp (gvm_connection_t *, gsad_credentials_t *, params_t *,
                     gsad_command_response_data_t *);

int
login (gsad_http_connection_t *con, params_t *params,
       gsad_command_response_data_t *response_data, const char *client_address);

#endif /* not _GSAD_GMP_H */
