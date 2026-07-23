/* Copyright (C) 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Runtime feature flag handling for gvmd.
 */

#include "gvmd_config.h"
#include "manage_runtime_flags.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain used for messages from this module.
 */
#define G_LOG_DOMAIN "md   manage"



#ifndef ENABLE_OPENVASD
/**
 * @brief Whether to enable openvasd scanners.
 */
#define ENABLE_OPENVASD 0
#endif


/**
 * @brief State of a single feature.
 */
static feature_state_t feature_openvasd =
  {ENABLE_OPENVASD, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_vt_metadata =
  {1, 0};

/**
 * @brief State of a single feature.
 */
static feature_state_t feature_jwt_auth =
  {ENABLE_JWT_AUTH, 0};

/**
 * @brief Feature flags as read from the configuration file.
 */
struct conf_feature_flags
{
  int has_openvasd;            ///< Whether flag is present.
  int openvasd;                ///< Value of flag.

  int has_vt_metadata;         ///< Whether flag is present.
  int vt_metadata;             ///< Value of flag.

  int has_jwt_auth;           ///< Whether flag is present.
  int jwt_auth;               ///< Value of flag.
};

/**
 * @brief Initialize a conf_feature_flags structure with zeros.
 *
 * @param[out] t  Structure to initialize. Must not be NULL.
 */
static void
conf_file_feature_flags_init_empty (struct conf_feature_flags *t)
{
  memset (t, 0, sizeof (*t));
}
/**
 * @brief Load all feature flags from a gvmd configuration file.
 *
 * @param[in]  config_path  Path to the configuration file.
 * @param[out] out          Output structure for parsed flags.
 *
 * @return  0 on success (file loaded or not present),
 *         -1 on other I/O or parse errors.
 */
static int
load_conf_file_feature_flags (struct conf_feature_flags *out)
{
  GKeyFile *kf;

  if (!out)
    return -1;

  conf_file_feature_flags_init_empty (out);

  kf = get_gvmd_config ();
  if (kf == NULL)
    return 0;

  gvmd_config_get_boolean (kf, "features", "enable_openvasd",
                           &out->has_openvasd,
                           &out->openvasd);

  gvmd_config_get_boolean (kf, "features", "enable_vt_metadata",
                           &out->has_vt_metadata,
                           &out->vt_metadata);

  gvmd_config_get_boolean (kf, "features", "enable_jwt_auth",
                           &out->has_jwt_auth,
                           &out->jwt_auth);

  return 0;
}

/**
 * @brief Resolve the effective state of a single feature.
 *
 * Resolution order:
 *  - If the feature is not compiled in, it is always disabled.
 *  - If an environment variable is set and valid, use that.
 *  - Else, if a config file value exists, use that.
 *  - Else, default to disabled (0).
 *
 * @param[in,out] feature        Feature state to update.
 * @param[in]     env_name       Environment variable name.
 * @param[in]     conf_has_value Non-zero if configuration provided a value.
 * @param[in]     conf_value     Value from configuration (1 or 0).
 */
static void
resolve_feature (feature_state_t *feature,
                 const char *env_name,
                 int conf_has_value,
                 int conf_value)
{
  if (!feature)
    return;

  if (!feature->compiled_in)
    {
      feature->enabled = 0;
      return;
    }

  gvmd_config_resolve_boolean (env_name, conf_has_value, conf_value,
                               &feature->enabled);
}

/**
 * @brief Initialize runtime feature flags from config file and environment.
 *
 * @return Always 0 (errors are handled internally and fall back to defaults).
 */
int
runtime_flags_init ()
{
  struct conf_feature_flags conf_flags;

  if (load_conf_file_feature_flags (&conf_flags) != 0)
    {
      /* Parse error */
      conf_file_feature_flags_init_empty (&conf_flags);
    }

  resolve_feature (&feature_openvasd,
                   "GVMD_ENABLE_OPENVASD",
                   conf_flags.has_openvasd,
                   conf_flags.openvasd);

  resolve_feature (&feature_vt_metadata,
                   "GVMD_ENABLE_VT_METADATA",
                   conf_flags.has_vt_metadata,
                   conf_flags.vt_metadata);

  resolve_feature (&feature_jwt_auth,
                   "GVMD_ENABLE_JWT_AUTH",
                   conf_flags.has_jwt_auth,
                   conf_flags.jwt_auth);

  return 0;
}

/**
 * @brief Check whether a feature is currently enabled at runtime.
 *
 * @param[in] t  Feature identifier.
 *
 * @return 1 if the feature is enabled at runtime, 0 otherwise.
 */
int
feature_enabled (feature_id_t t)
{
  /* IMPORTANT: compiled-out features are never enabled */
  if (!feature_compiled_in (t))
    return 0;

  switch (t)
    {
    case FEATURE_ID_OPENVASD_SCANNER:
      return feature_openvasd.enabled;
    case FEATURE_ID_VT_METADATA:
      return feature_vt_metadata.enabled;
    case FEATURE_ID_JWT_AUTH:
      return feature_jwt_auth.enabled;
    default:
      return 0;
    }
}
/**
 * @brief Check whether a feature is compiled into this binary.
 *
 * @param[in] t  Feature identifier.
 *
 * @return 1 if compiled in, 0 otherwise.
 */
int
feature_compiled_in (feature_id_t t)
{
  switch (t)
    {
    case FEATURE_ID_OPENVASD_SCANNER:
      return feature_openvasd.compiled_in;
    case FEATURE_ID_VT_METADATA:
      return feature_vt_metadata.compiled_in;
    case FEATURE_ID_JWT_AUTH:
      return feature_jwt_auth.enabled;
    default:
      return 0;
    }
}
