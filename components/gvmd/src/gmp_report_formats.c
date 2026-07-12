/* Copyright (C) 2020-2022 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Formats
 *
 * GMP report formats.
 */

#include "gmp_report_formats.h"
#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_report_formats.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"




/**
 * @brief Return text of child if child exists, else NULL.
 *
 * @param[in]  entity  Entity.
 * @param[in]  name    Name of child.
 *
 * @return Text of child if there is such a child, else NULL.
 */
static char *
child_or_null (entity_t entity, const gchar *name)
{
  entity_t child;

  child = entity_child (entity, name);
  if (child)
    return entity_text (child);
  return NULL;
}
/**
 * @brief Free a "params_options".
 *
 * @param[in] params_options  Param options.
 */
void
params_options_free (array_t *params_options)
{
  if (params_options)
    {
      guint index = params_options->len;
      while (index--)
        {
          array_t *options;
          options = (array_t*) g_ptr_array_index (params_options, index);
          if (options)
            array_free (options);
        }
      g_ptr_array_free (params_options, TRUE);
    }
}

/**
 * @brief Get creation data from a report_format entity.
 *
 * @param[in]  report_format     Report format entity.
 * @param[out] report_format_id  Address for report format ID if required, else NULL.
 * @param[out] name              Address for name.
 * @param[out] content_type      Address for content type.
 * @param[out] extension         Address for extension.
 * @param[out] summary           Address for summary.
 * @param[out] description       Address for description.
 * @param[out] signature         Address for signature.
 * @param[out] files             Address for files.
 * @param[out] params            Address for params.
 * @param[out] params_options    Address for param options.
 * @param[out] deprecated        Address for deprecation status.
 * @param[out] report_type       Address for report type.
 */
void
parse_report_format_entity (entity_t report_format,
                            const char **report_format_id, char **name,
                            char **content_type, char **extension,
                            char **summary, char **description,
                            char **signature, array_t **files,
                            array_t **params, array_t **params_options,
                            char **deprecated, char **report_type)
{
  entity_t file, param_entity;
  entities_t children;

  if (report_format_id)
    *report_format_id = entity_attribute (report_format, "id");

  *name = child_or_null (report_format, "name");
  *content_type = child_or_null (report_format, "content_type");
  *extension = child_or_null (report_format, "extension");
  *summary = child_or_null (report_format, "summary");
  *description = child_or_null (report_format, "description");
  *signature = child_or_null (report_format, "signature");
  if (deprecated)
    *deprecated = child_or_null (report_format, "deprecated");
  if (report_type)
    *report_type = child_or_null (report_format, "report_type");

  if (*report_type == NULL)
    *report_type = "all";
  else if (strcmp (*report_type, "scan") && strcmp (*report_type, "all"))
    {
      g_warning ("report_type for report format %s is invalid.",
                 *report_format_id);
      *report_type = "all";
    }

  *files = make_array ();
  *params = make_array ();
  *params_options = make_array ();

  /* Collect files. */

  children = report_format->entities;
  while ((file = first_entity (children)))
    {
      if (strcmp (entity_name (file), "file") == 0)
        {
          const char *file_name;

          file_name = entity_attribute (file, "name");
          if (file_name)
            {
              const char *content;
              gchar *combined;

              content = entity_text (file);
              combined = g_strconcat (file_name, "0", content, NULL);
              combined[strlen (file_name)] = '\0';
              array_add (*files, combined);
            }
        }
      children = next_entities (children);
    }
  array_terminate (*files);

  /* Collect params. */

  children = report_format->entities;
  while ((param_entity = first_entity (children)))
    {
      if (strcmp (entity_name (param_entity), "param") == 0)
        {
          create_report_format_param_t *param;
          entity_t type, options_entity;
          array_t *options;

          options = make_array ();

          param = g_malloc0 (sizeof (*param));

          if (entity_child (param_entity, "default"))
            param->fallback = g_strdup (entity_text (entity_child (param_entity,
                                                                   "default")));

          if (entity_child (param_entity, "name"))
            param->name = g_strdup (entity_text (entity_child (param_entity,
                                                               "name")));
          else
            param->name = g_strdup ("");

          type = entity_child (param_entity, "type");
          if (type)
            {
              param->type = g_strstrip (g_strdup (entity_text (type)));
              if (entity_child (type, "max"))
                param->type_max = g_strdup (entity_text (entity_child (type,
                                                                       "max")));
              if (entity_child (type, "min"))
                param->type_min = g_strdup (entity_text (entity_child (type,
                                                                       "min")));
            }

          if (entity_child (param_entity, "value"))
            param->value = g_strdup (entity_text (entity_child (param_entity,
                                                                "value")));
          else
            param->value = g_strdup ("");

          array_add (*params, param);

          /* Collect options for the param. */

          options_entity = entity_child (param_entity, "options");
          if (options_entity)
            {
              entities_t options_children;
              entity_t option;

              options_children = options_entity->entities;
              while ((option = first_entity (options_children)))
                {
                  if (strcmp (entity_name (option), "option") == 0)
                    array_add (options, g_strdup (entity_text (option)));

                  options_children = next_entities (options_children);
                }
            }

          array_terminate (options);
          array_add (*params_options, options);
        }
      children = next_entities (children);
    }

  array_terminate (*params_options);
  array_terminate (*params);
}
