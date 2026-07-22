/* Copyright (C) 2026 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_TAGS_H
#define _GVMD_MANAGE_TAGS_H

#include "manage_resources.h"

char*
tag_uuid (tag_t);

int
copy_tag (const char *, const char *, const char *, tag_t *);

int
delete_tag (const char *, int);

int
create_tag (const char *, const char *, const char *, const char *,
            array_t *, const char *, const char *, tag_t *, gchar **);

int
modify_tag (const char *, const char *, const char *, const char *,
            const char *, array_t *, const char *, const char *, const char*,
            gchar **);

int
init_resource_tag_iterator (iterator_t *, const char *, resource_t, int,
                            const char *, int);

const char*
resource_tag_iterator_uuid (iterator_t *);

const char*
resource_tag_iterator_name (iterator_t *);

const char*
resource_tag_iterator_value (iterator_t *);

const char*
resource_tag_iterator_comment (iterator_t *);

int
resource_tag_exists (const char *, resource_t, int);

int
resource_tag_count (const char *, resource_t, int);

#endif /* not _GVMD_MANAGE_TAGS_H */
