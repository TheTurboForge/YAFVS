/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 */

/**
 * @file
 * @brief API related to data compression (gzip format.)
 */

#ifndef _GVM_UTIL_COMPRESSUTILS_H
#define _GVM_UTIL_COMPRESSUTILS_H

#include <stdio.h>

#define GVM_UNCOMPRESS_MAX_OUTPUT (16UL * 1024UL * 1024UL)
#define GVM_UNCOMPRESS_MAX_INPUT (16UL * 1024UL * 1024UL)

typedef enum
{
  GVM_UNCOMPRESS_SUCCESS = 0,
  GVM_UNCOMPRESS_INVALID_ARGUMENT,
  GVM_UNCOMPRESS_INVALID_DATA,
  GVM_UNCOMPRESS_INPUT_LIMIT,
  GVM_UNCOMPRESS_OUTPUT_LIMIT,
  GVM_UNCOMPRESS_ALLOCATION_ERROR
} gvm_uncompress_status_t;

void *
gvm_compress (const void *, unsigned long, unsigned long *);

void *
gvm_compress_gzipheader (const void *, unsigned long, unsigned long *);

void *
gvm_uncompress (const void *, unsigned long, unsigned long *);

gvm_uncompress_status_t
gvm_uncompress_bounded (const void *, unsigned long, unsigned long, void **,
                        unsigned long *);

FILE *
gvm_gzip_open_file_reader (const char *);

FILE *
gvm_gzip_open_file_reader_fd (int);

#endif /* not _GVM_UTIL_COMPRESSUTILS_H */
