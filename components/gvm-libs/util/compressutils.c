/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 */

/**
 * @file
 * @brief Functions related to data compression (gzip format.)
 */

/**
 * @brief For z_const to be defined as const.
 */
#if !defined(ZLIB_CONST)
#define ZLIB_CONST
#endif

#define _GNU_SOURCE

#include "compressutils.h"

#include <glib.h> /* for g_free, g_malloc0 */
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h> /* for z_stream, Z_NULL, Z_OK, Z_BUF_ERROR, Z_STREAM_END */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

#ifdef GVM_COMPRESSUTILS_TESTING
static gboolean fail_zlib_allocation;
#endif

static voidpf
zlib_try_alloc (voidpf opaque, uInt items, uInt size)
{
  (void) opaque;
#ifdef GVM_COMPRESSUTILS_TESTING
  if (fail_zlib_allocation)
    return NULL;
#endif
  return g_try_malloc_n ((gsize) items, (gsize) size);
}

static void
zlib_free (voidpf opaque, voidpf address)
{
  (void) opaque;
  g_free (address);
}

static void *
compress_buffer (const void *src, unsigned long srclen, unsigned long *dstlen,
                 gboolean gzip)
{
  void *buffer;
  uLong bound;
  z_stream strm;
  int err;

  if (src == NULL || dstlen == NULL || srclen > UINT_MAX)
    return NULL;

  memset (&strm, 0, sizeof (strm));
  strm.zalloc = zlib_try_alloc;
  strm.zfree = zlib_free;
  if (gzip)
    err = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                        Z_DEFAULT_STRATEGY);
  else
    err = deflateInit (&strm, Z_DEFAULT_COMPRESSION);
  if (err != Z_OK)
    return NULL;

  bound = deflateBound (&strm, (uLong) srclen);
  if (bound == 0 || bound > UINT_MAX || (uintmax_t) bound > SIZE_MAX)
    {
      deflateEnd (&strm);
      return NULL;
    }

  buffer = g_try_malloc ((gsize) bound);
  if (buffer == NULL)
    {
      deflateEnd (&strm);
      return NULL;
    }

  strm.avail_in = (uInt) srclen;
#ifdef z_const
  strm.next_in = src;
#else
  /* Workaround for older zlib. */
  strm.next_in = (void *) src;
#endif
  strm.avail_out = (uInt) bound;
  strm.next_out = buffer;

  err = deflate (&strm, Z_FINISH);
  if (err != Z_STREAM_END || strm.avail_in != 0)
    {
      deflateEnd (&strm);
      g_free (buffer);
      return NULL;
    }

  *dstlen = strm.total_out;
  deflateEnd (&strm);
  return buffer;
}

/**
 * @brief Compresses data in src buffer.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise. Caller must
 *         g_free.
 */
void *
gvm_compress (const void *src, unsigned long srclen, unsigned long *dstlen)
{
  return compress_buffer (src, srclen, dstlen, FALSE);
}

#define GVM_UNCOMPRESS_CHUNK (64UL * 1024UL)

static gboolean
grow_uncompress_buffer (unsigned char **buffer, size_t *capacity,
                        size_t required, size_t limit)
{
  size_t new_capacity;
  void *new_buffer;

  if (required <= *capacity)
    return TRUE;

  new_capacity = *capacity ? *capacity : GVM_UNCOMPRESS_CHUNK;
  if (new_capacity > limit)
    new_capacity = limit;

  while (new_capacity < required)
    {
      size_t increase = new_capacity;

      if (increase > limit - new_capacity)
        increase = limit - new_capacity;
      if (increase == 0)
        return FALSE;
      new_capacity += increase;
    }

  new_buffer = *buffer ? g_try_realloc (*buffer, new_capacity)
                       : g_try_malloc (new_capacity);
  if (new_buffer == NULL)
    return FALSE;

  *buffer = new_buffer;
  *capacity = new_capacity;
  return TRUE;
}

/**
 * @brief Uncompress zlib or gzip data with a caller-selected bounded output.
 *
 * @param[in]   src         Buffer of data to uncompress.
 * @param[in]   srclen      Length of data to uncompress, at most
 *                          GVM_UNCOMPRESS_MAX_INPUT.
 * @param[in]   max_output  Nonzero output limit, at most
 *                          GVM_UNCOMPRESS_MAX_OUTPUT.
 * @param[out]  dst         Newly allocated output on success.
 * @param[out]  dstlen      Length of uncompressed data on success.
 *
 * @return A status identifying success or the reason for rejection. On every
 *         failure, dst is NULL and dstlen is zero.
 */
gvm_uncompress_status_t
gvm_uncompress_bounded (const void *src, unsigned long srclen,
                        unsigned long max_output, void **dst,
                        unsigned long *dstlen)
{
  const unsigned char *input = src;
  unsigned char *buffer = NULL;
  unsigned char limit_probe;
  size_t capacity = 0;
  size_t input_offset = 0;
  size_t output_size = 0;
  size_t output_limit;
  z_stream strm;
  int init_err;
  gvm_uncompress_status_t status = GVM_UNCOMPRESS_INVALID_DATA;

  if (dst != NULL)
    *dst = NULL;
  if (dstlen != NULL)
    *dstlen = 0;

  if (src == NULL || dst == NULL || dstlen == NULL || max_output == 0
      || max_output > GVM_UNCOMPRESS_MAX_OUTPUT
      || (uintmax_t) srclen > SIZE_MAX)
    return GVM_UNCOMPRESS_INVALID_ARGUMENT;
  if (srclen > GVM_UNCOMPRESS_MAX_INPUT)
    return GVM_UNCOMPRESS_INPUT_LIMIT;

  output_limit = (size_t) max_output;
  memset (&strm, 0, sizeof (strm));
  strm.zalloc = zlib_try_alloc;
  strm.zfree = zlib_free;

  /* Add 32 to windowBits for zlib/gzip decoding with header detection. */
  init_err = inflateInit2 (&strm, 15 + 32);
  if (init_err != Z_OK)
    return init_err == Z_MEM_ERROR ? GVM_UNCOMPRESS_ALLOCATION_ERROR
                                   : GVM_UNCOMPRESS_INVALID_DATA;

  while (1)
    {
      uInt input_before;
      uInt output_before;
      gboolean probing_limit;
      int err;

      if (strm.avail_in == 0 && input_offset < (size_t) srclen)
        {
          size_t input_size = (size_t) srclen - input_offset;

          if (input_size > UINT_MAX)
            input_size = UINT_MAX;
#ifdef z_const
          strm.next_in = input + input_offset;
#else
          /* Workaround for older zlib. */
          strm.next_in = (void *) (input + input_offset);
#endif
          strm.avail_in = (uInt) input_size;
          input_offset += input_size;
        }

      probing_limit = output_size == output_limit;
      if (probing_limit)
        {
          strm.next_out = &limit_probe;
          strm.avail_out = 1;
        }
      else
        {
          size_t allocation_limit = output_limit + 1;
          size_t payload_available = output_limit - output_size;
          size_t required;
          size_t output_size_available;

          if (output_size > SIZE_MAX - 2)
            {
              status = GVM_UNCOMPRESS_ALLOCATION_ERROR;
              break;
            }
          required = output_size + 2;
          if (allocation_limit <= output_limit
              || !grow_uncompress_buffer (&buffer, &capacity, required,
                                          allocation_limit))
            {
              status = GVM_UNCOMPRESS_ALLOCATION_ERROR;
              break;
            }

          /* Keep one allocation byte outside the writable payload budget. */
          output_size_available = capacity - output_size - 1;
          if (output_size_available > payload_available)
            output_size_available = payload_available;
          if (output_size_available > UINT_MAX)
            output_size_available = UINT_MAX;
          strm.next_out = buffer + output_size;
          strm.avail_out = (uInt) output_size_available;
        }

      input_before = strm.avail_in;
      output_before = strm.avail_out;
      err = inflate (&strm, Z_NO_FLUSH);

      if (err == Z_MEM_ERROR)
        {
          status = GVM_UNCOMPRESS_ALLOCATION_ERROR;
          break;
        }

      if (probing_limit && strm.avail_out != output_before)
        {
          status = GVM_UNCOMPRESS_OUTPUT_LIMIT;
          break;
        }

      if (!probing_limit)
        {
          size_t produced = (size_t) (output_before - strm.avail_out);

          if (produced > output_limit - output_size)
            {
              status = GVM_UNCOMPRESS_OUTPUT_LIMIT;
              break;
            }
          output_size += produced;
        }

      if (err == Z_STREAM_END)
        {
          if (strm.avail_in != 0 || input_offset != (size_t) srclen)
            break;

          buffer[output_size] = 0;
          *dst = buffer;
          *dstlen = (unsigned long) output_size;
          buffer = NULL;
          status = GVM_UNCOMPRESS_SUCCESS;
          break;
        }

      if (err != Z_OK
          || (input_before == strm.avail_in && output_before == strm.avail_out))
        break;
    }

  inflateEnd (&strm);
  g_free (buffer);
  return status;
}

/**
 * @brief Uncompresses data in src buffer, bounded to 16 MiB.
 *
 * @param[in]   src     Buffer of data to uncompress.
 * @param[in]   srclen  Length of data to uncompress.
 * @param[out]  dstlen  Length of uncompressed data.
 *
 * @return Pointer to uncompressed data if success, NULL otherwise. Caller must
 *         g_free.
 */
void *
gvm_uncompress (const void *src, unsigned long srclen, unsigned long *dstlen)
{
  void *dst;

  if (gvm_uncompress_bounded (src, srclen, GVM_UNCOMPRESS_MAX_OUTPUT, &dst,
                              dstlen)
      != GVM_UNCOMPRESS_SUCCESS)
    return NULL;
  return dst;
}

/**
 * @brief Compresses data in src buffer, gzip format compatible.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise. Caller must
 *         g_free.
 */
void *
gvm_compress_gzipheader (const void *src, unsigned long srclen,
                         unsigned long *dstlen)
{
  return compress_buffer (src, srclen, dstlen, TRUE);
}

/**
 * @brief Read decompressed data from a gzip file.
 *
 * @param[in]  cookie       The gzFile to read from.
 * @param[in]  buffer       The buffer to output decompressed data to.
 * @param[in]  buffer_size  The size of the buffer.
 *
 * @return The number of bytes read into the buffer.
 */
static ssize_t
gz_file_read (void *cookie, char *buffer, size_t buffer_size)
{
  gzFile gz_file = cookie;

  return gzread (gz_file, buffer, buffer_size);
}

/**
 * @brief Close a gzip file.
 *
 * @param[in]  cookie       The gzFile to close.
 *
 * @return 0 on success, other values on error (see gzclose() from zlib).
 */
static int
gz_file_close (void *cookie)
{
  gzFile gz_file = cookie;

  return gzclose (gz_file);
  ;
}

/**
 * @brief Opens a gzip file as a FILE* stream for reading and decompression.
 *
 * @param[in]  path  Path to the gzip file to open.
 *
 * @return The FILE* on success, NULL otherwise.
 */
FILE *
gvm_gzip_open_file_reader (const char *path)
{
  static cookie_io_functions_t io_functions = {
    .read = gz_file_read,
    .write = NULL,
    .seek = NULL,
    .close = gz_file_close,
  };

  if (path == NULL)
    {
      return NULL;
    }

  gzFile gz_file = gzopen (path, "r");
  if (gz_file == NULL)
    {
      return NULL;
    }

  FILE *file = fopencookie (gz_file, "r", io_functions);
  return file;
}

/**
 * @brief Opens a gzip file as a FILE* stream for reading and decompression.
 *
 * @param[in]  fd  File descriptor of the gzip file to open.
 *
 * @return The FILE* on success, NULL otherwise.
 */
FILE *
gvm_gzip_open_file_reader_fd (int fd)
{
  static cookie_io_functions_t io_functions = {
    .read = gz_file_read,
    .write = NULL,
    .seek = NULL,
    .close = gz_file_close,
  };

  if (fd < 0)
    {
      return NULL;
    }

  gzFile gz_file = gzdopen (fd, "r");
  if (gz_file == NULL)
    {
      return NULL;
    }

  FILE *file = fopencookie (gz_file, "r", io_functions);
  return file;
}
