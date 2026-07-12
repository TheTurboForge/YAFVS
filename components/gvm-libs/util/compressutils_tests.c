/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 */

#define GVM_COMPRESSUTILS_TESTING
#include "compressutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>

Describe (compressutils);
BeforeEach (compressutils)
{
}

Ensure (compressutils, reports_non_aborting_allocation_failures)
{
  const unsigned char zlib_fixture[] = {120, 156, 171, 2, 0, 0, 123, 0, 123};
  const unsigned char input = 'A';
  void *output = (void *) 1;
  unsigned long output_len = 1;
  unsigned long compressed_len = 1;
  gvm_uncompress_status_t status;
  void *compressed;

  fail_zlib_allocation = TRUE;
  status =
    gvm_uncompress_bounded (zlib_fixture, sizeof (zlib_fixture),
                            GVM_UNCOMPRESS_MAX_OUTPUT, &output, &output_len);
  compressed = gvm_compress (&input, sizeof (input), &compressed_len);
  fail_zlib_allocation = FALSE;

  assert_that (status, is_equal_to (GVM_UNCOMPRESS_ALLOCATION_ERROR));
  assert_that (output, is_null);
  assert_that (output_len, is_equal_to (0));
  assert_that (compressed, is_null);
}

AfterEach (compressutils)
{
}

static unsigned char *
compress_test_data (const void *data, unsigned long data_len, gboolean gzip,
                    unsigned long *compressed_len)
{
  if (gzip)
    return gvm_compress_gzipheader (data, data_len, compressed_len);
  return gvm_compress (data, data_len, compressed_len);
}

static void
assert_uncompress_rejected (const void *compressed,
                            unsigned long compressed_len,
                            gvm_uncompress_status_t expected_status)
{
  void *output = (void *) 1;
  unsigned long output_len = 1;

  assert_that (gvm_uncompress_bounded (compressed, compressed_len,
                                       GVM_UNCOMPRESS_MAX_OUTPUT, &output,
                                       &output_len),
               is_equal_to (expected_status));
  assert_that (output, is_null);
  assert_that (output_len, is_equal_to (0));
}

Ensure (compressutils, can_compress_and_uncompress_without_header)
{
  const char *testdata = "TEST-12345-12345-TEST";

  unsigned long compressed_len = 0;
  char *compressed =
    gvm_compress (testdata, strlen (testdata) + 1, &compressed_len);
  assert_that (compressed_len, is_greater_than (0));
  assert_that (compressed, is_not_null);
  assert_that (compressed, is_not_equal_to_string (testdata));

  unsigned long uncompressed_len;
  char *uncompressed =
    gvm_uncompress (compressed, compressed_len, &uncompressed_len);
  assert_that (uncompressed_len, is_equal_to (strlen (testdata) + 1));
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (compressed);
  g_free (uncompressed);
}

Ensure (compressutils, uncompresses_binary_zlib_and_gzip_data)
{
  const unsigned char testdata[] = {0x00, 0xff, 0x80, 0x41, 0x00, 0x7f};
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned long uncompressed_len;
      unsigned char *compressed =
        compress_test_data (testdata, sizeof (testdata), gzip, &compressed_len);
      unsigned char *uncompressed =
        gvm_uncompress (compressed, compressed_len, &uncompressed_len);

      assert_that (uncompressed, is_not_null);
      assert_that (uncompressed_len, is_equal_to (sizeof (testdata)));
      assert_that (memcmp (uncompressed, testdata, sizeof (testdata)),
                   is_equal_to (0));
      assert_that (uncompressed[uncompressed_len], is_equal_to (0));
      g_free (compressed);
      g_free (uncompressed);
    }
}

Ensure (compressutils, accepts_empty_zlib_and_gzip_streams)
{
  const unsigned char empty = 0;
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned long uncompressed_len = 1;
      unsigned char *compressed =
        compress_test_data (&empty, 0, gzip, &compressed_len);
      unsigned char *uncompressed =
        gvm_uncompress (compressed, compressed_len, &uncompressed_len);
      void *zero_limit_output = (void *) 1;
      unsigned long zero_limit_output_len = 1;

      assert_that (uncompressed, is_not_null);
      assert_that (uncompressed_len, is_equal_to (0));
      assert_that (uncompressed[0], is_equal_to (0));
      assert_that (gvm_uncompress_bounded (compressed, compressed_len, 0,
                                           &zero_limit_output,
                                           &zero_limit_output_len),
                   is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
      assert_that (zero_limit_output, is_null);
      assert_that (zero_limit_output_len, is_equal_to (0));
      g_free (compressed);
      g_free (uncompressed);
    }
}

Ensure (compressutils, accepts_high_ratio_output_below_limit)
{
  const unsigned long data_len = 1024UL * 1024UL;
  unsigned char *testdata = g_malloc0 (data_len);
  unsigned long compressed_len;
  unsigned long uncompressed_len;
  unsigned char *compressed =
    gvm_compress (testdata, data_len, &compressed_len);
  unsigned char *uncompressed =
    gvm_uncompress (compressed, compressed_len, &uncompressed_len);

  assert_that (compressed_len, is_less_than (data_len / 100));
  assert_that (uncompressed, is_not_null);
  assert_that (uncompressed_len, is_equal_to (data_len));
  assert_that (memcmp (uncompressed, testdata, data_len), is_equal_to (0));
  g_free (testdata);
  g_free (compressed);
  g_free (uncompressed);
}

Ensure (compressutils, accepts_output_at_exact_limit)
{
  unsigned char *testdata = g_malloc0 (GVM_UNCOMPRESS_MAX_OUTPUT);
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned long uncompressed_len;
      unsigned char *compressed = compress_test_data (
        testdata, GVM_UNCOMPRESS_MAX_OUTPUT, gzip, &compressed_len);
      unsigned char *uncompressed =
        gvm_uncompress (compressed, compressed_len, &uncompressed_len);

      assert_that (uncompressed, is_not_null);
      assert_that (uncompressed_len, is_equal_to (GVM_UNCOMPRESS_MAX_OUTPUT));
      assert_that (memcmp (uncompressed, testdata, GVM_UNCOMPRESS_MAX_OUTPUT),
                   is_equal_to (0));
      assert_that (uncompressed[uncompressed_len], is_equal_to (0));
      g_free (compressed);
      g_free (uncompressed);
    }
  g_free (testdata);
}

Ensure (compressutils, rejects_output_over_limit)
{
  const unsigned long data_len = GVM_UNCOMPRESS_MAX_OUTPUT + 1;
  unsigned char *testdata = g_malloc0 (data_len);
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned char *compressed =
        compress_test_data (testdata, data_len, gzip, &compressed_len);

      assert_uncompress_rejected (compressed, compressed_len,
                                  GVM_UNCOMPRESS_OUTPUT_LIMIT);
      g_free (compressed);
    }
  g_free (testdata);
}

Ensure (compressutils, rejects_truncated_input)
{
  const char testdata[] = "truncated input";
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned char *compressed =
        compress_test_data (testdata, sizeof (testdata), gzip, &compressed_len);

      assert_uncompress_rejected (compressed, compressed_len - 1,
                                  GVM_UNCOMPRESS_INVALID_DATA);
      g_free (compressed);
    }
}

Ensure (compressutils, rejects_malformed_and_checksum_failed_input)
{
  const unsigned char malformed[] = {0x78, 0x9c, 0x00, 0xff};
  const char testdata[] = "checksum";
  gboolean gzip;

  assert_uncompress_rejected (malformed, sizeof (malformed),
                              GVM_UNCOMPRESS_INVALID_DATA);
  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned char *compressed =
        compress_test_data (testdata, sizeof (testdata), gzip, &compressed_len);

      compressed[compressed_len - 1] ^= 0xff;
      assert_uncompress_rejected (compressed, compressed_len,
                                  GVM_UNCOMPRESS_INVALID_DATA);
      g_free (compressed);
    }
}

Ensure (compressutils, rejects_trailing_input)
{
  const char testdata[] = "trailing input";
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long compressed_len;
      unsigned char *compressed =
        compress_test_data (testdata, sizeof (testdata), gzip, &compressed_len);
      unsigned char *with_trailing = g_malloc (compressed_len + 1);

      memcpy (with_trailing, compressed, compressed_len);
      with_trailing[compressed_len] = 0x42;
      assert_uncompress_rejected (with_trailing, compressed_len + 1,
                                  GVM_UNCOMPRESS_INVALID_DATA);
      g_free (compressed);
      g_free (with_trailing);
    }
}

Ensure (compressutils, rejects_concatenated_streams)
{
  const char first[] = "first";
  const char second[] = "second";
  gboolean gzip;

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long first_len;
      unsigned long second_len;
      unsigned char *first_compressed =
        compress_test_data (first, sizeof (first), gzip, &first_len);
      unsigned char *second_compressed =
        compress_test_data (second, sizeof (second), gzip, &second_len);
      unsigned char *concatenated = g_malloc (first_len + second_len);

      memcpy (concatenated, first_compressed, first_len);
      memcpy (concatenated + first_len, second_compressed, second_len);
      assert_uncompress_rejected (concatenated, first_len + second_len,
                                  GVM_UNCOMPRESS_INVALID_DATA);
      g_free (first_compressed);
      g_free (second_compressed);
      g_free (concatenated);
    }
}

Ensure (compressutils, accepts_standard_fixtures_and_rejects_legacy_flush)
{
  const unsigned char zlib_fixture[] = {120, 156, 171, 2, 0, 0, 123, 0, 123};
  const unsigned char gzip_fixture[] = {31,  139, 8,   0,   0, 0, 0,
                                        0,   0,   255, 171, 2, 0, 175,
                                        119, 210, 98,  1,   0, 0, 0};
  const unsigned char legacy_sync_flush[] = {120, 156, 170, 2,  0,
                                             0,   0,   255, 255};
  const unsigned char *fixtures[] = {zlib_fixture, gzip_fixture};
  const unsigned long fixture_lengths[] = {sizeof (zlib_fixture),
                                           sizeof (gzip_fixture)};
  size_t i;

  for (i = 0; i < G_N_ELEMENTS (fixtures); i++)
    {
      unsigned long output_len;
      unsigned char *output =
        gvm_uncompress (fixtures[i], fixture_lengths[i], &output_len);

      assert_that (output, is_not_null);
      assert_that (output_len, is_equal_to (1));
      assert_that (output[0], is_equal_to ('z'));
      assert_that (output[output_len], is_equal_to (0));
      g_free (output);
    }

  assert_uncompress_rejected (legacy_sync_flush, sizeof (legacy_sync_flush),
                              GVM_UNCOMPRESS_INVALID_DATA);
}

Ensure (compressutils, enforces_custom_and_compressed_input_limits)
{
  const unsigned char one[] = {'A'};
  const unsigned char two[] = {'A', 'B'};
  unsigned char *oversized_input = g_malloc0 (GVM_UNCOMPRESS_MAX_INPUT + 1);
  gboolean gzip;

  oversized_input[0] = 0x1f;
  oversized_input[1] = 0x8b;
  assert_uncompress_rejected (oversized_input, GVM_UNCOMPRESS_MAX_INPUT,
                              GVM_UNCOMPRESS_INVALID_DATA);
  assert_uncompress_rejected (oversized_input, GVM_UNCOMPRESS_MAX_INPUT + 1,
                              GVM_UNCOMPRESS_INPUT_LIMIT);
  g_free (oversized_input);

  for (gzip = FALSE; gzip <= TRUE; gzip++)
    {
      unsigned long one_compressed_len;
      unsigned long two_compressed_len;
      unsigned char *one_compressed =
        compress_test_data (one, sizeof (one), gzip, &one_compressed_len);
      unsigned char *two_compressed =
        compress_test_data (two, sizeof (two), gzip, &two_compressed_len);
      void *output = (void *) 1;
      unsigned long output_len = 1;

      assert_that (gvm_uncompress_bounded (one_compressed, one_compressed_len,
                                           0, &output, &output_len),
                   is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
      assert_that (output, is_null);
      assert_that (output_len, is_equal_to (0));

      assert_that (gvm_uncompress_bounded (one_compressed, one_compressed_len,
                                           1, &output, &output_len),
                   is_equal_to (GVM_UNCOMPRESS_SUCCESS));
      assert_that (output_len, is_equal_to (1));
      assert_that (((unsigned char *) output)[0], is_equal_to ('A'));
      assert_that (((unsigned char *) output)[output_len], is_equal_to (0));
      g_free (output);

      assert_that (gvm_uncompress_bounded (two_compressed, two_compressed_len,
                                           sizeof (two), &output, &output_len),
                   is_equal_to (GVM_UNCOMPRESS_SUCCESS));
      assert_that (output_len, is_equal_to (sizeof (two)));
      assert_that (memcmp (output, two, sizeof (two)), is_equal_to (0));
      assert_that (((unsigned char *) output)[output_len], is_equal_to (0));
      g_free (output);

      assert_that (gvm_uncompress_bounded (two_compressed, two_compressed_len,
                                           sizeof (two) + 1, &output,
                                           &output_len),
                   is_equal_to (GVM_UNCOMPRESS_SUCCESS));
      assert_that (output_len, is_equal_to (sizeof (two)));
      g_free (output);

      assert_that (gvm_uncompress_bounded (two_compressed, two_compressed_len,
                                           1, &output, &output_len),
                   is_equal_to (GVM_UNCOMPRESS_OUTPUT_LIMIT));
      assert_that (output, is_null);
      assert_that (output_len, is_equal_to (0));
      g_free (one_compressed);
      g_free (two_compressed);
    }
}

Ensure (compressutils, rejects_invalid_arguments)
{
  const unsigned char input[] = {0x78};
  void *output = (void *) 1;
  unsigned long output_len = 1;

  assert_that (gvm_uncompress_bounded (NULL, sizeof (input),
                                       GVM_UNCOMPRESS_MAX_OUTPUT, &output,
                                       &output_len),
               is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
  assert_that (output, is_null);
  assert_that (output_len, is_equal_to (0));
  assert_that (gvm_uncompress_bounded (input, sizeof (input),
                                       GVM_UNCOMPRESS_MAX_OUTPUT, NULL,
                                       &output_len),
               is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
  assert_that (gvm_uncompress_bounded (input, sizeof (input),
                                       GVM_UNCOMPRESS_MAX_OUTPUT, &output,
                                       NULL),
               is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
  assert_that (gvm_uncompress_bounded (input, sizeof (input),
                                       GVM_UNCOMPRESS_MAX_OUTPUT + 1, &output,
                                       &output_len),
               is_equal_to (GVM_UNCOMPRESS_INVALID_ARGUMENT));
  assert_that (gvm_uncompress (input, sizeof (input), NULL), is_null);
}

Ensure (compressutils, rejects_invalid_or_unsupported_compress_arguments)
{
  const unsigned char input = 0;
  unsigned long compressed_len = 1;

  assert_that (gvm_compress (NULL, 1, &compressed_len), is_null);
  assert_that (gvm_compress (&input, 1, NULL), is_null);
  assert_that (gvm_compress_gzipheader (NULL, 1, &compressed_len), is_null);
  assert_that (gvm_compress_gzipheader (&input, 1, NULL), is_null);
#if ULONG_MAX > UINT_MAX
  assert_that (
    gvm_compress (&input, (unsigned long) UINT_MAX + 1UL, &compressed_len),
    is_null);
  assert_that (gvm_compress_gzipheader (&input, (unsigned long) UINT_MAX + 1UL,
                                        &compressed_len),
               is_null);
#endif
}

Ensure (compressutils, can_compress_and_uncompress_with_header)
{
  const char *testdata = "TEST-12345-12345-TEST";

  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);
  assert_that (compressed_len, is_greater_than (0));
  assert_that (compressed, is_not_null);
  assert_that (compressed, is_not_equal_to_string (testdata));
  // Check for gzip magic number and deflate compression mode byte
  assert_that (compressed[0], is_equal_to ((char) 0x1f));
  assert_that (compressed[1], is_equal_to ((char) 0x8b));
  assert_that (compressed[2], is_equal_to (8));

  unsigned long uncompressed_len;
  char *uncompressed =
    gvm_uncompress (compressed, compressed_len, &uncompressed_len);
  assert_that (uncompressed_len, is_equal_to (strlen (testdata) + 1));
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (compressed);
  g_free (uncompressed);
}

Ensure (compressutils, can_uncompress_using_reader)
{
  const char *testdata = "TEST-12345-12345-TEST";
  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);

  char compressed_filename[35] = "/tmp/gvm_gzip_test_XXXXXX";
  int compressed_fd = mkstemp (compressed_filename);
  (void) !write (compressed_fd, compressed, compressed_len);
  close (compressed_fd);
  g_free (compressed);

  FILE *stream = gvm_gzip_open_file_reader (compressed_filename);
  assert_that (stream, is_not_null);

  gchar *uncompressed = g_malloc0 (30);
  (void) !fread (uncompressed, 1, 30, stream);
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (uncompressed);

  assert_that (fclose (stream), is_equal_to (0));
}

Ensure (compressutils, can_uncompress_using_fd_reader)
{
  const char *testdata = "TEST-12345-12345-TEST";
  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);

  char compressed_filename[35] = "/tmp/gvm_gzip_test_XXXXXX";
  int compressed_fd = mkstemp (compressed_filename);
  (void) !write (compressed_fd, compressed, compressed_len);
  close (compressed_fd);
  g_free (compressed);

  compressed_fd = open (compressed_filename, O_RDONLY);

  FILE *stream = gvm_gzip_open_file_reader_fd (compressed_fd);
  assert_that (stream, is_not_null);

  gchar *uncompressed = g_malloc0 (30);
  (void) !fread (uncompressed, 1, 30, stream);
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (uncompressed);

  assert_that (fclose (stream), is_equal_to (0));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, compressutils,
                         can_compress_and_uncompress_without_header);
  add_test_with_context (suite, compressutils,
                         can_compress_and_uncompress_with_header);
  add_test_with_context (suite, compressutils,
                         uncompresses_binary_zlib_and_gzip_data);
  add_test_with_context (suite, compressutils,
                         accepts_empty_zlib_and_gzip_streams);
  add_test_with_context (suite, compressutils,
                         accepts_high_ratio_output_below_limit);
  add_test_with_context (suite, compressutils, accepts_output_at_exact_limit);
  add_test_with_context (suite, compressutils, rejects_output_over_limit);
  add_test_with_context (suite, compressutils, rejects_truncated_input);
  add_test_with_context (suite, compressutils,
                         rejects_malformed_and_checksum_failed_input);
  add_test_with_context (suite, compressutils, rejects_trailing_input);
  add_test_with_context (suite, compressutils, rejects_concatenated_streams);
  add_test_with_context (suite, compressutils,
                         accepts_standard_fixtures_and_rejects_legacy_flush);
  add_test_with_context (suite, compressutils,
                         enforces_custom_and_compressed_input_limits);
  add_test_with_context (suite, compressutils, rejects_invalid_arguments);
  add_test_with_context (suite, compressutils,
                         rejects_invalid_or_unsupported_compress_arguments);
  add_test_with_context (suite, compressutils,
                         reports_non_aborting_allocation_failures);
  add_test_with_context (suite, compressutils, can_uncompress_using_reader);
  add_test_with_context (suite, compressutils, can_uncompress_using_fd_reader);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
