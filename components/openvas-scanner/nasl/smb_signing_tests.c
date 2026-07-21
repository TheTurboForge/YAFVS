/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "smb_signing.h"

#include <glib.h>
#include <string.h>

static void
set_claimed_smb_length (unsigned char *packet, size_t length)
{
  packet[1] = (unsigned char) ((length >> 16) & 1);
  packet[2] = (unsigned char) ((length >> 8) & 0xff);
  packet[3] = (unsigned char) (length & 0xff);
}

static void
test_rejects_short_header (void)
{
  unsigned char key[16] = {0};
  unsigned char packet[25] = {0};
  unsigned char signature[16] = {0};

  g_assert_cmpint (simple_packet_signature_ntlmssp (
                     key, packet, sizeof (packet), 0, signature),
                   ==, -1);
}

static void
test_rejects_claim_beyond_buffer (void)
{
  unsigned char key[16] = {0};
  unsigned char packet[32] = {0};
  unsigned char signature[16] = {0};

  set_claimed_smb_length (packet, 64);
  g_assert_cmpint (simple_packet_signature_ntlmssp (
                     key, packet, sizeof (packet), 0, signature),
                   ==, -1);
}

static void
test_accepts_complete_packet (void)
{
  unsigned char key[16] = {0};
  unsigned char packet[32] = {0};
  unsigned char signature[16] = {0};
  unsigned char zero_signature[16] = {0};

  set_claimed_smb_length (packet, sizeof (packet) - 4);
  g_assert_cmpint (simple_packet_signature_ntlmssp (
                     key, packet, sizeof (packet), 0, signature),
                   ==, 0);
  g_assert_cmpint (memcmp (signature, zero_signature, sizeof (signature)), !=,
                   0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/nasl/smb-signing/short-header", test_rejects_short_header);
  g_test_add_func ("/nasl/smb-signing/oversized-claim",
                   test_rejects_claim_beyond_buffer);
  g_test_add_func ("/nasl/smb-signing/complete-packet",
                   test_accepts_complete_packet);
  return g_test_run ();
}
