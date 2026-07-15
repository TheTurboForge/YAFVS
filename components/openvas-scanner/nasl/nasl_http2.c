/* SPDX-FileCopyrightText: 2023 Greenbone AG
 * SPDX-FileCopyrightText: 2002-2004 Tenable Network Security
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "nasl_http2.h"

#include "../misc/plugutils.h"  /* plug_get_host_fqdn */
#include "../misc/user_agent.h" /* for user_agent_get */
#include "exec.h"
#include "nasl_debug.h"
#include "nasl_func.h"
#include "nasl_global_ctxt.h"
#include "nasl_lex_ctxt.h"
#include "nasl_socket.h"
#include "nasl_tree.h"
#include "nasl_var.h"

#include <arpa/inet.h>
#include <ctype.h> /* for isspace */
#include <curl/curl.h>
#include <gnutls/gnutls.h>
#include <gvm/base/networking.h> /* for addr6_to_str */
#include <gvm/base/prefs.h>      /* for prefs_get */
#include <gvm/util/kb.h>         /* for kb_item_get_str */
#include <stdint.h>              /* for SIZE_MAX */
#include <string.h>              /* for strlen */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  nasl"

/*-----------------[ http2_* functions ]-------------------------------*/

/** @brief Allowed methods
 **/
typedef enum KEYWORD_E
{
  POST,
  GET,
  PUT,
  DELETE,
  HEAD,
} KEYWORD;

/** @brief Struct to store handles
 **/
struct handle_table_s
{
  int handle_id;
  CURL *handle;
  long http_code;
  struct curl_slist *custom_headers;
};

#define MAX_HANDLES 10
#define HTTP2_RESPONSE_MAX_SIZE (16U * 1024U * 1024U)

struct scoped_http2_target
{
  GString *url;
  struct curl_slist *connect_to;
};

static void
scoped_http2_target_clear (struct scoped_http2_target *target)
{
  if (!target)
    return;

  if (target->url)
    g_string_free (target->url, TRUE);
  curl_slist_free_all (target->connect_to);
  target->url = NULL;
  target->connect_to = NULL;
}

static char *
normalize_http2_hostname (const char *hostname, gboolean *is_ipv6)
{
  const unsigned char *cursor;
  char *normalized;
  size_t length;
  struct in6_addr ipv6;

  if (!hostname || !*hostname || !is_ipv6)
    return NULL;

  *is_ipv6 = FALSE;
  length = strlen (hostname);
  if (hostname[0] == '[')
    {
      if (length < 3 || hostname[length - 1] != ']')
        return NULL;
      normalized = g_strndup (hostname + 1, length - 2);
      if (inet_pton (AF_INET6, normalized, &ipv6) != 1)
        {
          g_free (normalized);
          return NULL;
        }
      *is_ipv6 = TRUE;
      return normalized;
    }

  if (strchr (hostname, ':'))
    {
      if (inet_pton (AF_INET6, hostname, &ipv6) != 1)
        return NULL;
      *is_ipv6 = TRUE;
      return g_strdup (hostname);
    }

  if (length > 253)
    return NULL;
  for (cursor = (const unsigned char *) hostname; *cursor; cursor++)
    if (!g_ascii_isalnum (*cursor) && *cursor != '.' && *cursor != '-'
        && *cursor != '_')
      return NULL;

  return g_strdup (hostname);
}

static gboolean
http2_item_is_safe_path (const char *item)
{
  const unsigned char *cursor;

  if (!item || item[0] != '/')
    return FALSE;
  for (cursor = (const unsigned char *) item; *cursor; cursor++)
    if (*cursor < 0x20 || *cursor == 0x7f || *cursor == '\\')
      return FALSE;
  return TRUE;
}

/**
 * @brief Build a URL whose authority is kept for Host/SNI while libcurl's
 *        network connection is pinned to the authorized scan target.
 */
static gboolean
build_scoped_http2_target (const char *schema, const char *hostname,
                           const char *target_ip, int port, const char *item,
                           struct scoped_http2_target *target)
{
  const char *normalized_schema;
  char *connect_entry = NULL;
  char *curl_hostname = NULL;
  char *curl_target = NULL;
  char *normalized_hostname = NULL;
  gboolean hostname_is_ipv6;
  gboolean target_is_ipv6 = FALSE;
  struct in_addr ipv4;
  struct in6_addr ipv6;

  if (!target || target->url || target->connect_to || !target_ip || port <= 0
      || port > 65535 || !http2_item_is_safe_path (item))
    return FALSE;

  if (!schema || g_ascii_strcasecmp (schema, "https") == 0)
    normalized_schema = "https";
  else if (g_ascii_strcasecmp (schema, "http") == 0)
    normalized_schema = "http";
  else
    return FALSE;

  normalized_hostname = normalize_http2_hostname (hostname, &hostname_is_ipv6);
  if (!normalized_hostname)
    return FALSE;

  if (inet_pton (AF_INET, target_ip, &ipv4) != 1)
    {
      if (inet_pton (AF_INET6, target_ip, &ipv6) != 1)
        goto fail;
      target_is_ipv6 = TRUE;
    }

  curl_hostname = hostname_is_ipv6
                    ? g_strdup_printf ("[%s]", normalized_hostname)
                    : g_strdup (normalized_hostname);
  curl_target =
    target_is_ipv6 ? g_strdup_printf ("[%s]", target_ip) : g_strdup (target_ip);

  target->url = g_string_new (normalized_schema);
  g_string_append_printf (target->url, "://%s", curl_hostname);
  if (!((g_str_equal (normalized_schema, "http") && port == 80)
        || (g_str_equal (normalized_schema, "https") && port == 443)))
    g_string_append_printf (target->url, ":%d", port);
  g_string_append (target->url, item);

  connect_entry =
    g_strdup_printf ("%s:%d:%s:%d", curl_hostname, port, curl_target, port);
  target->connect_to = curl_slist_append (NULL, connect_entry);
  if (!target->connect_to)
    goto fail;

  g_free (connect_entry);
  g_free (curl_target);
  g_free (curl_hostname);
  g_free (normalized_hostname);
  return TRUE;

fail:
  g_free (connect_entry);
  g_free (curl_target);
  g_free (curl_hostname);
  g_free (normalized_hostname);
  scoped_http2_target_clear (target);
  return FALSE;
}

static CURLcode
configure_scoped_http2_transport (CURL *handle,
                                  const struct scoped_http2_target *target)
{
  CURLcode result;

  if (!handle || !target || !target->url || !target->connect_to)
    return CURLE_BAD_FUNCTION_ARGUMENT;

#define SET_SCOPED_OPTION(option, value)                 \
  do                                                     \
    {                                                    \
      result = curl_easy_setopt (handle, option, value); \
      if (result != CURLE_OK)                            \
        return result;                                   \
    }                                                    \
  while (0)

  SET_SCOPED_OPTION (CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  SET_SCOPED_OPTION (CURLOPT_URL, target->url->str);
  SET_SCOPED_OPTION (CURLOPT_CONNECT_TO, target->connect_to);
  SET_SCOPED_OPTION (CURLOPT_PROXY, "");
  SET_SCOPED_OPTION (CURLOPT_NOPROXY, "*");
  SET_SCOPED_OPTION (CURLOPT_FOLLOWLOCATION, 0L);
  SET_SCOPED_OPTION (CURLOPT_MAXREDIRS, 0L);
  SET_SCOPED_OPTION (CURLOPT_PROTOCOLS_STR, "http,https");

#undef SET_SCOPED_OPTION

  return CURLE_OK;
}

/** @brief Handle Table
 **/
static struct handle_table_s *handle_table[MAX_HANDLES];

/** @brief Find an exact handle identifier, including across sparse slots. */
static struct handle_table_s *
find_handle (int handle_id, unsigned int *table_slot)
{
  unsigned int slot;

  for (slot = 0; slot < MAX_HANDLES; slot++)
    if (handle_table[slot] && handle_table[slot]->handle_id == handle_id)
      {
        if (table_slot)
          *table_slot = slot;
        return handle_table[slot];
      }

  return NULL;
}

/** @brief Destroy all resources owned by a registered handle. */
static void
destroy_handle (unsigned int table_slot)
{
  struct handle_table_s *entry;

  if (table_slot >= MAX_HANDLES || !handle_table[table_slot])
    return;

  entry = handle_table[table_slot];
  handle_table[table_slot] = NULL;
  curl_slist_free_all (entry->custom_headers);
  curl_easy_cleanup (entry->handle);
  g_free (entry);
}

/** @brief Apply the persistent custom headers to an easy handle. */
static CURLcode
apply_custom_headers (struct handle_table_s *entry)
{
  return curl_easy_setopt (entry->handle, CURLOPT_HTTPHEADER,
                           entry->custom_headers);
}

/** @brief Append and apply one persistent custom header. */
static CURLcode
append_custom_header (struct handle_table_s *entry, const char *header_item)
{
  struct curl_slist *custom_headers;

  custom_headers = curl_slist_append (entry->custom_headers, header_item);
  if (!custom_headers)
    return CURLE_OUT_OF_MEMORY;

  entry->custom_headers = custom_headers;
  return apply_custom_headers (entry);
}

/** @brief Get the new available handle identifier
 **/
static int
next_handle_id (void)
{
  static int last = 9000;
  last++;

  return last;
}

/**
 * @brief Creates a handle for http requests
 * @naslfn{http2_handle}
 *
 * @naslret Handle identifier. Null on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with the handle
 *         identifier. Null on error.
 */
tree_cell *
nasl_http2_handle (lex_ctxt *lexic)
{
  (void) lexic;
  struct handle_table_s *entry;
  tree_cell *retc = NULL;
  CURL *handle = curl_easy_init ();
  unsigned int table_slot;

  if (!handle)
    return NULL;

  for (table_slot = 0; table_slot < MAX_HANDLES; table_slot++)
    if (!handle_table[table_slot] || !handle_table[table_slot]->handle_id)
      break;

  if (!(table_slot < MAX_HANDLES))
    {
      g_message ("%s: No space left in HTTP2 handle table", __func__);
      curl_easy_cleanup (handle);
      return NULL;
    }

  entry = g_try_malloc0 (sizeof (*entry));
  if (!entry)
    {
      curl_easy_cleanup (handle);
      return NULL;
    }

  entry->handle = handle;
  entry->handle_id = next_handle_id ();
  handle_table[table_slot] = entry;

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = entry->handle_id;
  return retc;
}

/**
 * @brief Close a handle for http requests previously initialized
 * @naslfn{http2_handle}
 *
 * @naslnparam
 * - @a handle The handle identifier for the handle to be closed
 *
 * @naslret O on success, -1 on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return The function returns a tree-cell with a integer.
 *         O on success, -1 on error.
 */
tree_cell *
nasl_http2_close_handle (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  int handle_id = get_int_var_by_num (lexic, 0, -1);
  unsigned int table_slot;
  int ret = -1;

  if (find_handle (handle_id, &table_slot))
    {
      destroy_handle (table_slot);
      ret = 0;
    }
  else
    g_message ("%s: Unknown handle identifier %d", __func__, handle_id);

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = ret;
  return retc;
}

/** @brief Shared retained-response accounting for headers and body. */
struct response_budget
{
  size_t retained;
  size_t max;
};

/** @brief Define a string struct for storing the response or header.
 */
struct string
{
  unsigned char *ptr;
  size_t len;
  struct response_budget *budget;
};

/** @brief Initialize the string struct to hold the response or header
 *
 *  @param s[in/out] The string struct to be initialized
 */
static gboolean
init_string (struct string *s, struct response_budget *budget)
{
  s->len = 0;
  s->budget = budget;
  s->ptr = g_try_malloc0 (1);
  if (!s->ptr)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return FALSE;
    }

  return TRUE;
}

/** @brief Append a response chunk while enforcing the shared size budget. */
static size_t
append_response_data (struct string *s, const void *data, size_t size,
                      size_t nmemb)
{
  size_t chunk_len;
  size_t new_len;
  unsigned char *new_ptr;

  if (!s || !s->ptr || !s->budget || (!data && size && nmemb)
      || (size && nmemb > SIZE_MAX / size))
    return 0;

  chunk_len = size * nmemb;
  if (!chunk_len)
    return 0;

  if (s->budget->retained > s->budget->max
      || chunk_len > s->budget->max - s->budget->retained || s->len == SIZE_MAX
      || chunk_len > SIZE_MAX - s->len - 1)
    return 0;

  new_len = s->len + chunk_len;
  new_ptr = g_try_realloc (s->ptr, new_len + 1);
  if (!new_ptr)
    {
      g_warning ("%s: Error allocating memory for response", __func__);
      return 0;
    }

  s->ptr = new_ptr;
  memcpy (s->ptr + s->len, data, chunk_len);
  s->ptr[new_len] = '\0';
  s->len = new_len;
  s->budget->retained += chunk_len;

  return chunk_len;
}

/** @brief Call back function to stored the response.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the response in s. It reallocate memory if necessary.
 */
static size_t
response_callback_fn (void *ptr, size_t size, size_t nmemb, void *struct_string)
{
  return append_response_data (struct_string, ptr, size, nmemb);
}

/** @brief Call back function to stored the header.
 *
 *  @description The function signature is the necessary to work with
 *  libcurl. It stores the header in s. It reallocate memory if necessary.
 */
static size_t
header_callback_fn (char *buffer, size_t size, size_t nmemb,
                    void *struct_string)
{
  return append_response_data (struct_string, buffer, size, nmemb);
}

/** @brief Build the binary-safe header, separator and body result. */
static unsigned char *
build_complete_response (const struct string *header,
                         const struct string *response, size_t *complete_len)
{
  unsigned char *complete_response;

  if (response->len > SIZE_MAX - 2
      || header->len > SIZE_MAX - response->len - 2)
    return NULL;

  *complete_len = header->len + 1 + response->len;
  complete_response = g_try_malloc (*complete_len + 1);
  if (!complete_response)
    return NULL;

  memcpy (complete_response, header->ptr, header->len);
  complete_response[header->len] = '\n';
  memcpy (complete_response + header->len + 1, response->ptr, response->len);
  complete_response[*complete_len] = '\0';

  return complete_response;
}

/**
 * @brief Perform an HTTP request. Forcing HTTP2 if possible.
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * - @a port The port to use for the connection
 *
 * - @a item The path
 *
 * - @a schema Optional URL schema to be used. http or https. Default to https.
 *
 * - @a data Optional data to be sent with POST or PUT
 *
 * @naslret http header followed by the response from the server. Null on error.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with the http header
 *         followed by the response from the server. Null on error.
 */
static tree_cell *
_http2_req (lex_ctxt *lexic, KEYWORD keyword)
{
  tree_cell *retc = NULL;
  char *item = get_str_var_by_name (lexic, "item");
  char *data = get_str_var_by_name (lexic, "data");
  int port = get_int_var_by_name (lexic, "port", -1);
  char *schema = get_str_var_by_name (lexic, "schema");
  struct script_infos *script_infos = lexic->script_infos;
  struct in6_addr *scan_target;
  char *hostname = NULL;
  char target_ip[INET6_ADDRSTRLEN] = {0};
  char *ua = NULL;
  struct scoped_http2_target target = {0};
  int handle_id = get_int_var_by_name (lexic, "handle", -1);
  struct handle_table_s *entry;
  struct response_budget budget = {1, HTTP2_RESPONSE_MAX_SIZE};
  struct string response = {0}, header_data = {0};
  unsigned char *complete_response = NULL;
  size_t complete_len;
  CURLcode curl_ret = CURLE_OK;

#define SET_HTTP2_OPTION(option, value)                             \
  do                                                                \
    {                                                               \
      curl_ret = curl_easy_setopt (entry->handle, option, value);   \
      if (curl_ret != CURLE_OK)                                     \
        {                                                           \
          g_warning ("%s: Failed to set curl option: %s", __func__, \
                     curl_easy_strerror (curl_ret));                \
          goto cleanup;                                             \
        }                                                           \
    }                                                               \
  while (0)

  if (item == NULL || port < 0 || handle_id < 0)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic, "http_*(handle: <handle>, port:<port>, item:<item> "
                          "[,schema:<schema>][, data:<data>]\n");
      return NULL;
    }

  entry = find_handle (handle_id, NULL);
  if (!entry)
    {
      g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
      return NULL;
    }

  if (port <= 0 || port > 65535)
    {
      nasl_perror (lexic, "http2_req: invalid value %d for port parameter\n",
                   port);
      return NULL;
    }

  curl_easy_reset (entry->handle);
  entry->http_code = 0;

  // Fork here for every vhost
  hostname = plug_get_host_fqdn (script_infos);
  if (hostname == NULL)
    return NULL;

  scan_target = plug_get_host_ip (script_infos);
  if (!scan_target)
    goto cleanup;
  addr6_to_str (scan_target, target_ip);
  if (!build_scoped_http2_target (schema, hostname, target_ip, port, item,
                                  &target))
    {
      nasl_perror (lexic, "http2_req: unsafe or invalid destination\n");
      goto cleanup;
    }

  g_message ("%s: URL: %s", __func__, target.url->str);
  curl_ret = configure_scoped_http2_transport (entry->handle, &target);
  if (curl_ret != CURLE_OK)
    {
      g_warning ("%s: Failed to configure scoped HTTP transport: %s", __func__,
                 curl_easy_strerror (curl_ret));
      goto cleanup;
    }

  // Accept an insecure connection. Don't verify the server certificate
  SET_HTTP2_OPTION (CURLOPT_SSL_VERIFYPEER, 0L);
  SET_HTTP2_OPTION (CURLOPT_SSL_VERIFYHOST, 0L);

  // Set User Agent
  if ((user_agent_get (lexic->script_infos->ipc_context, &ua) == -2)
      && !script_infos->standalone)
    {
      g_message ("Not possible to send the User Agent to the host process. "
                 "Invalid IPC context");
    }
  if (ua)
    SET_HTTP2_OPTION (CURLOPT_USERAGENT, ua);

  // Init the struct where the response is stored and set the callback function
  if (!init_string (&response, &budget))
    goto cleanup;
  SET_HTTP2_OPTION (CURLOPT_WRITEFUNCTION, response_callback_fn);
  SET_HTTP2_OPTION (CURLOPT_WRITEDATA, &response);

  if (!init_string (&header_data, &budget))
    goto cleanup;
  SET_HTTP2_OPTION (CURLOPT_HEADERFUNCTION, header_callback_fn);
  SET_HTTP2_OPTION (CURLOPT_HEADERDATA, &header_data);

  if (entry->custom_headers)
    {
      curl_ret = apply_custom_headers (entry);
      if (curl_ret != CURLE_OK)
        {
          g_warning ("%s: Failed to apply custom HTTP headers: %s", __func__,
                     curl_easy_strerror (curl_ret));
          goto cleanup;
        }
    }

  switch (keyword)
    {
    case DELETE:
      SET_HTTP2_OPTION (CURLOPT_CUSTOMREQUEST, "DELETE");
      break;
    case HEAD:
      SET_HTTP2_OPTION (CURLOPT_NOBODY, 1L);
      break;
    case PUT:
      SET_HTTP2_OPTION (CURLOPT_CUSTOMREQUEST, "PUT");
      if (data)
        {
          SET_HTTP2_OPTION (CURLOPT_POSTFIELDS, data);
          SET_HTTP2_OPTION (CURLOPT_POSTFIELDSIZE, (long) strlen (data));
        }
      break;
    case GET:
      SET_HTTP2_OPTION (CURLOPT_HTTPGET, 1L);
      break;
    case POST:
      // Set body. POST is set automatically with this options
      if (data)
        {
          SET_HTTP2_OPTION (CURLOPT_POSTFIELDS, data);
          SET_HTTP2_OPTION (CURLOPT_POSTFIELDSIZE, (long) strlen (data));
        }
      break;
    default:
      g_message ("%s: Invalid http method.", __func__);
      goto cleanup;
    }

  curl_ret = curl_easy_perform (entry->handle);
  if (curl_ret != CURLE_OK)
    {
      g_warning ("%s: Error sending request: %s", __func__,
                 curl_easy_strerror (curl_ret));
      goto cleanup;
    }

  curl_ret = curl_easy_getinfo (entry->handle, CURLINFO_RESPONSE_CODE,
                                &entry->http_code);
  if (curl_ret != CURLE_OK)
    {
      g_warning ("%s: Error retrieving response code: %s", __func__,
                 curl_easy_strerror (curl_ret));
      entry->http_code = 0;
      goto cleanup;
    }

  complete_response =
    build_complete_response (&header_data, &response, &complete_len);
  if (!complete_response)
    goto cleanup;

  retc = alloc_typed_cell (CONST_DATA);
  retc->size = complete_len;
  retc->x.str_val = (char *) complete_response;
  complete_response = NULL;

cleanup:
  curl_easy_reset (entry->handle);
  g_free (complete_response);
  g_free (response.ptr);
  g_free (header_data.ptr);
  g_free (ua);
  scoped_http2_target_clear (&target);
  g_free (hostname);
  return retc;

#undef SET_HTTP2_OPTION
}

/**
 * @brief Get the http response code after performing a HTTP request.
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * @naslret http code or 0 if not set. NULL on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell with and integer
 *         representing the http code response. Null on error.
 */
tree_cell *
nasl_http2_get_response_code (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct handle_table_s *entry;
  int handle_id = get_int_var_by_name (lexic, "handle", -1);

  if (handle_id < 0)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic, "http_*(handle: <handle>\n");
      return NULL;
    }

  entry = find_handle (handle_id, NULL);
  if (!entry)
    {
      g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = entry->http_code;
  return retc;
}

/**
 * @brief Set a custom header element in the header
 * @naslnparam
 *
 * - @a handle The handle identifier
 *
 * - @a header_item A string to add to the header
 *
 * @naslret 0 on success. NULL on error
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return On success the function returns a tree-cell
 *         integer 0 on success. Null on error.
 */
tree_cell *
nasl_http2_set_custom_header (lex_ctxt *lexic)
{
  tree_cell *retc = NULL;
  struct handle_table_s *entry;
  CURLcode curl_ret;
  int handle_id = get_int_var_by_name (lexic, "handle", -1);
  char *headeritem = get_str_var_by_name (lexic, "header_item");

  if (handle_id < 0 || headeritem == NULL)
    {
      nasl_perror (lexic,
                   "Error : http2_* functions have the following syntax :\n");
      nasl_perror (lexic,
                   "http_*(handle: <handle>, header_item:<header_item>\n");
      return NULL;
    }

  entry = find_handle (handle_id, NULL);
  if (!entry)
    {
      g_message ("%s: Unknown handle identifier %d", __func__, handle_id);
      return NULL;
    }

  curl_ret = append_custom_header (entry, headeritem);
  if (curl_ret != CURLE_OK)
    {
      g_warning ("%s: Error applying custom HTTP header: %s", __func__,
                 curl_easy_strerror (curl_ret));
      return NULL;
    }

  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = 0;

  return retc;
}

/** @brief Wrapper function for GET request. See @_http2_req
 */
tree_cell *
nasl_http2_get (lex_ctxt *lexic)
{
  return _http2_req (lexic, GET);
}

/** @brief Wrapper function for HEAD request. See @_http2_req
 */
tree_cell *
nasl_http2_head (lex_ctxt *lexic)
{
  return _http2_req (lexic, HEAD);
}

/** @brief Wrapper function for POST request. See @_http2_req
 */
tree_cell *
nasl_http2_post (lex_ctxt *lexic)
{
  return _http2_req (lexic, POST);
}

/** @brief Wrapper function for DELETE request. See @_http2_req
 */
tree_cell *
nasl_http2_delete (lex_ctxt *lexic)
{
  return _http2_req (lexic, DELETE);
}

/** @brief Wrapper function for PUT request. See @_http2_req
 */
tree_cell *
nasl_http2_put (lex_ctxt *lexic)
{
  return _http2_req (lexic, PUT);
}
