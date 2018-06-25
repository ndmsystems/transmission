/*
 * This file Copyright (C) 2008-2014 Mnemosyne LLC
 *
 * It may be used under the GNU GPL versions 2 or 3
 * or any future license endorsed by Mnemosyne LLC.
 *
 * $Id: rpc-server.c 14241 2014-01-21 03:10:30Z jordan $
 */

#include <assert.h>
#include <errno.h>
#include <string.h> /* memcpy */

#include <unistd.h>    /* close */

#ifdef HAVE_ZLIB
 #include <zlib.h>
#endif

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h> /* TODO: eventually remove this */

#include "transmission.h"
#include "crypto.h" /* tr_cryptoRandBuf (), tr_ssha1_matches () */
#include "fdlimit.h"
#include "list.h"
#include "log.h"
#include "net.h"
#include "platform.h" /* tr_getWebClientDir () */
#include "ptrarray.h"
#include "rpcimpl.h"
#include "rpc-server.h"
#include "session.h"
#include "trevent.h"
#include "utils.h"
#include "variant.h"
#include "web.h"

#ifdef HAVE_NDM /* { */
# include <fcntl.h>
# include <sys/un.h>
# include <sys/stat.h>
# include <event2/listener.h>
# include <ndm/core.h>
# include <ndm/dlist.h>

#ifndef  __TARGET_REALM__
# define __TARGET_REALM__           "Undefined realm"
#endif

# define NDM_LOCAL_AUTH_TIMEOUT_    500

# define NDM_CORE_CACHE_MAX_SIZE_   4096

/* Should be synchronized with NDM constants. */
# define NDM_LOCAL_USERNAME_SIZE_   32
# define NDM_LOCAL_PASSWORD_SIZE_   32

# define TR_RPC_UDS_                "/var/run/transmission.rpc.sock"

#else /* } HAVE_NDM { */

/* session-id is used to make cross-site request forgery attacks difficult.
 * Don't disable this feature unless you really know what you're doing!
 * http://en.wikipedia.org/wiki/Cross-site_request_forgery
 * http://shiflett.org/articles/cross-site-request-forgeries
 * http://www.webappsec.org/lists/websecurity/archive/2008-04/msg00037.html */
#define REQUIRE_SESSION_ID

#endif /* } HAVE_NDM */

#define MY_NAME "RPC Server"
#define MY_REALM "Transmission"
#define TR_N_ELEMENTS(ary) (sizeof (ary) / sizeof (*ary))

struct tr_rpc_server
{
    bool               isEnabled;
    bool               isPasswordEnabled;
    bool               isWhitelistEnabled;
    tr_port            port;
    char             * url;
    struct in_addr     bindAddress;
    struct evhttp    * httpd;
#ifdef HAVE_NDM
    struct evhttp    * rpcd;
#endif /* HAVE_NDM */
    tr_session       * session;
    char             * username;
    char             * password;
    char             * whitelistStr;
    tr_list          * whitelist;

    char             * sessionId;
    time_t             sessionIdExpiresAt;

#ifdef HAVE_ZLIB
    bool               isStreamInitialized;
    z_stream           stream;
#endif

#ifdef HAVE_NDM /* { */
    struct ndm_core_t * core;
#endif /* } HAVE_NDM */
};

#define dbgmsg(...) \
  do { \
    if (tr_logGetDeepEnabled ()) \
      tr_logAddDeep (__FILE__, __LINE__, MY_NAME, __VA_ARGS__); \
  } while (0)


/***
****
***/

static char*
get_current_session_id (struct tr_rpc_server * server)
{
  const time_t now = tr_time ();

  if (!server->sessionId || (now >= server->sessionIdExpiresAt))
    {
      int i;
      const int n = 48;
      const char * pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const size_t pool_size = strlen (pool);
      unsigned char * buf = tr_new (unsigned char, n+1);

      tr_cryptoRandBuf (buf, n);
      for (i=0; i<n; ++i)
        buf[i] = pool[ buf[i] % pool_size ];
      buf[n] = '\0';

      tr_free (server->sessionId);
      server->sessionId = (char*) buf;
      server->sessionIdExpiresAt = now + (60*60); /* expire in an hour */
    }

  return server->sessionId;
}


/**
***
**/

static void
send_simple_response (struct evhttp_request * req,
                      int                     code,
                      const char            * text)
{
  const char * code_text = tr_webGetResponseStr (code);
  struct evbuffer * body = evbuffer_new ();

  evbuffer_add_printf (body, "<h1>%d: %s</h1>", code, code_text);
  if (text)
    evbuffer_add_printf (body, "%s", text);
  evhttp_send_reply (req, code, code_text, body);

  evbuffer_free (body);
}

struct tr_mimepart
{
  char * headers;
  int headers_len;
  char * body;
  int body_len;
};

static void
tr_mimepart_free (struct tr_mimepart * p)
{
  tr_free (p->body);
  tr_free (p->headers);
  tr_free (p);
}

static void
extract_parts_from_multipart (const struct evkeyvalq  * headers,
                              struct evbuffer         * body,
                              tr_ptrArray             * setme_parts)
{
  const char * content_type = evhttp_find_header (headers, "Content-Type");
  const char * in = (const char*) evbuffer_pullup (body, -1);
  size_t inlen = evbuffer_get_length (body);

  const char * boundary_key = "boundary=";
  const char * boundary_key_begin = content_type ? strstr (content_type, boundary_key) : NULL;
  const char * boundary_val = boundary_key_begin ? boundary_key_begin + strlen (boundary_key) : "arglebargle";
  char * boundary = tr_strdup_printf ("--%s", boundary_val);
  const size_t boundary_len = strlen (boundary);

  const char * delim = tr_memmem (in, inlen, boundary, boundary_len);
  while (delim)
    {
      size_t part_len;
      const char * part = delim + boundary_len;

      inlen -= (part - in);
      in = part;

      delim = tr_memmem (in, inlen, boundary, boundary_len);
      part_len = delim ? (size_t)(delim - part) : inlen;

      if (part_len)
        {
          const char * rnrn = tr_memmem (part, part_len, "\r\n\r\n", 4);
          if (rnrn)
            {
              struct tr_mimepart * p = tr_new (struct tr_mimepart, 1);
              p->headers_len = rnrn - part;
              p->headers = tr_strndup (part, p->headers_len);
              p->body_len = (part+part_len) - (rnrn + 4);
              p->body = tr_strndup (rnrn+4, p->body_len);
              tr_ptrArrayAppend (setme_parts, p);
            }
        }
    }

  tr_free (boundary);
}

static void
handle_upload (struct evhttp_request * req,
               struct tr_rpc_server  * server)
{
  if (req->type != EVHTTP_REQ_POST)
    {
      send_simple_response (req, 405, NULL);
    }
  else
    {
      int i;
      int n;
      bool hasSessionId = false;
      tr_ptrArray parts = TR_PTR_ARRAY_INIT;

      const char * query = strchr (req->uri, '?');
      const bool paused = query && strstr (query + 1, "paused=true");

      extract_parts_from_multipart (req->input_headers, req->input_buffer, &parts);
      n = tr_ptrArraySize (&parts);

      /* first look for the session id */
      for (i=0; i<n; ++i)
        {
          struct tr_mimepart * p = tr_ptrArrayNth (&parts, i);
          if (tr_memmem (p->headers, p->headers_len, TR_RPC_SESSION_ID_HEADER, strlen (TR_RPC_SESSION_ID_HEADER)))
            break;
        }

      if (i<n)
        {
          const struct tr_mimepart * p = tr_ptrArrayNth (&parts, i);
          const char * ours = get_current_session_id (server);
          const int ourlen = strlen (ours);
          hasSessionId = ourlen<=p->body_len && !memcmp (p->body, ours, ourlen);
        }

      if (!hasSessionId)
        {
          int code = 409;
          const char * codetext = tr_webGetResponseStr (code);
          struct evbuffer * body = evbuffer_new ();
          evbuffer_add_printf (body, "%s", "{ \"success\": false, \"msg\": \"Bad Session-Id\" }");;
          evhttp_send_reply (req, code, codetext, body);
          evbuffer_free (body);
        }
      else for (i=0; i<n; ++i)
        {
          struct tr_mimepart * p = tr_ptrArrayNth (&parts, i);
          int body_len = p->body_len;
          tr_variant top, *args;
          tr_variant test;
          bool have_source = false;
          char * body = p->body;

          if (body_len >= 2 && !memcmp (&body[body_len - 2], "\r\n", 2))
            body_len -= 2;

          tr_variantInitDict (&top, 2);
          tr_variantDictAddStr (&top, TR_KEY_method, "torrent-add");
          args = tr_variantDictAddDict (&top, TR_KEY_arguments, 2);
          tr_variantDictAddBool (args, TR_KEY_paused, paused);

          if (tr_urlIsValid (body, body_len))
            {
              tr_variantDictAddRaw (args, TR_KEY_filename, body, body_len);
              have_source = true;
            }
          else if (!tr_variantFromBenc (&test, body, body_len))
            {
              char * b64 = tr_base64_encode (body, body_len, NULL);
              tr_variantDictAddStr (args, TR_KEY_metainfo, b64);
              tr_free (b64);
              have_source = true;
            }

          if (have_source)
            {
              struct evbuffer * json = tr_variantToBuf (&top, TR_VARIANT_FMT_JSON);
              tr_rpc_request_exec_json (server->session,
                                        evbuffer_pullup (json, -1),
                                        evbuffer_get_length (json),
                                        NULL, NULL);
              evbuffer_free (json);
            }

          tr_variantFree (&top);
        }

      tr_ptrArrayDestruct (&parts, (PtrArrayForeachFunc)tr_mimepart_free);

      /* send "success" response */
      {
        int code = HTTP_OK;
        const char * codetext = tr_webGetResponseStr (code);
        struct evbuffer * body = evbuffer_new ();
        evbuffer_add_printf (body, "%s", "{ \"success\": true, \"msg\": \"Torrent Added\" }");;
        evhttp_send_reply (req, code, codetext, body);
        evbuffer_free (body);
      }
    }
}

/***
****
***/

static const char*
mimetype_guess (const char * path)
{
  unsigned int i;

  const struct {
    const char * suffix;
    const char * mime_type;
  } types[] = {
    /* these are the ones we need for serving the web client's files... */
    { "css",  "text/css"                  },
    { "gif",  "image/gif"                 },
    { "html", "text/html"                 },
    { "ico",  "image/vnd.microsoft.icon"  },
    { "js",   "application/javascript"    },
    { "png",  "image/png"                 }
  };
  const char * dot = strrchr (path, '.');

  for (i = 0; dot && i < TR_N_ELEMENTS (types); ++i)
    if (!strcmp (dot + 1, types[i].suffix))
      return types[i].mime_type;

  return "application/octet-stream";
}

static void
add_response (struct evhttp_request * req,
              struct tr_rpc_server  * server,
              struct evbuffer       * out,
              struct evbuffer       * content)
{
#ifndef HAVE_ZLIB
  evbuffer_add_buffer (out, content);
#else
  const char * key = "Accept-Encoding";
  const char * encoding = evhttp_find_header (req->input_headers, key);
  const int do_compress = encoding && strstr (encoding, "gzip");

  if (!do_compress)
    {
      evbuffer_add_buffer (out, content);
    }
  else
    {
      int state;
      struct evbuffer_iovec iovec[1];
      void * content_ptr = evbuffer_pullup (content, -1);
      const size_t content_len = evbuffer_get_length (content);

      if (!server->isStreamInitialized)
        {
          int compressionLevel;

          server->isStreamInitialized = true;
          server->stream.zalloc = (alloc_func) Z_NULL;
          server->stream.zfree = (free_func) Z_NULL;
          server->stream.opaque = (voidpf) Z_NULL;

          /* zlib's manual says: "Add 16 to windowBits to write a simple gzip header
           * and trailer around the compressed data instead of a zlib wrapper." */
#ifdef TR_LIGHTWEIGHT
          compressionLevel = Z_DEFAULT_COMPRESSION;
#else
          compressionLevel = Z_BEST_COMPRESSION;
#endif
          deflateInit2 (&server->stream, compressionLevel, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY);
        }

      server->stream.next_in = content_ptr;
      server->stream.avail_in = content_len;

      /* allocate space for the raw data and call deflate () just once --
       * we won't use the deflated data if it's longer than the raw data,
       * so it's okay to let deflate () run out of output buffer space */
      evbuffer_reserve_space (out, content_len, iovec, 1);
      server->stream.next_out = iovec[0].iov_base;
      server->stream.avail_out = iovec[0].iov_len;
      state = deflate (&server->stream, Z_FINISH);

      if (state == Z_STREAM_END)
        {
          iovec[0].iov_len -= server->stream.avail_out;

#if 0
          fprintf (stderr, "compressed response is %.2f of original (raw==%"TR_PRIuSIZE" bytes; compressed==%"TR_PRIuSIZE")\n",
                   (double)evbuffer_get_length (out)/content_len,
                   content_len, evbuffer_get_length (out));
#endif
          evhttp_add_header (req->output_headers,
                             "Content-Encoding", "gzip");
        }
      else
        {
          memcpy (iovec[0].iov_base, content_ptr, content_len);
          iovec[0].iov_len = content_len;
        }

      evbuffer_commit_space (out, iovec, 1);
      deflateReset (&server->stream);
    }
#endif
}

static void
add_time_header (struct evkeyvalq  * headers,
                 const char        * key,
                 time_t              value)
{
  /* According to RFC 2616 this must follow RFC 1123's date format,
     so use gmtime instead of localtime... */
  char buf[128];
  struct tm tm = *gmtime (&value);
  strftime (buf, sizeof (buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  evhttp_add_header (headers, key, buf);
}

static void
evbuffer_ref_cleanup_tr_free (const void  * data UNUSED,
                              size_t        datalen UNUSED,
                              void        * extra)
{
  tr_free (extra);
}

static void
serve_file (struct evhttp_request  * req,
            struct tr_rpc_server   * server,
            const char             * filename)
{
  if (req->type != EVHTTP_REQ_GET)
    {
      evhttp_add_header (req->output_headers, "Allow", "GET");
      send_simple_response (req, 405, NULL);
    }
  else
    {
      void * file;
      size_t file_len;
      struct evbuffer * content;
      const int error = errno;

      errno = 0;
      file_len = 0;
      file = tr_loadFile (filename, &file_len);
      content = evbuffer_new ();
      evbuffer_add_reference (content, file, file_len, evbuffer_ref_cleanup_tr_free, file);

      if (errno)
        {
          char * tmp = tr_strdup_printf ("%s (%s)", filename, tr_strerror (errno));
          send_simple_response (req, HTTP_NOTFOUND, tmp);
          tr_free (tmp);
        }
      else
        {
          struct evbuffer * out;
          const time_t now = tr_time ();

          errno = error;
          out = evbuffer_new ();
          evhttp_add_header (req->output_headers, "Content-Type", mimetype_guess (filename));
          add_time_header (req->output_headers, "Date", now);
          add_time_header (req->output_headers, "Expires", now+ (24*60*60));
          add_response (req, server, out, content);
          evhttp_send_reply (req, HTTP_OK, "OK", out);

          evbuffer_free (out);
        }

      evbuffer_free (content);
    }
}

static void
handle_web_client (struct evhttp_request * req,
                   struct tr_rpc_server *  server)
{
  const char * webClientDir = tr_getWebClientDir (server->session);

  if (!webClientDir || !*webClientDir)
    {
        send_simple_response (req, HTTP_NOTFOUND,
          "<p>Couldn't find Transmission's web interface files!</p>"
          "<p>Users: to tell Transmission where to look, "
          "set the TRANSMISSION_WEB_HOME environment "
          "variable to the folder where the web interface's "
          "index.html is located.</p>"
          "<p>Package Builders: to set a custom default at compile time, "
          "#define PACKAGE_DATA_DIR in libtransmission/platform.c "
          "or tweak tr_getClutchDir () by hand.</p>");
    }
  else
    {
      char * pch;
      char * subpath;

      subpath = tr_strdup (req->uri + strlen (server->url) + 4);
      if ((pch = strchr (subpath, '?')))
        *pch = '\0';

      if (strstr (subpath, ".."))
        {
          send_simple_response (req, HTTP_NOTFOUND, "<p>Tsk, tsk.</p>");
        }
      else
        {
          char * filename = tr_strdup_printf ("%s%s%s",
                                              webClientDir,
                                              TR_PATH_DELIMITER_STR,
                                              subpath && *subpath ? subpath : "index.html");
          serve_file (req, server, filename);
          tr_free (filename);
        }

      tr_free (subpath);
    }
}

struct rpc_response_data
{
  struct evhttp_request * req;
  struct tr_rpc_server  * server;
};

static void
rpc_response_func (tr_session      * session UNUSED,
                   struct evbuffer * response,
                   void            * user_data)
{
  struct rpc_response_data * data = user_data;
  struct evbuffer * buf = evbuffer_new ();

  add_response (data->req, data->server, buf, response);
  evhttp_add_header (data->req->output_headers,
                     "Content-Type", "application/json; charset=UTF-8");
  evhttp_send_reply (data->req, HTTP_OK, "OK", buf);

  evbuffer_free (buf);
  tr_free (data);
}

static void
handle_rpc_from_json (struct evhttp_request * req,
                      struct tr_rpc_server  * server,
                      const char            * json,
                      size_t                  json_len)
{
  struct rpc_response_data * data;

  data = tr_new0 (struct rpc_response_data, 1);
  data->req = req;
  data->server = server;

  tr_rpc_request_exec_json (server->session, json, json_len, rpc_response_func, data);
}

static void
handle_rpc (struct evhttp_request * req, struct tr_rpc_server  * server)
{
  const char * q;

  if (req->type == EVHTTP_REQ_POST)
    {
      handle_rpc_from_json (req, server,
                            (const char *) evbuffer_pullup (req->input_buffer, -1),
                            evbuffer_get_length (req->input_buffer));
    }
  else if ((req->type == EVHTTP_REQ_GET) && ((q = strchr (req->uri, '?'))))
    {
      struct rpc_response_data * data = tr_new0 (struct rpc_response_data, 1);
      data->req = req;
      data->server = server;
      tr_rpc_request_exec_uri (server->session, q+1, -1, rpc_response_func, data);
    }
  else
    {
      send_simple_response (req, 405, NULL);
    }
}

#ifdef HAVE_NDM /* { */
static bool
ndm_login (struct tr_rpc_server * server,
           const bool             is_local,
           const char           * username,
           const char           * password)
{
  bool                authenticated = false;
  tr_session        * s = server->session;
  struct ndm_user_t * u = NULL;

  tr_lockLock (s->lock);

  ndm_dlist_foreach_entry (u, struct ndm_user_t, entry, &s->cached_accounts)
  {
    if (strcmp (u->name, username) == 0
        && strcmp (u->password, password) == 0)
    {
      authenticated = true;
	  break;
    }
  }

  if (!authenticated
      && server->core != NULL)
    {
      /* Try to authenticate using a local torrent account. */
      char local_username[NDM_LOCAL_USERNAME_SIZE_ + 1];
      char local_password[NDM_LOCAL_PASSWORD_SIZE_ + 1];

      /* Clear all cache to get a new username and password. */
      ndm_core_cache_clear (server->core, true);

      if (is_local
          && ndm_core_request_first_str_buffer_cf (
            server->core,
            NDM_CORE_REQUEST_PARSE,
            NDM_CORE_MODE_CACHE,
            local_username, sizeof(local_username), NULL,
            "local-account/username", NULL,
            "show torrent local-account") == NDM_CORE_RESPONSE_ERROR_OK
          && local_username[0] != 0
          && ndm_core_request_first_str_buffer_cf (
            server->core,
            NDM_CORE_REQUEST_PARSE,
            NDM_CORE_MODE_CACHE,
            local_password, sizeof(local_password), NULL,
            "local-account/password", NULL,
            "show torrent local-account") == NDM_CORE_RESPONSE_ERROR_OK
          && local_password[0] != 0
          && strcmp (username, local_username) == 0
          && strcmp (password, local_password) == 0)
        {
          /* Locally authenticated, do not cache an account data. */
          authenticated = true;
        }
      else if (ndm_core_authenticate (server->core, username, password,
                 __TARGET_REALM__, "torrent", &authenticated)
               && authenticated)
        {
          u = tr_malloc (sizeof (*u));

          if (u != NULL)
		    {
              u->name = NULL;
              u->password = NULL;
              ndm_dlist_init (&u->entry);

              if ((u->name = tr_strdup (username)) == NULL
                  || (u->password = tr_strdup (password)) == NULL)
                {
                  tr_free (u->name);
                  tr_free (u->password);
                  tr_free (u);
                }
              else
                {
                  ndm_dlist_insert_after (&s->cached_accounts, &u->entry);
                  authenticated = true;
                }
            }
        }
    }

  tr_lockUnlock (s->lock);

  return authenticated;
}
#endif /* } HAVE_NDM */

static bool
isAddressAllowed (const tr_rpc_server * server, const char * address)
{
  tr_list * l;

  if (!server->isWhitelistEnabled)
    return true;

  for (l=server->whitelist; l!=NULL; l=l->next)
    if (tr_wildmat (address, l->data))
      return true;

  return false;
}

#ifdef REQUIRE_SESSION_ID
static bool
test_session_id (struct tr_rpc_server * server, struct evhttp_request * req)
{
  const char * ours = get_current_session_id (server);
  const char * theirs = evhttp_find_header (req->input_headers, TR_RPC_SESSION_ID_HEADER);
  const bool success =  theirs && !strcmp (theirs, ours);
  return success;
}
#endif

#ifdef HAVE_NDM
static void
handle_rpcd_request (struct evhttp_request * req, void * arg)
{
  struct tr_rpc_server * server = arg;

  if (req && req->evcon)
    {
      evhttp_add_header (req->output_headers, "Server", MY_REALM);

      if (!strcmp (req->uri + strlen (server->url), "upload"))
        {
          handle_upload (req, server);
        }
#ifdef REQUIRE_SESSION_ID
      else if (!test_session_id (server, req))
        {
          const char * sessionId = get_current_session_id (server);
          char * tmp = tr_strdup_printf (
            "<p>Your request had an invalid session-id header.</p>"
            "<p>To fix this, follow these steps:"
            "<ol><li> When reading a response, get its X-Transmission-Session-Id header and remember it"
            "<li> Add the updated header to your outgoing requests"
            "<li> When you get this 409 error message, resend your request with the updated header"
            "</ol></p>"
            "<p>This requirement has been added to help prevent "
            "<a href=\"http://en.wikipedia.org/wiki/Cross-site_request_forgery\">CSRF</a> "
            "attacks.</p>"
            "<p><code>%s: %s</code></p>",
            TR_RPC_SESSION_ID_HEADER, sessionId);
          evhttp_add_header (req->output_headers, TR_RPC_SESSION_ID_HEADER, sessionId);
          send_simple_response (req, 409, tmp);
          tr_free (tmp);
        }
#endif
      else if (!strncmp (req->uri + strlen (server->url), "rpc", 3))
        {
          handle_rpc (req, server);
        }
      else
        {
          send_simple_response (req, HTTP_NOTFOUND, req->uri);
        }
    }
}
#endif /* HAVE_NDM */

static void
handle_request (struct evhttp_request * req, void * arg)
{
  struct tr_rpc_server * server = arg;

  if (req && req->evcon)
    {
      const char * auth;
      char       * user = NULL;
      char       * pass = NULL;
#ifdef HAVE_NDM /* { */
      const bool  is_local = strcmp (req->remote_host, "127.0.0.1") == 0 ||
                             strcmp (req->remote_host, "::1") == 0;
#endif /* } HAVE_NDM */

      evhttp_add_header (req->output_headers, "Server", MY_REALM);

      auth = evhttp_find_header (req->input_headers, "Authorization");
      if (auth && !evutil_ascii_strncasecmp (auth, "basic ", 6))
        {
          int plen;
          char * p = tr_base64_decode (auth + 6, 0, &plen);
          if (p && plen && ((pass = strchr (p, ':'))))
            {
              user = p;
              *pass++ = '\0';
            }
        }

      if (!isAddressAllowed (server, req->remote_host))
        {
          send_simple_response (req, 403,
            "<p>Unauthorized IP Address.</p>"
            "<p>Either disable the IP address whitelist or add your address to it.</p>"
            "<p>If you're editing settings.json, see the 'rpc-whitelist' and 'rpc-whitelist-enabled' entries.</p>"
            "<p>If you're still using ACLs, use a whitelist instead. See the transmission-daemon manpage for details.</p>");
        }
      else if (server->isPasswordEnabled
#ifdef HAVE_NDM /* { */
                 && (!pass || !user || !ndm_login(server, is_local, user, pass)))
#else  /* } HAVE_NDM { */
                 && (!pass || !user || strcmp (server->username, user)
                                    || !tr_ssha1_matches (server->password,
                                                          pass)))
#endif /* } HAVE_NDM */
        {
          evhttp_add_header (req->output_headers,
                             "WWW-Authenticate",
                             "Basic realm=\"" MY_REALM "\"");
          send_simple_response (req, 401, "Unauthorized User");
        }
      else if (strncmp (req->uri, server->url, strlen (server->url)))
        {
          char * location = tr_strdup_printf ("%sweb/", server->url);
          evhttp_add_header (req->output_headers, "Location", location);
          send_simple_response (req, HTTP_MOVEPERM, NULL);
          tr_free (location);
        }
      else if (!strncmp (req->uri + strlen (server->url), "web/", 4))
        {
          handle_web_client (req, server);
        }
      else if (!strcmp (req->uri + strlen (server->url), "upload"))
        {
          handle_upload (req, server);
        }
#ifdef REQUIRE_SESSION_ID
      else if (!test_session_id (server, req))
        {
          const char * sessionId = get_current_session_id (server);
          char * tmp = tr_strdup_printf (
            "<p>Your request had an invalid session-id header.</p>"
            "<p>To fix this, follow these steps:"
            "<ol><li> When reading a response, get its X-Transmission-Session-Id header and remember it"
            "<li> Add the updated header to your outgoing requests"
            "<li> When you get this 409 error message, resend your request with the updated header"
            "</ol></p>"
            "<p>This requirement has been added to help prevent "
            "<a href=\"http://en.wikipedia.org/wiki/Cross-site_request_forgery\">CSRF</a> "
            "attacks.</p>"
            "<p><code>%s: %s</code></p>",
            TR_RPC_SESSION_ID_HEADER, sessionId);
          evhttp_add_header (req->output_headers, TR_RPC_SESSION_ID_HEADER, sessionId);
          send_simple_response (req, 409, tmp);
          tr_free (tmp);
        }
#endif
      else if (!strncmp (req->uri + strlen (server->url), "rpc", 3))
        {
          handle_rpc (req, server);
        }
      else
        {
          send_simple_response (req, HTTP_NOTFOUND, req->uri);
        }

      tr_free (user);
    }
}

static void
startServer (void * vserver)
{
  tr_rpc_server * server  = vserver;
  tr_address addr;

  if (!server->httpd)
    {
      addr.type = TR_AF_INET;
      addr.addr.addr4 = server->bindAddress;
      server->httpd = evhttp_new (server->session->event_base);
      evhttp_bind_socket (server->httpd, tr_address_to_string (&addr), server->port);
      evhttp_set_gencb (server->httpd, handle_request, server);
    }

#ifdef HAVE_NDM
  if (!server->rpcd)
    {
      int uds;
      struct sockaddr_un addr_un;
      int len = 0;
      struct evconnlistener *listener;
      const mode_t new_mode = S_IRUSR | S_IWUSR | S_IXUSR |
           S_IRGRP | S_IWGRP | S_IXGRP |
           S_IROTH | S_IWOTH | S_IXOTH;

      memset (&addr_un, 0, sizeof(addr_un));
      addr_un.sun_family = AF_UNIX;

      len = snprintf(addr_un.sun_path, sizeof(addr_un.sun_path), "%s", TR_RPC_UDS_);

      if (len < 0 || len >= sizeof(addr_un.sun_path))
        {
          tr_logAddNamedError (MY_NAME, "Unable to make UDS");

          return;
        }

      if (unlink (addr_un.sun_path) )
        {
          const int err = errno;

          if (err != ENOENT)
            {
              tr_logAddNamedError (MY_NAME, "unable to unlink old UDS: %s",
                strerror (err));

              return;
            }
        }

      uds = socket (PF_UNIX, SOCK_STREAM, 0);

      if (uds < 0)
        {
          tr_logAddNamedError (MY_NAME, "unable open UDS");

          return;
        }

      if (bind (uds, (struct sockaddr *) &addr_un, sizeof (addr_un)) < 0)
        {
          const int err = errno;
          tr_logAddNamedError (MY_NAME, "unable to bind UDS: %1", strerror (err));

          return;
        }

       if (chmod (addr_un.sun_path, new_mode) < 0)
         {
           const int err = errno;

           tr_logAddNamedError (MY_NAME, "unable to change UDS mode: %1", strerror (err));

           return;
         }

      fcntl(uds, F_SETFD, fcntl(uds, F_GETFD) | FD_CLOEXEC);

      if (fcntl (uds, F_SETFL, O_NONBLOCK) == -1)
        {
          const int err = errno;

          tr_logAddNamedError (MY_NAME, "unable to set UDS to nonblocking: %1", strerror (err));

          return;
        }

      server->rpcd = evhttp_new (server->session->event_base);

      listener = evconnlistener_new(server->session->event_base,
          NULL, NULL,
          LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_CLOSE_ON_FREE,
          -1,
          uds);

      evhttp_bind_listener (server->rpcd, listener);
      evhttp_set_gencb (server->rpcd, handle_rpcd_request, server);
    }

  server->core = ndm_core_open (
    "transmission/ci",
    NDM_LOCAL_AUTH_TIMEOUT_,
    NDM_CORE_CACHE_MAX_SIZE_);
#endif
}

static void
stopServer (tr_rpc_server * server)
{
  if (server->httpd)
    {
      evhttp_free (server->httpd);
      server->httpd = NULL;
    }

#ifdef HAVE_NDM
  if (server->rpcd)
    {
      evhttp_free (server->rpcd);
      server->rpcd = NULL;
      unlink (TR_RPC_UDS_);
    }

  ndm_core_close (&server->core);
#endif
}

static void
onEnabledChanged (void * vserver)
{
  tr_rpc_server * server = vserver;

  if (!server->isEnabled)
    stopServer (server);
  else
    startServer (server);
}

void
tr_rpcSetEnabled (tr_rpc_server * server,
                  bool            isEnabled)
{
  server->isEnabled = isEnabled;

  tr_runInEventThread (server->session, onEnabledChanged, server);
}

bool
tr_rpcIsEnabled (const tr_rpc_server * server)
{
  return server->isEnabled;
}

static void
restartServer (void * vserver)
{
  tr_rpc_server * server = vserver;

  if (server->isEnabled)
    {
      stopServer (server);
      startServer (server);
    }
}

void
tr_rpcSetPort (tr_rpc_server * server,
               tr_port         port)
{
  assert (server != NULL);

  if (server->port != port)
    {
      server->port = port;

      if (server->isEnabled)
        tr_runInEventThread (server->session, restartServer, server);
    }
}

tr_port
tr_rpcGetPort (const tr_rpc_server * server)
{
  return server->port;
}

void
tr_rpcSetUrl (tr_rpc_server * server, const char * url)
{
  char * tmp = server->url;
  server->url = tr_strdup (url);
  dbgmsg ("setting our URL to [%s]", server->url);
  tr_free (tmp);
}

const char*
tr_rpcGetUrl (const tr_rpc_server * server)
{
  return server->url ? server->url : "";
}

void
tr_rpcSetWhitelist (tr_rpc_server * server, const char * whitelistStr)
{
  void * tmp;
  const char * walk;

  /* keep the string */
  tmp = server->whitelistStr;
  server->whitelistStr = tr_strdup (whitelistStr);
  tr_free (tmp);

  /* clear out the old whitelist entries */
  while ((tmp = tr_list_pop_front (&server->whitelist)))
    tr_free (tmp);

  /* build the new whitelist entries */
  for (walk=whitelistStr; walk && *walk;)
    {
      const char * delimiters = " ,;";
      const size_t len = strcspn (walk, delimiters);
      char * token = tr_strndup (walk, len);
      tr_list_append (&server->whitelist, token);
      if (strcspn (token, "+-") < len)
        tr_logAddNamedInfo (MY_NAME, "Adding address to whitelist: %s (And it has a '+' or '-'!  Are you using an old ACL by mistake?)", token);
      else
        tr_logAddNamedInfo (MY_NAME, "Adding address to whitelist: %s", token);

      if (walk[len]=='\0')
        break;

      walk += len + 1;
    }
}

const char*
tr_rpcGetWhitelist (const tr_rpc_server * server)
{
  return server->whitelistStr ? server->whitelistStr : "";
}

void
tr_rpcSetWhitelistEnabled (tr_rpc_server  * server,
                           bool             isEnabled)
{
  assert (tr_isBool (isEnabled));

  server->isWhitelistEnabled = isEnabled;
}

bool
tr_rpcGetWhitelistEnabled (const tr_rpc_server * server)
{
  return server->isWhitelistEnabled;
}

/****
*****  PASSWORD
****/

void
tr_rpcSetUsername (tr_rpc_server * server, const char * username)
{
  char * tmp = server->username;
  server->username = tr_strdup (username);
  dbgmsg ("setting our Username to [%s]", tr_rpcGetUsername(server));
  tr_free (tmp);
}

const char*
tr_rpcGetUsername (const tr_rpc_server * server)
{
  return server->username ? server->username : "";
}

void
tr_rpcSetPassword (tr_rpc_server * server,
                   const char *    password)
{
  tr_free (server->password);
#ifndef HAVE_NDM // {
  if (*password != '{')
    server->password = tr_ssha1 (password);
  else
#endif // } !HAVE_NDM
    server->password = strdup (password);
  dbgmsg ("setting our Password to [%s]", tr_rpcGetPassword(server));
}

const char*
tr_rpcGetPassword (const tr_rpc_server * server)
{
  return server->password ? server->password : "" ;
}

void
tr_rpcSetPasswordEnabled (tr_rpc_server * server, bool isEnabled)
{
  server->isPasswordEnabled = isEnabled;
  dbgmsg ("setting 'password enabled' to %d", (int)isEnabled);
}

bool
tr_rpcIsPasswordEnabled (const tr_rpc_server * server)
{
  return server->isPasswordEnabled;
}

const char *
tr_rpcGetBindAddress (const tr_rpc_server * server)
{
  tr_address addr;
  addr.type = TR_AF_INET;
  addr.addr.addr4 = server->bindAddress;
  return tr_address_to_string (&addr);
}

/****
*****  LIFE CYCLE
****/

static void
closeServer (void * vserver)
{
  void * tmp;
  tr_rpc_server * s = vserver;

  stopServer (s);
  while ((tmp = tr_list_pop_front (&s->whitelist)))
    tr_free (tmp);
#ifdef HAVE_ZLIB
  if (s->isStreamInitialized)
    deflateEnd (&s->stream);
#endif
  tr_free (s->url);
  tr_free (s->sessionId);
  tr_free (s->whitelistStr);
  tr_free (s->username);
  tr_free (s->password);
  tr_free (s);
}

void
tr_rpcClose (tr_rpc_server ** ps)
{
  tr_runInEventThread ((*ps)->session, closeServer, *ps);
  *ps = NULL;
}

static void
missing_settings_key (const tr_quark q)
{
  const char * str = tr_quark_get_string (q, NULL);
  tr_logAddNamedError (MY_NAME, _("Couldn't find settings key \"%s\""), str);
} 

tr_rpc_server *
tr_rpcInit (tr_session  * session, tr_variant * settings)
{
  tr_rpc_server * s;
  bool boolVal;
  int64_t i;
  const char * str;
  tr_quark key;
  tr_address address;

  s = tr_new0 (tr_rpc_server, 1);
  s->session = session;

  key = TR_KEY_rpc_enabled;
  if (!tr_variantDictFindBool (settings, key, &boolVal))
    missing_settings_key (key);
  else
    s->isEnabled = boolVal;

  key = TR_KEY_rpc_port;
  if (!tr_variantDictFindInt (settings, key, &i))
    missing_settings_key (key);
  else
    s->port = i;

  key = TR_KEY_rpc_url;
  if (!tr_variantDictFindStr (settings, key, &str, NULL))
    missing_settings_key (key);
  else
    s->url = tr_strdup (str);

  key = TR_KEY_rpc_whitelist_enabled;
  if (!tr_variantDictFindBool (settings, key, &boolVal))
    missing_settings_key (key);
  else
    tr_rpcSetWhitelistEnabled (s, boolVal);

  key = TR_KEY_rpc_authentication_required;
  if (!tr_variantDictFindBool (settings, key, &boolVal))
    missing_settings_key (key);
  else
    tr_rpcSetPasswordEnabled (s, boolVal);

  key = TR_KEY_rpc_whitelist;
  if (!tr_variantDictFindStr (settings, key, &str, NULL) && str)
    missing_settings_key (key);
  else
    tr_rpcSetWhitelist (s, str);

#ifndef HAVE_NDM // {
  key = TR_KEY_rpc_username;
  if (!tr_variantDictFindStr (settings, key, &str, NULL))
    missing_settings_key (key);
  else
    tr_rpcSetUsername (s, str);

  key = TR_KEY_rpc_password;
  if (!tr_variantDictFindStr (settings, key, &str, NULL))
    missing_settings_key (key);
  else
    tr_rpcSetPassword (s, str);
#endif // } !HAVE_NDM

  key = TR_KEY_rpc_bind_address;
  if (!tr_variantDictFindStr (settings, key, &str, NULL))
    {
      missing_settings_key (key);
      address = tr_inaddr_any;
    }
  else if (!tr_address_from_string (&address, str))
    {
      tr_logAddNamedError (MY_NAME, _("%s is not a valid address"), str);
      address = tr_inaddr_any;
    }
  else if (address.type != TR_AF_INET)
    {
      tr_logAddNamedError (MY_NAME, _("%s is not an IPv4 address. RPC listeners must be IPv4"), str);
      address = tr_inaddr_any;
    }
  s->bindAddress = address.addr.addr4;

  if (s->isEnabled)
    {
      tr_logAddNamedInfo (MY_NAME, _("Serving RPC and Web requests on port 127.0.0.1:%d%s"), (int) s->port, s->url);
      tr_runInEventThread (session, startServer, s);

      if (s->isWhitelistEnabled)
        tr_logAddNamedInfo (MY_NAME, "%s", _("Whitelist enabled"));

      if (s->isPasswordEnabled)
        tr_logAddNamedInfo (MY_NAME, "%s", _("Password required"));
    }

  return s;
}
