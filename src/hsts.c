/* HTTP Strict Transport Security (HSTS) support.
   Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
   2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2015 Free Software
   Foundation, Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */
#include "wget.h"

#ifdef HAVE_HSTS
#include "hsts.h"
#include "host.h" /* for is_valid_ip_address() */
#include "init.h" /* for home_dir() */
#include "utils.h"
#ifdef TESTING
#include "test.h"
#endif
#include "c-ctype.h"

#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>

struct hsts_kh {
  char *host;
  int explicit_port;
};

struct hsts_kh_info {
  time_t created;
  time_t max_age;
  bool include_subdomains;
};

enum hsts_kh_match {
  NO_MATCH,
  SUPERDOMAIN_MATCH,
  CONGRUENT_MATCH
};

#define hsts_is_host_name_valid(host) (!is_valid_ip_address (host))
#define hsts_is_scheme_valid(scheme) (scheme == SCHEME_HTTPS)
#define hsts_is_host_eligible(scheme, host) \
    (hsts_is_scheme_valid (scheme) && hsts_is_host_name_valid (host))

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_SSL_PORT  443
#define CHECK_EXPLICIT_PORT(p1, p2) (p1 == 0 || p1 == p2)
#define MAKE_EXPLICIT_PORT(s, p) (s == SCHEME_HTTPS ? (p == DEFAULT_SSL_PORT ? 0 : p) \
    : (p == DEFAULT_HTTP_PORT ? 0 : p))

#define SETPARAM(p, v) do {     \
    if (p != NULL)              \
      *p = v;                   \
  } while (0)

#define COPYPARAM(dst, src, l) do {	\
    if (dst != NULL)			\
      memcpy (dst, src, l);             \
  } while (0)

#define SEPARATOR '\t'

/* Hashing and comparison functions for the hash table */

static unsigned long
hsts_hash_func (const void *key)
{
  struct hsts_kh *k = (struct hsts_kh *) key;
  const char *h = NULL;
  unsigned int hash = k->explicit_port;

  for (h = k->host; *h; h++)
    hash = hash * 31 + *h;

  return hash;
}

static int
hsts_cmp_func (const void *h1, const void *h2)
{
  struct hsts_kh *kh1 = (struct hsts_kh *) h1,
      *kh2 = (struct hsts_kh *) h2;

  return (!strcmp (kh1->host, kh2->host)) && (kh1->explicit_port == kh2->explicit_port);
}

/* Private functions. Feel free to make some of these public when needed. */

static struct hsts_kh_info *
hsts_find_entry (hsts_store_t store,
                 const char *host, int explicit_port,
                 enum hsts_kh_match *match_type,
                 struct hsts_kh *kh)
{
  struct hsts_kh *k = NULL;
  struct hsts_kh_info *khi = NULL;
  enum hsts_kh_match match = NO_MATCH;
  char *pos = NULL;
  char *org_ptr = NULL;

  k = (struct hsts_kh *) xnew (struct hsts_kh);
  k->host = xstrdup_lower (host);
  k->explicit_port = explicit_port;

  /* save pointer so that we don't get into trouble later when freeing */
  org_ptr = k->host;

  khi = (struct hsts_kh_info *) hash_table_get (store->store, k);
  if (khi)
    {
      match = CONGRUENT_MATCH;
      goto end;
    }

  while (match == NO_MATCH &&
      (pos = strchr (k->host, '.')) && pos - k->host > 0 &&
      countchars (k->host, '.') > 1)
    {
      k->host += (pos - k->host + 1);
      khi = (struct hsts_kh_info *) hash_table_get (store->store, k);
      if (khi)
        match = SUPERDOMAIN_MATCH;
    }

end:
  /* restore pointer or we'll get a SEGV */
  k->host = org_ptr;
  xfree (k->host);

  SETPARAM (match_type, match);
  COPYPARAM (kh, k, sizeof (struct hsts_kh));

  return khi;
}

static bool
hsts_new_entry_internal (hsts_store_t store,
                         const char *host, int port,
                         time_t created, time_t max_age,
                         bool include_subdomains,
                         bool check_validity,
                         bool check_expired,
                         bool check_duplicates)
{
  struct hsts_kh *kh = xnew (struct hsts_kh);
  struct hsts_kh_info *khi = xnew0 (struct hsts_kh_info);
  bool success = false;

  kh->host = xstrdup_lower (host);
  kh->explicit_port = MAKE_EXPLICIT_PORT (SCHEME_HTTPS, port);

  khi->created = created;
  khi->max_age = max_age;
  khi->include_subdomains = include_subdomains;

  /* Check validity */
  if (check_validity && !hsts_is_host_name_valid (host))
    goto bail;

  if (check_expired && ((khi->created + khi->max_age) < khi->created))
    goto bail;

  if (check_duplicates && hash_table_contains (store->store, kh))
    goto bail;

  /* Now store the new entry */
  hash_table_put (store->store, kh, khi);
  success = true;

bail:
  if (!success)
    {
      /* abort! */
      xfree (kh->host);
      xfree (kh);
      xfree (khi);
    }

  return success;
}

/*
   Creates a new entry, but does not check whether that entry already exists.
   This function assumes that check has already been done by the caller.
 */
static bool
hsts_add_entry (hsts_store_t store,
                const char *host, int port,
                time_t max_age, bool include_subdomains)
{
  time_t t = time (NULL);

  /* It might happen time() returned -1 */
  return (t < 0 ?
      false :
      hsts_new_entry_internal (store, host, port, t, max_age, include_subdomains, false, true, false));
}

/* Creates a new entry, unless an identical one already exists. */
static bool
hsts_new_entry (hsts_store_t store,
                const char *host, int port,
                time_t created, time_t max_age,
                bool include_subdomains)
{
  return hsts_new_entry_internal (store, host, port, created, max_age, include_subdomains, true, true, true);
}

static void
hsts_remove_entry (hsts_store_t store, struct hsts_kh *kh)
{
  if (hash_table_remove (store->store, kh))
    xfree (kh->host);
}

static bool
hsts_store_merge (hsts_store_t store,
                  const char *host, int port,
                  time_t created, time_t max_age,
                  bool include_subdomains)
{
  enum hsts_kh_match match_type = NO_MATCH;
  struct hsts_kh_info *khi = NULL;
  bool success = false;

  port = MAKE_EXPLICIT_PORT (SCHEME_HTTPS, port);
  khi = hsts_find_entry (store, host, port, &match_type, NULL);
  if (khi && match_type == CONGRUENT_MATCH && created > khi->created)
    {
      /* update the entry with the new info */
      khi->created = created;
      khi->max_age = max_age;
      khi->include_subdomains = include_subdomains;

      success = true;
    }

  return success;
}

static bool
hsts_parse_line (const char *line,
                 char **host, int *port,
                 time_t *created, time_t *max_age,
                 bool *include_subdomains)
{
  bool result = false;
  int items_read = 0;

  char hostname[256];
  char *port_st = NULL, *tail = NULL;
  int myport = 0;
  char my_incl_subdomains = 0;
  time_t my_created = 0, my_max_age = 0;

  hostname[0] = 0;

  /* read hostname */
  items_read = sscanf (line, "%255s\t%c\t%lu\t%lu",
                       hostname,
                       &my_incl_subdomains,
                       &my_created,
                       &my_max_age);

  /* attempt to extract port number */
  port_st = strchr (hostname, ':');
  if (port_st)
    myport = strtol (++port_st, &tail, 10);

  if (items_read == 4)
    {
      if (hostname && host)
        *host = xstrdup_lower (hostname);

      if (myport && !tail)
        SETPARAM (port, myport);

      SETPARAM (created, my_created);
      SETPARAM (max_age, my_max_age);
      SETPARAM (include_subdomains, (my_incl_subdomains == '1' ? true : false));

      result = true;
    }

  return result;
}

static bool
hsts_read_database (hsts_store_t store, const char *file, bool merge_with_existing_entries)
{
  FILE *fp = NULL;
  char *line = NULL;
  size_t len = 0;
  bool result = false;
  bool (*func)(hsts_store_t, const char *, int, time_t, time_t, bool);

  char *host = NULL;
  int port = 0;
  time_t created = 0, max_age = 0;
  bool include_subdomains = false;

  func = (merge_with_existing_entries ? hsts_store_merge : hsts_new_entry);

  fp = fopen (file, "r");
  if (fp)
    {
      while (getline (&line, &len, fp) > 0)
        {
          if (line[0] != '#')
            {
              if (hsts_parse_line (line, &host, &port, &created, &max_age, &include_subdomains) &&
                  host && created && max_age)
                func (store, host, port, created, max_age, include_subdomains);
            }
          xfree (line);
        }
      fclose (fp);
      result = true;
    }

  return result;
}

static void
hsts_store_dump (hsts_store_t store, const char *filename)
{
  int written = 0;
  char *tmp = NULL;
  FILE *fp = NULL;
  hash_table_iterator it;
  struct hsts_kh *kh = NULL;
  struct hsts_kh_info *khi = NULL;

  fp = fopen (filename, "w");
  if (fp)
    {
      /* Print preliminary comments. We don't care if any of these fail. */
      fputs ("# HSTS 1.0 Known Hosts database for GNU Wget.\n", fp);
      fputs ("# Edit at your own risk.\n", fp);
      fputs ("# <hostname>[:<port>]\t<incl. subdomains>\t<created>\t<max-age>\n", fp);

      /* Now cycle through the HSTS store in memory and dump the entries */
      for (hash_table_iterate (store->store, &it); hash_table_iter_next (&it) && (written >= 0);)
      {
        kh = (struct hsts_kh *) it.key;
        khi = (struct hsts_kh_info *) it.value;

	/* print hostname */
	written |= fputs (kh->host, fp);

        if (kh->explicit_port != 0)
          {
            tmp = aprintf ("%i", kh->explicit_port);
            if (tmp)
              {
                written |= fputc (':', fp);
                written |= fputs (tmp, fp);
              }
            free (tmp);
          }

        written |= fputc (SEPARATOR, fp);

	/* print include subdomains flag */
	written |= fputc ((khi->include_subdomains ? '1' : '0'), fp);
	written |= fputc (SEPARATOR, fp);

	/* print creation time */
	tmp = aprintf ("%lu", khi->created);
	written |= fputs (tmp, fp);
	free (tmp);

        written |= fputc (SEPARATOR, fp);

        /* print max-age */
        tmp = aprintf ("%lu", khi->max_age);
        written |= fputs (tmp, fp);
        free (tmp);

        written |= fputc ('\n', fp);
      }

      fclose (fp);
    }
}

/* HSTS API */

/*
   Changes the given URLs according to the HSTS policy.

   If there's no host in the store that either congruently
   or not, matches the given URL, no changes are made.
   Returns true if the URL was changed, or false
   if it was left intact.
 */
bool
hsts_match (hsts_store_t store, struct url *u)
{
  bool url_changed = false;
  struct hsts_kh_info *entry = NULL;
  struct hsts_kh *kh = xnew(struct hsts_kh);
  enum hsts_kh_match match = NO_MATCH;
  int port = MAKE_EXPLICIT_PORT (u->scheme, u->port);

  entry = hsts_find_entry (store, u->host, port, &match, kh);
  if (entry)
    {
      if ((entry->created + entry->max_age) >= time(NULL))
        {
          if ((match == CONGRUENT_MATCH) ||
              (match == SUPERDOMAIN_MATCH && entry->include_subdomains))
            {
              /* we found a matching Known HSTS Host
                 rewrite the URL */
              u->scheme = SCHEME_HTTPS;
              if (u->port == 80)
                u->port = 443;
              url_changed = true;
            }
        }
      else
        hsts_remove_entry (store, kh);
    }

  xfree(kh);

  return url_changed;
}

/*
   Add a new HSTS Known Host to the HSTS store.

   If the host already exists, its information is updated,
   or it'll be removed from the store if max_age is zero.

   Bear in mind that the store is kept in memory, and will not
   be written to disk until hsts_store_save is called.
   This function regrows the in-memory HSTS store if necessary.

   Currently, for a host to be taken into consideration,
   two conditions have to be met:
     - Connection must be through a secure channel (HTTPS).
     - The host must not be an IPv4 or IPv6 address.

   The RFC 6797 states that hosts that match IPv4 or IPv6 format
   should be discarded at URI rewrite time. But we short-circuit
   that check here, since there's no point in storing a host that
   will never be matched.

   Returns true if a new entry was actually created, or false
   if an existing entry was updated/deleted. */
bool
hsts_store_entry (hsts_store_t store,
                  enum url_scheme scheme, const char *host, int port,
                  time_t max_age, bool include_subdomains)
{
  bool result = false;
  enum hsts_kh_match match = NO_MATCH;
  struct hsts_kh *kh = xnew(struct hsts_kh);
  struct hsts_kh_info *entry = NULL;
  time_t t = 0;

  if (hsts_is_host_eligible (scheme, host))
    {
      port = MAKE_EXPLICIT_PORT (scheme, port);
      entry = hsts_find_entry (store, host, port, &match, kh);
      if (entry && match == CONGRUENT_MATCH)
        {
          if (max_age == 0)
            hsts_remove_entry (store, kh);
          else if (max_age > 0)
            {
              entry->include_subdomains = include_subdomains;

              if (entry->max_age != max_age)
                {
                  /* RFC 6797 states that 'max_age' is a TTL relative to the reception of the STS header
                     so we have to update the 'created' field too */
                  t = time (NULL);
                  if (t != -1)
                    entry->created = t;
                  entry->max_age = max_age;
                }
            }
          /* we ignore negative max_ages */
        }
      else if (entry == NULL || match == SUPERDOMAIN_MATCH)
        {
          /* Either we didn't find a matching host,
             or we got a superdomain match.
             In either case, we create a new entry.

             We have to perform an explicit check because it might
             happen we got a non-existent entry with max_age == 0.
          */
          result = hsts_add_entry (store, host, port, max_age, include_subdomains);
        }
      /* we ignore new entries with max_age == 0 */
    }

  xfree(kh);

  return result;
}

hsts_store_t
hsts_store_open (const char *filename)
{
  hsts_store_t store = NULL;
  struct stat st;

  store = xnew0 (hsts_store_t);
  store->store = hash_table_new (0, hsts_hash_func, hsts_cmp_func);
  store->last_mtime = 0;

  if (file_exists_p (filename))
    {
      if (stat (filename, &st) == 0)
        store->last_mtime = st.st_mtime;

      if (!hsts_read_database (store, filename, false))
        {
          /* abort! */
          hsts_store_close (store);
          xfree (store);
          store = NULL;
        }
    }

  return store;
}

void
hsts_store_save (hsts_store_t store, const char *filename)
{
  struct stat st;

  if (hash_table_count (store->store) > 0)
    {
      /* If the file has changed, merge the changes with our in-memory data
         before dumping them to the file.
         Otherwise we could potentially overwrite the data stored by other Wget processes.
       */
      if (stat (filename, &st) == 0 && store->last_mtime && st.st_mtime > store->last_mtime)
        hsts_read_database (store, filename, true);

      /* now dump to the file */
      hsts_store_dump (store, filename);
    }
}

void
hsts_store_close (hsts_store_t store)
{
  hash_table_iterator it;

  /* free all the host fields */
  for (hash_table_iterate (store->store, &it); hash_table_iter_next (&it);)
    {
      xfree (((struct hsts_kh *) it.key)->host);
      xfree (it.key);
      xfree (it.value);
    }

  hash_table_destroy (store->store);
}

#ifdef TESTING
#define TEST_URL_RW(s, u, p) do { \
    if (test_url_rewrite (s, u, p, true)) \
      return test_url_rewrite (s, u, p, true); \
  } while (0)

#define TEST_URL_NORW(s, u, p) do { \
    if (test_url_rewrite (s, u, p, false)) \
      return test_url_rewrite (s, u, p, false); \
  } while (0)

static hsts_store_t
open_hsts_test_store ()
{
  char *home = NULL, *filename = NULL;
  FILE *fp = NULL;
  hsts_store_t store = NULL;

  home = home_dir ();
  if (home)
    {
      filename = aprintf ("%s/.wget-hsts-test", home);
      fp = fopen (filename, "w");
      if (fp)
        {
          fclose (fp);
          store = hsts_store_open (filename);
        }
      xfree (filename);
    }

  return store;
}

static char*
test_url_rewrite (hsts_store_t s, const char *url, int port, bool rewrite)
{
  bool result;
  struct url u;

  u.host = xstrdup (url);
  u.port = port;
  u.scheme = SCHEME_HTTP;

  result = hsts_match (s, &u);

  if (rewrite)
    {
      if (port == 80)
       mu_assert("URL: port should've been rewritten to 443", u.port == 443);
      else
        mu_assert("URL: port should've been left intact", u.port == port);
      mu_assert("URL: scheme should've been rewritten to HTTPS", u.scheme == SCHEME_HTTPS);
      mu_assert("result should've been true", result == true);
    }
  else
    {
      mu_assert("URL: port should've been left intact", u.port == port);
      mu_assert("URL: scheme should've been left intact", u.scheme == SCHEME_HTTP);
      mu_assert("result should've been false", result == false);
    }

  xfree (u.host);
  return NULL;
}

const char *
test_hsts_new_entry (void)
{
  enum hsts_kh_match match = NO_MATCH;
  struct hsts_kh_info *khi = NULL;

  hsts_store_t s = open_hsts_test_store ();
  mu_assert("Could not open the HSTS store. This could be due to lack of memory.", s != NULL);

  bool created = hsts_store_entry (s, SCHEME_HTTP, "www.foo.com", 80, 1234, true);
  mu_assert("No entry should have been created.", created == false);

  created = hsts_store_entry (s, SCHEME_HTTPS, "www.foo.com", 443, 1234, true);
  mu_assert("A new entry should have been created", created == true);

  khi = hsts_find_entry (s, "www.foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been a congruent match", match == CONGRUENT_MATCH);
  mu_assert("No valid HSTS info was returned", khi != NULL);
  mu_assert("Variable 'max_age' should be 1234", khi->max_age == 1234);
  mu_assert("Variable 'include_subdomains' should be asserted", khi->include_subdomains == true);

  khi = hsts_find_entry (s, "b.www.foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been a superdomain match", match == SUPERDOMAIN_MATCH);
  mu_assert("No valid HSTS info was returned", khi != NULL);
  mu_assert("Variable 'max_age' should be 1234", khi->max_age == 1234);
  mu_assert("Variable 'include_subdomains' should be asserted", khi->include_subdomains == true);

  khi = hsts_find_entry (s, "ww.foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry (s, "foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry (s, ".foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry (s, ".www.foo.com", MAKE_EXPLICIT_PORT (SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  hsts_store_close (s);

  return NULL;
}

const char*
test_hsts_url_rewrite_superdomain (void)
{
  hsts_store_t s;
  bool created;

  s = open_hsts_test_store ();
  mu_assert("Could not open the HSTS store", s != NULL);

  created = hsts_store_entry (s, SCHEME_HTTPS, "www.foo.com", 443, time(NULL) + 1234, true);
  mu_assert("A new entry should've been created", created == true);

  TEST_URL_RW (s, "www.foo.com", 80);
  TEST_URL_RW (s, "bar.www.foo.com", 80);

  hsts_store_close (s);

  return NULL;
}

const char*
test_hsts_url_rewrite_congruent (void)
{
  hsts_store_t s;
  bool created;

  s = open_hsts_test_store ();
  mu_assert("Could not open the HSTS store", s != NULL);

  created = hsts_store_entry (s, SCHEME_HTTPS, "foo.com", 443, time(NULL) + 1234, false);
  mu_assert("A new entry should've been created", created == true);

  TEST_URL_RW (s, "foo.com", 80);
  TEST_URL_NORW (s, "www.foo.com", 80);

  hsts_store_close (s);

  return NULL;
}

const char*
test_hsts_read_database (void)
{
  hsts_store_t store;
  char *home = home_dir();
  char *file = NULL;
  FILE *fp = NULL;

  if (home)
    {
      file = aprintf ("%s/.wget-hsts-testing", home);
      fp = fopen (file, "w");
      if (fp)
        {
          fputs ("# dummy comment\n", fp);
          fputs ("foo.example.com\t1\t1434224817\t123123123\n", fp);
          fputs ("bar.example.com\t0\t1434224817\t456456456\n", fp);
          fputs ("test.example.com:8080\t0\t1434224817\t789789789\n", fp);
          fclose (fp);

          store = hsts_store_open (file);

          TEST_URL_RW (store, "foo.example.com", 80);
          TEST_URL_RW (store, "www.foo.example.com", 80);
          TEST_URL_RW (store, "bar.example.com", 80);

          TEST_URL_NORW(store, "www.bar.example.com", 80);

          TEST_URL_RW (store, "test.example.com", 8080);

          hsts_store_close (store);
          unlink (file);
        }
    }

  return NULL;
}
#endif /* TESTING */
#endif /* HAVE_HSTS */
