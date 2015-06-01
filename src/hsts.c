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

#include <stdlib.h>

#include "hsts.h"
#include "utils.h"
#ifdef TESTING
#include "test.h"
#endif

struct hsts_kh {
  char *host;
  int port;
};

struct hsts_kh_info {
  time_t created;
  time_t max_age;
  bool include_subdomains;
};

enum hsts_kh_match {
  SUPERDOMAIN_MATCH = 1,
  CONGRUENT_MATCH
};

/* Hashing and comparison functions for the hash table */

static unsigned long
hsts_hash_func (const void *key)
{
  unsigned int hash = 0;
  struct hsts_kh *k = (struct hsts_kh *) key;
  const char *h = xstrdup (k->host);
  char p[6];
  int p_len = 0, i = 0;

  p_len = snprintf (p, 6, "%d", k->port);

  if (hash)
    {
      for (h += 1; *h != '\0'; h++)
	hash = (hash << 5) - hash + c_tolower (*h);

      for (i = 0; i < p_len; i++)
	hash = (hash << 5) - hash + p[i];
    }

  return hash;
}

static int
hsts_cmp_func (const void *h1, const void *h2)
{
  struct hsts_kh *kh1 = (struct hsts_kh *) h1,
      *kh2 = (struct hsts_kh *) h2;

  return (!strcasecmp (kh1->host, kh2->host)) && (kh1->port == kh2->port);
}

/* Private functions. Feel free to make some of these public when needed. */

static enum hsts_kh_match
hsts_match_type (const char *h1, const char *h2)
{
  const char *pi[2] = {h1, h2};
  const char *p[2] = {h1 + strlen (h1), h2 + strlen (h2)};
  int eq_labels[2] = {0, 0};
  enum hsts_kh_match match_type = 0;

  for (; p[0] >= pi[0] || p[1] >= pi[1]; p[0]--, p[1]--)
    {
      if (*p[0] != *p[1])
	goto end;
      if (*p[0] == '.')
	{
	  eq_labels[0]++;
	  eq_labels[1]++;
	}
    }

  if (eq_labels[0] == eq_labels[1])
    match_type = CONGRUENT_MATCH;
  else
    match_type = SUPERDOMAIN_MATCH;

end:
  return match_type;
}

#define hsts_congruent_match(h1, h2) (hsts_match_type (h1, h2) == CONGRUENT_MATCH)
#define hsts_superdomain_match(h1, h2) (hsts_match_type (h1, h2) == SUPERDOMAIN_MATCH)

static struct hsts_kh_info *
hsts_find_entry (hsts_store_t store,
		 const char *host, int port,
		 enum hsts_kh_match *match_type,
		 struct hsts_kh *kh)
{
  struct hsts_kh *k = NULL;
  struct hsts_kh_info *khi = NULL;
  hash_table_iterator it;

  /* TODO Refactor: avoid code repetition here. */

  /* Look for congruent matches first */
  for (hash_table_iterate (store, &it); hash_table_iter_next (&it) && (khi == NULL);)
    {
      k = (struct hsts_kh *) it.key;
      if (hsts_congruent_match (host, k->host) && k->port == port)
	{
	  khi = (struct hsts_kh_info *) it.value;
	  if (match_type != NULL)
	    *match_type = CONGRUENT_MATCH;
	  if (kh != NULL)
	    memcpy (kh, k, sizeof (struct hsts_kh));
	}
    }

  if (khi)
    goto end;

  /* If no congruent matches were found,
   * look for superdomain matches.
   */
  for (hash_table_iterate (store, &it); hash_table_iter_next (&it) && (khi == NULL);)
    {
      k = (struct hsts_kh *) it.key;
      if (hsts_superdomain_match (host, k->host) && k->port == port)
	{
	  khi = (struct hsts_kh_info *) it.value;
	  if (match_type != NULL)
	    *match_type = SUPERDOMAIN_MATCH;
	  if (kh != NULL)
	    memcpy (kh, k, sizeof (struct hsts_kh));
	}
    }

end:
  return khi;
}

static bool
hsts_is_host_eligible (enum url_scheme scheme, const char *host)
{
  return (scheme == SCHEME_HTTPS) && (!is_valid_ip_address (host));
}

static void
hsts_remove_entry (hsts_store_t store, struct hsts_kh *kh)
{
  xfree (kh->host);
  hash_table_remove (store, kh);
}

static bool
hsts_new_entry (hsts_store_t store,
		const char *host, int port,
		time_t max_age,
		bool include_subdomains)
{
  struct hsts_kh *kh = xnew(struct hsts_kh);
  struct hsts_kh_info *khi = xnew0(struct hsts_kh_info);
  bool success = false;

  kh->host = xstrdup (host);
  kh->port = port;

  khi->created = time(NULL);
  khi->max_age = max_age;
  khi->include_subdomains = include_subdomains;

  /*
     Check that it's valid.
     Also, it might happen that time() returned -1.
   */
  if (khi->created != -1)
    {
      if ((khi->created + khi->max_age) > khi->created)
	{
	  hash_table_put (store, kh, khi);
	  success = true;
	}
    }

  if (!success)
    {
      /* abort! */
      xfree (kh->host);
      xfree (kh);
      xfree (khi);
    }

  return success;
}

/* HSTS API */

/*
 * Changes the given URLs according to the HSTS policy.
 *
 * If there's no host in the store that either congruently
 * or not, matches the given URL, no changes are made.
 * Returns true if the URL was changed, or false
 * if it was left intact.
 */
bool
hsts_match (struct url *u)
{
  return true;
}

/*
 * Add a new HSTS Known Host to the HSTS store.
 *
 * If the host already exists, its information is updated,
 * or it'll be removed from the store if max_age is zero.

   Bear in mind that the store is kept in memory, and will not
   be written to disk until hsts_store_save is called.
   This function regrows the in-memory HSTS store if necessary.

   Currently, for a host to be taken into consideration,
 * two conditions have to be met:
 *   - Connection must be through a secure channel (HTTPS).
 *   - The host must not be an IPv4 or IPv6 address.
 *
 * The RFC 6797 states that hosts that match IPv4 or IPv6 format
 * should be discarded at URI rewrite time. But we short-circuit
 * that check here, since there's no point in storing a host that
 * will never be matched.
 *
 * Returns true if a new entry was actually created, or false
 * if an existing entry was updated/deleted.
 */
bool
hsts_store_entry (hsts_store_t store,
		  enum url_scheme scheme, const char *host, int port,
		  time_t max_age, bool include_subdomains)
{
  bool result = false;
  enum hsts_kh_match match = 0;
  struct hsts_kh *kh = xnew(struct hsts_kh);
  struct hsts_kh_info *entry = NULL;

  if (hsts_is_host_eligible (scheme, host))
    {
      entry = hsts_find_entry (store, host, port, &match, kh);
      if (entry && match == CONGRUENT_MATCH)
	{
	  if (max_age == 0)
	    hsts_remove_entry (store, kh);
	  else if (max_age > 0)
	    {
	      entry->max_age = max_age;
	      entry->include_subdomains = include_subdomains;
	    }
	  /* we ignore negative max_ages */
	}
      else if (entry == NULL || match == SUPERDOMAIN_MATCH)
	{
	  /* Either we didn't find a matching host,
	   * or we got a superdomain match.
	   * In either case, we create a new entry.
	   *
	   * We have to perform an explicit check because it might
	   * happen we got a non-existent entry with max_age == 0.
	   */
	  hsts_new_entry (store, host, port, max_age, include_subdomains);
	  result = true;
	}
      /* we ignore new entries with max_age == 0 */
    }

  return result;
}

hsts_store_t
hsts_store_open (const char *filename)
{
  hsts_store_t store = hash_table_new (0, hsts_hash_func, hsts_cmp_func);
  return store;
}

/* TODO next iteration */
void
hsts_store_save (hsts_store_t store, const char *filename)
{
  return;
}

void
hsts_store_close (hsts_store_t store)
{
  hash_table_iterator it;

  /* free all the host fields */
  for (hash_table_iterate (store, &it); hash_table_iter_next (&it);)
    xfree (((struct hsts_kh *) it.key)->host);

  hash_table_destroy (store);
}

#ifdef TESTING
const char *
test_hsts_new_entry (void)
{
  hsts_store_t s = hsts_store_open ("foo");
  mu_assert("Could not open the HSTS store. This could be due to lack of memory.", s != NULL);

  bool created = hsts_store_entry (s, SCHEME_HTTP, "www.foo.com", 80, 1234, true);
  mu_assert("No entry should have been created.", created == false);

  created = hsts_store_entry (s, SCHEME_HTTPS, "www.foo.com", 443, 1234, true);
  mu_assert("A new entry should have been created", created == true);

  hsts_store_close (s);

//  mu_assert("this should fail", false);
  return NULL;
}
#endif
