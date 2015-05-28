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

#include "xstrndup.h"
#include "c-strcasestr.h"
#include "hsts.h"
#include "hash.h"
#include "utils.h"

#define DEFAULT_HSTS_HOSTS 2

static struct hash_table *known_hosts;

struct hsts_key {
  char *name;
  enum {
    MAX_AGE,
    INCL_SD
  } id;
};
static struct hsts_key hsts_keys[] = {
    {"max-age", MAX_AGE},
    {"includeSubDomains", INCL_SD}
};

static char *hsts_parse_value (const char *val_start)
{
  int state = 0;
#define EQUAL_PASSED 1
#define QUOTE_OPEN   2
#define QUOTE_END    3
#define VALUE_START  4
#define VALUE_END    5
  const char *p = val_start;
  const char *vs = NULL, *ve = NULL;
  char *value = NULL;

  for (; state != VALUE_END || *p != '\0'; p++)
    {
      switch (*p)
      {
	case '\t': /* fall through */
	case ' ':
	  continue;
	case ';':
	  if (state == QUOTE_END || state == VALUE_START)
	    {
	      if (state == VALUE_START)
		ve = p - 1;
	      state = VALUE_END;
	    }
	  break;
	case '=':
	  state = EQUAL_PASSED;
	  break;
	case '"':
	  if (state == EQUAL_PASSED)
	    state = QUOTE_OPEN;
	  else if (state == QUOTE_OPEN)
	    {
	      state = QUOTE_END;
	      if (value == NULL)
		value = xstrdup ("");
	    }
	  else if (state == VALUE_START)
	    {
	      ve = p - 1;
	      state = QUOTE_END;
	    }
	  break;
	default:
	  if (state == QUOTE_OPEN || state == EQUAL_PASSED)
	    state = VALUE_START;
	  if (state == VALUE_START)
	    {
	      if (vs == NULL)
		vs = p;
	    }
	  break;
      }
    }

  if (vs && ve)
    value = xstrndup (vs, ve - vs);

  return value;
}

static void hsts_parse_key (int key_id, const char *val_start, struct hsts_kh *kh)
{
  char *val = NULL;
  switch (key_id)
  {
    case MAX_AGE:
      val = hsts_parse_value (val_start);
      /* TODO convert parsed value to time_t */
      /* kh->max_age = (val ? xstrtoul (val) : -1) */
      /* TODO xfree val if val != NULL */
      kh->max_age = 0;
      break;
    case INCL_SD:
      kh->incl_subdomains = true;
      break;
  }
}

/* TODO complete
   We're not intending to read/write the real HSTS database in this iteration.
   That'll go later. So, this is OK like this.
*/
void hsts_store_load (const char *filename)
{
  known_hosts = make_nocase_string_hash_table (DEFAULT_HSTS_HOSTS);
}

/* TODO complete
   Here same as in hsts_store_load().
   We're not interacting with HSTS database yet.
*/
void hsts_store_close (const char *filename)
{
  hash_table_destroy (known_hosts);
}

/* TODO complete */
bool hsts_kh_match (struct url *u)
{
  return true;
}

/* Parse a Strict-Transport-Security header field
   according to the following grammar:

     Strict-Transport-Security = "Strict-Transport-Security" ":"
                                 [ directive ]  *( ";" [ directive ] )

     directive                 = directive-name [ "=" directive-value ]
     directive-name            = token
     directive-value           = token | quoted-string

   This function expects the _value_ of the Strict-Transport-Security header,
   *not* the whole header itself.  */
struct hsts_kh *hsts_header_parse (const char *header)
{
  int i;
  char *p;
  struct hsts_kh *kh = xnew0 (struct hsts_kh);

  for (i = 0; i < countof(hsts_keys); i++)
    {
      p = c_strcasestr (header, hsts_keys[i].name);
      if (p)
	hsts_parse_key (hsts_keys[i].id, p + strlen(hsts_keys[i].name), kh);
    }

  return kh;
}

/* Add a new HSTS Known Host to the HSTS store.

   Bear in mind that the store is kept in memory, and will not
   be written to disk until hsts_store_save is called.
   This function regrows the in-memory HSTS store if necessary.

   TODO I'm not really sure whether this function should return a bool.
   TODO What will happen with hosts with explicit port (eg. localhost:8080)?
 */
bool hsts_new_kh (const char *hostname, struct hsts_kh *kh)
{
  if (hash_table_contains (known_hosts, hostname))
    hash_table_put (known_hosts, hostname, kh);
  return true;
}

/* Remove an HSTS Known Host from the HSTS store.
   Attempting to remove a hostname which is not present in the store
   is a no-op.  */
void hsts_remove_kh (const char *hostname)
{
  if (hash_table_contains (known_hosts, hostname))
    hash_table_remove (known_hosts, hostname);
}
