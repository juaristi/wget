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

#define HSTS_KEYS (sizeof (hsts_keys) / sizeof (hsts_keys[0]))

/* TODO complete */
static time_t hsts_value (const char *val_start)
{
  return 0;
}

static int hsts_key (const char *key_name)
{
  int i;
  for (i = 0; i < HSTS_KEYS; i++)
    {
      if (c_strcasecmp (key_name, hsts_keys[i].name) == 0)
	return hsts_keys[i].id;
    }
  return 0;
}

static void hsts_process_key (struct hsts_kh *kh, const char *key,
			      const char *val_start)
{
  switch (hsts_key(key))
  {
    case INCL_SD:
      kh->incl_subdomains = true;
      break;
    case MAX_AGE:
      kh->max_age = hsts_value (val_start);
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
*/
struct hsts_kh *hsts_header_parse (const char *header)
{
  struct hsts_kh *kh = xnew0 (struct hsts_kh);
  return kh;
}

/* TODO complete */
bool hsts_new_kh (const char *hostname, struct hsts_kh *kh)
{
  return true;
}

/* TODO complete */
void hsts_remove_kh (const char *hostname)
{
  return;
}
