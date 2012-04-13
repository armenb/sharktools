/* Copyright (c) 2007-2011
 *      Massachusetts Institute of Technology
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, see
 * http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 ****************************************************************
 */

/* IN NO EVENT SHALL MIT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
 * THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF MIT HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * MIT SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTIES INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
 *
 * MIT HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS TO THIS SOFTWARE.
 */

/*
 * This command-line program tests out the basic functionality of sharktools.
 *
 * Contact: Armen Babikyan, MIT Lincoln Laboratory, <armenb@mit.edu>
 */

#include "sharktools_core.h"
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#define WS_VAR_IMPORT extern
#include <epan/epan.h>

extern char sharktools_errmsg[2048];

// Allow a -DDEBUG=0 to be passed to the compiler.
#ifndef DEBUG
#define DEBUG 1
#endif

#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif


gpointer cb_row_new(sharktools_callbacks *cb)
{
  return NULL;
}

gpointer cb_row_set(sharktools_callbacks *cb, void *row, void *key, gulong type, GPtrArray *tree_values)
{
  static nstime_t *tmp_timestamp;
  double tmp_double;

  // Bomb out; I haven't updated this app...
  fvalue_t *val_native;
  const gchar *val_string;
  g_assert_not_reached();

  //printf("%s (%d)\t\t", val_string, (int)type);
  switch(type)
    {
    case FT_NONE:      /* used for text labels with no value */
      printf("None");
      break;
      //case FT_PROTOCOL:
      //case FT_BOOLEAN:	/* TRUE and FALSE come from <glib.h> */
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
    case FT_UINT32:
      /* FIXME: does fvalue_get_uinteger() work properly with FT_UINT{8,16,24} types? */
      printf("%u", fvalue_get_uinteger(val_native));
      break;
    case FT_INT64:
      /* Wireshark doesn't seem to make a difference between INT64 and UINT64 */
    case FT_UINT64:
      //guint64 tmp = 
      printf("%llu", (long long unsigned int)fvalue_get_integer64(val_native));// tmp);
      break;
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:	/* same as for UINT24 */
    case FT_INT32:
      /* FIXME: does fvalue_get_sinteger() work properly with FT_INT{8,16,24} types? */
      printf("%d", fvalue_get_sinteger(val_native));
      break;
    case FT_FLOAT:
    case FT_DOUBLE:
      printf("%f", fvalue_get_floating(val_native));
      break;
    case FT_ABSOLUTE_TIME:
    case FT_RELATIVE_TIME:
      tmp_timestamp = fvalue_get(val_native);
      // Use fn in $wireshark/epan/nstime.c to convert timestamp to a float
      tmp_double = nstime_to_sec(tmp_timestamp);
      printf("%f", tmp_double);
      break;
    //case FT_UINT_STRING:	/* for use with proto_tree_add_item() */
    //case FT_ETHER:
    //case FT_BYTES:
    //case FT_UINT_BYTES:
    //case FT_IPv4:
    //case FT_IPv6:
    //case FT_IPXNET:
    //case FT_FRAMENUM:	/* a UINT32, but if selected lets you go to frame with that numbe */
    //case FT_PCRE:		/* a compiled Perl-Compatible Regular Expression object */
    //case FT_GUID:		/* GUID, UUID */
    //case FT_OID:			/* OBJECT IDENTIFIER */
    default:
      printf("%s", val_string);
      break;
    }

  printf(" (%d)\t\t", (int)type);

  /*
  if(type == FT_UINT32)
    {
      //printf("%d (%d)\t\t", val_native->value.uinteger, (int)type);
      printf("%d (%d)\t\t", fvalue_get_uinteger(val_native), (int)type);
    }
  */

  return NULL;
}

gpointer cb_row_add(sharktools_callbacks *cb, gpointer row)
{
  printf("\n");
  return NULL;
}

void sharktools_print(gchar *filename, gchar **fieldnames, gsize nfields, gchar *dfilter)
{
  // Construct a cb "object" with state variables and callbacks
  sharktools_callbacks cb;
  cb.root = (gpointer)NULL;
  cb.keys = (gpointer *)fieldnames;
  cb.row_new = cb_row_new;
  cb.row_set = cb_row_set;
  cb.row_add = cb_row_add;

  //int count;
  //count = (int)sharktools_count(filename, dfilter);
  //printf("count: %d\n", count);

  printf("<value as a char*> (<type in decimal>)\n");

  int ret;
  ret = sharktools_get_cb(filename, nfields, (const gchar**)fieldnames, dfilter, &cb);

  if(!ret)
    {
      dprintf("%s\n", sharktools_errmsg);
    }

  return;
}

#if DEBUG==0
static void log_func_ignore (const gchar *log_domain, GLogLevelFlags log_level,
			     const gchar *message, gpointer user_data)
{
}
#endif

void usage(char *argv0)
{
  fprintf(stderr, "%s -f <filename> -i <field name 1> [-i <field name 2> ...] -d <display filter>\n", argv0);
}

int main(int argc, char **argv)
{
#if DEBUG==0
  GLogLevelFlags       log_flags;

  // Bomb out
  g_assert_not_reached();

  /* nothing more than the standard GLib handler, but without a warning */
  log_flags =
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;


  g_log_set_handler(NULL,
		    log_flags,
		    log_func_ignore, NULL /* user_data */);


  // Handle all GLib messages with a fn that throws them away
  g_log_set_handler ("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
		     log_func_ignore, NULL);


  //g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
  //log_flags,
  //log_func_ignore, NULL /* user_data */);
#endif

  /*
  char *filename = "ws1.pcap";
  gsize nfields = 4;
  char *pfieldnames[] = {"frame.number", "ip.version", "tcp.seq", "udp.srcport"};
  //char *dfilter = "tcp.dstport eq 25 or udp.srcport eq 30768";
  //char *dfilter = "tcp.srcport eq 761";
  char *dfilter = "ip.version eq 4";
  //char *dfilter = "frame.number < 13";
  */

#define MAX_STR_LEN 1024
#define MAX_NUM_FIELDS 10

  char *filename = NULL;
  gsize nfields = 0;
  char **fieldnames;
  char *dfilter = NULL;

  struct option long_options[] =
    {
      {"filename",     1, 0, 0},
      {"fieldname",    1, 0, 1},
      {"dfilter",      1, 0, 2},
      {0,              0, 0, 0}
    };

  fieldnames = g_new(char*, MAX_NUM_FIELDS);

  int option_index = 0;
 
  while(1)
    {
      int val = getopt_long(argc, argv, "f:i:d:", long_options, &option_index);
      if(val == -1) break;
      switch(val)
        {
        case 'f':
        case 0:
          filename = g_strndup(optarg, MAX_STR_LEN);
          break;
        case 'i':
        case 1:
          if(nfields > MAX_NUM_FIELDS-1)
            {
              fprintf(stderr, "Error: Too many fieldnames specified (max is %d)\n", MAX_NUM_FIELDS);
              fprintf(stderr, "Recompile with a higher maximum number\n");
              return 1;
            }
          fieldnames[nfields] = g_strndup(optarg, MAX_STR_LEN);
          nfields += 1;
          break;
        case 'd':
        case 2:
          dfilter = g_strndup(optarg, MAX_STR_LEN);
          break;
        default:
          usage(argv[0]);
          return 1;
        }
    }
  
  // User must specify a filename and at least one field.
  if(nfields == 0 || filename == NULL)
    {
      g_free(fieldnames);
      usage(argv[0]);
      exit(1);
    }

  // If dfilter is not specified, provide an empty display filter (i.e. "")
  if(dfilter == NULL)
    {
      dfilter = g_new(char, 1);
      dfilter[0] = 0;
    }

  sharktools_init();

  GTree *native_types = g_tree_new((GCompareFunc)sharktools_gulong_cmp);

  gsize i;

  gulong native_type_array[] = { FT_BOOLEAN, 
                                 FT_UINT8,
                                 FT_UINT16,
                                 FT_UINT24,
                                 FT_UINT32,
                                 FT_INT8,
                                 FT_INT16,
                                 FT_INT24,
                                 FT_INT32,
                                 FT_INT64,
                                 FT_UINT64,
                                 FT_FLOAT,
                                 FT_DOUBLE,
                                 FT_ABSOLUTE_TIME,
                                 FT_RELATIVE_TIME};

  gulong native_type_array_size = (sizeof(native_type_array)/sizeof(native_type_array[0]));

  // NB: We only care about the keys, not the values.
  gulong dummy_value = 1;

  for(i = 0; i < native_type_array_size; i++)
    {
      g_tree_insert(native_types, (gpointer)native_type_array[i], (gpointer)dummy_value);
    }

  dprintf("native_types height = %d\n", g_tree_height(native_types));

  // Test program has no native data types! convert everything to string.
  sharktools_register_native_types(native_types);


  sharktools_print(filename, fieldnames, nfields, dfilter);

  sharktools_cleanup();

  // Clean up our heap variables
  if(filename)
    {
      g_free(filename);
      filename = NULL;
    }

  for(i = 0; i < nfields; i++)
    if(fieldnames[i])
      {
        g_free(fieldnames[i]);
        fieldnames[i] = NULL;
      }
  g_free(fieldnames);

  if(dfilter)
    {
      g_free(dfilter);
      dfilter = NULL;
    }

  return 0;
}
