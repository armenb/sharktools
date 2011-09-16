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
 * Sharktools 'matshark' mex function - Matlab interface to libsharktools
 *
 * Contact: Armen Babikyan, MIT Lincoln Laboratory, <armenb@mit.edu>
 */

#include <mex.h>
#include "matrix.h"
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include "sharktools_core.h"

#define BUFSIZE 1024

/* Allow a -DDEBUG=1 to be passed to the compiler. */
#define DEBUG 0
#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif

extern char sharktools_errmsg[2048];

#if DEBUG==0
static void log_func_ignore (const gchar *log_domain, GLogLevelFlags log_level,
			     const gchar *message, gpointer user_data)
{
}
#endif

static int initialized = FALSE;

gpointer cb_row_new(sharktools_callbacks *cb)
{
  dprintf("%s: entering\n", __FUNCTION__);
  dprintf("%s: leaving\n", __FUNCTION__);

  return (gpointer)(cb->count);

}

gpointer cb_row_set(sharktools_callbacks *cb, gpointer row, gpointer key, gulong type, fvalue_t *val_native, const gchar *val_string)
{
  dprintf("%s: entering\n", __FUNCTION__);

  long li = (long)row;
  long *lj = (long*)key;

  mxArray *mx = (mxArray *)cb->root;
  int i = (int)li;
  int j = (int)*lj;

  dprintf("mx = %p ; i = %d ; j = %X\n", mx, i, j);

  mxArray *obj = NULL;
  
  /*
   * Apriori variable declarations (because we can't declare these inline in a switch statement)
   */

  static unsigned long tmp_unsigned_long;
  static unsigned long long tmp_unsigned_long_long;
  static long tmp_long;
  static double tmp_double;
  static nstime_t *tmp_timestamp;

  int ndim;
  int *dims;

  /*
   * MATLAB doesn't seem to make a distinction between doubles, booleans, unsigned integers and
   * signed integers;  MATLAB uses 64-bit floating point numbers (i.e. mxREALs, aka double) to
   * represent all of these. So here, we convert Wireshark types to their respective native C
   * data types, then convert it to double before passing to MATLAB.
   */

  /*printf("%s (%d)\t\t", val_string, (int)type);*/
  switch(type)
    {
    case FT_NONE:	/* used for text labels with no value */
      /* Create a "[]" in matlab: */
      dprintf("NONE\n");
      ndim = 0;
      dims = NULL;
      obj = mxCreateNumericArray(ndim, dims, mxUINT32_CLASS, mxREAL);
      break;

    case FT_BOOLEAN:	/* TRUE and FALSE come from <glib.h> */
      /* Wireshark considers booleans as uintegers. See epan/ftype/ftype-integer.c */
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
    case FT_UINT32:
      /* FIXME: does fvalue_get_uinteger() work properly with FT_UINT{8,16,24} types? */
      tmp_unsigned_long = fvalue_get_uinteger(val_native);
      tmp_double = tmp_unsigned_long; /* convert from long to double */
      obj = mxCreateDoubleMatrix(1, 1, mxREAL);
      *mxGetPr(obj) = tmp_double;
      break;

    case FT_INT8:
    case FT_INT16:
    case FT_INT24:	/* same as for UINT24 */
    case FT_INT32:
      /* FIXME: does fvalue_get_sinteger() work properly with FT_INT{8,16,24} types? */
      tmp_long = fvalue_get_sinteger(val_native);
      tmp_double = tmp_long; /* convert from long to double */
      obj = mxCreateDoubleMatrix(1, 1, mxREAL);
      *mxGetPr(obj) = tmp_double;
      break;

    case FT_INT64:
      /* Wireshark doesn't seem to make a difference between INT64 and UINT64 */
    case FT_UINT64:
      tmp_unsigned_long_long = fvalue_get_integer64(val_native);
      tmp_double = tmp_unsigned_long_long; /* convert from uint64 to double */
      obj = mxCreateDoubleMatrix(1, 1, mxREAL);
      *mxGetPr(obj) = tmp_double;
      break;

    case FT_FLOAT:
    case FT_DOUBLE:
      tmp_double = fvalue_get_floating(val_native);
      obj = mxCreateDoubleMatrix(1, 1, mxREAL);
      *mxGetPr(obj) = tmp_double;
      break;

    case FT_ABSOLUTE_TIME:
    case FT_RELATIVE_TIME:
      tmp_timestamp = fvalue_get(val_native);
      /* Use fn in $wireshark/epan/nstime.c to convert timestamp to a float */
      tmp_double = nstime_to_sec(tmp_timestamp);
      obj = mxCreateDoubleMatrix(1, 1, mxREAL);
      *mxGetPr(obj) = tmp_double;
      break;

#if 0
    // Convert all the rest to strings:
    //case FT_PROTOCOL:
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
#endif
    default:
      obj = mxCreateString(val_string);
      break;
    }

  mxSetFieldByNumber(mx, i, j, obj);
  
  /* printf("%s (%d)\t\t", value, type); */
  
  dprintf("%s: leaving\n", __FUNCTION__);

  return NULL;
}

gpointer cb_row_add(sharktools_callbacks *cb, gpointer row)
{
  dprintf("%s: entering\n", __FUNCTION__);
  int rownum;
  rownum = (long)row;

  cb->count++;

  if(cb->count != rownum)
    {
      dprintf("cb->count = %d, rownum = %d\n", cb->count, rownum);
    }

  dprintf("%s: leaving\n", __FUNCTION__);

  return NULL;
}

void mexFunction(int nlhs, mxArray *plhs[],
		 int nrhs, const mxArray *prhs[]) {
  int m, i;
  mxArray *tmp;
  char *filename;
  char **fieldnames;
  char **mx_fieldnames;
  int nfields;
  char *dfilter;
  char *decode_as = NULL;

  int ret;

#if DEBUG==0
  GLogLevelFlags       log_flags;
  
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
  
  
  /*
    Handle all GLib messages with a fn that throws them away
  */
  g_log_set_handler ("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
		     log_func_ignore, NULL);
  
#if 0
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
                    log_flags,
                    log_func_ignore, NULL /* user_data */);
#endif
#endif
  
  dprintf("%s: entering...\n", __FUNCTION__);
  
  /* Register all dissectors, and only once (otherwise assertions will fail) */
  if(!initialized)
    {
      sharktools_init();

      /* Create a binary tree with Wireshark types that can be natively casted
       * to Matlab types.
       */
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
      
      /* NB: We only care about the keys, not the values. */
      gulong dummy_value = 1;
      
      for(i = 0; i < native_type_array_size; i++)
        {
          g_tree_insert(native_types, (gpointer)native_type_array[i], (gpointer)dummy_value);
        }
      
      dprintf("native_types height = %d\n", g_tree_height(native_types));

      /* Register the native_types with the sharktools engine */
      sharktools_register_native_types(native_types);
      
      initialized = TRUE;
    }
  
  if(nrhs < 3)
    mexErrMsgTxt("Must provide filename, cell array of fieldnames, and display filter");
  
  if(mxIsChar(prhs[0]) != 1)
    mexErrMsgTxt("1st arg (filename) must be a string");
  
  if(mxIsCell(prhs[1]) != 1)
    mexErrMsgTxt("2nd arg (fields) must be a cellarray of strings");
  
  if(mxIsChar(prhs[2]) != 1)
    mexErrMsgTxt("3rd arg (filter) must be a string");
  
  if(nrhs == 4)
    {
      if(mxIsChar(prhs[3]) != 1)
        mexErrMsgTxt("4th arg (decode_as rule) must be a string");
      
      decode_as = mxCalloc(BUFSIZE, sizeof(char));
      if(mxGetString(prhs[3], decode_as, BUFSIZE))
        mexErrMsgTxt("error getting decode_as string");
      
      dprintf("decode_as = %s\n", decode_as);
      
      sharktools_add_decode_as(decode_as);
    }
  
  filename = mxCalloc(BUFSIZE, sizeof(char));
  if(mxGetString(prhs[0], filename, BUFSIZE))
    mexErrMsgTxt("error getting pcap filename string");
  
  dprintf("pcap filename = %s\n", filename);
  
  /* Get the number of fields */
  nfields = mxGetNumberOfElements(prhs[1]);
  dprintf("nfields = %d\n", nfields);
  
  fieldnames = g_new(char*, nfields);
  mx_fieldnames = mxCalloc(nfields, sizeof(char*));
  
  for(i = 0; i < nfields; i++)
    {
      mxArray *tmp;
      tmp = mxGetCell(prhs[1], i);

      /*
       * Get a copy of the fieldnames for sharkcore
       */
      fieldnames[i] = g_new(char, BUFSIZE);

      if(mxGetString(tmp, fieldnames[i], BUFSIZE))
	mexErrMsgTxt("error getting a field string");

      /*
       * Get a copy of the fieldnames for Matlab
       */
      mx_fieldnames[i] = mxCalloc(BUFSIZE, sizeof(char));
      
      if(mxGetString(tmp, mx_fieldnames[i], BUFSIZE))
	mexErrMsgTxt("error getting a field string");
      
      /*
       * In Matlab's copy of the fieldnames, replace each "."
       * character in the field name with a "_" (In Matlab, '.'
       * is not a valid character in a fieldname)
       */
      char *s;
      s = mx_fieldnames[i];
      char *c = NULL;
      while((c = strchr(s, '.')))
	{
	  *c = '_';
	}

      /* printf("field #%d = %s\n", i, mx_fieldnames[i]); */
    }
  
  dfilter = mxCalloc(BUFSIZE, sizeof(char));
  if(mxGetString(prhs[2], dfilter, BUFSIZE))
    mexErrMsgTxt("error getting filter string");
  
  dprintf("filter = %s\n", dfilter);
  
  /*
   * Matlab doesn't (as far as I can tell) have an efficient mechanism to
   * let a program dynamically expand a data structure.  It has mxRealloc(),
   * but this seems to work just like a plain realloc() - an expensive
   * operation that allocates a new contiguous block of memory and copies
   * data from the old to the new, leaving the extra values uninitialized.
   *
   * It would be great to see Mathworks create a mxRealloc() that uses Linux's
   * mremap() - this would make mxRealloc() very efficient.
   *
   * In the meantime, we use sharktools_count() to walk through the pcap
   * file, and count the number of entries we need to prescribe in the
   * creation of the object we return to the Matlab interpreter.
   *
   * There is a tradeoff;  we are sacrificing time efficiency for memory
   * efficiency, but dealing with time efficiency is considerably easier than
   * dealing with memory efficiency.
   */

  int count;
  count = (int)sharktools_count(filename, dfilter);
  dprintf("count = %d\n", count);

  if(count < 0)
    {
      mexErrMsgTxt(sharktools_errmsg);
    }

  m = 1;
  mxArray *mx;
  mx = mxCreateStructMatrix(m, count, nfields, (const char**) mx_fieldnames);

  /*
   * Here, we create a list of keys that is simply an integer index
   */
  int **keys = g_new(int*, nfields);
  for(i = 0; i < nfields; i++)
    {
      keys[i] = g_new(int, 1);
      *keys[i] = i;
    }

  /*
   * Construct a cb "object" with state variables and callbacks 
   */
  sharktools_callbacks cb;
  cb.root = (gpointer)mx;
  cb.keys = (gpointer *)keys;
  cb.count = 0;
  cb.row_new = cb_row_new;
  cb.row_set = cb_row_set;
  cb.row_add = cb_row_add;

  ret = sharktools_get_cb(filename, nfields, (const gchar**)fieldnames, dfilter, &cb);
  
  if(!mexIsLocked())
    {
      /* Lock this function so that static variables are not reset by
       * "clear" in Matlab.
       */
      mexLock();
    }
  
  /* Remove the decode_as string (otherwise, since the setting is global,
   * it will persist across calls to this function)
   */
  if(decode_as)
    {
      sharktools_remove_decode_as(decode_as);
    }

  /*
   * Free memory
   */
  for(i = 0; i < nfields; i++)
    {
      g_free(keys[i]);
      g_free(fieldnames[i]);
    }

  g_free(keys);
  g_free(fieldnames);

  if(ret)
    {
      mexErrMsgTxt(sharktools_errmsg);
    }
  
  plhs[0] = mx;
}

/****************** CRUFT follows ******************/

