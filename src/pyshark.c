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
 * Sharktools 'pyshark' python module - Python interface to libsharktools
 *
 * Example invocation:
 *
 * >>> import pyshark
 * >>> b = pyshark.read('ws1.pcap',
 *                      ['frame.number', 'ip.version', 'tcp.seq', 'udp.dstport','frame.len'],
 *                      'ip.version eq 4')
 * >>> print b
 * [ {'frame.number': 6,
 *    'ip.version' : 4,
 *    'tcp.seq' : None,
 *    'udp.dstport' : 9618,
 *    'frame.len' : 1042
 *    },
 *    { ... },
 *      ...
 * ]
 *
 * Contact: Armen Babikyan, MIT Lincoln Laboratory, <armenb@mit.edu>
 */

#include "sharktools_core.h"
#include <stdlib.h>
#include <string.h>

#include <Python.h>

#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#define WS_VAR_IMPORT extern
#include <epan/epan.h>

extern char sharktools_errmsg[2048];

// Allow a -DDEBUG=1 to be passed to the compiler.
//#define DEBUG 0
#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif

static PyObject *PysharkError;

gpointer cb_row_new(sharktools_callbacks *cb)
{
  return PyDict_New();
}

gpointer cb_row_set(sharktools_callbacks *cb, gpointer row, gpointer key, gulong type, fvalue_t *val_native, const gchar *val_string)
{
  PyObject *dictobj;
  dictobj = (PyObject *)row;

  PyObject *keyobj;
  keyobj = (PyObject *)key;

  PyObject *valueobj = NULL;

  // A-priori variable declarations (because we can't declare these inline in a switch statement)
  static unsigned long tmp_unsigned_long;
  static unsigned long long tmp_unsigned_long_long;
  static long tmp_long;
  static double tmp_double;
  static nstime_t *tmp_timestamp;

  /**
   * More info on the Python type converted to is here:
   *   http://docs.python.org/c-api/arg.html
   * 
   * NB: If you add a new native type conversion, don't forget to register it in initpyshark()
   */
  switch(type)
    {
    case FT_NONE:	/* used for text labels with no value */
      valueobj = Py_BuildValue("");
      break;

    case FT_BOOLEAN:	/* TRUE and FALSE come from <glib.h> */
      /* Wireshark implements FT_BOOLEANs as uintegers. See epan/ftype/ftype-integer.c */
      tmp_unsigned_long = fvalue_get_uinteger(val_native);
      valueobj = PyBool_FromLong(tmp_unsigned_long);
      break;

    case FT_FRAMENUM:  /* a UINT32, but if selected lets you go to frame with that numbe */
      /* Wireshark implements FT_FRAMENUMs as uintegers. See epan/ftype/ftype-integer.c */
    case FT_IPXNET:
      /* Wireshark implements FT_IPXNETs as uintegers. See epan/ftype/ftype-integer.c */
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
    case FT_UINT32:
      /* FIXME: does fvalue_get_uinteger() work properly with FT_UINT{8,16,24} types? */
      tmp_unsigned_long = fvalue_get_uinteger(val_native);
      valueobj = Py_BuildValue("k", tmp_unsigned_long);
      break;

    case FT_INT8:
    case FT_INT16:
    case FT_INT24:	/* same as for UINT24 */
    case FT_INT32:
      /* FIXME: does fvalue_get_sinteger() work properly with FT_INT{8,16,24} types? */
      tmp_long = fvalue_get_sinteger(val_native);
      valueobj = Py_BuildValue("i", tmp_long);
      break;

    case FT_INT64:
      /* Wireshark doesn't seem to make a difference between INT64 and UINT64 */
    case FT_UINT64:
      tmp_unsigned_long_long = fvalue_get_integer64(val_native);
      valueobj = Py_BuildValue("K", tmp_unsigned_long_long);
      break;

    case FT_FLOAT:
    case FT_DOUBLE:
      tmp_double = fvalue_get_floating(val_native);
      valueobj = Py_BuildValue("f", tmp_double);
      break;

    case FT_ABSOLUTE_TIME:
    case FT_RELATIVE_TIME:
      {
        tmp_timestamp = fvalue_get(val_native);
        // Use fn in $wireshark/epan/nstime.c to convert timestamp to a float
        tmp_double = nstime_to_sec(tmp_timestamp);
        
        valueobj = Py_BuildValue("f", tmp_double);
        // XXX FIXME: create a Python-native time or timedelta object instead.
      }
      break;

    // Convert all the rest to strings:
    //case FT_PROTOCOL:
    //case FT_UINT_STRING:	/* for use with proto_tree_add_item() */
    //case FT_ETHER:
    //case FT_BYTES:
    //case FT_UINT_BYTES:
    //case FT_IPv4:
    //case FT_IPv6:
    //case FT_PCRE:		/* a compiled Perl-Compatible Regular Expression object */
    //case FT_GUID:		/* GUID, UUID */
    //case FT_OID:			/* OBJECT IDENTIFIER */
    default:
      valueobj = Py_BuildValue("s", val_string);
      dprintf("pyshark val_string: %s\n", val_string);
      break;
    }

  // Add the key/value pair to the dictionary
  if(PyDict_SetItem(dictobj, keyobj, valueobj) != 0)
    {
      PyErr_SetString(PysharkError, "Adding key/value pair to dictionary failed\n");
      return NULL;
    }
  
  // PyDict_SetItem does not take over ownership, so we explicitly need to disown
  // valueobj.
  Py_DECREF(valueobj);

  return NULL;
}

gpointer cb_row_add(sharktools_callbacks *cb, gpointer row)
{
  PyObject *listobj;
  listobj = (PyObject *)cb->root;
  
  PyObject *dictobj;
  dictobj = (PyObject *)row;

  // Add the dictionary to the list
  if(PyList_Append(listobj, dictobj) != 0)
    {
      PyErr_SetString(PysharkError, "Adding dictionary to list failed\n");
      return NULL;
    }

  return NULL;
}

static PyObject *pyshark_read_cb(PyObject *self, PyObject *args)
{
  char *filename;
  PyObject *fieldnamelist;
  const char *dfilter;
  char *decode_as = NULL;

  int ret;
  
  if(!PyArg_ParseTuple(args, "sOs|s", &filename, &fieldnamelist, &dfilter, &decode_as))
    {
      //PyErrPysharkError;
      return NULL;
    }

  // Check to make sure the list is a Python list.
  if(!PyList_Check(fieldnamelist))
    {
      PyErr_SetString(PysharkError, "Second argument must be a list of wireshark fields");
      return NULL;
    }

  long nfields = PyList_Size(fieldnamelist);
  gchar **fieldnames;
  fieldnames = g_new(char*, nfields);

  long size = -1;

  gsize i;
  for(i = 0; i < nfields; i++)
    {
      PyObject *fieldname = PyList_GetItem(fieldnamelist, i);

      if(!PyString_Check(fieldname))
        {
          //Error!
          // XXX memory cleanup
          return NULL;
        }

      // Returns length minus termination character, so add 1.
      size = PyString_Size(fieldname) + 1;

      fieldnames[i] = g_new(gchar, size);
      strncpy(fieldnames[i], PyString_AsString(fieldname), size-1);
      fieldnames[i][size-1] = 0; // Null terminate the string
    }

  // Add the decode_as string
  if(decode_as)
    {
      sharktools_add_decode_as(decode_as);
    }

  // Create the list into which packets will be stored
  PyObject *listobj = PyList_New((long)0);

  // Create the array of key objects
  PyObject **keys = g_new(PyObject *, nfields);

  int j;
  for(j = 0; j < nfields; j++)
    {
      //keyobjs[j] = Py_BuildValue("s", fieldnames[j]);
      keys[j] = Py_BuildValue("s#", fieldnames[j], strlen(fieldnames[j]));
    }

  // Construct a cb "object" with state variables and callbacks 
  sharktools_callbacks cb;
  cb.root = (gpointer)listobj;
  cb.keys = (gpointer *)keys;
  cb.row_new = cb_row_new;
  cb.row_set = cb_row_set;
  cb.row_add = cb_row_add;

  //dprintf("sharktools_get starting\n");

  ret = sharktools_get_cb(filename, nfields, (const gchar**)fieldnames, strdup(dfilter), &cb);
  
  // Remove the decode_as string (otherwise, since the setting is global,
  // It will persist across calls to this function
  if(decode_as)
    {
      sharktools_remove_decode_as(decode_as);
    }

  //dprintf("sharktools_get done\n");

  // Don't need to free each key because these are in the returned list
  g_free(keys);

  for(i = 0; i < nfields; i++)
    {
      //Py_DECREF(keyobjs[j]);
      g_free(fieldnames[i]);
    }
  g_free(fieldnames);

  if(ret)
    {
      dprintf("%s\n", sharktools_errmsg);
      PyErr_SetString(PysharkError, sharktools_errmsg);
      return NULL;
    }

  return listobj;
}

static PyMethodDef PysharkMethods[] = {
  //{"read",  pyshark_read, METH_VARARGS,
  //"Run pyshark_read"},
  {"read",  pyshark_read_cb, METH_VARARGS,
   "Run pyshark_read_cb"},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};

#if DEBUG==0
static void log_func_ignore (const gchar *log_domain, GLogLevelFlags log_level,
			     const gchar *message, gpointer user_data)
{
}
#endif

PyMODINIT_FUNC
initpyshark(void)
{
  // Create the pyshark module
  PyObject *m;
  m = Py_InitModule("pyshark", PysharkMethods);
  if (m == NULL)
    return;

  // Create pyshark-specific Exception
  PysharkError = PyErr_NewException("pyshark.error", NULL, NULL);
  Py_INCREF(PysharkError);
  PyModule_AddObject(m, "error", PysharkError);

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


  // Handle all GLib messages with a fn that throws them away
  g_log_set_handler ("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
		     log_func_ignore, NULL);


  //g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
  //log_flags,
  //log_func_ignore, NULL /* user_data */);
#endif

  sharktools_init();

  // Create a binary tree with Wireshark types that can be natively casted
  // to Python types.
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

  // Register the native_types with the sharktools engine
  sharktools_register_native_types(native_types);
}


//////////////////////////////////////////////////////////////

