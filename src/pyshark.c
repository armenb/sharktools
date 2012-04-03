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

#include <pyshark.h>

#define WS_VAR_IMPORT extern
#include <epan/epan.h>

extern char sharktools_errmsg[2048];

// Allow a -DDEBUG=1 to be passed to the compiler.
#define DEBUG 0
#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif

static PyTypeObject pyshark_IterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "pyshark._Iter",            /*tp_name*/
    sizeof(pyshark_Iter),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    pyshark_Iter_dealloc,    /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
      /* tp_flags: Py_TPFLAGS_HAVE_ITER tells python to
         use tp_iter and tp_iternext fields. */
    "Internal iter iterator object.",           /* tp_doc */
    0,  /* tp_traverse */
    0,  /* tp_clear */
    0,  /* tp_richcompare */
    0,  /* tp_weaklistoffset */
    pyshark_Iter_iter,  /* tp_iter: __iter__() method */
    pyshark_Iter_iternext  /* tp_iternext: next() method */
};

static PyObject *PySharkError;

static PyObject *
pyshark_iter(PyObject *self, PyObject *args)
{
  gsize i;
  char *filename;
  PyObject *keylistobj;
  const char *dfilter;
  char *decode_as = NULL;

  gint ret;
  
  // NB: Automatic sanity checks for 1st, 3rd, and optional 4th argument
  if(!PyArg_ParseTuple(args, "sOs|s", &filename, &keylistobj, &dfilter, &decode_as))
    {
      return NULL;
    }

  // NB: Explicit sanity checks needed for the second argument
  if(!PyList_Check(keylistobj))
    {
      PyErr_SetString(PyExc_TypeError, "Second argument must be a list of wireshark fieldnames");
      return NULL;
    }
  long nfields = PyList_Size(keylistobj);
  for(i = 0; i < nfields; i++)
    {
      PyObject *fieldnameobj = PyList_GetItem(keylistobj, i);

      if(!PyString_Check(fieldnameobj))
        {
          PyErr_SetString(PyExc_TypeError, "All items in second argument list must be strings");
          return NULL;
        }
    }

  /*
    Create our iterator object
  */
  pyshark_Iter *p;
  p = PyObject_New(pyshark_Iter, &pyshark_IterType);
  if(!p)
    {
      return NULL;
    }

  /*
    Initialize all our data structures in the iterator object to 0. This makes it easier
    to implement deallocation logic for both expected and unexpected cases.
   */
  p->clean = FALSE;
  p->decode_as = NULL;
  p->stdata = NULL;
  p->fieldnames = NULL;
  p->keylist = NULL;

  if(!PyObject_Init((PyObject *)p, &pyshark_IterType))
    {
      Py_DECREF(p);
      return NULL;
    }
  
  // NB: Keep a copy of the second argument as a native PyList object (which
  // contains PyStrings)
  p->keylist = keylistobj;
  Py_INCREF(p->keylist);

  // NB: Convert PyList of PyStrings to array of char *'s for sharktools
  p->fieldnames = g_ptr_array_new();
  for(i = 0; i < nfields; i++)
    {
      // NB: we know these are not NULL because of our sanity checks above
      PyObject *keyobj = PyList_GetItem(p->keylist, i);

      g_ptr_array_add(p->fieldnames, PyString_AsString(keyobj));

      // NB: Since the above array_add() call doesn't deep copy the fieldname,
      // let's increment the refcount, and decrement it when we cleanup
      Py_INCREF(keyobj);
    }

  /* If there is a decode_as string set, add it */
  if(decode_as)
    {
      ret = sharktools_add_decode_as(decode_as);
      if(ret == FALSE)
        {
          dprintf("%s\n", sharktools_errmsg);
          PyErr_SetString(PySharkError, sharktools_errmsg);
          Py_DECREF(p);
          return NULL;
        }
      // NB: Add to object state; we'll need to remove it later
      p->decode_as = strndup(decode_as, strlen(decode_as));
    }
  
  /*
   * Create and initialize sharktools' state
   */
  p->stdata = g_new0(st_data_t, 1);
  
  ret = sharktools_iter_init(p->stdata, filename, p->fieldnames, strdup(dfilter));
  if(ret < 0)
    {
      dprintf("%s\n", sharktools_errmsg);
      PyErr_SetString(PySharkError, sharktools_errmsg);
      Py_DECREF(p);
      return NULL;
    }

  p->stdata->nfields = nfields;

  // NB: We are dirty
  p->clean = FALSE;

  return (PyObject *)p;
}

PyObject *
pyshark_getDict(pyshark_Iter *p)
{
  PyObject *dictobj = PyDict_New();
  int i;

  // For each of the keys we are looking to extract values for
  long nfields = PyList_Size(p->keylist);
  for(i = 0; i < nfields; i++)
    {
      PyObject *keyobj = PyList_GetItem(p->keylist, i);
      PyObject *valueobj = pyshark_getValueByIndex(p->stdata, i);
      
      if(PyDict_SetItem(dictobj, keyobj, valueobj) != 0)
        {
          PyErr_SetString(PySharkError, "Adding key/value pair to dictionary failed\n");
          // XXX memory cleanup
          return NULL;
        }
      
      /* NB: PyDict_SetItem does not take over ownership,
         so we explicitly need to disown valueobj.
      */
      Py_DECREF(valueobj);
    }
  
  return dictobj;
}

PyObject*
pyshark_getValueByIndex(st_data_t *stdata, int i)
{
  gulong type = stdata->field_types[i];
  fvalue_t *val_native = stdata->field_values_native[i];
  const gchar *val_string = stdata->field_values_str[i];

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

  return valueobj;
}

/*
 * pyshark_Iter_iter() is intended to be registered as
 * PyTypeObject.tp_iter
 */
PyObject *
pyshark_Iter_iter(PyObject *self)
{
  //printf("%s\n", __FUNCTION__);
  Py_INCREF(self);
  return self;
}

/*
 * pyshark_Iter_iternext() is intended to be registered as
 * PyTypeObject.tp_iternext
 */
PyObject *
pyshark_Iter_iternext(PyObject *self)
{
  //printf("%s\n", __FUNCTION__);
  pyshark_Iter *p = (pyshark_Iter *)self;

  gboolean pkt_exists = sharktools_iter_next(p->stdata);
  
  if(pkt_exists)
    {
      PyObject *tmp = pyshark_getDict(p);
      return tmp;
    }
  else
    {
      /* We're done with the iterator, and hence, and {pyshark,sharktools}-specific
       * data, so run the cleanup routine.
       * 
       * NB: We also call this in pyshark_Iter_dealloc().
       * NB: This is called to aggressively remove the decode_as string, if set.
       */
      pyshark_iter_cleanup(p);

      /* Raise a standard StopIteration exception with empty value. */
      PyErr_SetNone(PyExc_StopIteration);

      return NULL;
    }
}

/*
 * pyshark_Iter_dealloc() is intended to be registered as
 * PyTypeObject.tp_dealloc
 */
void
pyshark_Iter_dealloc(PyObject *self)
{  
  //printf("%s\n", __FUNCTION__);

  /* Assuming self is not NULL, lets try deleting {pyshark,sharktools}-specific
   * data.  
   * NB: it may have already been deleted when we hit the end of the iterator
   */
  pyshark_Iter *p = (pyshark_Iter*)self;
  pyshark_iter_cleanup(p);

  Py_DECREF(self);
}

void
pyshark_iter_cleanup(pyshark_Iter *p)
{
  gsize i;
  gint ret;

  /* NB: this function can be called from the pyshark_Iter object's
     destructor, OR from running to the end of the Python iterator.
   */
  if(p->clean == TRUE)
    {
      // Already cleaned up; we're done
      return;
    }

  if(p->stdata)
    {
      sharktools_iter_cleanup(p->stdata);
      g_free(p->stdata);
      p->stdata = NULL;
    }

  if(p->fieldnames)
    g_ptr_array_free(p->fieldnames, FALSE);

  /* Remove the decode_as string (otherwise, since the setting is global,
     It will persist across calls to this function
  */
  if(p->decode_as)
    {
      ret = sharktools_remove_decode_as(p->decode_as);

      // Deallocate the decode_as string
      g_free(p->decode_as);
      p->decode_as = NULL;

      if(ret == FALSE)
        {
          // Generate the pyshark.error exception
          dprintf("%s\n", sharktools_errmsg);
          PyErr_SetString(PySharkError, sharktools_errmsg);
          return;
        }
    }

  if(p->keylist)
    {
      long nfields = PyList_Size(p->keylist);
      for(i = 0; i < nfields; i++)
        {
          PyObject *key = PyList_GetItem(p->keylist, i);
          // NB: This DECREF is for the PyString_AsString() calls, where we did NOT
          // copy the strings
          Py_DECREF(key);
        }
      Py_DECREF(p->keylist);
      p->keylist = NULL;
    }

  /* NB: All (pyshark,sharktools}-specific data should
     be deallocated at this point.
  */
  p->clean = TRUE;

  return;
}

static PyMethodDef PySharkMethods[] = {
  {"read",  pyshark_iter, METH_VARARGS, "Return a pyshark iterator"},
  {"iter",  pyshark_iter, METH_VARARGS, "Return a pyshark iterator"},

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
  pyshark_IterType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pyshark_IterType) < 0)
    return;

  // Create the pyshark module
  PyObject *m;
  m = Py_InitModule("pyshark", PySharkMethods);
  if (m == NULL)
    return;

  // Create pyshark-specific Exception
  PySharkError = PyErr_NewException("pyshark.PySharkError", NULL, NULL);
  Py_INCREF(PySharkError);
  PyModule_AddObject(m, "PySharkError", PySharkError);

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

