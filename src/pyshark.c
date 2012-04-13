/* Copyright (c) 2007-2012
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

/* Allow a -DDEBUG=1 to be passed to the compiler. */
#define DEBUG 0
#if DEBUG
#define dprintf(args...) printf(args)
#else
#define dprintf(args...) ((void)0)
#endif

static PyMethodDef pyshark_Iter_methods[] = {
    {"setAllowSingleElementLists",
     (PyCFunction)pysharkIter_setAllowSingleElementLists,
     METH_NOARGS,
     "yay setAllowSingleElementLists\n"
     "hmm."},
    /*
    {"data", (PyCFunction)Sequence_data, METH_NOARGS,
     "sequence.data() -> iterator object\n"
     "Returns iterator of range [0, sequence.max)."},
    */
    {NULL} /* Sentinel */
};

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
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    pyshark_Iter_iter,         /* tp_iter: __iter__() method */
    pyshark_Iter_iternext,     /* tp_iternext: next() method */
    pyshark_Iter_methods,      /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Sequence_init,   /* tp_init */
    0,                         /* tp_alloc */
    PyType_GenericNew,         /* tp_new */
};

static PyObject *PySharkError;

static PyObject *Sequence_data(SequenceObject *self, PyObject *args)
{
    size_t *info = malloc(sizeof(size_t));
    if (info == NULL) return NULL;
    *info = 0;

    /* |info| will be free'()d by the returned generator object. */
    GeneratorObject *ret = Generator_New(self, info, true,
                                         &Sequence_data_next_callback);
    if (ret == NULL) {
        free(info); /* Watch out for memory leaks! */
    }
    return ret;
}

static gpointer
pyshark_format_field(gpointer item, gchar *format)
{
  if(strcmp(format,"s") == 0) {
    return Py_BuildValue(format, item);
  }
  else if(strcmp(format,"T") == 0) {
    nstime_t *tmp_timestamp = fvalue_get( item );
    /* Use fn in $wireshark/epan/nstime.c to convert timestamp to a float */
    double tmp_double = nstime_to_sec(tmp_timestamp);

    /* TODO: create a Python-native time or timedelta object instead (?) */
    return Py_BuildValue("f", tmp_double);
  }
  else if(strcmp(format,"f") == 0) {
    double tmp_double = fvalue_get_floating( item );
    return Py_BuildValue(format, tmp_double);
  }
  else if(strcmp(format,"K") == 0) {
    unsigned long long tmp_unsigned_long_long = fvalue_get_integer64( item );
    return Py_BuildValue(format, tmp_unsigned_long_long);
  }
  else if(strcmp(format,"i") == 0) {
    /* FIXME: does fvalue_get_sinteger() work properly with FT_INT{8,16,24} types? */
    unsigned long tmp_long = fvalue_get_sinteger( item );
    return Py_BuildValue(format, tmp_long);
  }
  else if(strcmp(format,"k") == 0) {
    unsigned long tmp_unsigned_long = fvalue_get_uinteger( item );
    return Py_BuildValue(format, tmp_unsigned_long);
  }
  else if(strcmp(format,"B") == 0) {
    /* Wireshark implements FT_BOOLEANs as uintegers. See epan/ftype/ftype-integer.c */
    unsigned long tmp_unsigned_long = fvalue_get_uinteger( item );
    return PyBool_FromLong(tmp_unsigned_long);
  }
  else
    return NULL;
}

static gpointer
pyshark_getTypedValue(GPtrArray* tree_values, gchar *format, gboolean allow_single_elem_list)
{
  if(!allow_single_elem_list && tree_values->len == 1) {
    return pyshark_format_field(g_ptr_array_index(tree_values, 0), format);
  }
  else {
    gint i;
    PyObject *valueobj = PyList_New((long)0);

    for(i = 0; i < tree_values->len; ++i) {
      PyList_Append(valueobj, pyshark_format_field(g_ptr_array_index(tree_values, i), format));
    }
    
    return valueobj;
  }
}

static PyObject *
pyshark_iter(PyObject *self, PyObject *args)
{
  gsize i;
  char *filename;
  PyObject *keylistobj;
  const char *dfilter;
  char *decode_as = NULL;
  pyshark_Iter *p;

  gint ret;
  
  /* NB: Automatic sanity checks for 1st, 3rd, and optional 4th argument */
  if(!PyArg_ParseTuple(args, "sOs|s", &filename, &keylistobj, &dfilter, &decode_as)) {
    return NULL;
  }

  /* NB: Explicit sanity checks needed for the second argument */
  if(!PyList_Check(keylistobj)) {
    PyErr_SetString(PyExc_TypeError, "Second argument must be a list of wireshark fieldnames");
    return NULL;
  }

  for(i = 0; i < PyList_Size(keylistobj); i++) {
    PyObject *fieldnameobj = PyList_GetItem(keylistobj, i);
    
    if (!PyString_Check(fieldnameobj)) {
      PyErr_SetString(PyExc_TypeError, "All items in second argument list must be strings");
      return NULL;
    }
  }

  /*
    Create our iterator object
  */
  p = PyObject_New(pyshark_Iter, &pyshark_IterType);
  if(!p) {
    return NULL;
  }

  /*
    Initialize all our data structures in the iterator object to 0. This makes it easier
    to implement deallocation logic for both expected and unexpected cases.
   */
  p->clean = FALSE;
  p->decode_as = NULL;
  p->stdata = NULL;
  p->nwpykeylist = NULL;
  p->wpykeyhash = NULL;
  p->asel = FALSE;
  p->ane = TRUE;

  if(!PyObject_Init((PyObject *)p, &pyshark_IterType)) {
    Py_DECREF(p);
    return NULL;
  }
  
  p->stdata = stdata_new();
  if(!p->stdata) {
    Py_DECREF(p);
    return NULL;
  }
  
  p->wpykeyhash = g_hash_table_new(g_str_hash, g_str_equal);

  p->nwpykeylist = g_ptr_array_new();

  /*
    Iterate through the Python List and add to either fieldnames OR wfieldnames
   depending on presence of a '*' in the string
  */
  for(i = 0; i < PyList_Size(keylistobj); i++) {
    /* NB: we know these are not NULL because of our sanity checks above */
    PyObject *keyobj = PyList_GetItem(keylistobj, i);
    
    /* Check for wildcard entries, e.g. "*", "ip.*", "eth.*", etc. */
    const gchar *key = PyString_AsString(keyobj);
    gchar *ptr = g_strstr_len(key, strnlen(key, 100), "*");

    if(ptr) {
      /* We have a fieldname with a wildcard in it
       * 
       * Use pointer arithmetic to figure out the length
       * TODO: better way to do this, maybe?
       */
      gsize prefix_len = (gsize)ptr - (gsize)key;
      
      g_ptr_array_add(p->stdata->wfieldnames, g_strndup(key, prefix_len));
    }
    else {
      /*
       * Non-wildcard entry.
       */
      g_ptr_array_add(p->stdata->fieldnames, PyString_AsString(keyobj));
          
          /* On the python-module side of things, keep a list of python objects,
             one for each non-wildcard fieldname to be processed by sharktools.
             NB: the index between entries in p->{stdata->fieldnames,nwpykeylist}
             MUST be the same.
          */
          g_ptr_array_add(p->nwpykeylist, keyobj);

          /* The above array_add() call doesn't deep copy the fieldname,
             let's increment the refcount, and decrement it when we cleanup.
             NB: also used for our copy of the key in p->nwpykeylist
          */
          Py_INCREF(keyobj);
        }
    }

  /* If there is a decode_as string set, add it */
  if(decode_as) {
    dprintf("decode as string added: %s\n", decode_as);
    ret = sharktools_add_decode_as(decode_as);
    if(ret == FALSE) {
      dprintf("%s\n", sharktools_errmsg);
      PyErr_SetString(PySharkError, sharktools_errmsg);
      Py_DECREF(p);
      return NULL;
    }
    /* NB: Add to object state; we'll need to remove it later */
    p->decode_as = strndup(decode_as, strlen(decode_as));
  }
  
  /*
   * Create and initialize sharktools' state
   */
  ret = sharktools_iter_init(p->stdata, filename, strdup(dfilter));
  if(ret < 0) {
    dprintf("%s\n", sharktools_errmsg);
    PyErr_SetString(PySharkError, sharktools_errmsg);
    Py_DECREF(p);
    return NULL;
  }

  /* NB: We are dirty */
  p->clean = FALSE;

  return (PyObject *)p;
}

typedef struct ht_foreach
{
  GHashTable *wtree_type_hash;
  GHashTable *wpykeyhash;
  PyObject *dictobj;
  gboolean asel; /* "Allow Single Element Lists" */
  gboolean ane;  /* "Allow None Entries" */
} ht_foreach_t;

static void
my_ht_foreach_fn(gpointer key, gpointer value, gpointer user_data)
{
  /*
    Unpack
   */
  ht_foreach_t *htft = user_data;
  GHashTable *wtree_type_hash = htft->wtree_type_hash;
  GHashTable *wpykeyhash = htft->wpykeyhash;
  PyObject *dictobj = htft->dictobj;
  gboolean asel = htft->asel;

  /* Get the PyString object of the key (and make one if it doesn't) */
  PyObject *keyobj = g_hash_table_lookup(wpykeyhash, key);
  if(!keyobj) {
    keyobj = Py_BuildValue("s", key);
    g_hash_table_insert(wpykeyhash, key, keyobj);
    Py_INCREF(keyobj);
  }
  
  GPtrArray* wtree_values = value;
  
  /* NB: gpointer is being cast as a gulong; hash table holds
     values, NOT pointers to values
  */
  gulong type = (gulong)g_hash_table_lookup(wtree_type_hash, key);
  //dprintf("type: %d\n", type);

  PyObject *valueobj = pyshark_getValueWithType(wtree_values, type, asel);
  
  if(PyDict_SetItem(dictobj, keyobj, valueobj) != 0) {
    PyErr_SetString(PySharkError, "Adding key/value pair to dictionary failed\n");
  }
  
  /* NB: PyDict_SetItem does not take over ownership,
     so we explicitly need to disown valueobj.
  */
  Py_DECREF(valueobj);
}


PyObject *
pyshark_getDict(pyshark_Iter *p)
{
  PyObject *dictobj = PyDict_New();
  gint i;

  /* Get all the non-wildcard entries
   */
  for(i = 0; i < p->nwpykeylist->len; i++) {
    PyObject *keyobj = g_ptr_array_index(p->nwpykeylist, i);
    
    gulong type;
    type = p->stdata->field_types[i];
    type = g_array_index(p->stdata->tree_types, gulong, i);

    GPtrArray* tree_values = g_ptr_array_index(p->stdata->tree_values, i);
    
    PyObject *valueobj = pyshark_getValueWithType(tree_values, type, p->asel);
    
    if(PyDict_SetItem(dictobj, keyobj, valueobj) != 0) {
      PyErr_SetString(PySharkError, "Adding key/value pair to dictionary failed\n");
      /* XXX memory cleanup */
      return NULL;
    }
    
    /* NB: PyDict_SetItem does not take over ownership,
       so we explicitly need to disown valueobj.
    */
    Py_DECREF(valueobj);
  }

  /* Get all the wildcard entries
   * 
   * NB: We use g_hash_table_foreach() instead of GHashTableIter for
   * backwards compatibility with Glib 2.12, which is the only (standard)
   * option present on RHEL5.
   */
  ht_foreach_t htft;
  htft.wtree_type_hash = p->stdata->wtree_types;
  htft.wpykeyhash = p->wpykeyhash;
  htft.dictobj = dictobj;
  htft.asel = p->asel;
  htft.ane = p->ane;

  g_hash_table_foreach(p->stdata->wtree_values, my_ht_foreach_fn, &htft);

  return dictobj;
}

PyObject*
pyshark_getValueWithType(GPtrArray* tree_values, gulong type, gboolean asel)
{
  PyObject *valueobj = NULL;

  /**
   * More info on the Python type converted to is here:
   *   http://docs.python.org/c-api/arg.html
   * 
   * NB: If you add a new native type conversion, don't forget to register it in initpyshark()
   */
  switch(type) {
  case FT_NONE:	/* used for text labels with no value */
    valueobj = Py_BuildValue("");
    break;
    
  case FT_BOOLEAN:	/* TRUE and FALSE come from <glib.h> */
    valueobj = pyshark_getTypedValue(tree_values, "B", asel);
    break;
    
  case FT_FRAMENUM:  /* a UINT32, but if selected lets you go to frame with that numbe */
    /* Wireshark implements FT_FRAMENUMs as uintegers. See epan/ftype/ftype-integer.c */
  case FT_IPXNET:
    /* Wireshark implements FT_IPXNETs as uintegers. See epan/ftype/ftype-integer.c */
  case FT_UINT8:
  case FT_UINT16:
  case FT_UINT24:	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
  case FT_UINT32:
    valueobj = pyshark_getTypedValue(tree_values, "k", asel);
    break;
    
  case FT_INT8:
  case FT_INT16:
  case FT_INT24:	/* same as for UINT24 */
  case FT_INT32:
    valueobj = pyshark_getTypedValue(tree_values, "i", asel);
    break;
    
  case FT_INT64:
    /* Wireshark doesn't seem to make a difference between INT64 and UINT64 */
  case FT_UINT64:
    valueobj = pyshark_getTypedValue(tree_values, "K", asel);
    break;
    
  case FT_FLOAT:
  case FT_DOUBLE:
    valueobj = pyshark_getTypedValue(tree_values, "f", asel);
    break;
    
  case FT_ABSOLUTE_TIME:
  case FT_RELATIVE_TIME:
    valueobj = pyshark_getTypedValue(tree_values, "T", asel);
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
  //case FT_PCRE:		/* a compiled Perl-Compatible Regular Expression object */
  //case FT_GUID:		/* GUID, UUID */
  //case FT_OID:			/* OBJECT IDENTIFIER */
#endif
  default:
    valueobj = pyshark_getTypedValue(tree_values, "s", asel);
    break;
  }

  return valueobj;
}

/*
 * Helper method to deallocate ptr_arrays set as values in a hashtable
 */
static void
my_ht_value_ptrarray_free_fn(gpointer key, gpointer value, gpointer user_data)
{
  g_ptr_array_free(value, TRUE);
}

/*
 * pyshark_Iter_iter() is intended to be registered as
 * PyTypeObject.tp_iter
 */
PyObject *
pyshark_Iter_iter(PyObject *self)
{
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
  pyshark_Iter *p = (pyshark_Iter *)self;

  gboolean pkt_exists = sharktools_iter_next(p->stdata);
  
  if(pkt_exists) {
    PyObject *tmp = pyshark_getDict(p);
    gsize i;
    
    /* Reset tree_values */
    g_ptr_array_free(p->stdata->tree_values, TRUE);
    p->stdata->tree_values = g_ptr_array_new();
    for(i = 0; i < p->stdata->fieldnames->len; i++) {
        g_ptr_array_add(p->stdata->tree_values, g_ptr_array_new() ); 
      }
    
    /* Reset wtree_values
     * Call our helper method to deallocate the pointer arrays that are set
     * as values in the hash table
     */
    g_hash_table_foreach(p->stdata->wtree_values, my_ht_value_ptrarray_free_fn, NULL);
    
    g_hash_table_remove_all(p->stdata->wtree_values);
    
    return tmp;
  }
  else {
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
  /* Assuming self is not NULL, lets try deleting {pyshark,sharktools}-specific
   * data.  
   * NB: it may have already been deleted; i.e. if we hit the end of the iterator
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
  if(p->clean == TRUE) {
    /* Already cleaned up; we're done */
    return;
  }

  if(p->stdata) {
    sharktools_iter_cleanup(p->stdata);
    stdata_free(p->stdata);
    p->stdata = NULL;
  }

  /* Remove the decode_as string (otherwise, since the setting is global,
     It will persist across calls to this function
  */
  if(p->decode_as) {
    ret = sharktools_remove_decode_as(p->decode_as);
    
    g_free(p->decode_as);
    p->decode_as = NULL;
    
    if(ret == FALSE) {
      /* Generate the pyshark.error exception */
      dprintf("%s\n", sharktools_errmsg);
      PyErr_SetString(PySharkError, sharktools_errmsg);
      return;
    }
  }

  if(p->nwpykeylist) {
    for(i = 0; i < p->nwpykeylist->len; i++) {
      PyObject *key = g_ptr_array_index(p->nwpykeylist, i);
      /* NB: This DECREF is for the PyString_AsString() calls, where we did NOT
       copy the strings
      */
      Py_DECREF(key);
    }
    g_ptr_array_free(p->nwpykeylist, FALSE);
    p->nwpykeylist = NULL;
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
  PyObject *m;
  GTree *native_types;
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

  gulong native_type_array_size;
  gulong dummy_value = 1;

  pyshark_IterType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pyshark_IterType) < 0)
    return;

  /* Create the pyshark module */
  m = Py_InitModule("pyshark", PySharkMethods);
  if (m == NULL)
    return;

  /* Create pyshark-specific Exception */
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


  /* Handle all GLib messages with a fn that throws them away */
  g_log_set_handler ("GLib", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL,
		     log_func_ignore, NULL);
#endif

  sharktools_init();

  /* Create a binary tree with Wireshark types that can be natively casted
     to Python types.
  */
  native_types = g_tree_new((GCompareFunc)sharktools_gulong_cmp);

  native_type_array_size = (sizeof(native_type_array)/sizeof(native_type_array[0]));

  /* NB: We only care about the keys, not the values */
  dummy_value = 1;

  for(i = 0; i < native_type_array_size; i++) {
    g_tree_insert(native_types, (gpointer)native_type_array[i], (gpointer)dummy_value);
  }

  dprintf("native_types height = %d\n", g_tree_height(native_types));

  /* Register the native_types with the sharktools engine */
  sharktools_register_native_types(native_types);
}

