#ifndef PYSHARK_H
#define PYSHARK_H

#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#include <Python.h>

typedef struct {
  PyObject_HEAD
  gboolean clean; // NB: specifies whether or not the dealloc routine has been called
  char *decode_as;
  st_data_t *stdata;
  GPtrArray *fieldnames;
  GPtrArray *wfieldnames;
  GPtrArray *nwpykeylist;
  GHashTable *wpykeyhash;
} pyshark_Iter;

static PyObject *pyshark_iter(PyObject *self, PyObject *args);

PyObject *pyshark_getDict(pyshark_Iter *p);
//PyObject *pyshark_getValueByIndex(st_data_t *stdata, int i);
PyObject *pyshark_getTypedValue(gulong type, GPtrArray* tree_values);


// Functions to be registered in PyTypeObject struct
PyObject *pyshark_Iter_iter(PyObject *self);
PyObject* pyshark_Iter_iternext(PyObject *self);
void pyshark_Iter_dealloc(PyObject *self);

void pyshark_iter_cleanup(pyshark_Iter *p);

PyMODINIT_FUNC initpyshark(void);

#endif //PYSHARK_H
