#ifndef PYSHARK_H
#define PYSHARK_H

#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#include <Python.h>

typedef struct {
  PyObject_HEAD
  gboolean clean;
  char *decode_as;
  st_data_t *stdata;
  PyObject **keyobjs;
} pyshark_Iter;

static PyObject *pyshark_iter(PyObject *self, PyObject *args);

PyObject *pyshark_getDict(pyshark_Iter *p);
PyObject *pyshark_getValueForKey(PyObject *keyobj, gulong type, fvalue_t *val_native, const gchar *val_string);

// Functions to be registered in PyTypeObject struct
PyObject *pyshark_Iter_iter(PyObject *self);
PyObject* pyshark_Iter_iternext(PyObject *self);
void pyshark_Iter_dealloc(PyObject *self);

void pyshark_iter_cleanup(pyshark_Iter *p);

PyMODINIT_FUNC initpyshark(void);

#endif //PYSHARK_H
