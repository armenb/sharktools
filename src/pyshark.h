



#ifndef PYSHARK_H
#define PYSHARK_H

#define HAVE_STDARG_H /* for using stdarg.h instead of varargs.h */
#include <Python.h>

typedef struct {
  PyObject_HEAD
  char *decode_as;
  st_data_t *stdata;
  PyObject **keyobjs;
} pyshark_MyIter;



static PyObject *pyshark_myiter(PyObject *self, PyObject *args);

PyObject *pyshark_getDict(pyshark_MyIter *p);

PyObject *pyshark_getValueForKey(PyObject *keyobj, gulong type, fvalue_t *val_native, const gchar *val_string);

PyObject *pyshark_MyIter_iter(PyObject *self);

PyObject* pyshark_MyIter_iternext(PyObject *self);

void pyshark_iter_cleanup(pyshark_MyIter *p);

PyMODINIT_FUNC initpyshark(void);








#endif //PYSHARK_H
