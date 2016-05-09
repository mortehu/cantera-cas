#ifndef PYTHON_CAS_H_
#define PYTHON_CAS_H_ 1

#include <Python.h>

PyObject* get(PyObject* key);
PyObject* put(PyObject* data);

#endif  // !PYTHON_CAS_H_
