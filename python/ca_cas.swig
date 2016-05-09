%module(docstring="Python Interface for Cantera CAS") ca_cas

%feature("docstring", "Retreive one or more objects from CAS");
PyObject* get(PyObject* key);

%feature("docstring", "Store one or more objects in CAS");
PyObject* put(PyObject* data);

%{
#include "python/cas.h"
%}
