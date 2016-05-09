#include "python/cas.h"

#include <mutex>

#include <kj/async-io.h>

#include "src/client.h"

namespace {

struct CASClientState {
  CASClientState() : aio_context(kj::setupAsyncIo()), cas_client(aio_context) {}

  kj::AsyncIoContext aio_context;
  cantera::CASClient cas_client;
};

// CASClientState singleton constructor.
CASClientState* GetState() {
  static CASClientState state;
  return &state;
}

// Converts a Python 'bytes' object to cantera::string_view.  Throws an
// exception if the input is not a 'bytes' object.
cantera::string_view AsStringView(PyObject* value) {
  KJ_REQUIRE(PyBytes_Check(value));
  return {PyBytes_AS_STRING(value), static_cast<size_t>(PyBytes_GET_SIZE(value))};
}

}  // namespace

PyObject* get(PyObject* key_arg) {
  try {
    auto state = GetState();

    if (PyList_Check(key_arg)) {
      // When a list of keys is requested, we issue simultaneous requests for
      // all the requested objects.

      auto count = PyList_Size(key_arg);

      auto promise_array_builder =
          kj::heapArrayBuilder<kj::Promise<kj::Array<const char>>>(count);

      for (size_t i = 0; i < count; ++i) {
        const auto key_item = PyList_GetItem(key_arg, i);
        promise_array_builder.add(state->cas_client.GetAsync(AsStringView(key_item)));
      }

      auto datas = kj::joinPromises(promise_array_builder.finish())
                       .wait(state->aio_context.waitScope);

      auto result = PyList_New(count);

      for (size_t i = 0; i < count; ++i) {
        auto& data = datas[i];
        PyList_SetItem(result, i,
                       PyBytes_FromStringAndSize(data.begin(), data.size()));
      }

      return result;
    } else {
      const auto data = state->cas_client.Get(AsStringView(key_arg));

      return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(&data[0]),
                                       data.size());
    }
  } catch (kj::Exception e) {
    return PyErr_Format(PyExc_RuntimeError, "CAS get error: %s:%d: %s",
                        e.getFile(), e.getLine(), e.getDescription().cStr());
  }
}

PyObject* put(PyObject* data) {
  try {
    const auto key = GetState()->cas_client.Put(PyBytes_AS_STRING(data), PyBytes_GET_SIZE(data));

    return PyBytes_FromStringAndSize(key.data(), key.size());
  } catch (kj::Exception e) {
    return PyErr_Format(PyExc_RuntimeError, "CAS put error: %s:%d: %s",
                        e.getFile(), e.getLine(), e.getDescription().cStr());
  }
}
