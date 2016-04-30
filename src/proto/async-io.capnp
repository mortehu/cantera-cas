@0xb21883168d6ebc08;

$import "/capnp/c++.capnp".namespace("cantera");

# Provides an asynchronous I/O interface for use when the client is in the same
# address space as the server.  Pointers are passed as unsigned 64-bit
# integers.
interface AsyncIO {
  pread @0 (fd :Int32, buffer :UInt64, start :UInt64, length :UInt64);

  pwrite @1 (fd :Int32, buffer :UInt64, start :UInt64, length :UInt64);

  fsync @2 (fd :Int32);
}
