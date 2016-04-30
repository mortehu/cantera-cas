@0xfce6d689f6ca5c88;

$import "/capnp/c++.capnp".namespace("cantera");

using Util = import "util.capnp";

# Implements a content hash addressable storage system.
interface CAS {
  struct Config {
    generation @0 :UInt64 = 0;

    buckets @1 :List(Data);
  }

  interface ObjectList {
    read @0 (count :UInt64 = 50) -> (objects :List(Data));
  }

  enum ListMode {
    # List all non-removed objects
    default @0;

    # List objects scheduled for removal by garbage collector.
    garbage @1;
  }

  # Starts a garbage collection cycle and returns a unique idenfitifer that
  # must be passed to `endGC` in order to finished the cycle.
  beginGC @0 () -> (id :UInt64);

  # Marks objects that should be kept.  When `endGC` is called, all objects not
  # marked with this function will be removed.
  markGC @1 (keys :List(Data));

  # Ends a garbage collection cycle.
  endGC @2 (id :UInt64);

  # Retrieves a byte range of the object denoted by `key`.
  #
  # This function does not return a data object, but accepts an interface for
  # uploading the object, allowing efficient proxying.
  get @3 (key :Data,
          stream :Util.ByteStream,
          offset :UInt64 = 0,
          size :UInt64 = 0xffffffffffffffff);

  # Stores an object with the hash given in `key`.  The hash must be calculated
  # up front, to be able to pick the correct storage backend in a distributed
  # configuration.
  #
  # This function does not take a data argument, but instead returns an
  # interface that can be used to upload the object, allowing efficient
  # proxying.  For example, the interface can be passed to the `get` function
  # of another storage server.
  put @4 (key :Data, sync :Bool = true) -> (stream :Util.ByteStream);

  # Removes any object matching the hash given in `key`.
  remove @5 (key :Data);

  # Returns capacity numbers for the underlying storage.  `unreclaimed`
  # represents the number of bytes that could be saved by calling `compact`.
  # `garbage` represents the number of bytes that could be moved to
  # `unreclaimed` by calling `endGC`.
  capacity @6 () -> (total :UInt64, available :UInt64, unreclaimed :UInt64, garbage :UInt64);

  # Returns a handle for listing objects.  Only objects whose size is greater
  # than or equal to `minSize`, and less than `maxSize`, are returned.
  list @7 (mode :ListMode = default,
           minSize :UInt64 = 0,
           maxSize :UInt64 = 0xffffffffffffffff) -> (list :ObjectList);

  getConfig @8 () -> (config :Config);

  setConfig @9 (config :Config);

  # Frees up storage used by deleted objects.  This can be extremely expensive
  # on rotational storage, and should only be called as needed.
  compact @10 (sync :Bool = true);
}
