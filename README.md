Content Addressable Storage
===========================

The purpose of the Cantera CAS service is to keep long-lived copies of large
objects, with read times below 100 ms.  This is acheived with two major
components: the storage server and the balancing server.

# Storage Server

The storage server stores objects in a user-specified location on the file
system.  There should only be one storage server per storage device, and RAID
is not recommended.  On its first startup, the storage server measures the
total capacity of the underlying file system, and generates a proportional
number of keys for participating in a consistent hash ring.

Storage servers have no information about, and do not connect to other servers.

## On-disk Storage Format

Insertions and deletions are logged to the `index` file, while the actual
object data is kept in 50 files with the prefix `data`.  Any time a new object
is inserted, it is appended to the shortest data file.  Sharding the data to 50
separate files helps ensure we can perform compaction as long as the underlying
file system has at least 2% free space.

# Balancing Server

Balancing servers read YAML formatted configuration files that list the
backends it should connect to, along with the failure domain of each backend.
The configuration file also denotes the minmum replication limit for write
request.  If the required number of failure domains is not currently available,
writes will fail.

Balancing servers are stateless to the extent that there can be multiple
balancing servers with the same set of backends, and they don't need to know
about each other.

# Garbage Collection

Garbage collection is started by the `beginGC` remote procedure call, or the
`begin-gc` command to the `ca-cas` tool.  This cancels any ongoing garbage
collections, and returns a unique ID which can be used to complete the garbage
collection cycle.  Before the command returns, all objects are marked for
removal.

Once in a garbage collection cycle, the `get`, `put`, and `mark-gc` calls
remove the garbage markers for the objects in their parameters.  When the
`end-gc` call is made, all objects that still have a garbage marker are
removed.

Note that removed objects remain on the file system until a call to `compact`
clears them away.

The `capacity` call provides information about how much space would be freed if
the current garbage collection cycle was ended.

The `list` call has an option to list only the objects that are about to be
removed.
