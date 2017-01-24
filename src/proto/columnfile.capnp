@0xd38155c7349bfe1a;

$import "/capnp/c++.capnp".namespace("cantera");

# Index structure for column files stored in CAS.
struct CASColumnFileIndex {
  # Represents a range of rows for a given column.
  struct Chunk {
    # Identifies the column the underlying data represents.
    column @0 :UInt32;

    # CAS key of the underlying data.
    casKey @1 :Text;
  }

  # Represents a range of rows.
  struct Segment {
    # Identifies the compression scheme used by the chunks in this range of rows.
    #
    # 0: No compression
    # 1: Snappy (very fast).  https://google.github.io/snappy/
    # 2: LZ4 (extremely fast).  https://github.com/Cyan4973/lz4
    # 3: LZMA (extremely slow).
    # 4: Deflate (normal).
    compression @0 :UInt32;

    # List of columns in this range.  This is a sparse list; columns that do
    # not have any data in this row range don't get a chunk.
    chunks @1 :List(Chunk);

    # Number of messages (or rows) stored in the segment.
    size @2 :UInt32 = 0;
  }

  # Lists indexes to be inserted before the row ranges found in `segments`.
  # 
  # This field exists to be able to create a table by appending to an existing
  # table.
  subIndexes @0 :List(CASColumnFileIndex);

  # List of row ranges in this table.
  segments @1 :List(Segment);
}
