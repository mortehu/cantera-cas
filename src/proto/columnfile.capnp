@0xd38155c7349bfe1a;

$import "/capnp/c++.capnp".namespace("cantera");

struct CASColumnFileIndex {
  struct Chunk {
    column @0 :UInt32;

    casKey @1 :Text;
  }

  struct Segment {
    compression @0 :UInt32;

    chunks @1 :List(Chunk);

    # Number of messages (or rows) stored in the segment.
    size @2 :UInt32 = 0;
  }

  subIndexes @0 :List(CASColumnFileIndex);

  segments @1 :List(Segment);
}
