@0xa5e7389cf66d5ba0;

$import "/capnp/c++.capnp".namespace("cantera");

# Represents a destination for a stream of bytes. The bytes are ordered, but
# boundaries between messages are not semantically important.
#
# Compatible with `sandstorm::ByteStream` from the Sandstorm project.
interface ByteStream @0xcd57387729cfe35f {
  # Adds bytes.
  write @0 (data :Data);

  # Call after the last write to indicate that there is no more data.
  done @1 ();

  # Optionally called to let the receiver know exactly how much data will be written.
  expectSize @2 (size :UInt64);
}
