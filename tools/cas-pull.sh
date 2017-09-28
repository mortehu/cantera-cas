#!/bin/sh

# Copies objects from a remote CAS store, skipping objects we already have.

if [ $# != 1 ]; then
  echo >&2 "Usage: $0 HOST"
  exit 1
fi

host="$1"
shift

ca-cas --keys-only export | ssh "$host" 'ca-cas --exclude=- export' | ca-cas import
