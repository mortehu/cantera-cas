#!/bin/bash

set -e
set -o pipefail

#LAUNCHER="valgrind -q"

repo=`mktemp -d`

trap 'rm -rf "$repo"' EXIT INT

$LAUNCHER ./ca-casd --address=127.0.0.1 --port=5923 -n "$repo" &
SERVER_PID=$!

export CA_CAS_SERVER=127.0.0.1:5923

trap 'rm -rf "$repo" && kill $SERVER_PID' EXIT INT

fatal_error() {
  echo "$@" >&2
  exit 1
}

declare -A KEYS

put() {
  KEY=`echo "$1" | $LAUNCHER ./ca-cas put`
  if [ 0 != $? ]; then
    fatal_error "Inserting $1 failed"
  fi
  KEYS["$1"]="$KEY"
}

test_200() {
  KEY="${KEYS[$1]}"
  if [ -z "$KEY" ]; then
    KEY=`echo "$1" | sha1sum | cut -d' ' -f1`
  fi
  if ! $LAUNCHER ./ca-cas get "$KEY" \
    | cmp /proc/self/fd/3 3<<EOF
$1
EOF
  then
    fatal_error "Retrieving $1 failed"
  fi
}

test_404() {
  KEY="${KEYS[$1]}"
  if [ -z "$KEY" ]; then
    KEY=`echo "$1" | sha1sum | cut -d' ' -f1`
  fi
  if $LAUNCHER ./ca-cas get "$KEY" 2>/dev/null; then
    fatal_error "Retrieving $1 succeeded unexpectedly"
  fi
}

expect_n_objects() {
  L=`$LAUNCHER ./ca-cas list | wc -l`
  L=`expr $L`
  if [ $1 != $L ]; then
    fatal_error "Expected $1 objects, but got $L"
  fi
}

if [ 0 != `$LAUNCHER ./ca-cas list | wc -l` ]; then
  fatal_error "Unexpected LIST output on empty repository"
fi

# Short objects aren't actually stored, so we need this padding to make "large" objects.
PADDING="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
PADDING="${PADDING}${PADDING}"
PADDING="${PADDING}${PADDING}"

test_404 "data000000"
put "data000000"
test_200 "data000000"

test_404 "missing"

test_200 "data000000"
test_404 "missing"

put "data000001"
put "data000001$PADDING"
put "data000002$PADDING"
expect_n_objects 2

put "data000002"
put "data000003$PADDING"
expect_n_objects 3

test_200 "data000001$PADDING"
test_200 "data000002$PADDING"
test_200 "data000003$PADDING"

test_200 "data000000"
test_200 "data000001"
test_200 "data000002"

put "data000000"
put "novel_object"

for x in `seq 3 30`
do
  put "data$x"
done

for x in `seq 3 30`
do
  test_200 "data$x"
done

for x in `seq 3 30`
do
  test_200 "data$x"
done

test_200 "data000000"
test_200 "data000001"
test_200 "data000002"

$LAUNCHER ./ca-cas-fsck "$repo"
