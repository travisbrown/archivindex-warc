#!/usr/bin/env bash
#
# Run every example in dependency order: each writer creates the archive that
# the readers following it consume. The archives are left in examples/tmp so
# that they can be inspected afterwards.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# The writers append to an existing archive, so remove the ones an earlier run
# left behind to keep repeated runs of this script identical.
rm -f "$script_dir/tmp/warc_example.warc" "$script_dir/tmp/warc_example.warc.gz"

run() {
    echo
    echo "=== $1 ==="
    cargo run --quiet --manifest-path "$script_dir/../Cargo.toml" --example "$@"
}

run hello_warc
run write_file
run read_file
run write_raw
run read_raw
run write_gzip
run read_gzip
run read_filtered -- warc_example.warc.gz index.html
