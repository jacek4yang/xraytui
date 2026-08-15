# Delivery

## Where things go

The absolute delivery directory is recorded in `DELIVERY-LOCATION.txt` and is
read by `cargo xtask checkpoint`. Everything the user is meant to keep is
written there and then **sent to them as a downloadable file**.

## Why a checkpoint is the unit of progress

This environment has destroyed committed work three times: twice losing
finished, committed slices, and once losing a tagged release. A local commit is
not a backup here, and neither is a file in the workspace.

The durable unit is therefore an archive the user has downloaded, containing
complete Git history *and* a clean source snapshot. Either alone is
insufficient: a bundle that will not clone is worthless without the snapshot,
and a snapshot without history loses every decision record.

## Producing one

```sh
cargo xtask checkpoint --label durable-state \
  --completed "slice 1" --next "slice 2" \
  --resume-command "cargo test -p xraytui-state-store" \
  --tests target/test-summary.txt
```

It refuses to run on a dirty tree, because the source archive comes from `HEAD`
and uncommitted work would vanish silently. It verifies its own bundle by
cloning it into a temporary directory and comparing `HEAD`. It numbers itself
from what is already in the delivery directory, so numbering survives a reset
without being remembered.

## The final archive

One file, `xraytui-v1.0.0-delivery.tar.gz` (or `-rcN-`), containing source,
history, packaging, test results, checksums, `VERIFY.sh` and
`RESTORE-SOURCE.sh`. The user should need to download only that one file.

## What must never be in an archive

Real credentials, real subscription URLs, real UUIDs or passwords, private
keys, developer runtime state, private logs, Cargo registry caches, or
`target/`.
