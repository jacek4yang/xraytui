#!/bin/sh
# Build the deterministic source archive attached to GitHub releases.
#
# The Arch PKGBUILD points at this asset. PKGBUILD itself is intentionally
# omitted from the archive: its checksum names the archive, so including it
# would create a checksum cycle. The install hook remains beside PKGBUILD in
# the Git repository and is not needed while compiling the source tree.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if ! git diff-index --quiet HEAD --; then
    echo "source-dist: the worktree must be clean" >&2
    exit 1
fi

VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
if [ -z "$VERSION" ]; then
    echo "source-dist: cannot read workspace version" >&2
    exit 1
fi

NAME="xraytui-$VERSION"
case ${1:-target/dist} in
    /*) OUT=${1:-target/dist} ;;
    *) OUT="$ROOT/${1:-target/dist}" ;;
esac

mkdir -p "$OUT"
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT INT TERM
mkdir -p "$TEMP/$NAME"

git archive --format=tar HEAD > "$TEMP/source.tar"
tar -xf "$TEMP/source.tar" -C "$TEMP/$NAME"
rm -f "$TEMP/$NAME/packaging/arch/PKGBUILD"
rm -f "$TEMP/$NAME/packaging/arch/.SRCINFO"

ARCHIVE="$OUT/$NAME.tar.gz"
tar \
    --sort=name \
    --owner=root:0 \
    --group=root:0 \
    --numeric-owner \
    --mtime='UTC 2020-01-01' \
    -C "$TEMP" \
    -cf - "$NAME" | gzip -n -9 > "$ARCHIVE"

SUM=$(sha256sum "$ARCHIVE" | awk '{print $1}')
printf '%s  %s\n' "$SUM" "$NAME.tar.gz" | tee "$ARCHIVE.sha256"
