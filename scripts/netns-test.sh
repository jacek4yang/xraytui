#!/bin/sh
# Run the privileged tests inside a disposable namespace.
#
# The brief is explicit that privileged networking must be proven in an
# isolated Linux network namespace and that the host's real routes, DNS and
# nftables rules must never be touched. This script is how that is arranged:
#
#   * the test binary is built OUTSIDE the namespace, because building may need
#     the network and the namespace deliberately has none;
#   * it is then run INSIDE a fresh network, mount, PID and UTS namespace, with
#     a private cgroup v2 hierarchy mounted at a temporary path;
#   * the tests themselves refuse to run unless the namespace they find contains
#     nothing but loopback, so setting the variable on a real machine by mistake
#     stops rather than reconfigures it.
#
# Usage:
#   sudo ./scripts/netns-test.sh [extra cargo-test arguments]
#
# Nothing outside the namespace is modified. When the last process in the
# namespace exits, the kernel destroys it along with every interface, route,
# rule and nftables table created inside.

set -eu

if [ "${XRAYTUI_NETNS_INNER:-}" = "1" ]; then
    # --- inside the namespace ---------------------------------------------
    # nftables resolves a `socket cgroupv2` path against /sys/fs/cgroup and
    # nowhere else, so the private hierarchy has to go there. The mount is
    # confined to this mount namespace with --propagation private, so the host's
    # own /sys/fs/cgroup is untouched and disappears with the namespace.
    CGROUP_ROOT=/sys/fs/cgroup
    if mount -t cgroup2 none "$CGROUP_ROOT" 2>/dev/null; then
        XRAYTUI_TEST_CGROUP_ROOT="$CGROUP_ROOT"
        export XRAYTUI_TEST_CGROUP_ROOT
        echo "netns-test: private cgroup v2 hierarchy shadowing $CGROUP_ROOT"
    else
        echo "netns-test: no cgroup v2 available; cgroup tests will be skipped" >&2
    fi

    # Loopback starts down in a new namespace and several tests need it.
    ip link set lo up

    echo "netns-test: interfaces visible inside the namespace:"
    ip -brief link show

    XRAYTUI_NETNS_TESTS=1
    export XRAYTUI_NETNS_TESTS
    # One namespace, one set of routing tables: the tests must not interleave.
    status=0
    for binary in $XRAYTUI_TEST_BINARIES; do
        echo "netns-test: running $binary"
        "$binary" --test-threads=1 --nocapture "$@" || status=$?
    done
    exit "$status"
fi

# --- outside the namespace -------------------------------------------------
if [ "$(id -u)" != "0" ]; then
    echo "netns-test: must be run as root (it creates namespaces)" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

# Two suites, deliberately. `netns` proves the kernel-side arrangement;
# `netns_transparent` proves acceptance scenario M through the real helper, the
# real command-line client and the real core on top of it. The client and the
# helper are ordinary binaries, so they are built here too — the namespace has no
# network to fetch or compile with.
echo "netns-test: building the privileged test binaries"
cargo test -p xraytui-linux-net --test netns --no-run
cargo test -p xraytui-controller --test netns_transparent --no-run
cargo build --bin xraytui --bin xraytui-netd

newest() {
    find target/debug/deps -maxdepth 1 -name "$1" ! -name '*.d' -type f \
        -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-
}

XRAYTUI_TEST_BINARIES=""
for pattern in 'netns-*' 'netns_transparent-*'; do
    found=$(newest "$pattern")
    if [ -z "$found" ]; then
        echo "netns-test: could not find a compiled test binary for $pattern" >&2
        exit 1
    fi
    XRAYTUI_TEST_BINARIES="$XRAYTUI_TEST_BINARIES $(pwd)/$found"
done
export XRAYTUI_TEST_BINARIES
XRAYTUI_TEST_BIN_DIR="$(pwd)/target/debug"
export XRAYTUI_TEST_BIN_DIR
XRAYTUI_NETNS_INNER=1
export XRAYTUI_NETNS_INNER

# --mount-proc matters: without it /proc still belongs to the host's PID
# namespace, so a pidfd's `Pid:` field and a child's own pid disagree and
# cgroup classification writes a pid that does not exist here.
exec unshare --net --mount --pid --fork --mount-proc --propagation private -- "$0" "$@"
