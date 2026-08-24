#!/bin/sh
# Run the full TUN + systemd-resolved + proxied-DNS acceptance test inside a
# network-less, disposable container. The host's routes, resolver, nftables and
# cgroups are never used.

set -eu

cd "$(dirname "$0")/.."

if [ -z "${XRAYTUI_TEST_XRAY:-}" ] || [ ! -x "$XRAYTUI_TEST_XRAY" ]; then
    echo "combined-netns-test: set XRAYTUI_TEST_XRAY to an official executable Xray binary" >&2
    exit 2
fi

echo "combined-netns-test: building product and acceptance binaries"
cargo test -p xraytui-controller --test netns_resolved_tun --no-run
cargo build --bin xraytui --bin xraytuid --bin xraytui-netd

test_binary=$(
    find target/debug/deps -maxdepth 1 -name 'netns_resolved_tun-*' ! -name '*.d' -type f \
        -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-
)
if [ -z "$test_binary" ]; then
    echo "combined-netns-test: compiled test binary was not found" >&2
    exit 1
fi

case "$test_binary" in
    /*) ;;
    *) test_binary="$(pwd)/$test_binary" ;;
esac
case "$XRAYTUI_TEST_XRAY" in
    /*) xray_binary="$XRAYTUI_TEST_XRAY" ;;
    *) xray_binary="$(cd "$(dirname "$XRAYTUI_TEST_XRAY")" && pwd)/$(basename "$XRAYTUI_TEST_XRAY")" ;;
esac
xray_dir=$(dirname "$xray_binary")
workspace=$(pwd)

container_runtime=${XRAYTUI_CONTAINER_RUNTIME:-}
if [ -z "$container_runtime" ]; then
    if command -v podman >/dev/null 2>&1; then
        container_runtime=podman
    elif command -v docker >/dev/null 2>&1; then
        container_runtime=docker
    else
        echo "combined-netns-test: podman or docker is required" >&2
        exit 2
    fi
fi

# Pinned because systemd-resolved is part of the behavior under test. Override
# only to deliberately qualify a newer systemd build.
image=${XRAYTUI_RESOLVED_IMAGE:-docker.io/library/archlinux@sha256:714acd1eef9ae997d95691b1c5220ada0076185b77857c1813f02de0fa83cf7b}

echo "combined-netns-test: isolated runtime=$container_runtime image=$image"
# The quoted program is expanded by the container's inner shell, not here.
# shellcheck disable=SC2016
exec "$container_runtime" run --rm --privileged --network none \
    --volume "$workspace:$workspace:ro" \
    --volume "$xray_dir:$xray_dir:ro" \
    --workdir "$workspace" \
    --env "XRAYTUI_TEST_XRAY=$xray_binary" \
    --env "XRAY_LOCATION_ASSET=$xray_dir" \
    --env "XRAYTUI_TEST_BIN_DIR=$workspace/target/debug" \
    --env "XRAYTUI_COMBINED_DNS_TESTS=1" \
    --env "XRAYTUI_COMBINED_TEST_BINARY=$test_binary" \
    "$image" sh -eu -c '
        ip link set lo up
        mkdir -p /run/dbus /run/systemd
        rm -rf /run/systemd/resolve
        dbus-daemon --system --fork --nopidfile
        SYSTEMD_LOG_LEVEL=info /usr/lib/systemd/systemd-resolved \
            >/tmp/xraytui-resolved.log 2>&1 &
        resolved_pid=$!
        trap '\''kill "$resolved_pid" 2>/dev/null || true; wait "$resolved_pid" 2>/dev/null || true'\'' EXIT INT TERM
        ready=0
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if busctl --system introspect org.freedesktop.resolve1 /org/freedesktop/resolve1 \
                >/dev/null 2>&1; then
                ready=1
                break
            fi
            sleep 1
        done
        if [ "$ready" != 1 ]; then
            echo "combined-netns-test: private systemd-resolved did not acquire D-Bus" >&2
            cat /tmp/xraytui-resolved.log >&2
            exit 1
        fi
        resolved_version=$(/usr/lib/systemd/systemd-resolved --version | head -1)
        echo "combined-netns-test: $resolved_version"
        "$XRAYTUI_COMBINED_TEST_BINARY" \
            --exact combined_tun_resolved_and_proxied_dns_is_dual_stack_and_fail_closed \
            --test-threads=1 --nocapture
    '
