#!/bin/sh
# The release smoke test: the whole user workflow, real binaries.
#
# This is the test that answers "can somebody actually use this?". It runs the
# binaries a user would run, in a temporary HOME, against local fixtures — no
# public proxy, no public resolver, no internet — and it touches nothing outside
# its own temporary directories.
#
#   ./scripts/release-smoke.sh
#
# What it does not do: host networking. TUN, nftables, policy routing and
# acceptance scenario M are proven by ./scripts/netns-test.sh, which runs inside
# a disposable namespace; running them here would mean changing the machine.
#
# Exit status is the number of failed steps, so it is usable from a release gate.

# No `set -e`: this script counts failures and reports them all, so one failing
# step must not end the run. `set -u` stays, because an unset variable here is a
# bug in the test rather than a finding about the product.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release"
[ -x "$BIN/xraytui" ] || BIN="$ROOT/target/debug"
WORK=$(mktemp -d)
FAILURES=0
DAEMON=""
FIXTURES=""

cleanup() {
    [ -n "$DAEMON" ] && kill "$DAEMON" 2>/dev/null
    [ -n "$FIXTURES" ] && kill "$FIXTURES" 2>/dev/null
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM

step() { printf '\n=== %s\n' "$1"; }
ok()   { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
check() { if [ "$1" = "0" ]; then ok "$2"; else fail "$2"; fi }

XRAYTUI="$BIN/xraytui --root $WORK/home"

for binary in xraytui xraytuid xraytui-netd; do
    if [ ! -x "$BIN/$binary" ]; then
        echo "release-smoke: $BIN/$binary is missing; build the workspace first" >&2
        exit 1
    fi
done
echo "release-smoke: using $BIN"

# --- 1. a first run in an empty home ---------------------------------------
step "first run"
mkdir -p "$WORK/home"
$XRAYTUI init > "$WORK/init.log" 2>&1
check $? "xraytui init"
[ -f "$WORK/home/config/config.toml" ]; check $? "config.toml exists"
[ -f "$WORK/home/config/profiles.toml" ]; check $? "profiles.toml exists"
[ -f "$WORK/home/state/state.sqlite3" ]; check $? "state database exists"
mode=$(stat -c '%a' "$WORK/home/config/config.toml")
[ "$mode" = "600" ]; check $? "config.toml is mode 0600 (was $mode)"
mode=$(stat -c '%a' "$WORK/home/state/state.sqlite3")
[ "$mode" = "600" ]; check $? "state database is mode 0600 (was $mode)"
$XRAYTUI init > /dev/null 2>&1
check $? "init is idempotent"

# A policy file that does not parse must not be treated as a fresh install.
cp "$WORK/home/config/nodes.toml" "$WORK/nodes.bak"
printf 'this is not toml {{{\n' > "$WORK/home/config/nodes.toml"
if $XRAYTUI init > /dev/null 2>&1; then
    fail "init overwrote a policy file it could not parse"
else
    ok "init refuses to overwrite unparseable policy"
fi
cp "$WORK/nodes.bak" "$WORK/home/config/nodes.toml"

# --- 2. two mock egresses and a fixture subscription -----------------------
step "fixtures"
python3 "$ROOT/scripts/smoke-fixtures.py" "$WORK" > "$WORK/fixtures.log" 2>&1 &
FIXTURES=$!
for _ in $(seq 1 100); do
    [ -f "$WORK/fixtures.env" ] && break
    sleep 0.1
done
if [ ! -f "$WORK/fixtures.env" ]; then
    fail "fixtures did not start"
    exit 1
fi
. "$WORK/fixtures.env"
ok "mock egresses on $EGRESS_A_PORT and $EGRESS_B_PORT, subscription on $HTTP_PORT"

# --- 3. the daemon ----------------------------------------------------------
step "daemon"
"$BIN/xraytuid" --root "$WORK/home" > "$WORK/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 150); do
    [ -S "$WORK/home/run/control.sock" ] && break
    sleep 0.1
done
[ -S "$WORK/home/run/control.sock" ]; check $? "control socket appeared"
$XRAYTUI status > /dev/null 2>&1
check $? "xraytui status"
$XRAYTUI doctor > "$WORK/doctor.log" 2>&1
grep -q "xray-binary" "$WORK/doctor.log"; check $? "doctor reports on the core"

# --- 4. nodes, typed in and imported ----------------------------------------
step "configuration"
printf 'socks://127.0.0.1:%s#exit-alpha\nsocks://127.0.0.1:%s#exit-bravo\n' \
    "$EGRESS_A_PORT" "$EGRESS_B_PORT" | $XRAYTUI node import --stdin > /dev/null 2>&1
check $? "import two share links"
ALPHA_ID=$($XRAYTUI node list | awk '$2 == "exit-alpha" { print $1; exit }')
BRAVO_ID=$($XRAYTUI node list | awk '$2 == "exit-bravo" { print $1; exit }')
[ -n "$ALPHA_ID" ] && [ -n "$BRAVO_ID" ]; check $? "both imported nodes have identifiers"

$XRAYTUI node add --protocol socks --name typed-in \
    --address 127.0.0.1 --port "$EGRESS_A_PORT" > "$WORK/nodeadd.log" 2>&1
check $? "node add"
TYPED_ID=$($XRAYTUI node list | awk '$2 == "typed-in" { print $1; exit }')
$XRAYTUI node edit "$TYPED_ID" --name renamed > /dev/null 2>&1
check $? "node edit"
$XRAYTUI node list | grep -q renamed; check $? "the edit took effect"

# A field belonging to another protocol must be refused, not ignored.
if $XRAYTUI node edit "$TYPED_ID" --uuid 11111111-2222-3333-4444-555555555555 \
        > /dev/null 2>&1; then
    fail "a VLESS field was accepted on a SOCKS node"
else
    ok "a field from another protocol is refused"
fi

# --- 5. subscriptions -------------------------------------------------------
step "subscriptions"
$XRAYTUI subscription add "http://127.0.0.1:$HTTP_PORT/sub" --name smoke --allow-plaintext \
    > "$WORK/subadd.log" 2>&1
check $? "add a subscription"
$XRAYTUI subscription update smoke --yes > "$WORK/subupdate.log" 2>&1
check $? "update the subscription"
if $XRAYTUI node list | grep -q "sub-node"; then
    ok "the subscription's nodes arrived"
else
    fail "the subscription's nodes arrived"
    sed 's/^/    /' "$WORK/subupdate.log"
fi

# --- 6. groups, chains, profiles, rules -------------------------------------
step "the rest of the configuration surface"
$XRAYTUI group add fast --name Fast --node "$ALPHA_ID" --node "$BRAVO_ID" > /dev/null 2>&1
check $? "group add"
$XRAYTUI target list | grep -q "group:fast"; check $? "the group is selectable"
$XRAYTUI chain add relay --name Relay --hop "$ALPHA_ID" --hop "$BRAVO_ID" > /dev/null 2>&1
check $? "chain add"
$XRAYTUI target list | grep -q "chain:relay"; check $? "the chain is selectable"

$XRAYTUI profile add alpha --target "node:$ALPHA_ID" --socks 11190 > "$WORK/pa.log" 2>&1
check $? "create profile alpha"
$XRAYTUI profile add bravo --target "node:$BRAVO_ID" --socks 11191 > "$WORK/pb.log" 2>&1
check $? "create profile bravo"
$XRAYTUI profile listeners alpha --http 11192 > /dev/null 2>&1
check $? "profile listeners"
$XRAYTUI app assign alpha firefox > /dev/null 2>&1
check $? "assign an application"
$XRAYTUI app list | grep -q firefox; check $? "the rule is listed"
RULE_ID=$($XRAYTUI app list | awk '/firefox/ { print $2; exit }')
$XRAYTUI rule disable "$RULE_ID" > /dev/null 2>&1
check $? "rule disable"
$XRAYTUI rule enable "$RULE_ID" > /dev/null 2>&1
check $? "rule enable"

# A change that cannot work must fail loudly and change nothing.
if $XRAYTUI profile set-target alpha "node:does-not-exist" > /dev/null 2>&1; then
    fail "a target that does not exist was accepted"
else
    ok "an impossible target is refused"
fi

# --- 7. two profiles, two exits, at the same time ---------------------------
step "two profiles, two exits, at the same time"
$XRAYTUI up > /dev/null 2>&1
sleep 2
answer_a=$(python3 "$ROOT/scripts/smoke-fixtures.py" --probe 11190 2>/dev/null || echo "")
answer_b=$(python3 "$ROOT/scripts/smoke-fixtures.py" --probe 11191 2>/dev/null || echo "")
case "$answer_a" in *"EGRESS alpha"*) ok "profile alpha reached its own exit" ;;
    *) fail "profile alpha got '$answer_a'" ;; esac
case "$answer_b" in *"EGRESS bravo"*) ok "profile bravo reached its own exit" ;;
    *) fail "profile bravo got '$answer_b'" ;; esac

# --- 8. hot switch ----------------------------------------------------------
step "switching a target without restarting the core"
pid_before=$($XRAYTUI status --format json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["runtime"]["core"].get("pid",""))' \
    2>/dev/null || echo "")
$XRAYTUI profile set-target alpha "node:$BRAVO_ID" > "$WORK/switch.log" 2>&1
check $? "set-target"
sleep 1
answer=$(python3 "$ROOT/scripts/smoke-fixtures.py" --probe 11190 2>/dev/null || echo "")
case "$answer" in *"EGRESS bravo"*) ok "new connections take the new exit" ;;
    *) fail "after the switch, alpha got '$answer'" ;; esac
pid_after=$($XRAYTUI status --format json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["runtime"]["core"].get("pid",""))' \
    2>/dev/null || echo "")
[ -n "$pid_before" ] && [ "$pid_before" = "$pid_after" ]
check $? "the core was not restarted (pid $pid_before)"

# --- 9. sharing -------------------------------------------------------------
step "sharing"
$XRAYTUI node share "$ALPHA_ID" > "$WORK/link.txt" 2>/dev/null
check $? "export a share link"
grep -q "socks://" "$WORK/link.txt"; check $? "the link is a share link"
$XRAYTUI node share "$ALPHA_ID" --png "$WORK/qr.png" > /dev/null 2>&1
check $? "export a QR code"
[ -s "$WORK/qr.png" ]; check $? "the QR file has content"
$XRAYTUI node share "$ALPHA_ID" --qr > "$WORK/qr.txt" 2>/dev/null
check $? "render a QR code in the terminal"
[ -s "$WORK/qr.txt" ]; check $? "the terminal QR has content"

# --- 10. a supervised core comes back --------------------------------------
step "core supervision"
core_pid=$($XRAYTUI status --format json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["runtime"]["core"].get("pid",""))' \
    2>/dev/null || echo "")
if [ -n "$core_pid" ]; then
    kill -9 "$core_pid" 2>/dev/null
    recovered=""
    for _ in $(seq 1 60); do
        sleep 0.5
        new_pid=$($XRAYTUI status --format json \
            | python3 -c 'import json,sys; d=json.load(sys.stdin)["runtime"]["core"]; print(d.get("pid","") if d.get("state")=="running" else "")' \
            2>/dev/null || echo "")
        if [ -n "$new_pid" ] && [ "$new_pid" != "$core_pid" ]; then
            recovered="$new_pid"
            break
        fi
    done
    if [ -n "$recovered" ]; then
        ok "a killed core was noticed and restarted (was $core_pid, now $recovered)"
    else
        fail "a killed core was never restarted"
    fi
else
    fail "could not read the core's pid"
fi

# --- 11. restart, and what survives ------------------------------------------
step "restart"
before=$($XRAYTUI profile list --format json \
    | python3 -c 'import json,sys; print(sorted((p["id"], str(p["target"])) for p in json.load(sys.stdin)))' \
    2>/dev/null || echo "")
kill "$DAEMON" 2>/dev/null
sleep 1
"$BIN/xraytuid" --root "$WORK/home" >> "$WORK/daemon.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 150); do
    [ -S "$WORK/home/run/control.sock" ] && break
    sleep 0.1
done
after=$($XRAYTUI profile list --format json \
    | python3 -c 'import json,sys; print(sorted((p["id"], str(p["target"])) for p in json.load(sys.stdin)))' \
    2>/dev/null || echo "")
[ -n "$before" ] && [ "$before" = "$after" ]
check $? "profiles and their targets survived the restart"
$XRAYTUI status > /dev/null 2>&1
check $? "the daemon is usable again"

# --- 12. removal leaves nothing behind ---------------------------------------
step "removal"
$XRAYTUI app unassign "$RULE_ID" > /dev/null 2>&1
check $? "unassign the application"
$XRAYTUI profile remove bravo > /dev/null 2>&1
check $? "remove a profile"
if $XRAYTUI profile list 2>/dev/null | awk '{print $1}' | grep -qx bravo; then
    fail "the profile is still listed"
else
    ok "the profile is gone"
fi
$XRAYTUI chain remove relay > /dev/null 2>&1
check $? "remove the chain"
$XRAYTUI subscription remove smoke > /dev/null 2>&1
check $? "remove the subscription"
$XRAYTUI down > /dev/null 2>&1
check $? "stop the core"

# --- 13. install into a staging root ----------------------------------------
step "installation"
DESTDIR="$WORK/destdir"
if [ -x "$ROOT/target/release/xraytui" ]; then
    (cd "$ROOT" && cargo run --quiet -p xtask -- install --prefix /usr --destdir "$DESTDIR") \
        > "$WORK/install.log" 2>&1
    check $? "cargo xtask install --destdir"
    for file in usr/bin/xraytui usr/bin/xraytuid usr/bin/xraytui-netd \
                usr/lib/systemd/user/xraytuid.service \
                usr/lib/systemd/system/xraytui-netd.service; do
        [ -f "$DESTDIR/$file" ]; check $? "installed $file"
    done
    setuid=$(find "$DESTDIR" -perm /6000 -type f | wc -l)
    [ "$setuid" = "0" ]; check $? "no setuid or setgid files ($setuid found)"
    mode=$(stat -c '%a' "$DESTDIR/usr/bin/xraytui-netd")
    [ "$mode" = "755" ]; check $? "the helper is 0755 (was $mode)"
    (cd "$ROOT" && cargo run --quiet -p xtask -- uninstall --prefix /usr --destdir "$DESTDIR") \
        > "$WORK/uninstall.log" 2>&1
    check $? "cargo xtask uninstall --destdir"
    [ ! -f "$DESTDIR/usr/bin/xraytui" ]; check $? "uninstall removed the binaries"
    [ -f "$WORK/home/config/config.toml" ]; check $? "uninstall kept the user's configuration"
else
    printf '  skip  installation (no release build)\n'
fi

kill "$FIXTURES" 2>/dev/null

printf '\n'
if [ "$FAILURES" = "0" ]; then
    echo "release-smoke: everything passed"
else
    echo "release-smoke: $FAILURES step(s) failed"
fi
exit "$FAILURES"
