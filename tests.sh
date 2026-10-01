#!/bin/bash
# Runs sshauth against the fake server in server.py, then against sshauthd.
#
# Usage: ./tests.sh   (or: make check)
#
# The client is rebuilt with SOCK_PATH pointing at a relative socket in a
# temporary directory: a unix socket path is limited to 108 bytes, so an
# absolute path under a deep directory might not fit.
set -u

SRC=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP" || exit 1

${CC:-cc} -O2 -Wall -Wextra -Werror -DSOCK_PATH='"t.sock"' -o client "$SRC/sshauth.c" || exit 1

pass=0
fail=0

ok() { pass=$((pass + 1)); echo "ok   $1"; }
not_ok() {
    fail=$((fail + 1))
    echo "FAIL $1: $2"
    sed 's/^/     stdout: /' out
    sed 's/^/     stderr: /' err
}

# run MODE STDIN ARGS...: starts the server, runs the client and leaves
# its stdout in ./out, stderr in ./err and exit code in $rc.
run() {
    local mode=$1 input=$2
    shift 2
    rm -f t.sock t.sock.args
    timeout 10 python3 "$SRC/server.py" t.sock "$mode" &
    local srv=$!
    for _ in $(seq 100); do
        [ -S t.sock ] && break
        sleep 0.05
    done
    printf '%s' "$input" | timeout 10 ./client "$@" >out 2>err
    rc=$?
    wait "$srv"
}

# check NAME EXPECTED_RC EXPECTED_STDOUT STDERR_PATTERN
# An empty STDERR_PATTERN means stderr must be empty.
check() {
    local name=$1 want_rc=$2 want_out=$3 err_pat=$4
    if [ "$rc" != "$want_rc" ]; then
        not_ok "$name" "exit code $rc, expected $want_rc"
    elif [ "$(cat out)" != "$want_out" ]; then
        not_ok "$name" "unexpected stdout"
    elif [ -z "$err_pat" ] && [ -s err ]; then
        not_ok "$name" "stderr is not empty"
    elif [ -n "$err_pat" ] && ! grep -q -- "$err_pat" err; then
        not_ok "$name" "stderr does not match '$err_pat'"
    else
        ok "$name"
    fi
}

run ok $'hello\nworld\n' tr a-z A-Z
check "stdin and stdout are forwarded" 0 $'HELLO\nWORLD' "running: tr a-z A-Z"

run ok "" sh -c 'exit 7'
check "exit code is returned" 7 "" "running:"

run ok "" sh -c 'echo "[$0]"' 'a b'
check "argument with a space stays one argument" 0 "[a b]" "running:"
if [ "$(od -An -c t.sock.args | tr -s ' ')" = "$(printf 'sh\0-c\0echo "[$0]"\0a b' | od -An -c | tr -s ' ')" ]; then
    ok "arguments are separated by NUL"
else
    not_ok "arguments are separated by NUL" "server got: $(od -An -c t.sock.args)"
fi

run ok "" head -c 100000 /dev/zero
if [ "$rc" = 0 ] && [ "$(wc -c <out)" = 100000 ]; then
    ok "large output is not lost on EXIT"
else
    not_ok "large output is not lost on EXIT" "rc=$rc, $(wc -c <out) bytes"
fi

run ok "" cat
check "EOF on stdin reaches the command" 0 "" "running: cat"

run split "" sh -c 'echo hi; exit 3'
check "errfd messages split across reads" 3 "hi" "running: sh -c"

run exit=-1 "" true
check "negative exit code" 255 "" ""

run err "" ls -l
check "ERR! reply" 1 "" "^denied: ls -l$"

run nofd "" true
check "OKAY without a file descriptor" 255 "" "OKAY without a file descriptor"

run badreply "" true
check "unknown reply" 255 "" "unknown reply"

run noexit "" true
check "connection closed without EXIT" 255 "" "closed without EXIT"

run badmsg "" true
check "unknown message on errfd" 255 "" "unknown message on errfd"

# Rejected before connecting, so no server is started.
timeout 10 ./client "$(head -c 5000 /dev/zero | tr '\0' x)" >out 2>err
rc=$?
check "command line over 4096 bytes" 255 "" "longer than 4096 bytes"

rm -f t.sock
timeout 10 ./client true >out 2>err
rc=$?
check "no server listening" 255 "" "connect t.sock"

# The real server, built from cmd/sshauthd. It serves every connection,
# so it is started once for all the tests below.
rm -f t.sock
(cd "$SRC" && go build -buildvcs=false -o "$TMP/sshauthd" ./cmd/sshauthd) || exit 1
./sshauthd -socket t.sock 2>sshauthd.log &
srv=$!
for _ in $(seq 100); do
    [ -S t.sock ] && break
    sleep 0.05
done

# srun STDIN ARGS...: like run, against sshauthd.
srun() {
    local input=$1
    shift
    printf '%s' "$input" | timeout 10 ./client "$@" >out 2>err
    rc=$?
}

srun $'hello\nworld\n' tr a-z A-Z
check "sshauthd: stdin and stdout are forwarded" 0 $'HELLO\nWORLD' ""

srun "" sh -c 'echo out; echo err >&2; exit 7'
check "sshauthd: stderr and exit code" 7 "out" "^err$"

srun "abc" cat
check "sshauthd: EOF on stdin reaches the command" 0 "abc" ""

srun "" sh -c 'echo "[$0]"' 'a b'
check "sshauthd: argument with a space stays one argument" 0 "[a b]" ""

srun "" head -c 1000000 /dev/zero
if [ "$rc" = 0 ] && [ "$(wc -c <out)" = 1000000 ]; then
    ok "sshauthd: large output is not lost on EXIT"
else
    not_ok "sshauthd: large output is not lost on EXIT" "rc=$rc, $(wc -c <out) bytes"
fi

srun "" sh -c 'head -c 5000 /dev/zero | tr "\0" e >&2'
if [ "$rc" = 0 ] && [ "$(wc -c <err)" = 5000 ]; then
    ok "sshauthd: stderr longer than one TEXT message"
else
    not_ok "sshauthd: stderr longer than one TEXT message" "rc=$rc, $(wc -c <err) bytes"
fi

srun "" sh -c 'kill -9 $$'
check "sshauthd: killed by a signal" 137 "" ""

srun "" nosuchcommand
check "sshauthd: unknown command gives ERR!" 1 "" "nosuchcommand"

srun ""
check "sshauthd: empty command gives ERR!" 1 "" "^empty command$"

# The client must not wait for its stdin to close once EXIT arrives.
start=$SECONDS
timeout 10 ./client true < <(sleep 5) >out 2>err
rc=$?
if [ "$rc" = 0 ] && [ $((SECONDS - start)) -lt 5 ]; then
    ok "sshauthd: EXIT without EOF on stdin"
else
    not_ok "sshauthd: EXIT without EOF on stdin" "rc=$rc after $((SECONDS - start))s"
fi

kill "$srv"
wait "$srv" 2>/dev/null

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
