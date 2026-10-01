#!/usr/bin/env python3
"""Fake sshauth server for tests: accepts one connection and exits.

Usage: server.py SOCKET MODE

The arguments received are written, NUL separated, to SOCKET.args.

Modes:
  ok        run the command, forwarding stdin/stdout, then send EXIT
  err       reply ERR! with "denied: <args>"
  nofd      reply OKAY without passing a file descriptor
  badreply  reply with an unknown tag
  noexit    reply OKAY, then close everything without sending EXIT
  badmsg    reply OKAY, then send an unknown message on errfd
  split     like ok, but send the errfd messages one byte at a time
  exit=N    reply OKAY, then send EXIT N without running anything
"""
import array
import os
import socket
import struct
import subprocess
import sys
import time

path, mode = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(1)
conn, _ = srv.accept()


def recv_exact(n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            sys.exit("server: connection closed")
        buf += chunk
    return buf


hdr = recv_exact(8)
assert hdr[:4] == b"SSHA" and hdr[4:6] == b"\0\1", hdr
cmd = recv_exact(struct.unpack(">H", hdr[6:8])[0])
with open(path + ".args", "wb") as f:
    f.write(cmd)
args = cmd.split(b"\0")

if mode == "err":
    msg = b"denied: " + b" ".join(args)
    conn.sendall(b"ERR!" + struct.pack(">H", len(msg)) + msg)
    sys.exit()
if mode == "badreply":
    conn.sendall(b"WHAT")
    sys.exit()
if mode == "nofd":
    conn.sendall(b"OKAY")
    time.sleep(1)
    sys.exit()

r, w = os.pipe()
conn.sendmsg([b"OKAY"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [r]))])
os.close(r)


def send_err(data):
    if mode == "split":
        for b in data:
            os.write(w, bytes([b]))
            time.sleep(0.01)
    else:
        os.write(w, data)


def text(t):
    send_err(b"TEXT" + struct.pack(">H", len(t)) + t)


if mode == "noexit":
    conn.close()
    os.close(w)
    sys.exit()
if mode == "badmsg":
    send_err(b"WHAT")
    time.sleep(1)
    sys.exit()
if mode.startswith("exit="):
    send_err(b"EXIT" + struct.pack(">i", int(mode[5:])))
    time.sleep(1)
    sys.exit()

text(b"running: " + b" ".join(args) + b"\n")
p = subprocess.run(args, stdin=conn.makefile("rb"), stdout=subprocess.PIPE)
# Send all output before EXIT: the client exits as soon as it reads EXIT.
conn.sendall(p.stdout)
send_err(b"EXIT" + struct.pack(">i", p.returncode))
conn.close()
