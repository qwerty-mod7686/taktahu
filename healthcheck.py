# language: Python, file: healthcheck.py, target: own vulnbox services (RE:HACK compliant)
# Defence-side tool. Polls YOUR OWN services every N seconds so you know the
# moment a patch breaks something or a service goes down (SLA points).
#
# Usage:
#   python healthcheck.py services.txt            (checks every 30s, forever)
#   python healthcheck.py services.txt --once     (single pass, good for after-patch check)
#
# services.txt format (one per line):
#   http://127.0.0.1:8080/           Name=webapp    contains=Welcome
#   tcp://127.0.0.1:9000             Name=fileserver
#   http://127.0.0.1:3000/api/health Name=api       status=200
#
# contains=  -> body must contain this string (omit for any response)
# status=    -> exact HTTP status expected (default: any 2xx/3xx)
# Alert goes to stderr + log so it's visible in a terminal you keep open.

import sys
import time
import socket
import argparse
import urllib.request

from toolbox import run_tool, ToolError, UsageError, EnvError, safe_read

CHECK_INTERVAL = 30  # own box — org delay rule is about attacking others, but keep polite


def parse_services(raw):
    """Parse services.txt lines into check dicts."""
    services = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        url = parts[0]
        opts = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                opts[k.lower()] = v
        if not url.startswith(("http://", "https://", "tcp://")):
            raise UsageError(f"bad service line (needs http:// or tcp://): {ln}")
        services.append({
            "url": url,
            "name": opts.get("name", url),
            "contains": opts.get("contains"),
            "status": int(opts.get("status", 0)),
        })
    if not services:
        raise UsageError("services.txt is empty",
                         hint="one service per line: http://127.0.0.1:8080/ Name=webapp contains=Welcome")
    return services


def check_http(svc):
    try:
        r = urllib.request.urlopen(svc["url"], timeout=8)
        status, body = r.status, r.read(64 * 1024)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(64 * 1024)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    if svc["status"] and status != svc["status"]:
        return False, f"status {status} != expected {svc['status']}"
    if svc["contains"] and svc["contains"].encode() not in body:
        return False, f"body missing {svc['contains']!r} (patch broke the page?)"
    return True, f"ok ({status}, {len(body)}B)"


def check_tcp(svc):
    hostport = svc["url"][len("tcp://"):]
    host, _, port = hostport.rpartition(":")
    try:
        s = socket.create_connection((host, int(port)), timeout=8)
        s.close()
        return True, "ok (connect)"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"


def check(svc):
    if svc["url"].startswith("tcp://"):
        return check_tcp(svc)
    return check_http(svc)


def run_checks(services, log, round_no=None):
    """One pass over all services. Returns number of failures."""
    failed = 0
    tag = f"[round {round_no}] " if round_no is not None else ""
    for svc in services:
        ok, detail = check(svc)
        mark = "OK  " if ok else "DOWN"
        line = f"{tag}{mark} {svc['name']:20s} {detail}"
        print(line)
        if not ok:
            failed += 1
            log.error(f"SERVICE DOWN: {svc['name']} ({svc['url']}) — {detail}")
            print("      !! fix it NOW — SLA points are bleeding", file=sys.stderr)
    return failed


def main(log=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("services_file")
    ap.add_argument("--once", action="store_true", help="single pass then exit (post-patch check)")
    ap.add_argument("--interval", type=int, default=CHECK_INTERVAL)
    args = ap.parse_args()

    raw = safe_read(args.services_file, "services file")
    services = parse_services(raw)
    log.info(f"watching {len(services)} services, interval {args.interval}s")

    if args.once:
        failed = run_checks(services, log)
        return 1 if failed else 0

    round_no = 0
    while True:
        round_no += 1
        print(f"--- check round {round_no} ---")
        try:
            run_checks(services, log, round_no)
        except KeyboardInterrupt:
            log.info("healthcheck stopped")
            return 0
        except Exception as e:
            log.error(f"check round crashed: {type(e).__name__}: {e} — continuing")
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            log.info("healthcheck stopped")
            return 0


if __name__ == "__main__":
    sys.exit(run_tool(main, "healthcheck"))
