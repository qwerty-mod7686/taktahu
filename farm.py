# language: Python, file: farm.py, target: ructf-protocol gameservers (most common)
# Minimal exploit farm. Runs every exploit in ./exploits/ against every team
# every tick, collects flags from stdout, submits to the gameserver API.
#
# Config via env or edit below:
#   TEAM_HOSTS   = "10.10.1.1,10.10.2.1,..."  (or auto from attack-info)
#   API_URL      = "http://gameserver:8080"   (ructf-style)
#   FLAG_REGEX   = same as exp_template.py
#
# ructf protocol:
#   GET  {API}/attack.json   -> [{"team_id":1,"hostname":"10.10.1.1"," ...}]
#   PUT  {API}/flags         -> body "flag1\nflag2\n" -> {"status":"ok", ...}

import os
import re
import sys
import time
import json
import glob
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from toolbox import run_tool, ToolError, EnvError, TargetError, UsageError

API_URL = os.getenv("API_URL", "http://127.0.0.1:8080")
TICK_SECONDS = int(os.getenv("TICK_SECONDS", "60"))
EXPLOIT_DELAY = float(os.getenv("EXPLOIT_DELAY", "2.0"))  # rule: min 2s between automation actions
EXPLOIT_DIR = os.getenv("EXPLOIT_DIR", "exploits")
EXPLOIT_TIMEOUT = int(os.getenv("EXPLOIT_TIMEOUT", "30"))

seen_flags = set()
LOG = None  # set by main()
def get_targets():
    """Poll attack-info; fall back to static team list."""
    try:
        with urllib.request.urlopen(f"{API_URL}/attack.json", timeout=10) as r:
            data = json.loads(r.read())
        # ructf: [{"team_id":..,"hostname":"ip", ...}] — adapt key names to your gameserver
        return [(t.get("team_id", t.get("id")), t.get("hostname", t.get("ip"))) for t in data]
    except urllib.error.URLError as e:
        LOG.warn(f"attack-info unreachable: {e} — falling back to TEAM_HOSTS")
        hosts = os.getenv("TEAM_HOSTS", "").split(",")
        pairs = [(i, h.strip()) for i, h in enumerate(hosts) if h.strip()]
        if not pairs:
            raise TargetError("no attack-info and TEAM_HOSTS empty",
                              hint="export TEAM_HOSTS=ip1,ip2,... or fix API_URL")
        return pairs
    except json.JSONDecodeError as e:
        raise TargetError(f"attack-info returned non-JSON: {e}",
                          hint="check API_URL points at the gameserver attack endpoint")


def run_exploit(exploit, host, extra_json="[]"):
    import subprocess
    env = dict(os.environ, TARGET_IP=host, TARGET_EXTRA=extra_json)
    try:
        p = subprocess.run(
            [sys.executable, exploit], env=env, capture_output=True, timeout=EXPLOIT_TIMEOUT)
        return p.stdout
    except subprocess.TimeoutExpired:
        LOG.warn(f"exploit timed out after {EXPLOIT_TIMEOUT}s: {exploit} -> {host}")
        return b""
    except OSError as e:
        LOG.error(f"cannot execute exploit {exploit}: {e}")
        return b""


def submit_flags(flags):
    if not flags:
        return
    body = "\n".join(flags).encode() + b"\n"
    req = urllib.request.Request(f"{API_URL}/flags", data=body, method="PUT",
                                 headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            LOG.info(f"submitted {len(flags)} flags: {r.read()[:200]}")
    except urllib.error.HTTPError as e:
        # gameserver answered but rejected — could be rate limit, bad flag, wrong endpoint
        detail = e.read()[:200]
        LOG.warn(f"submit rejected ({e.code}): {detail}")
    except urllib.error.URLError as e:
        LOG.error(f"submit failed (gameserver down?): {e} — flags kept, will not resubmit old ones")
    except Exception as e:
        LOG.error(f"submit unexpected: {type(e).__name__}: {e}")


def tick():
    targets = get_targets()
    exploits = sorted(glob.glob(os.path.join(EXPLOIT_DIR, "*.py")))
    if not exploits:
        LOG.warn(f"no exploits found in {EXPLOIT_DIR}/ — write one with exp_template.py")
    print(f"[*] tick: {len(exploits)} exploits x {len(targets)} targets")
    found = []
    with ThreadPoolExecutor(max_workers=3) as ex:  # low concurrency: rules forbid flooding
        futures = []
        for exp in exploits:
            for team_id, host in targets:
                if not host:
                    continue
                time.sleep(EXPLOIT_DELAY)  # MANDATORY: >=2s delay between automated requests
                extra = json.dumps([{"team_id": team_id}])  # farm passes flag_id info here if gameserver provides it
                futures.append(ex.submit(run_exploit, exp, host, extra))
        for f in futures:
            try:
                out = f.result()
            except Exception as e:
                LOG.error(f"exploit worker crashed: {type(e).__name__}: {e}")
                continue
            for m in FLAG_RE.finditer(out or b""):
                fl = m.group(0).decode()
                if fl not in seen_flags:
                    seen_flags.add(fl)
                    found.append(fl)
                    LOG.hit(f"flag: {fl}")
    submit_flags(found)


def main(log=None):
    global LOG
    LOG = log
    if not os.path.isdir(EXPLOIT_DIR):
        raise EnvError(f"exploit dir missing: {EXPLOIT_DIR}",
                       hint="mkdir exploits  — or set EXPLOIT_DIR env to your folder")
    log.info(f"farm up. api={API_URL} tick={TICK_SECONDS}s dir={EXPLOIT_DIR}")
    while True:
        start = time.time()
        try:
            tick()
        except ToolError:
            raise  # env/target problems surface immediately with a message
        except KeyboardInterrupt:
            log.info("bye")
            return 0
        except Exception as e:
            # unknown per-tick failure: log full detail, keep the farm alive
            log.error(f"tick error: {type(e).__name__}: {e} — continuing next tick")
        time.sleep(max(0, TICK_SECONDS - (time.time() - start)))


if __name__ == "__main__":
    sys.exit(run_tool(main, "farm"))
