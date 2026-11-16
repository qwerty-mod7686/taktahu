# language: Python, file: rollback.py, target: own vulnbox services
# One-command service rollback: restore source from git + restart the service.
# Use when a patch breaks your service and SLA is bleeding.
#
# Usage:
#   python rollback.py init <service_dir> [--restart "systemctl restart x"]   (once, before comp)
#   python rollback.py save <name>                                            (snapshot current state)
#   python rollback.py list                                                   (see snapshots)
#   python rollback.py restore <name>                                         (roll back NOW)
#
# How it works:
#   init    -> makes <service_dir> a git repo (if not already) and saves the
#              restart command so every later restore+restart is one command
#   save    -> git commit -am "snapshot: <name>" (before/after every patch)
#   restore -> git checkout the previous snapshot, run the restart command,
#              then run healthcheck --once if services file exists
#
# Example session during the comp:
#   python rollback.py init /opt/bigbearcrafty --restart "supervisorctl restart bear"
#   # ... you patch the service ...
#   python rollback.py save patched-auth-bypass
#   # ... healthcheck says DOWN — patch broke it ...
#   python rollback.py restore patched-auth-bypass    # back to before in seconds

import os
import sys
import subprocess
import argparse

from toolbox import run_tool, ToolError, UsageError, EnvError

# where rollback.py remembers service dirs + restart commands
STATE_FILE = ".rollback_state"


def git(service_dir, *args):
    """Run a git command inside service_dir. Returns (rc, output)."""
    p = subprocess.run(["git", "-C", service_dir, *args],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout + p.stderr).strip()


def load_state():
    import json
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise EnvError(f"cannot read {STATE_FILE}: {e}",
                       hint="delete the file and re-run init")


def save_state(state):
    import json
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def cmd_init(service_dir, restart_cmd, log):
    if not os.path.isdir(service_dir):
        raise UsageError(f"service dir not found: {service_dir}")
    rc, out = git(service_dir, "rev-parse", "--git-dir")
    if rc != 0:
        # not a repo yet — init one silently
        rc, out = git(service_dir, "init", "-q")
        if rc != 0:
            raise EnvError(f"git init failed in {service_dir}: {out}")
        rc, out = git(service_dir, "add", "-A")
        if rc != 0:
            raise EnvError(f"git add failed: {out}")
        rc, out = git(service_dir, "commit", "-qm", "rollback.py baseline")
        if rc != 0 and "nothing to commit" not in out:
            # empty dir or git identity not set — commit needs a name
            git(service_dir, "config", "user.email", "rollback@local")
            git(service_dir, "config", "user.name", "rollback")
            rc, out = git(service_dir, "commit", "-qm", "rollback.py baseline")
            if rc != 0:
                raise EnvError(f"git commit failed: {out}", hint=str(out))
    state = load_state()
    key = os.path.abspath(service_dir)
    state[key] = {"restart": restart_cmd or ""}
    save_state(state)
    log.info(f"service registered: {key}")
    if restart_cmd:
        log.info(f"restart command: {restart_cmd}")
    else:
        log.warn("no --restart given; restore will not restart the service")
    return 0


def cmd_save(service_dir, name, log):
    key = os.path.abspath(service_dir)
    state = load_state()
    if key not in state:
        raise UsageError(f"{service_dir} not registered — run: rollback.py init {service_dir}")
    rc, out = git(service_dir, "add", "-A")
    if rc != 0:
        raise EnvError(f"git add failed: {out}")
    rc, out = git(service_dir, "commit", "-qm", f"snapshot: {name}")
    if rc != 0 and "nothing to commit" not in out:
        raise EnvError(f"git commit failed: {out}")
    if "nothing to commit" in out:
        log.info(f"no changes since last snapshot — '{name}' not created")
    else:
        log.info(f"snapshot saved: {name}")
    return 0


def cmd_list(service_dir, log):
    rc, out = git(service_dir, "log", "--oneline", "-20")
    if rc != 0:
        raise UsageError(f"not a git repo: {service_dir}",
                         hint="run: rollback.py init <service_dir> first")
    print(out)
    return 0


def cmd_restore(service_dir, name, log):
    key = os.path.abspath(service_dir)
    state = load_state()
    if key not in state:
        raise UsageError(f"{service_dir} not registered — run: rollback.py init {service_dir}")
    # find the commit BEFORE the named snapshot
    rc, out = git(service_dir, "log", "--oneline", f"--grep=snapshot: {name}")
    if rc != 0 or not out:
        raise UsageError(f"no snapshot named '{name}'",
                         hint="run: rollback.py list to see snapshots")
    target_hash = out.splitlines()[0].split()[0]
    rc, out = git(service_dir, "log", "--oneline", f"{target_hash}~1", "-1")
    if rc != 0 or not out:
        raise UsageError(f"snapshot '{name}' is the baseline — nothing before it to restore to")
    prev_hash = out.splitlines()[0].split()[0]
    # restore
    rc, out = git(service_dir, "checkout", "-q", prev_hash, "--", ".")
    if rc != 0:
        raise EnvError(f"git checkout failed: {out}")
    log.info(f"restored source to {prev_hash[:8]} (before '{name}')")
    # restart
    restart = state[key].get("restart")
    if restart:
        p = subprocess.run(restart, shell=True, capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            log.error(f"restart command failed ({p.returncode}): {p.stdout} {p.stderr}")
            print("  fix: restart the service manually, then verify with healthcheck", file=sys.stderr)
        else:
            log.info(f"restarted: {restart}")
    else:
        log.warn("no restart command registered — restart the service manually")
    # verify if services file exists
    for cand in ("services.txt", "services.txt.example"):
        if os.path.isfile(cand):
            print(f"[*] verifying with healthcheck ({cand})...")
            subprocess.run([sys.executable, "healthcheck.py", cand, "--once"])
            break
    return 0


def main(log=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="register a service dir")
    p_init.add_argument("service_dir")
    p_init.add_argument("--restart", help='command to restart the service, e.g. "supervisorctl restart bear"')
    p_save = sub.add_parser("save", help="snapshot current state")
    p_save.add_argument("service_dir")
    p_save.add_argument("name")
    p_list = sub.add_parser("list", help="show snapshots")
    p_list.add_argument("service_dir")
    p_rest = sub.add_parser("restore", help="roll back to before a snapshot")
    p_rest.add_argument("service_dir")
    p_rest.add_argument("name")
    args = ap.parse_args()

    if args.cmd == "init":
        return cmd_init(args.service_dir, args.restart, log)
    if args.cmd == "save":
        return cmd_save(args.service_dir, args.name, log)
    if args.cmd == "list":
        return cmd_list(args.service_dir, log)
    if args.cmd == "restore":
        return cmd_restore(args.service_dir, args.name, log)


if __name__ == "__main__":
    sys.exit(run_tool(main, "rollback"))
