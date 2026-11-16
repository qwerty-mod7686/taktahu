# language: Python, file: toolbox.py, target: shared error-handling for all A&D tools
# Error-handling backbone for every tool in this folder.
#
# Layers implemented (reference doc mapping):
#   error response  -> exit codes (0 ok / 2 usage / 3 target / 4 env / 1 unknown)
#   error message   -> ToolError(msg, hint=...) — what broke + how to fix it
#   error handling  -> catchpoints at every IO/network/parse boundary, never crash silent
#   error reporting -> stderr for humans, .log file per tool run, machine-readable summary line
#   descriptive     -> every message names: tool, target, param, cause, suggested fix

import sys
import os
import time
import traceback

LOG_DIR = os.getenv("TOOLBOX_LOG_DIR", "logs")


class ToolError(Exception):
    """Base. code: 2=usage, 3=target-side, 4=environment."""
    def __init__(self, msg, hint="", code=1):
        super().__init__(msg)
        self.hint = hint
        self.code = code


class UsageError(ToolError):
    def __init__(self, msg, hint=""):
        super().__init__(msg, hint, code=2)


class TargetError(ToolError):
    """Remote side refused/timed out/behaved unexpectedly."""
    def __init__(self, msg, hint=""):
        super().__init__(msg, hint, code=3)


class EnvError(ToolError):
    """Local side: missing file, bad env var, wrong python."""
    def __init__(self, msg, hint=""):
        super().__init__(msg, hint, code=4)


class Logger:
    """Dual-channel reporting: stderr (human, terse) + logfile (full detail)."""
    def __init__(self, tool_name):
        self.tool = tool_name
        self.start = time.time()
        self.counts = {"info": 0, "warn": 0, "error": 0, "hit": 0}
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            self.path = os.path.join(LOG_DIR, f"{tool_name}-{time.strftime('%Y%m%d-%H%M%S')}.log")
            self.fh = open(self.path, "a", encoding="utf-8")
        except OSError as e:
            # logging must never kill the tool — degrade to stderr-only
            print(f"[toolbox] log file unavailable ({e}); stderr only", file=sys.stderr)
            self.fh = None
            self.path = None

    def _write(self, level, msg):
        line = f"[{time.strftime('%H:%M:%S')}] [{level:5s}] {msg}"
        if level in ("ERROR", "WARN", "HIT"):
            print(line, file=sys.stderr)   # humans see problems immediately
        if self.fh:
            try:
                self.fh.write(line + "\n")
                self.fh.flush()
            except OSError:
                pass
        self.counts[level.lower() if level != "WARN" else "warn"] = self.counts.get(
            level.lower() if level != "WARN" else "warn", 0) + 1

    def info(self, msg): self._write("INFO", msg)
    def warn(self, msg): self._write("WARN", msg)
    def error(self, msg): self._write("ERROR", msg)
    def hit(self, msg): self._write("HIT", msg)

    def summary(self):
        """Machine-readable one-liner — farm/other tools can parse this."""
        dur = time.time() - self.start
        s = (f"SUMMARY tool={self.tool} duration={dur:.1f}s "
             f"info={self.counts['info']} warn={self.counts['warn']} "
             f"error={self.counts['error']} hits={self.counts['hit']}")
        if self.fh:
            try:
                self.fh.write(s + "\n")
            except OSError:
                pass
        print(s, file=sys.stderr)
        return s

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass


def run_tool(main_fn, tool_name):
    """Universal entrypoint wrapper — THE error-handling layer for every tool.
    Usage: if __name__ == "__main__": run_tool(main, "omniprobe")"""
    log = Logger(tool_name)
    try:
        rc = main_fn(log) or 0
        log.summary()
        log.close()
        return rc
    except UsageError as e:
        log.error(f"usage: {e}")
        if e.hint:
            print(f"  fix: {e.hint}", file=sys.stderr)
        log.summary(); log.close()
        return 2
    except TargetError as e:
        log.error(f"target: {e}")
        if e.hint:
            print(f"  fix: {e.hint}", file=sys.stderr)
        log.summary(); log.close()
        return 3
    except EnvError as e:
        log.error(f"env: {e}")
        if e.hint:
            print(f"  fix: {e.hint}", file=sys.stderr)
        log.summary(); log.close()
        return 4
    except KeyboardInterrupt:
        log.warn("interrupted by user (Ctrl+C) — partial results kept in log")
        log.summary(); log.close()
        return 130
    except Exception as e:
        # unknown crash: full trace to log (descriptive), one line to stderr (usable)
        if log.fh:
            try:
                log.fh.write(traceback.format_exc() + "\n")
            except OSError:
                pass
        log.error(f"unexpected: {type(e).__name__}: {e}")
        print(f"  fix: check {log.path} for full traceback; "
              f"rerun with fewer --classes to isolate", file=sys.stderr)
        log.summary(); log.close()
        return 1


def http_result(status, body, hdrs):
    """Wrap raw HTTP outcome as a value — never raise from transport.
    status -1 means transport-level failure (already stringified in body)."""
    ok = 200 <= status < 400
    return {"ok": ok, "status": status, "body": body, "headers": hdrs}


def safe_read(path, what="file"):
    """Read a file with descriptive failure — for targets files, wordlists, tokens."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise EnvError(f"{what} not found: {path}",
                       hint="check the path, or run from the folder containing it")
    except PermissionError:
        raise EnvError(f"no permission to read {what}: {path}",
                       hint="file owned by another user?")
    except OSError as e:
        raise EnvError(f"cannot read {what} {path}: {e}")


def parse_url(url):
    """Validate a target URL with a useful message when it's malformed."""
    from urllib.parse import urlsplit
    if not url:
        raise UsageError("no URL given", hint="python omniprobe.py http://ip:port/path --data 'a=b'")
    if "://" not in url:
        raise UsageError(f"URL missing scheme: {url!r}",
                         hint="use http://ip:port or https://ip:port")
    parts = urlsplit(url)
    if not parts.hostname:
        raise UsageError(f"URL has no host: {url!r}")
    return parts
