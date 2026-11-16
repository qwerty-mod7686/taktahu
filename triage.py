# language: Python, file: triage.py, target: source-code folders from vulnbox
# Usage: python triage.py <source_dir>
# Static bug-signature scanner. Not magic — it greps with context and severity.
# Every hit needs a human eyeball, but it points you at the right lines first.

import os
import re
import sys

from toolbox import run_tool, ToolError, EnvError, UsageError

RULES = [
    # (severity, bug class, regex, languages)
    ("HIGH", "buffer overflow",  r"\b(strcpy|strcat|sprintf|gets|scanf)\s*\(", ["c", "h", "cpp"]),
    ("HIGH", "command injection", r"(system|popen)\s*\(", ["c", "h", "cpp"]),
    ("HIGH", "command injection", r"shell\s*=\s*True", ["py"]),
    ("HIGH", "command injection", r"\b(system|exec|spawn|execSync)\s*\(", ["js"]),
    ("HIGH", "deserialization",   r"(pickle\.loads?|yaml\.load\b(?!_safe)|marshal\.loads)", ["py"]),
    ("HIGH", "deserialization",   r"unserialize\s*\(", ["php"]),
    ("HIGH", "deserialization",   r"readObject\(", ["java"]),
    ("HIGH", "code injection",    r"\beval\s*\(", ["py", "php", "js"]),
    ("HIGH", "SQL injection",     r"""(SELECT|INSERT|UPDATE|DELETE)[^;\n]*['"`\s](?:\+|\{|%|\.)\s*\w""", ["py", "php", "java", "js", "rb"]),
    ("MED",  "format string",     r"printf\s*\(\s*[a-zA-Z_][\w.]*\s*[,)]", ["c", "h", "cpp"]),
    ("MED",  "path traversal",    r"(open|file_get_contents|readFile|ifstream)\s*\([^)]*\+", ["py", "php", "js", "cpp"]),
    ("MED",  "weak compare",      r"==\s*(True|False)\b|password\s*==", ["py", "php", "js"]),
    ("MED",  "regex DoS",         r"re\.compile\s*\(\s*['\"].*\*.*\*.*['\"]", ["py"]),
    ("MED",  "XXE",               r"parseString|fromstring|DocumentBuilder", ["py", "java", "js"]),
    ("LOW",  "hardcoded secret",  r"(password|secret|token|apikey|api_key)\s*[:=]\s*['\"][^'\"]{4,}", ["py", "php", "js", "java", "rb", "env", "yml", "yaml", "conf", "ini"]),
    ("LOW",  "debug mode",        r"debug\s*[:=]\s*(True|true|1)", ["py", "php", "js", "env"]),
    ("LOW",  "weak random",       r"\brandom\.\w+\(|\brand\s*\(|Math\.random", ["py", "php", "js"]),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor", "dist"}

def scan_file(path):
    hits = []
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    lang = ext if ext in {"py", "php", "js", "java", "rb", "c", "h", "cpp"} else None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[skip] cannot read {path}: {e}", file=sys.stderr)  # skip, never stop the walk
        return hits
    for sev, bug, pattern, langs in RULES:
        if lang not in langs and ext not in langs:
            continue
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            print(f"[bug-in-triage] bad regex for {bug}: {e}", file=sys.stderr)
            continue
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                hits.append((sev, bug, path, i, line.rstrip()[:150]))
    return hits

def main(log=None):
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.isdir(root):
        raise UsageError(f"source directory not found: {root}",
                         hint="pass the vulnbox source folder, e.g. python triage.py ~/services/bigbear")
    all_hits = []
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            r = scan_file(os.path.join(dirpath, fn))
            all_hits.extend(r[0] if isinstance(r, tuple) else r)
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    all_hits.sort(key=lambda h: (order[h[0]], h[2]))
    for sev, bug, path, line, text in all_hits:
        print(f"[{sev:4s}] {bug:18s} {path}:{line}")
        print(f"       {text}")
    print(f"\n[*] {len(all_hits)} findings. HIGH first — confirm each against the actual data flow before trusting it.")
    return 0

if __name__ == "__main__":
    sys.exit(run_tool(main, "triage"))
