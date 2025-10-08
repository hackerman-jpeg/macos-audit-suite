#!/usr/bin/env python3

## AI is skipped if not present. Remember this won't run with AI unless you install the right model and have it up and running. Use the provided script to do it easily. 
import os, sys, re, json, subprocess, datetime, webbrowser
from collections import Counter
import report_theme as theme

STREAM = ("-stream" in sys.argv) or ("--stream" in sys.argv)
OPEN_BROWSER = "--no-open" not in sys.argv

LLM_HOST  = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
LLM_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
LLM_CTX   = int(os.environ.get("OLLAMA_NUM_CTX", "8192"))
LLM_TO    = 90

NOW = datetime.datetime.now(datetime.timezone.utc)
STAMP = NOW.strftime("%Y-%m-%d_%H%M")
OUT_TXT = f"audit_{STAMP}.txt"
OUT_HTML = f"audit_{STAMP}.html"

def info(m): 
    if STREAM: print(m, flush=True)

def menu():
    print("MacOS Audit Agent   " + ("[streaming on]" if STREAM else "[streaming off]"))
    print("1) Quick last hour")
    print("2) Last 24 hours")
    print("3) Last 48 hours")
    print("4) Last 7 days")
    print("5) Custom range")
    print("6) Run STIGs if stig_runner.py present")
    return (input("Choice [1-6]: ").strip() or "1")

def resolve_range(choice):
    end = datetime.datetime.now()
    if choice == "1": start = end - datetime.timedelta(hours=1)
    elif choice == "2": start = end - datetime.timedelta(hours=24)
    elif choice == "3": start = end - datetime.timedelta(hours=48)
    elif choice == "4": start = end - datetime.timedelta(days=7)
    elif choice == "5":
        s = input("Start YYYY-MM-DD HH:MM (local): ").strip()
        e = input("End   YYYY-MM-DD HH:MM (local): ").strip()
        start = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M"); end = datetime.datetime.strptime(e, "%Y-%m-%d %H:%M")
    else: start = end - datetime.timedelta(hours=1)
    return start.isoformat(), end.isoformat()

def shquote(s): return "'" + s.replace("'", "'\\''") + "'"

def _ollama(prompt:str, temperature=0.0):
    req = {"model": LLM_MODEL, "options":{"temperature":temperature, "num_ctx": LLM_CTX}, "prompt": prompt, "stream": False}
    try:
        import urllib.request
        r = urllib.request.Request(f"{LLM_HOST}/api/generate", data=json.dumps(req).encode(), headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(r, timeout=LLM_TO) as f:
            return json.loads(f.read()).get("response","").strip()
    except Exception as e:
        return f"__LLM_ERROR__ {type(e).__name__}: {e}"

def ai_triage(category, evidence):
    sys_prompt = ('You are a macOS blue-team auditor. Given CATEGORY and EVIDENCE (log/config snippets), '
                  'return compact JSON only: verdict,rationale,tags,confidence. verdict ∈ '
                  '["Benign Likely FP","Risk Needs Review","Fail Confirmed","Inconclusive"].')
    body = _ollama(f"<<SYS>>{sys_prompt}<</SYS>>\nCATEGORY:\n{category}\nEVIDENCE:\n{evidence}\nRESPONSE:")
    try:
        obj = json.loads(body)
        if all(k in obj for k in ("verdict","rationale","tags","confidence")): return obj
    except Exception: pass
    body2 = _ollama("JSON only with verdict,rationale,tags,confidence\n" + f"CATEGORY:\n{category}\nEVIDENCE:\n{evidence}\nRESPONSE:")
    try:
        obj2 = json.loads(body2)
        if all(k in obj2 for k in ("verdict","rationale","tags","confidence")): return obj2
    except Exception: pass
    return {"verdict":"Inconclusive","rationale":"Model returned non JSON.","tags":[],"confidence":"low"}

CATEGORIES = {
    "AUTH": [
        'eventMessage CONTAINS "Failed to authenticate"',
        'processImagePath CONTAINS "/usr/sbin/sshd" AND eventMessage CONTAINS "Failed"',
        'category == "authentication" AND (eventMessage CONTAINS "failure" OR eventMessage CONTAINS "denied")',
        'subsystem == "com.apple.Authorization" AND eventMessage CONTAINS "refused"',
    ],
    "PRIV": [
        'eventMessage CONTAINS "sudo" AND eventMessage CONTAINS "authentication failure"',
        'processImagePath CONTAINS "launchctl" AND eventMessage CONTAINS "Permission denied"',
    ],
    "PERSIST": [
        'subsystem == "com.apple.xpc.activity" AND eventMessage CONTAINS "register" AND eventMessage CONTAINS "LaunchAgent"',
        'senderImagePath CONTAINS "/Library/LaunchDaemons" AND eventMessage CONTAINS "adding service"',
    ],
    "NETWORK": [
        'subsystem == "com.apple.network" AND eventMessage CONTAINS "proxy"',
        'processImagePath CONTAINS "/usr/libexec/ApplicationFirewall" AND eventMessage CONTAINS "allowing" AND eventMessage CONTAINS "unsigned"',
    ],
    "SECURITY": [
        'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "deny"',
        'category == "policy" AND eventMessage CONTAINS "Gatekeeper" AND (eventMessage CONTAINS "disabled" OR eventMessage CONTAINS "bypass")',
    ],
}

def run_log_show(start_iso, end_iso, predicate):
    cmd = f"/usr/bin/log show --info --debug --predicate {shquote(predicate)} --style json --start {shquote(start_iso)} --end {shquote(end_iso)}"
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0: return []
    rows = []
    for ln in p.stdout.splitlines():
        try:
            obj = json.loads(ln)
            rows.append((obj.get('timestamp',''), obj.get('processImagePath') or obj.get('senderImagePath') or obj.get('process',''), obj.get('eventMessage','')))
        except Exception: continue
    return rows

def audit_once(start_iso, end_iso):
    info("Starting scan, this may take a moment")
    kpi = Counter({"pass":0,"fail":0,"error":0,"manual":0})
    sev_counts = Counter({"high":0,"medium":0,"low":0})
    rows = []

    with open(OUT_TXT, "w") as txt:
        txt.write(f"AUDIT window {start_iso} .. {end_iso}\n")
        for cat, preds in CATEGORIES.items():
            info(f"{cat} ({len(preds)} predicates)")
            hits = []
            for pr in preds:
                info(f"Scanning {cat} | {pr}")
                hits.extend(run_log_show(start_iso, end_iso, pr)[:50])
            if not hits:
                ai = ai_triage(cat, f"No hits in window {start_iso}..{end_iso}.")
                rows.append({"id":cat,"title":f"{cat} signals","severity":"medium",
                             "commands":[f"log show --predicate {pr}" for pr in preds],"status":"executed-pass",
                             "ai":ai,"rc":0,"out":"no hits","err":""})
                kpi["pass"] += 1; sev_counts["medium"] += 1
                continue
            ev = "\n".join(f"{t} {p} {m}" for t,p,m in hits[:200])
            ai = ai_triage(cat, ev[:6000])
            rows.append({"id":cat,"title":f"{cat} signals","severity":"high" if cat in ("PERSIST","SECURITY") else "medium",
                         "commands":[f"log show --predicate {pr}" for pr in preds],"status":"executed-fail",
                         "ai":ai,"rc":0,"out":ev[:4000],"err":""})
            kpi["fail"] += 1; sev_counts["high" if cat in ("PERSIST","SECURITY") else "medium"] += 1
            txt.write(f"\n## {cat}\n")
            for t,p,m in hits[:50]: txt.write(f"{t} {p} {m}\n")

    ai_index = min(100, kpi["fail"]*10 + sev_counts["high"]*3 + sev_counts["medium"])

    with open(OUT_HTML, "w") as h:
        h.write(theme.html_head("MacOS Audit Report", f"Window {start_iso} → {end_iso}", LLM_MODEL, LLM_CTX, unsafe=False))
        h.write(theme.html_dashboard(kpi, sev_counts, ai_index))
        h.write(theme.html_table_open("Execution summary"))
        for r in rows:
            h.write(theme.html_table_row(r["id"], r["title"], r["severity"], r["commands"], r["status"], r["ai"]["verdict"] if r.get("ai") else None))
        h.write(theme.html_table_close())
        h.write('<div class="section"><h2>Details</h2>')
        for r in rows:
            h.write(theme.html_rule_block(r["id"], r["title"], r["severity"], r["commands"], r["rc"], r["out"], r["err"], r.get("ai")))
        h.write(theme.html_close())

    print(f"TXT report: {OUT_TXT}")
    print(f"HTML report: {OUT_HTML}")
    if OPEN_BROWSER:
        try: webbrowser.open("file://" + os.path.abspath(OUT_HTML))
        except Exception: pass

def main():
    ch = menu()
    if ch == "6":
        if not os.path.exists("stig_runner.py"):
            print("stig_runner.py not found next to this script."); sys.exit(1)
        os.execv(sys.executable, [sys.executable, "stig_runner.py"] + (["--stream"] if STREAM else []))
    start_iso, end_iso = resolve_range(ch)
    audit_once(start_iso, end_iso)

if __name__ == "__main__": main()
