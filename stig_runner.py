#!/usr/bin/env python3
import os, sys, re, json, shlex, subprocess, datetime, tempfile, webbrowser, signal, time, html as htmllib
import xml.etree.ElementTree as ET
from collections import Counter
import report_theme as theme

STREAM        = ("-stream" in sys.argv) or ("--stream" in sys.argv)
OPEN_BROWSER  = "--no-open" not in sys.argv
ALLOW_UNSAFE  = "--allow-unsafe" in sys.argv
NOW           = datetime.datetime.now(datetime.timezone.utc)
STAMP         = NOW.strftime("%Y-%m-%d_%H%M")
OUT_HTML      = f"stig_{STAMP}.html"
OUT_TXT       = f"stig_{STAMP}.txt"

LLM_HOST     = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
LLM_MODEL    = os.environ.get("OLLAMA_MODEL", "llama3.1")
LLM_TIMEOUT  = 90
LLM_NUM_CTX  = int(os.environ.get("OLLAMA_NUM_CTX", "8192"))
ENABLE_LLM   = True
DEFAULT_TIMEOUT = int(next((sys.argv[i+1] for i,a in enumerate(sys.argv) if a=="--timeout"), "8")) if "--timeout" in sys.argv else 8

SAFE_BIN_ALLOWLIST = ("/usr/bin/","/bin/","/usr/sbin/","/sbin/","/System/Library/","/usr/libexec/")
NS = {"x":"http://checklists.nist.gov/xccdf/1.1","x12":"http://checklists.nist.gov/xccdf/1.2"}
HEREDOC_OSA_MARK = "__HEREDOC_OSASCRIPT__::"
HEREDOC_RE = re.compile(r'(?ms)^\s*(/usr/bin/osascript[^\n]*?)<<\s*([A-Za-z0-9_]+)\s*\n(.*?)\n\2\s*$')
LINE_CMD_RES = [re.compile(r'^\s*\$\s+(.+)$', re.M), re.compile(r'`(/[^`]+)`'), re.compile(r'(?m)^\s*(/usr/\S+|/bin/\S+|/sbin/\S+)\b[^\n]*')]

def info(m): 
    if STREAM: print(m, flush=True)

def _ollama_generate(prompt, temperature=0.1):
    req = {"model": LLM_MODEL, "options":{"temperature":temperature,"num_ctx":LLM_NUM_CTX},"prompt":prompt,"stream":False}
    try:
        import urllib.request
        r = urllib.request.Request(f"{LLM_HOST}/api/generate", data=json.dumps(req).encode(), headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(r, timeout=LLM_TIMEOUT) as f:
            return json.loads(f.read()).get("response","").strip()
    except Exception as e:
        return f"__LLM_ERROR__ {type(e).__name__}: {e}"

def ai_judge(rule_meta, evidence):
    if not ENABLE_LLM or not evidence.strip():
        return {"verdict":"Inconclusive","rationale":"No evidence to analyze.","tags":[],"confidence":"low"}
    sys_prompt = ('You are a macOS compliance auditor. Analyze the STIG check EVIDENCE and decide if a failure is likely a false positive, '
                  'real issue, or inconclusive. Return JSON only: verdict,rationale,tags,confidence. verdict ∈ '
                  '["Benign Likely FP","Risk Needs Review","Fail Confirmed","Inconclusive"].')
    body = _ollama_generate(f"<<SYS>>{sys_prompt}<</SYS>>\nRULE_META:\n{json.dumps(rule_meta)}\nEVIDENCE:\n{evidence}\nRESPONSE:", 0.0)
    try:
        obj = json.loads(body)
        if all(k in obj for k in ("verdict","rationale","tags","confidence")): return obj
    except Exception: pass
    body2 = _ollama_generate("JSON only with verdict,rationale,tags,confidence\n" + f"RULE_META:\n{json.dumps(rule_meta)}\nEVIDENCE:\n{evidence}\nRESPONSE:", 0.0)
    try:
        obj2 = json.loads(body2)
        if all(k in obj2 for k in ("verdict","rationale","tags","confidence")): return obj2
    except Exception: pass
    return {"verdict":"Inconclusive","rationale":"Model returned non JSON.","tags":[],"confidence":"low"}

def extract_commands(check_text):
    if not check_text: return []
    commands = []
    for m in HEREDOC_RE.finditer(check_text):
        payload = {"head": m.group(1).strip(), "script": m.group(3)}
        commands.append(HEREDOC_OSA_MARK + json.dumps(payload))
    for rx in LINE_CMD_RES:
        for m in rx.findall(check_text):
            cmd = m if isinstance(m, str) else m[0]
            cmd = re.sub(r'\s+#.*$', '', cmd.strip())
            if not cmd: continue
            if not ALLOW_UNSAFE and re.search(r'\b(rm\s+-rf|defaults\s+write.*\s+true|launchctl\s+(remove|unload)|pwpolicy\s+-set|\bprofiles\b\s+-R|\bsystemsetup\b.*-set)', cmd):
                continue
            if not cmd.split()[0].startswith(SAFE_BIN_ALLOWLIST): continue
            if cmd.startswith("/usr/bin/osascript") and "<< " in check_text: continue
            if cmd not in commands: commands.append(cmd)
    return commands[:6]

def find_rules(xml_path):
    try: root = ET.parse(xml_path).getroot()
    except Exception as e: print(f"Failed to parse {xml_path}: {e}"); return []
    def text_in(el, name):
        for ns in (NS["x12"], NS["x"], ""):
            tag = f"./{{{ns}}}{name}" if ns else f"./{name}"
            n = el.find(tag)
            if n is not None and (n.text or "").strip(): return n.text
        return ""
    rules=[]
    for ns in (NS["x12"], NS["x"], ""):
        for r in root.findall(f".//{{{ns}}}Rule" if ns else ".//Rule"):
            rid = r.get("id","").strip()
            title = text_in(r, "title").strip()
            sev = r.get("severity","").lower() or "unknown"
            check_text = ""
            for tns in (NS["x12"], NS["x"], ""):
                cc = r.find(f".//{{{tns}}}check/{{{tns}}}check-content") if tns else r.find(".//check/check-content")
                if cc is not None and cc.text: check_text = cc.text; break
            cmds = extract_commands(check_text)
            rules.append({"id":rid,"title":title,"severity":sev,"check_text":check_text,"commands":cmds})
    return rules

def run_cmd(cmd, timeout_s):
    if cmd.startswith(HEREDOC_OSA_MARK):
        payload = json.loads(cmd[len(HEREDOC_OSA_MARK):])
        head, script = payload["head"], payload["script"]
        import tempfile, shlex
        with tempfile.NamedTemporaryFile(prefix="stig_jxa_", suffix=".js", delete=False, mode="w") as tf:
            tf.write(script); tmp = tf.name
        head_args = shlex.split(head); final = [head_args[0]]
        if "-l" in head_args:
            i = head_args.index("-l"); final.extend(head_args[i:i+2])
        final.append(tmp)
        final_cmd = " ".join(shlex.quote(x) for x in final)
        try: rc, out, err = _run_shell(final_cmd, timeout_s)
        finally:
            try: os.unlink(tmp)
            except Exception: pass
        return rc, out, f"{err}\n[heredoc from STIG]"
    return _run_shell(cmd, timeout_s)

def _run_shell(cmd, timeout_s):
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        try: out, err = p.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); return 124, "", f"timeout after {timeout_s}s"
        return p.returncode, (out or "").strip(), (err or "").strip()
    except KeyboardInterrupt:
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
        return 130, "", "interrupted by user"
    except Exception as e:
        return 255, "", f"runner exception: {e}"

def triage_status(rc, out, err, rule):
    blob = (out+"\n"+err).lower()
    if not rule["commands"]: return "manual", False
    if rc == 0:
        if re.search(r"\b(pass|yes|enabled|ok)\b", blob): return "executed", True
        return "executed", False
    if rc in (124,127,130): return ("errors" if rc!=130 else "skipped"), False
    if "grep -c" in " ".join(rule["commands"]) and out.strip()=="0": return "executed", False
    return "errors", False

def probable_false_positive(rc, out, err):
    text = (out+"\n"+err).lower()
    if rc in (124,130): return True, "Check timed out or was interrupted."
    if rc == 127 or "command not found" in text or "xpath set is empty" in text: return True, "Dependency absent or key missing; often Not Applicable."
    return False, ""

def main():
    files = [f for f in os.listdir(".") if f.lower().endswith(".xml") and ("stig" in f.lower() or "xccdf" in f.lower()) and "macos" in f.lower()]
    if not files: print("No STIG XCCDF XML files found in current dir."); sys.exit(1)
    print("STIG Runner")
    for i,f in enumerate(files,1): print(f"{i}) {f}")
    print("a) Run All (first STIG)")
    sel = input("Select STIG [1..N or a]: ").strip().lower() or "a"
    source = files[0] if sel=="a" else files[int(sel)-1]

    rules = find_rules(source)
    rows=[]; kpi=Counter({"pass":0,"fail":0,"error":0,"manual":0,"skipped":0}); sev_counts=Counter({"high":0,"medium":0,"low":0})
    with open(OUT_TXT,"w") as txt, open(OUT_HTML,"w") as h:
        h.write(theme.html_head("STIG Runner", f"Source {source}", LLM_MODEL, LLM_NUM_CTX, ALLOW_UNSAFE, timeout=DEFAULT_TIMEOUT))
        # iterate
        for r in rules:
            sev_counts[r["severity"]] += 1
            if r["commands"]:
                c0 = r["commands"][0]
                info(f"{r['id']} :: $ {'/usr/bin/osascript [heredoc]' if c0.startswith(HEREDOC_OSA_MARK) else c0}")
                rc, out, err = run_cmd(c0, DEFAULT_TIMEOUT)
                status, pass_like = triage_status(rc, out, err, r)
            else:
                rc,out,err=0,"",""
                status, pass_like = "manual", False

            # AI for non-pass
            ai_obj=None
            if status in ("errors","manual","skipped") or (status=="executed" and not pass_like):
                likely_fp, why = probable_false_positive(rc,out,err)
                meta={"id":r["id"],"title":r["title"],"severity":r["severity"],"status":status,"likely_fp":likely_fp,"why_fp":why,
                      "command": r["commands"][0] if r["commands"] else ""}
                ev=f"EXIT {rc}\nOUT:\n{out[:4000]}\nERR:\n{err[:2000]}"
                ai_obj = ai_judge(meta, ev)

            if status=="executed" and pass_like: kpi["pass"]+=1
            elif status=="executed" and not pass_like: kpi["fail"]+=1
            elif status=="errors": kpi["error"]+=1
            elif status=="skipped": kpi["skipped"]+=1
            else: kpi["manual"]+=1

            rows.append({"id":r["id"],"title":r["title"],"severity":r["severity"],"commands":r["commands"],"status":status,"pass_like":pass_like,
                         "rc":rc,"out":out,"err":err,"ai":ai_obj})

            # TXT
            txt.write(f"{r['id']}  {r['title']}  sev={r['severity']}\n")
            if r["commands"]:
                txt.write("$ " + ("/usr/bin/osascript  # heredoc\n" if r["commands"][0].startswith(HEREDOC_OSA_MARK) else r["commands"][0]+"\n"))
            txt.write(f"status={status} rc={rc}\n")
            if out: txt.write("STDOUT:\n"+out+"\n")
            if err: txt.write("STDERR:\n"+err+"\n")
            if ai_obj: txt.write("AI verdict: "+json.dumps(ai_obj, ensure_ascii=False)+"\n")
            txt.write("-"*72+"\n")

        # KPI + table + details
        ai_index = min(100, kpi["fail"]*5 + kpi["error"]*3 + sev_counts["high"]*2 + sev_counts["medium"])
        h.write(theme.html_dashboard(kpi, sev_counts, ai_index))
        h.write(theme.html_table_open("Execution summary"))
        for r in rows:
            cmds = []
            if r["commands"]:
                first = r["commands"][0]
                cmds = ["/usr/bin/osascript (heredoc)"] if isinstance(first,str) and first.startswith(HEREDOC_OSA_MARK) else [first]
            status_key = ("executed-pass" if (r["status"]=="executed" and r["pass_like"]) else
                          "executed-fail" if (r["status"]=="executed" and not r["pass_like"]) else r["status"])
            h.write(theme.html_table_row(r["id"], r["title"], r["severity"], cmds, status_key, r["ai"]["verdict"] if r.get("ai") else None))
        h.write(theme.html_table_close())
        h.write('<div class="section"><h2>Rule details with evidence</h2>')
        for r in rows:
            cmds=[]
            if r["commands"]:
                cmds = ["/usr/bin/osascript (heredoc)"] if r["commands"][0].startswith(HEREDOC_OSA_MARK) else r["commands"]
            h.write(theme.html_rule_block(r["id"], r["title"], r["severity"], cmds, r["rc"], r["out"], r["err"], r.get("ai")))
        h.write(theme.html_close())

    print(f"STIG HTML: {OUT_HTML}")
    print(f"STIG TXT:  {OUT_TXT}")
    if OPEN_BROWSER:
        try: webbrowser.open("file://" + os.path.abspath(OUT_HTML))
        except Exception: pass

if __name__ == "__main__": main()
