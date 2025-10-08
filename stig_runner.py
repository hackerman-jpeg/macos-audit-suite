#!/usr/bin/env python3
# stig_runner.py
# Execute macOS STIG checks from DISA XCCDF, preserve evidence, and render a clean HTML report.
# Robust multi-line extraction (heredocs, backslash continuations, fenced blocks),
# safe-by-default execution, per-command timeouts, and optional local LLM analysis via Ollama.

import argparse, datetime, glob, json, os, re, shlex, subprocess, sys, textwrap, webbrowser
from typing import List, Dict, Tuple

# --- Theme
try:
    from report_theme import html_head, html_tail, dashboard_html
except Exception:
    # Fallback minimal if theme not present
    def html_head(t): return f"<!doctype html><meta charset='utf-8'><title>{t}</title><style>body{{font-family:sans-serif;}}</style><h1>{t}</h1>"
    def html_tail(): return ""
    def dashboard_html(t, m, c): return f"<h2>{t}</h2>"

NOW = datetime.datetime.now(datetime.timezone.utc)
STAMP = NOW.strftime("%Y-%m-%d_%H%M")
STREAM = False

# --- Execution safety
_EXEC_WHITELIST_PREFIX = ("/",)
_EXEC_WHITELIST_CMDS = {
    "osascript","defaults","profiles","security","csrutil","spctl","pwpolicy",
    "launchctl","grep","awk","sed","xmllint","stat","ls","find","sysctl",
    "more","cat","dscl","cupsctl","pgrep","mdmclient","sshd","sudo","sh","bash","zsh","printf","echo"
}

# --- Regex for extraction
_RE_FENCE = re.compile(r"```(?:bash|sh|zsh)?\s*\n(?P<body>.+?)\n```", re.DOTALL)
_RE_PROMPT = re.compile(r"^\s*\$\s*(?P<cmd>.+?)\s*$")
_RE_HEREDOC_OPEN = re.compile(r"(?P<head>.+?)<<\s*(?P<tag>[A-Za-z0-9_]+)\s*$")
def _RE_HEREDOC_TERM(tag): return re.compile(rf"^\s*{re.escape(tag)}\s*$")

def log(msg):
    if STREAM: print(msg, flush=True)

def join_backslash_lines(s: str) -> str:
    lines, out, buf = s.splitlines(), [], ""
    for line in lines:
        line_r = line.rstrip()
        if not buf:
            buf = line_r
        else:
            buf += line_r
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        out.append(buf); buf = ""
    if buf: out.append(buf)
    return "\n".join(out)

def looks_executable(cmd: str) -> bool:
    cmd = cmd.strip()
    if not cmd or cmd.startswith("#"): return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*", cmd): return False  # assignment examples
    token = cmd.split()[0]
    if token.startswith(_EXEC_WHITELIST_PREFIX): return True
    if token in _EXEC_WHITELIST_CMDS: return True
    return False

def extract_from_fences(text: str) -> List[str]:
    commands = []
    for m in _RE_FENCE.finditer(text):
        body = join_backslash_lines(m.group("body"))
        lines = body.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            h = _RE_HEREDOC_OPEN.search(line)
            if h:
                head, tag = h.group("head").rstrip(), h.group("tag")
                block = [line]; i += 1
                while i < len(lines) and not _RE_HEREDOC_TERM(tag).match(lines[i]):
                    block.append(lines[i]); i += 1
                if i < len(lines): block.append(lines[i])
                cmd = "\n".join(block).strip()
                if looks_executable(head): commands.append(cmd)
                i += 1; continue
            pm = _RE_PROMPT.match(line)
            cand = pm.group("cmd") if pm else line
            cand = cand.strip()
            if looks_executable(cand): commands.append(cand)
            i += 1
    return commands

def extract_from_free_text(text: str) -> List[str]:
    commands, lines = [], join_backslash_lines(text).splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        pm = _RE_PROMPT.match(raw)
        if pm:
            cand = pm.group("cmd")
            h = _RE_HEREDOC_OPEN.search(cand)
            if h:
                head, tag = h.group("head").rstrip(), h.group("tag")
                block = [cand]; i += 1
                while i < len(lines) and not _RE_HEREDOC_TERM(tag).match(lines[i]):
                    block.append(lines[i]); i += 1
                if i < len(lines): block.append(lines[i])
                cmd = "\n".join(block).strip()
                if looks_executable(head): commands.append(cmd)
                i += 1; continue
            if looks_executable(cand): commands.append(cand)
            i += 1; continue
        h = _RE_HEREDOC_OPEN.search(raw)
        if h:
            head, tag = h.group("head").rstrip(), h.group("tag")
            block = [raw]; i += 1
            while i < len(lines) and not _RE_HEREDOC_TERM(tag).match(lines[i]):
                block.append(lines[i]); i += 1
            if i < len(lines): block.append(lines[i])
            cmd = "\n".join(block).strip()
            if looks_executable(head): commands.append(cmd)
            i += 1; continue
        i += 1
    return commands

# --- XCCDF parsing (lxml optional, fallback to crude)
def extract_rules_from_xccdf(xccdf_path: str):
    rules = []
    try:
        from lxml import etree, html as lxml_html
        parser = etree.XMLParser(remove_blank_text=False, resolve_entities=False)
        root = etree.parse(xccdf_path, parser)
        ns = {"xccdf":"http://checklists.nist.gov/xccdf/1.2"}
        for rule in root.findall(".//xccdf:Rule", namespaces=ns):
            rid = rule.get("id") or "UNKNOWN_ID"
            title_el = rule.find("xccdf:title", namespaces=ns)
            title = (title_el.text or "").strip() if title_el is not None else "Untitled"
            sev = (rule.get("severity") or "unknown").strip()
            cmd_blocks, manual = [], False
            for check in rule.findall("xccdf:check", namespaces=ns):
                cc = check.find("xccdf:check-content", namespaces=ns)
                if cc is None: continue
                cc_text = "".join(cc.itertext(with_tail=True))
                try:
                    blob = lxml_html.fromstring(f"<div>{cc_text}</div>").text_content()
                except Exception:
                    blob = cc_text
                blob = blob.replace("\r\n","\n")
                cmds = extract_from_fences(blob)
                if not cmds: cmds = extract_from_free_text(blob)
                cmd_blocks.extend(cmds)
            if not cmd_blocks: manual = True
            rules.append({"id":rid,"title":title,"severity":sev,"commands":cmd_blocks,"manual":manual})
    except Exception as e:
        # Fallback: very simple pull of <check-content> text
        import xml.etree.ElementTree as ET
        root = ET.parse(xccdf_path).getroot()
        for rule in root.iter():
            if rule.tag.endswith("Rule"):
                rid = rule.attrib.get("id","UNKNOWN_ID")
                title = "Untitled"; sev = rule.attrib.get("severity","unknown")
                for child in rule:
                    if child.tag.endswith("title"): title = (child.text or "Untitled").strip()
                cmd_blocks, manual = [], False
                for check in rule:
                    if check.tag.endswith("check"):
                        for cc in check:
                            if cc.tag.endswith("check-content"):
                                blob = "".join(cc.itertext())
                                blob = blob.replace("\r\n","\n")
                                cmds = extract_from_fences(blob)
                                if not cmds: cmds = extract_from_free_text(blob)
                                cmd_blocks.extend(cmds)
                if not cmd_blocks: manual = True
                rules.append({"id":rid,"title":title,"severity":sev,"commands":cmd_blocks,"manual":manual})
    return rules

# --- Command runner with a real shell
def run_cmd(cmd: str, timeout: int = 12) -> Tuple[int,str,str]:
    env = os.environ.copy()
    env["ENV"] = ""; env["BASH_ENV"] = ""
    # Feed the whole block to bash -lc so heredocs work
    p = subprocess.run(
        ["/bin/bash","-lc",cmd if cmd.endswith("\n") else cmd+"\n"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout
    )
    return p.returncode, p.stdout, p.stderr

# --- Ollama AI (optional, offline)
def ai_judge(rule: Dict, rc: int, out: str, err: str) -> Dict:
    host = os.getenv("OLLAMA_HOST","http://127.0.0.1:11434")
    model = os.getenv("OLLAMA_MODEL","llama3.1")
    prompt = f"""You are a macOS compliance assistant. Analyze this STIG rule result and return strict JSON.
Fields: verdict (one of: "pass","fail","inconclusive","needs_review"), risk_note (short), tags (array of 1-4 short labels).

Rule:
ID: {rule['id']}
Title: {rule['title']}
Severity: {rule['severity']}

ExitCode: {rc}
STDOUT:
{out[:4000]}

STDERR:
{err[:2000]}
Return JSON only."""
    try:
        data = {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.1}}
        resp = subprocess.run(
            ["curl","-fsS","-H","Content-Type: application/json","-d",json.dumps(data),f"{host}/api/generate"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
        )
        j = json.loads(resp.stdout)
        txt = j.get("response","").strip()
        # Extract JSON if the model wrapped anything
        m = re.search(r"\{.*\}", txt, re.DOTALL)
        if m: txt = m.group(0)
        return json.loads(txt)
    except Exception:
        return {"verdict":"inconclusive","risk_note":"AI unavailable or non-JSON","tags":["ai-fallback"]}

# --- HTML builders
def status_class(verdict: str) -> str:
    return {"pass":"pass","fail":"fail","needs_review":"warn","inconclusive":"err"}.get(verdict,"err")

def render_report_html(title: str, meta: Dict, rows: List[Dict]) -> str:
    total = len(rows)
    pass_n = sum(1 for r in rows if r["ai"]["verdict"]=="pass")
    fail_n = sum(1 for r in rows if r["ai"]["verdict"]=="fail")
    review_n = sum(1 for r in rows if r["ai"]["verdict"]=="needs_review")
    err_n = sum(1 for r in rows if r["ai"]["verdict"]=="inconclusive")
    sev_high = sum(1 for r in rows if r["severity"].lower()=="high")
    sev_med = sum(1 for r in rows if r["severity"].lower()=="medium")
    sev_low = sum(1 for r in rows if r["severity"].lower()=="low" or r["severity"].lower()=="informational")

    counters = {
        "Rules": (total,""),
        "Pass": (pass_n,"ok"),
        "Fail": (fail_n,"err"),
        "Needs review": (review_n,"warn"),
        "Inconclusive": (err_n,""),
    }
    dash = dashboard_html(title, meta, counters)

    table_rows = []
    for r in rows:
        sev = r["severity"]
        verdict = r["ai"]["verdict"]
        note = r["ai"].get("risk_note","")
        tags = ", ".join(r["ai"].get("tags",[]))
        cmd_html = "".join(f"<pre><code>{escape_html(c)}</code></pre>" for c in r["commands"]) if r["commands"] else "<i>manual</i>"
        ev_html = ""
        for ev in r["evidence"]:
            ee = f"<details><summary><code>$ {escape_html(first_line(ev['cmd']))}</code> <span class='small'>(exit {ev['rc']})</span></summary>"
            if ev["stdout"].strip():
                ee += f"<b>stdout</b><pre>{escape_html(ev['stdout'])}</pre>"
            if ev["stderr"].strip():
                ee += f"<b>stderr</b><pre>{escape_html(ev['stderr'])}</pre>"
            ee += "</details>"
            ev_html += ee
        table_rows.append(f"""
<tr>
  <td><div><b>{escape_html(r['id'])}</b><div class="small">{escape_html(r['title'])}</div></div></td>
  <td><span class="sev">{escape_html(sev)}</span></td>
  <td><span class="status {status_class(verdict)}">{escape_html(verdict)}</span><div class="small">{escape_html(note)}{(' · '+escape_html(tags)) if tags else ''}</div></td>
  <td>{cmd_html}</td>
  <td>{ev_html}</td>
</tr>
""")

    html = []
    html.append(html_head(title))
    html.append(dash)
    html.append('<div class="panel"><table><thead><tr><th>Rule</th><th>Severity</th><th>AI Verdict</th><th>Commands</th><th>Evidence</th></tr></thead><tbody>')
    html.extend(table_rows)
    html.append("</tbody></table></div>")
    html.append(html_tail())
    return "".join(html)

def escape_html(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def first_line(s: str) -> str:
    return (s or "").splitlines()[0] if s else ""

# --- Runner
def run_rules(rules: List[Dict], ids: List[str], keyword: str, allow_unsafe: bool, timeout: int, debug: bool) -> Tuple[List[Dict], Dict]:
    selected = []
    if ids:
        want = set(ids)
        selected = [r for r in rules if r["id"] in want]
    elif keyword:
        kw = keyword.lower()
        selected = [r for r in rules if kw in r["title"].lower()]
    else:
        selected = rules

    results = []
    counts = {"executed":0,"manual":0,"errors":0}
    for r in selected:
        log(f"{r['id']} :: {r['title']}")
        ev = []
        if not r["commands"]:
            counts["manual"] += 1
        for c in r["commands"]:
            # safety: block dangerous non-whitelisted bare commands if unsafe not allowed
            head = c.strip().split()[0]
            if not allow_unsafe and not (head.startswith("/") or head in _EXEC_WHITELIST_CMDS):
                ev.append({"cmd": c, "rc": 127, "stdout": "", "stderr": "blocked by safe mode"})
                counts["errors"] += 1
                continue
            if debug:
                sys.stderr.write("\n--- EXEC ---\n" + c + "\n-----------\n")
            try:
                rc, out, err = run_cmd(c, timeout=timeout)
            except subprocess.TimeoutExpired:
                rc, out, err = 124, "", "timeout"
            counts["executed"] += 1
            ev.append({"cmd": c, "rc": rc, "stdout": out, "stderr": err})

        # AI verdict from last evidence primarily, else manual
        last = ev[-1] if ev else {"cmd":"","rc":0,"stdout":"","stderr":""}
        ai = ai_judge(r, last["rc"], last["stdout"], last["stderr"])
        results.append({"id":r["id"],"title":r["title"],"severity":r["severity"],"commands":r["commands"],"evidence":ev,"ai":ai})
    return results, counts

def discover_xccdf_files() -> List[str]:
    return sorted(glob.glob("*.xml")) + sorted(glob.glob("*.xccdf.xml"))

def interactive_select(files: List[str]) -> str:
    print("STIG Runner")
    for i,f in enumerate(files,1):
        print(f"{i}) {f}")
    print("a) Run All (first STIG)")
    sel = input("Select STIG [1..N or a]: ").strip().lower()
    if sel == "a": return files[0]
    try:
        idx = int(sel)
        return files[idx-1]
    except Exception:
        return files[0]

def main():
    ap = argparse.ArgumentParser(description="macOS STIG XCCDF runner")
    ap.add_argument("xccdf", nargs="?", help="Path to XCCDF XML (optional, else interactive)")
    ap.add_argument("--ids", help="Comma separated rule IDs to run")
    ap.add_argument("--keyword", help="Run rules whose title contains keyword")
    ap.add_argument("--allow-unsafe", action="store_true", help="Allow non-whitelisted commands")
    ap.add_argument("--timeout", type=int, default=12, help="Per-command timeout seconds")
    ap.add_argument("--stream", action="store_true", help="Print progress as it runs")
    ap.add_argument("--no-open", action="store_true", help="Do not open HTML in browser")
    ap.add_argument("--debug-commands", action="store_true", help="Print exact command blocks before execution to stderr")
    args = ap.parse_args()
    global STREAM
    STREAM = args.stream

    xccdf = args.xccdf
    if not xccdf:
        files = discover_xccdf_files()
        if not files:
            print("No XCCDF XML found in the current folder.")
            sys.exit(1)
        xccdf = interactive_select(files)

    log(f"Parsing XCCDF: {xccdf}")
    rules = extract_rules_from_xccdf(xccdf)
    log(f"Loaded rules: {len(rules)}")

    ids = [s.strip() for s in args.ids.split(",")] if args.ids else []
    results, counts = run_rules(rules, ids, args.keyword or "", args.allow_unsafe, args.timeout, args.debug_commands)

    base = os.path.splitext(os.path.basename(xccdf))[0]
    html_path = f"stig_{STAMP}.html"
    txt_path  = f"stig_{STAMP}.txt"

    # TXT
    with open(txt_path,"w",encoding="utf-8") as f:
        f.write(f"STIG Runner\nGenerated UTC {NOW.strftime('%Y-%m-%d %H:%M')}, Source {base}\n\n")
        for r in results:
            f.write(f"{r['id']} [{r['severity']}] {r['title']}\n")
            f.write(f"AI verdict: {r['ai'].get('verdict')} - {r['ai'].get('risk_note')}\n")
            for ev in r["evidence"]:
                f.write(f"$ {first_line(ev['cmd'])} (exit {ev['rc']})\n")
                if ev["stdout"].strip(): f.write(ev["stdout"]+"\n")
                if ev["stderr"].strip(): f.write(ev["stderr"]+"\n")
            f.write("\n")

    # HTML
    meta = {"Generated UTC": NOW.strftime("%Y-%m-%d %H:%M"), "Source": base}
    html = render_report_html("STIG Runner", meta, results)
    with open(html_path,"w",encoding="utf-8") as f:
        f.write(html)

    print(f"TXT report: {txt_path}")
    print(f"HTML report: {html_path}")
    if not args.no_open:
        try: webbrowser.open(f"file://{os.path.abspath(html_path)}")
        except Exception: pass

if __name__ == "__main__":
    main()
