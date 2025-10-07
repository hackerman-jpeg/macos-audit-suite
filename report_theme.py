# report_theme.py
import html as htmllib, datetime
NOW = datetime.datetime.now(datetime.timezone.utc)

CSS = """
:root { --bg:#0b1220; --card:#121a2a; --muted:#9fb3c8; --text:#e6eef7; --accent:#77b2ff; --chip:#1a2438; --line:#22304a;
        --ok:#1fd186; --warn:#ffd166; --bad:#ff6b6b; }
*{box-sizing:border-box} body{font-family:-apple-system,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
.header{position:sticky;top:0;z-index:5;backdrop-filter:saturate(180%) blur(10px);background:rgba(11,18,32,.75);border-bottom:1px solid var(--line)}
.wrap{max-width:1200px;margin:0 auto;padding:16px} h1,h2,h3{margin:.6em 0} a{color:var(--accent)}
.grid{display:grid;gap:12px} .cards{grid-template-columns:repeat(4,minmax(0,1fr));margin-top:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.card h3{margin:0 0 8px 0;font-size:14px;color:var(--muted);font-weight:600;letter-spacing:.4px;text-transform:uppercase}
.big{font-size:28px;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#20304a;color:#cbd5e1;border:1px solid var(--line)}
.badge.pass{background:rgba(31,209,134,.15);color:#8cf0c1;border-color:#1a6247}
.badge.fail{background:rgba(255,107,107,.15);color:#ff9a9a;border-color:#703a3a}
.badge.err{background:rgba(255,209,102,.15);color:#ffe099;border-color:#6a5620}
.badge.manual{background:rgba(119,178,255,.15);color:#b7d4ff;border-color:#274064}
.badge.skipped{background:rgba(128,128,128,.2);color:#cbd5e1;border-color:#3b3b3b}
.badge.HIGH{background:rgba(255,107,107,.15);color:#ff9a9a;border-color:#703a3a}
.badge.MEDIUM{background:rgba(255,209,102,.15);color:#ffe099;border-color:#6a5620}
.badge.LOW{background:rgba(119,178,255,.15);color:#b7d4ff;border-color:#274064}
.badge.ai{background:rgba(119,178,255,.15);color:#b7d4ff;border-color:#274064}
hr.sep{border:0;border-top:1px solid var(--line);margin:20px 0}
.section{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin:16px 0;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.table{width:100%;border-collapse:collapse}
.table th,.table td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}
.small{color:var(--muted);font-size:12px} progress{width:100%;height:10px;accent-color:var(--accent)}
details{margin:8px 0} code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;white-space:pre-wrap;color:#dfe7f2}
.chips{display:flex;gap:6px;flex-wrap:wrap} .chip{background:var(--chip);color:#cbd5e1;padding:4px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px}
.kpi{display:flex;align-items:baseline;gap:8px}
"""

def html_head(title, source_note, model, num_ctx, unsafe, timeout=None):
    chips = [f"<span class='chip'>Model {htmllib.escape(model)}</span>",
             f"<span class='chip'>Ctx {num_ctx}</span>",
             f"<span class='chip'>Unsafe {'ON' if unsafe else 'OFF'}</span>"]
    if timeout is not None:
        chips.append(f"<span class='chip'>Timeout {timeout}s</span>")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{htmllib.escape(title)}</title>
<style>{CSS}</style></head><body>
<div class="header"><div class="wrap">
  <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
    <div>
      <div class="small">{htmllib.escape(title)}</div>
      <h2 style="margin:0">Generated UTC {NOW.strftime('%Y-%m-%d %H:%M')}</h2>
      <div class="small">{htmllib.escape(source_note)}</div>
    </div>
    <div class="chips">{''.join(chips)}</div>
  </div>
</div></div>
<div class="wrap">"""

def html_dashboard(kpi, sev_counts, ai_index):
    return f"""
<div class="grid cards">
  <div class="card"><h3>Fail</h3><div class="kpi"><div class="big">{kpi.get('fail',0)}</div><span class="badge fail">FAILED</span></div></div>
  <div class="card"><h3>Pass</h3><div class="kpi"><div class="big">{kpi.get('pass',0)}</div><span class="badge pass">PASSED</span></div></div>
  <div class="card"><h3>Error</h3><div class="kpi"><div class="big">{kpi.get('error',0)}</div><span class="badge err">ERRORS</span></div></div>
  <div class="card"><h3>Manual</h3><div class="kpi"><div class="big">{kpi.get('manual',0)}</div><span class="badge manual">REVIEW</span></div></div>
</div>
<div class="grid cards">
  <div class="card"><h3>High Severity</h3><div class="kpi"><div class="big">{sev_counts.get('high',0)}</div><span class="badge HIGH">HIGH</span></div></div>
  <div class="card"><h3>Medium Severity</h3><div class="kpi"><div class="big">{sev_counts.get('medium',0)}</div><span class="badge MEDIUM">MEDIUM</span></div></div>
  <div class="card"><h3>Low Severity</h3><div class="kpi"><div class="big">{sev_counts.get('low',0)}</div><span class="badge LOW">LOW</span></div></div>
  <div class="card"><h3>AI Risk Index</h3><div class="kpi"><div class="big">{ai_index}</div><span class="badge ai">0 low 100 high</span></div><progress value="{ai_index}" max="100"></progress></div>
</div>
<hr class="sep">"""

def html_table_open(title="Execution summary"):
    return f'<div class="section"><h2>{htmllib.escape(title)}</h2><table class="table"><tr><th>Category/Rule</th><th>Title</th><th>Severity</th><th>Command</th><th>Status</th><th>AI verdict</th></tr>'

def html_table_row(id_or_cat, title, severity, cmd_list, status, ai_verdict):
    sev_badge = {"high":"HIGH","medium":"MEDIUM","low":"LOW"}.get(severity,"LOW")
    st_badge = {"executed-pass":"pass","executed-fail":"fail","errors":"err","manual":"manual","skipped":"skipped"}.get(status,"manual")
    cmd_html = "<span class='small'>manual</span>" if not cmd_list else "<br>".join(f"<code>{htmllib.escape(c)}</code>" for c in cmd_list)
    ai_chip = f"<span class='badge ai'>{htmllib.escape(ai_verdict or '—')}</span>"
    return f"<tr><td>{htmllib.escape(id_or_cat)}</td><td>{htmllib.escape(title or '')}</td><td><span class='badge {sev_badge}'>{sev_badge}</span></td><td>{cmd_html}</td><td><span class='badge {st_badge}'>{st_badge}</span></td><td>{ai_chip}</td></tr>"

def html_table_close():
    return "</table></div>"

def html_rule_block(rule_id, title, severity, commands, rc, out, err, ai_obj):
    sev_badge = {"high":"HIGH","medium":"MEDIUM","low":"LOW"}.get(severity,"LOW")
    s = [f"<h3>{htmllib.escape(rule_id)} · <span class='badge {sev_badge}'>{sev_badge}</span></h3>",
         f"<div class='small'>{htmllib.escape(title or '')}</div>"]
    if commands:
        s.append("<details open><summary><b>Commands</b></summary>")
        for c in commands:
            s.append(f"<code>$ {htmllib.escape(c)}</code><br>")
        s.append("</details>")
    ev = f"exit {rc}\nSTDOUT:\n{out}\n\nSTDERR:\n{err}"
    s.append("<details open><summary><b>Evidence</b></summary><pre>"+htmllib.escape(ev)+"</pre></details>")
    if ai_obj:
        s.append("<details open><summary><b>AI verdict</b> "
                 f"<span class='badge ai'>{htmllib.escape(ai_obj.get('verdict',''))}</span> "
                 f"<span class='small'>confidence {htmllib.escape(ai_obj.get('confidence',''))}</span></summary>")
        s.append("<pre>"+htmllib.escape(ai_obj.get("rationale",""))+"</pre>")
        tags = ai_obj.get("tags") or []
        if tags:
            s.append("<div class='chips'>"+"".join(f"<span class='chip'>{htmllib.escape(str(t)[:80])}</span>" for t in tags[:8])+"</div>")
        s.append("</details>")
    s.append("<hr class='sep'>")
    return "".join(s)

def html_close(): return "</div></body></html>"
