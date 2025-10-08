# report_theme.py
# Minimal shared CSS and helpers for HTML reports

THEME_CSS = """
:root{
  --bg:#0b0f16; --panel:#121826; --muted:#9fb3c8; --text:#e6edf3; --ok:#2ecc71; --warn:#f1c40f; --err:#ff6b6b;
  --link:#7aa2ff; --hi:#20304a; --chip:#1b2435; --border:#22304a;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--link);text-decoration:none}
.container{max-width:1080px;margin:24px auto;padding:0 16px}
.header{display:flex;align-items:center;gap:12px;margin:16px 0 12px}
h1{font-size:24px;margin:0}
.small{color:var(--muted);font-size:12px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.card{background:var(--chip);border:1px solid var(--border);border-radius:12px;padding:12px;text-align:center}
.k{display:block;color:var(--muted);font-size:12px}
.v{display:block;font-size:20px;margin-top:2px}
.k.ok{color:var(--ok)} .k.warn{color:var(--warn)} .k.err{color:var(--err)}
table{width:100%;border-collapse:collapse;margin-top:6px}
th,td{padding:10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);text-align:left}
.status{padding:3px 8px;border-radius:999px;font-size:12px;background:var(--chip);border:1px solid var(--border)}
.status.pass{color:var(--ok);border-color:#234} .status.fail{color:var(--err)} .status.err{color:#ff9d76}
.sev{padding:2px 6px;border-radius:999px;font-size:11px;border:1px solid var(--border);background:#182236;color:#cfe1ff}
pre,code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
pre{background:#0d1422;border:1px solid var(--border);border-radius:10px;padding:10px;overflow:auto}
details{border:1px solid var(--border);border-radius:10px;padding:8px;background:#0e1524}
summary{cursor:pointer;color:#cfe1ff}
kbd{background:#111827;border:1px solid #374151;border-bottom-width:2px;border-radius:6px;padding:1px 6px;font-size:12px}
hr{border:0;border-top:1px solid var(--border);margin:18px 0}
.footer{color:var(--muted);font-size:12px;margin:18px 0}
"""

def dashboard_html(title, meta, counters):
    # meta: dict; counters: dict of label -> value
    cards = []
    for label, (val, cls) in counters.items():
        cards.append(f'<div class="card"><span class="k {cls}">{label}</span><span class="v">{val}</span></div>')
    meta_rows = " · ".join(f"<span class='small'>{k}: <b>{v}</b></span>" for k,v in meta.items())
    return f"""
<div class="header"><h1>{title}</h1><span class="small">{meta_rows}</span></div>
<div class="panel">
  <div class="grid">{''.join(cards)}</div>
</div>
"""

def html_head(doc_title):
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{doc_title}</title><style>{THEME_CSS}</style></head><body><div class="container">"""

def html_tail():
    return "</div><div class='container footer'>Generated locally. No network calls.</div></body></html>"
