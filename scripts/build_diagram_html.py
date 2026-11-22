"""Create the standalone, offline dark HTML edition of the Nucleus diagrams."""
from pathlib import Path
import html
import build_share_diagrams as art

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/diagrams/alpha-0.2"
DARK = OUT / "dark"
DARK.mkdir(parents=True, exist_ok=True)
art.C.update(paper="#0C1317", ink="#E8F2EF", muted="#AEC2BF", faint="#829A96",
             line="#30454A", card="#131F24", soft="#1B2B30", green="#62DDB3",
             pale="#16392F", blue="#9CCBF0", bluepale="#182F40", white="#E8F2EF")
scenes = [art.topology(), art.transport(), art.pairing()]
titles = ["Fabric topology", "Private transport", "Secure pairing"]
ids = ["fabric", "transport", "pairing"]
mobile = [
"""
<div class="mobile-heading"><span class="eyebrow">Logical topology</span><h1>One trusted fabric.</h1><p>A shared view of your machines.</p></div>
<div class="node browser"><span class="node-role">LOCAL BROWSER VIEW / OMEGA</span><strong>Resource map</strong><p>Reads OMEGA's loopback API using a separate browser bearer token.</p></div>
<div class="connector local">Local read-only API<span aria-hidden="true">↕</span></div>
<div class="members">
  <div class="node"><strong>OMEGA</strong><p>WSL / local member</p></div>
  <div class="node"><strong>Alpha</strong><p>alpha.wphyperdrive.com</p></div>
  <div class="node"><strong>Iota</strong><p>iota.parallaxws.com</p></div>
  <div class="node"><strong>Tarragon</strong><p>tarragon.app</p></div>
</div>
<div class="connector">Mutual TLS 1.3<span aria-hidden="true">↕</span><small>Telemetry + fabric view</small></div>
<div class="node owner"><span class="node-role">FABRIC OWNER</span><strong>Slipstream</strong><p>slipstream.host</p><hr><h2>Membership authority</h2><p>Fabric CA + approved nodes. Separate CA and node keys.</p><h2>Positronic</h2><p>Heartbeats + shared view, including the owner's inventory.</p><div class="note">One Nucleus runtime on this host</div></div>
<p class="scope">One runtime per node. The fabric shares membership, health and resource inventory.</p>
""",
"""
<div class="mobile-heading"><span class="eyebrow">Prototype transport</span><h1>Private reachability.</h1><p>End-to-end node identity.</p></div>
<div class="note secure">End-to-end Nucleus mTLS 1.3<br><small>Remote member ↔ Slipstream</small></div>
<div class="node"><span class="node-role">REMOTE MEMBERS</span><strong>Alpha / Iota / Tarragon</strong><h2>Nucleus member</h2><p>Loopback tunnel endpoint</p></div>
<div class="connector">SSH -R<span aria-hidden="true">↓</span></div>
<div class="node"><strong>OMEGA</strong><p>Local forwarding bridge</p><h2>OpenSSH client</h2><p>Forwards the inner TLS session without terminating it.</p></div>
<div class="connector">SSH -L<span aria-hidden="true">↓</span></div>
<div class="node owner"><span class="node-role">FABRIC OWNER</span><strong>Slipstream</strong><h2>Nucleus owner</h2><p>Loopback coordinator + API</p></div>
<p class="scope"><strong>OMEGA initiates both SSH connections.</strong><br>Arrows show telemetry traffic; the fabric view returns over the same path.</p>
<div class="note secure">No public Nucleus listener.</div>
""",
"""
<div class="mobile-heading"><span class="eyebrow">Secure enrollment</span><h1>Explicit pairing.</h1><p>Verified at both ends.</p></div>
<div class="participants"><div class="node"><span class="node-role">OWNER</span><strong>Slipstream</strong><p>Node key + separate fabric CA key</p></div><div class="node"><span class="node-role">JOINING NODE</span><strong>New member</strong><p>Own persistent identity key</p></div></div>
<p class="scope">Signed documents travel through an existing trusted out-of-band channel.</p>
<ol class="steps">
<li><span class="step-num">01</span><div><span class="direction">Owner → joining node</span><h2>Signed invitation</h2><p>Pinned authority + expiring, one-use secret.</p><div class="note">Joining node accepts invitation</div></div></li>
<li><span class="step-num">02</span><div><span class="direction">Joining node → owner</span><h2>Signed certificate request</h2><p>Proves possession of the joining node's key.</p><div class="note">Owner inspects + approves</div></div></li>
<li><span class="step-num">03</span><div><span class="direction">Owner → joining node</span><h2>Signed grant + membership certificate</h2><p>Bound to the pending request and joining node.</p><div class="note">Joining node verifies + accepts membership</div></div></li>
<li><span class="step-num">04</span><div><h2>Mutual TLS telemetry begins</h2><p>Both endpoints prove their identity.</p></div></li>
</ol>
<p class="scope">Private keys stay on their originating nodes. Certificates establish membership.</p>
"""
]
panels = []
for i,(scene,name,title,pid,desc) in enumerate(zip(scenes, art.NAMES, titles, ids, art.DESCRIPTIONS)):
    scene.description = desc
    svg = scene.svg()
    (DARK/(name+".svg")).write_text(svg, encoding="utf-8")
    svg = svg.replace('id="title"',f'id="{pid}-title"').replace('id="desc"',f'id="{pid}-desc"')
    svg = svg.replace('aria-labelledby="title desc"',f'aria-labelledby="{pid}-title {pid}-desc"')
    panels.append(f'<section class="diagram-panel" id="{pid}" role="tabpanel" aria-labelledby="tab-{pid}" data-filename="{name}-dark.svg">\n'
                  f'<div class="desktop-diagram">{svg}</div>\n'
                  f'<div class="mobile-diagram">{mobile[i]}<footer>ALPHA 0.2 / IMPLEMENTED PROTOTYPE<br>November 01, 2026</footer></div>\n</section>')

template = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="description" content="Nucleus Alpha 0.2: fabric topology, private transport and secure pairing. Standalone dark architecture diagrams.">
<title>Nucleus - Architecture diagrams</title>
<style>
:root { color-scheme: dark; --bg:#0C1317; --card:#131F24; --soft:#1B2B30; --fg:#E8F2EF; --muted:#AEC2BF; --line:#30454A; --accent:#62DDB3; --pale:#16392F; --blue:#9CCBF0; --blue-bg:#182F40; }
* { box-sizing:border-box; }
html { background:var(--bg); }
body { margin:0; color:var(--fg); background:var(--bg); font:16px/1.5 "Segoe UI",Arial,sans-serif; }
button { font:inherit; color:inherit; cursor:pointer; }
button:focus-visible,a:focus-visible { outline:2px solid var(--accent); outline-offset:4px; }
.page { max-width:1664px; margin:0 auto; padding:24px 32px 32px; }
.toolbar { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:20px; padding:0 0 20px; border-bottom:1px solid var(--line); }
.tabs { display:flex; gap:6px; flex-wrap:wrap; }
.tab,.action { background:transparent; border:1px solid transparent; border-radius:9px; padding:10px 16px; }
.tab { color:var(--muted); display:flex; align-items:center; gap:10px; }
.tab .ordinal { font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums; }
.tab[aria-selected="true"] { background:var(--soft); color:var(--fg); border-color:var(--line); }
.tab[aria-selected="true"] .ordinal { color:var(--accent); }
.tab:hover,.action:hover { background:var(--soft); }
.actions { display:flex; gap:8px; }
.action { border-color:var(--line); padding:9px 14px; font-size:14px; }
.action.primary { color:var(--accent); border-color:var(--pale); background:var(--pale); }
.diagram-panel { scroll-margin-top:20px; }
.desktop-diagram>svg { display:block; width:100%; height:auto; }
.mobile-diagram { display:none; }
.page-footer { margin-top:12px; color:var(--muted); font-size:13px; text-align:center; }
.print-only { display:none; }
@media (max-width:1100px) {
 .page { padding:16px 18px 24px; }
 .toolbar { gap:12px; padding-bottom:16px; }
 .tabs { width:100%; gap:4px; }
 .tab { flex:1; justify-content:center; padding:10px 9px; gap:7px; font-size:14px; }
 .actions { width:100%; justify-content:flex-end; }
 .action { min-height:44px; }
 .desktop-diagram { display:none; }
 .mobile-diagram { display:block; padding-top:30px; max-width:680px; margin:0 auto; }
 .mobile-heading { margin-bottom:28px; }
 .eyebrow { color:var(--accent); font-size:12px; text-transform:uppercase; letter-spacing:.1em; }
 h1 { font-size:clamp(30px,7.7vw,42px); line-height:1.14; letter-spacing:-.035em; margin:10px 0 12px; }
 p { margin:8px 0 0; color:var(--muted); overflow-wrap:anywhere; }
 h2 { font-size:17px; margin:18px 0 0; line-height:1.35; }
 .node { padding:20px; border-radius:14px; border:1px solid var(--line); background:var(--card); }
 .node>strong { display:block; font-size:23px; line-height:1.3; overflow-wrap:anywhere; }
 .node-role { display:block; margin:0 0 9px; color:var(--accent); font-size:11px; font-weight:600; letter-spacing:.07em; }
 .browser { background:var(--blue-bg); border-color:transparent; }
 .browser .node-role { color:var(--blue); }
 .members { display:grid; gap:10px; grid-template-columns:minmax(0,1fr); }
 .members .node { padding:16px; }
 .members .node>strong { font-size:20px; }
 .members p { font-size:13px; }
 .connector { display:flex; flex-direction:column; align-items:center; gap:3px; color:var(--accent); font-size:14px; padding:15px 0; text-align:center; }
 .connector span { font-size:25px; line-height:1; }
 .connector small { color:var(--muted); font-size:12px; }
 .connector.local { color:var(--blue); }
 hr { border:0; border-top:1px solid var(--line); margin:18px 0; }
 .note { margin-top:16px; border-radius:9px; background:var(--pale); color:var(--accent); padding:12px 14px; font-size:14px; line-height:1.5; }
 .secure { text-align:center; margin:0 0 18px; }
 .scope { margin:20px 0; font-size:14px; line-height:1.6; }
 .scope strong { color:var(--fg); font-weight:600; }
 .participants { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
 .participants .node { padding:16px; }
 .participants strong { font-size:20px; }
 .participants p { font-size:13px; }
 .steps { list-style:none; margin:24px 0; padding:0; }
 .steps li { display:grid; grid-template-columns:34px minmax(0,1fr); gap:14px; padding:0 0 28px; }
 .steps li:last-child { padding-bottom:0; }
 .step-num { color:var(--accent); font-size:13px; padding-top:3px; border-right:1px solid var(--line); }
 .steps h2 { margin:6px 0 0; font-size:19px; }
 .steps p { font-size:14px; }
 .steps .note { margin-top:12px; }
 .direction { font-size:12px; color:var(--muted); }
 .mobile-diagram footer { padding:24px 0 8px; border-top:1px solid var(--line); color:var(--muted); font-size:11px; letter-spacing:.04em; line-height:1.8; }
 .page-footer { text-align:left; font-size:12px; }
}
@media print {
 @page { size: 16in 9in; margin:0; }
 html,body { margin:0!important; background:var(--bg)!important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
 .page { max-width:none; width:16in; padding:0; }
 .toolbar,.page-footer,.mobile-diagram { display:none!important; }
 .diagram-panel,.diagram-panel[hidden] { display:block!important; width:16in; height:9in; break-after:page; page-break-after:always; }
 .diagram-panel:last-of-type { break-after:auto; page-break-after:auto; }
 .desktop-diagram { display:block!important; }
 .desktop-diagram>svg { width:16in!important; height:9in!important; }
}
@media (prefers-reduced-motion:reduce) { * { scroll-behavior:auto!important; } }
html.js .diagram-panel[hidden] { display:none; }
</style>
</head>
<body>
<div class="page">
<header class="toolbar">
<nav class="tabs" role="tablist" aria-label="Architecture diagrams">
<button class="tab" type="button" id="tab-fabric" role="tab" aria-controls="fabric" aria-selected="true"><span class="ordinal">01</span>Fabric</button>
<button class="tab" type="button" id="tab-transport" role="tab" aria-controls="transport" aria-selected="false"><span class="ordinal">02</span>Transport</button>
<button class="tab" type="button" id="tab-pairing" role="tab" aria-controls="pairing" aria-selected="false"><span class="ordinal">03</span>Pairing</button>
</nav>
<div class="actions">
<button class="action primary" id="download" type="button">Download SVG</button>
<button class="action" id="print" type="button">Print all</button>
</div>
</header>
<main>
@@PANELS@@
</main>
<div class="page-footer">Nucleus Alpha 0.2 / Architecture collection</div>
<noscript><style>.toolbar{display:none}</style><p>All three diagrams are shown below.</p></noscript>
</div>
<script>
(() => {
 'use strict';
 document.documentElement.classList.add('js');
 const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
 const panels = Array.from(document.querySelectorAll('[role="tabpanel"]'));
 let active = 0;
 function select(index, focus) {
   active = index;
   tabs.forEach((tab,i) => {
     tab.setAttribute('aria-selected',String(i===index));
     tab.tabIndex = i===index ? 0 : -1;
     panels[i].hidden = i!==index;
   });
   if (focus) tabs[index].focus();
   history.replaceState(null,'','#'+panels[index].id);
 }
 tabs.forEach((tab,i) => {
   tab.addEventListener('click',()=>select(i,false));
   tab.addEventListener('keydown',e=>{
     let next;
     if(e.key==='ArrowRight') next=(i+1)%tabs.length;
     else if(e.key==='ArrowLeft') next=(i+tabs.length-1)%tabs.length;
     else if(e.key==='Home') next=0;
     else if(e.key==='End') next=tabs.length-1;
     else return;
     e.preventDefault(); select(next,true);
   });
 });
 const chosen = panels.findIndex(p=>'#'+p.id===location.hash);
 select(chosen<0 ? 0 : chosen,false);
 window.addEventListener('hashchange',()=>{
   const i=panels.findIndex(p=>'#'+p.id===location.hash);
   if(i>=0) select(i,false);
 });
 document.getElementById('download').addEventListener('click',()=>{
   const panel=panels[active];
   const clone=panel.querySelector('svg').cloneNode(true);
   const data='<?xml version="1.0" encoding="utf-8"?>\n'+new XMLSerializer().serializeToString(clone);
   const url=URL.createObjectURL(new Blob([data],{type:'image/svg+xml;charset=utf-8'}));
   const link=document.createElement('a');
   link.href=url; link.download=panel.dataset.filename;
   document.body.append(link); link.click(); link.remove();
   window.setTimeout(()=>URL.revokeObjectURL(url),30000);
 });
 document.getElementById('print').addEventListener('click',()=>window.print());
})();
</script>
</body>
</html>
"""
output = OUT / "nucleus-diagrams-dark.html"
output.write_text(template.replace("@@PANELS@@", "\n".join(panels)), encoding="utf-8")
print(output)
