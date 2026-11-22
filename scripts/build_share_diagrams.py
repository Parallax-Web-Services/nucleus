"""Rebuild the shareable Nucleus Alpha 0.2 diagrams.

Requires ReportLab. On Windows, Segoe UI is embedded into the PDF; override
NUCLEUS_FONT_DIR to use another directory containing segoeui.ttf/seguisb.ttf.
SVGs retain editable text, with system font fallbacks. No live fleet data is read.
"""
from pathlib import Path
import html
import math
import os
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "diagrams" / "alpha-0.2"
PDF = ROOT / "output" / "pdf" / "nucleus-alpha-0.2-diagrams.pdf"
W, H = 1600, 900
C = dict(paper="#FCFDFC", ink="#142E30", muted="#536A6B", faint="#819293",
         line="#DCE6E3", card="#FFFFFF", soft="#F3F7F5", green="#168565",
         pale="#EAF5EF", blue="#54758E", bluepale="#EEF3F8", white="#FFFFFF")
fonts = Path(os.environ.get("NUCLEUS_FONT_DIR", "C:/Windows/Fonts"))
pdfmetrics.registerFont(TTFont("Nucleus", str(fonts / "segoeui.ttf")))
pdfmetrics.registerFont(TTFont("NucleusBold", str(fonts / "seguisb.ttf")))

class Scene:
    def __init__(self, title, description):
        self.title, self.description, self.ops = title, description, []
    def rect(self, x,y,w,h, fill="card", stroke=None, r=0, sw=1):
        self.ops.append(("rect",x,y,w,h,C.get(fill,fill),C.get(stroke,stroke),r,sw))
    def line(self,x1,y1,x2,y2,color="line",sw=2,dash=None):
        self.ops.append(("line",x1,y1,x2,y2,C.get(color,color),sw,dash))
    def circle(self,x,y,r,fill="green",stroke=None,sw=1):
        self.ops.append(("circle",x,y,r,C.get(fill,fill),C.get(stroke,stroke),sw))
    def polygon(self,points,fill="green"):
        self.ops.append(("polygon",points,C.get(fill,fill)))
    def path(self,commands,color="green",sw=2.5,dash=None):
        self.ops.append(("path",commands,C.get(color,color),sw,dash))
    def text(self,x,y,t,size=20,weight="normal",color="ink",anchor="start",maxw=None):
        name = "NucleusBold" if weight == "bold" else "Nucleus"
        width=pdfmetrics.stringWidth(t,name,size)
        if maxw is not None and width>maxw:
            raise ValueError(f"Text overflow: {t!r}: {width:.1f} > {maxw}")
        self.ops.append(("text",x,y,t,size,weight,C.get(color,color),anchor))
    def arrow(self,x1,y1,x2,y2,color="green",sw=2.5,both=False):
        self.line(x1,y1,x2,y2,color,sw)
        self.head(x2,y2,math.atan2(y2-y1,x2-x1),color)
        if both: self.head(x1,y1,math.atan2(y1-y2,x1-x2),color)
    def head(self,x,y,a,color="green",length=11):
        pts=[(x,y),(x-length*math.cos(a)+5*math.sin(a),y-length*math.sin(a)-5*math.cos(a)),
             (x-length*math.cos(a)-5*math.sin(a),y-length*math.sin(a)+5*math.cos(a))]
        self.polygon(pts,color)
    def curve_arrow(self,x1,y1,c1x,c1y,c2x,c2y,x2,y2,both=True):
        self.path([("M",x1,y1),("C",c1x,c1y,c2x,c2y,x2,y2)],sw=2.6)
        self.head(x2,y2,math.atan2(y2-c2y,x2-c2x))
        if both: self.head(x1,y1,math.atan2(y1-c1y,x1-c1x))
    def svg(self):
        q=html.escape
        parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900" role="img" aria-labelledby="title desc">',
               f'<title id="title">{q(self.title)}</title><desc id="desc">{q(self.description)}</desc>']
        for op in self.ops:
            k,*a=op
            if k=="rect":
                x,y,w,h,fill,stroke,r,sw=a
                parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill or "none"}" stroke="{stroke or "none"}" stroke-width="{sw}"/>')
            elif k=="line":
                x1,y1,x2,y2,color,sw,dash=a
                d=f' stroke-dasharray="{dash}"' if dash else ""
                parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}" stroke-linecap="round"{d}/>')
            elif k=="circle":
                x,y,r,fill,stroke,sw=a
                parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill or "none"}" stroke="{stroke or "none"}" stroke-width="{sw}"/>')
            elif k=="polygon":
                pts,fill=a
                parts.append(f'<polygon points="{" ".join(f"{x},{y}" for x,y in pts)}" fill="{fill}"/>')
            elif k=="path":
                commands,color,sw,dash=a
                d=" ".join(" ".join(str(x) for x in c) for c in commands)
                da=f' stroke-dasharray="{dash}"' if dash else ""
                parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round"{da}/>')
            elif k=="text":
                x,y,t,size,weight,color,anchor=a
                parts.append(f'<text x="{x}" y="{y}" fill="{color}" font-family="Segoe UI, Arial, sans-serif" font-size="{size}" font-weight="{"600" if weight=="bold" else "400"}" text-anchor="{anchor}">{q(t)}</text>')
        return "\n".join(parts+["</svg>"])+"\n"
    def draw_pdf(self, c):
        for op in self.ops:
            k,*a=op
            if k=="rect":
                x,y,w,h,fill,stroke,r,sw=a
                if fill: c.setFillColor(HexColor(fill))
                if stroke: c.setStrokeColor(HexColor(stroke))
                c.setLineWidth(sw)
                c.roundRect(x,H-y-h,w,h,r,stroke=int(bool(stroke)),fill=int(bool(fill)))
            elif k=="circle":
                x,y,r,fill,stroke,sw=a
                if fill: c.setFillColor(HexColor(fill))
                if stroke: c.setStrokeColor(HexColor(stroke))
                c.setLineWidth(sw); c.circle(x,H-y,r,stroke=int(bool(stroke)),fill=int(bool(fill)))
            elif k=="polygon":
                pts,fill=a
                c.setFillColor(HexColor(fill)); p=c.beginPath()
                p.moveTo(pts[0][0],H-pts[0][1])
                for x,y in pts[1:]: p.lineTo(x,H-y)
                p.close(); c.drawPath(p,fill=1,stroke=0)
            elif k in ("line","path"):
                if k=="line":
                    x1,y1,x2,y2,color,sw,dash=a
                    commands=[("M",x1,y1),("L",x2,y2)]
                else: commands,color,sw,dash=a
                c.setStrokeColor(HexColor(color)); c.setLineWidth(sw); c.setLineCap(1); c.setLineJoin(1)
                c.setDash([float(d) for d in dash.split()] if dash else [])
                p=c.beginPath()
                for cmd in commands:
                    if cmd[0]=="M": p.moveTo(cmd[1],H-cmd[2])
                    elif cmd[0]=="L": p.lineTo(cmd[1],H-cmd[2])
                    elif cmd[0]=="C": p.curveTo(cmd[1],H-cmd[2],cmd[3],H-cmd[4],cmd[5],H-cmd[6])
                    elif cmd[0]=="Q": raise ValueError("Use cubic paths")
                c.drawPath(p,fill=0,stroke=1); c.setDash([])
            elif k=="text":
                x,y,t,size,weight,color,anchor=a
                c.setFillColor(HexColor(color))
                c.setFont("NucleusBold" if weight=="bold" else "Nucleus",size)
                if anchor=="middle": c.drawCentredString(x,H-y,t)
                elif anchor=="end": c.drawRightString(x,H-y,t)
                else: c.drawString(x,H-y,t)

def base(title,subtitle,index,kind):
    s=Scene(title,subtitle)
    s.rect(0,0,W,H,"paper")
    s.text(72,73,"nucleus",28,"bold")
    s.circle(174,69,4)
    s.text(1528,69,"ALPHA 0.2  /  "+kind,15,"bold","muted","end")
    s.text(72,145,title,51,"bold")
    s.text(72,189,subtitle,24,color="muted")
    s.line(72,214,1528,214)
    s.line(72,808,1528,808)
    s.text(72,847,"IDENTITY, MEMBERSHIP & TELEMETRY",15,"bold","muted")
    s.text(72,877,"Implemented prototype  /  November 01, 2026",15,color="muted")
    s.text(1528,859,f"0{index} / 03",17,"bold","muted","end")
    return s

def device(s,x,y,kind="node"):
    s.rect(x,y,44,44,"pale",r=12)
    if kind=="browser":
        s.rect(x+10,y+11,24,21,None,"green",r=3,sw=1.7)
        s.line(x+10,y+17,x+34,y+17,"green",1.5)
        s.circle(x+14,y+14,1,"green")
    else:
        s.rect(x+10,y+10,24,18,None,"green",r=3,sw=1.7)
        s.line(x+22,y+29,x+22,y+34,"green",1.7)
        s.line(x+15,y+34,x+29,y+34,"green",1.7)

def member(s,y,title,detail):
    s.rect(72,y,416,100,"card","line",16)
    device(s,92,y+28)
    s.text(153,y+43,title,25,"bold",maxw=310)
    s.text(153,y+73,detail,18,color="muted",maxw=315)

def topology():
    s=base("One trusted fabric.","A shared view of your machines.",1,"LOGICAL TOPOLOGY")
    member(s,242,"OMEGA","WSL / local member")
    member(s,382,"Alpha","alpha.wphyperdrive.com")
    member(s,510,"Iota","iota.parallaxws.com")
    member(s,638,"Tarragon","tarragon.app")
    # Browser access is local to a member, separate from fabric authentication.
    s.arrow(503,276,749,276,"blue",2.2,True)
    s.text(626,260,"Local read-only API",16,"bold","blue","middle")
    s.text(626,308,"Browser bearer token",16,color="muted",anchor="middle")
    s.rect(764,242,764,120,"bluepale",r=16)
    device(s,790,268,"browser")
    s.text(855,286,"Local browser view / OMEGA",25,"bold")
    s.text(855,321,"The map reads its own node's loopback API.",20,color="muted")
    # The member initiates telemetry; the authoritative fabric view returns.
    ends=[(324,473),(432,535),(560,597),(688,659)]
    for y1,y2 in ends:
        s.curve_arrow(503,y1,606,y1,645,y2,749,y2)
    s.rect(764,423,764,315,"card","line",20)
    s.text(764,400,"MUTUAL TLS 1.3  /  TELEMETRY + FABRIC VIEW",16,"bold","green")
    s.rect(790,447,148,28,"pale",r=8)
    s.text(864,467,"FABRIC OWNER",13,"bold","green","middle")
    s.text(790,512,"Slipstream",35,"bold")
    s.text(1498,510,"slipstream.host",20,color="muted",anchor="end")
    s.line(790,535,1502,535)
    s.text(790,575,"Membership authority",23,"bold")
    s.text(790,609,"Fabric CA + approved nodes",19,color="muted")
    s.text(790,640,"Separate CA and node keys",18,color="muted")
    s.line(1142,560,1142,656)
    s.text(1170,575,"Positronic",23,"bold")
    s.text(1170,609,"Heartbeats + shared view",19,color="muted")
    s.text(1170,640,"Includes owner inventory",18,color="muted")
    s.rect(790,684,712,34,"soft",r=8)
    s.text(1146,707,"One Nucleus runtime on this host",17,"bold","muted","middle")
    s.text(72,780,"One runtime per node. The fabric shares membership, health and resource inventory.",20,color="muted")
    return s


def transport():
    s=base("Private reachability.","End-to-end node identity.",2,"PROTOTYPE TRANSPORT")
    # Only the end nodes terminate the Nucleus TLS session.
    s.path([("M",274,346),("L",274,300),("C",274,282,280,276,298,276),
            ("L",1302,276),("C",1320,276,1326,282,1326,300),("L",1326,346)],sw=3)
    s.circle(274,346,5); s.circle(1326,346,5)
    s.rect(533,249,534,52,"pale",r=26)
    s.text(800,282,"END-TO-END NUCLEUS mTLS 1.3",19,"bold","green","middle")
    s.text(800,328,"The forwarding bridge does not terminate this session.",18,color="muted",anchor="middle")
    cards=[(72,"Remote members","Alpha / Iota / Tarragon","Nucleus member","Loopback tunnel endpoint"),
           (598,"OMEGA","Local forwarding bridge","OpenSSH client","Loopback forwarding path"),
           (1124,"Slipstream","Fabric owner","Nucleus owner","Loopback coordinator + API")]
    for x,title,sub,a,b in cards:
        s.rect(x,365,404,316,"card","line",18)
        device(s,x+26,390)
        s.text(x+26,475,title,29,"bold",maxw=352)
        s.text(x+26,507,sub,20,color="muted",maxw=352)
        s.rect(x+26,543,352,109,"soft",r=12)
        s.text(x+46,578,a,22,"bold",maxw=315)
        s.text(x+46,613,b,18,color="muted",maxw=315)
    s.arrow(488,590,586,590,sw=2.7)
    s.text(537,556,"SSH -R",18,"bold","green","middle")
    s.arrow(1014,590,1112,590,sw=2.7)
    s.text(1063,556,"SSH -L",18,"bold","green","middle")
    s.text(72,733,"OMEGA initiates both SSH connections.",21,"bold")
    s.text(72,766,"Arrows show telemetry traffic; the fabric view returns over the same path.",20,color="muted")
    s.rect(1130,713,398,66,"pale",r=12)
    s.text(1329,753,"No public Nucleus listener.",20,"bold","green","middle")
    return s

def pill(s,x,y,w,t,color="green"):
    fill="pale" if color=="green" else "soft"
    s.rect(x,y,w,37,fill,r=10)
    s.text(x+w/2,y+25,t,17,"bold",color,"middle",maxw=w-20)

def pairing():
    s=base("Explicit pairing.","Verified at both ends.",3,"SECURE ENROLLMENT")
    for x,title,detail in [
        (72,"Slipstream / fabric owner","Node key + separate fabric CA key"),
        (1114,"Joining node","Own persistent identity key")]:
        s.rect(x,242,414,96,"card","line",16)
        s.text(x+26,281,title,25,"bold",maxw=362)
        s.text(x+26,313,detail,18,color="muted",maxw=362)
    s.line(279,340,279,755,"line",2,"5 8")
    s.line(1321,340,1321,755,"line",2,"5 8")
    s.text(800,269,"TRUSTED OUT-OF-BAND EXCHANGE",15,"bold","muted","middle")
    s.text(800,302,"Signed documents travel through an existing trusted channel.",17,color="muted",anchor="middle")
    # Accepting documents and accepting membership are explicit local actions.
    s.text(800,381,"01   Signed invitation",23,"bold",anchor="middle")
    s.arrow(279,401,1321,401,sw=2.5)
    s.text(800,430,"Pinned authority + expiring, one-use secret",18,color="muted",anchor="middle")
    pill(s,1183,423,276,"Accept invitation")
    s.text(800,493,"02   Signed certificate request",23,"bold",anchor="middle")
    s.arrow(1321,513,279,513,sw=2.5)
    s.text(800,542,"Joining node proves possession of its key",18,color="muted",anchor="middle")
    pill(s,141,535,276,"Owner inspects + approves")
    s.text(800,605,"03   Signed grant + membership certificate",23,"bold",anchor="middle")
    s.arrow(279,625,1321,625,sw=2.5)
    s.text(800,654,"Bound to the pending request and joining node",18,color="muted",anchor="middle")
    pill(s,1167,647,308,"Verify + accept membership")
    s.rect(279,706,1042,49,"pale",r=13)
    s.text(800,738,"04   Mutual TLS telemetry begins",23,"bold","green","middle")
    s.text(800,784,"Private keys stay on their originating nodes. Certificates establish membership.",19,color="muted",anchor="middle")
    return s

NAMES=["01-logical-topology","02-private-transport","03-secure-pairing"]
DESCRIPTIONS=[
    "Four members (OMEGA, Alpha, Iota, and Tarragon) use mutual TLS 1.3 with the Slipstream fabric owner. The owner's single runtime contains membership authority, local inventory, and Positronic's aggregated telemetry. A browser on OMEGA reads only OMEGA's loopback API with a separate browser token.",
    "Alpha, Iota, and Tarragon reach Slipstream using a reverse SSH forward into OMEGA, then a local SSH forward to Slipstream's loopback coordinator. OMEGA initiates both SSH connections. Nucleus mutual TLS remains end-to-end between member and owner, and no public Nucleus listener is exposed.",
    "The owner sends a signed expiring one-use invitation. The joining node accepts it and returns a signed certificate request. The owner inspects and approves, then issues a signed grant and membership certificate. The joining node verifies and accepts membership before mutual TLS telemetry begins. Private keys remain on their originating machines."
]

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    PDF.parent.mkdir(parents=True,exist_ok=True)
    scenes=[topology(),transport(),pairing()]
    c=canvas.Canvas(str(PDF),pagesize=(960,540),pageCompression=1)
    c.setTitle("Nucleus Alpha 0.2 | Architecture diagrams")
    c.setAuthor("Nucleus")
    c.setSubject("Implemented prototype: logical topology, SSH transport, and secure pairing")
    for scene,name,desc in zip(scenes,NAMES,DESCRIPTIONS):
        scene.description=desc
        (OUT/(name+".svg")).write_text(scene.svg(),encoding="utf-8")
        c.saveState(); c.scale(.6,.6); scene.draw_pdf(c); c.restoreState(); c.showPage()
    c.save()
    notes="""# Nucleus Alpha 0.2 - shareable diagrams

Three matching 16:9 diagrams of the implemented prototype, documented on November 1, 2026.

## Files
- SVG: editable vector artwork with accessible titles and descriptions.
- PNG: 3200 x 1800 pixels for chat, documents and slides.
- PDF: three vector pages, one diagram per page.
- build_share_diagrams.py: reproducible source for all vector artwork.

SVG text uses Segoe UI with Arial and sans-serif fallbacks. The PDF embeds its fonts.
All artwork is self-contained; no private keys, bearer tokens, or live status links are included.

## Use
1. Logical topology: introduce the fabric and the roles of Nucleus and Positronic.
2. Private transport: explain the prototype's SSH forwarding path and end-to-end mTLS.
3. Secure pairing: explain explicit authorization and the signed document exchange.

These are architecture diagrams, not a live health report. Alpha 0.2 provides identity,
membership, and resource telemetry. Resource inventory is not scheduled or pooled compute.

## Architecture references
Repository: docs/ARCHITECTURE.md and docs/PROTOCOL.md.
Transport verification: docs/validation/fleet-rollout.json.
This set illustrates the recorded prototype and does not query the running fleet.

## Alt text
"""
    for i,desc in enumerate(DESCRIPTIONS,1):
        notes+=f"\n{i}. {desc}\n"
    (OUT/"README.md").write_text(notes,encoding="utf-8")
    print(f"Created 3 SVGs and {PDF}")
if __name__=="__main__":
    main()
