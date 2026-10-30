"""HTML pages served for blocked / challenged visitors. Branding (name, logo, accent colour, language) comes from the config: nothing is hard-coded.
Telemetry (counters of trusted input events + mouse-trajectory measures, never coordinates) is collected on these two pages only,
i.e. for addresses that are already suspicious."""
import base64
import html
import json
import mimetypes
import os

from . import providers

TEXT = {
    "en": {
        "ban_badge": "Automatic protection", "ban_title": "Access temporarily blocked",
        "ban_text": "Our automatic system detected suspicious activity from your address, so access is blocked for a while.",
        "ban_fix": "Blocked by mistake?", "ban_btn": "I am human: unblock me",
        "ch_badge": "Security check", "ch_title": "One moment, we are checking your connection",
        "ch_text": "This check is automatic and takes about a second. You will be redirected afterwards.",
        "wait": "Checking...", "ok": "Verified. Reloading...", "retry": "Try again", "confirm": "I confirm I am human", "net": "Network error.",
        "unavailable": "Verification unavailable, please retry.", "pending": "Still waiting, please retry in a moment.", "legal_p": "Privacy", "legal_t": "Terms", "protected": "Protected by",
    },
    "fr": {
        "ban_badge": "Protection automatique", "ban_title": "Accès temporairement bloqué",
        "ban_text": "Notre système automatique a détecté une activité suspecte depuis votre adresse : l'accès est bloqué pour un moment.",
        "ban_fix": "Bloqué à tort ?", "ban_btn": "Je suis humain : me débloquer",
        "ch_badge": "Vérification de sécurité", "ch_title": "Un instant, nous vérifions votre connexion",
        "ch_text": "Cette vérification est automatique et dure environ une seconde. Vous serez redirigé ensuite.",
        "wait": "Vérification...", "ok": "Vérifié. Rechargement...", "retry": "Réessayer", "confirm": "Je confirme que je suis humain", "net": "Erreur réseau.",
        "unavailable": "Vérification indisponible, réessayez.", "pending": "Toujours en attente, réessayez dans un instant.", "legal_p": "Confidentialité", "legal_t": "Conditions", "protected": "Protégé par",
    },
}

SHIELD = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13z" fill="{c}"/>'
          '<text x="32" y="41" font-family="system-ui,sans-serif" font-size="26" font-weight="700" text-anchor="middle" fill="#fff">{l}</text></svg>')

# Collected on the challenge page only. Numbers and flags, no coordinates, no content.
TELEMETRY_JS = r"""
var T0=performance.now(),E={mc:0,tc:0,kc:0,sc:0,ut:0,clk:0,pts:[]};
function tr(c,e){if(!e.isTrusted){E.ut++;return false}if(E[c]<100000)E[c]++;return true}
addEventListener("mousemove",function(e){if(tr("mc",e)&&E.pts.length<200)E.pts.push([e.clientX,e.clientY,e.timeStamp])},{passive:true});
addEventListener("touchstart",function(e){tr("tc",e)},{passive:true});addEventListener("touchmove",function(e){tr("tc",e)},{passive:true});
addEventListener("keydown",function(e){tr("kc",e)});addEventListener("scroll",function(e){tr("sc",e)},{passive:true});addEventListener("click",function(e){tr("clk",e)});
function feats(){var f={mc:E.mc,tc:E.tc,kc:E.kc,sc:E.sc,ut:E.ut,clk:E.clk,dt:Math.round(performance.now()-T0)},ua=navigator.userAgent||"";
f.wd=navigator.webdriver?1:0;
f.hl=(/HeadlessChrome/.test(ua)||(/Chrome\//.test(ua)&&!window.chrome&&!/; wv\)/.test(ua))||(navigator.languages&&!navigator.languages.length)||(!screen.width||!screen.height))?1:0;
try{var c=document.createElement("canvas"),g=c.getContext("webgl")||c.getContext("experimental-webgl"),x=g&&g.getExtension("WEBGL_debug_renderer_info"),r=x?g.getParameter(x.UNMASKED_RENDERER_WEBGL):"";f.sw=/swiftshader|llvmpipe|software|offscreen/i.test(r)?1:0}catch(z){f.sw=0}
var p=E.pts;f.mmn=p.length;
if(p.length>=8){var L=0,s=[],i,dx,dy,ds;for(i=1;i<p.length;i++){dx=p[i][0]-p[i-1][0];dy=p[i][1]-p[i-1][1];ds=Math.sqrt(dx*dx+dy*dy);L+=ds;s.push(ds/Math.max(p[i][2]-p[i-1][2],1))}
var net=Math.sqrt(Math.pow(p[p.length-1][0]-p[0][0],2)+Math.pow(p[p.length-1][1]-p[0][1],2));f.mms=L>0?Math.min(net/L,1):1;
var m=s.reduce(function(a,v){return a+v},0)/s.length,sd=Math.sqrt(s.reduce(function(a,v){return a+(v-m)*(v-m)},0)/s.length);f.mmv=m>0?sd/m:0}
return f}
"""

FLOW_JS = r"""
var d=document,$=function(i){return d.getElementById(i)},msg=$("rcm"),b=$("rcb"),b2=$("rcb2"),sp=$("sp"),step=1,loaded=false;
function say(t){msg.textContent=t}
function busy(on){if(sp)sp.style.display=on?"block":"none";if(b&&!AUTO)b.disabled=on}
function fail(t){say(t);busy(false);if(b)b.style.display="inline-block"}
function send(tok){fetch("/__rmon/unlock",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:tok,f:feats(),step:step})})
.then(function(r){return r.json()}).then(function(j){
if(j.ok){busy(false);say(T.ok);setTimeout(function(){location.reload()},800)}
else if(j.step2&&step===1){busy(false);say(j.msg);if(b2)b2.style.display="inline-block"}
else fail(j.msg||T.unavailable)}).catch(function(){fail(T.net)})}
function ensure(cb){if(SRC===""){cb();return}if(loaded){cb();return}loaded=true;var s=d.createElement("script");s.src=SRC;s.async=true;s.onload=cb;s.onerror=function(){loaded=false;fail(T.unavailable)};d.head.appendChild(s)}
function start(){busy(true);say(T.wait);if(b)b.style.display="none";ensure(function(){getToken(send)})}
if(b2)b2.onclick=function(){step=2;b2.style.display="none";start()};
if(b)b.onclick=start;
if(AUTO){setTimeout(start,Math.max(0,900-(performance.now()-T0)))}
"""


def logo_data_uri(cfg):
    p = cfg["branding"].get("logo") or ""
    if p and os.path.isfile(p) and os.path.getsize(p) < 2_000_000:
        mt = mimetypes.guess_type(p)[0] or "image/png"
        with open(p, "rb") as f:
            return "data:%s;base64,%s" % (mt, base64.b64encode(f.read()).decode())
    svg = SHIELD.format(c=html.escape(cfg["branding"].get("accent", "#c2294a")), l=html.escape((cfg["branding"].get("bot_name") or "R")[:1].upper()))
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


def render(kind, cfg, site_key):
    """kind: 'ban' (button, stricter) or 'challenge' (runs by itself)."""
    t = TEXT.get(cfg["branding"].get("lang", "en"), TEXT["en"])
    prov = cfg["challenge"].get("provider", "none")
    auto = kind == "challenge"
    accent = html.escape(cfg["branding"].get("accent", "#c2294a"))
    key = json.dumps(site_key or "")
    src = providers.SCRIPT.get(prov, "").replace("{key}", site_key or "") if prov in providers.SCRIPT else ""
    legal = ""
    if prov in providers.PRIVACY:
        pr, te = providers.PRIVACY[prov]
        legal = '<p><small>%s %s &middot; <a href="%s" rel="noopener">%s</a> &middot; <a href="%s" rel="noopener">%s</a></small></p>' % (
            t["protected"], prov.replace("_v3", "").replace("hcaptcha", "hCaptcha").title(), pr, t["legal_p"], te, t["legal_t"])
    body = ('<span class="badge">%(badge)s</span><h1>%(title)s</h1><p>%(text)s</p><div class="spin" id="sp" style="display:%(spin)s"></div><p id="rcm"></p>' % {
        "badge": t["ch_badge" if auto else "ban_badge"], "title": t["ch_title" if auto else "ban_title"], "text": t["ch_text" if auto else "ban_text"], "spin": "block" if auto else "none"})
    if not auto:
        body += '<p><small>%s</small></p><button id="rcb" type="button" class="btn">%s</button>' % (t["ban_fix"], t["ban_btn"])
    else:
        body += '<button id="rcb" type="button" class="btn" style="display:none">%s</button>' % t["retry"]
    body += '<button id="rcb2" type="button" class="btn" style="display:none">%s</button>' % t["confirm"]
    js = "(function(){var K=%s,AUTO=%s,SRC=%s,T=%s;%s%s%s})();" % (key, "true" if auto else "false", json.dumps(src), json.dumps(t),
                                                                  TELEMETRY_JS, providers.js_get_token(prov, site_key), FLOW_JS)
    name = html.escape(cfg["branding"].get("bot_name") or "RMON")
    return f"""<!doctype html><html lang="{html.escape(cfg['branding'].get('lang', 'en'))}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{html.escape(t['ch_badge' if auto else 'ban_badge'])} - {name}</title><style>
:root{{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--tx:#151a21;--mut:#5a6573;--ac:{accent};--bd:#e2e5ea}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0e1217;--card:#161b22;--tx:#eef1f5;--mut:#9aa6b5;--bd:#262d37}}}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--tx);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:24px}}
.card{{max-width:560px;width:100%;background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:32px 26px;text-align:center;box-shadow:0 12px 34px rgba(0,0,0,.08)}}
.logo{{display:block;margin:0 auto 18px;max-width:220px;max-height:90px;width:auto;height:auto}}.badge{{display:inline-block;color:var(--ac);border:1px solid var(--ac);font-weight:600;font-size:13px;padding:3px 12px;border-radius:999px;margin-bottom:14px}}
h1{{font-size:24px;line-height:1.25;margin:0 0 12px}}p{{margin:0 0 12px;color:var(--mut)}}small{{color:var(--mut);font-size:12.5px}}
.btn{{margin-top:6px;background:var(--ac);color:#fff;border:0;border-radius:10px;padding:11px 20px;font:600 15px system-ui;cursor:pointer}}.btn[disabled]{{opacity:.6;cursor:wait}}
.spin{{width:32px;height:32px;border:4px solid var(--bd);border-top-color:var(--ac);border-radius:50%;margin:16px auto 6px;animation:s 1s linear infinite}}@keyframes s{{to{{transform:rotate(360deg)}}}}#rcm{{font-size:14px;min-height:20px}}
</style></head><body><main class="card"><img class="logo" alt="{name}" src="{logo_data_uri(cfg)}">{body}{legal}</main><script>{js}</script></body></html>"""
