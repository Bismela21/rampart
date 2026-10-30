"""Captcha providers. All use the same server-side contract (secret + response + remoteip -> JSON with `success`).
recaptcha_v3 also returns a score; turnstile and hcaptcha do not (a pass is then scored neutral and the behaviour model decides)."""
import json
import urllib.parse
import urllib.request

VERIFY = {
    "recaptcha_v3": "https://www.google.com/recaptcha/api/siteverify",
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "hcaptcha": "https://api.hcaptcha.com/siteverify",
}
SCRIPT = {
    "recaptcha_v3": "https://www.google.com/recaptcha/api.js?render={key}",
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
    "hcaptcha": "https://js.hcaptcha.com/1/api.js?render=explicit",
}
PRIVACY = {
    "recaptcha_v3": ("https://policies.google.com/privacy", "https://policies.google.com/terms"),
    "turnstile": ("https://www.cloudflare.com/privacypolicy/", "https://www.cloudflare.com/website-terms/"),
    "hcaptcha": ("https://www.hcaptcha.com/privacy", "https://www.hcaptcha.com/terms"),
}


def verify(provider, secret, token, ip, timeout=8, opener=None):
    """Returns {"ok": bool, "score": float|None, "hostname": str, "codes": [..], "action": str|None}."""
    if provider == "none":
        return {"ok": True, "score": None, "hostname": "", "codes": [], "action": None}
    data = urllib.parse.urlencode({"secret": secret, "response": token, "remoteip": ip}).encode()
    req = urllib.request.Request(VERIFY[provider], data=data)
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:
        j = json.loads(r.read())
    return {"ok": bool(j.get("success")), "score": j.get("score"), "hostname": str(j.get("hostname", "")).lower(), "codes": j.get("error-codes", []) or [], "action": j.get("action")}


def js_get_token(provider, key):
    """JavaScript defining getToken(cb): calls cb(token) once the provider is ready. For `none` the token is a constant."""
    if provider == "recaptcha_v3":
        return 'function getToken(cb){grecaptcha.ready(function(){grecaptcha.execute(K,{action:"unlock"}).then(cb).catch(function(){fail(T.unavailable)})})}'
    if provider == "turnstile":
        return ('var tsId=null;function getToken(cb){if(tsId!==null){turnstile.reset(tsId);return}var d=document.createElement("div");d.id="rmon-ts";document.querySelector("main").appendChild(d);'
                'tsId=turnstile.render(d,{sitekey:K,appearance:"interaction-only",callback:cb,"error-callback":function(){fail(T.unavailable)}})}')
    if provider == "hcaptcha":
        return ('var hcId=null;function getToken(cb){if(hcId===null){var d=document.createElement("div");d.id="rmon-hc";document.querySelector("main").appendChild(d);'
                'hcId=hcaptcha.render(d,{sitekey:K,size:"invisible",callback:cb,"error-callback":function(){fail(T.unavailable)}})}hcaptcha.execute(hcId)}')
    return "function getToken(cb){cb('none')}"
