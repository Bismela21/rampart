"""Optional AI helper (any OpenAI-compatible API: Mistral, DeepSeek, OpenAI, a local Ollama, ...). READ-ONLY by design:
the model only writes a short explanation of an incident; it can never ban, unban, run a command or touch a file.
IP addresses are masked before anything is sent unless ai.send_ips is true."""
import json
import re
import urllib.request

SYSTEM = {
    "en": "You are a security assistant for a web server. Explain the incident in at most 3 short sentences for a non-expert, say whether it looks serious, and what to check. Never invent facts.",
    "fr": "Tu es un assistant de sécurité pour un serveur web. Explique l'incident en 3 phrases courtes maximum pour un non-expert, dis si cela paraît grave et quoi vérifier. N'invente rien.",
}


def mask_ips(text):
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", text)
    return re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", "<ip>", text)


def ask(cfg, secrets, question, context="", opener=None, timeout=30):
    """Returns the model's answer, or "" when the AI is off or fails (callers must always work without it)."""
    ai = cfg.get("ai", {})
    if ai.get("provider", "none") == "none" or not ai.get("base_url") or not ai.get("model"):
        return ""
    prompt = "%s\n\n%s" % (question, context)
    if not ai.get("send_ips"):
        prompt = mask_ips(prompt)
    body = json.dumps({"model": ai["model"], "temperature": 0.2, "max_tokens": 300,
                       "messages": [{"role": "system", "content": SYSTEM.get(cfg["branding"].get("lang", "en"), SYSTEM["en"])}, {"role": "user", "content": prompt[:6000]}]}).encode()
    headers = {"Content-Type": "application/json"}
    if secrets.get("ai_key"):
        headers["Authorization"] = "Bearer " + secrets["ai_key"]
    try:
        with (opener or urllib.request.urlopen)(urllib.request.Request(ai["base_url"].rstrip("/") + "/chat/completions", data=body, headers=headers), timeout=timeout) as r:
            return str(json.loads(r.read())["choices"][0]["message"]["content"]).strip()[:1200]
    except Exception:
        return ""
