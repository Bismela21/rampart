# RMON

**Un garde auto-hébergé pour vos serveurs web.** Il lit votre journal d'accès, piège les scanners, évalue les comportements à risque, demande un captcha d'une seconde aux visiteurs suspects au lieu de les bannir, bloque les outils d'attaque par empreinte, pose des fichiers pièges sur vos machines et vous alerte (notification, Telegram, e-mail, webhook, même un **appel téléphonique**). Fonctionne avec **Caddy** ou **nginx**, sur n'importe quel serveur Debian/Ubuntu, **sans envoyer aucune donnée** sauf ce que vous activez.

> English: [README.md](README.md)

## Ce qui le distingue

* **Zéro faux positif sur les humains, par conception.** Deux niveaux :
  * Détections *certaines* (requêtes vers `/.env`, `/.git`, `phpinfo.php`, PHP dans uploads, injection SQL, scanners...) : bannissement immédiat.
  * Détections *ambiguës* (beaucoup de 404, mots de passe ratés, score de risque élevé) : **jamais de ban**, un **défi captcha** automatique qu'un humain franchit en une seconde. Un robot qui l'ignore ou ne le résout jamais est banni.
* **Probabilité de robot** (captcha + environnement du navigateur + comportement souris/toucher + historique), modèle lisible : [`rmon/rules.py`](rmon/rules.py). Incertain : un clic de confirmation.
* **Empreinte client** : un attaquant change d'adresse, pas d'outil. Même empreinte rare derrière 3 adresses bannies et aucun visiteur normal : l'outil est bloqué.
* **Fichiers pièges** (faux mots de passe, clés AWS/SSH, dumps SQL) : l'ouverture d'un seul déclenche une alerte avec le processus exact et l'adresse SSH d'origine.
* **Alertes souples** : Telegram, ntfy, e-mail, webhook, **appel téléphonique** (Twilio, votre PBX Asterisk/SIP, ou n'importe quelle commande).
* **IA optionnelle en lecture seule** : Mistral, DeepSeek, OpenAI, Ollama local ou toute API compatible OpenAI. Elle explique, elle ne bannit rien et ne lance rien ; les IP sont masquées.
* **À vous** : nom du bot, logo, couleurs, pages FR/EN. Pas de télémétrie, pas de compte.

## Démarrage rapide

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/rmon/main/install.sh | sudo RMON_REPO=OWNER/rmon bash
sudo rmon setup          # ~8 questions courtes, tout a une valeur par défaut ou est détecté
# collez les 1-2 lignes affichées dans votre config Caddy / nginx, puis :
sudo systemctl enable --now rmon-guard rmon-challenge
sudo rmon doctor
```

Documentation : [docs/INSTALL.md](docs/INSTALL.md), [docs/CONFIG.md](docs/CONFIG.md), [docs/VOIP.md](docs/VOIP.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PRIVACY.md](docs/PRIVACY.md).

## Limites honnêtes

Un robot pilotant un vrai navigateur furtif avec un bon score et une souris réaliste peut passer ; derrière Cloudflare l'origine ne voit pas l'empreinte TLS (JA3) ; un score captcha bas arrive à de vrais utilisateurs (VPN) : ils ont un clic de confirmation, jamais une sanction. Ce n'est pas un WAF.

## Licence

[GNU AGPL-3.0](LICENSE).
