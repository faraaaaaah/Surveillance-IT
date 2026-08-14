"""
Interface locale de deploiement d'agents de surveillance
------------------------------------------------------------------------------
Petite application web A LANCER SUR LE PC DE L'ADMIN (pas sur le dashboard
OpenShift - voir explication ci-dessous), qui permet d'ajouter une machine a
surveiller via un formulaire, plutot qu'en ligne de commande.

POURQUOI CET OUTIL TOURNE EN LOCAL ET PAS SUR LE DASHBOARD CLOUD :
    Le dashboard est heberge sur OpenShift (cloud), qui n'a pas de route
    reseau vers le reseau local de l'entreprise (192.168.x.x) sans VPN.
    Cet outil doit donc tourner sur un PC qui, lui, est deja sur ce reseau
    local - typiquement le PC de l'admin. Le resultat visuel et l'usage
    sont les memes qu'un bouton "Ajouter un serveur" sur le dashboard :
    un formulaire, un clic, et c'est fait.

INSTALLATION :
    pip install flask paramiko pywinrm

UTILISATION :
    python deploiement_ui.py
    Puis ouvrir http://localhost:5050 dans le navigateur.

CONFIGURATION :
    Modifie URL_INGEST_DEFAUT et CLE_API_DEFAUT ci-dessous une fois pour
    toutes (evite de les retaper a chaque machine ajoutee) - l'admin peut
    quand meme les modifier depuis le formulaire si besoin.
"""

import os
import time

from flask import Flask, render_template_string, request

from deploiement_distant import deployer_linux, deployer_windows, AGENT_LOCAL_DEFAUT

# --- A adapter une fois pour toutes ---
URL_INGEST_DEFAUT = "https://surveillance-dash-tls-farah-boubaker-dev.apps.rm2.thpm.p1.openshiftapps.com/api/ingest"
CLE_API_DEFAUT = "cle-demo-a-changer"

app = Flask(__name__)

PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Ajouter un serveur — Déploiement agent</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0B0F14;
    --panel: #131A22;
    --panel2: #1B232D;
    --border: #232D38;
    --text: #E6EDF3;
    --muted: #8B98A5;
    --accent: #4C6EF5;
    --accent-hover: #3D5CE0;
    --ok: #37B24D;
    --err: #F03E3E;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    display: flex;
    justify-content: center;
    padding: 48px 16px;
  }
  .carte {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px;
    max-width: 480px;
    width: 100%;
  }
  h1 {
    font-size: 20px;
    margin: 0 0 4px;
  }
  .sous-titre {
    color: var(--muted);
    font-size: 13px;
    margin: 0 0 24px;
  }
  label {
    display: block;
    font-size: 13px;
    color: var(--muted);
    margin: 16px 0 6px;
  }
  input, select {
    width: 100%;
    background: var(--panel2);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 14px;
  }
  input:focus, select:focus {
    outline: none;
    border-color: var(--accent);
  }
  .os-choix {
    display: flex;
    gap: 8px;
    margin-top: 6px;
  }
  .os-choix label {
    flex: 1;
    margin: 0;
    text-align: center;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    cursor: pointer;
    background: var(--panel2);
    font-size: 13px;
    color: var(--text);
  }
  .os-choix input { display: none; width: auto; }
  .os-choix input:checked + span {
    color: var(--accent);
    font-weight: 600;
  }
  .os-choix label:has(input:checked) {
    border-color: var(--accent);
    background: rgba(76, 110, 245, 0.1);
  }
  button {
    width: 100%;
    background: var(--accent);
    color: white;
    border: none;
    padding: 12px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 24px;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: 0.6; cursor: wait; }
  .resultat {
    margin-top: 20px;
    padding: 14px 16px;
    border-radius: 8px;
    font-size: 13px;
    white-space: pre-wrap;
    line-height: 1.5;
  }
  .resultat.ok { background: rgba(55, 178, 77, 0.12); border: 1px solid var(--ok); color: #6FD98A; }
  .resultat.err { background: rgba(240, 62, 62, 0.12); border: 1px solid var(--err); color: #FF8787; }
  .aide { font-size: 12px; color: var(--muted); margin-top: 4px; }
  #chargement { display: none; text-align: center; color: var(--muted); font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<div class="carte">
  <h1>Ajouter un serveur à surveiller</h1>
  <p class="sous-titre">Installe et démarre automatiquement l'agent sur la machine cible.</p>

  <form method="post" id="form-deploiement">
    <label>Nom affiché dans le dashboard</label>
    <input type="text" name="nom" placeholder="PC-Comptabilité" required value="{{ request.form.get('nom', '') }}">

    <label>Adresse IP de la machine</label>
    <input type="text" name="ip" placeholder="192.168.1.42" required value="{{ request.form.get('ip', '') }}">

    <label>Système d'exploitation</label>
    <div class="os-choix">
      <label>
        <input type="radio" name="os" value="windows" {% if request.form.get('os', 'windows') == 'windows' %}checked{% endif %}>
        <span>🪟 Windows</span>
      </label>
      <label>
        <input type="radio" name="os" value="linux" {% if request.form.get('os') == 'linux' %}checked{% endif %}>
        <span>🐧 Linux</span>
      </label>
    </div>

    <label>Identifiant admin (sur la machine cible)</label>
    <input type="text" name="login" placeholder="Nom d'utilisateur" required value="{{ request.form.get('login', '') }}">

    <label>Mot de passe</label>
    <input type="password" name="motdepasse" placeholder="Mot de passe" required>
    <p class="aide">Jamais enregistré, utilisé uniquement pour cette installation.</p>

    <button type="submit" id="btn-submit">Ajouter et déployer</button>
  </form>

  <div id="chargement">⏳ Déploiement en cours (peut prendre jusqu'à 30s)...</div>

  {% if resultat %}
  <div class="resultat {{ 'ok' if succes else 'err' }}">{{ resultat }}</div>
  {% endif %}
</div>

<script>
document.getElementById('form-deploiement').addEventListener('submit', function() {
  document.getElementById('btn-submit').disabled = true;
  document.getElementById('btn-submit').innerText = 'Déploiement en cours...';
  document.getElementById('chargement').style.display = 'block';
});
</script>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def formulaire():
    resultat = None
    succes = False

    if request.method == "POST":
        nom = request.form.get("nom", "").strip()
        ip = request.form.get("ip", "").strip()
        os_cible = request.form.get("os", "windows")
        login = request.form.get("login", "").strip()
        mot_de_passe = request.form.get("motdepasse", "")

        debut = time.time()
        try:
            if os_cible == "linux":
                deployer_linux(ip, login, mot_de_passe, AGENT_LOCAL_DEFAUT, nom, URL_INGEST_DEFAUT, CLE_API_DEFAUT)
            else:
                deployer_windows(ip, login, mot_de_passe, AGENT_LOCAL_DEFAUT, nom, URL_INGEST_DEFAUT, CLE_API_DEFAUT)
            duree = time.time() - debut
            resultat = (
                f"✅ '{nom}' installé et démarré avec succès sur {ip} (en {duree:.0f}s).\n"
                f"Vérifiez dans le dashboard dans quelques instants."
            )
            succes = True
        except RuntimeError as e:
            resultat = f"❌ Échec du déploiement :\n{e}"
            succes = False
        except Exception as e:
            resultat = f"❌ Erreur inattendue :\n{e}"
            succes = False

    return render_template_string(PAGE, resultat=resultat, succes=succes, request=request)


if __name__ == "__main__":
    print("=== Interface de déploiement d'agents ===")
    print("Ouvre http://localhost:5050 dans ton navigateur.")
    app.run(host="127.0.0.1", port=5050, debug=False)