"""
Interface locale de deploiement d'agents de surveillance
------------------------------------------------------------------------------
Version avec plage d'adresses IP et correspondance automatique login/mdp.
Les credentials sont lus depuis machines.json — plus de saisie manuelle.

FICHIER machines.json (meme dossier) :
    [
      {"ip": "172.31.4.101", "login": "admin", "motdepasse": "...", "os": "windows"},
      ...
    ]

UTILISATION :
    python deploiement_ui.py
    Puis ouvrir http://localhost:5050

SAISIE IP acceptee :
    - IP unique      : 172.31.4.103
    - Plage          : 172.31.4.101-110   (de .101 a .110)
    - CIDR (optionnel si besoin futur)
"""

import ipaddress
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, request

from deploiement_distant import deployer_linux, deployer_windows, AGENT_LOCAL_DEFAUT

# --- Configuration ---
URL_INGEST_DEFAUT = "https://surveillance-dash-tls-farah-boubaker-dev.apps.rm2.thpm.p1.openshiftapps.com/api/ingest"
CLE_API_DEFAUT    = "cle-demo-a-changer"
FICHIER_MACHINES  = Path(__file__).parent / "machines.json"
FICHIER_LOG       = Path(__file__).parent / "deploiement.log"

# --- Logger fichier ---
logging.basicConfig(
    filename=str(FICHIER_LOG),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    encoding="utf-8",
)
logger = logging.getLogger("deploiement")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def charger_machines() -> dict:
    """Charge machines.json et retourne un dict { ip -> {login, motdepasse, os} }."""
    if not FICHIER_MACHINES.exists():
        return {}
    with open(FICHIER_MACHINES, encoding="utf-8") as f:
        liste = json.load(f)
    return {m["ip"]: m for m in liste}


def parser_plage(saisie: str) -> list[str]:
    """
    Accepte :
      - IP unique        : "172.31.4.103"
      - Plage tiret      : "172.31.4.101-110"  ou  "172.31.4.101-172.31.4.110"
      - CIDR             : "172.31.4.0/28"
    Retourne une liste d'IPs sous forme de strings.
    """
    saisie = saisie.strip()

    # Plage avec tiret  ex: 172.31.4.101-110  ou  172.31.4.101-172.31.4.110
    if "-" in saisie:
        gauche, droite = saisie.split("-", 1)
        gauche = gauche.strip()
        droite = droite.strip()
        # Si droite est juste un suffixe numérique (ex: "110")
        if "." not in droite:
            prefix = ".".join(gauche.split(".")[:-1])
            debut  = int(gauche.split(".")[-1])
            fin    = int(droite)
            return [f"{prefix}.{i}" for i in range(debut, fin + 1)]
        # Sinon deux IPs complètes
        debut = int(ipaddress.ip_address(gauche))
        fin   = int(ipaddress.ip_address(droite))
        return [str(ipaddress.ip_address(i)) for i in range(debut, fin + 1)]

    # CIDR  ex: 172.31.4.0/28
    if "/" in saisie:
        reseau = ipaddress.ip_network(saisie, strict=False)
        return [str(ip) for ip in reseau.hosts()]

    # IP unique
    ipaddress.ip_address(saisie)  # lève ValueError si invalide
    return [saisie]


def log_resultat(nom, ip, os_cible, succes, message, simulation=True):
    mode = "[SIMULATION]" if simulation else "[REEL]"
    statut = "SUCCES" if succes else "ECHEC"
    logger.info(f"{mode} {statut} | nom={nom!r} ip={ip} os={os_cible} | {message}")


# ---------------------------------------------------------------------------
# Template HTML
# ---------------------------------------------------------------------------

PAGE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Déploiement — Plage IP</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg:#0B0F14;--panel:#131A22;--panel2:#1B232D;--border:#232D38;
    --text:#E6EDF3;--muted:#8B98A5;--accent:#4C6EF5;--accent-h:#3D5CE0;
    --ok:#37B24D;--err:#F03E3E;--warn:#F59F00;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
    display:flex;justify-content:center;padding:40px 16px}
  .carte{background:var(--panel);border:1px solid var(--border);
    border-radius:12px;padding:32px;max-width:640px;width:100%}
  h1{font-size:20px;margin:0 0 4px}
  .sous-titre{color:var(--muted);font-size:13px;margin:0 0 24px}
  label{display:block;font-size:13px;color:var(--muted);margin:16px 0 6px}
  input{width:100%;background:var(--panel2);border:1px solid var(--border);
    color:var(--text);padding:10px 12px;border-radius:8px;font-size:14px}
  input:focus{outline:none;border-color:var(--accent)}
  .aide{font-size:12px;color:var(--muted);margin-top:4px}
  button{width:100%;background:var(--accent);color:#fff;border:none;
    padding:12px;border-radius:8px;font-size:14px;font-weight:600;
    cursor:pointer;margin-top:24px}
  button:hover{background:var(--accent-h)}
  button:disabled{opacity:.6;cursor:wait}
  #chargement{display:none;text-align:center;color:var(--muted);
    font-size:13px;margin-top:16px}

  /* Table résultats */
  .table-wrap{margin-top:24px;overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:var(--panel2);color:var(--muted);padding:8px 12px;
    text-align:left;border-bottom:1px solid var(--border)}
  td{padding:8px 12px;border-bottom:1px solid var(--border)}
  .badge{display:inline-block;padding:2px 8px;border-radius:20px;
    font-size:11px;font-weight:600}
  .badge.ok{background:rgba(55,178,77,.15);color:#6FD98A}
  .badge.err{background:rgba(240,62,62,.15);color:#FF8787}
  .badge.skip{background:rgba(255,159,0,.15);color:#FFD580}

  /* Résumé */
  .resume{margin-top:16px;padding:12px 16px;border-radius:8px;
    font-size:13px;background:var(--panel2);border:1px solid var(--border)}
  .resume b{color:var(--text)}
</style>
</head>
<body>
<div class="carte">
  <h1>Déployer des agents sur une plage IP</h1>
  <p class="sous-titre">
    Les identifiants sont lus automatiquement depuis <code>machines.json</code>.
  </p>

  <form method="post" id="form-deploy">
    <label>Plage d'adresses IP</label>
    <input type="text" name="plage" required
      placeholder="172.31.4.101-110  ou  172.31.4.103  ou  172.31.4.0/28"
      value="{{ request.form.get('plage', '') }}">
    <p class="aide">
      IP unique, plage avec tiret (172.31.4.101-110) ou bloc CIDR (172.31.4.0/28).
    </p>

    <label>Nom de préfixe (facultatif)</label>
    <input type="text" name="prefixe" placeholder="PC-Agence"
      value="{{ request.form.get('prefixe', '') }}">
    <p class="aide">Chaque machine sera nommée "Préfixe-IP" dans le dashboard.</p>

    <label>
      <input type="checkbox" name="simulation" style="width:auto"
        {% if request.form.get('simulation', '1') == '1' %}checked{% endif %}>
      &nbsp;Mode simulation (log uniquement, pas de vraie connexion)
    </label>

    <button type="submit" id="btn">Lancer le déploiement</button>
  </form>

  <div id="chargement">⏳ Déploiement en cours...</div>

  {% if resultats %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>IP</th><th>OS</th><th>Login</th><th>Statut</th><th>Message</th>
        </tr>
      </thead>
      <tbody>
      {% for r in resultats %}
        <tr>
          <td>{{ r.ip }}</td>
          <td>{{ r.os }}</td>
          <td>{{ r.login }}</td>
          <td>
            {% if r.statut == 'succes' %}
              <span class="badge ok">✅ Succès</span>
            {% elif r.statut == 'echec' %}
              <span class="badge err">❌ Échec</span>
            {% else %}
              <span class="badge skip">⚠ Inconnu</span>
            {% endif %}
          </td>
          <td>{{ r.message }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="resume">
    <b>{{ nb_succes }}</b> succès &nbsp;·&nbsp;
    <b>{{ nb_echec }}</b> échec(s) &nbsp;·&nbsp;
    <b>{{ nb_skip }}</b> non trouvé(s) dans machines.json
    &nbsp;·&nbsp; Résultats sauvegardés dans <code>deploiement.log</code>
  </div>
  {% endif %}
</div>

<script>
document.getElementById('form-deploy').addEventListener('submit',function(){
  document.getElementById('btn').disabled=true;
  document.getElementById('btn').innerText='Déploiement en cours...';
  document.getElementById('chargement').style.display='block';
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Route principale
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def formulaire():
    resultats  = None
    nb_succes  = nb_echec = nb_skip = 0

    if request.method == "POST":
        plage_saisie = request.form.get("plage", "").strip()
        prefixe      = request.form.get("prefixe", "").strip() or "Machine"
        simulation   = request.form.get("simulation") == "1"

        machines = charger_machines()
        resultats = []

        # Parser la plage
        try:
            ips = parser_plage(plage_saisie)
        except ValueError as e:
            resultats = [{"ip": plage_saisie, "os": "-", "login": "-",
                          "statut": "echec",
                          "message": f"Plage IP invalide : {e}"}]
            nb_echec = 1
            return render_template_string(PAGE, resultats=resultats,
                nb_succes=0, nb_echec=1, nb_skip=0, request=request)

        logger.info(f"--- Début déploiement {'(SIMULATION)' if simulation else '(RÉEL)'} "
                    f"| plage={plage_saisie!r} | {len(ips)} IP(s) ---")

        for ip in ips:
            machine = machines.get(ip)

            if machine is None:
                # IP pas dans machines.json
                msg = "Non trouvé dans machines.json — ignoré."
                resultats.append({"ip": ip, "os": "-", "login": "-",
                                   "statut": "skip", "message": msg})
                log_resultat("-", ip, "-", False, msg, simulation)
                nb_skip += 1
                continue

            login     = machine["login"]
            motdepasse = machine["motdepasse"]
            os_cible  = machine["os"]
            nom       = f"{prefixe}-{ip}" if prefixe else ip

            if simulation:
                # --- MODE SIMULATION ---
                msg = f"Simulation OK — aurait déployé avec login={login!r} os={os_cible}"
                resultats.append({"ip": ip, "os": os_cible, "login": login,
                                   "statut": "succes", "message": msg})
                log_resultat(nom, ip, os_cible, True, msg, simulation=True)
                nb_succes += 1
            else:
                # --- MODE RÉEL ---
                debut = time.time()
                try:
                    if os_cible == "linux":
                        deployer_linux(ip, login, motdepasse, AGENT_LOCAL_DEFAUT,
                                       nom, URL_INGEST_DEFAUT, CLE_API_DEFAUT)
                    else:
                        deployer_windows(ip, login, motdepasse, AGENT_LOCAL_DEFAUT,
                                         nom, URL_INGEST_DEFAUT, CLE_API_DEFAUT)
                    duree = time.time() - debut
                    msg = f"Installé et démarré en {duree:.0f}s."
                    resultats.append({"ip": ip, "os": os_cible, "login": login,
                                       "statut": "succes", "message": msg})
                    log_resultat(nom, ip, os_cible, True, msg, simulation=False)
                    nb_succes += 1
                except Exception as e:
                    msg = str(e)[:120]
                    resultats.append({"ip": ip, "os": os_cible, "login": login,
                                       "statut": "echec", "message": msg})
                    log_resultat(nom, ip, os_cible, False, msg, simulation=False)
                    nb_echec += 1

        logger.info(f"--- Fin | succes={nb_succes} echec={nb_echec} skip={nb_skip} ---\n")

    return render_template_string(PAGE, resultats=resultats,
                                  nb_succes=nb_succes, nb_echec=nb_echec,
                                  nb_skip=nb_skip, request=request)


if __name__ == "__main__":
    print("=== Déploiement par plage IP ===")
    print(f"Machines chargées depuis : {FICHIER_MACHINES}")
    print(f"Logs écrits dans         : {FICHIER_LOG}")
    print("Ouvre http://localhost:5050 dans ton navigateur.")
    app.run(host="127.0.0.1", port=5050, debug=False)