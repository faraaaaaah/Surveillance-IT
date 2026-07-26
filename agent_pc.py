"""
Agent PC - a installer sur chaque PC/serveur (Windows ou Linux) a surveiller.
------------------------------------------------------------------------------
Lit les metriques LOCALES de la machine sur laquelle ce script tourne
(CPU, memoire, disque, reseau, batterie) et les envoie regulierement au
dashboard central via /api/ingest.

C'est le meme principe que monitoring_core.lire_metriques(), mais en
version autonome et legere : pas besoin du modele IA (modele.pkl) ni de
pandas ici, seulement psutil + requests. La detection d'anomalies (seuils)
est faite ICI, sur l'agent, car /api/ingest attend une liste d'anomalies
deja calculee.

Installation sur la machine a surveiller :
    pip install psutil requests

Utilisation :
    python agent_pc.py --nom "PC-Reception" --url http://surveillance-dash-farah-boubaker-dev.apps.rm2.thpm.p1.openshiftapps.com/api/ingest --cle cle-demo-a-changer

Options :
    --nom          Nom affiche dans le dashboard (ex: "PC-Comptabilite", "Serveur-Fichiers")
    --url          URL COMPLETE du endpoint /api/ingest de ton dashboard OpenShift
    --cle          La cle API (doit etre IDENTIQUE a DASHBOARD_API_KEY cote dashboard)
    --intervalle   Frequence d'envoi en secondes (defaut : 5)

Pour lancer l'agent au demarrage de Windows en continu, voir le fichier
.bat fourni (lancer_agent.bat) : double-clic ou raccourci dans le dossier
demarrage de Windows.
"""

import argparse
import time
from datetime import datetime

import psutil
import requests

# --- Seuils (identiques a monitoring_core.py, dupliques ici pour que
# l'agent soit autonome et n'ait pas besoin d'importer le reste du projet) ---
SEUILS = {
    "cpu": 85, "memoire": 85, "disque": 90,
    "paquets_perdus": 30, "nb_processus": 400, "batterie": 15,
}
SEUILS_WARNING = {"cpu": 70, "memoire": 70, "disque": 80, "batterie": 25}

_prev_net = psutil.net_io_counters()
_prev_disk = psutil.disk_io_counters()


def lire_metriques():
    """Lit les metriques de CETTE machine (celle qui execute l'agent)."""
    global _prev_net, _prev_disk

    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disque = psutil.disk_usage("/")
    disk_io = psutil.disk_io_counters()
    net = psutil.net_io_counters()

    # Pas de batterie -> None (pas une fausse valeur a 100%, voir discussion
    # precedente sur ce meme probleme dans monitoring_core.py)
    batterie_brute = psutil.sensors_battery()
    batterie_disponible = batterie_brute is not None

    dl = round((net.bytes_recv - _prev_net.bytes_recv) / 1024 / 1024, 3)
    ul = round((net.bytes_sent - _prev_net.bytes_sent) / 1024 / 1024, 3)
    dr = round((disk_io.read_bytes - _prev_disk.read_bytes) / 1024 / 1024, 3) if disk_io and _prev_disk else 0
    dw = round((disk_io.write_bytes - _prev_disk.write_bytes) / 1024 / 1024, 3) if disk_io and _prev_disk else 0
    paquets_perdus = max(0, (net.dropin + net.dropout) - (_prev_net.dropin + _prev_net.dropout))

    _prev_net = net
    _prev_disk = disk_io

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "cpu": cpu,
        "memoire": mem.percent,
        "memoire_gb": round(mem.used / (1024 ** 3), 2),
        "disque_pct": disque.percent,
        "disque_lecture_mb": max(0, dr),
        "disque_ecriture_mb": max(0, dw),
        "download_mb": max(0, dl),
        "upload_mb": max(0, ul),
        "paquets_perdus": paquets_perdus,
        "nb_processus": len(psutil.pids()),
        "top_processus": [],
        "batterie": round(batterie_brute.percent, 1) if batterie_disponible else None,
        "en_charge": batterie_brute.power_plugged if batterie_disponible else None,
        "batterie_disponible": batterie_disponible,
        "erreurs": paquets_perdus,
    }


def detecter_anomalies(m):
    """Meme logique de seuils que monitoring_core.detecter_anomalies (sans
    le scoring IA, qui necessite le modele.pkl - pas indispensable ici,
    les seuils suffisent pour un agent leger)."""
    anomalies = []

    if m["cpu"] >= SEUILS["cpu"]:
        anomalies.append(f"🔴 CPU critique : {m['cpu']}%")
    elif m["cpu"] >= SEUILS_WARNING["cpu"]:
        anomalies.append(f"🟠 CPU élevé : {m['cpu']}%")

    if m["memoire"] >= SEUILS["memoire"]:
        anomalies.append(f"🔴 Mémoire saturée : {m['memoire']}% ({m['memoire_gb']} GB)")
    elif m["memoire"] >= SEUILS_WARNING["memoire"]:
        anomalies.append(f"🟠 Mémoire élevée : {m['memoire']}% ({m['memoire_gb']} GB)")

    if m["disque_pct"] >= SEUILS["disque"]:
        anomalies.append(f"🔴 Disque presque plein : {m['disque_pct']}%")
    elif m["disque_pct"] >= SEUILS_WARNING["disque"]:
        anomalies.append(f"🟠 Disque bien rempli : {m['disque_pct']}%")

    if m["paquets_perdus"] >= SEUILS["paquets_perdus"]:
        anomalies.append(f"🟠 Paquets réseau perdus : {m['paquets_perdus']}")
    if m["nb_processus"] >= SEUILS["nb_processus"]:
        anomalies.append(f"🟠 Trop de processus : {m['nb_processus']}")

    if m.get("batterie_disponible"):
        if m["batterie"] <= SEUILS["batterie"] and not m["en_charge"]:
            anomalies.append(f"🔴 Batterie critique : {m['batterie']}%")
        elif m["batterie"] <= SEUILS_WARNING["batterie"] and not m["en_charge"]:
            anomalies.append(f"🟠 Batterie faible : {m['batterie']}%")

    return anomalies


def main():
    parser = argparse.ArgumentParser(description="Agent de surveillance PC - envoie les metriques vers le dashboard")
    parser.add_argument("--nom", required=True, help="Nom affiche dans le dashboard, ex: PC-Reception")
    parser.add_argument("--url", required=True, help="URL complete vers /api/ingest du dashboard")
    parser.add_argument("--cle", required=True, help="Cle API (doit correspondre a DASHBOARD_API_KEY cote serveur)")
    parser.add_argument("--intervalle", type=int, default=5, help="Frequence d'envoi en secondes (defaut: 5)")
    args = parser.parse_args()

    print(f"[agent_pc] '{args.nom}' demarre, envoi vers {args.url} toutes les {args.intervalle}s")
    print(f"[agent_pc] Ctrl+C pour arreter.")

    while True:
        try:
            m = lire_metriques()
            anomalies = detecter_anomalies(m)
            payload = {"serveur": args.nom, "metriques": m, "anomalies": anomalies, "explication": None}
            reponse = requests.post(args.url, json=payload, headers={"X-API-KEY": args.cle}, timeout=10)
            if reponse.status_code != 200:
                print(f"[agent_pc] Erreur envoi ({reponse.status_code}) : {reponse.text}")
            elif anomalies:
                print(f"[agent_pc] Envoye - {len(anomalies)} anomalie(s) : {', '.join(anomalies)}")
        except requests.exceptions.RequestException as e:
            print(f"[agent_pc] Erreur reseau (ignoree, on continue) : {e}")
        except Exception as e:
            print(f"[agent_pc] Erreur inattendue (ignoree, on continue) : {e}")
        time.sleep(args.intervalle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agent_pc] Arrete par l'utilisateur.")