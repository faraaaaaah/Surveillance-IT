"""
Agent de surveillance distant - Multi-serveurs
----------------------------------------------------
A executer sur CHAQUE machine que tu veux surveiller (en plus de celle qui
fait tourner le dashboard). L'agent lit les metriques locales et les envoie
au dashboard central via HTTP, exactement comme fonctionnent les vrais
agents de supervision (Zabbix, Datadog, Prometheus node_exporter...).

Utilisation :
    python agent.py --nom "serveur-web-1" --dashboard http://192.168.1.10:5000 --cle MA_CLE_SECRETE

Si tu n'as qu'une seule machine pour la demo, tu peux quand meme lancer
plusieurs agents dessus avec des noms differents (--nom "serveur-A",
"serveur-B"...) pour simuler un parc de plusieurs serveurs.
"""

import argparse
import time
import requests

from monitoring_core import lire_metriques, detecter_anomalies, expliquer


def boucle_agent(nom_serveur: str, url_dashboard: str, cle_api: str, intervalle: int = 5):
    print(f"Agent '{nom_serveur}' demarre, envoie vers {url_dashboard}")
    print("CTRL+C pour arreter\n")

    while True:
        m = lire_metriques()
        anomalies = detecter_anomalies(m)
        explication = expliquer(m, anomalies) if anomalies else None

        paquet = {
            "serveur": nom_serveur,
            "metriques": m,
            "anomalies": anomalies,
            "explication": explication,
        }

        try:
            resp = requests.post(
                f"{url_dashboard.rstrip('/')}/api/ingest",
                json=paquet,
                headers={"X-API-KEY": cle_api},
                timeout=8,
            )
            if resp.status_code == 200:
                statut = "ANOMALIE" if anomalies else "ok"
                print(f"[{m['timestamp']}] Envoye - {statut}")
            else:
                print(f"[{m['timestamp']}] Erreur serveur : {resp.status_code} - {resp.text[:150]}")
        except requests.RequestException as e:
            print(f"[{m['timestamp']}] Impossible de joindre le dashboard : {e}")

        time.sleep(intervalle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agent de surveillance distant")
    parser.add_argument("--nom", required=True, help="Nom de ce serveur (affiche dans le dashboard)")
    parser.add_argument("--dashboard", required=True, help="URL du dashboard central, ex: http://192.168.1.10:5000")
    parser.add_argument("--cle", required=True, help="Cle API partagee (doit correspondre a celle du dashboard)")
    parser.add_argument("--intervalle", type=int, default=5, help="Secondes entre deux mesures (defaut: 5)")
    args = parser.parse_args()

    boucle_agent(args.nom, args.dashboard, args.cle, args.intervalle)