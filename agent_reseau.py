"""
Agent Reseau (SNMP) - surveille des switches/routeurs qui ne peuvent pas
faire tourner de script Python.
------------------------------------------------------------------------------
Principe : ce script tourne sur UN PC/serveur qui a acces reseau aux
equipements a surveiller (switches, routeurs). Il interroge chaque
equipement via SNMP (le protocole standard pour la supervision reseau),
recupere ce qu'il peut (trafic reseau = quasi toujours disponible ; CPU/
memoire = disponible seulement sur certains modeles, variable selon le
constructeur), puis envoie le resultat au dashboard via /api/ingest -
exactement comme agent_pc.py, mais pour du materiel reseau.

PREREQUIS SUR L'EQUIPEMENT (switch/routeur) :
    Le SNMP doit etre active dessus, avec une "communaute" (mot de passe
    simple, souvent "public" en lecture seule par defaut - A CHANGER en
    vrai environnement de production, "public" est un choix par defaut
    tres peu securise). Ca se configure dans l'interface d'admin web ou
    en CLI du switch/routeur (differe selon le constructeur : Cisco,
    TP-Link, Netgear, MikroTik...). Demande a la personne qui gere le
    reseau si tu n'as pas acces toi-meme.

INSTALLATION (sur la machine qui fait tourner ce script) :
    pip install pysnmp requests

CONFIGURATION :
    Modifie le fichier equipements.json (cree automatiquement si absent
    au premier lancement, avec un exemple a completer) pour lister tes
    switches/routeurs.

UTILISATION :
    python agent_reseau.py --url http://ton-dashboard/api/ingest --cle cle-demo-a-changer
"""

import argparse
import json
import os
import time
from datetime import datetime

import requests

try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd,
    )
except ImportError:
    raise SystemExit(
        "pysnmp n'est pas installe. Lance : pip install pysnmp"
    )

FICHIER_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "equipements.json")

# --- OID standards (IF-MIB), disponibles sur QUASIMENT tous les
# equipements SNMP, quel que soit le constructeur : compteurs cumules
# d'octets recus/envoyes sur l'interface reseau numero 1 (souvent la
# premiere interface physique - a ajuster si besoin selon l'equipement,
# voir commentaire plus bas sur comment lister les interfaces). ---
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10.1"    # octets recus, interface 1
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16.1"   # octets envoyes, interface 1
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"           # uptime du systeme (verifie que le SNMP repond)

SEUILS_RESEAU = {"cpu": 85, "memoire": 85}
SEUILS_WARNING_RESEAU = {"cpu": 70, "memoire": 70}

# Historique des compteurs precedents par equipement, pour calculer un
# delta (comme pour dl/ul dans monitoring_core.py) plutot qu'un total
# cumule qui ne redescend jamais.
_precedent = {}


def _charger_equipements():
    """Charge la liste des switches/routeurs depuis equipements.json.
    Cree un exemple si le fichier n'existe pas encore."""
    if not os.path.exists(FICHIER_CONFIG):
        exemple = [
            {
                "nom": "Switch-Etage1",
                "ip": "192.168.1.10",
                "type": "switch",
                "communaute": "public",
                "oid_cpu": None,
                "oid_memoire": None
            },
            {
                "nom": "Routeur-Principal",
                "ip": "192.168.1.1",
                "type": "routeur",
                "communaute": "public",
                "oid_cpu": None,
                "oid_memoire": None
            }
        ]
        with open(FICHIER_CONFIG, "w", encoding="utf-8") as f:
            json.dump(exemple, f, indent=2, ensure_ascii=False)
        print(f"[agent_reseau] Fichier {FICHIER_CONFIG} cree avec un exemple.")
        print("[agent_reseau] Modifie-le avec les vraies IP/communautes de tes equipements, puis relance.")
        raise SystemExit(0)

    with open(FICHIER_CONFIG, encoding="utf-8") as f:
        return json.load(f)


def _snmp_get(ip, communaute, oid, timeout=2):
    """Interroge un OID precis sur un equipement. Retourne None si
    l'equipement ne repond pas ou ne supporte pas cet OID (frequent pour
    CPU/memoire selon les modeles - le trafic reseau, lui, repond presque
    toujours)."""
    iterateur = getCmd(
        SnmpEngine(),
        CommunityData(communaute, mpModel=0),  # mpModel=0 -> SNMP v1 (large compatibilite)
        UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    try:
        erreur_indication, erreur_statut, _, var_binds = next(iterateur)
        if erreur_indication or erreur_statut:
            return None
        for var_bind in var_binds:
            return var_bind[1]
    except Exception:
        return None
    return None


def lire_metriques_equipement(equip):
    """Interroge un equipement et construit un dict de metriques compatible
    avec le format attendu par /api/ingest. Les valeurs non mesurables
    (CPU/memoire sur du materiel qui ne les expose pas, batterie qui n'a
    aucun sens sur un switch) restent a None plutot que d'inventer une
    fausse valeur - meme logique que la correction faite sur la batterie
    dans monitoring_core.py."""
    ip = equip["ip"]
    communaute = equip.get("communaute", "public")
    nom = equip["nom"]

    uptime = _snmp_get(ip, communaute, OID_SYS_UPTIME)
    if uptime is None:
        print(f"[agent_reseau] {nom} ({ip}) ne repond pas au SNMP, cycle ignore.")
        return None

    in_octets = _snmp_get(ip, communaute, OID_IF_IN_OCTETS)
    out_octets = _snmp_get(ip, communaute, OID_IF_OUT_OCTETS)
    in_octets = int(in_octets) if in_octets is not None else None
    out_octets = int(out_octets) if out_octets is not None else None

    prev = _precedent.get(nom, {})
    dl = ul = 0.0
    if in_octets is not None and "in_octets" in prev:
        dl = max(0, round((in_octets - prev["in_octets"]) / 1024 / 1024, 3))
    if out_octets is not None and "out_octets" in prev:
        ul = max(0, round((out_octets - prev["out_octets"]) / 1024 / 1024, 3))
    _precedent[nom] = {"in_octets": in_octets, "out_octets": out_octets}

    # CPU/memoire : specifiques au constructeur (pas de standard universel
    # comme pour le trafic reseau). Si tu connais l'OID pour ton modele
    # precis (ex: Cisco cpmCPUTotal5minRev = 1.3.6.1.4.1.9.9.109.1.1.1.1.7),
    # renseigne-le dans equipements.json ("oid_cpu"/"oid_memoire"). Sinon,
    # reste a None - le disque et la batterie n'ont de toute facon pas de
    # sens pour ce type d'equipement.
    cpu = memoire = None
    if equip.get("oid_cpu"):
        val = _snmp_get(ip, communaute, equip["oid_cpu"])
        cpu = float(val) if val is not None else None
    if equip.get("oid_memoire"):
        val = _snmp_get(ip, communaute, equip["oid_memoire"])
        memoire = float(val) if val is not None else None

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "cpu": cpu if cpu is not None else 0,
        "cpu_disponible": cpu is not None,
        "memoire": memoire if memoire is not None else 0,
        "memoire_disponible": memoire is not None,
        "memoire_gb": None,
        "disque_pct": 0,
        "disque_lecture_mb": 0,
        "disque_ecriture_mb": 0,
        "download_mb": dl,
        "upload_mb": ul,
        "paquets_perdus": 0,
        "nb_processus": 0,
        "top_processus": [],
        "batterie": None,
        "en_charge": None,
        "batterie_disponible": False,
        "erreurs": 0,
    }


def detecter_anomalies(m):
    """Anomalies pour du materiel reseau : seul CPU/memoire (si disponibles
    pour ce modele) sont juges - le reste (disque, batterie...) n'a pas de
    sens sur un switch/routeur."""
    anomalies = []
    if m.get("cpu_disponible"):
        if m["cpu"] >= SEUILS_RESEAU["cpu"]:
            anomalies.append(f"🔴 CPU critique : {m['cpu']}%")
        elif m["cpu"] >= SEUILS_WARNING_RESEAU["cpu"]:
            anomalies.append(f"🟠 CPU élevé : {m['cpu']}%")
    if m.get("memoire_disponible"):
        if m["memoire"] >= SEUILS_RESEAU["memoire"]:
            anomalies.append(f"🔴 Mémoire saturée : {m['memoire']}%")
        elif m["memoire"] >= SEUILS_WARNING_RESEAU["memoire"]:
            anomalies.append(f"🟠 Mémoire élevée : {m['memoire']}%")
    return anomalies


def main():
    parser = argparse.ArgumentParser(description="Agent SNMP - surveille des switches/routeurs")
    parser.add_argument("--url", required=True, help="URL complete vers /api/ingest du dashboard")
    parser.add_argument("--cle", required=True, help="Cle API (doit correspondre a DASHBOARD_API_KEY cote serveur)")
    parser.add_argument("--intervalle", type=int, default=15, help="Frequence de sondage en secondes (defaut: 15)")
    args = parser.parse_args()

    equipements = _charger_equipements()
    print(f"[agent_reseau] {len(equipements)} equipement(s) charge(s) depuis {FICHIER_CONFIG}")
    print(f"[agent_reseau] Envoi vers {args.url} toutes les {args.intervalle}s. Ctrl+C pour arreter.")

    while True:
        for equip in equipements:
            try:
                m = lire_metriques_equipement(equip)
                if m is None:
                    continue
                anomalies = detecter_anomalies(m)
                payload = {"serveur": equip["nom"], "metriques": m, "anomalies": anomalies, "explication": None}
                reponse = requests.post(args.url, json=payload, headers={"X-API-KEY": args.cle}, timeout=10)
                if reponse.status_code != 200:
                    print(f"[agent_reseau] Erreur envoi pour {equip['nom']} ({reponse.status_code}) : {reponse.text}")
                else:
                    print(f"[agent_reseau] {equip['nom']} : OK"
                          + (f" - anomalies : {', '.join(anomalies)}" if anomalies else ""))
            except requests.exceptions.RequestException as e:
                print(f"[agent_reseau] Erreur reseau vers le dashboard (ignoree) : {e}")
            except Exception as e:
                print(f"[agent_reseau] Erreur inattendue pour {equip.get('nom')} (ignoree) : {e}")
        time.sleep(args.intervalle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[agent_reseau] Arrete par l'utilisateur.")