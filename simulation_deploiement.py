# -*- coding: utf-8 -*-
"""
Simulation de deploiement par plage IP - module pedagogique
------------------------------------------------------------------------------
A la demande de l'encadrant : pouvoir cibler une plage d'adresses IP sans
saisir de login/mot de passe a la main a chaque fois. Un inventaire fictif
(inventaire_machines.json, donnees bidon) associe chaque IP a un login, un
mot de passe et un OS ; ce module se contente d'enumerer la plage, de faire
la correspondance automatique, et de JOURNALISER une execution SIMULEE.

IMPORTANT : ce module ne fait AUCUNE connexion reseau reelle (pas de SSH,
pas de WinRM). C'est un complement pedagogique au vrai flux de deploiement
(deploiement_distant.py / relais_deploiement.py / /api/deployer), pas un
remplacement - les deux coexistent, chacun dans son propre onglet du
formulaire "Ajouter un serveur".
"""

import ipaddress
import json
import os

import historique  # reutilise DOSSIER_DATA : le journal vit sur le PVC, comme le reste des donnees

CHEMIN_INVENTAIRE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "inventaire_machines.json"
)
CHEMIN_JOURNAL = os.path.join(historique.DOSSIER_DATA, "journal_simulation_deploiement.log")

# Garde-fou : au-dela de ce nombre d'adresses dans une seule plage, on
# refuse plutot que de risquer de generer des milliers de lignes de
# journal en un clic (ex: faute de frappe sur un /8 au lieu d'un /28).
MAX_ADRESSES_PAR_PLAGE = 1024


def charger_inventaire() -> dict:
    """Charge l'inventaire fictif et le renvoie indexe par IP (recherche
    O(1)). Relu a chaque appel - le fichier est petit, et ca evite d'avoir
    a redemarrer le dashboard apres une modification de l'inventaire."""
    if not os.path.exists(CHEMIN_INVENTAIRE):
        return {}
    with open(CHEMIN_INVENTAIRE, "r", encoding="utf-8") as f:
        machines = json.load(f)
    return {m["ip"]: m for m in machines}


def parser_plage(saisie: str) -> list:
    """Transforme une saisie utilisateur en liste d'adresses IP (str).
    Trois formats acceptes :
      - IP unique       : "192.168.1.42"
      - Plage complete   : "192.168.1.10-192.168.1.20"
      - Plage abregee    : "192.168.1.10-20" (dernier octet seulement)
      - Notation CIDR    : "192.168.1.0/28"
    Leve ValueError avec un message clair si rien ne correspond, si la
    plage est mal formee, ou si elle depasse MAX_ADRESSES_PAR_PLAGE."""
    saisie = saisie.strip()
    if not saisie:
        raise ValueError("Adresse ou plage IP requise.")

    if "/" in saisie:
        try:
            reseau = ipaddress.ip_network(saisie, strict=False)
        except ValueError:
            raise ValueError(f"Notation CIDR invalide : « {saisie} ».")
        ips = [str(ip) for ip in reseau.hosts()]
        if len(ips) > MAX_ADRESSES_PAR_PLAGE:
            raise ValueError(
                f"Plage trop large ({len(ips)} adresses, max {MAX_ADRESSES_PAR_PLAGE}) "
                "- decoupe en plusieurs plages plus petites."
            )
        return ips

    if "-" in saisie:
        debut_s, fin_s = [p.strip() for p in saisie.split("-", 1)]
        try:
            debut = ipaddress.ip_address(debut_s)
        except ValueError:
            raise ValueError(f"Adresse de debut invalide : « {debut_s} ».")
        # Forme abregee ("192.168.1.10-20") : la borne de fin n'est que le
        # dernier octet, a combiner avec les 3 premiers de la borne de debut.
        if "." not in fin_s:
            octets = debut_s.split(".")
            fin_s = ".".join(octets[:3] + [fin_s])
        try:
            fin = ipaddress.ip_address(fin_s)
        except ValueError:
            raise ValueError(f"Adresse de fin invalide : « {fin_s} ».")
        if int(fin) < int(debut):
            raise ValueError("La borne de fin doit etre superieure ou egale a la borne de debut.")
        nb = int(fin) - int(debut) + 1
        if nb > MAX_ADRESSES_PAR_PLAGE:
            raise ValueError(
                f"Plage trop large ({nb} adresses, max {MAX_ADRESSES_PAR_PLAGE}) "
                "- decoupe en plusieurs plages plus petites."
            )
        return [str(ipaddress.ip_address(i)) for i in range(int(debut), int(fin) + 1)]

    # IP unique
    try:
        return [str(ipaddress.ip_address(saisie))]
    except ValueError:
        raise ValueError(f"Adresse IP invalide : « {saisie} ».")


def _consigner(entree: dict):
    with open(CHEMIN_JOURNAL, "a", encoding="utf-8") as f:
        f.write(json.dumps(entree, ensure_ascii=False) + "\n")


def simuler_deploiement(plage_saisie: str) -> list:
    """Enumere la plage saisie, fait correspondre chaque IP a l'inventaire
    fictif (login/mot de passe/OS trouves automatiquement, jamais saisis a
    la main), et journalise une execution SIMULEE - aucune connexion SSH
    ou WinRM reelle n'est faite. Renvoie la liste des resultats (un par
    IP, dans l'ordre de la plage) ; chaque resultat est aussi ajoute a
    CHEMIN_JOURNAL pour garder une trace persistante des simulations."""
    ips = parser_plage(plage_saisie)
    inventaire = charger_inventaire()
    horodatage = historique.maintenant_local().strftime("%Y-%m-%d %H:%M:%S")

    resultats = []
    for ip in ips:
        machine = inventaire.get(ip)
        if machine is None:
            resultat = {
                "horodatage": horodatage,
                "ip": ip,
                "trouve": False,
                "nom": None,
                "os": None,
                "statut": "echec",
                "message": "Aucune correspondance dans l'inventaire fictif.",
            }
        else:
            resultat = {
                "horodatage": horodatage,
                "ip": ip,
                "trouve": True,
                "nom": machine.get("nom", ip),
                "os": machine.get("os", "?"),
                "statut": "succes",
                "message": (
                    f"Identifiants trouves automatiquement (login « {machine.get('login', '?')} ») "
                    "- agent installe et demarre (execution simulee, aucune connexion reelle)."
                ),
            }
        _consigner(resultat)
        resultats.append(resultat)

    return resultats


def lire_journal(limite: int = 100) -> list:
    """Renvoie les 'limite' dernieres entrees du journal de simulation,
    les plus recentes en premier. Liste vide si le journal n'existe pas
    encore (aucune simulation lancee)."""
    if not os.path.exists(CHEMIN_JOURNAL):
        return []
    with open(CHEMIN_JOURNAL, "r", encoding="utf-8") as f:
        lignes = f.readlines()
    entrees = []
    for ligne in reversed(lignes[-limite:]):
        ligne = ligne.strip()
        if not ligne:
            continue
        try:
            entrees.append(json.loads(ligne))
        except json.JSONDecodeError:
            continue
    return entrees