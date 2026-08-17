"""
Relais de deploiement - a lancer sur un PC deja connecte au reseau de
l'entreprise (typiquement le PC de l'admin).
------------------------------------------------------------------------------
Le dashboard cloud (OpenShift) ne peut pas joindre directement les
machines du reseau local de l'entreprise (pas de route reseau sans VPN).
Ce script contourne le probleme en inversant le sens de la communication,
exactement comme le font deja les agents de surveillance (agent_pc.py,
agent_reseau.py) : il interroge PERIODIQUEMENT le dashboard ("as-tu une
tache de deploiement pour moi ?"), execute localement celles qu'il trouve
(donc avec un vrai acces au reseau local), puis rapporte le resultat.

Ca permet au bouton "+" du dashboard cloud de fonctionner normalement du
point de vue de l'admin (un formulaire, un clic), meme si l'execution
reelle se fait ailleurs.

INSTALLATION :
    pip install paramiko pywinrm requests

CONFIGURATION :
    Modifie DASHBOARD_URL et RELAIS_TOKEN ci-dessous (RELAIS_TOKEN doit
    etre IDENTIQUE a la variable d'environnement RELAIS_TOKEN configuree
    cote dashboard - sinon le relais n'aura pas le droit de recuperer les
    taches, par securite).

UTILISATION :
    python relais_deploiement.py
    (a laisser tourner en arriere-plan en permanence, ou au moins pendant
    les periodes ou l'admin peut avoir besoin d'ajouter une machine)
"""

import sys
import time

try:
    import requests
except ImportError:
    print("[relais] ERREUR FATALE : le module 'requests' n'est pas installe.", flush=True)
    print("[relais] Lance dans un terminal : pip install requests paramiko pywinrm", flush=True)
    input("Appuie sur Entree pour fermer...")
    sys.exit(1)

try:
    from deploiement_distant import deployer_linux, deployer_windows, AGENT_LOCAL_DEFAUT
except ImportError as e:
    print(f"[relais] ERREUR FATALE : impossible d'importer deploiement_distant.py ({e}).", flush=True)
    print("[relais] Verifie que relais_deploiement.py est bien lance depuis le meme dossier "
          "que deploiement_distant.py et agent_pc.py.")
    input("Appuie sur Entree pour fermer...")
    sys.exit(1)

# --- A adapter une fois pour toutes ---
DASHBOARD_URL = "http://surveillance-dash-farah-boubaker-dev.apps.rm2.thpm.p1.openshiftapps.com"
RELAIS_TOKEN = "relais-token-a-changer"

INTERVALLE_SONDAGE_SECONDES = 5


def _message_erreur(exc: Exception, os_cible: str) -> str:
    """Traduit une exception technique (SSH/WinRM/reseau) en message clair
    pour l'admin, affiche dans le formulaire du dashboard. Les RuntimeError
    levees par deploiement_distant.py sont deja redigees a la main -> on
    les garde telles quelles. Les autres (timeouts reseau, erreurs
    paramiko/winrm brutes) sont traduites ici."""
    texte = str(exc)
    bas = texte.lower()

    if "timed out" in bas or "timeout" in bas:
        if os_cible == "windows":
            return ("Impossible de joindre cette machine sur le port WinRM (5985). "
                     "Verifiez qu'elle est allumee, sur le meme reseau que ce relais, "
                     "et que WinRM est active dessus (Enable-PSRemoting -Force).")
        return ("Impossible de joindre cette machine sur le port SSH (22). "
                 "Verifiez qu'elle est allumee, sur le meme reseau que ce relais, "
                 "et que le service SSH est actif.")

    if "connection refused" in bas or "actively refused" in bas:
        service = "WinRM" if os_cible == "windows" else "SSH"
        return f"La machine a refuse la connexion {service} — le service {service} n'est probablement pas actif dessus."

    if "authentication" in bas or "access is denied" in bas or "auth failed" in bas or " 401" in bas:
        return "Identifiant ou mot de passe incorrect pour cette machine."

    if "getaddrinfo failed" in bas or "name or service not known" in bas or "no address associated" in bas:
        return "Adresse IP introuvable ou invalide."

    if isinstance(exc, RuntimeError):
        return texte

    return f"Le deploiement a echoue de facon inattendue : {texte[:200]}"


def traiter_job(job: dict):
    job_id = job["id"]
    nom = job["nom"]
    ip = job["ip"]
    os_cible = job["os"]
    login = job["login"]
    mot_de_passe = job["motdepasse"]
    url_ingest = job["url_ingest"]
    cle_api = job["cle_api"]

    print(f"[relais] Traitement de la tache {job_id} : {nom} ({ip}, {os_cible})...", flush=True)

    try:
        if os_cible == "linux":
            deployer_linux(ip, login, mot_de_passe, AGENT_LOCAL_DEFAUT, nom, url_ingest, cle_api)
        else:
            deployer_windows(ip, login, mot_de_passe, AGENT_LOCAL_DEFAUT, nom, url_ingest, cle_api)
        message = f"« {nom} » a été installé et démarré sur {ip}. Il apparaîtra dans le dashboard sous peu."
        _rapporter_resultat(job_id, True, message)
        print(f"[relais] ✅ Tache {job_id} terminee avec succes.", flush=True)
    except Exception as e:
        message = _message_erreur(e, os_cible)
        _rapporter_resultat(job_id, False, message)
        print(f"[relais] ❌ Tache {job_id} echouee : {message}", flush=True)


def _rapporter_resultat(job_id: str, succes: bool, message: str):
    try:
        requests.post(
            f"{DASHBOARD_URL}/api/deployer/resultat",
            json={"job_id": job_id, "succes": succes, "message": message},
            headers={"X-RELAIS-TOKEN": RELAIS_TOKEN},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"[relais] ⚠️  Impossible de rapporter le resultat de {job_id} au dashboard : {e}", flush=True)


def _test_connexion_initiale():
    """Auto-diagnostic lance UNE FOIS au demarrage : evite de decouvrir un
    probleme de configuration (URL, jeton, reseau) seulement apres avoir
    attendu betement le timeout de 3 minutes cote navigateur."""
    print(f"[relais] Test de connexion vers {DASHBOARD_URL} ...", flush=True)
    try:
        reponse = requests.get(
            f"{DASHBOARD_URL}/api/deployer/jobs",
            headers={"X-RELAIS-TOKEN": RELAIS_TOKEN},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"[relais] ❌ ECHEC : impossible de joindre {DASHBOARD_URL} ({e}).", flush=True)
        print("[relais] Verifie : l'URL DASHBOARD_URL dans ce script, la connexion internet "
              "de ce PC, et qu'aucun pare-feu/proxy d'entreprise ne bloque la requete.", flush=True)
        return False

    if reponse.status_code == 403:
        print("[relais] ❌ ECHEC : jeton refuse (403). Le RELAIS_TOKEN de ce script ne correspond "
              "pas a la variable d'environnement RELAIS_TOKEN configuree sur le pod OpenShift.", flush=True)
        return False
    if reponse.status_code != 200:
        print(f"[relais] ❌ ECHEC : reponse HTTP {reponse.status_code} inattendue "
              f"({reponse.text[:200]}).", flush=True)
        return False

    print("[relais] ✅ Connexion au dashboard OK. Le relais est operationnel.", flush=True)
    return True


def boucle_principale():
    print(f"[relais] Demarre. Sondage de {DASHBOARD_URL} toutes les {INTERVALLE_SONDAGE_SECONDES}s.", flush=True)
    print("[relais] Ctrl+C pour arreter.", flush=True)

    connecte = _test_connexion_initiale()

    while True:
        try:
            reponse = requests.get(
                f"{DASHBOARD_URL}/api/deployer/jobs",
                headers={"X-RELAIS-TOKEN": RELAIS_TOKEN},
                timeout=10,
            )
            if reponse.status_code == 403:
                print("[relais] ❌ Jeton invalide (RELAIS_TOKEN) — verifie qu'il correspond "
                      "a la variable d'environnement RELAIS_TOKEN cote dashboard.", flush=True)
            elif reponse.status_code == 200:
                if not connecte:
                    print("[relais] ✅ Connexion retablie.", flush=True)
                    connecte = True
                jobs = reponse.json().get("jobs", [])
                for job in jobs:
                    traiter_job(job)
            else:
                print(f"[relais] ⚠️  Reponse HTTP inattendue du dashboard : {reponse.status_code} "
                      f"{reponse.text[:200]}", flush=True)
        except requests.exceptions.RequestException as e:
            connecte = False
            print(f"[relais] ⚠️  Dashboard injoignable (reessai dans {INTERVALLE_SONDAGE_SECONDES}s) : {e}", flush=True)

        time.sleep(INTERVALLE_SONDAGE_SECONDES)


if __name__ == "__main__":
    try:
        boucle_principale()
    except KeyboardInterrupt:
        print("\n[relais] Arrete par l'utilisateur.", flush=True)
    except Exception as e:
        # Filet de securite : sans ca, une erreur inattendue fermerait la
        # fenetre instantanement si le script est lance par double-clic,
        # donnant l'impression trompeuse qu'"il ne se passe rien".
        import traceback
        print(f"\n[relais] ❌ ERREUR INATTENDUE : {e}", flush=True)
        traceback.print_exc()
        input("Appuie sur Entree pour fermer...")