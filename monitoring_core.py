"""
Module central - logique de surveillance partagée
-----------------------------------------------------
Toute la logique de lecture des métriques, détection d'anomalies et
génération d'explications vit ICI, dans un seul endroit.

surveillance_complete.py (console) ET dashboard.py (web) importent ce
fichier, au lieu de dupliquer le code. Ça évite le bug qu'on a eu avant
(deux fichiers avec la même logique, un seul mis à jour).
"""

import os
import pickle
import psutil
import pandas as pd
import ollama
from datetime import datetime
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

FUSEAU_LOCAL = ZoneInfo("Africa/Tunis")
# Pool dédié à l'appel LLM : permet de le "timeout-er" proprement (voir
# expliquer() ci-dessous) sans jamais bloquer indéfiniment le cycle de
# surveillance, qui doit rester rapide pour que les alertes partent vite.
_EXECUTOR_LLM = ThreadPoolExecutor(max_workers=6)
DELAI_MAX_LLM_SECONDES = 6

# Adresse du serveur Ollama a contacter. Sans variable d'environnement (ex:
# en local sur un poste de dev ou Ollama tourne sur la meme machine), le
# comportement est inchange : on vise localhost. En production (OpenShift),
# "localhost" designerait le pod lui-meme (qui ne fait pas tourner Ollama) -
# il faut alors definir OLLAMA_HOST vers un service Ollama joignable sur le
# reseau (ex: http://ollama:11434 si deploye comme Service dans le meme
# namespace). Client construit explicitement (plutot que de compter sur le
# client global par defaut du package) pour que ce soit lisible et fiable
# quelle que soit la version du package installee.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_client_ollama = ollama.Client(host=OLLAMA_HOST)

# --- Chargement du modèle IA (module 2) ---
_CHEMIN_MODELE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "modele.pkl"
)
with open(_CHEMIN_MODELE, "rb") as f:
    _donnees_modele = pickle.load(f)

MODELE = _donnees_modele["modele"]
FEATURES_MODELE = _donnees_modele["features"]

# --- Seuils d'anomalies ---
SEUILS = {
    "cpu": 85,
    "memoire": 85,
    "disque": 90,
    "paquets_perdus": 30,  # par cycle (~5-6s) depuis la correction du delta, plus un total cumule
    "nb_processus": 400,
    "batterie": 15,
}

# Seuils "warning" (🟠) : moins graves que SEUILS (🔴 critique), pour avoir
# un vrai palier intermediaire sur cpu/memoire/disque/batterie - avant, ces
# 4 metriques passaient directement de "rien" a "critique", jamais de
# warning (contrairement au reseau/processus qui, eux, n'ont qu'un seuil
# 🟠). Un stress test qui monte le cpu/la memoire ne generait donc jamais
# de warning, seulement du critique.
SEUILS_WARNING = {
    "cpu": 70,
    "memoire": 70,
    "disque": 80,
    "batterie": 25,
}

_prev = psutil.net_io_counters()
_prev_disk = psutil.disk_io_counters()


def lire_metriques():
    """Module 1 - lit les métriques système actuelles (CPU, RAM, disque, réseau...)."""
    global _prev, _prev_disk

    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disque = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters()
    net = psutil.net_io_counters()
    # psutil.sensors_battery() renvoie None des que le systeme n'expose pas
    # d'info batterie (PC de bureau, VM, conteneur, ou laptop selon l'OS/les
    # droits) - PAS uniquement quand la batterie est a 100%. Avant, ce None
    # etait remplace par un "100% + en charge" fixe, indiscernable d'une
    # vraie lecture a 100% : la metrique semblait figee car c'etait en fait
    # une valeur bidon reconduite a chaque cycle, jamais une vraie mesure.
    batterie_brute = psutil.sensors_battery()
    batterie_disponible = batterie_brute is not None
    top_processus = sorted(
        psutil.process_iter(['name', 'cpu_percent']),
        key=lambda p: p.info['cpu_percent'],
        reverse=True
    )[:3]

    dl = round((net.bytes_recv - _prev.bytes_recv) / 1024 / 1024, 3)
    ul = round((net.bytes_sent - _prev.bytes_sent) / 1024 / 1024, 3)
    dr = round((disk_io.read_bytes - _prev_disk.read_bytes) / 1024 / 1024, 3)
    dw = round((disk_io.write_bytes - _prev_disk.write_bytes) / 1024 / 1024, 3)
    # BUG CORRIGE : net.dropin/dropout sont des compteurs CUMULES depuis le
    # demarrage de la machine (comme bytes_recv/bytes_sent), pas une valeur
    # "depuis le dernier cycle". dl/ul ci-dessus font bien la soustraction
    # avec la mesure precedente pour obtenir un delta ; paquets_perdus ne le
    # faisait PAS avant, et comparait donc un total qui ne fait qu'augmenter
    # a un seuil fixe. Resultat : une fois le seuil franchi une fois (parfois
    # des le demarrage), l'anomalie reseau ne pouvait plus jamais se
    # resoudre, puisque le total ne redescend jamais.
    paquets_perdus_delta = max(0, (net.dropin + net.dropout) - (_prev.dropin + _prev.dropout))
    _prev = net
    _prev_disk = disk_io

    return {
        "timestamp": datetime.now(FUSEAU_LOCAL).strftime("%H:%M:%S"),
        "cpu": cpu,
        "memoire": mem.percent,
        "memoire_gb": round(mem.used / (1024 ** 3), 2),
        "disque_pct": disque.percent,
        "disque_lecture_mb": max(0, dr),
        "disque_ecriture_mb": max(0, dw),
        "download_mb": max(0, dl),
        "upload_mb": max(0, ul),
        "paquets_perdus": paquets_perdus_delta,
        "nb_processus": len(psutil.pids()),
        "top_processus": [p.info['name'] for p in top_processus],
        "batterie": round(batterie_brute.percent, 1) if batterie_disponible else None,
        "en_charge": batterie_brute.power_plugged if batterie_disponible else None,
        "batterie_disponible": batterie_disponible,
        "erreurs": paquets_perdus_delta,
    }


def detecter_anomalies(m):
    """Module 2 - règles de seuils = les VRAIES anomalies remontées à l'utilisateur.

    Le modèle IA (IsolationForest) reste calculé ci-dessous à titre de
    diagnostic (log serveur uniquement) mais NE DÉCLENCHE PLUS d'anomalie :
    il générait trop de faux positifs (combinaisons de métriques jugées
    "inhabituelles" mais qui ne posaient aucun problème réel), ce qui
    polluait les alertes, l'historique et le dashboard. Seuls les vrais
    dépassements de seuils ci-dessous sont considérés comme des anomalies."""
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

    # On ne juge la batterie que si une vraie lecture a ete obtenue (voir
    # lire_metriques) : pas de capteur -> pas d'anomalie fabriquee.
    if m.get("batterie_disponible"):
        if m["batterie"] <= SEUILS["batterie"] and not m["en_charge"]:
            anomalies.append(f"🔴 Batterie critique : {m['batterie']}%")
        elif m["batterie"] <= SEUILS_WARNING["batterie"] and not m["en_charge"]:
            anomalies.append(f"🟠 Batterie faible : {m['batterie']}%")

    valeurs = [[
        m["cpu"], m["memoire"], m["disque_pct"],
        m["disque_lecture_mb"], m["disque_ecriture_mb"],
        m["paquets_perdus"], m["nb_processus"], m["erreurs"]
    ]]
    try:
        df_val = pd.DataFrame(valeurs, columns=FEATURES_MODELE)
        score = MODELE.decision_function(df_val)[0]
        if score < -0.15:
            # Diagnostic uniquement : on le log pour investigation manuelle,
            # mais on ne l'ajoute plus a `anomalies` (voir docstring).
            print(f"[monitoring_core] (info) Combinaison de métriques jugée inhabituelle par l'IA "
                  f"(score: {score:.3f}) - non remontée comme anomalie.")
    except Exception as e:
        print(f"[monitoring_core] Erreur lors du scoring IA (ignorée) : {e}")

    return anomalies


def _type_anomalie(texte_anomalie: str) -> str:
    """Classe une ligne d'anomalie par type (meme logique que historique.py,
    dupliquee ici pour eviter un couplage entre modules)."""
    texte = texte_anomalie.lower()
    if "cpu" in texte:
        return "cpu"
    if "memoire" in texte or "mémoire" in texte:
        return "memoire"
    if "disque" in texte:
        return "disque"
    if "reseau" in texte or "réseau" in texte or "paquets" in texte:
        return "reseau"
    if "processus" in texte:
        return "processus"
    if "batterie" in texte:
        return "batterie"
    return "autre"


def _construire_prompt(m: dict, anomalies: list) -> str:
    details_anomalies = "\n".join(anomalies)
    return f"""Tu préviens un administrateur non-expert par notification (Slack/WhatsApp/bureau)
d'UN SEUL problème (ne parle pas d'autre chose). Sois direct et concret : 1 à 2 phrases
courtes maximum (40 mots max au total), langage simple, SANS jargon technique.
Explique brièvement ce qui se passe ET donne une action concrète à faire maintenant.
Pas d'introduction ("Voici", "Il semble que"...), va droit au but.

Métriques : CPU {m.get('cpu')}%, Mémoire {m.get('memoire')}%, Disque {m.get('disque_pct')}%, Processus {m.get('nb_processus')}
Problème détecté :
{details_anomalies}

Réponds en français, 1 à 2 phrases courtes."""


def _appeler_llm(prompt: str) -> str:
    """Appel Ollama synchrone, borné par timeout via _EXECUTOR_LLM. Ne doit
    JAMAIS être appelée depuis une tâche déjà soumise à _EXECUTOR_LLM (sous
    peine de blocage : avec un pool à taille fixe, une tâche qui attend une
    sous-tâche sur le MEME pool peut se retrouver sans worker disponible)."""
    def _appel_ollama():
        response = _client_ollama.chat(model="mistral", messages=[{"role": "user", "content": prompt}])
        return response["message"]["content"].strip()

    future = _EXECUTOR_LLM.submit(_appel_ollama)
    return future.result(timeout=DELAI_MAX_LLM_SECONDES)


def expliquer_par_type(m: dict, anomalies: list) -> dict:
    """Genere UNE explication PAR TYPE d'anomalie (cpu / memoire / disque / ...),
    au lieu d'une seule explication combinee pour tout le lot.

    BUG CORRIGE : avant, quand 2 anomalies de nature differente arrivaient en
    meme temps (ex: CPU critique + batterie critique), une seule explication
    etait generee pour les deux — le LLM devait choisir entre les deux
    problemes ou produire une phrase confuse qui n'expliquait bien ni l'un
    ni l'autre. Chaque type a maintenant sa propre explication, generee en
    parallele (donc pas plus lent), et chaque incident en base recoit
    l'explication qui le concerne vraiment."""
    if not anomalies:
        return {}

    par_type = {}
    for a in anomalies:
        par_type.setdefault(_type_anomalie(a), []).append(a)

    # Tous les appels LLM sont soumis directement (un seul niveau) sur
    # _EXECUTOR_LLM, en parallele - pas d'imbrication de pool.
    futures = {
        type_: _EXECUTOR_LLM.submit(lambda p=_construire_prompt(m, lignes): (
            _client_ollama.chat(model="mistral", messages=[{"role": "user", "content": p}])["message"]["content"].strip()
        ))
        for type_, lignes in par_type.items()
    }

    resultats = {}
    for type_, future in futures.items():
        try:
            resultats[type_] = future.result(timeout=DELAI_MAX_LLM_SECONDES)
        except Exception as e:
            print(f"[monitoring_core] Erreur explication ({type_}), repli utilisé : {e}")
            resultats[type_] = "⚠️ " + par_type[type_][0].lstrip("🔴🟠 ")
    return resultats


def expliquer(m, anomalies):
    """Module 3 - explication en langage naturel via LLM local (Ollama/Mistral),
    pour UN LOT d'anomalies (utilisée par la console ; le dashboard utilise
    expliquer_par_type ci-dessus pour ne pas mélanger plusieurs problèmes).

    Deux points corrigés par rapport à l'origine :
    1) TEMPS DE REPONSE : l'appel Ollama est borné à DELAI_MAX_LLM_SECONDES
       au lieu de pouvoir bloquer indéfiniment.
    2) LISIBILITE : prompt resserré sur 1-2 phrases concrètes et sans jargon,
       au lieu d'un pavé technique.
    Ne doit JAMAIS faire planter l'appelant."""
    prompt = _construire_prompt(m, anomalies)
    try:
        return _appeler_llm(prompt)
    except FutureTimeoutError:
        print(f"[monitoring_core] Ollama trop lent (> {DELAI_MAX_LLM_SECONDES}s), "
              "explication de repli utilisée pour ne pas retarder l'alerte.")
        return "⚠️ " + anomalies[0].lstrip("🔴🟠 ")
    except Exception as e:
        print(f"[monitoring_core] Ollama indisponible, explication de repli utilisée : {e}")
        return "⚠️ " + anomalies[0].lstrip("🔴🟠 ")


def cycle_surveillance():
    """Exécute un cycle complet : lecture -> détection -> (explication si besoin).
    Retourne (metriques, anomalies, explication_ou_None)."""
    m = lire_metriques()
    anomalies = detecter_anomalies(m)
    explication = expliquer(m, anomalies) if anomalies else None
    return m, anomalies, explication