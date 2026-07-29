"""
Module 5+ - Historique, incidents et score de sante (v2, multi-serveurs)
----------------------------------------------------------------------------
Evolution du module historique simple : au lieu de juste empiler des lignes
d'anomalies, on regroupe les anomalies proches dans le temps en "incidents"
(comme un vrai systeme de tickets), on garde une dimension "serveur" pour
surveiller plusieurs machines, et on calcule un score de sante global.
"""

import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from contextlib import contextmanager

# Meme fuseau que monitoring_core.py : le serveur (OpenShift, etc.) tourne
# souvent en UTC quel que soit l'endroit d'ou on le consulte. On force donc
# explicitement l'heure de Tunis pour TOUS les timestamps stockes ici
# (debut/derniere_occurrence/fin d'incident, mesures...), sinon l'historique
# affiche dans le dashboard se decale selon l'hebergeur.
FUSEAU_LOCAL = ZoneInfo("Africa/Tunis")


def maintenant_local() -> datetime:
    """Horodatage courant dans le fuseau de Tunis, independant de l'horloge
    systeme du serveur qui execute le code."""
    return datetime.now(FUSEAU_LOCAL).replace(tzinfo=None)

# DOSSIER_DATA permet de placer la base sur un volume persistant (PVC sur
# OpenShift) plutot que dans le dossier du code lui-meme. Sans cette
# variable d'environnement (ex: en local sur un poste de dev), le
# comportement est inchange : la base reste a cote de ce fichier.
DOSSIER_DATA = os.environ.get("DOSSIER_DATA", os.path.dirname(os.path.abspath(__file__)))
CHEMIN_DB = os.path.join(DOSSIER_DATA, "historique_anomalies.db")

# Si deux anomalies du meme type sur le meme serveur arrivent a moins de
# ce delai l'une de l'autre, on considere que c'est LE MEME incident qui
# continue, plutot que d'en creer un nouveau a chaque cycle de 5s.
FENETRE_REGROUPEMENT_MINUTES = 15

# Thread lock for database operations
_db_lock = threading.Lock()


@contextmanager
def _connexion():
    """Context manager for database connections with proper timeout and WAL mode."""
    conn = None
    try:
        conn = sqlite3.connect(CHEMIN_DB, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")  # Wait up to 5 seconds if locked
        conn.execute("PRAGMA synchronous=NORMAL")  # Better performance
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()


def _execute_with_lock(sql, params=None, fetch=False, commit=True):
    """Execute SQL with thread safety and automatic retry on lock."""
    if params is None:
        params = ()
    
    max_retries = 3
    retry_delay = 0.5
    
    for attempt in range(max_retries):
        try:
            with _db_lock:
                with _connexion() as conn:
                    cursor = conn.execute(sql, params)
                    if fetch:
                        result = cursor.fetchall()
                    else:
                        if commit:
                            conn.commit()
                        result = None
                    return result
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
                continue
            raise
        except Exception as e:
            raise


def _colonnes_existantes(conn, table):
    return {ligne[1] for ligne in conn.execute(f"PRAGMA table_info({table})")}


def _migrer_schema_si_besoin(conn):
    """Si une base a ete creee avec l'ancienne version du module 5 (sans
    incident_id / serveur), on ajoute les colonnes manquantes au lieu de
    planter. Ne fait rien si la base est deja a jour ou n'existe pas encore."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "anomalies" not in tables:
        return
    colonnes = _colonnes_existantes(conn, "anomalies")
    if "incident_id" not in colonnes:
        conn.execute("ALTER TABLE anomalies ADD COLUMN incident_id INTEGER")
    if "serveur" not in colonnes:
        conn.execute("ALTER TABLE anomalies ADD COLUMN serveur TEXT NOT NULL DEFAULT 'local'")

    if "incidents" in tables:
        colonnes_incidents = _colonnes_existantes(conn, "incidents")
        if "stabilise_depuis" not in colonnes_incidents:
            conn.execute("ALTER TABLE incidents ADD COLUMN stabilise_depuis TEXT")


def initialiser_db():
    """Initialize database with all required tables."""
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serveur TEXT NOT NULL DEFAULT 'local',
                type_anomalie TEXT NOT NULL,
                niveau_max TEXT NOT NULL,
                debut TEXT NOT NULL,
                derniere_occurrence TEXT NOT NULL,
                fin TEXT,
                statut TEXT NOT NULL DEFAULT 'ouvert',
                nb_occurrences INTEGER NOT NULL DEFAULT 1,
                derniere_explication TEXT,
                stabilise_depuis TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                serveur TEXT NOT NULL DEFAULT 'local',
                horodatage TEXT NOT NULL,
                type_anomalie TEXT NOT NULL,
                niveau TEXT NOT NULL,
                message TEXT NOT NULL,
                cpu REAL, memoire REAL, disque_pct REAL, nb_processus INTEGER,
                explication TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS serveurs (
                nom TEXT PRIMARY KEY,
                derniere_maj TEXT
            )
        """)
        _migrer_schema_si_besoin(conn)
        conn.commit()


# Seuils de "retour a la normale" (plus tolerants que les seuils de
# detection pour eviter les oscillations ouvert/surveillance/ouvert en
# continu si une metrique flotte pile autour du seuil de detection).
SEUILS_RESOLUTION = {
    "cpu": 70, "memoire": 75, "disque": 85, "reseau": 10,
    "processus": 350, "batterie": 25,
}

# Metriques dans le dict `m` (voir monitoring_core.lire_metriques) qui
# correspondent a chaque type d'anomalie.
_METRIQUE_PAR_TYPE = {
    "cpu": "cpu", "memoire": "memoire", "disque": "disque_pct",
    "reseau": "paquets_perdus", "processus": "nb_processus", "batterie": "batterie",
}


def a_une_metrique(type_anomalie: str) -> bool:
    """True si ce type d'anomalie correspond a une metrique numerique
    (cpu/memoire/disque/reseau/processus/batterie), False pour 'ia'/'autre'."""
    return type_anomalie in _METRIQUE_PAR_TYPE or type_anomalie == "batterie"


def metrique_est_normale(type_anomalie: str, m: dict) -> bool:
    """Fonction UNIQUE (canonique) qui decide si la metrique d'un type
    d'anomalie est revenue a la normale. Utilisee a la fois ici (pour faire
    passer un incident de 'ouvert' a 'surveillance') et par notifier.py
    (pour arreter les rappels bureau/WhatsApp) — avoir DEUX implementations
    separees de la meme regle est exactement ce qui a cause le bug ou la
    batterie était considérée "résolue" dès qu'elle était basse (sens
    inversé par rapport à cpu/mémoire/disque). Une seule version, partagée,
    evite que ce genre de bug puisse revenir.

    Cas particulier batterie : "normal" = en charge OU au-dessus du seuil
    (pour toutes les autres metriques, plus bas = mieux ; pour la batterie
    c'est l'inverse)."""
    if not m:
        return False
    if type_anomalie == "batterie":
        if m.get("en_charge"):
            return True
        return m.get("batterie", 100) > SEUILS_RESOLUTION["batterie"]

    champ = _METRIQUE_PAR_TYPE.get(type_anomalie)
    if not champ:
        # types "ia"/"autre" : pas de metrique correspondante ->
        # on ne peut pas juger, on considere que ce n'est pas "revenu a la
        # normale" tant qu'aucune nouvelle occurrence n'arrive (le
        # nettoyage par delai d'inactivite s'en charge).
        return False
    return m.get(champ, 0) < SEUILS_RESOLUTION[type_anomalie]


def _type_et_niveau(texte_anomalie: str):
    texte = texte_anomalie.lower()
    if "cpu" in texte:
        type_ = "cpu"
    elif "memoire" in texte or "mémoire" in texte:
        type_ = "memoire"
    elif "disque" in texte:
        type_ = "disque"
    elif "reseau" in texte or "réseau" in texte or "paquets" in texte:
        type_ = "reseau"
    elif "processus" in texte:
        type_ = "processus"
    elif "batterie" in texte:
        type_ = "batterie"
    elif "ia" in texte or "🤖" in texte_anomalie:
        type_ = "ia"
    else:
        type_ = "autre"

    if texte_anomalie.startswith("🔴"):
        niveau = "critique"
    elif texte_anomalie.startswith("🟠"):
        niveau = "warning"
    else:
        niveau = "ia"
    return type_, niveau


# Explications en langage courant (pas de jargon informatique), pensees pour
# un utilisateur qui n'est ni ingenieur ni technicien. Utilisees dans la
# liste "Incidents" (phrase courte) et dans le panneau "Historique" detaille
# (phrase + explication detaillee + solution).
INFOS_ANOMALIES = {
    "cpu": {
        "phrase": "Le processeur est surchargé — l'appareil peut ralentir.",
        "detaillee": "Le processeur (CPU) traite beaucoup plus de travail que d'habitude. "
                      "Cela vient souvent d'un programme bloqué, d'une tâche lourde en cours, "
                      "ou d'un logiciel indésirable qui tourne en arrière-plan.",
        "solution": "Ouvrez le gestionnaire des tâches pour voir quel programme utilise le plus "
                     "le processeur, et fermez-le si besoin. Si ça revient souvent sans raison, "
                     "redémarrez l'appareil.",
    },
    "memoire": {
        "phrase": "La mémoire (RAM) est presque pleine — les programmes peuvent devenir lents.",
        "detaillee": "L'appareil n'a presque plus de mémoire vive disponible. Trop de programmes "
                      "sont ouverts en même temps, ou l'un d'eux consomme anormalement de mémoire.",
        "solution": "Fermez les programmes ou onglets inutilisés. Si le problème revient souvent, "
                     "un redémarrage régulier aide à libérer la mémoire.",
    },
    "disque": {
        "phrase": "L'espace de stockage est presque plein.",
        "detaillee": "Le disque dur / SSD est presque saturé. Sans espace libre, l'appareil peut "
                      "devenir instable et certains programmes ne pourront plus enregistrer de fichiers.",
        "solution": "Supprimez ou déplacez des fichiers volumineux (téléchargements, vidéos, "
                     "anciennes sauvegardes) et videz la corbeille.",
    },
    "reseau": {
        "phrase": "La connexion réseau perd des données — internet peut être instable.",
        "detaillee": "Le réseau perd un nombre anormal de paquets de données, ce qui peut causer "
                      "des ralentissements ou des coupures de connexion.",
        "solution": "Vérifiez le câble ou le Wi-Fi, redémarrez le routeur si possible. Si le "
                     "problème persiste, contactez le support réseau.",
    },
    "processus": {
        "phrase": "Un nombre anormalement élevé de programmes tournent en même temps.",
        "detaillee": "Le nombre de processus actifs dépasse largement la normale, ce qui peut "
                      "indiquer un programme qui se duplique anormalement ou un logiciel indésirable.",
        "solution": "Regardez le gestionnaire des tâches pour repérer un programme qui s'ouvre "
                     "en de nombreux exemplaires, et fermez-le.",
    },
    "batterie": {
        "phrase": "La batterie est presque vide et l'appareil n'est pas en charge.",
        "detaillee": "Le niveau de batterie est très bas et l'appareil n'est pas branché : il "
                      "risque de s'éteindre à tout moment, avec perte du travail en cours.",
        "solution": "Branchez le chargeur dès que possible.",
    },
    "ia": {
        "phrase": "Combinaison de métriques jugée inhabituelle (diagnostic, pas une panne confirmée).",
        "detaillee": "Aucun seuil n'est dépassé individuellement, mais l'ensemble des métriques "
                      "sort de l'habitude apprise par le modèle de détection.",
        "solution": "Surveillez l'évolution ; si un problème concret apparaît, il sera signalé séparément.",
    },
    "autre": {
        "phrase": "Anomalie détectée sur le serveur.",
        "detaillee": "Un problème a été détecté sans catégorie précise.",
        "solution": "Consultez les métriques détaillées pour identifier la cause.",
    },
}


def infos_type(type_anomalie: str) -> dict:
    """Retourne {phrase, detaillee, solution} en langage simple pour un type
    d'anomalie donne (utilise par le dashboard, pour un public non-technique)."""
    return INFOS_ANOMALIES.get(type_anomalie, INFOS_ANOMALIES["autre"])


def enregistrer_serveur_vu(serveur: str):
    initialiser_db()
    maintenant = maintenant_local().strftime("%Y-%m-%d %H:%M:%S")
    _execute_with_lock(
        """INSERT INTO serveurs (nom, derniere_maj) VALUES (?, ?)
           ON CONFLICT(nom) DO UPDATE SET derniere_maj = excluded.derniere_maj""",
        (serveur, maintenant)
    )


def enregistrer_anomalie(m: dict, anomalies: list, explication: str = None, serveur: str = "local",
                          explications_par_type: dict = None):
    """Enregistre les anomalies et les rattache a un incident existant si
    un incident du meme type est encore ouvert recemment, sinon en cree un
    nouveau (logique de systeme de tickets).

    `explications_par_type` (optionnel) : dict {type_anomalie: explication}.
    Avant, une SEULE explication (generee pour TOUTES les anomalies du cycle
    en meme temps) etait enregistree sur CHAQUE incident, meme si CPU et
    batterie n'ont rien a voir. Si fourni, chaque incident recoit
    l'explication qui correspond a SON type ; sinon on retombe sur
    `explication` (comportement precedent, pour compatibilite)."""
    if not anomalies:
        return

    initialiser_db()
    enregistrer_serveur_vu(serveur)
    maintenant = maintenant_local()
    maintenant_str = maintenant.strftime("%Y-%m-%d %H:%M:%S")
    seuil_regroupement = (maintenant - timedelta(minutes=FENETRE_REGROUPEMENT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

    # Use a single transaction for all operations
    with _db_lock:
        with _connexion() as conn:
            for a in anomalies:
                type_, niveau = _type_et_niveau(a)
                explication_type = (explications_par_type or {}).get(type_) or explication or ""

                incident = conn.execute("""
                    SELECT id, niveau_max, nb_occurrences FROM incidents
                    WHERE serveur = ? AND type_anomalie = ? AND statut IN ('ouvert', 'surveillance')
                      AND derniere_occurrence >= ?
                    ORDER BY derniere_occurrence DESC LIMIT 1
                """, (serveur, type_, seuil_regroupement)).fetchone()

                ordre_niveau = {"warning": 0, "ia": 0, "critique": 1}

                if incident:
                    # Rattache a l'incident existant, et le ROUVRE s'il etait
                    # passe en 'surveillance' entre-temps (le probleme revient,
                    # ce n'est donc plus juste une metrique "a l'oeil").
                    incident_id = incident["id"]
                    nouveau_niveau_max = niveau if ordre_niveau.get(niveau, 0) > ordre_niveau.get(incident["niveau_max"], 0) else incident["niveau_max"]
                    conn.execute("""
                        UPDATE incidents
                        SET derniere_occurrence = ?, nb_occurrences = nb_occurrences + 1,
                            niveau_max = ?, derniere_explication = ?, statut = 'ouvert', stabilise_depuis = NULL
                        WHERE id = ?
                    """, (maintenant_str, nouveau_niveau_max, explication_type, incident_id))
                else:
                    cur = conn.execute("""
                        INSERT INTO incidents (serveur, type_anomalie, niveau_max, debut, derniere_occurrence, statut, nb_occurrences, derniere_explication)
                        VALUES (?, ?, ?, ?, ?, 'ouvert', 1, ?)
                    """, (serveur, type_, niveau, maintenant_str, maintenant_str, explication_type))
                    incident_id = cur.lastrowid

                conn.execute("""
                    INSERT INTO anomalies
                        (incident_id, serveur, horodatage, type_anomalie, niveau, message, cpu, memoire, disque_pct, nb_processus, explication)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident_id, serveur, maintenant_str, type_, niveau, a,
                    m.get("cpu"), m.get("memoire"), m.get("disque_pct"), m.get("nb_processus"),
                    explication_type,
                ))
            conn.commit()


DELAI_STABILISATION_MINUTES = 15  # temps "en surveillance" avant cloture definitive


def mettre_a_jour_stabilisation(serveur: str, m: dict) -> list:
    """A appeler a CHAQUE cycle (operation legere : pas de LLM ni de reseau,
    juste une comparaison de seuils) pour faire passer les incidents
    'ouvert' dont la metrique est revenue a la normale vers un statut
    'surveillance' — moins alarmant qu'"ouvert" (l'alerte critique
    s'arrete), mais pas encore ferme, pour rester attentif un moment avant
    de considerer le probleme vraiment termine.

    AVANT : un incident restait 'ouvert' (alerte active) meme des que le
    CPU repassait a 5%, jusqu'a 10 minutes d'inactivite totale — ce qui
    donnait l'impression de continuer a signaler un probleme qui n'existe
    plus. MAINTENANT : des que la metrique redescend, l'incident passe en
    'surveillance' immediatement (visuellement plus calme), et se ferme
    tout seul apres DELAI_STABILISATION_MINUTES sans nouvelle occurrence.

    Retourne la liste des IDs d'incidents qui viennent de changer de statut
    (pour que l'appelant sache s'il doit rafraichir le dashboard)."""
    if not m:
        return []
    initialiser_db()
    maintenant_str = maintenant_local().strftime("%Y-%m-%d %H:%M:%S")
    ids_changes = []

    with _db_lock:
        with _connexion() as conn:
            ouverts = conn.execute(
                "SELECT id, type_anomalie FROM incidents WHERE serveur = ? AND statut = 'ouvert'",
                (serveur,)
            ).fetchall()
            for inc in ouverts:
                if metrique_est_normale(inc["type_anomalie"], m):
                    conn.execute(
                        "UPDATE incidents SET statut = 'surveillance', stabilise_depuis = ? WHERE id = ?",
                        (maintenant_str, inc["id"])
                    )
                    ids_changes.append(inc["id"])
            conn.commit()
    return ids_changes


def resoudre_incidents_expires(minutes_inactivite: int = 10):
    """A appeler periodiquement :
    - ferme les incidents 'surveillance' stabilises depuis plus de
      DELAI_STABILISATION_MINUTES (cas normal : le probleme s'est resolu).
    - ferme aussi, en filet de securite, les incidents restes 'ouvert' sans
      AUCUNE nouvelle occurrence depuis `minutes_inactivite` (ex: l'agent
      distant s'est arrete en pleine anomalie et ne peut plus confirmer
      que la metrique est revenue a la normale)."""
    initialiser_db()
    maintenant_str = maintenant_local().strftime("%Y-%m-%d %H:%M:%S")

    seuil_stabilisation = (maintenant_local() - timedelta(minutes=DELAI_STABILISATION_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    _execute_with_lock(
        """UPDATE incidents SET statut = 'resolu', fin = ?
           WHERE statut = 'surveillance' AND stabilise_depuis < ?""",
        (maintenant_str, seuil_stabilisation)
    )

    seuil_inactivite = (maintenant_local() - timedelta(minutes=minutes_inactivite)).strftime("%Y-%m-%d %H:%M:%S")
    _execute_with_lock(
        """UPDATE incidents SET statut = 'resolu', fin = ?
           WHERE statut = 'ouvert' AND derniere_occurrence < ?""",
        (maintenant_str, seuil_inactivite)
    )


def resoudre_incident_manuellement(incident_id: int):
    initialiser_db()
    maintenant_str = maintenant_local().strftime("%Y-%m-%d %H:%M:%S")
    _execute_with_lock(
        """UPDATE incidents SET statut = 'resolu', fin = ? WHERE id = ?""",
        (maintenant_str, incident_id)
    )


def obtenir_serveur_incident(incident_id: int) -> str:
    """Retourne le nom du serveur associe a un incident, ou None si
    introuvable — utilise pour diffuser les evenements temps reel
    (incident_resolu) uniquement aux utilisateurs autorises sur ce serveur."""
    initialiser_db()
    rows = _execute_with_lock("SELECT serveur FROM incidents WHERE id = ?", (incident_id,), fetch=True)
    return rows[0]["serveur"] if rows else None


def compter_incidents_par_statut(serveur: str = None, serveurs: list = None) -> dict:
    """Compte les incidents par statut sans charger toutes les lignes —
    utilise pour le petit compteur du dashboard, qui devient vite illisible
    si on essaie d'afficher TOUS les incidents un par un des que leur
    nombre augmente.

    serveur : un seul serveur precis. serveurs : une liste (ex. machines
    autorisees pour un compte restreint) — les deux sont exclusifs."""
    initialiser_db()
    if serveurs is not None:
        if not serveurs:  # liste vide = aucune machine autorisee -> rien a compter
            return {"ouvert": 0, "surveillance": 0, "resolu": 0}
        placeholders = ",".join("?" for _ in serveurs)
        condition, params = f"WHERE serveur IN ({placeholders})", tuple(serveurs)
    elif serveur:
        condition, params = "WHERE serveur = ?", (serveur,)
    else:
        condition, params = "", ()
    rows = _execute_with_lock(
        f"SELECT statut, COUNT(*) AS total FROM incidents {condition} GROUP BY statut",
        params, fetch=True
    )
    compteur = {"ouvert": 0, "surveillance": 0, "resolu": 0}
    for r in (rows or []):
        compteur[r["statut"]] = r["total"]
    return compteur


def lister_incidents(serveur: str = None, serveurs: list = None, statut: str = None, limite: int = 50,
                      type_anomalie: str = None, niveau: str = None,
                      depuis: str = None, jusqua: str = None):
    """serveur : un seul serveur precis. serveurs : une liste (ex. machines
    autorisees pour un compte restreint) — les deux sont exclusifs."""
    initialiser_db()
    if serveurs is not None and not serveurs:
        return []  # aucune machine autorisee -> rien a lister
    conditions, params = [], []
    if serveurs:
        placeholders = ",".join("?" for _ in serveurs)
        conditions.append(f"serveur IN ({placeholders})")
        params.extend(serveurs)
    elif serveur:
        conditions.append("serveur = ?")
        params.append(serveur)
    if statut:
        conditions.append("statut = ?")
        params.append(statut)
    if type_anomalie:
        conditions.append("type_anomalie = ?")
        params.append(type_anomalie)
    if niveau:
        conditions.append("niveau_max = ?")
        params.append(niveau)
    if depuis:
        conditions.append("derniere_occurrence >= ?")
        params.append(depuis)
    if jusqua:
        conditions.append("debut <= ?")
        params.append(jusqua)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limite)
    
    rows = _execute_with_lock(
        f"SELECT * FROM incidents {where} ORDER BY derniere_occurrence DESC LIMIT ?",
        tuple(params),
        fetch=True
    )
    return [dict(r) for r in rows] if rows else []


def lister_serveurs():
    initialiser_db()
    rows = _execute_with_lock("SELECT * FROM serveurs ORDER BY nom", fetch=True)
    return [dict(r) for r in rows] if rows else []


# ---------------------------------------------------------------------------
# Historique long terme des mesures (pour les graphiques 1h/6h/24h)
# ---------------------------------------------------------------------------
RETENTION_JOURS = 30
_dernier_enregistrement_mesure = {}  # serveur -> objet datetime
_mesure_lock = threading.Lock()


def initialiser_table_mesures():
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mesures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serveur TEXT NOT NULL,
                horodatage TEXT NOT NULL,
                cpu REAL, memoire REAL, disque_pct REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mesures_serveur_horodatage ON mesures (serveur, horodatage)")
        # Migration : ajoute les colonnes des metriques supplementaires
        # (necessaires pour les graphiques Reseau/Batterie/Processus) si la
        # table a ete creee avec une version anterieure du schema.
        colonnes = _colonnes_existantes(conn, "mesures")
        for colonne in ("paquets_perdus", "nb_processus", "batterie"):
            if colonne not in colonnes:
                type_sql = "INTEGER" if colonne in ("paquets_perdus", "nb_processus") else "REAL"
                conn.execute(f"ALTER TABLE mesures ADD COLUMN {colonne} {type_sql}")
        conn.commit()


def enregistrer_mesure(serveur: str, m: dict):
    """A appeler a CHAQUE cycle : ne stocke reellement qu'un point par minute
    par serveur (le reste du temps, ne fait rien - tres rapide)."""
    maintenant = maintenant_local()
    
    with _mesure_lock:
        dernier = _dernier_enregistrement_mesure.get(serveur)
        if dernier and (maintenant - dernier).total_seconds() < 60:
            return
        _dernier_enregistrement_mesure[serveur] = maintenant

    initialiser_table_mesures()
    _execute_with_lock(
        """INSERT INTO mesures (serveur, horodatage, cpu, memoire, disque_pct, paquets_perdus, nb_processus, batterie)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (serveur, maintenant.strftime("%Y-%m-%d %H:%M:%S"),
         m.get("cpu"), m.get("memoire"), m.get("disque_pct"),
         m.get("paquets_perdus"), m.get("nb_processus"), m.get("batterie"))
    )


def recuperer_mesures(serveur: str, heures: float = 1):
    initialiser_table_mesures()
    depuis = (maintenant_local() - timedelta(hours=heures)).strftime("%Y-%m-%d %H:%M:%S")
    rows = _execute_with_lock(
        """SELECT horodatage, cpu, memoire, disque_pct, paquets_perdus, nb_processus, batterie FROM mesures
           WHERE serveur = ? AND horodatage >= ?
           ORDER BY horodatage ASC""",
        (serveur, depuis),
        fetch=True
    )
    return [dict(r) for r in rows] if rows else []


def nettoyer_vieilles_mesures():
    """A appeler periodiquement pour eviter que la base grossisse indefiniment."""
    initialiser_table_mesures()
    seuil = (maintenant_local() - timedelta(days=RETENTION_JOURS)).strftime("%Y-%m-%d %H:%M:%S")
    _execute_with_lock("DELETE FROM mesures WHERE horodatage < ?", (seuil,))


def calculer_score_sante(serveur: str = "local", m_actuel: dict = None, fenetre_heures: int = 24) -> dict:
    """Calcule un score de sante 0-100, combinant l'etat instantane des
    metriques et la frequence des incidents recents."""
    initialiser_db()
    maintenant = maintenant_local()
    depuis_dt = maintenant - timedelta(hours=fenetre_heures)
    depuis = depuis_dt.strftime("%Y-%m-%d %H:%M:%S")
    maintenant_str = maintenant.strftime("%Y-%m-%d %H:%M:%S")

    # Get incident counts
    nb_critiques = _execute_with_lock(
        """SELECT COUNT(*) AS n FROM incidents
           WHERE serveur = ? AND niveau_max = 'critique' AND derniere_occurrence >= ?""",
        (serveur, depuis),
        fetch=True
    )[0]["n"]

    nb_warnings = _execute_with_lock(
        """SELECT COUNT(*) AS n FROM incidents
           WHERE serveur = ? AND niveau_max != 'critique' AND derniere_occurrence >= ?""",
        (serveur, depuis),
        fetch=True
    )[0]["n"]

    nb_ouverts = _execute_with_lock(
        """SELECT COUNT(*) AS n FROM incidents WHERE serveur = ? AND statut = 'ouvert'""",
        (serveur,),
        fetch=True
    )[0]["n"]

    # Incidents critiques qui chevauchent la fenetre
    incidents_critiques = _execute_with_lock(
        """SELECT debut, fin, statut FROM incidents
           WHERE serveur = ? AND niveau_max = 'critique'
             AND debut <= ? AND (fin IS NULL OR fin >= ?)""",
        (serveur, maintenant_str, depuis),
        fetch=True
    )

    # Duree cumulee des pannes critiques
    duree_panne = timedelta()
    for inc in incidents_critiques or []:
        debut_inc = datetime.strptime(inc["debut"], "%Y-%m-%d %H:%M:%S")
        fin_inc = datetime.strptime(inc["fin"], "%Y-%m-%d %H:%M:%S") if inc["fin"] else maintenant
        debut_clip = max(debut_inc, depuis_dt)
        fin_clip = min(fin_inc, maintenant)
        if fin_clip > debut_clip:
            duree_panne += (fin_clip - debut_clip)

    duree_fenetre = timedelta(hours=fenetre_heures)
    disponibilite_pct = round(100 - min(100, (duree_panne / duree_fenetre) * 100), 2)

    score_historique = 100 - min(60, nb_critiques * 8) - min(20, nb_warnings * 3) - min(20, nb_ouverts * 15)
    score_historique = max(0, score_historique)

    score_instantane = 100
    if m_actuel:
        for cle, seuil in (("cpu", 85), ("memoire", 85), ("disque_pct", 90)):
            valeur = m_actuel.get(cle, 0)
            if valeur >= seuil:
                score_instantane -= 25
            elif valeur >= seuil * 0.8:
                score_instantane -= 10
    score_instantane = max(0, score_instantane)

    score_global = round(score_historique * 0.6 + score_instantane * 0.4)

    return {
        "score": score_global,
        "disponibilite_pct": disponibilite_pct,
        "duree_panne_minutes": round(duree_panne.total_seconds() / 60, 1),
        "nb_incidents_critiques_24h": nb_critiques,
        "nb_incidents_warning_24h": nb_warnings,
        "nb_incidents_ouverts": nb_ouverts,
    }


def contexte_pour_chatbot(serveur: str = None, jours: int = 7, limite: int = 40) -> str:
    """Construit un resume textuel de l'historique recent, a injecter dans
    le prompt du LLM pour repondre a des questions en langage naturel."""
    initialiser_db()
    depuis = (maintenant_local() - timedelta(days=jours)).strftime("%Y-%m-%d %H:%M:%S")
    conditions, params = ["derniere_occurrence >= ?"], [depuis]
    if serveur:
        conditions.append("serveur = ?")
        params.append(serveur)
    where = "WHERE " + " AND ".join(conditions)
    params.append(limite)

    rows = _execute_with_lock(
        f"""SELECT serveur, type_anomalie, niveau_max, debut, derniere_occurrence,
                   statut, nb_occurrences, derniere_explication
            FROM incidents {where}
            ORDER BY derniere_occurrence DESC LIMIT ?""",
        tuple(params),
        fetch=True
    )

    if not rows:
        return "Aucun incident enregistre sur la periode demandee."

    lignes = []
    for r in rows:
        lignes.append(
            f"- [{r['serveur']}] {r['type_anomalie']} ({r['niveau_max']}), "
            f"du {r['debut']} au {r['derniere_occurrence']}, "
            f"{r['nb_occurrences']} occurrence(s), statut: {r['statut']}. "
            f"Explication: {(r['derniere_explication'] or '')[:200]}"
        )
    return "\n".join(lignes)


if __name__ == "__main__":
    initialiser_db()
    faux_m = {"cpu": 97.0, "memoire": 40.0, "disque_pct": 55, "nb_processus": 200}
    enregistrer_anomalie(faux_m, ["🔴 CPU critique : 97.0%"], "Explication de test.", serveur="serveur-test")
    print("Incidents :", lister_incidents())
    print("Score sante :", calculer_score_sante("serveur-test", faux_m))
    print("Contexte chatbot :\n", contexte_pour_chatbot())