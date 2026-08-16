"""
File d'attente de deploiement pour le relais local
------------------------------------------------------------------------------
Le dashboard (cloud) ne peut pas joindre directement les machines du reseau
d'entreprise (pas de route reseau sans VPN). A la place, il depose des
"jobs" de deploiement ici ; un petit script relais (relais_deploiement.py),
lance sur un PC deja present sur ce reseau local, vient les recuperer,
les execute localement (SSH/WinRM), puis rapporte le resultat.

SECURITE : le mot de passe de la machine cible transite UNE FOIS par cette
file d'attente (le temps que le relais le recupere), puis est EFFACE de la
base immediatement apres recuperation - il n'est jamais conserve au-dela
de cette fenetre courte (quelques secondes, le temps du prochain sondage
du relais).
"""
import sqlite3
import time
import uuid

from historique import CHEMIN_DB


def _init():
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deploiement_jobs (
                id TEXT PRIMARY KEY,
                nom TEXT NOT NULL,
                ip TEXT NOT NULL,
                os TEXT NOT NULL,
                login TEXT NOT NULL,
                motdepasse TEXT,
                url_ingest TEXT NOT NULL,
                cle_api TEXT NOT NULL,
                statut TEXT NOT NULL DEFAULT 'en_attente',
                message TEXT,
                cree_le REAL NOT NULL,
                termine_le REAL
            )
        """)


def creer_job(nom, ip, os_cible, login, motdepasse, url_ingest, cle_api) -> str:
    _init()
    job_id = uuid.uuid4().hex
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.execute(
            "INSERT INTO deploiement_jobs "
            "(id, nom, ip, os, login, motdepasse, url_ingest, cle_api, statut, cree_le) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'en_attente', ?)",
            (job_id, nom, ip, os_cible, login, motdepasse, url_ingest, cle_api, time.time())
        )
    return job_id


def recuperer_jobs_en_attente() -> list:
    """Appele par le relais : recupere les jobs en attente, les passe en
    'en_cours', et EFFACE le mot de passe de la base immediatement (il est
    retourne une seule fois au relais, qui l'utilise tout de suite sans le
    stocker lui-meme)."""
    _init()
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM deploiement_jobs WHERE statut = 'en_attente' ORDER BY cree_le"
        ).fetchall()
        jobs = [dict(r) for r in rows]
        for j in jobs:
            conn.execute(
                "UPDATE deploiement_jobs SET statut = 'en_cours', motdepasse = NULL WHERE id = ?",
                (j["id"],)
            )
    return jobs


def marquer_resultat(job_id: str, succes: bool, message: str):
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.execute(
            "UPDATE deploiement_jobs SET statut = ?, message = ?, termine_le = ? WHERE id = ?",
            ("succes" if succes else "echec", message, time.time(), job_id)
        )


def obtenir_statut(job_id: str):
    _init()
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM deploiement_jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row else None


def purger_jobs_anciens(max_age_heures: int = 24):
    """Menage : supprime les jobs termines (succes/echec) depuis plus de
    max_age_heures, pour ne pas laisser grossir la table indefiniment."""
    seuil = time.time() - max_age_heures * 3600
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.execute(
            "DELETE FROM deploiement_jobs WHERE statut IN ('succes', 'echec') AND termine_le < ?",
            (seuil,)
        )