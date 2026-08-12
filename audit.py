# -*- coding: utf-8 -*-
"""
Module Audit — Journal des actions d'administration
-------------------------------------------------------------
Trace qui a fait quoi et quand : creation/suppression de compte,
changement de role, assignation de machine, modification de la config
email, creation/suppression de groupe, ajout/retrait de responsable...

Standard en entreprise pour la tracabilite (savoir qui avait acces a quoi
a un instant donne, et qui a change quoi). Lecture seule pour les admins,
personne ne peut modifier ou supprimer une ligne depuis l'interface —
un journal qu'on peut corriger n'est pas un journal.
"""

import os
import sqlite3
import threading
import time
from datetime import datetime
from contextlib import contextmanager

from flask import Blueprint, request, render_template_string
from flask_login import current_user

import historique
import auth
from auth import admin_required

CHEMIN_DB = os.path.join(historique.DOSSIER_DATA, "auth.db")

_db_lock = threading.Lock()


@contextmanager
def _connexion():
    conn = None
    try:
        conn = sqlite3.connect(CHEMIN_DB, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()


def _execute(sql, params=None, fetch=False, commit=True):
    params = params or ()
    for tentative in range(3):
        try:
            with _db_lock:
                with _connexion() as conn:
                    cur = conn.execute(sql, params)
                    if fetch:
                        return cur.fetchall()
                    if commit:
                        conn.commit()
                    return cur.lastrowid
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and tentative < 2:
                time.sleep(0.5 * (tentative + 1))
                continue
            raise


def initialiser_db():
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS journal_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                horodatage TEXT NOT NULL,
                acteur TEXT NOT NULL,       -- username de qui a fait l'action
                action TEXT NOT NULL,       -- ex. 'creation_compte', 'assignation_machine'
                cible TEXT,                 -- ex. nom du compte/machine/groupe concerne
                details TEXT
            )
        """)
        conn.commit()


def consigner(action: str, cible: str = None, details: str = None, acteur: str = None):
    """Ajoute une ligne au journal. acteur : deduit de current_user si non
    fourni (pratique pour les appels depuis une route Flask deja
    authentifiee) ; sinon passe explicitement (ex. bootstrap automatique,
    sans utilisateur connecte)."""
    initialiser_db()
    if acteur is None:
        try:
            acteur = current_user.username if current_user.is_authenticated else "systeme"
        except Exception:
            acteur = "systeme"
    _execute(
        "INSERT INTO journal_audit (horodatage, acteur, action, cible, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), acteur, action, cible, details),
    )


def lister(limite: int = 200):
    initialiser_db()
    rows = _execute(
        "SELECT * FROM journal_audit ORDER BY id DESC LIMIT ?", (limite,), fetch=True
    )
    return [dict(r) for r in rows] if rows else []


# ---------------------------------------------------------------------------
# Page de consultation (admin, lecture seule)
# ---------------------------------------------------------------------------

audit_bp = Blueprint("audit", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Journal d'audit - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + auth.TOKENS_CSS + """
  .action-tag{padding:2px 8px; border-radius:5px; background:var(--panel2); border:1px solid var(--border);
              font-family:monospace; font-size:12px;}
  .acteur{color:var(--accent); font-weight:600;}
  .details-cell{color:var(--muted);}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>📜 Journal d'audit</h1>
    <p>Les {{ lignes|length }} dernieres actions d'administration (lecture seule).</p>
  </div>

  <div class="carte">
    {% if lignes %}
    <table class="table-pro">
      <tr><th>Date</th><th>Qui</th><th>Action</th><th>Cible</th><th>Details</th></tr>
      {% for l in lignes %}
      <tr>
        <td>{{ l.horodatage }}</td>
        <td class="acteur">{{ l.acteur }}</td>
        <td><span class="action-tag">{{ l.action }}</span></td>
        <td>{{ l.cible or '' }}</td>
        <td class="details-cell">{{ l.details or '' }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <div class="vide-etat">Aucune action enregistree pour le moment.</div>
    {% endif %}
  </div>
</main>

<script>""" + auth.JS_TEMA_ET_MENU + """</script>
</body></html>
"""


@audit_bp.route("/admin/audit")
@admin_required
def page_audit():
    return render_template_string(_PAGE, lignes=lister(), topbar=auth.render_topbar("audit"))