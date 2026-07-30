# -*- coding: utf-8 -*-
"""
Module Assignations — Accès individuel machine par machine
-------------------------------------------------------------------
Complement de groupes.py : pour les cas exceptionnels ponctuels, on peut
assigner directement une machine a un utilisateur sans passer par un
groupe. Un utilisateur voit l'union de :
  - ses assignations individuelles directes (ce module)
  - les machines de tous les groupes dont il est membre (groupes.py)
Les administrateurs voient toutes les machines.
"""

import os
import sqlite3
import threading
import time
from datetime import datetime
from contextlib import contextmanager

from flask import Blueprint, request, redirect, url_for, render_template_string

import historique
import auth
from auth import admin_required
import audit
import groupes

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
    """Initialise la table des assignations individuelles"""
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assignations_individuelles (
                user_id INTEGER NOT NULL,
                machine TEXT NOT NULL,
                assigne_le TEXT NOT NULL,
                UNIQUE(user_id, machine)
            )
        """)
        conn.commit()


# ============================================================================
# CRUD ASSIGNATIONS INDIVIDUELLES
# ============================================================================

def assigner_machine(user_id: int, machine: str):
    """Assigne une machine directement a un utilisateur"""
    initialiser_db()
    try:
        _execute(
            "INSERT INTO assignations_individuelles (user_id, machine, assigne_le) VALUES (?, ?, ?)",
            (user_id, machine, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
    except sqlite3.IntegrityError:
        pass  # Deja assignee


def retirer_machine(user_id: int, machine: str):
    """Retire une assignation individuelle"""
    _execute(
        "DELETE FROM assignations_individuelles WHERE user_id = ? AND machine = ?",
        (user_id, machine),
    )


def machines_de_utilisateur(user_id: int) -> set:
    """Machines assignees individuellement (hors groupes) a cet utilisateur"""
    initialiser_db()
    rows = _execute(
        "SELECT machine FROM assignations_individuelles WHERE user_id = ?",
        (user_id,),
        fetch=True,
    )
    return {r["machine"] for r in rows} if rows else set()


def toutes_assignations() -> dict:
    """Toutes les assignations individuelles, groupees par utilisateur"""
    initialiser_db()
    rows = _execute(
        "SELECT user_id, machine FROM assignations_individuelles ORDER BY user_id",
        fetch=True,
    )
    result = {}
    for r in rows or []:
        result.setdefault(r["user_id"], set()).add(r["machine"])
    return result


# ============================================================================
# FONCTION PRINCIPALE D'AUTORISATION
# ============================================================================

def machines_autorisees(user) -> set:
    """Renvoie l'ensemble des machines qu'un utilisateur a le droit de voir.

    - Admin : toutes les machines connues.
    - Utilisateur normal : union des assignations individuelles directes
      et des machines accessibles via ses groupes (groupes.py).
    - Non authentifie : aucune machine.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return set()

    if getattr(user, "is_admin", False):
        return {s["nom"] for s in historique.lister_serveurs()}

    user_id = getattr(user, "id", None)
    if user_id is None:
        return set()

    directes = machines_de_utilisateur(user_id)
    via_groupes = groupes.machines_via_groupes(user_id)
    return directes | via_groupes


# ============================================================================
# ROUTES FLASK
# ============================================================================

assignations_bp = Blueprint("assignations", __name__)

_PAGE_LISTE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Assignations - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + auth.TOKENS_CSS + """
  .tableau{width:100%; border-collapse:collapse; margin:16px 0;}
  .tableau th, .tableau td{padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; text-align:left;}
  .tableau th{color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase;}
  .tag-machine{display:inline-block; background:var(--panel2); border:1px solid var(--border); border-radius:6px;
                padding:2px 8px; font-size:11px; margin:2px 4px 2px 0;}
  .form-ajout{display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; align-items:center;}
  .form-ajout select{padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text);}
  .btn-primary-small{padding:6px 14px; border-radius:6px; border:1px solid var(--accent); background:var(--accent); color:#08131f; font-size:12px; cursor:pointer;}
  .btn-danger-small{padding:4px 10px; font-size:11px; border-radius:4px; border:1px solid rgba(248,81,73,.3); background:rgba(248,81,73,.1); color:var(--crit); cursor:pointer;}
  .vide{color:var(--muted); text-align:center; padding:40px 0;}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

{{ topbar|safe }}

<main class="contenu">
  <div class="page-entete">
    <h1>🎯 Assignations individuelles</h1>
    <p>Cas exceptionnels ponctuels : assigne une machine a un utilisateur precis, sans passer par un groupe.</p>
  </div>

  {% if msg %}
  <div class="toast">{{ msg }}</div>
  {% endif %}

  <div class="carte">
    <h3 style="margin:0 0 12px;">Nouvelle assignation</h3>
    <form class="form-ajout" method="post" action="{{ url_for('assignations.assigner_route') }}">
      <select name="user_id" required>
        <option value="" disabled selected>Utilisateur…</option>
        {% for u in utilisateurs %}
        <option value="{{ u.id }}">{{ u.username }} ({{ u.role }})</option>
        {% endfor %}
      </select>
      <select name="machine" required>
        <option value="" disabled selected>Machine…</option>
        {% for m in machines_disponibles %}
        <option value="{{ m }}">{{ m }}</option>
        {% endfor %}
      </select>
      <button type="submit" class="btn-primary-small">+ Assigner</button>
    </form>
  </div>

  {% if assignations_par_user %}
  <table class="tableau">
    <thead><tr><th>Utilisateur</th><th>Machines assignées individuellement</th><th></th></tr></thead>
    <tbody>
      {% for row in assignations_par_user %}
      <tr>
        <td>{{ row.username }} <span class="tag-machine">{{ row.role }}</span></td>
        <td>
          {% for m in row.machines %}
          <span class="tag-machine">
            {{ m }}
            <form method="post" action="{{ url_for('assignations.retirer_route') }}" style="display:inline;">
              <input type="hidden" name="user_id" value="{{ row.id }}">
              <input type="hidden" name="machine" value="{{ m }}">
              <button type="submit" class="btn-danger-small" onclick="return confirm('Retirer {{ m }} de {{ row.username }} ?');">✕</button>
            </form>
          </span>
          {% endfor %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="vide">Aucune assignation individuelle pour le moment.</div>
  {% endif %}
</main>

<script>""" + auth.JS_TEMA_ET_MENU + """</script>
</body></html>
"""


@assignations_bp.route("/admin/assignations")
@admin_required
def page_liste():
    """Page de liste des assignations individuelles"""
    tous_users = auth.lister_utilisateurs()
    par_user_id = toutes_assignations()

    assignations_par_user = []
    for u in tous_users:
        machs = par_user_id.get(u["id"])
        if machs:
            assignations_par_user.append({
                "id": u["id"],
                "username": u["username"],
                "role": u["role"],
                "machines": sorted(machs),
            })

    toutes_machines = [s["nom"] for s in historique.lister_serveurs()]

    return render_template_string(
        _PAGE_LISTE,
        utilisateurs=tous_users,
        machines_disponibles=toutes_machines,
        assignations_par_user=assignations_par_user,
        msg=request.args.get("msg"),
        topbar=auth.render_topbar("assignations"),
    )


@assignations_bp.route("/admin/assignations/assigner", methods=["POST"])
@admin_required
def assigner_route():
    """Assigne une machine a un utilisateur"""
    user_id = request.form.get("user_id", type=int)
    machine = request.form.get("machine", "").strip()

    if user_id and machine:
        assigner_machine(user_id, machine)
        user = auth._get_user_by_id(user_id)
        audit.consigner(
            "assignation_individuelle",
            cible=user["username"] if user else str(user_id),
            details=machine,
        )
        return redirect(url_for("assignations.page_liste", msg=f" Machine '{machine}' assignée."))

    return redirect(url_for("assignations.page_liste", msg=" Utilisateur et machine requis."))


@assignations_bp.route("/admin/assignations/retirer", methods=["POST"])
@admin_required
def retirer_route():
    """Retire une assignation individuelle"""
    user_id = request.form.get("user_id", type=int)
    machine = request.form.get("machine", "").strip()

    if user_id and machine:
        retirer_machine(user_id, machine)
        user = auth._get_user_by_id(user_id)
        audit.consigner(
            "retrait_assignation_individuelle",
            cible=user["username"] if user else str(user_id),
            details=machine,
        )
        return redirect(url_for("assignations.page_liste", msg=f" Machine '{machine}' retirée."))

    return redirect(url_for("assignations.page_liste", msg=" Utilisateur et machine requis."))