# -*- coding: utf-8 -*-
"""
Module Groupes — Acces par groupe plutot que machine par machine
-------------------------------------------------------------------
Approche "niveau entreprise" : au lieu d'assigner chaque machine a chaque
utilisateur individuellement (ingerable des que le nombre de machines ou
d'utilisateurs grandit), on definit des groupes (ex. 'equipe-reseau',
'datacenter-tunis'), on met des machines DANS le groupe, et on met des
utilisateurs DANS le groupe. Un utilisateur voit l'union des machines de
TOUS les groupes dont il est membre, plus ses assignations individuelles
directes (assignations.py) pour les cas exceptionnels ponctuels.
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
            CREATE TABLE IF NOT EXISTS groupes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT UNIQUE NOT NULL,
                description TEXT,
                cree_le TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groupe_machines (
                groupe_id INTEGER NOT NULL REFERENCES groupes(id) ON DELETE CASCADE,
                machine TEXT NOT NULL,
                UNIQUE(groupe_id, machine)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groupe_utilisateurs (
                groupe_id INTEGER NOT NULL REFERENCES groupes(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL,
                UNIQUE(groupe_id, user_id)
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# CRUD groupes
# ---------------------------------------------------------------------------

def creer_groupe(nom: str, description: str = "") -> bool:
    initialiser_db()
    try:
        _execute(
            "INSERT INTO groupes (nom, description, cree_le) VALUES (?, ?, ?)",
            (nom.strip(), description.strip(), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        return True
    except sqlite3.IntegrityError:
        return False


def supprimer_groupe(groupe_id: int):
    initialiser_db()
    with _connexion() as conn:
        conn.execute("DELETE FROM groupe_machines WHERE groupe_id = ?", (groupe_id,))
        conn.execute("DELETE FROM groupe_utilisateurs WHERE groupe_id = ?", (groupe_id,))
        conn.execute("DELETE FROM groupes WHERE id = ?", (groupe_id,))
        conn.commit()


def lister_groupes():
    initialiser_db()
    rows = _execute("SELECT * FROM groupes ORDER BY nom", fetch=True)
    return [dict(r) for r in rows] if rows else []


def obtenir_groupe(groupe_id: int):
    initialiser_db()
    rows = _execute("SELECT * FROM groupes WHERE id = ?", (groupe_id,), fetch=True)
    return dict(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# Machines dans un groupe
# ---------------------------------------------------------------------------

def ajouter_machine(groupe_id: int, machine: str):
    initialiser_db()
    try:
        _execute("INSERT INTO groupe_machines (groupe_id, machine) VALUES (?, ?)", (groupe_id, machine))
    except sqlite3.IntegrityError:
        pass


def retirer_machine(groupe_id: int, machine: str):
    _execute("DELETE FROM groupe_machines WHERE groupe_id = ? AND machine = ?", (groupe_id, machine))


def machines_du_groupe(groupe_id: int) -> set:
    initialiser_db()
    rows = _execute("SELECT machine FROM groupe_machines WHERE groupe_id = ?", (groupe_id,), fetch=True)
    return {r["machine"] for r in rows} if rows else set()


# ---------------------------------------------------------------------------
# Utilisateurs dans un groupe
# ---------------------------------------------------------------------------

def ajouter_utilisateur(groupe_id: int, user_id: int):
    initialiser_db()
    try:
        _execute("INSERT INTO groupe_utilisateurs (groupe_id, user_id) VALUES (?, ?)", (groupe_id, user_id))
    except sqlite3.IntegrityError:
        pass


def retirer_utilisateur(groupe_id: int, user_id: int):
    _execute("DELETE FROM groupe_utilisateurs WHERE groupe_id = ? AND user_id = ?", (groupe_id, user_id))


def utilisateurs_du_groupe(groupe_id: int) -> set:
    initialiser_db()
    rows = _execute("SELECT user_id FROM groupe_utilisateurs WHERE groupe_id = ?", (groupe_id,), fetch=True)
    return {r["user_id"] for r in rows} if rows else set()


def groupes_de_utilisateur(user_id: int) -> list:
    initialiser_db()
    rows = _execute("""
        SELECT g.* FROM groupes g
        JOIN groupe_utilisateurs gu ON gu.groupe_id = g.id
        WHERE gu.user_id = ?
        ORDER BY g.nom
    """, (user_id,), fetch=True)
    return [dict(r) for r in rows] if rows else []


def machines_via_groupes(user_id: int) -> set:
    """Union des machines de TOUS les groupes dont cet utilisateur est
    membre — c'est la fonction que assignations.py appelle pour combiner
    avec les assignations individuelles directes."""
    initialiser_db()
    rows = _execute("""
        SELECT DISTINCT gm.machine FROM groupe_machines gm
        JOIN groupe_utilisateurs gu ON gu.groupe_id = gm.groupe_id
        WHERE gu.user_id = ?
    """, (user_id,), fetch=True)
    return {r["machine"] for r in rows} if rows else set()


# ---------------------------------------------------------------------------
# Page d'administration
# ---------------------------------------------------------------------------

groupes_bp = Blueprint("groupes", __name__)

_PAGE_LISTE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Groupes</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:820px;margin:0 auto}
  a{color:#3b82f6}
  .msg{color:#4ade80;margin-bottom:1rem}
  input{padding:.5rem;border-radius:6px;border:1px solid #333;background:#1a1d24;color:#e6e6e6;margin-right:.4rem}
  button{padding:.5rem 1rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer}
  .danger{background:#e01e5a}
  .carte{background:#1a1d24;border:1px solid #2a2d34;border-radius:8px;padding:1rem 1.2rem;margin:1rem 0;
         display:flex;justify-content:space-between;align-items:center}
  .carte h3{margin:0 0 .2rem}
  .carte p{margin:0;color:#9aa0aa;font-size:.85rem}
  .vide{color:#9aa0aa}
</style></head><body>
<p><a href="{{ url_for('accueil') }}">&larr; Retour au dashboard</a></p>
<h1>Groupes</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

<h3>Nouveau groupe</h3>
<form method="post" action="{{ url_for('groupes.creer_route') }}">
  <input name="nom" placeholder="ex. equipe-reseau" required>
  <input name="description" placeholder="description (optionnel)" style="width:280px">
  <button type="submit">Creer</button>
</form>

{% if groupes %}
  {% for g in groupes %}
  <div class="carte">
    <div>
      <h3>{{ g.nom }}</h3>
      <p>{{ g.description or 'Pas de description' }} — {{ g.nb_machines }} machine(s), {{ g.nb_utilisateurs }} utilisateur(s)</p>
    </div>
    <div>
      <a href="{{ url_for('groupes.page_detail', groupe_id=g.id) }}"><button type="button">Gerer</button></a>
      <form method="post" action="{{ url_for('groupes.supprimer_route', groupe_id=g.id) }}" style="display:inline">
        <button type="submit" class="danger">Supprimer</button>
      </form>
    </div>
  </div>
  {% endfor %}
{% else %}
  <p class="vide">Aucun groupe pour le moment.</p>
{% endif %}
</body></html>
"""

_PAGE_DETAIL = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Groupe {{ groupe.nom }}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:820px;margin:0 auto}
  a{color:#3b82f6}
  .msg{color:#4ade80;margin-bottom:1rem}
  .colonnes{display:flex;gap:1.5rem;margin-top:1.5rem}
  .colonne{flex:1;background:#1a1d24;border:1px solid #2a2d34;border-radius:8px;padding:1rem 1.2rem}
  .colonne h3{margin-top:0}
  .item{display:flex;justify-content:space-between;align-items:center;padding:.4rem 0;border-bottom:1px solid #2a2d34}
  select,button{padding:.4rem .6rem;border-radius:6px;border:1px solid #333;background:#0f1115;color:#e6e6e6}
  button{background:#3b82f6;border:0;color:#fff;cursor:pointer}
  button.retirer{background:#e01e5a}
  .vide{color:#9aa0aa;font-size:.85rem}
  form.ajout{display:flex;gap:.4rem;margin-top:.8rem}
</style></head><body>
<p><a href="{{ url_for('groupes.page_liste') }}">&larr; Retour aux groupes</a></p>
<h1>{{ groupe.nom }}</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

<div class="colonnes">
  <div class="colonne">
    <h3>Machines</h3>
    {% for m in machines %}
      <div class="item">{{ m }}
        <form method="post" action="{{ url_for('groupes.retirer_machine_route', groupe_id=groupe.id) }}">
          <input type="hidden" name="machine" value="{{ m }}">
          <button type="submit" class="retirer">Retirer</button>
        </form>
      </div>
    {% else %}
      <p class="vide">Aucune machine dans ce groupe.</p>
    {% endfor %}
    {% if machines_disponibles %}
    <form class="ajout" method="post" action="{{ url_for('groupes.ajouter_machine_route', groupe_id=groupe.id) }}">
      <select name="machine">
        {% for m in machines_disponibles %}<option value="{{ m }}">{{ m }}</option>{% endfor %}
      </select>
      <button type="submit">Ajouter</button>
    </form>
    {% endif %}
  </div>

  <div class="colonne">
    <h3>Utilisateurs</h3>
    {% for u in utilisateurs_membres %}
      <div class="item">{{ u.username }}
        <form method="post" action="{{ url_for('groupes.retirer_utilisateur_route', groupe_id=groupe.id) }}">
          <input type="hidden" name="user_id" value="{{ u.id }}">
          <button type="submit" class="retirer">Retirer</button>
        </form>
      </div>
    {% else %}
      <p class="vide">Aucun utilisateur dans ce groupe.</p>
    {% endfor %}
    {% if utilisateurs_disponibles %}
    <form class="ajout" method="post" action="{{ url_for('groupes.ajouter_utilisateur_route', groupe_id=groupe.id) }}">
      <select name="user_id">
        {% for u in utilisateurs_disponibles %}<option value="{{ u.id }}">{{ u.username }}</option>{% endfor %}
      </select>
      <button type="submit">Ajouter</button>
    </form>
    {% endif %}
  </div>
</div>
</body></html>
"""


@groupes_bp.route("/admin/groupes")
@admin_required
def page_liste():
    groupes = lister_groupes()
    for g in groupes:
        g["nb_machines"] = len(machines_du_groupe(g["id"]))
        g["nb_utilisateurs"] = len(utilisateurs_du_groupe(g["id"]))
    return render_template_string(_PAGE_LISTE, groupes=groupes, msg=request.args.get("msg"))


@groupes_bp.route("/admin/groupes/creer", methods=["POST"])
@admin_required
def creer_route():
    nom = request.form.get("nom", "").strip()
    description = request.form.get("description", "").strip()
    if not nom:
        return redirect(url_for("groupes.page_liste", msg="Nom manquant."))
    if creer_groupe(nom, description):
        audit.consigner("creation_groupe", cible=nom)
        return redirect(url_for("groupes.page_liste", msg=f"Groupe '{nom}' cree."))
    return redirect(url_for("groupes.page_liste", msg=f"Le groupe '{nom}' existe deja."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/supprimer", methods=["POST"])
@admin_required
def supprimer_route(groupe_id):
    g = obtenir_groupe(groupe_id)
    supprimer_groupe(groupe_id)
    if g:
        audit.consigner("suppression_groupe", cible=g["nom"])
    return redirect(url_for("groupes.page_liste", msg="Groupe supprime."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>")
@admin_required
def page_detail(groupe_id):
    groupe = obtenir_groupe(groupe_id)
    if not groupe:
        return redirect(url_for("groupes.page_liste", msg="Groupe introuvable."))
    machines = sorted(machines_du_groupe(groupe_id))
    toutes_machines = [s["nom"] for s in historique.lister_serveurs()]
    machines_disponibles = [m for m in toutes_machines if m not in machines]

    membres_ids = utilisateurs_du_groupe(groupe_id)
    tous_users = auth.lister_utilisateurs()
    utilisateurs_membres = [u for u in tous_users if u["id"] in membres_ids]
    utilisateurs_disponibles = [u for u in tous_users if u["id"] not in membres_ids]

    return render_template_string(
        _PAGE_DETAIL, groupe=groupe, machines=machines,
        machines_disponibles=machines_disponibles,
        utilisateurs_membres=utilisateurs_membres,
        utilisateurs_disponibles=utilisateurs_disponibles,
        msg=request.args.get("msg"),
    )


@groupes_bp.route("/admin/groupes/<int:groupe_id>/machines/ajouter", methods=["POST"])
@admin_required
def ajouter_machine_route(groupe_id):
    machine = request.form.get("machine", "").strip()
    if machine:
        ajouter_machine(groupe_id, machine)
        g = obtenir_groupe(groupe_id)
        audit.consigner("ajout_machine_groupe", cible=g["nom"] if g else str(groupe_id), details=machine)
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg="Machine ajoutee."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/machines/retirer", methods=["POST"])
@admin_required
def retirer_machine_route(groupe_id):
    machine = request.form.get("machine", "").strip()
    if machine:
        retirer_machine(groupe_id, machine)
        g = obtenir_groupe(groupe_id)
        audit.consigner("retrait_machine_groupe", cible=g["nom"] if g else str(groupe_id), details=machine)
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg="Machine retiree."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/utilisateurs/ajouter", methods=["POST"])
@admin_required
def ajouter_utilisateur_route(groupe_id):
    user_id = request.form.get("user_id", type=int)
    if user_id:
        ajouter_utilisateur(groupe_id, user_id)
        g = obtenir_groupe(groupe_id)
        audit.consigner("ajout_utilisateur_groupe", cible=g["nom"] if g else str(groupe_id), details=f"user_id={user_id}")
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg="Utilisateur ajoute."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/utilisateurs/retirer", methods=["POST"])
@admin_required
def retirer_utilisateur_route(groupe_id):
    user_id = request.form.get("user_id", type=int)
    if user_id:
        retirer_utilisateur(groupe_id, user_id)
        g = obtenir_groupe(groupe_id)
        audit.consigner("retrait_utilisateur_groupe", cible=g["nom"] if g else str(groupe_id), details=f"user_id={user_id}")
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg="Utilisateur retire."))