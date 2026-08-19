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


def retirer_machine_partout(machine: str):
    """Retire une machine de TOUS les groupes. A appeler quand un serveur
    est supprime du dashboard, pour ne pas laisser une reference vers une
    machine qui n'existe plus dans les groupes existants."""
    initialiser_db()
    _execute("DELETE FROM groupe_machines WHERE machine = ?", (machine,))


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
<title>Groupes - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + auth.TOKENS_CSS + """
  .liste-groupes{display:flex; flex-direction:column; gap:12px;}
  .groupe-item{display:flex; justify-content:space-between; align-items:center;
               background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px 20px;}
  .groupe-item h3{margin:0 0 4px; font-size:14px;}
  .groupe-item p{margin:0; color:var(--muted); font-size:12.5px;}
  .groupe-actions{display:flex; gap:8px;}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>🗂️ Groupes</h1>
    <p>Regroupe des machines et des utilisateurs pour gerer les acces par lot plutot qu'un par un.</p>
  </div>

  {% if msg %}<div class="toast">{{ msg }}</div>{% endif %}

  <div class="carte">
    <h3>Nouveau groupe</h3>
    <p class="aide-carte">ex. equipe-reseau, datacenter-tunis…</p>
    <form method="post" action="{{ url_for('groupes.creer_route') }}">
      <div class="champs-form">
        <div class="champ"><label>Nom</label><input name="nom" placeholder="ex. equipe-reseau" required></div>
        <div class="champ"><label>Description</label><input name="description" placeholder="description (optionnel)"></div>
        <button type="submit" class="btn-principal">+ Creer</button>
      </div>
    </form>
  </div>

  <div class="carte">
    <h3 style="margin-bottom:14px;">Groupes existants</h3>
    {% if groupes %}
    <div class="liste-groupes">
      {% for g in groupes %}
      <div class="groupe-item">
        <div>
          <h3>{{ g.nom }}</h3>
          <p>{{ g.description or 'Pas de description' }} — {{ g.nb_machines }} machine(s), {{ g.nb_utilisateurs }} utilisateur(s)</p>
        </div>
        <div class="groupe-actions">
          <a href="{{ url_for('groupes.page_detail', groupe_id=g.id) }}"><button type="button" class="btn-fantome">Gerer</button></a>
          <form method="post" action="{{ url_for('groupes.supprimer_route', groupe_id=g.id) }}" style="display:inline"
                onsubmit="return confirm('Supprimer le groupe {{ g.nom }} ?');">
            <button type="submit" class="btn-danger">Supprimer</button>
          </form>
        </div>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <div class="vide-etat">Aucun groupe pour le moment.</div>
    {% endif %}
  </div>
</main>

<script>""" + auth.JS_TEMA_ET_MENU + """</script>
</body></html>
"""

_PAGE_DETAIL = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Groupe {{ groupe.nom }} - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + auth.TOKENS_CSS + """
  .colonnes{display:flex; gap:20px; flex-wrap:wrap;}
  .colonne{flex:1; min-width:280px;}
  .colonne h3{margin:0 0 12px; font-size:14px;}
  .item-liste{display:flex; justify-content:space-between; align-items:center; padding:10px 0;
              border-bottom:1px solid var(--border); font-size:13.5px;}
  .item-liste:last-of-type{border-bottom:none;}
  form.ajout{display:flex; gap:8px; margin-top:14px;}
  .lien-retour{display:inline-block; margin-bottom:14px; font-size:13px; color:var(--muted);}
  .lien-retour:hover{color:var(--text);}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <a class="lien-retour" href="{{ url_for('groupes.page_liste') }}">&larr; Retour aux groupes</a>
  <div class="page-entete">
    <h1>🗂️ {{ groupe.nom }}</h1>
    <p>{{ groupe.description or 'Pas de description' }}</p>
  </div>

  {% if msg %}<div class="toast">{{ msg }}</div>{% endif %}

  <div class="colonnes">
    <div class="carte colonne">
      <h3>Machines</h3>
      {% for m in machines %}
      <div class="item-liste">
        <span>{{ m }}</span>
        <form method="post" action="{{ url_for('groupes.retirer_machine_route', groupe_id=groupe.id) }}">
          <input type="hidden" name="machine" value="{{ m }}">
          <button type="submit" class="btn-danger">Retirer</button>
        </form>
      </div>
      {% else %}
      <div class="vide-etat">Aucune machine dans ce groupe.</div>
      {% endfor %}
      {% if machines_disponibles %}
      <form class="ajout" method="post" action="{{ url_for('groupes.ajouter_machine_route', groupe_id=groupe.id) }}">
        <select name="machine">
          {% for m in machines_disponibles %}<option value="{{ m }}">{{ m }}</option>{% endfor %}
        </select>
        <button type="submit" class="btn-principal">Ajouter</button>
      </form>
      {% endif %}
    </div>

    <div class="carte colonne">
      <h3>Utilisateurs</h3>
      {% for u in utilisateurs_membres %}
      <div class="item-liste">
        <span>{{ u.username }}</span>
        <form method="post" action="{{ url_for('groupes.retirer_utilisateur_route', groupe_id=groupe.id) }}">
          <input type="hidden" name="user_id" value="{{ u.id }}">
          <button type="submit" class="btn-danger">Retirer</button>
        </form>
      </div>
      {% else %}
      <div class="vide-etat">Aucun utilisateur dans ce groupe.</div>
      {% endfor %}
      {% if utilisateurs_disponibles %}
      <form class="ajout" method="post" action="{{ url_for('groupes.ajouter_utilisateur_route', groupe_id=groupe.id) }}">
        <select name="user_id">
          {% for u in utilisateurs_disponibles %}<option value="{{ u.id }}">{{ u.username }}</option>{% endfor %}
        </select>
        <button type="submit" class="btn-principal">Ajouter</button>
      </form>
      {% endif %}
    </div>
  </div>
</main>

<script>""" + auth.JS_TEMA_ET_MENU + """</script>
</body></html>
"""


@groupes_bp.route("/admin/groupes")
@admin_required
def page_liste():
    groupes = lister_groupes()
    for g in groupes:
        g["nb_machines"] = len(machines_du_groupe(g["id"]))
        g["nb_utilisateurs"] = len(utilisateurs_du_groupe(g["id"]))
    return render_template_string(
        _PAGE_LISTE, groupes=groupes, msg=request.args.get("msg"),
        topbar=auth.render_topbar("groupes"),
    )


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
        topbar=auth.render_topbar("groupes"),
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