# -*- coding: utf-8 -*-
"""
Module Assignations — Quelle machine chaque utilisateur peut voir
-------------------------------------------------------------------
Un compte 'user' ne doit voir QUE les machines qui lui sont accessibles ;
un compte 'admin' voit tout, sans restriction.

Une machine devient visible pour un 'user' de DEUX facons, combinees :
  1. Via un groupe (voir groupes.py) — l'approche normale/recommandee des
     qu'il y a plus de quelques machines ou utilisateurs : on gere des
     equipes, pas des cases a cocher individuelles.
  2. Via une assignation DIRECTE (ce module) — reservee aux exceptions
     ponctuelles (ex. un utilisateur qui a besoin d'une machine hors de
     son groupe habituel, temporairement).

Table stockee dans le meme auth.db que les comptes/responsables/config
email — geree depuis une page web /admin/assignations (aucune ligne de
commande, aucune variable d'environnement).
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
            CREATE TABLE IF NOT EXISTS assignations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                machine TEXT NOT NULL,
                cree_le TEXT NOT NULL,
                UNIQUE(user_id, machine)
            )
        """)
        conn.commit()


def assigner(user_id: int, machine: str):
    initialiser_db()
    try:
        _execute(
            "INSERT INTO assignations (user_id, machine, cree_le) VALUES (?, ?, ?)",
            (user_id, machine, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
    except sqlite3.IntegrityError:
        pass  # deja assignee, rien a faire


def retirer(user_id: int, machine: str):
    _execute("DELETE FROM assignations WHERE user_id = ? AND machine = ?", (user_id, machine))


def machines_de(user_id: int) -> set:
    initialiser_db()
    rows = _execute("SELECT machine FROM assignations WHERE user_id = ?", (user_id,), fetch=True)
    return {r["machine"] for r in rows} if rows else set()


def machines_autorisees(utilisateur) -> set | None:
    """None = pas de restriction (admin, voit tout).
    set() ou {machines...} = restriction stricte a l'union des machines
    obtenues via les groupes de l'utilisateur ET ses assignations directes
    (role 'user')."""
    if utilisateur.is_admin:
        return None
    import groupes  # import tardif : evite un cycle au chargement du module
    user_id = int(utilisateur.id)
    return machines_de(user_id) | groupes.machines_via_groupes(user_id)


# ---------------------------------------------------------------------------
# Page d'administration
# ---------------------------------------------------------------------------

assignations_bp = Blueprint("assignations", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Assignation des machines</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:820px;margin:0 auto}
  a{color:#3b82f6}
  .msg{color:#4ade80;margin-bottom:1rem}
  .bloc{background:#1a1d24;border:1px solid #2a2d34;border-radius:8px;padding:1rem 1.2rem;margin-bottom:1rem}
  .bloc h3{margin:0 0 .6rem;font-size:1rem}
  .machine{display:inline-flex;align-items:center;gap:.4rem;background:#14161b;border:1px solid #2a2d34;
           border-radius:6px;padding:.35rem .7rem;margin:.2rem .3rem .2rem 0}
  .machine.assignee{border-color:#3b82f6;background:rgba(59,130,246,.12)}
  .machine.via-groupe{border-color:#8b5cf6;background:rgba(139,92,246,.12)}
  button{padding:.3rem .7rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer;font-size:.8rem}
  button.retirer{background:#e01e5a}
  button[disabled]{opacity:.4;cursor:not-allowed}
  .vide{color:#9aa0aa;font-size:.85rem}
  .badge{padding:.1rem .5rem;border-radius:4px;font-size:.75rem;background:#333}
  .aide{background:#1a1d24;border:1px solid #2a2d34;border-radius:8px;padding:.8rem 1.1rem;font-size:.85rem;color:#9aa0aa;margin-bottom:1.2rem;line-height:1.5}
</style></head><body>
<p><a href="{{ url_for('accueil') }}">&larr; Retour au dashboard</a></p>
<h1>Assignation des machines</h1>
<div class="aide">
  Pour gerer l'acces d'une <b>equipe entiere</b> a un ensemble de machines, utilise plutot
  <a href="{{ url_for('groupes.page_liste') }}">les groupes</a> — plus simple des que tu as
  plusieurs utilisateurs ou plusieurs machines. Cette page sert pour des exceptions
  ponctuelles : donner UNE machine en plus a UN utilisateur, hors de son groupe habituel.
</div>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

{% for u in utilisateurs %}
<div class="bloc">
  <h3>{{ u.username }} <span class="badge">{{ u.role }}</span></h3>
  {% if u.role == 'admin' %}
    <p class="vide">Voit toutes les machines (admin).</p>
  {% elif toutes_machines %}
    {% for m in toutes_machines %}
      {% set assignee_directe = m in assignations.get(u.id, []) %}
      {% set via_groupe = m in via_groupes.get(u.id, []) %}
      <span class="machine {{ 'assignee' if assignee_directe else ('via-groupe' if via_groupe else '') }}">
        {{ m }}{% if via_groupe %} <span class="badge">groupe</span>{% endif %}
        {% if via_groupe and not assignee_directe %}
          <button disabled title="Deja visible via un groupe">deja visible</button>
        {% else %}
        <form method="post" style="display:inline;margin:0"
              action="{{ url_for('assignations.retirer_route' if assignee_directe else 'assignations.assigner_route', user_id=u.id) }}">
          <input type="hidden" name="machine" value="{{ m }}">
          <button type="submit" class="{{ 'retirer' if assignee_directe else '' }}">{{ '✕ Retirer' if assignee_directe else '+ Assigner' }}</button>
        </form>
        {% endif %}
      </span>
    {% endfor %}
  {% else %}
    <p class="vide">Aucune machine detectee pour le moment (attends qu'au moins une machine envoie des metriques).</p>
  {% endif %}
</div>
{% endfor %}
</body></html>
"""


@assignations_bp.route("/admin/assignations")
@admin_required
def page_assignations():
    import groupes
    utilisateurs = auth.lister_utilisateurs()
    toutes_machines = [s["nom"] for s in historique.lister_serveurs()]
    assignations_par_user = {u["id"]: machines_de(u["id"]) for u in utilisateurs}
    via_groupes_par_user = {u["id"]: groupes.machines_via_groupes(u["id"]) for u in utilisateurs}
    return render_template_string(
        _PAGE, utilisateurs=utilisateurs, toutes_machines=toutes_machines,
        assignations=assignations_par_user, via_groupes=via_groupes_par_user,
        msg=request.args.get("msg"),
    )


@assignations_bp.route("/admin/assignations/<int:user_id>/assigner", methods=["POST"])
@admin_required
def assigner_route(user_id):
    machine = request.form.get("machine", "").strip()
    if machine:
        assigner(user_id, machine)
        cible = auth._get_user_by_id(user_id)
        audit.consigner("assignation_machine_directe",
                         cible=cible["username"] if cible else str(user_id), details=machine)
    return redirect(url_for("assignations.page_assignations", msg=f"'{machine}' assignee."))


@assignations_bp.route("/admin/assignations/<int:user_id>/retirer", methods=["POST"])
@admin_required
def retirer_route(user_id):
    machine = request.form.get("machine", "").strip()
    if machine:
        retirer(user_id, machine)
        cible = auth._get_user_by_id(user_id)
        audit.consigner("retrait_machine_directe",
                         cible=cible["username"] if cible else str(user_id), details=machine)
    return redirect(url_for("assignations.page_assignations", msg=f"'{machine}' retiree."))