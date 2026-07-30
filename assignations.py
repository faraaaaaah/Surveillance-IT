# -*- coding: utf-8 -*-
"""
Module Groupes — Accès par groupe plutôt que machine par machine
-------------------------------------------------------------------
Approche "niveau entreprise" : au lieu d'assigner chaque machine à chaque
utilisateur individuellement, on définit des groupes (ex. 'equipe-reseau',
'datacenter-tunis'), on met des machines DANS le groupe, et on met des
utilisateurs DANS le groupe. Un utilisateur voit l'union des machines de
TOUS les groupes dont il est membre.

Intégration avec provisionnement.py :
- Les prévisions ML sont générées par serveur
- Un utilisateur ne voit que les prévisions des machines de ses groupes
- Les administrateurs voient toutes les machines
"""

import os
import sqlite3
import threading
import time
from datetime import datetime
from contextlib import contextmanager

from flask import Blueprint, request, redirect, url_for, render_template_string, flash

import historique
import auth
from auth import admin_required, login_required
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
    """Initialise la base de données des groupes"""
    with _connexion() as conn:
        # Table des groupes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groupes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT UNIQUE NOT NULL,
                description TEXT,
                cree_le TEXT NOT NULL
            )
        """)
        
        # Table des machines par groupe
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groupe_machines (
                groupe_id INTEGER NOT NULL REFERENCES groupes(id) ON DELETE CASCADE,
                machine TEXT NOT NULL,
                UNIQUE(groupe_id, machine)
            )
        """)
        
        # Table des utilisateurs par groupe
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groupe_utilisateurs (
                groupe_id INTEGER NOT NULL REFERENCES groupes(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL,
                UNIQUE(groupe_id, user_id)
            )
        """)
        
        conn.commit()


# ============================================================================
# CRUD GROUPES
# ============================================================================

def creer_groupe(nom: str, description: str = "") -> bool:
    """Crée un nouveau groupe"""
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
    """Supprime un groupe et ses associations"""
    initialiser_db()
    with _connexion() as conn:
        conn.execute("DELETE FROM groupe_machines WHERE groupe_id = ?", (groupe_id,))
        conn.execute("DELETE FROM groupe_utilisateurs WHERE groupe_id = ?", (groupe_id,))
        conn.execute("DELETE FROM groupes WHERE id = ?", (groupe_id,))
        conn.commit()


def lister_groupes() -> list:
    """Liste tous les groupes"""
    initialiser_db()
    rows = _execute("SELECT * FROM groupes ORDER BY nom", fetch=True)
    return [dict(r) for r in rows] if rows else []


def obtenir_groupe(groupe_id: int) -> dict | None:
    """Récupère un groupe par son ID"""
    initialiser_db()
    rows = _execute("SELECT * FROM groupes WHERE id = ?", (groupe_id,), fetch=True)
    return dict(rows[0]) if rows else None


def modifier_groupe(groupe_id: int, nom: str, description: str = "") -> bool:
    """Modifie un groupe"""
    try:
        _execute(
            "UPDATE groupes SET nom = ?, description = ? WHERE id = ?",
            (nom.strip(), description.strip(), groupe_id)
        )
        return True
    except sqlite3.IntegrityError:
        return False


# ============================================================================
# MACHINES DANS UN GROUPE
# ============================================================================

def ajouter_machine(groupe_id: int, machine: str):
    """Ajoute une machine à un groupe"""
    initialiser_db()
    try:
        _execute("INSERT INTO groupe_machines (groupe_id, machine) VALUES (?, ?)", (groupe_id, machine))
    except sqlite3.IntegrityError:
        pass  # Déjà présente


def retirer_machine(groupe_id: int, machine: str):
    """Retire une machine d'un groupe"""
    _execute("DELETE FROM groupe_machines WHERE groupe_id = ? AND machine = ?", (groupe_id, machine))


def machines_du_groupe(groupe_id: int) -> set:
    """Récupère toutes les machines d'un groupe"""
    initialiser_db()
    rows = _execute("SELECT machine FROM groupe_machines WHERE groupe_id = ?", (groupe_id,), fetch=True)
    return {r["machine"] for r in rows} if rows else set()


def toutes_machines_avec_groupes() -> dict:
    """Récupère toutes les machines avec leurs groupes"""
    initialiser_db()
    rows = _execute("""
        SELECT gm.machine, g.nom as groupe_nom, g.id as groupe_id
        FROM groupe_machines gm
        JOIN groupes g ON g.id = gm.groupe_id
        ORDER BY gm.machine
    """, fetch=True)
    
    result = {}
    for r in rows:
        machine = r["machine"]
        if machine not in result:
            result[machine] = []
        result[machine].append({
            'groupe_id': r["groupe_id"],
            'groupe_nom': r["groupe_nom"]
        })
    return result


# ============================================================================
# UTILISATEURS DANS UN GROUPE
# ============================================================================

def ajouter_utilisateur(groupe_id: int, user_id: int):
    """Ajoute un utilisateur à un groupe"""
    initialiser_db()
    try:
        _execute("INSERT INTO groupe_utilisateurs (groupe_id, user_id) VALUES (?, ?)", (groupe_id, user_id))
    except sqlite3.IntegrityError:
        pass  # Déjà présent


def retirer_utilisateur(groupe_id: int, user_id: int):
    """Retire un utilisateur d'un groupe"""
    _execute("DELETE FROM groupe_utilisateurs WHERE groupe_id = ? AND user_id = ?", (groupe_id, user_id))


def utilisateurs_du_groupe(groupe_id: int) -> set:
    """Récupère tous les utilisateurs d'un groupe"""
    initialiser_db()
    rows = _execute("SELECT user_id FROM groupe_utilisateurs WHERE groupe_id = ?", (groupe_id,), fetch=True)
    return {r["user_id"] for r in rows} if rows else set()


def groupes_de_utilisateur(user_id: int) -> list:
    """Récupère tous les groupes d'un utilisateur"""
    initialiser_db()
    rows = _execute("""
        SELECT g.* FROM groupes g
        JOIN groupe_utilisateurs gu ON gu.groupe_id = g.id
        WHERE gu.user_id = ?
        ORDER BY g.nom
    """, (user_id,), fetch=True)
    return [dict(r) for r in rows] if rows else []


def machines_via_groupes(user_id: int) -> set:
    """
    Union des machines de TOUS les groupes dont l'utilisateur est membre.
    Cette fonction est appelée par assignations.py pour combiner
    avec les assignations individuelles directes.
    """
    initialiser_db()
    rows = _execute("""
        SELECT DISTINCT gm.machine FROM groupe_machines gm
        JOIN groupe_utilisateurs gu ON gu.groupe_id = gm.groupe_id
        WHERE gu.user_id = ?
    """, (user_id,), fetch=True)
    return {r["machine"] for r in rows} if rows else set()


# ============================================================================
# STATISTIQUES
# ============================================================================

def statistiques_groupes() -> dict:
    """Retourne des statistiques sur les groupes"""
    initialiser_db()
    
    total_groupes = len(lister_groupes())
    
    # Machines totales
    machines_rows = _execute("SELECT COUNT(DISTINCT machine) as total FROM groupe_machines", fetch=True)
    total_machines = machines_rows[0]["total"] if machines_rows else 0
    
    # Utilisateurs totaux
    users_rows = _execute("SELECT COUNT(DISTINCT user_id) as total FROM groupe_utilisateurs", fetch=True)
    total_utilisateurs = users_rows[0]["total"] if users_rows else 0
    
    return {
        'total_groupes': total_groupes,
        'total_machines': total_machines,
        'total_utilisateurs': total_utilisateurs
    }


# ============================================================================
# ROUTES FLASK
# ============================================================================

groupes_bp = Blueprint("groupes", __name__)

_PAGE_LISTE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Groupes - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + auth.TOKENS_CSS + """
  .grille-groupes{display:grid; grid-template-columns:repeat(auto-fill, minmax(320px,1fr)); gap:16px; margin:16px 0;}
  .carte-groupe{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px;}
  .carte-groupe h3{margin:0 0 6px; font-size:15px; display:flex; justify-content:space-between; align-items:center;}
  .carte-groupe .desc{color:var(--muted); font-size:12.5px; margin:0 0 10px;}
  .carte-groupe .stats{display:flex; gap:16px; font-size:12px; color:var(--muted); margin-bottom:10px;}
  .carte-groupe .stats span{display:flex; align-items:center; gap:4px;}
  .actions{display:flex; gap:6px; flex-wrap:wrap;}
  .btn{display:inline-block; padding:6px 14px; border-radius:6px; border:1px solid var(--border); 
       background:var(--panel2); color:var(--text); font-size:12px; cursor:pointer; text-decoration:none;}
  .btn-primary{background:var(--accent); color:#08131f; border-color:var(--accent);}
  .btn-danger{background:rgba(248,81,73,.12); color:var(--crit); border-color:rgba(248,81,73,.3);}
  .btn-small{padding:4px 10px; font-size:11px;}
  .stats-globales{display:grid; grid-template-columns:repeat(auto-fit, minmax(150px,1fr)); gap:12px; margin:16px 0 24px;}
  .stat-item{background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px; text-align:center;}
  .stat-item .nombre{font-size:24px; font-weight:700;}
  .stat-item .label{font-size:11px; color:var(--muted);}
  .vide{color:var(--muted); text-align:center; padding:40px 0;}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>👥 Groupes d'accès</h1>
    <p>Gérez les groupes d'utilisateurs et les machines qu'ils peuvent voir.</p>
  </div>

  <div class="stats-globales">
    <div class="stat-item">
      <div class="nombre">{{ stats.total_groupes }}</div>
      <div class="label">Groupes</div>
    </div>
    <div class="stat-item">
      <div class="nombre">{{ stats.total_machines }}</div>
      <div class="label">Machines assignées</div>
    </div>
    <div class="stat-item">
      <div class="nombre">{{ stats.total_utilisateurs }}</div>
      <div class="label">Utilisateurs</div>
    </div>
  </div>

  {% if msg %}
  <div class="toast">{{ msg }}</div>
  {% endif %}

  <div class="carte">
    <h3 style="margin:0 0 12px;">Créer un nouveau groupe</h3>
    <form method="post" action="{{ url_for('groupes.creer_route') }}" style="display:flex; gap:10px; flex-wrap:wrap;">
      <input name="nom" placeholder="Nom du groupe (ex: equipe-reseau)" required style="flex:1; min-width:200px;">
      <input name="description" placeholder="Description (optionnel)" style="flex:2; min-width:250px;">
      <button type="submit" class="btn btn-primary">+ Créer</button>
    </form>
  </div>

  {% if groupes %}
  <div class="grille-groupes">
    {% for g in groupes %}
    <div class="carte-groupe">
      <h3>
        <span>{{ g.nom }}</span>
        <span style="font-size:11px; color:var(--muted); font-weight:normal;">
          #{{ g.id }}
        </span>
      </h3>
      <p class="desc">{{ g.description or 'Aucune description' }}</p>
      <div class="stats">
        <span>🖥️ {{ g.nb_machines }} machine(s)</span>
        <span>👤 {{ g.nb_utilisateurs }} utilisateur(s)</span>
        <span>📅 {{ g.cree_le[:10] }}</span>
      </div>
      <div class="actions">
        <a href="{{ url_for('groupes.page_detail', groupe_id=g.id) }}" class="btn btn-primary btn-small">Gérer</a>
        <form method="post" action="{{ url_for('groupes.supprimer_route', groupe_id=g.id) }}" style="display:inline;" 
              onsubmit="return confirm('Supprimer le groupe {{ g.nom }} ?');">
          <button type="submit" class="btn btn-danger btn-small">Supprimer</button>
        </form>
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="vide">
    <div style="font-size:48px; margin-bottom:12px;">👥</div>
    <p>Aucun groupe pour le moment.</p>
    <p style="font-size:13px;">Créez votre premier groupe ci-dessus pour commencer à organiser vos utilisateurs et machines.</p>
  </div>
  {% endif %}
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
  .deux-colonnes{display:grid; grid-template-columns:1fr 1fr; gap:20px; margin:16px 0;}
  .colonne{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px;}
  .colonne h3{margin:0 0 12px; font-size:14px; display:flex; justify-content:space-between; align-items:center;}
  .colonne .badge{font-size:11px; font-weight:normal; background:var(--panel2); padding:2px 10px; border-radius:10px; color:var(--muted);}
  .item{display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border);}
  .item:last-child{border-bottom:none;}
  .item .nom{font-size:13px;}
  .item .tag{font-size:11px; color:var(--muted); background:var(--panel2); padding:2px 8px; border-radius:4px;}
  .btn-small{padding:4px 10px; font-size:11px; border-radius:4px; border:1px solid var(--border); background:var(--panel2); color:var(--text); cursor:pointer;}
  .btn-danger-small{padding:4px 10px; font-size:11px; border-radius:4px; border:1px solid rgba(248,81,73,.3); background:rgba(248,81,73,.1); color:var(--crit); cursor:pointer;}
  .btn-primary-small{padding:4px 10px; font-size:11px; border-radius:4px; border:1px solid var(--accent); background:var(--accent); color:#08131f; cursor:pointer;}
  .form-ajout{display:flex; gap:8px; margin-top:12px; flex-wrap:wrap;}
  .form-ajout select{flex:1; min-width:120px; padding:6px 8px; border-radius:6px; border:1px solid var(--border); background:var(--bg); color:var(--text);}
  .vide-item{color:var(--muted); font-size:13px; padding:12px 0;}
  .retour{margin-bottom:16px;}
  .retour a{color:var(--accent); text-decoration:none;}
  .infos-groupe{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px 18px; margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;}
  .infos-groupe .titre{font-size:18px; font-weight:700;}
  .infos-groupe .desc{color:var(--muted); font-size:13px;}
  @media (max-width: 768px){ .deux-colonnes{grid-template-columns:1fr;} }
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="retour">
    <a href="{{ url_for('groupes.page_liste') }}">&larr; Retour aux groupes</a>
  </div>

  <div class="infos-groupe">
    <div>
      <div class="titre">👥 {{ groupe.nom }}</div>
      <div class="desc">{{ groupe.description or 'Aucune description' }}</div>
    </div>
    <div style="font-size:13px; color:var(--muted);">
      Créé le {{ groupe.cree_le[:10] }}
    </div>
  </div>

  {% if msg %}
  <div class="toast">{{ msg }}</div>
  {% endif %}

  <div class="deux-colonnes">
    <!-- Colonne Machines -->
    <div class="colonne">
      <h3>
        🖥️ Machines
        <span class="badge">{{ machines|length }}</span>
      </h3>
      
      {% if machines %}
        {% for m in machines %}
        <div class="item">
          <span class="nom">{{ m }}</span>
          <form method="post" action="{{ url_for('groupes.retirer_machine_route', groupe_id=groupe.id) }}" style="display:inline;">
            <input type="hidden" name="machine" value="{{ m }}">
            <button type="submit" class="btn-danger-small" onclick="return confirm('Retirer {{ m }} du groupe ?');">✕ Retirer</button>
          </form>
        </div>
        {% endfor %}
      {% else %}
        <div class="vide-item">Aucune machine dans ce groupe</div>
      {% endif %}
      
      {% if machines_disponibles %}
      <form class="form-ajout" method="post" action="{{ url_for('groupes.ajouter_machine_route', groupe_id=groupe.id) }}">
        <select name="machine">
          {% for m in machines_disponibles %}
          <option value="{{ m }}">{{ m }}</option>
          {% endfor %}
        </select>
        <button type="submit" class="btn-primary-small">+ Ajouter</button>
      </form>
      {% endif %}
    </div>

    <!-- Colonne Utilisateurs -->
    <div class="colonne">
      <h3>
        👤 Utilisateurs
        <span class="badge">{{ utilisateurs_membres|length }}</span>
      </h3>
      
      {% if utilisateurs_membres %}
        {% for u in utilisateurs_membres %}
        <div class="item">
          <span class="nom">{{ u.username }} <span class="tag">{{ u.role }}</span></span>
          <form method="post" action="{{ url_for('groupes.retirer_utilisateur_route', groupe_id=groupe.id) }}" style="display:inline;">
            <input type="hidden" name="user_id" value="{{ u.id }}">
            <button type="submit" class="btn-danger-small" onclick="return confirm('Retirer {{ u.username }} du groupe ?');">✕ Retirer</button>
          </form>
        </div>
        {% endfor %}
      {% else %}
        <div class="vide-item">Aucun utilisateur dans ce groupe</div>
      {% endif %}
      
      {% if utilisateurs_disponibles %}
      <form class="form-ajout" method="post" action="{{ url_for('groupes.ajouter_utilisateur_route', groupe_id=groupe.id) }}">
        <select name="user_id">
          {% for u in utilisateurs_disponibles %}
          <option value="{{ u.id }}">{{ u.username }} ({{ u.role }})</option>
          {% endfor %}
        </select>
        <button type="submit" class="btn-primary-small">+ Ajouter</button>
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
    """Page de liste des groupes"""
    groupes = lister_groupes()
    for g in groupes:
        g["nb_machines"] = len(machines_du_groupe(g["id"]))
        g["nb_utilisateurs"] = len(utilisateurs_du_groupe(g["id"]))
    
    stats = statistiques_groupes()
    
    return render_template_string(
        _PAGE_LISTE,
        groupes=groupes,
        stats=stats,
        msg=request.args.get("msg")
    )


@groupes_bp.route("/admin/groupes/creer", methods=["POST"])
@admin_required
def creer_route():
    """Crée un nouveau groupe"""
    nom = request.form.get("nom", "").strip()
    description = request.form.get("description", "").strip()
    
    if not nom:
        return redirect(url_for("groupes.page_liste", msg="Nom du groupe requis."))
    
    if creer_groupe(nom, description):
        audit.consigner("creation_groupe", cible=nom)
        return redirect(url_for("groupes.page_liste", msg=f" Groupe '{nom}' créé."))
    
    return redirect(url_for("groupes.page_liste", msg=f" Le groupe '{nom}' existe déjà."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/supprimer", methods=["POST"])
@admin_required
def supprimer_route(groupe_id):
    """Supprime un groupe"""
    g = obtenir_groupe(groupe_id)
    supprimer_groupe(groupe_id)
    if g:
        audit.consigner("suppression_groupe", cible=g["nom"])
    return redirect(url_for("groupes.page_liste", msg=f" Groupe '{g['nom'] if g else ''}' supprimé."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>")
@admin_required
def page_detail(groupe_id):
    """Page de détail d'un groupe"""
    groupe = obtenir_groupe(groupe_id)
    if not groupe:
        return redirect(url_for("groupes.page_liste", msg=" Groupe introuvable."))
    
    machines = sorted(machines_du_groupe(groupe_id))
    toutes_machines = [s["nom"] for s in historique.lister_serveurs()]
    machines_disponibles = [m for m in toutes_machines if m not in machines]
    
    membres_ids = utilisateurs_du_groupe(groupe_id)
    tous_users = auth.lister_utilisateurs()
    utilisateurs_membres = [u for u in tous_users if u["id"] in membres_ids]
    utilisateurs_disponibles = [u for u in tous_users if u["id"] not in membres_ids]
    
    return render_template_string(
        _PAGE_DETAIL,
        groupe=groupe,
        machines=machines,
        machines_disponibles=machines_disponibles,
        utilisateurs_membres=utilisateurs_membres,
        utilisateurs_disponibles=utilisateurs_disponibles,
        msg=request.args.get("msg")
    )


@groupes_bp.route("/admin/groupes/<int:groupe_id>/machines/ajouter", methods=["POST"])
@admin_required
def ajouter_machine_route(groupe_id):
    """Ajoute une machine à un groupe"""
    machine = request.form.get("machine", "").strip()
    if machine:
        ajouter_machine(groupe_id, machine)
        g = obtenir_groupe(groupe_id)
        audit.consigner("ajout_machine_groupe", cible=g["nom"] if g else str(groupe_id), details=machine)
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg=f" Machine '{machine}' ajoutée."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/machines/retirer", methods=["POST"])
@admin_required
def retirer_machine_route(groupe_id):
    """Retire une machine d'un groupe"""
    machine = request.form.get("machine", "").strip()
    if machine:
        retirer_machine(groupe_id, machine)
        g = obtenir_groupe(groupe_id)
        audit.consigner("retrait_machine_groupe", cible=g["nom"] if g else str(groupe_id), details=machine)
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg=f" Machine '{machine}' retirée."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/utilisateurs/ajouter", methods=["POST"])
@admin_required
def ajouter_utilisateur_route(groupe_id):
    """Ajoute un utilisateur à un groupe"""
    user_id = request.form.get("user_id", type=int)
    if user_id:
        ajouter_utilisateur(groupe_id, user_id)
        g = obtenir_groupe(groupe_id)
        user = auth._get_user_by_id(user_id)
        audit.consigner("ajout_utilisateur_groupe", cible=g["nom"] if g else str(groupe_id), 
                       details=f"user={user['username'] if user else user_id}")
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg=" Utilisateur ajouté."))


@groupes_bp.route("/admin/groupes/<int:groupe_id>/utilisateurs/retirer", methods=["POST"])
@admin_required
def retirer_utilisateur_route(groupe_id):
    """Retire un utilisateur d'un groupe"""
    user_id = request.form.get("user_id", type=int)
    if user_id:
        retirer_utilisateur(groupe_id, user_id)
        g = obtenir_groupe(groupe_id)
        user = auth._get_user_by_id(user_id)
        audit.consigner("retrait_utilisateur_groupe", cible=g["nom"] if g else str(groupe_id),
                       details=f"user={user['username'] if user else user_id}")
    return redirect(url_for("groupes.page_detail", groupe_id=groupe_id, msg=" Utilisateur retiré."))