# -*- coding: utf-8 -*-
"""
Module Auth — Comptes utilisateurs, sessions et controle d'acces
------------------------------------------------------------------
ZERO CONFIGURATION : rien a taper en ligne de commande, aucune variable
d'environnement a definir pour que ca marche. Tout s'initialise tout seul
au premier demarrage :

  - Un compte admin par defaut est cree automatiquement s'il n'existe
    encore AUCUN utilisateur (identifiants ci-dessous). Il doit changer
    son mot de passe des la premiere connexion (ecran impose, impossible
    a contourner tant que ce n'est pas fait).
  - La cle secrete de session (necessaire pour que les connexions restent
    valides) est generee une fois puis sauvegardee dans un fichier sur le
    meme volume persistant que la base de donnees — donc stable au fil des
    redemarrages du pod, sans avoir a la definir soi-meme.
  - Pas de "signup" public ensuite : seul un admin peut creer d'autres
    comptes, depuis /admin/utilisateurs (dans le navigateur).

    IDENTIFIANTS PAR DEFAUT (premiere connexion uniquement) :
        identifiant : admin
        mot de passe : ChangeMoi123!
    -> Le changement de mot de passe est obligatoire des la 1ere connexion.

Integration minimale dans dash.py :

    import auth
    app.secret_key = auth.obtenir_secret_key()
    auth.init_login_manager(app)
    app.register_blueprint(auth.auth_bp)

    @app.before_request
    def _proteger_routes():
        return auth.verifier_acces()
"""

import os
import sqlite3
import secrets
import time
import threading
from datetime import datetime
from contextlib import contextmanager
from functools import wraps

from flask import (
    Blueprint, request, redirect, url_for, session,
    render_template_string, flash, jsonify
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

import historique  # reutilise le meme DOSSIER_DATA (donc le meme PVC)

CHEMIN_DB = os.path.join(historique.DOSSIER_DATA, "auth.db")

# Routes accessibles SANS etre connecte. Tout le reste du site passe par
# verifier_acces() (voir dash.py) et redirige vers /login sinon.
ROUTES_PUBLIQUES = {"auth.login", "static"}

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
    max_retries = 3
    for tentative in range(max_retries):
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
            if "database is locked" in str(e) and tentative < max_retries - 1:
                time.sleep(0.5 * (tentative + 1))
                continue
            raise


def initialiser_db():
    with _connexion() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                actif INTEGER NOT NULL DEFAULT 1,
                doit_changer_mdp INTEGER NOT NULL DEFAULT 0,
                cree_le TEXT NOT NULL
            )
        """)
        colonnes = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        if "doit_changer_mdp" not in colonnes:
            conn.execute("ALTER TABLE users ADD COLUMN doit_changer_mdp INTEGER NOT NULL DEFAULT 0")
        conn.commit()


def obtenir_secret_key() -> str:
    """Cle secrete de session Flask, generee UNE fois puis sauvegardee dans
    un fichier sur le meme volume persistant que la base de donnees. Aucune
    variable d'environnement a definir : stable au fil des redemarrages du
    pod tant que le PVC reste attache, exactement comme la base SQLite."""
    chemin = os.path.join(historique.DOSSIER_DATA, "secret.key")
    if os.path.exists(chemin):
        with open(chemin, "r") as f:
            cle = f.read().strip()
            if cle:
                return cle
    cle = secrets.token_hex(32)
    with open(chemin, "w") as f:
        f.write(cle)
    return cle


# ---------------------------------------------------------------------------
# CRUD utilisateurs
# ---------------------------------------------------------------------------

def creer_utilisateur(username: str, mot_de_passe: str, role: str = "user",
                       forcer_changement: bool = True) -> bool:
    """Cree un utilisateur. Retourne False si le nom existe deja.
    forcer_changement=True (par defaut) : l'utilisateur devra changer son
    mot de passe des sa premiere connexion — utile quand c'est l'admin qui
    choisit un mot de passe temporaire pour quelqu'un d'autre."""
    initialiser_db()
    if role not in ("admin", "user"):
        raise ValueError("role doit etre 'admin' ou 'user'")
    try:
        _execute(
            "INSERT INTO users (username, password_hash, role, doit_changer_mdp, cree_le) "
            "VALUES (?, ?, ?, ?, ?)",
            (username.strip(), generate_password_hash(mot_de_passe), role,
             1 if forcer_changement else 0,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        return True
    except sqlite3.IntegrityError:
        return False


def verifier_identifiants(username: str, mot_de_passe: str):
    """Retourne la ligne utilisateur si les identifiants sont valides et le
    compte actif, sinon None."""
    initialiser_db()
    rows = _execute(
        "SELECT * FROM users WHERE username = ? AND actif = 1",
        (username.strip(),), fetch=True,
    )
    if not rows:
        return None
    row = rows[0]
    if check_password_hash(row["password_hash"], mot_de_passe):
        return row
    return None


def lister_utilisateurs():
    initialiser_db()
    rows = _execute(
        "SELECT id, username, role, actif, doit_changer_mdp, cree_le FROM users ORDER BY username",
        fetch=True,
    )
    return [dict(r) for r in rows] if rows else []


def changer_role(user_id: int, role: str):
    if role not in ("admin", "user"):
        raise ValueError("role doit etre 'admin' ou 'user'")
    _execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def desactiver_utilisateur(user_id: int):
    """Desactive plutot que supprimer : garde une trace de qui avait acces."""
    _execute("UPDATE users SET actif = 0 WHERE id = ?", (user_id,))


def reactiver_utilisateur(user_id: int):
    _execute("UPDATE users SET actif = 1 WHERE id = ?", (user_id,))


def changer_mot_de_passe(user_id: int, nouveau_mdp: str):
    _execute("UPDATE users SET password_hash = ? WHERE id = ?",
              (generate_password_hash(nouveau_mdp), user_id))


def _get_user_by_id(user_id: int):
    initialiser_db()
    rows = _execute("SELECT * FROM users WHERE id = ?", (user_id,), fetch=True)
    return dict(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# Integration Flask-Login
# ---------------------------------------------------------------------------

class Utilisateur(UserMixin):
    def __init__(self, row: dict):
        self.id = str(row["id"])
        self.username = row["username"]
        self.role = row["role"]
        self.actif = bool(row["actif"])
        self.doit_changer_mdp = bool(row["doit_changer_mdp"])

    def get_id(self):
        return self.id

    @property
    def is_active(self):
        return self.actif

    @property
    def is_admin(self):
        return self.role == "admin"


login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def _charger_utilisateur(user_id):
    row = _get_user_by_id(int(user_id))
    if not row or not row["actif"]:
        return None
    return Utilisateur(row)


def init_login_manager(app):
    initialiser_db()
    login_manager.init_app(app)


IDENTIFIANT_ADMIN_DEFAUT = "admin"
MOT_DE_PASSE_ADMIN_DEFAUT = "ChangeMoi123!"


def bootstrap_admin_auto():
    """Cree automatiquement un compte admin par defaut au tout premier
    demarrage — RIEN a configurer, rien a taper. Ne fait quelque chose que
    si la base ne contient encore AUCUN utilisateur (donc sans danger a
    chaque redemarrage du pod ensuite : des qu'un compte existe, cette
    fonction ne touche plus a rien).

    Le compte cree DOIT changer son mot de passe des la premiere connexion
    (voir doit_changer_mdp / verifier_acces)."""
    initialiser_db()
    if lister_utilisateurs():
        return
    creer_utilisateur(IDENTIFIANT_ADMIN_DEFAUT, MOT_DE_PASSE_ADMIN_DEFAUT,
                       role="admin", forcer_changement=True)
    print(f"✅ Compte admin par defaut cree automatiquement "
          f"({IDENTIFIANT_ADMIN_DEFAUT} / {MOT_DE_PASSE_ADMIN_DEFAUT}) — "
          f"changement de mot de passe obligatoire a la 1ere connexion.")


def admin_par_defaut_pas_encore_change() -> bool:
    """True si le compte admin par defaut existe toujours avec son mot de
    passe d'origine — pour afficher le rappel sur la page de connexion."""
    initialiser_db()
    rows = _execute(
        "SELECT doit_changer_mdp FROM users WHERE username = ?",
        (IDENTIFIANT_ADMIN_DEFAUT,), fetch=True,
    )
    return bool(rows and rows[0]["doit_changer_mdp"])


def verifier_acces():
    """A brancher sur @app.before_request. Laisse passer les routes
    publiques (login, fichiers statiques) ; redirige vers /login sinon ;
    et impose le changement de mot de passe tant que doit_changer_mdp est
    actif (impossible d'atteindre le reste du site avant de l'avoir fait)."""
    endpoint = request.endpoint or ""
    if endpoint in ROUTES_PUBLIQUES:
        return None
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login", suivant=request.path))
    if current_user.doit_changer_mdp and endpoint not in (
        "auth.changer_mot_de_passe_route", "auth.logout"
    ):
        return redirect(url_for("auth.changer_mot_de_passe_route"))
    return None


def admin_required(fonction):
    """Decorateur pour les routes reservees aux admins (a utiliser APRES
    @login_required, ou seul puisque verifier_acces() protege deja tout)."""
    @wraps(fonction)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if not current_user.is_admin:
            return "Acces reserve aux administrateurs.", 403
        return fonction(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes (Blueprint)
# ---------------------------------------------------------------------------

auth_bp = Blueprint("auth", __name__)

_PAGE_LOGIN = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Connexion - Monitoring</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
  form{background:#1a1d24;padding:2rem 2.5rem;border-radius:10px;min-width:280px}
  h1{font-size:1.2rem;margin:0 0 1.2rem}
  input{width:100%;padding:.6rem;margin:.4rem 0 1rem;border-radius:6px;
        border:1px solid #333;background:#0f1115;color:#e6e6e6;box-sizing:border-box}
  button{width:100%;padding:.6rem;border:0;border-radius:6px;background:#3b82f6;
         color:#fff;font-weight:600;cursor:pointer}
  .erreur{color:#f87171;font-size:.9rem;margin-bottom:.8rem}
  .rappel{background:#1e2530;border:1px solid #2a3a52;border-radius:6px;
          padding:.7rem .9rem;font-size:.82rem;color:#9aa0aa;margin-bottom:1rem;line-height:1.5}
  .rappel code{color:#e6e6e6}
</style></head><body>
<form method="post">
  <h1>🔒 Connexion au monitoring</h1>
  {% if premiere_fois %}
  <div class="rappel">Premier acces : <code>{{ identifiant_defaut }}</code> /
  <code>{{ mdp_defaut }}</code><br>Le mot de passe sera a changer immediatement.</div>
  {% endif %}
  {% if erreur %}<div class="erreur">{{ erreur }}</div>{% endif %}
  <label>Identifiant</label>
  <input name="username" autofocus required>
  <label>Mot de passe</label>
  <input name="password" type="password" required>
  <button type="submit">Se connecter</button>
</form></body></html>
"""


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("accueil"))
    erreur = None
    if request.method == "POST":
        username = request.form.get("username", "")
        mot_de_passe = request.form.get("password", "")
        row = verifier_identifiants(username, mot_de_passe)
        if row:
            login_user(Utilisateur(dict(row)))
            suivant = request.args.get("suivant") or url_for("accueil")
            return redirect(suivant)
        erreur = "Identifiant ou mot de passe incorrect."
    return render_template_string(
        _PAGE_LOGIN, erreur=erreur,
        premiere_fois=admin_par_defaut_pas_encore_change(),
        identifiant_defaut=IDENTIFIANT_ADMIN_DEFAUT,
        mdp_defaut=MOT_DE_PASSE_ADMIN_DEFAUT,
    )


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


_PAGE_CHANGER_MDP = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Changer le mot de passe</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
  form{background:#1a1d24;padding:2rem 2.5rem;border-radius:10px;min-width:300px}
  h1{font-size:1.15rem;margin:0 0 .5rem}
  p{color:#9aa0aa;font-size:.85rem;margin:0 0 1.2rem}
  input{width:100%;padding:.6rem;margin:.4rem 0 1rem;border-radius:6px;
        border:1px solid #333;background:#0f1115;color:#e6e6e6;box-sizing:border-box}
  button{width:100%;padding:.6rem;border:0;border-radius:6px;background:#3b82f6;
         color:#fff;font-weight:600;cursor:pointer}
  .erreur{color:#f87171;font-size:.9rem;margin-bottom:.8rem}
</style></head><body>
<form method="post">
  <h1>🔑 Nouveau mot de passe requis</h1>
  <p>Premiere connexion (ou mot de passe reinitialise par un admin) :
  choisissez un mot de passe personnel avant de continuer.</p>
  {% if erreur %}<div class="erreur">{{ erreur }}</div>{% endif %}
  <input name="nouveau" type="password" placeholder="nouveau mot de passe (8 caracteres min.)" required>
  <input name="confirmation" type="password" placeholder="confirmer le mot de passe" required>
  <button type="submit">Valider</button>
</form></body></html>
"""


@auth_bp.route("/changer-mot-de-passe", methods=["GET", "POST"])
@login_required
def changer_mot_de_passe_route():
    erreur = None
    if request.method == "POST":
        nouveau = request.form.get("nouveau", "")
        confirmation = request.form.get("confirmation", "")
        if len(nouveau) < 8:
            erreur = "8 caracteres minimum."
        elif nouveau != confirmation:
            erreur = "Les deux mots de passe ne correspondent pas."
        else:
            changer_mot_de_passe(int(current_user.id), nouveau)
            _execute("UPDATE users SET doit_changer_mdp = 0 WHERE id = ?", (int(current_user.id),))
            return redirect(url_for("accueil"))
    return render_template_string(_PAGE_CHANGER_MDP, erreur=erreur)


_PAGE_ADMIN_USERS = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Gestion des utilisateurs</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:760px;margin:0 auto}
  a{color:#3b82f6}
  table{width:100%;border-collapse:collapse;margin-top:1rem}
  th,td{padding:.5rem;border-bottom:1px solid #2a2d34;text-align:left}
  form.inline{display:inline}
  input,select{padding:.4rem;border-radius:6px;border:1px solid #333;background:#1a1d24;color:#e6e6e6}
  button{padding:.4rem .8rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer}
  .danger{background:#e01e5a}
  .badge{padding:.1rem .5rem;border-radius:4px;font-size:.8rem}
  .badge.admin{background:#3b82f6}
  .badge.user{background:#333}
  .msg{color:#4ade80;margin-bottom:1rem}
</style></head><body>
<p><a href="{{ url_for('accueil') }}">&larr; Retour au dashboard</a></p>
<h1>Gestion des utilisateurs</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

<h3>Nouveau compte</h3>
<form method="post" action="{{ url_for('auth.admin_creer_utilisateur') }}">
  <input name="username" placeholder="identifiant" required>
  <input name="password" type="password" placeholder="mot de passe" required>
  <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
  <button type="submit">Creer</button>
</form>

<table>
<tr><th>Identifiant</th><th>Role</th><th>Statut</th><th>Cree le</th><th>Actions</th></tr>
{% for u in utilisateurs %}
<tr>
  <td>{{ u.username }}{% if u.doit_changer_mdp %} <span class="badge" style="background:#d97706;">mdp a changer</span>{% endif %}</td>
  <td><span class="badge {{ u.role }}">{{ u.role }}</span></td>
  <td>{{ 'actif' if u.actif else 'desactive' }}</td>
  <td>{{ u.cree_le }}</td>
  <td>
    {% if u.username != current_username %}
    <form class="inline" method="post" action="{{ url_for('auth.admin_changer_role', user_id=u.id) }}">
      <input type="hidden" name="role" value="{{ 'user' if u.role == 'admin' else 'admin' }}">
      <button type="submit">Passer {{ 'user' if u.role == 'admin' else 'admin' }}</button>
    </form>
    <form class="inline" method="post" action="{{ url_for('auth.admin_toggle_actif', user_id=u.id) }}">
      <button type="submit" class="danger">{{ 'Desactiver' if u.actif else 'Reactiver' }}</button>
    </form>
    {% else %}
    <em>(vous)</em>
    {% endif %}
  </td>
</tr>
{% endfor %}
</table>
</body></html>
"""


@auth_bp.route("/admin/utilisateurs")
@admin_required
def admin_utilisateurs():
    return render_template_string(
        _PAGE_ADMIN_USERS,
        utilisateurs=lister_utilisateurs(),
        current_username=current_user.username,
        msg=request.args.get("msg"),
    )


@auth_bp.route("/admin/utilisateurs/creer", methods=["POST"])
@admin_required
def admin_creer_utilisateur():
    username = request.form.get("username", "").strip()
    mot_de_passe = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not mot_de_passe:
        return redirect(url_for("auth.admin_utilisateurs", msg="Champs manquants."))
    ok = creer_utilisateur(username, mot_de_passe, role)
    msg = f"Compte '{username}' cree." if ok else f"'{username}' existe deja."
    return redirect(url_for("auth.admin_utilisateurs", msg=msg))


@auth_bp.route("/admin/utilisateurs/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_changer_role(user_id):
    role = request.form.get("role", "user")
    changer_role(user_id, role)
    return redirect(url_for("auth.admin_utilisateurs", msg="Role mis a jour."))


@auth_bp.route("/admin/utilisateurs/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_actif(user_id):
    cible = _get_user_by_id(user_id)
    if cible:
        if cible["actif"]:
            desactiver_utilisateur(user_id)
        else:
            reactiver_utilisateur(user_id)
    return redirect(url_for("auth.admin_utilisateurs", msg="Statut mis a jour."))