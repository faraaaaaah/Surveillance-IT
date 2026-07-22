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
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>SENTINEL - Connexion</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  /* === Thème sombre (par défaut) === */
  :root {
    --bg-primary: #0B0F14;
    --bg-secondary: #121820;
    --bg-card: #161D26;
    --bg-input: #0B0F14;
    --border-color: #1E2733;
    --text-primary: #E6EDF3;
    --text-secondary: #7C8B99;
    --text-muted: #4A5A6A;
    --accent: #58A6FF;
    --accent-hover: #79C0FF;
    --success: #3FB950;
    --danger: #F85149;
    --warning: #D29922;
    --shadow: rgba(0,0,0,0.5);
    --input-bg: #0B0F14;
    --transition: 0.3s ease;
  }

  /* === Thème clair === */
  body.light {
    --bg-primary: #EBEEF2;
    --bg-secondary: #F7F8FA;
    --bg-card: #EFF1F4;
    --bg-input: #F7F8FA;
    --border-color: #D8DDE3;
    --text-primary: #2B3138;
    --text-secondary: #6B7280;
    --text-muted: #9AA0A8;
    --accent: #2563EB;
    --accent-hover: #3B82F6;
    --shadow: rgba(0,0,0,0.12);
    --input-bg: #F7F8FA;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
    padding: 20px;
    transition: background var(--transition), color var(--transition);
  }

  /* === Conteneur principal === */
  .login-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    max-width: 420px;
    animation: fadeIn 0.6s ease;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* === Logo / En-tête === */
  .login-header {
    text-align: center;
    margin-bottom: 32px;
  }

  .login-header .logo {
    font-size: 48px;
    margin-bottom: 8px;
    display: block;
  }

  .login-header h1 {
    font-size: 26px;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: var(--text-primary);
  }

  .login-header .subtitle {
    font-size: 14px;
    color: var(--text-secondary);
    margin-top: 4px;
  }

  /* === Carte de connexion === */
  .login-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 36px 32px 32px;
    width: 100%;
    box-shadow: 0 8px 40px var(--shadow);
    transition: background var(--transition), border-color var(--transition), box-shadow var(--transition);
  }

  /* === Rappel premier accès === */
  .rappel {
    background: rgba(88, 166, 255, 0.08);
    border: 1px solid rgba(88, 166, 255, 0.2);
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 13px;
    line-height: 1.6;
    color: var(--text-secondary);
    margin-bottom: 20px;
    transition: all var(--transition);
  }

  .rappel strong {
    color: var(--accent);
  }

  .rappel code {
    background: var(--bg-primary);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--accent);
    font-family: 'JetBrains Mono', 'Consolas', monospace;
  }

  .rappel .warning-icon {
    color: var(--warning);
    margin-right: 6px;
  }

  /* === Messages d'erreur === */
  .erreur {
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid rgba(248, 81, 73, 0.25);
    border-radius: 10px;
    padding: 10px 14px;
    font-size: 13px;
    color: var(--danger);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    animation: shake 0.4s ease;
  }

  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-6px); }
    40% { transform: translateX(6px); }
    60% { transform: translateX(-4px); }
    80% { transform: translateX(4px); }
  }

  .erreur .icon {
    font-size: 18px;
    flex-shrink: 0;
  }

  /* === Champs du formulaire === */
  .form-group {
    margin-bottom: 18px;
  }

  .form-group label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 6px;
    letter-spacing: 0.3px;
  }

  .form-group .input-wrapper {
    position: relative;
  }

  .form-group input {
    width: 100%;
    padding: 12px 14px;
    font-size: 15px;
    font-family: inherit;
    background: var(--bg-input);
    border: 1.5px solid var(--border-color);
    border-radius: 10px;
    color: var(--text-primary);
    outline: none;
    transition: all var(--transition);
    box-sizing: border-box;
  }

  .form-group input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
    background: var(--bg-input);
  }

  .form-group input::placeholder {
    color: var(--text-muted);
    font-size: 14px;
  }

  .form-group input:-webkit-autofill {
    -webkit-box-shadow: 0 0 0 1000px var(--bg-input) inset !important;
    -webkit-text-fill-color: var(--text-primary) !important;
  }

  /* === Bouton de connexion === */
  .btn-login {
    width: 100%;
    padding: 13px;
    font-size: 16px;
    font-weight: 600;
    font-family: inherit;
    background: var(--accent);
    color: #0B0F14;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: all var(--transition);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-top: 6px;
  }

  .btn-login:hover {
    background: var(--accent-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 20px rgba(88, 166, 255, 0.3);
  }

  .btn-login:active {
    transform: translateY(0);
  }

  .btn-login .arrow {
    transition: transform 0.3s ease;
  }

  .btn-login:hover .arrow {
    transform: translateX(4px);
  }

  /* === Pied de page === */
  .login-footer {
    margin-top: 24px;
    text-align: center;
    font-size: 13px;
    color: var(--text-muted);
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .login-footer .sep {
    opacity: 0.3;
  }

  .login-footer .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    animation: pulse-dot 2s ease-in-out infinite;
  }

  @keyframes pulse-dot {
    0%, 100% { opacity: 0.6; transform: scale(0.9); }
    50% { opacity: 1; transform: scale(1.1); }
  }

  /* === Bouton de basculement thème === */
  .theme-toggle {
    position: fixed;
    top: 20px;
    right: 24px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 50%;
    width: 44px;
    height: 44px;
    font-size: 20px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all var(--transition);
    color: var(--text-secondary);
    z-index: 100;
  }

  .theme-toggle:hover {
    background: var(--border-color);
    transform: scale(1.05);
  }

  .theme-toggle .icon-sun { display: none; }
  .theme-toggle .icon-moon { display: block; }

  body.light .theme-toggle .icon-sun { display: block; }
  body.light .theme-toggle .icon-moon { display: none; }

  /* === Responsive === */
  @media (max-width: 480px) {
    .login-card {
      padding: 28px 20px 24px;
    }

    .login-header h1 {
      font-size: 22px;
    }

    .login-header .logo {
      font-size: 38px;
    }

    .form-group input {
      font-size: 14px;
      padding: 10px 12px;
    }

    .theme-toggle {
      top: 12px;
      right: 12px;
      width: 38px;
      height: 38px;
      font-size: 17px;
    }
  }

  /* === Scrollbar styling === */
  ::-webkit-scrollbar {
    width: 6px;
  }
  ::-webkit-scrollbar-track {
    background: var(--bg-primary);
  }
  ::-webkit-scrollbar-thumb {
    background: var(--border-color);
    border-radius: 3px;
  }
</style>
</head>
<body>

<!-- Bouton de basculement thème -->
<button class="theme-toggle" onclick="basculerTheme()" aria-label="Basculer le thème">
  <span class="icon-moon">🌙</span>
  <span class="icon-sun">☀️</span>
</button>

<div class="login-container">
  <div class="login-header">
    <span class="logo">🛡️</span>
    <h1>SENTINEL</h1>
    <div class="subtitle">Surveillance infrastructure</div>
  </div>

  <div class="login-card">
    <form method="post" action="{{ url_for('auth.login') }}" autocomplete="off">
      <input type="hidden" name="suivant" value="{{ request.args.get('suivant', '') }}">

      {% if premiere_fois %}
      <div class="rappel">
        <span class="warning-icon">ℹ️</span>
        <strong>Premier accès</strong><br>
        Identifiant : <code>{{ identifiant_defaut }}</code> &nbsp;·&nbsp;
        Mot de passe : <code>{{ mdp_defaut }}</code><br>
        <span style="font-size:12px; color:var(--text-muted);">
          Le mot de passe devra être changé immédiatement.
        </span>
      </div>
      {% endif %}

      {% if erreur %}
      <div class="erreur">
        <span class="icon">⚠️</span>
        {{ erreur }}
      </div>
      {% endif %}

      <div class="form-group">
        <label for="username">Identifiant</label>
        <div class="input-wrapper">
          <input id="username" name="username" type="text" placeholder="votre identifiant" 
                 value="{{ request.form.get('username', '') }}" required autofocus>
        </div>
      </div>

      <div class="form-group">
        <label for="password">Mot de passe</label>
        <div class="input-wrapper">
          <input id="password" name="password" type="password" placeholder="••••••••" required>
        </div>
      </div>

      <button type="submit" class="btn-login">
        Se connecter
        <span class="arrow">→</span>
      </button>
    </form>
  </div>

  <div class="login-footer">
    <span class="status-dot"></span>
    <span>Système opérationnel</span>
    <span class="sep">·</span>
    <span>v2.0</span>
  </div>
</div>

<script>
  // === Gestion du thème ===
  function basculerTheme() {
    const clair = document.body.classList.toggle('light');
    localStorage.setItem('sentinel-theme', clair ? 'light' : 'dark');
  }

  // === Rétablir le thème sauvegardé ===
  (function initTheme() {
    if (localStorage.getItem('sentinel-theme') === 'light') {
      document.body.classList.add('light');
    }
  })();

  // === Soumission du formulaire avec la touche Entrée ===
  document.querySelector('form').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      this.submit();
    }
  });

  // === Focus automatique sur le champ identifiant ===
  document.addEventListener('DOMContentLoaded', function() {
    const usernameInput = document.getElementById('username');
    if (usernameInput) {
      usernameInput.focus();
      // Si un nom d'utilisateur est déjà rempli (après erreur), focus sur le mot de passe
      if (usernameInput.value) {
        document.getElementById('password').focus();
      }
    }
  });
</script>
</body>
</html>
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
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>SENTINEL - Changer le mot de passe</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  /* === Thème sombre (par défaut) === */
  :root {
    --bg-primary: #0B0F14;
    --bg-secondary: #121820;
    --bg-card: #161D26;
    --bg-input: #0B0F14;
    --border-color: #1E2733;
    --text-primary: #E6EDF3;
    --text-secondary: #7C8B99;
    --text-muted: #4A5A6A;
    --accent: #58A6FF;
    --accent-hover: #79C0FF;
    --success: #3FB950;
    --danger: #F85149;
    --warning: #D29922;
    --shadow: rgba(0,0,0,0.5);
    --input-bg: #0B0F14;
    --transition: 0.3s ease;
  }

  /* === Thème clair === */
  body.light {
    --bg-primary: #EBEEF2;
    --bg-secondary: #F7F8FA;
    --bg-card: #EFF1F4;
    --bg-input: #F7F8FA;
    --border-color: #D8DDE3;
    --text-primary: #2B3138;
    --text-secondary: #6B7280;
    --text-muted: #9AA0A8;
    --accent: #2563EB;
    --accent-hover: #3B82F6;
    --shadow: rgba(0,0,0,0.12);
    --input-bg: #F7F8FA;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
    padding: 20px;
    transition: background var(--transition), color var(--transition);
  }

  .login-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    max-width: 420px;
    animation: fadeIn 0.6s ease;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .login-header {
    text-align: center;
    margin-bottom: 28px;
  }

  .login-header .logo { font-size: 42px; display: block; margin-bottom: 6px; }
  .login-header h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
  .login-header .subtitle { font-size: 14px; color: var(--text-secondary); margin-top: 2px; }

  .login-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 32px 28px 28px;
    width: 100%;
    box-shadow: 0 8px 40px var(--shadow);
    transition: all var(--transition);
  }

  .info-text {
    font-size: 13.5px;
    color: var(--text-secondary);
    line-height: 1.6;
    margin-bottom: 20px;
    padding: 12px 16px;
    background: rgba(88, 166, 255, 0.06);
    border-radius: 10px;
    border-left: 3px solid var(--accent);
  }

  .info-text strong { color: var(--accent); }

  .erreur {
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid rgba(248, 81, 73, 0.25);
    border-radius: 10px;
    padding: 10px 14px;
    font-size: 13px;
    color: var(--danger);
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    animation: shake 0.4s ease;
  }

  @keyframes shake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-6px); }
    40% { transform: translateX(6px); }
    60% { transform: translateX(-4px); }
    80% { transform: translateX(4px); }
  }

  .form-group { margin-bottom: 16px; }

  .form-group label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 5px;
    letter-spacing: 0.3px;
  }

  .form-group input {
    width: 100%;
    padding: 12px 14px;
    font-size: 15px;
    font-family: inherit;
    background: var(--bg-input);
    border: 1.5px solid var(--border-color);
    border-radius: 10px;
    color: var(--text-primary);
    outline: none;
    transition: all var(--transition);
    box-sizing: border-box;
  }

  .form-group input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
  }

  .btn-login {
    width: 100%;
    padding: 13px;
    font-size: 16px;
    font-weight: 600;
    font-family: inherit;
    background: var(--accent);
    color: #0B0F14;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: all var(--transition);
    margin-top: 4px;
  }

  .btn-login:hover {
    background: var(--accent-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 20px rgba(88, 166, 255, 0.3);
  }

  .btn-login:active { transform: translateY(0); }

  .login-footer {
    margin-top: 20px;
    text-align: center;
    font-size: 13px;
    color: var(--text-muted);
  }

  .login-footer a {
    color: var(--accent);
    text-decoration: none;
    transition: color var(--transition);
  }

  .login-footer a:hover { color: var(--accent-hover); text-decoration: underline; }

  .theme-toggle {
    position: fixed;
    top: 20px;
    right: 24px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 50%;
    width: 44px;
    height: 44px;
    font-size: 20px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all var(--transition);
    color: var(--text-secondary);
    z-index: 100;
  }

  .theme-toggle:hover {
    background: var(--border-color);
    transform: scale(1.05);
  }

  .theme-toggle .icon-sun { display: none; }
  .theme-toggle .icon-moon { display: block; }

  body.light .theme-toggle .icon-sun { display: block; }
  body.light .theme-toggle .icon-moon { display: none; }

  @media (max-width: 480px) {
    .login-card { padding: 24px 16px 20px; }
    .login-header h1 { font-size: 20px; }
    .theme-toggle { top: 12px; right: 12px; width: 38px; height: 38px; font-size: 17px; }
  }
</style>
</head>
<body>

<button class="theme-toggle" onclick="basculerTheme()" aria-label="Basculer le thème">
  <span class="icon-moon">🌙</span>
  <span class="icon-sun">☀️</span>
</button>

<div class="login-container">
  <div class="login-header">
    <span class="logo">🔑</span>
    <h1>Nouveau mot de passe</h1>
    <div class="subtitle">Première connexion ou mot de passe réinitialisé</div>
  </div>

  <div class="login-card">
    <div class="info-text">
      <strong>📌 Important :</strong> Choisissez un mot de passe personnel et sécurisé
      (8 caractères minimum) avant de continuer.
    </div>

    {% if erreur %}
    <div class="erreur">
      <span>⚠️</span>
      {{ erreur }}
    </div>
    {% endif %}

    <form method="post">
      <div class="form-group">
        <label for="nouveau">Nouveau mot de passe</label>
        <input id="nouveau" name="nouveau" type="password" placeholder="8 caractères minimum" required>
      </div>

      <div class="form-group">
        <label for="confirmation">Confirmer le mot de passe</label>
        <input id="confirmation" name="confirmation" type="password" placeholder="retapez le mot de passe" required>
      </div>

      <button type="submit" class="btn-login">Valider et continuer →</button>
    </form>
  </div>

  <div class="login-footer">
    <a href="{{ url_for('auth.logout') }}">Se déconnecter</a>
  </div>
</div>

<script>
  function basculerTheme() {
    document.body.classList.toggle('light');
    localStorage.setItem('sentinel-theme', document.body.classList.contains('light') ? 'light' : 'dark');
  }

  (function initTheme() {
    if (localStorage.getItem('sentinel-theme') === 'light') {
      document.body.classList.add('light');
    }
  })();

  document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('nouveau').focus();
  });
</script>
</body>
</html>
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
  :root {
    --bg-primary: #0B0F14;
    --bg-secondary: #121820;
    --bg-card: #161D26;
    --border-color: #1E2733;
    --text-primary: #E6EDF3;
    --text-secondary: #7C8B99;
    --accent: #58A6FF;
    --accent-hover: #79C0FF;
    --danger: #F85149;
    --success: #3FB950;
    --transition: 0.3s ease;
  }

  body.light {
    --bg-primary: #EBEEF2;
    --bg-secondary: #F7F8FA;
    --bg-card: #EFF1F4;
    --border-color: #D8DDE3;
    --text-primary: #2B3138;
    --text-secondary: #6B7280;
    --accent: #2563EB;
    --danger: #CF222E;
    --success: #1A7F37;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    padding: 2rem;
    max-width: 900px;
    margin: 0 auto;
    transition: background var(--transition), color var(--transition);
  }

  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 12px; }
  .header h1 { font-size: 1.5rem; }

  .theme-toggle {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    font-size: 18px;
    cursor: pointer;
    transition: all var(--transition);
    color: var(--text-secondary);
  }

  .theme-toggle:hover { background: var(--border-color); transform: scale(1.05); }

  .msg {
    background: rgba(63, 185, 80, 0.1);
    border: 1px solid rgba(63, 185, 80, 0.2);
    border-radius: 8px;
    padding: 10px 14px;
    color: var(--success);
    margin-bottom: 1rem;
  }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    transition: all var(--transition);
  }

  .card h3 { font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }

  .form-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
  }

  .form-row input, .form-row select {
    padding: 8px 12px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    transition: all var(--transition);
    flex: 1 1 140px;
  }

  .form-row input:focus, .form-row select:focus {
    border-color: var(--accent);
    outline: none;
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
  }

  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: all var(--transition);
    background: var(--accent);
    color: #0B0F14;
    white-space: nowrap;
  }

  .btn:hover { background: var(--accent-hover); transform: translateY(-1px); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { opacity: 0.85; }

  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { padding: 10px 8px; border-bottom: 1px solid var(--border-color); text-align: left; }
  th { color: var(--text-secondary); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }

  .badge {
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-admin { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
  .badge-user { background: var(--border-color); color: var(--text-secondary); }
  .badge-warning { background: rgba(210, 153, 34, 0.2); color: #D29922; }
  .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); }

  .actions { display: flex; flex-wrap: wrap; gap: 4px; }
  .actions .btn { font-size: 11px; padding: 4px 10px; }
  .actions form { display: inline; }

  @media (max-width: 600px) {
    body { padding: 1rem; }
    .form-row { flex-direction: column; }
    .form-row input, .form-row select { flex: 1 1 100%; }
    .header { flex-direction: column; align-items: flex-start; }
    table { font-size: 12px; }
    th, td { padding: 6px 4px; }
  }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>👥 Gestion des utilisateurs</h1>
    <a href="{{ url_for('accueil') }}">← Retour au dashboard</a>
  </div>
  <button class="theme-toggle" onclick="basculerTheme()">🌙</button>
</div>

{% if msg %}<div class="msg">✅ {{ msg }}</div>{% endif %}

<div class="card">
  <h3>➕ Nouveau compte</h3>
  <form method="post" action="{{ url_for('auth.admin_creer_utilisateur') }}" class="form-row">
    <input name="username" placeholder="Identifiant" required>
    <input name="password" type="password" placeholder="Mot de passe" required>
    <select name="role">
      <option value="user">utilisateur</option>
      <option value="admin">administrateur</option>
    </select>
    <button type="submit" class="btn">Créer</button>
  </form>
</div>

<table>
  <thead>
    <tr>
      <th>Identifiant</th>
      <th>Rôle</th>
      <th>Statut</th>
      <th>Créé le</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    {% for u in utilisateurs %}
    <tr>
      <td>
        {{ u.username }}
        {% if u.doit_changer_mdp %}
        <span class="badge badge-warning">mdp à changer</span>
        {% endif %}
      </td>
      <td><span class="badge {{ 'badge-admin' if u.role == 'admin' else 'badge-user' }}">{{ u.role }}</span></td>
      <td><span class="badge {{ 'badge-success' if u.actif else 'badge-warning' }}">{{ 'actif' if u.actif else 'inactif' }}</span></td>
      <td>{{ u.cree_le[:10] if u.cree_le else '' }}</td>
      <td>
        <div class="actions">
          {% if u.username != current_username %}
          <form method="post" action="{{ url_for('auth.admin_changer_role', user_id=u.id) }}">
            <input type="hidden" name="role" value="{{ 'user' if u.role == 'admin' else 'admin' }}">
            <button type="submit" class="btn">{{ '⬇ user' if u.role == 'admin' else '⬆ admin' }}</button>
          </form>
          <form method="post" action="{{ url_for('auth.admin_toggle_actif', user_id=u.id) }}">
            <button type="submit" class="btn btn-danger">{{ 'Désactiver' if u.actif else 'Réactiver' }}</button>
          </form>
          {% else %}
          <span style="color:var(--text-secondary); font-size:12px;">(vous)</span>
          {% endif %}
        </div>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<script>
  function basculerTheme() {
    const clair = document.body.classList.toggle('light');
    localStorage.setItem('sentinel-theme', clair ? 'light' : 'dark');
    document.querySelector('.theme-toggle').textContent = clair ? '☀️' : '🌙';
  }

  (function initTheme() {
    if (localStorage.getItem('sentinel-theme') === 'light') {
      document.body.classList.add('light');
      document.querySelector('.theme-toggle').textContent = '☀️';
    }
  })();
</script>
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