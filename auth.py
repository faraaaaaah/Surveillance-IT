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
# Design partage — jetons de style, theme clair/sombre, menu utilisateur
# ---------------------------------------------------------------------------
# Ces blocs (CSS/JS/HTML) sont reutilises par TOUTES les pages "back-office"
# (connexion, gestion des utilisateurs, gestion des responsables) ET par le
# dashboard (dash.py), pour garder un rendu identique partout — memes
# variables de couleur que dash.py, meme cle localStorage 'sentinel-theme'.

TOKENS_CSS = """
  :root{
    --bg:#0B0F14; --panel:#121820; --panel2:#161D26; --border:#1E2733;
    --text:#E6EDF3; --muted:#7C8B99;
    --ok:#3FB950; --warn:#D29922; --crit:#F85149; --accent:#58A6FF;
  }
  body.light{
    --bg:#EBEEF2; --panel:#F7F8FA; --panel2:#EFF1F4; --border:#D8DDE3;
    --text:#2B3138; --muted:#6B7280;
    --ok:#1A7F37; --warn:#9A6700; --crit:#CF222E; --accent:#2563EB;
  }
  *{box-sizing:border-box;}
  body{margin:0; font-family:Inter,system-ui,-apple-system,sans-serif; background:var(--bg);
       color:var(--text); transition:background-color .2s, color .2s;}
  a{color:var(--accent); text-decoration:none;}

  .topbar{display:flex; align-items:center; justify-content:space-between; gap:16px;
          padding:14px 28px; background:var(--panel); border-bottom:1px solid var(--border);}
  .topbar-left{display:flex; align-items:center; gap:26px;}
  .topbar-logo{display:flex; align-items:center; gap:9px; font-weight:700; font-size:15px; letter-spacing:.04em;}
  .topbar-nav{display:flex; gap:4px;}
  .topbar-nav a{color:var(--muted); font-size:13px; padding:7px 12px; border-radius:6px;}
  .topbar-nav a:hover{background:var(--panel2); color:var(--text);}
  .topbar-nav a.actif{background:rgba(88,166,255,.12); color:var(--accent); font-weight:600;}
  .topbar-right{display:flex; align-items:center; gap:10px;}

  .btn-icone{background:transparent; border:1px solid var(--border); color:var(--muted);
             font-size:13px; padding:7px 10px; border-radius:6px; cursor:pointer;}
  .btn-icone:hover{color:var(--text); border-color:var(--muted);}

  /* Menu utilisateur (avatar + nom + menu deroulant) ------------------- */
  .menu-user{position:relative;}
  .menu-user-btn{display:flex; align-items:center; gap:8px; background:transparent; border:1px solid var(--border);
                 border-radius:20px; padding:5px 12px 5px 5px; cursor:pointer; color:var(--text); font-size:13px;}
  .menu-user-btn:hover{border-color:var(--muted);}
  .menu-user .avatar{width:26px; height:26px; border-radius:50%; background:var(--accent); color:#08131f;
                      display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px; flex-shrink:0;}
  .menu-user .chevron{color:var(--muted); font-size:10px; transition:transform .15s;}
  .menu-user.ouvert .chevron{transform:rotate(180deg);}
  .menu-user-dropdown{display:none; position:absolute; top:calc(100% + 8px); right:0; min-width:220px;
                       background:var(--panel); border:1px solid var(--border); border-radius:10px;
                       box-shadow:0 10px 30px rgba(0,0,0,.3); z-index:200; overflow:hidden;}
  .menu-user.ouvert .menu-user-dropdown{display:block;}
  .menu-user-info{padding:12px 14px; border-bottom:1px solid var(--border);}
  .menu-user-info .nom{font-weight:600; font-size:13.5px;}
  .menu-user-info .role{display:inline-block; margin-top:4px; font-size:10.5px; padding:2px 8px; border-radius:10px;
                          background:rgba(88,166,255,.15); color:var(--accent); text-transform:uppercase; letter-spacing:.04em;}
  .menu-user-dropdown a, .menu-user-dropdown .item{display:flex; align-items:center; gap:9px; padding:10px 14px;
                          font-size:13px; color:var(--text); cursor:pointer;}
  .menu-user-dropdown a:hover, .menu-user-dropdown .item:hover{background:var(--panel2);}
  .menu-user-dropdown .item.danger{color:var(--crit);}
  .menu-user-dropdown .separateur{height:1px; background:var(--border); margin:4px 0;}

  main.contenu{max-width:1000px; margin:0 auto; padding:28px;}
  .page-entete{margin-bottom:22px;}
  .page-entete h1{font-size:20px; margin:0 0 4px;}
  .page-entete p{color:var(--muted); font-size:13px; margin:0;}

  .carte{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:22px; margin-bottom:20px;}
  .carte h3{margin:0 0 4px; font-size:14px;}
  .carte .aide-carte{color:var(--muted); font-size:12.5px; margin:0 0 16px;}

  .champs-form{display:flex; flex-wrap:wrap; gap:12px; align-items:flex-end;}
  .champ{display:flex; flex-direction:column; gap:5px; flex:1; min-width:160px;}
  .champ label{font-size:11.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em;}
  input, select{padding:.55rem .7rem; border-radius:7px; border:1px solid var(--border); background:var(--bg);
                color:var(--text); font-size:13.5px;}
  input:focus, select:focus{outline:none; border-color:var(--accent);}
  button{font-family:inherit;}
  .btn-principal{padding:.6rem 1.1rem; border:0; border-radius:7px; background:var(--accent); color:#08131f;
                 font-weight:600; font-size:13.5px; cursor:pointer;}
  .btn-principal:hover{filter:brightness(1.08);}
  .btn-fantome{padding:.5rem .9rem; border:1px solid var(--border); border-radius:7px; background:transparent;
               color:var(--text); font-size:12.5px; cursor:pointer;}
  .btn-fantome:hover{border-color:var(--muted);}
  .btn-danger{padding:.5rem .9rem; border:1px solid rgba(248,81,73,.4); border-radius:7px; background:rgba(248,81,73,.1);
              color:var(--crit); font-size:12.5px; cursor:pointer;}
  .btn-danger:hover{background:rgba(248,81,73,.18);}

  table.table-pro{width:100%; border-collapse:collapse; font-size:13px;}
  table.table-pro th{text-align:left; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em;
                      padding:10px 12px; border-bottom:1px solid var(--border);}
  table.table-pro td{padding:11px 12px; border-bottom:1px solid var(--border); vertical-align:middle;}
  table.table-pro tr:last-child td{border-bottom:none;}
  table.table-pro tr:hover td{background:var(--panel2);}
  .cellule-nom{display:flex; align-items:center; gap:10px;}
  .cellule-nom .avatar{width:30px; height:30px; font-size:12px;}
  .badge{display:inline-block; font-size:10.5px; padding:2px 9px; border-radius:10px; font-weight:600; text-transform:uppercase; letter-spacing:.03em;}
  .badge.admin{background:rgba(88,166,255,.15); color:var(--accent);}
  .badge.user{background:var(--panel2); color:var(--muted); border:1px solid var(--border);}
  .badge.actif{background:rgba(63,185,80,.15); color:var(--ok);}
  .badge.inactif{background:rgba(248,81,73,.12); color:var(--crit);}
  .badge.attention{background:rgba(210,153,34,.15); color:var(--warn);}
  .actions-ligne{display:flex; gap:6px; flex-wrap:wrap;}
  .recherche{max-width:280px;}
  .toast{background:rgba(63,185,80,.12); border:1px solid rgba(63,185,80,.35); color:var(--ok);
         padding:10px 16px; border-radius:8px; font-size:13px; margin-bottom:18px;}
  .vide-etat{text-align:center; color:var(--muted); font-size:13px; padding:30px 0;}
"""

JS_TEMA_ET_MENU = """
function basculerTheme(){
  const clair = document.body.classList.toggle('light');
  localStorage.setItem('sentinel-theme', clair ? 'light' : 'dark');
  const btn = document.getElementById('btn-theme');
  if(btn) btn.textContent = clair ? '☀️' : '🌙';
}
(function initTheme(){
  if(localStorage.getItem('sentinel-theme') === 'light'){
    document.body.classList.add('light');
    document.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('btn-theme');
      if(btn) btn.textContent = '☀️';
    });
  }
})();

// Menu utilisateur : ouverture au clic OU au survol, fermeture au clic
// exterieur ou quand la souris quitte la zone (avec un court delai pour
// eviter une fermeture intempestive en passant d'un element a l'autre).
(function(){
  let delaiFermeture = null;
  document.addEventListener('DOMContentLoaded', () => {
    const menu = document.getElementById('menu-utilisateur');
    if(!menu) return;
    const bouton = menu.querySelector('.menu-user-btn');
    const ouvrir = () => { clearTimeout(delaiFermeture); menu.classList.add('ouvert'); };
    const fermer = () => { delaiFermeture = setTimeout(() => menu.classList.remove('ouvert'), 220); };
    bouton.addEventListener('click', (e) => { e.stopPropagation(); menu.classList.toggle('ouvert'); });
    menu.addEventListener('mouseenter', ouvrir);
    menu.addEventListener('mouseleave', fermer);
    document.addEventListener('click', (e) => { if(!menu.contains(e.target)) menu.classList.remove('ouvert'); });
  });
})();
"""


def render_menu_utilisateur(page_active: str = None) -> str:
    """HTML du bloc "avatar + nom + menu deroulant" affiche en haut a droite
    (profil, liens admin, deconnexion). Utilise par dash.py ET par les pages
    de ce module — un seul et meme composant, pour un rendu identique partout.
    A appeler dans le contexte d'une requete authentifiee (current_user)."""
    initiale = (current_user.username or "?")[0].upper()
    liens_admin = ""
    if current_user.is_admin:
        liens_admin = (
            f'<a href="{url_for("auth.admin_utilisateurs")}" class="item">👤 Utilisateurs</a>'
            f'<a href="{url_for("destinataires.page_responsables")}" class="item">📣 Responsables</a>'
            f'<a href="{url_for("parametres.page_parametres")}" class="item">✉️ Email</a>'
            f'<div class="separateur"></div>'
        )
    lien_connaissances = (
        f'<a href="{url_for("base_connaissances.page_base_connaissances")}" class="item">📚 Base de connaissances</a>'
    )
    lien_provisionnement = (
        f'<a href="{url_for("provisionnement.page_provisionnement")}" class="item">📈 Provisionnement</a>'
    )
    return f"""
    <div class="menu-user" id="menu-utilisateur">
      <button class="menu-user-btn" type="button">
        <span class="avatar">{initiale}</span>
        <span class="username">{current_user.username}</span>
        <span class="chevron">▾</span>
      </button>
      <div class="menu-user-dropdown">
        <div class="menu-user-info">
          <div class="nom">{current_user.username}</div>
          <span class="role">{'Administrateur' if current_user.is_admin else 'Utilisateur'}</span>
        </div>
        <a href="{url_for('auth.changer_mot_de_passe_route')}" class="item">🔑 Mon profil</a>
        {lien_connaissances}
        {lien_provisionnement}
        <div class="separateur"></div>
        {liens_admin}
        <a href="{url_for('auth.logout')}" class="item danger">🚪 Deconnexion</a>
      </div>
    </div>
    """


def render_topbar(page_active: str) -> str:
    """Barre superieure commune aux pages d'administration (utilisateurs,
    responsables) et a la base de connaissances : logo, navigation, theme,
    menu utilisateur."""
    def cls(nom):
        return "actif" if nom == page_active else ""
    liens_admin_nav = ""
    if current_user.is_admin:
        liens_admin_nav = (
            f'<a href="{url_for("auth.admin_utilisateurs")}" class="{cls("utilisateurs")}">Utilisateurs</a>'
            f'<a href="{url_for("destinataires.page_responsables")}" class="{cls("responsables")}">Responsables</a>'
            f'<a href="{url_for("parametres.page_parametres")}" class="{cls("parametres")}">Email</a>'
        )
    return f"""
    <header class="topbar">
      <div class="topbar-left">
        <div class="topbar-logo">🛡️ SENTINEL</div>
        <nav class="topbar-nav">
          <a href="{url_for('accueil')}" class="{cls('dashboard')}">Tableau de bord</a>
          <a href="{url_for('base_connaissances.page_base_connaissances')}" class="{cls('base_connaissances')}">Base de connaissances</a>
          <a href="{url_for('provisionnement.page_provisionnement')}" class="{cls('provisionnement')}">Provisionnement</a>
          {liens_admin_nav}
        </nav>
      </div>
      <div class="topbar-right">
        <button class="btn-icone" id="btn-theme" onclick="basculerTheme()">🌙</button>
        {render_menu_utilisateur(page_active)}
      </div>
    </header>
    """


# ---------------------------------------------------------------------------
# Routes (Blueprint)
# ---------------------------------------------------------------------------

auth_bp = Blueprint("auth", __name__)

_PAGE_LOGIN = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Connexion - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
  html,body{height:100%;}
  .auth-shell{display:flex; min-height:100vh;}
  .auth-brand{flex:1; display:flex; flex-direction:column; justify-content:center; gap:22px;
              padding:60px; background:
                radial-gradient(circle at 20% 20%, rgba(88,166,255,.18), transparent 45%),
                radial-gradient(circle at 80% 80%, rgba(88,166,255,.10), transparent 50%),
                var(--panel);
              border-right:1px solid var(--border); position:relative; overflow:hidden;}
  .auth-brand .marque{display:flex; align-items:center; gap:12px; font-size:26px; font-weight:800; letter-spacing:.03em;}
  .auth-brand .marque .pastille{width:14px; height:14px; border-radius:50%; background:var(--ok);
                                 box-shadow:0 0 0 4px rgba(63,185,80,.18);}
  .auth-brand h2{font-size:15px; font-weight:500; color:var(--muted); margin:0; max-width:340px; line-height:1.6;}
  .auth-brand ul{list-style:none; padding:0; margin:10px 0 0; display:flex; flex-direction:column; gap:14px; max-width:340px;}
  .auth-brand li{display:flex; align-items:flex-start; gap:10px; font-size:13px; color:var(--text); line-height:1.5;}
  .auth-brand li .puce{width:22px; height:22px; border-radius:6px; background:rgba(88,166,255,.14); color:var(--accent);
                        display:flex; align-items:center; justify-content:center; flex-shrink:0; font-size:12px; margin-top:1px;}

  .auth-form-wrap{flex:1; display:flex; align-items:center; justify-content:center; padding:40px; position:relative;}
  .theme-toggle{position:absolute; top:24px; right:24px;}
  .auth-card{background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:36px 38px;
             width:100%; max-width:360px; box-shadow:0 20px 60px rgba(0,0,0,.25);}
  .auth-card h1{font-size:19px; margin:0 0 4px;}
  .auth-card .sous{color:var(--muted); font-size:13px; margin:0 0 22px;}
  .champ-auth{margin-bottom:16px;}
  .champ-auth label{display:block; font-size:11.5px; color:var(--muted); text-transform:uppercase;
                     letter-spacing:.04em; margin-bottom:6px;}
  .champ-auth input{width:100%;}
  .btn-connexion{width:100%; padding:.7rem; margin-top:6px; border:0; border-radius:8px; background:var(--accent);
                 color:#08131f; font-weight:700; font-size:14px; cursor:pointer;}
  .btn-connexion:hover{filter:brightness(1.08);}
  .erreur{background:rgba(248,81,73,.1); border:1px solid rgba(248,81,73,.35); color:var(--crit);
          font-size:12.5px; padding:9px 12px; border-radius:7px; margin-bottom:14px;}
  .rappel{background:rgba(88,166,255,.08); border:1px solid rgba(88,166,255,.3); border-radius:8px;
          padding:.8rem 1rem; font-size:.8rem; color:var(--muted); margin-bottom:18px; line-height:1.55;}
  .rappel code{color:var(--text); background:var(--panel2); padding:1px 6px; border-radius:4px;}
  @media (max-width: 860px){ .auth-brand{display:none;} }
</style></head>
<body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

<div class="auth-shell">
  <div class="auth-brand">
    <div class="marque"><span class="pastille"></span> SENTINEL</div>
    <h2>Plateforme de surveillance infrastructure en temps reel : metriques, alertes intelligentes et rapports, sur tous vos serveurs.</h2>
    <ul>
      <li><span class="puce">⚡</span> Alertes email &amp; WhatsApp des la premiere anomalie detectee</li>
      <li><span class="puce">📊</span> Historique complet et rapports PDF a la demande</li>
      <li><span class="puce">🖥️</span> Vue unifiee de tous vos serveurs, locaux ou distants</li>
    </ul>
  </div>

  <div class="auth-form-wrap">
    <button class="btn-icone theme-toggle" id="btn-theme" onclick="basculerTheme()">🌙</button>
    <form method="post" class="auth-card">
      <h1>Connexion</h1>
      <p class="sous">Accedez a votre tableau de bord</p>
      {% if premiere_fois %}
      <div class="rappel">Premier acces : <code>{{ identifiant_defaut }}</code> /
      <code>{{ mdp_defaut }}</code><br>Le mot de passe sera a changer immediatement.</div>
      {% endif %}
      {% if erreur %}<div class="erreur">{{ erreur }}</div>{% endif %}
      <div class="champ-auth">
        <label>Identifiant</label>
        <input name="username" autofocus required>
      </div>
      <div class="champ-auth">
        <label>Mot de passe</label>
        <input name="password" type="password" required>
      </div>
      <button type="submit" class="btn-connexion">Se connecter →</button>
    </form>
  </div>
</div>

<script>""" + JS_TEMA_ET_MENU + """</script>
</body></html>
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
<title>Changer le mot de passe - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
  html,body{height:100%;}
  body{display:flex; align-items:center; justify-content:center; position:relative;}
  .theme-toggle{position:absolute; top:24px; right:24px;}
  .auth-card{background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:36px 38px;
             width:100%; max-width:380px; box-shadow:0 20px 60px rgba(0,0,0,.25);}
  .auth-card h1{font-size:18px; margin:0 0 8px; display:flex; align-items:center; gap:8px;}
  .auth-card p.sous{color:var(--muted); font-size:13px; margin:0 0 20px; line-height:1.55;}
  .champ-auth{margin-bottom:16px;}
  .champ-auth label{display:block; font-size:11.5px; color:var(--muted); text-transform:uppercase;
                     letter-spacing:.04em; margin-bottom:6px;}
  .champ-auth input{width:100%;}
  .btn-connexion{width:100%; padding:.7rem; margin-top:6px; border:0; border-radius:8px; background:var(--accent);
                 color:#08131f; font-weight:700; font-size:14px; cursor:pointer;}
  .btn-connexion:hover{filter:brightness(1.08);}
  .erreur{background:rgba(248,81,73,.1); border:1px solid rgba(248,81,73,.35); color:var(--crit);
          font-size:12.5px; padding:9px 12px; border-radius:7px; margin-bottom:14px;}
</style></head>
<body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>
<button class="btn-icone theme-toggle" id="btn-theme" onclick="basculerTheme()">🌙</button>

<form method="post" class="auth-card">
  <h1>🔑 Nouveau mot de passe requis</h1>
  <p class="sous">Premiere connexion (ou mot de passe reinitialise par un admin) :
  choisissez un mot de passe personnel avant de continuer.</p>
  {% if erreur %}<div class="erreur">{{ erreur }}</div>{% endif %}
  <div class="champ-auth">
    <label>Nouveau mot de passe</label>
    <input name="nouveau" type="password" placeholder="8 caracteres minimum" required>
  </div>
  <div class="champ-auth">
    <label>Confirmation</label>
    <input name="confirmation" type="password" placeholder="confirmer le mot de passe" required>
  </div>
  <button type="submit" class="btn-connexion">Valider</button>
</form>

<script>""" + JS_TEMA_ET_MENU + """</script>
</body></html>
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
<title>Gestion des utilisateurs - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>Gestion des utilisateurs</h1>
    <p>Cree, active ou desactive les comptes ayant acces au dashboard.</p>
  </div>

  {% if msg %}<div class="toast">{{ msg }}</div>{% endif %}

  <div class="carte">
    <h3>Nouveau compte</h3>
    <p class="aide-carte">L'utilisateur devra changer ce mot de passe des sa premiere connexion.</p>
    <form method="post" action="{{ url_for('auth.admin_creer_utilisateur') }}">
      <div class="champs-form">
        <div class="champ"><label>Identifiant</label><input name="username" placeholder="ex: jean.dupont" required></div>
        <div class="champ"><label>Mot de passe temporaire</label><input name="password" type="password" placeholder="mot de passe initial" required></div>
        <div class="champ" style="max-width:150px;"><label>Role</label>
          <select name="role"><option value="user">Utilisateur</option><option value="admin">Administrateur</option></select>
        </div>
        <button type="submit" class="btn-principal">+ Creer</button>
      </div>
    </form>
  </div>

  <div class="carte">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
      <h3 style="margin:0;">Comptes existants</h3>
      <input class="recherche" id="recherche-user" placeholder="Rechercher..." oninput="filtrerUtilisateurs()">
    </div>
    <table class="table-pro" id="table-utilisateurs">
      <tr><th>Utilisateur</th><th>Role</th><th>Statut</th><th>Cree le</th><th>Actions</th></tr>
      {% for u in utilisateurs %}
      <tr>
        <td>
          <div class="cellule-nom">
            <span class="avatar">{{ u.username[0]|upper }}</span>
            {{ u.username }}
            {% if u.doit_changer_mdp %}<span class="badge attention">mdp a changer</span>{% endif %}
          </div>
        </td>
        <td><span class="badge {{ u.role }}">{{ 'Admin' if u.role == 'admin' else 'Utilisateur' }}</span></td>
        <td><span class="badge {{ 'actif' if u.actif else 'inactif' }}">{{ 'Actif' if u.actif else 'Desactive' }}</span></td>
        <td>{{ u.cree_le }}</td>
        <td class="actions-ligne">
          {% if u.username != current_username %}
          <form method="post" action="{{ url_for('auth.admin_changer_role', user_id=u.id) }}" style="display:inline">
            <input type="hidden" name="role" value="{{ 'user' if u.role == 'admin' else 'admin' }}">
            <button type="submit" class="btn-fantome">Passer {{ 'utilisateur' if u.role == 'admin' else 'admin' }}</button>
          </form>
          <form method="post" action="{{ url_for('auth.admin_toggle_actif', user_id=u.id) }}" style="display:inline"
                {% if u.actif %}onsubmit="return confirm('Desactiver {{ u.username }} ?');"{% endif %}>
            <button type="submit" class="{{ 'btn-danger' if u.actif else 'btn-fantome' }}">{{ 'Desactiver' if u.actif else 'Reactiver' }}</button>
          </form>
          {% else %}
          <span style="color:var(--muted); font-size:12.5px;">(vous)</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
</main>

<script>""" + JS_TEMA_ET_MENU + """
function filtrerUtilisateurs(){
  const q = document.getElementById('recherche-user').value.toLowerCase();
  document.querySelectorAll('#table-utilisateurs tr').forEach((ligne, i) => {
    if(i === 0) return;
    ligne.style.display = ligne.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
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
        topbar=render_topbar("utilisateurs"),
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