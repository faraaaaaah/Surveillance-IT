# -*- coding: utf-8 -*-
"""
Module Parametres — Configuration email via une page web
-------------------------------------------------------------
Remplace les variables d'environnement EMAIL_SMTP_HOST / EMAIL_USER /
EMAIL_PASSWORD par un reglage fait UNE FOIS depuis le navigateur
(/admin/parametres-email), stocke dans la meme base que les comptes et les
responsables. Aucune variable d'environnement, aucune ligne de commande.

Pourquoi un reglage est quand meme necessaire : un email reel qui arrive
dans une vraie boite de reception doit forcement passer par un compte email
authentifie quelque part (Gmail, Outlook...) - aucun code ne peut
contourner ça, une adresse/mot de passe d'application doit exister
QUELQUE PART. Ce module deplace juste ce reglage d'un fichier de
configuration/CLI vers une page web, ce qui est la seule vraie alternative
"zero config technique" : plus de export, plus de oc rsh, juste un
formulaire rempli une fois par un admin depuis le dashboard.
"""

import os
import sqlite3
import threading
import time
from datetime import datetime
from contextlib import contextmanager

from flask import Blueprint, request, redirect, url_for, render_template_string

import historique
from auth import admin_required

CHEMIN_DB = os.path.join(historique.DOSSIER_DATA, "auth.db")  # meme fichier que auth.py/destinataires.py

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
            CREATE TABLE IF NOT EXISTS config_email (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                host TEXT NOT NULL DEFAULT 'smtp.gmail.com',
                port INTEGER NOT NULL DEFAULT 465,
                utilisateur TEXT NOT NULL DEFAULT '',
                mot_de_passe TEXT NOT NULL DEFAULT '',
                maj_le TEXT
            )
        """)
        conn.commit()


def obtenir_config_email() -> dict:
    """Lit la config email depuis la base. Repli sur les anciennes variables
    d'environnement EMAIL_SMTP_HOST/EMAIL_USER/EMAIL_PASSWORD si la table
    est vide (compatibilite avec un ancien deploiement deja configure
    autrement)."""
    initialiser_db()
    rows = _execute("SELECT * FROM config_email WHERE id = 1", fetch=True)
    if rows and rows[0]["utilisateur"] and rows[0]["mot_de_passe"]:
        r = rows[0]
        return {"host": r["host"], "port": r["port"],
                "utilisateur": r["utilisateur"], "mot_de_passe": r["mot_de_passe"]}
    return {
        "host": os.environ.get("EMAIL_SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.environ.get("EMAIL_SMTP_PORT", "465")),
        "utilisateur": os.environ.get("EMAIL_USER", ""),
        "mot_de_passe": os.environ.get("EMAIL_PASSWORD", ""),
    }


def enregistrer_config_email(host: str, port: int, utilisateur: str, mot_de_passe: str):
    initialiser_db()
    _execute("""
        INSERT INTO config_email (id, host, port, utilisateur, mot_de_passe, maj_le)
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            host=excluded.host, port=excluded.port,
            utilisateur=excluded.utilisateur, mot_de_passe=excluded.mot_de_passe,
            maj_le=excluded.maj_le
    """, (host.strip(), port, utilisateur.strip(), mot_de_passe.strip(),
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


def config_email_complete() -> bool:
    c = obtenir_config_email()
    return bool(c["host"] and c["utilisateur"] and c["mot_de_passe"])


# ---------------------------------------------------------------------------
# Page d'administration
# ---------------------------------------------------------------------------

parametres_bp = Blueprint("parametres", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Parametres email</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:640px;margin:0 auto}
  a{color:#3b82f6}
  label{display:block;margin:.8rem 0 .3rem;font-size:.85rem;color:#9aa0aa}
  input{width:100%;padding:.55rem;border-radius:6px;border:1px solid #333;background:#1a1d24;color:#e6e6e6;box-sizing:border-box}
  button{margin-top:1.2rem;padding:.6rem 1.2rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer;font-weight:600}
  .msg{color:#4ade80;margin-bottom:1rem}
  .aide{color:#9aa0aa;font-size:.85rem;line-height:1.6;background:#1a1d24;border:1px solid #2a2d34;border-radius:8px;padding:.9rem 1.1rem;margin-top:1.5rem}
  .aide a{color:#58a6ff}
  .statut{padding:.5rem .8rem;border-radius:6px;font-size:.85rem;margin-bottom:1rem}
  .statut.ok{background:rgba(63,185,80,.15);color:#4ade80}
  .statut.manquant{background:rgba(248,81,73,.15);color:#f87171}
</style></head><body>
<p><a href="{{ url_for('accueil') }}">&larr; Retour au dashboard</a></p>
<h1>Parametres email</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

<div class="statut {{ 'ok' if complete else 'manquant' }}">
  {{ 'Configuration email active — les alertes peuvent partir.' if complete
     else "Aucune configuration email valide pour le moment — les alertes email ne partiront pas tant que ce formulaire n'est pas rempli." }}
</div>

<form method="post" action="{{ url_for('parametres.enregistrer_route') }}">
  <label>Serveur SMTP</label>
  <input name="host" value="{{ config.host }}" required>

  <label>Port</label>
  <input name="port" type="number" value="{{ config.port }}" required>

  <label>Adresse email d'envoi</label>
  <input name="utilisateur" type="email" value="{{ config.utilisateur }}" placeholder="exemple@gmail.com" required>

  <label>Mot de passe d'application</label>
  <input name="mot_de_passe" type="password" value="{{ config.mot_de_passe }}" placeholder="{{ '(deja enregistre — laisser tel quel pour ne pas changer)' if config.mot_de_passe else '' }}">

  <button type="submit">Enregistrer</button>
</form>

<div class="aide">
  <b>Avec Gmail (recommande, gratuit) :</b><br>
  1. Utilise ou cree une adresse Gmail dediee au projet.<br>
  2. Active la validation en 2 etapes sur ce compte : 
     <a href="https://myaccount.google.com/signinoptions/two-step-verification" target="_blank">myaccount.google.com</a><br>
  3. Genere un "mot de passe d'application" ici :
     <a href="https://myaccount.google.com/apppasswords" target="_blank">myaccount.google.com/apppasswords</a><br>
  4. Colle ce mot de passe (pas ton mot de passe Gmail normal) dans le champ ci-dessus.<br><br>
  Serveur : <code>smtp.gmail.com</code>, port <code>465</code> (deja pre-rempli).<br><br>
  C'est un reglage a faire une seule fois — il reste enregistre meme si le pod redemarre.
</div>
</body></html>
"""


@parametres_bp.route("/admin/parametres-email")
@admin_required
def page_parametres():
    return render_template_string(
        _PAGE, config=obtenir_config_email(),
        complete=config_email_complete(), msg=request.args.get("msg"),
    )


@parametres_bp.route("/admin/parametres-email/enregistrer", methods=["POST"])
@admin_required
def enregistrer_route():
    host = request.form.get("host", "smtp.gmail.com").strip()
    port = request.form.get("port", "465").strip()
    utilisateur = request.form.get("utilisateur", "").strip()
    mot_de_passe = request.form.get("mot_de_passe", "").strip()

    if not utilisateur:
        return redirect(url_for("parametres.page_parametres", msg="Adresse email manquante."))

    # Si le champ mot de passe est laisse vide (rechargement du formulaire
    # apres un 1er enregistrement), on garde l'ancien plutot que d'ecraser
    # avec une chaine vide.
    if not mot_de_passe:
        mot_de_passe = obtenir_config_email()["mot_de_passe"]
        if not mot_de_passe:
            return redirect(url_for("parametres.page_parametres", msg="Mot de passe manquant."))

    try:
        port_int = int(port)
    except ValueError:
        port_int = 465

    enregistrer_config_email(host, port_int, utilisateur, mot_de_passe)
    import audit
    audit.consigner("modification_config_email", cible=utilisateur,
                     details=f"host={host}:{port_int}")  # jamais le mot de passe dans le journal
    return redirect(url_for("parametres.page_parametres", msg="Configuration enregistree."))