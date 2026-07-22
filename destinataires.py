# -*- coding: utf-8 -*-
"""
Module Destinataires — Gestion des responsables d'alertes
-------------------------------------------------------------
Remplace la config statique par variables d'environnement (EMAIL_DEST,
CALLMEBOT_PHONE/APIKEY) par une table SQLite geree depuis une page web
/admin/responsables (reservee aux admins, voir auth.py).

Compatibilite : si la table est vide (rien n'a encore ete ajoute via la
page), notifier.py continue de retomber sur les variables d'environnement
EMAIL_DEST / CALLMEBOT_PHONE / CALLMEBOT_APIKEY, pour ne rien casser tant
que la migration n'est pas faite.
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

CHEMIN_DB = os.path.join(historique.DOSSIER_DATA, "auth.db")  # meme fichier que auth.py

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
            CREATE TABLE IF NOT EXISTS responsables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT NOT NULL,
                canal TEXT NOT NULL,        -- 'email' ou 'whatsapp'
                contact TEXT NOT NULL,      -- adresse email OU numero de telephone
                apikey TEXT,                -- cle CallMeBot (uniquement pour whatsapp)
                actif INTEGER NOT NULL DEFAULT 1,
                cree_le TEXT NOT NULL
            )
        """)
        conn.commit()


def ajouter(nom: str, canal: str, contact: str, apikey: str = None):
    if canal not in ("email", "whatsapp"):
        raise ValueError("canal doit etre 'email' ou 'whatsapp'")
    initialiser_db()
    _execute(
        "INSERT INTO responsables (nom, canal, contact, apikey, cree_le) VALUES (?, ?, ?, ?, ?)",
        (nom.strip(), canal, contact.strip(), (apikey or "").strip() or None,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )


def supprimer(resp_id: int):
    _execute("DELETE FROM responsables WHERE id = ?", (resp_id,))


def toggle_actif(resp_id: int):
    initialiser_db()
    rows = _execute("SELECT actif FROM responsables WHERE id = ?", (resp_id,), fetch=True)
    if rows:
        _execute("UPDATE responsables SET actif = ? WHERE id = ?", (0 if rows[0]["actif"] else 1, resp_id))


def lister(canal: str = None):
    initialiser_db()
    if canal:
        rows = _execute("SELECT * FROM responsables WHERE canal = ? ORDER BY nom", (canal,), fetch=True)
    else:
        rows = _execute("SELECT * FROM responsables ORDER BY canal, nom", fetch=True)
    return [dict(r) for r in rows] if rows else []


def emails_actifs() -> list[str]:
    """Adresses email actives. Retombe sur EMAIL_DEST (env) si la table est vide."""
    contacts = [r["contact"] for r in lister("email") if r["actif"]]
    if contacts:
        return contacts
    return [d.strip() for d in os.environ.get("EMAIL_DEST", "").split(",") if d.strip()]


def whatsapp_actifs() -> list[dict]:
    """Liste de {telephone, apikey} actifs. Retombe sur CALLMEBOT_PHONE/APIKEY
    (env, un seul destinataire) si la table est vide."""
    contacts = [
        {"telephone": r["contact"], "apikey": r["apikey"]}
        for r in lister("whatsapp") if r["actif"] and r["apikey"]
    ]
    if contacts:
        return contacts
    tel, cle = os.environ.get("CALLMEBOT_PHONE", ""), os.environ.get("CALLMEBOT_APIKEY", "")
    return [{"telephone": tel, "apikey": cle}] if (tel and cle) else []


# ---------------------------------------------------------------------------
# Page d'administration
# ---------------------------------------------------------------------------

destinataires_bp = Blueprint("destinataires", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Responsables des alertes</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;padding:2rem;max-width:820px;margin:0 auto}
  a{color:#3b82f6}
  table{width:100%;border-collapse:collapse;margin:1rem 0 2rem}
  th,td{padding:.5rem;border-bottom:1px solid #2a2d34;text-align:left}
  input,select{padding:.4rem;border-radius:6px;border:1px solid #333;background:#1a1d24;color:#e6e6e6;margin-right:.3rem}
  button{padding:.4rem .8rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer}
  .danger{background:#e01e5a}
  .msg{color:#4ade80;margin-bottom:1rem}
  .aide{color:#9aa0aa;font-size:.85rem;margin:.3rem 0 1rem}
</style></head><body>
<p><a href="{{ url_for('accueil') }}">&larr; Retour au dashboard</a></p>
<h1>Responsables des alertes</h1>
{% if msg %}<div class="msg">{{ msg }}</div>{% endif %}

<h3>Ajouter un responsable</h3>
<form method="post" action="{{ url_for('destinataires.ajouter_route') }}">
  <input name="nom" placeholder="nom" required>
  <select name="canal" id="canal-select" onchange="document.getElementById('champ-apikey').style.display = this.value === 'whatsapp' ? 'inline-block' : 'none'">
    <option value="email">email</option>
    <option value="whatsapp">whatsapp</option>
  </select>
  <input name="contact" placeholder="adresse email ou numero (+216...)" required>
  <input id="champ-apikey" name="apikey" placeholder="cle CallMeBot (whatsapp uniquement)" style="display:none">
  <button type="submit">Ajouter</button>
</form>
<p class="aide">Pour WhatsApp : le responsable doit d'abord envoyer "I allow callmebot to send me
messages" au contact CallMeBot pour recevoir sa propre cle API.</p>

<table>
<tr><th>Nom</th><th>Canal</th><th>Contact</th><th>Statut</th><th>Actions</th></tr>
{% for r in responsables %}
<tr>
  <td>{{ r.nom }}</td>
  <td>{{ r.canal }}</td>
  <td>{{ r.contact }}</td>
  <td>{{ 'actif' if r.actif else 'desactive' }}</td>
  <td>
    <form class="inline" method="post" action="{{ url_for('destinataires.toggle_route', resp_id=r.id) }}" style="display:inline">
      <button type="submit">{{ 'Desactiver' if r.actif else 'Reactiver' }}</button>
    </form>
    <form class="inline" method="post" action="{{ url_for('destinataires.supprimer_route', resp_id=r.id) }}" style="display:inline">
      <button type="submit" class="danger">Supprimer</button>
    </form>
  </td>
</tr>
{% endfor %}
</table>
</body></html>
"""


@destinataires_bp.route("/admin/responsables")
@admin_required
def page_responsables():
    return render_template_string(_PAGE, responsables=lister(), msg=request.args.get("msg"))


@destinataires_bp.route("/admin/responsables/ajouter", methods=["POST"])
@admin_required
def ajouter_route():
    nom = request.form.get("nom", "").strip()
    canal = request.form.get("canal", "email")
    contact = request.form.get("contact", "").strip()
    apikey = request.form.get("apikey", "").strip()
    if not nom or not contact or (canal == "whatsapp" and not apikey):
        return redirect(url_for("destinataires.page_responsables",
                                 msg="Champs manquants (cle CallMeBot requise pour whatsapp)."))
    ajouter(nom, canal, contact, apikey or None)
    return redirect(url_for("destinataires.page_responsables", msg=f"'{nom}' ajoute."))


@destinataires_bp.route("/admin/responsables/<int:resp_id>/toggle", methods=["POST"])
@admin_required
def toggle_route(resp_id):
    toggle_actif(resp_id)
    return redirect(url_for("destinataires.page_responsables", msg="Statut mis a jour."))


@destinataires_bp.route("/admin/responsables/<int:resp_id>/supprimer", methods=["POST"])
@admin_required
def supprimer_route(resp_id):
    supprimer(resp_id)
    return redirect(url_for("destinataires.page_responsables", msg="Supprime."))