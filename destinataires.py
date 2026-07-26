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
from auth import admin_required, TOKENS_CSS, JS_TEMA_ET_MENU, render_topbar

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
<title>Responsables des alertes - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>Responsables des alertes</h1>
    <p>Definit qui recoit les notifications par email ou WhatsApp, machine par machine.</p>
  </div>

  {% if msg %}<div class="toast">{{ msg }}</div>{% endif %}

  <div class="carte">
    <h3>Ajouter un responsable</h3>
    <p class="aide-carte">Pour WhatsApp : le responsable doit d'abord envoyer "I allow callmebot to send me
    messages" au contact CallMeBot pour recevoir sa propre cle API.</p>
    <form method="post" action="{{ url_for('destinataires.ajouter_route') }}">
      <div class="champs-form">
        <div class="champ"><label>Nom</label><input name="nom" placeholder="ex: Jean Dupont" required></div>
        <div class="champ" style="max-width:150px;"><label>Canal</label>
          <select name="canal" id="canal-select" onchange="document.getElementById('champ-apikey').style.display = this.value === 'whatsapp' ? 'flex' : 'none'">
            <option value="email">📧 Email</option>
            <option value="whatsapp">💬 WhatsApp</option>
          </select>
        </div>
        <div class="champ"><label>Contact</label><input name="contact" placeholder="email ou +216..." required></div>
        <div class="champ" id="champ-apikey" style="display:none;"><label>Cle CallMeBot</label><input name="apikey" placeholder="cle API"></div>
        <button type="submit" class="btn-principal">+ Ajouter</button>
      </div>
    </form>
  </div>

  <div class="carte">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
      <h3 style="margin:0;">Responsables enregistres</h3>
      <input class="recherche" id="recherche-resp" placeholder="Rechercher..." oninput="filtrerResponsables()">
    </div>
    {% if responsables %}
    <table class="table-pro" id="table-responsables">
      <tr><th>Nom</th><th>Canal</th><th>Contact</th><th>Statut</th><th>Actions</th></tr>
      {% for r in responsables %}
      <tr>
        <td><div class="cellule-nom"><span class="avatar">{{ r.nom[0]|upper }}</span> {{ r.nom }}</div></td>
        <td>{{ '📧 Email' if r.canal == 'email' else '💬 WhatsApp' }}</td>
        <td>{{ r.contact }}</td>
        <td><span class="badge {{ 'actif' if r.actif else 'inactif' }}">{{ 'Actif' if r.actif else 'Desactive' }}</span></td>
        <td class="actions-ligne">
          <form method="post" action="{{ url_for('destinataires.toggle_route', resp_id=r.id) }}" style="display:inline">
            <button type="submit" class="btn-fantome">{{ 'Desactiver' if r.actif else 'Reactiver' }}</button>
          </form>
          <form method="post" action="{{ url_for('destinataires.supprimer_route', resp_id=r.id) }}" style="display:inline"
                onsubmit="return confirm('Supprimer {{ r.nom }} ?');">
            <button type="submit" class="btn-danger">Supprimer</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <div class="vide-etat">Aucun responsable enregistre pour l'instant. Les alertes utilisent la configuration par defaut (variables d'environnement).</div>
    {% endif %}
  </div>
</main>

<script>""" + JS_TEMA_ET_MENU + """
function filtrerResponsables(){
  const q = document.getElementById('recherche-resp').value.toLowerCase();
  document.querySelectorAll('#table-responsables tr').forEach((ligne, i) => {
    if(i === 0) return;
    ligne.style.display = ligne.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body></html>
"""


@destinataires_bp.route("/admin/responsables")
@admin_required
def page_responsables():
    return render_template_string(
        _PAGE, responsables=lister(), msg=request.args.get("msg"),
        topbar=render_topbar("responsables"),
    )


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