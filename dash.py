"""
Dashboard v2 - Surveillance temps reel multi-serveurs
-----------------------------------------------------------
Version avancee du module 1 :
  - WebSocket (push instantane, pas de polling)
  - Multi-serveurs (le poste local + des agents distants via /api/ingest)
  - Graphiques avec historique (courbes CPU/Memoire sur les dernieres minutes)
  - Systeme de tickets/incidents (acquittement, resolution, MTTR)
  - Score de sante global par serveur
  - Chatbot IA sur l'historique

Lancement :
    python dashboard.py
Puis ouvre : http://localhost:5000

Pour connecter un agent distant, voir agent.py.
"""

import os
import threading
import time
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, request, send_file, url_for
from flask_socketio import SocketIO
from flask_login import current_user, login_required

from monitoring_core import lire_metriques, detecter_anomalies, expliquer, expliquer_par_type
import notifier
from notifier import envoyer_alerte_slack, envoyer_sms_alerte, envoyer_email_alerte, notifier_bureau_persistant
import historique
from rapport_pdf import lancer_planificateur_en_arriere_plan, generer_rapport
from chatbot import repondre_question
import auth
from destinataires import destinataires_bp

app = Flask(__name__)
# Cle de session generee et sauvegardee automatiquement (voir auth.py) : pas
# de variable d'environnement a definir, stable au fil des redemarrages du
# pod tant que le PVC reste attache.
app.secret_key = auth.obtenir_secret_key()
auth.init_login_manager(app)
auth.bootstrap_admin_auto()
app.register_blueprint(auth.auth_bp)
app.register_blueprint(destinataires_bp)


@app.before_request
def _proteger_routes():
    # /api/ingest reste protegee par CLE_API (machine-a-machine, pas de
    # session utilisateur possible pour un agent distant) : on la laisse
    # passer ici, sa propre verification de cle est faite dans la route.
    if request.endpoint == "api_ingest":
        return None
    return auth.verifier_acces()


socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Permet aux rappels de notification bureau de verifier l'etat REEL du
# systeme local (et pas un instantane fige au moment de la 1ere alerte).
notifier.definir_source_metriques(lambda: (_etat_serveurs.get("Serveur-Dashboard-OpenShift") or {}).get("metriques"))

# Cle partagee entre le dashboard et les agents distants (agent.py).
# A CHANGER en production : export DASHBOARD_API_KEY="quelque-chose-de-solide"
CLE_API = os.environ.get("DASHBOARD_API_KEY", "cle-demo-a-changer")

HISTORIQUE_MAX_POINTS = 120  # 120 x 5s = 10 minutes de courbe glissante

_etat_serveurs = {}
_verrou = threading.Lock()


def _point_courbe(m: dict) -> dict:
    return {
        "heure": m["timestamp"], "cpu": m["cpu"], "memoire": m["memoire"],
        "disque_pct": m.get("disque_pct"), "batterie": m.get("batterie"),
        "paquets_perdus": m.get("paquets_perdus"), "nb_processus": m.get("nb_processus"),
    }


def _etat_par_defaut():
    return {
        "metriques": None,
        "anomalies": [],
        "explication": None,
        "derniere_maj": None,
        "courbe": deque(maxlen=HISTORIQUE_MAX_POINTS),
    }


def _score_json(serveur, m):
    return historique.calculer_score_sante(serveur, m)


def traiter_mesure(serveur: str, m: dict, anomalies: list, explication: str = None):
    """Point d'entree unique pour traiter une mesure (locale ou distante).

    IMPORTANT (correction perf) : la courbe live est poussee au dashboard
    IMMEDIATEMENT ci-dessous, AVANT tout traitement des anomalies. Avant,
    l'explication IA + les envois Slack/WhatsApp/bureau (qui peuvent prendre
    plusieurs secondes chacun) tournaient AVANT le socketio.emit : pendant un
    stress-test, une anomalie est detectee a quasi chaque cycle de 5s, donc
    ce chemin lent tournait en boucle et retardait d'autant chaque point de
    la courbe -> dashboard qui semble "en retard"/buggé alors que la lecture
    des metriques, elle, est instantanee. Le traitement des anomalies
    (IA + alertes + historique) tourne maintenant dans un thread séparé,
    sans jamais bloquer l'affichage temps réel."""
    with _verrou:
        etat = _etat_serveurs.setdefault(serveur, _etat_par_defaut())
        etat["metriques"] = m
        etat["anomalies"] = anomalies
        if explication is not None:
            etat["explication"] = explication
        etat["derniere_maj"] = datetime.now().strftime("%H:%M:%S")
        etat["courbe"].append(_point_courbe(m))
        explication_actuelle = etat["explication"]

    if not anomalies:
        historique.enregistrer_serveur_vu(serveur)
    historique.enregistrer_mesure(serveur, m)  # historique long terme (downsample 1/min), rapide

    # Fait passer les incidents 'ouvert' dont la metrique est revenue a la
    # normale vers 'surveillance' (operation legere, pas de LLM/reseau).
    incidents_stabilises = historique.mettre_a_jour_stabilisation(serveur, m)

    score = _score_json(serveur, m)
    socketio.emit("maj_serveur", {
        "serveur": serveur, "metriques": m, "anomalies": anomalies,
        "explication": explication_actuelle, "score": score,
        "courbe_point": _point_courbe(m),
    })

    if incidents_stabilises:
        socketio.emit("incident_stabilise", {"serveur": serveur, "ids": incidents_stabilises})

    if anomalies:
        threading.Thread(
            target=_traiter_anomalies_en_arriere_plan,
            args=(serveur, m, anomalies, explication),
            daemon=True,
        ).start()


def _traiter_anomalies_en_arriere_plan(serveur: str, m: dict, anomalies: list, explication: str):
    """Genere l'explication IA (une PAR TYPE d'anomalie, si pas deja fournie)
    et envoie les alertes Slack/WhatsApp/bureau + sauvegarde l'incident en
    base. Tourne dans un thread separe du cycle de lecture des metriques :
    c'est la partie lente (LLM local + requetes reseau), elle ne doit jamais
    retarder la courbe live du dashboard."""
    try:
        if explication is None:
            explications_par_type = expliquer_par_type(m, anomalies)
        else:
            # Explication deja fournie par l'appelant (ex: agent distant) :
            # on ne peut pas la re-decouper par type, on l'utilise pour tous.
            explications_par_type = {}

        # Texte combine (une ligne par type) pour Slack/WhatsApp, qui recoivent
        # de toute facon TOUTES les anomalies critiques dans un seul message.
        explication_combinee = explication or "\n".join(
            f"• {v}" for v in explications_par_type.values()
        ) or ""

        envoyer_alerte_slack(m, anomalies, explication_combinee)
        envoyer_sms_alerte(m, anomalies, explication_combinee)
        envoyer_email_alerte(m, anomalies, explication_combinee)
        notifier_bureau_persistant(m, anomalies, explication_combinee, explications_par_type)
        historique.enregistrer_anomalie(m, anomalies, explication_combinee, serveur=serveur,
                                         explications_par_type=explications_par_type)

        with _verrou:
            etat = _etat_serveurs.setdefault(serveur, _etat_par_defaut())
            etat["explication"] = explication_combinee

        # Diffuse l'explication (arrivee un peu apres les metriques) sans
        # retoucher au reste de l'etat deja affiche.
        socketio.emit("maj_explication", {"serveur": serveur, "explication": explication_combinee})
    except Exception as e:
        print(f"[dashboard] Erreur traitement anomalies en arriere-plan (ignoree) : {e}")


def boucle_surveillance_locale():
    while True:
        try:
            m = lire_metriques()
            anomalies = detecter_anomalies(m)
            # L'explication IA et les alertes sont générées/envoyées en
            # arrière-plan par traiter_mesure (voir sa docstring) : ce cycle
            # reste rapide (lecture métriques + push dashboard uniquement),
            # peu importe le nombre d'anomalies en cours.
            traiter_mesure("Serveur-Dashboard-OpenShift", m, anomalies)
        except Exception as e:
            # Filet de securite : une erreur ponctuelle (Ollama, reseau, DB...)
            # ne doit JAMAIS arreter definitivement la surveillance.
            print(f"[dashboard] Erreur dans le cycle de surveillance (ignoree, on continue) : {e}")
        time.sleep(5)


def boucle_resolution_auto():
    compteur_cycles = 0
    while True:
        avant = {i["id"] for i in historique.lister_incidents(statut="ouvert")}
        historique.resoudre_incidents_expires()
        apres_ouverts = {i["id"] for i in historique.lister_incidents(statut="ouvert")}
        for resolu_id in (avant - apres_ouverts):
            socketio.emit("incident_resolu", {"id": resolu_id})

        compteur_cycles += 1
        if compteur_cycles % 60 == 0:  # une fois par heure environ (60 x 60s)
            historique.nettoyer_vieilles_mesures()

        time.sleep(60)

def boucle_nettoyage_notifications():
    """Nettoie périodiquement les anomalies actives obsolètes."""
    while True:
        try:
            import notifier
            notifier.nettoyer_anomalies_obsoletes()
        except Exception as e:
            print(f"[dashboard] Erreur nettoyage notifications: {e}")
        time.sleep(3600)  # Nettoyage toutes les heures

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    if request.headers.get("X-API-KEY") != CLE_API:
        return jsonify({"erreur": "cle API invalide"}), 403
    data = request.get_json(force=True, silent=True) or {}
    serveur = data.get("serveur", "inconnu")
    m = data.get("metriques")
    anomalies = data.get("anomalies", [])
    explication = data.get("explication")
    if not m:
        return jsonify({"erreur": "champ 'metriques' manquant"}), 400
    traiter_mesure(serveur, m, anomalies, explication)
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    with _verrou:
        return jsonify({
            nom: {
                "metriques": e["metriques"], "anomalies": e["anomalies"],
                "explication": e["explication"], "derniere_maj": e["derniere_maj"],
                "courbe": list(e["courbe"]), "score": _score_json(nom, e["metriques"]),
            }
            for nom, e in _etat_serveurs.items()
        })


@app.route("/api/incidents")
def api_incidents():
    limite = request.args.get("limite", default=50, type=int)
    return jsonify(historique.lister_incidents(
        serveur=request.args.get("serveur"), statut=request.args.get("statut"), limite=limite,
        type_anomalie=request.args.get("type"), niveau=request.args.get("niveau"),
        depuis=request.args.get("depuis"), jusqua=request.args.get("jusqua"),
    ))


@app.route("/api/incidents/compte")
def api_incidents_compte():
    return jsonify(historique.compter_incidents_par_statut(serveur=request.args.get("serveur")))


@app.route("/api/acquitter", methods=["POST"])
def api_acquitter():
    """Appele quand l'utilisateur clique 'J'ai vu' dans le dashboard : relie
    l'acquittement web aux rappels de notification bureau (Windows), qui
    s'arretent mais reprendront automatiquement si le probleme persiste."""
    data = request.get_json(force=True, silent=True) or {}
    type_anomalie = data.get("type")
    if not type_anomalie:
        return jsonify({"erreur": "champ 'type' manquant"}), 400
    notifier.acquitter(type_anomalie)
    return jsonify({"ok": True})


@app.route("/api/infos_types")
def api_infos_types():
    """Explications en langage simple par type d'anomalie (phrase courte +
    explication detaillee + solution), pour un public non-technique."""
    return jsonify(historique.INFOS_ANOMALIES)


@app.route("/api/rapport")
def api_rapport():
    """Genere un rapport PDF a la demande et le renvoie en telechargement.
    ?jours=1|7|30|90 (defaut 7) et ?serveur=nom (optionnel, sinon tous les
    serveurs). La generation (graphiques + PDF) prend quelques secondes,
    c'est normal — le bouton cote dashboard affiche un indicateur de
    chargement pendant ce temps."""
    jours = request.args.get("jours", default=7, type=int)
    serveur = request.args.get("serveur") or None
    try:
        chemin = generer_rapport(jours_historique=jours, serveur=serveur)
    except Exception as e:
        return jsonify({"erreur": f"Echec de generation du rapport : {e}"}), 500
    return send_file(chemin, as_attachment=True, download_name=os.path.basename(chemin))


@app.route("/api/historique_metriques")
def api_historique_metriques():
    serveur = request.args.get("serveur", "Serveur-Dashboard-OpenShift")
    heures = float(request.args.get("heures", 1))
    mesures = historique.recuperer_mesures(serveur, heures=heures)
    incidents = historique.lister_incidents(serveur=serveur)
    return jsonify({"mesures": mesures, "incidents": incidents})


@app.route("/api/incidents/<int:incident_id>/resoudre", methods=["POST"])
def api_resoudre_incident(incident_id):
    historique.resoudre_incident_manuellement(incident_id)
    socketio.emit("incident_resolu", {"id": incident_id})
    return jsonify({"ok": True})


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(force=True, silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"erreur": "question vide"}), 400
    reponse = repondre_question(question, serveur=data.get("serveur"))
    return jsonify({"reponse": reponse})


@app.route("/")
@login_required
def accueil():
    liens_admin = ""
    if current_user.is_admin:
        liens_admin = (
            f'<a class="menu-item" href="{url_for("auth.admin_utilisateurs")}">👤 Gérer les utilisateurs</a>'
            f'<a class="menu-item" href="{url_for("destinataires.page_responsables")}">📣 Gérer les responsables</a>'
        )
    barre = f'''
    <div class="user-menu-wrapper">
        <span class="user-name" id="userMenuBtn">{current_user.username} ▾</span>
        <div class="user-dropdown" id="userDropdown">
            <div class="menu-item" onclick="alert('Profil - Fonctionnalité à venir')">👤 Profil</div>
            <div class="menu-item" onclick="alert('Paramètres - Fonctionnalité à venir')">⚙️ Paramètres</div>
            {liens_admin}
            <hr style="border-color:var(--border); margin:4px 0;">
            <a class="menu-item" href="{url_for("auth.logout")}" style="color:var(--crit);">🚪 Déconnexion</a>
        </div>
    </div>
    '''
    return PAGE_HTML.replace("<!--__BARRE_UTILISATEUR__-->", barre)


@socketio.on("connect")
def on_connect():
    # Le handshake WebSocket partage le cookie de session Flask : on peut
    # donc verifier ici aussi que l'utilisateur est bien connecte, sinon
    # les donnees temps reel fuiteraient meme avec les routes HTTP protegees.
    if not current_user.is_authenticated:
        return False  # refuse la connexion socket.io
    with _verrou:
        socketio.emit("etat_initial", {
            nom: {
                "metriques": e["metriques"], "anomalies": e["anomalies"],
                "explication": e["explication"], "courbe": list(e["courbe"]),
                "score": _score_json(nom, e["metriques"]),
            }
            for nom, e in _etat_serveurs.items()
        })


PAGE_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>SENTINEL - Surveillance Infrastructure</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
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
  body{transition:background-color .2s, color .2s;}
  *{box-sizing:border-box;}
  body{margin:0; background:var(--bg); color:var(--text); font-family:Inter,system-ui,-apple-system,sans-serif; min-height:100vh;}
  #layout{display:flex; min-height:100vh;}

  /* Barre laterale - liste des serveurs */
  #sidebar{width:220px; background:var(--panel); border-right:1px solid var(--border); padding:18px 12px; flex-shrink:0;}
  #sidebar h2{font-size:12px; letter-spacing:.12em; color:var(--muted); text-transform:uppercase; margin:6px 8px 14px;}
  .serveur-item{display:flex; align-items:center; gap:8px; padding:9px 10px; border-radius:6px; cursor:pointer; font-size:13px; margin-bottom:3px;}
  .serveur-item:hover{background:var(--panel2);}
  .serveur-item.actif{background:rgba(88,166,255,.12); color:var(--accent);}
  .serveur-item .pastille{width:8px; height:8px; border-radius:50%; flex-shrink:0;}

  main{flex:1; padding:22px 28px; max-width:1000px;}
  header{display:flex; align-items:center; justify-content:space-between; margin-bottom:18px;}
  header h1{font-size:17px; margin:0; letter-spacing:.04em;}
  header .sous{color:var(--muted); font-size:12px; margin-top:3px;}
  #horloge{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace; color:var(--muted); font-size:13px;}

  .ligne-haut{display:flex; gap:16px; margin-bottom:18px; flex-wrap:wrap;}
  .carte-score{background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 20px; display:flex; align-items:center; gap:16px;}
  .carte-score svg{transform:rotate(-90deg);}
  .carte-score .chiffre{font-family:'JetBrains Mono',monospace; font-size:22px; font-weight:700;}
  .carte-score .detail{font-size:12px; color:var(--muted); line-height:1.5;}

  #banniere{display:none; margin-bottom:18px; padding:14px 18px; background:rgba(248,81,73,.08); border:1px solid var(--crit); border-left:4px solid var(--crit); border-radius:6px;}
  #banniere.actif{display:block; animation:pulse 1.6s ease-in-out infinite;}
  #banniere.warning{border-color:var(--warn); border-left-color:var(--warn); background:rgba(210,153,34,.08);}
  #banniere.observation{display:block; animation:none; border-color:var(--accent); border-left-color:var(--accent); background:rgba(88,166,255,.06);}
  @keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(248,81,73,.35);} 50%{box-shadow:0 0 0 8px rgba(248,81,73,0);}}
  #banniere h3{margin:0 0 6px; font-size:13px; color:var(--crit);}
  #banniere.warning h3{color:var(--warn);}
  #banniere.observation h3{color:var(--accent);}
  #banniere ul{margin:6px 0; padding-left:18px; font-family:'JetBrains Mono',monospace; font-size:12.5px;}
  #banniere .explication{margin-top:8px; font-size:13px; line-height:1.5; border-top:1px solid var(--border); padding-top:8px;}

  .grille{display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; margin-bottom:20px;}
  .carte{background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px;}
  .carte .label{font-size:10.5px; color:var(--muted); letter-spacing:.06em; text-transform:uppercase; margin-bottom:6px;}
  .carte .valeur{font-family:'JetBrains Mono',monospace; font-size:22px; font-weight:600;}

  #zone-graph{background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:20px;}
  #zone-graph h3{margin:0 0 10px; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:600;}
  #canvasGraph{max-height:220px;}
  .btn-periode{background:transparent; border:1px solid var(--border); color:var(--muted); font-size:11px; padding:5px 10px; border-radius:5px; cursor:pointer; margin-left:5px;}
  .btn-periode.actif{background:var(--accent); border-color:var(--accent); color:#08131f; font-weight:600;}
  #btn-rapport.chargement{opacity:.6; cursor:wait; pointer-events:none;}

  .menu-deroulant{display:none; position:absolute; top:calc(100% + 6px); right:0; background:var(--panel); border:1px solid var(--border); border-radius:8px; min-width:180px; z-index:50; box-shadow:0 8px 24px rgba(0,0,0,.25); overflow:hidden;}
  .menu-deroulant.ouvert{display:block;}
  .menu-item{padding:9px 14px; font-size:12.5px; color:var(--text); cursor:pointer;}
  .menu-item:hover{background:var(--panel2);}

  .grille-graphs-secondaires{display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; margin-bottom:20px;}
  .zone-graph-mini{background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px;}
  .zone-graph-mini h3{margin:0 0 8px; font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:600;}
  .zone-graph-mini canvas{max-height:260px;}

  #zone-incidents{background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; margin-bottom:90px;}
  #zone-incidents h3{margin:0; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:600;}
  .compteur-incidents{display:flex; gap:6px; font-size:11px;}
  .compteur-incidents span{padding:2px 8px; border-radius:10px; font-weight:600;}
  .compteur-incidents .c-ouvert{background:rgba(248,81,73,.15); color:var(--crit);}
  .compteur-incidents .c-surveillance{background:rgba(88,166,255,.15); color:var(--accent);}
  .compteur-incidents .c-resolu{background:rgba(63,185,80,.15); color:var(--ok);}
  #btn-plus-incidents{width:100%; margin-top:10px; background:var(--panel2); border:1px solid var(--border); color:var(--muted); font-size:11.5px; padding:8px; border-radius:6px; cursor:pointer;}
  #btn-plus-incidents:hover{color:var(--text);}
  .incident{display:flex; justify-content:space-between; align-items:center; padding:9px 0; border-bottom:1px solid var(--border); font-size:12.5px;}
  .incident:last-child{border-bottom:none;}
  .incident .info b{font-family:'JetBrains Mono',monospace;}
  .incident .info .phrase{color:var(--muted); font-size:11.5px; margin-top:3px; line-height:1.4;}
  .incident .badge{font-size:10px; padding:2px 8px; border-radius:10px; margin-left:6px;}
  .badge.ouvert{background:rgba(248,81,73,.15); color:var(--crit);}
  .badge.surveillance{background:rgba(88,166,255,.15); color:var(--accent);}
  .badge.resolu{background:rgba(63,185,80,.15); color:var(--ok);}
  .incident button{background:var(--accent); border:none; color:#08131f; font-size:11px; padding:5px 10px; border-radius:5px; cursor:pointer; font-weight:600; flex-shrink:0;}
  .incident button:disabled{opacity:.4; cursor:default;}
  #vide-incidents{color:var(--muted); font-size:12.5px;}

  /* Modal Historique detaille */
  #modal-historique{display:none; position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:100; align-items:center; justify-content:center; padding:24px;}
  #modal-historique.ouvert{display:flex;}
  #modal-historique .contenu{background:var(--panel); border:1px solid var(--border); border-radius:12px; width:100%; max-width:760px; max-height:85vh; display:flex; flex-direction:column; overflow:hidden;}
  #modal-historique .entete{padding:16px 20px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center;}
  #modal-historique .entete h2{margin:0; font-size:15px;}
  #modal-historique .fermer{background:transparent; border:none; color:var(--muted); font-size:20px; cursor:pointer; line-height:1;}
  .filtres-historique{display:flex; flex-wrap:wrap; gap:8px; padding:12px 20px; border-bottom:1px solid var(--border); background:var(--panel2);}
  .filtres-historique select, .filtres-historique input[type="date"]{background:var(--panel); border:1px solid var(--border); color:var(--text); font-size:11.5px; padding:6px 8px; border-radius:5px;}
  #modal-historique .liste{overflow-y:auto; padding:16px 20px;}
  .fiche-incident{border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:12px; background:var(--panel2);}
  .fiche-incident .entete-fiche{display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:6px;}
  .fiche-incident .titre-fiche{font-weight:700; font-size:13.5px;}
  .fiche-incident .temps-fiche{color:var(--muted); font-size:11px; font-family:'JetBrains Mono',monospace;}
  .fiche-incident .bloc{margin-top:8px; font-size:12.5px; line-height:1.5;}
  .fiche-incident .bloc b{color:var(--muted); font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; display:block; margin-bottom:2px;}

  /* Chatbot flottant */
  #chat-bulle{position:fixed; bottom:22px; right:22px; width:52px; height:52px; border-radius:50%; background:var(--accent); display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:22px; box-shadow:0 4px 14px rgba(0,0,0,.4); z-index:50;}
  #chat-panel{position:fixed; bottom:86px; right:22px; width:330px; height:420px; background:var(--panel); border:1px solid var(--border); border-radius:12px; display:none; flex-direction:column; overflow:hidden; z-index:50; box-shadow:0 8px 30px rgba(0,0,0,.5);}
  #chat-panel.ouvert{display:flex;}
  #chat-entete{padding:12px 14px; border-bottom:1px solid var(--border); font-size:13px; font-weight:600;}
  #chat-messages{flex:1; overflow-y:auto; padding:12px; font-size:12.5px; display:flex; flex-direction:column; gap:8px;}
  .bulle{padding:8px 11px; border-radius:10px; max-width:85%; line-height:1.4;}
  .bulle.moi{align-self:flex-end; background:var(--accent); color:#08131f;}
  .bulle.bot{align-self:flex-start; background:var(--panel2); border:1px solid var(--border);}
  #chat-form{display:flex; border-top:1px solid var(--border);}
  #chat-input{flex:1; background:transparent; border:none; color:var(--text); padding:10px 12px; font-size:12.5px; outline:none;}
  #chat-form button{background:none; border:none; color:var(--accent); font-weight:700; padding:0 14px; cursor:pointer;}

  
  /* Menu utilisateur déroulant */
.user-menu-wrapper {
  position: relative;
  display: inline-block;
}
.user-name {
  color: var(--text);
  font-size: 13px;
  cursor: pointer;
  padding: 6px 10px;
  border-radius: 6px;
  transition: background 0.2s;
  user-select: none;
}
.user-name:hover {
  background: var(--panel2);
}
.user-dropdown {
  display: none;
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  min-width: 200px;
  z-index: 100;
  box-shadow: 0 8px 30px rgba(0,0,0,0.4);
  padding: 6px 0;
  overflow: hidden;
}
.user-dropdown.ouvert {
  display: block;
}
.user-dropdown .menu-item {
  display: block;
  padding: 8px 16px;
  font-size: 13px;
  color: var(--text);
  text-decoration: none;
  cursor: pointer;
  transition: background 0.15s;
  border: none;
  background: transparent;
  width: 100%;
  text-align: left;
}
.user-dropdown .menu-item:hover {
  background: var(--panel2);
}
.user-dropdown hr {
  margin: 4px 12px;
  border: none;
  border-top: 1px solid var(--border);
}
</style>
</head>
<body>

<div id="layout">
  <div id="sidebar">
    <h2>Serveurs</h2>
    <div id="liste-serveurs"><div style="color:var(--muted); font-size:12px; padding:8px;">En attente...</div></div>
  </div>

  <main>
    <header>
      <div>
        <h1 id="titre-serveur">SENTINEL</h1>
        <div class="sous">surveillance infrastructure temps reel</div>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <div style="position:relative;">
          <button class="btn-periode" id="btn-rapport" onclick="toggleMenuRapport()" style="padding:7px 12px;">📄 Rapport</button>
          <div id="menu-rapport" class="menu-deroulant">
            <div class="menu-item" onclick="genererRapport(1)">Journalier (24h)</div>
            <div class="menu-item" onclick="genererRapport(7)">Hebdomadaire (7j)</div>
            <div class="menu-item" onclick="genererRapport(30)">Mensuel (30j)</div>
            <div class="menu-item" onclick="genererRapport(90)">Trimestriel (90j)</div>
          </div>
        </div>
        <button class="btn-periode" onclick="ouvrirHistorique()" style="padding:7px 12px;">🕘 Historique</button>
        <button class="btn-periode" id="btn-theme" onclick="basculerTheme()" style="padding:7px 10px;">🌙</button>
        <div id="horloge">--:--:--</div>
        <!--__BARRE_UTILISATEUR__-->
      </div>
    </header>

    <div class="ligne-haut">
      <div class="carte-score">
        <svg width="64" height="64" viewBox="0 0 64 64">
          <circle cx="32" cy="32" r="26" stroke="var(--border)" stroke-width="7" fill="none"/>
          <circle id="cercle-score" cx="32" cy="32" r="26" stroke="#3FB950" stroke-width="7" fill="none"
                  stroke-dasharray="163" stroke-dashoffset="163" stroke-linecap="round"/>
        </svg>
        <div>
          <div class="chiffre" id="valeur-score">--</div>
          <div class="detail" id="detail-score">Score de sante</div>
        </div>
      </div>
    </div>

    <div id="banniere">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
        <h3 id="banniere-titre" style="flex:1;">ANOMALIE DETECTEE</h3>
        <button onclick="acquitterBanniere()" id="btn-acquitter"
                style="background:transparent; border:1px solid currentColor; color:inherit; font-size:11px; padding:4px 10px; border-radius:5px; cursor:pointer; flex-shrink:0;">
          J'ai vu ✓
        </button>
      </div>
      <ul id="banniere-liste"></ul>
      <div class="explication" id="banniere-explication" style="display:flex; align-items:flex-start; gap:8px; justify-content:space-between;">
        <span id="banniere-explication-texte" style="flex:1;"></span>
        <button onclick="lireHautVoix()" title="Lire à voix haute"
                style="background:transparent; border:1px solid currentColor; color:inherit; font-size:13px; padding:3px 8px; border-radius:5px; cursor:pointer; flex-shrink:0;">
          🔊
        </button>
      </div>
    </div>

    <div class="grille" id="grille-metriques"></div>

    <div id="zone-graph">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0;">CPU / Memoire</h3>
        <div id="selecteur-periode">
          <button class="btn-periode actif" data-periode="live" onclick="changerPeriode('live')">Live (10 min)</button>
          <button class="btn-periode" data-periode="1" onclick="changerPeriode('1')">1h</button>
          <button class="btn-periode" data-periode="6" onclick="changerPeriode('6')">6h</button>
          <button class="btn-periode" data-periode="24" onclick="changerPeriode('24')">24h</button>
        </div>
      </div>
      <canvas id="canvasGraph"></canvas>
    </div>

    <div class="grille-graphs-secondaires">
      <div class="zone-graph-mini" style="grid-column:1/-1;">
        <h3>Disque · Batterie · Reseau · Processus</h3>
        <canvas id="canvasCombine"></canvas>
      </div>
    </div>

    <div id="zone-incidents">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h3 style="margin:0;">Incidents</h3>
        <div id="compteur-incidents" class="compteur-incidents"></div>
      </div>
      <div id="liste-incidents"><div id="vide-incidents">Aucun incident pour l'instant.</div></div>
    </div>
  </main>
</div>

<div id="chat-bulle" onclick="toggleChat()">&#128172;</div>
<div id="chat-panel">
  <div id="chat-entete">Assistant IA - historique</div>
  <div id="chat-messages">
    <div class="bulle bot">Pose-moi une question sur l'historique, ex : "pourquoi le CPU a eu un probleme cette semaine ?"</div>
  </div>
  <form id="chat-form">
    <input id="chat-input" type="text" placeholder="Ta question..." autocomplete="off">
    <button type="submit">Envoyer</button>
  </form>
</div>

<div id="modal-historique">
  <div class="contenu">
    <div class="entete">
      <h2>Historique des anomalies</h2>
      <button class="fermer" onclick="fermerHistorique()">&times;</button>
    </div>
    <div class="filtres-historique">
      <select id="filtre-type"><option value="">Tous les types</option></select>
      <select id="filtre-niveau">
        <option value="">Tous niveaux</option>
        <option value="critique">Critique</option>
        <option value="warning">Warning</option>
      </select>
      <select id="filtre-statut">
        <option value="">Tous statuts</option>
        <option value="ouvert">Ouvert seulement</option>
        <option value="surveillance">En observation seulement</option>
        <option value="resolu">Resolu seulement</option>
      </select>
      <input type="date" id="filtre-depuis" title="Depuis le">
      <input type="date" id="filtre-jusqua" title="Jusqu'au">
      <button class="btn-periode" onclick="ouvrirHistorique()" style="padding:7px 12px;">Filtrer</button>
      <button class="btn-periode" onclick="reinitialiserFiltresHistorique()" style="padding:7px 12px;">Reinitialiser</button>
    </div>
    <div class="liste" id="liste-historique"></div>
  </div>
</div>

<script>
const socket = io();
let etatServeurs = {};
let serveurActif = null;
const CIRCONFERENCE = 2 * Math.PI * 26;

// Incidents ouverts connus par serveur (rafraichis via chargerIncidents()),
// et incidents que l'utilisateur a explicitement "vus" (bouton "J'ai vu ✓").
// Le bandeau reste affiche tant qu'il existe un incident ouvert non acquitte,
// au lieu de suivre l'etat instantane des metriques (qui change toutes les 5s
// et faisait disparaitre le bandeau des qu'un seul cycle repassait sous le seuil).
let incidentsParServeur = {};
let incidentsAcquittes = new Set();

const CARTES = [
  {cle:"cpu", label:"CPU", unite:"%", seuil:85},
  {cle:"memoire", label:"Memoire", unite:"%", seuil:85},
  {cle:"disque_pct", label:"Disque", unite:"%", seuil:90},
  {cle:"nb_processus", label:"Processus", unite:"", seuil:400},
  {cle:"paquets_perdus", label:"Paquets perdus", unite:"", seuil:100},
  {cle:"batterie", label:"Batterie", unite:"%", seuil:15},
];

function majHorloge(){ document.getElementById('horloge').textContent = new Date().toLocaleTimeString('fr-FR'); }
setInterval(majHorloge, 1000); majHorloge();

function couleurCSS(nomVariable){
  return getComputedStyle(document.body).getPropertyValue(nomVariable).trim();
}

// Options communes : hover en mode "index" -> survoler la courbe montre la
// valeur exacte de TOUS les datasets a ce point (tooltip Chart.js natif).
function optionsCommunes(yMax){
  return {
    responsive:true, animation:{duration:280}, maintainAspectRatio:false,
    interaction:{mode:'index', intersect:false},
    scales:{
      y:{min:0, max:yMax, ticks:{color:couleurCSS('--muted')}, grid:{color:couleurCSS('--border')}},
      x:{ticks:{color:couleurCSS('--muted'), maxTicksLimit:8}, grid:{color:couleurCSS('--border')}}
    },
    plugins:{legend:{labels:{color:couleurCSS('--text')}}, tooltip:{mode:'index', intersect:false}}
  };
}

const TOUS_LES_GRAPHIQUES = [];

const ctx = document.getElementById('canvasGraph').getContext('2d');
const graphique = new Chart(ctx, {
  type: 'line',
  data: { labels: [], datasets: [
    {label:'CPU %', data:[], borderColor:'#F85149', backgroundColor:'rgba(248,81,73,.08)', tension:.35, fill:true, pointRadius:0},
    {label:'Memoire %', data:[], borderColor:'#58A6FF', backgroundColor:'rgba(88,166,255,.08)', tension:.35, fill:true, pointRadius:0},
    {label:'Incidents', data:[], type:'scatter', showLine:false, pointRadius:5, pointStyle:'triangle',
     borderColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149',
     backgroundColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149'},
  ]},
  options: optionsCommunes(100)
});
TOUS_LES_GRAPHIQUES.push(graphique);

// --- Graphique secondaire combiné (disque / batterie / reseau / processus) -
// Un seul graphique au lieu de 4, pour optimiser l'espace et mieux voir les
// tendances ensemble. Deux axes Y : pourcentage (disque/batterie, 0-100 a
// gauche) et compteur (paquets perdus/processus, echelle libre a droite),
// car ce sont des unites trop differentes pour partager un seul axe.
const CONFIG_METRIQUES_SECONDAIRES = [
  {champ:'disque_pct',     label:'Disque %',        couleur:'#D29922', type:'disque',    axe:'y'},
  {champ:'batterie',       label:'Batterie %',       couleur:'#3FB950', type:'batterie',  axe:'y'},
  {champ:'paquets_perdus', label:'Paquets perdus',   couleur:'#58A6FF', type:'reseau',    axe:'y1'},
  {champ:'nb_processus',   label:'Processus',        couleur:'#BC8CFF', type:'processus', axe:'y1'},
];
// Index des 2 datasets "Incidents" (un par axe) dans graphiqueCombine
const IDX_INCIDENTS_POURCENT = CONFIG_METRIQUES_SECONDAIRES.length;
const IDX_INCIDENTS_COMPTE = CONFIG_METRIQUES_SECONDAIRES.length + 1;

const graphiqueCombine = new Chart(document.getElementById('canvasCombine').getContext('2d'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      ...CONFIG_METRIQUES_SECONDAIRES.map(cfg => ({
        label: cfg.label, data: [], borderColor: cfg.couleur, backgroundColor: cfg.couleur + '15',
        tension: .35, fill: false, pointRadius: 0, yAxisID: cfg.axe,
      })),
      {label:'Incidents', data:[], type:'scatter', showLine:false, pointRadius:5, pointStyle:'triangle', yAxisID:'y',
       borderColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149',
       backgroundColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149'},
      {label:'Incidents', data:[], type:'scatter', showLine:false, pointRadius:5, pointStyle:'triangle', yAxisID:'y1',
       borderColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149',
       backgroundColor: ctx => ctx.raw?.niveau === 'warning' ? '#D29922' : '#F85149'},
    ],
  },
  options: {
    responsive:true, animation:{duration:280}, maintainAspectRatio:false,
    interaction:{mode:'index', intersect:false},
    scales:{
      y:{min:0, max:100, position:'left',
         title:{display:true, text:'%', color:couleurCSS('--muted')},
         ticks:{color:couleurCSS('--muted')}, grid:{color:couleurCSS('--border')}},
      y1:{min:0, position:'right',
          title:{display:true, text:'compte', color:couleurCSS('--muted')},
          ticks:{color:couleurCSS('--muted')}, grid:{drawOnChartArea:false}},
      x:{ticks:{color:couleurCSS('--muted'), maxTicksLimit:8}, grid:{color:couleurCSS('--border')}},
    },
    plugins:{legend:{labels:{color:couleurCSS('--text'), filter: (item) => item.text !== 'Incidents (compte)'}},
    tooltip:{mode:'index', intersect:false},
    },
  },
});
TOUS_LES_GRAPHIQUES.push(graphiqueCombine);

function couleurScore(score){
  if(score >= 80) return '#3FB950';
  if(score >= 50) return '#D29922';
  return '#F85149';
}

// --- Theme clair/sombre ------------------------------------------------
function basculerTheme(){
  const clair = document.body.classList.toggle('light');
  localStorage.setItem('sentinel-theme', clair ? 'light' : 'dark');
  document.getElementById('btn-theme').textContent = clair ? '☀️' : '🌙';
  // Les couleurs des graphiques sont lues depuis les variables CSS a la
  // creation : il faut les recalculer manuellement apres un changement de theme.
  TOUS_LES_GRAPHIQUES.forEach(g => {
    Object.values(g.options.scales).forEach(echelle => {
      if(echelle.ticks) echelle.ticks.color = couleurCSS('--muted');
      if(echelle.grid && echelle.grid.color) echelle.grid.color = couleurCSS('--border');
      if(echelle.title) echelle.title.color = couleurCSS('--muted');
    });
    g.options.plugins.legend.labels.color = couleurCSS('--text');
    g.update();
  });
}
(function initTheme(){
  if(localStorage.getItem('sentinel-theme') === 'light'){
    document.body.classList.add('light');
    document.getElementById('btn-theme').textContent = '☀️';
  }
})();

// --- Lecture a voix haute (utile pour surveiller sans regarder l'ecran) ---
function lireHautVoix(){
  if(!('speechSynthesis' in window)) return;
  const texte = document.getElementById('banniere-explication-texte').textContent;
  if(!texte) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(texte);
  u.lang = 'fr-FR';
  window.speechSynthesis.speak(u);
}

let INFOS_TYPES = {};
fetch('/api/infos_types').then(r => r.json()).then(d => {
  INFOS_TYPES = d;
  const select = document.getElementById('filtre-type');
  if(select){
    Object.keys(d).forEach(type => {
      const opt = document.createElement('option');
      opt.value = type;
      opt.textContent = type;
      select.appendChild(opt);
    });
  }
}).catch(() => {});

function phraseType(type){
  return (INFOS_TYPES[type] && INFOS_TYPES[type].phrase) || '';
}

// --- Bandeau d'anomalie persistant -----------------------------------------
// Le bandeau distingue maintenant 3 etats :
//  - 'ouvert'       : probleme actif (metrique toujours au-dessus du seuil) -> rouge/orange, pulse
//  - 'surveillance' : la metrique est revenue a la normale, mais on reste
//                      attentif quelques minutes avant de considerer le
//                      probleme vraiment termine -> bleu calme, ne pulse pas
//                      (AVANT : l'incident restait affiche comme "ouvert",
//                      alarme active, alors que le probleme n'existait plus)
//  - acquitte ('J'ai vu') : masque cote client jusqu'a nouvelle occurrence
function renderBanniere(){
  const banniere = document.getElementById('banniere');
  if(!serveurActif){ banniere.className = ''; return; }

  const incidents = (incidentsParServeur[serveurActif] || []).filter(i => i.statut === 'ouvert' || i.statut === 'surveillance');
  const nonAcquittes = incidents.filter(i => !incidentsAcquittes.has(i.id));

  if(nonAcquittes.length === 0){
    banniere.className = '';
    return;
  }

  const ouverts = nonAcquittes.filter(i => i.statut === 'ouvert');
  const enSurveillance = nonAcquittes.filter(i => i.statut === 'surveillance');
  const critique = ouverts.some(i => i.niveau_max === 'critique');

  let classe, titre;
  if(ouverts.length > 0){
    classe = 'actif ' + (critique ? '' : 'warning');
    titre = (critique ? 'ANOMALIE CRITIQUE EN COURS' : 'ANOMALIE EN COURS') + ` (${ouverts.length})`;
  } else {
    classe = 'observation';
    titre = `À surveiller — revenu à la normale récemment (${enSurveillance.length})`;
  }
  banniere.className = classe;
  document.getElementById('banniere-titre').textContent = titre;

  document.getElementById('banniere-liste').innerHTML = nonAcquittes.map(i => `
    <li>
      <b>${i.type_anomalie}</b> (${i.statut === 'surveillance' ? 'revenu à la normale, en observation' : i.niveau_max}) — depuis ${i.debut}, ${i.nb_occurrences}x<br>
      <span style="color:var(--muted); font-family:inherit; font-size:12px;">${i.derniere_explication || phraseType(i.type_anomalie)}</span>
    </li>`
  ).join('');
  document.getElementById('banniere-explication-texte').textContent =
    nonAcquittes.map(i => `${i.type_anomalie} : ${i.derniere_explication || phraseType(i.type_anomalie)}`).join('. ');
}

function acquitterBanniere(){
  const incidents = (incidentsParServeur[serveurActif] || []).filter(i => i.statut === 'ouvert' || i.statut === 'surveillance');
  const typesTouches = new Set();
  incidents.forEach(i => { incidentsAcquittes.add(i.id); typesTouches.add(i.type_anomalie); });

  // Relie l'acquittement web aux rappels de notification bureau (Windows) :
  // avant, cliquer "J'ai vu" dans le dashboard n'avait aucun effet sur les
  // toasts Windows, qui continuaient a rappeler independamment.
  typesTouches.forEach(type => {
    fetch('/api/acquitter', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({type}),
    }).catch(() => {});
  });

  renderBanniere();
}

// --- Correlation incidents <-> courbe (triangles rouges) -------------------
// Convertit un horodatage en Date exploitable. Deux formats possibles :
//  - "HH:MM:SS" (points de la courbe live) -> on suppose la date du jour
//  - "YYYY-MM-DD HH:MM:SS" (incidents.debut, mesures.horodatage) -> complet
function versDate(chaineHeure){
  if(!chaineHeure) return null;
  if(chaineHeure.includes('-')){
    return new Date(chaineHeure.replace(' ', 'T'));
  }
  const [hh, mm, ss] = chaineHeure.split(':').map(Number);
  const d = new Date();
  d.setHours(hh, mm, ss || 0, 0);
  return d;
}

// Trouve, parmi une liste de points {heure, ...}, celui dont l'horodatage
// est le plus proche de dateCible, a condition d'etre a moins de
// toleranceMs (sinon on ne place pas de marqueur plutot que d'en placer un
// au mauvais endroit).
function pointLePlusProche(points, dateCible, toleranceMs){
  let meilleur = null, meilleurEcart = Infinity;
  for(const p of points){
    const d = versDate(p.heure);
    if(!d) continue;
    const ecart = Math.abs(d.getTime() - dateCible.getTime());
    if(ecart < meilleurEcart){ meilleurEcart = ecart; meilleur = p; }
  }
  return meilleurEcart <= toleranceMs ? meilleur : null;
}

function renderSidebar(){
  const liste = document.getElementById('liste-serveurs');
  const noms = Object.keys(etatServeurs);
  if(noms.length === 0){
    liste.innerHTML = '<div style="color:var(--muted); font-size:12px; padding:8px;">En attente de donnees...</div>';
    return;
  }
  liste.innerHTML = noms.map(nom => {
    const s = etatServeurs[nom].score;
    const couleur = s ? couleurScore(s.score) : '#7C8B99';
    const actif = nom === serveurActif ? 'actif' : '';
    return `<div class="serveur-item ${actif}" onclick="selectionnerServeur('${nom}')">
              <div class="pastille" style="background:${couleur}"></div>${nom}
            </div>`;
  }).join('');
}

function selectionnerServeur(nom){
  serveurActif = nom;
  renderSidebar();
  renderPrincipal();
  chargerIncidents();
}

function renderPrincipal(){
  if(!serveurActif || !etatServeurs[serveurActif]){
    document.getElementById('titre-serveur').textContent = 'SENTINEL';
    return;
  }
  const e = etatServeurs[serveurActif];
  document.getElementById('titre-serveur').textContent = serveurActif;

  if(e.score){
    const pct = e.score.score;
    const decalage = CIRCONFERENCE - (pct/100)*CIRCONFERENCE;
    const cercle = document.getElementById('cercle-score');
    cercle.style.stroke = couleurScore(pct);
    cercle.setAttribute('stroke-dashoffset', decalage);
    document.getElementById('valeur-score').textContent = pct;
    document.getElementById('detail-score').innerHTML =
      `Disponibilite ${e.score.disponibilite_pct}%<br>${e.score.nb_incidents_ouverts} incident(s) ouvert(s)`;
  }

  const m = e.metriques;
  if(m){
    const grille = document.getElementById('grille-metriques');
    grille.innerHTML = CARTES.map(c => {
      const valeur = m[c.cle];
      // Pas de capteur batterie (PC de bureau, VM...) -> valeur = null.
      // On l'affiche distinctement au lieu de montrer "null%".
      if(valeur === null || valeur === undefined){
        return `<div class="carte"><div class="label">${c.label}</div>
                  <div class="valeur" style="color:var(--muted)">N/D</div></div>`;
      }
      // Pour la batterie, une valeur BASSE est le probleme (inverse du
      // reste : cpu/memoire/disque/processus/paquets sont dangereux quand
      // ILS montent). Avant, la meme regle "valeur >= seuil = rouge" etait
      // appliquee partout, ce qui coloriait la batterie en rouge quasiment
      // tout le temps (des 15%+) au lieu de seulement quand elle est faible.
      const couleur = c.cle === 'batterie'
        ? (valeur <= c.seuil ? '#F85149' : (valeur <= c.seuil*1.6 ? '#D29922' : '#3FB950'))
        : (valeur >= c.seuil ? '#F85149' : (valeur >= c.seuil*0.8 ? '#D29922' : '#3FB950'));
      return `<div class="carte"><div class="label">${c.label}</div>
                <div class="valeur" style="color:${couleur}">${valeur}${c.unite}</div></div>`;
    }).join('');
  }

  renderBanniere();

  if(periodeActuelle === 'live'){
    const incidents = incidentsParServeur[serveurActif] || [];

    graphique.data.labels = e.courbe.map(p => p.heure);
    graphique.data.datasets[0].data = e.courbe.map(p => p.cpu);
    graphique.data.datasets[1].data = e.courbe.map(p => p.memoire);
    // Marqueurs CPU sur la valeur cpu, marqueurs Memoire sur la valeur memoire
    // (avant, tout etait plaque sur la courbe CPU quel que soit le type).
    graphique.data.datasets[2].data = [
      ...marqueursIncidents(e.courbe, incidents, {cpu: 'cpu'}, 15000),
      ...marqueursIncidents(e.courbe, incidents, {memoire: 'memoire'}, 15000),
    ];
    graphique.update();

    CONFIG_METRIQUES_SECONDAIRES.forEach((cfg, i) => {
      graphiqueCombine.data.labels = e.courbe.map(p => p.heure);
      graphiqueCombine.data.datasets[i].data = e.courbe.map(p => p[cfg.champ]);
    });
    const champsParTypePourcent = Object.fromEntries(
      CONFIG_METRIQUES_SECONDAIRES.filter(c => c.axe === 'y').map(c => [c.type, c.champ])
    );
    const champsParTypeCompte = Object.fromEntries(
      CONFIG_METRIQUES_SECONDAIRES.filter(c => c.axe === 'y1').map(c => [c.type, c.champ])
    );
    graphiqueCombine.data.datasets[IDX_INCIDENTS_POURCENT].data = marqueursIncidents(e.courbe, incidents, champsParTypePourcent, 15000);
    graphiqueCombine.data.datasets[IDX_INCIDENTS_COMPTE].data = marqueursIncidents(e.courbe, incidents, champsParTypeCompte, 15000);
    graphiqueCombine.update();
  }
}

let periodeActuelle = 'live';

// Place un triangle rouge sur LE GRAPHIQUE CONCERNE (pas systematiquement
// celui du CPU) au point le plus proche dans le temps du debut de chaque
// incident critique DONT LE TYPE correspond a `champParType`, positionne
// sur SA propre valeur — pour que la correlation visuelle ait un sens
// meme pour un incident batterie/disque/reseau/processus.
function marqueursIncidents(points, incidents, champParType, toleranceMs){
  if(!points.length || !incidents.length) return [];

  // Un seul marqueur par type : on ne garde que l'incident ACTIF (ouvert
  // ou surveillance) le plus recent de chaque type. Avant, un marqueur
  // etait pousse pour CHAQUE incident connu (jusqu'a 200, tous statuts
  // confondus) qui matchait le type -> plusieurs triangles pour le meme
  // probleme des que 2 incidents du meme type se trouvaient dans la
  // fenetre visible (ex: un ancien deja resolu + le nouveau).
  const parType = {};
  incidents.forEach(inc => {
    if(inc.statut === 'resolu') return;
    if(!['critique', 'warning'].includes(inc.niveau_max)) return;
    if(!champParType[inc.type_anomalie]) return;
    const actuel = parType[inc.type_anomalie];
    if(!actuel || inc.derniere_occurrence > actuel.derniere_occurrence) parType[inc.type_anomalie] = inc;
  });

  const marqueurs = [];
  Object.values(parType).forEach(inc => {
    const champ = champParType[inc.type_anomalie];
    // On se positionne sur derniere_occurrence, pas sur debut : debut est
    // fige au tout premier declenchement et n'est JAMAIS mis a jour quand
    // l'incident est rattache/reouvert plus tard (voir historique.py,
    // enregistrer_anomalie) - l'utiliser plagait le triangle a l'heure du
    // tout premier declenchement, parfois hors de la fenetre live visible
    // ou a la mauvaise minute par rapport au probleme actuel.
    const dateRef = versDate(inc.derniere_occurrence);
    if(!dateRef) return;
    const point = pointLePlusProche(points, dateRef, toleranceMs);
    if(point && point[champ] != null) {
      const yMax = champ === 'cpu' || champ === 'memoire' || champ === 'disque_pct' || champ === 'batterie' ? 100 : point[champ] * 1.15 + 5;
      marqueurs.push({
        x: point.heure ?? point.label,
        y: Math.min(yMax, point[champ] + Math.max(2, point[champ]*0.05)),
        niveau: inc.niveau_max,
      });
    }
  });
  return marqueurs;
}

async function changerPeriode(periode){
  periodeActuelle = periode;
  document.querySelectorAll('.btn-periode').forEach(b => b.classList.toggle('actif', b.dataset.periode === periode));

  if(periode === 'live'){
    renderPrincipal();
    return;
  }
  if(!serveurActif) return;

  try{
    const res = await fetch(`/api/historique_metriques?serveur=${encodeURIComponent(serveurActif)}&heures=${periode}`);
    const data = await res.json();

    const labels = data.mesures.map(p => p.horodatage.slice(5, 16));
    graphique.data.labels = labels;
    graphique.data.datasets[0].data = data.mesures.map(p => p.cpu);
    graphique.data.datasets[1].data = data.mesures.map(p => p.memoire);

    // Marqueurs d'incidents critiques positionnes sur le point de mesure le
    // plus proche dans le temps (les mesures sont enregistrees 1x/minute,
    // le debut de l'incident peut tomber a n'importe quelle seconde de
    // cette minute-la : on ne cherche donc plus une egalite exacte de
    // sous-chaine, qui ratait la plupart des correspondances), et sur la
    // valeur/le graphique qui correspond VRAIMENT a son type.
    const pointsMesures = data.mesures.map(p => ({
      heure: p.horodatage, label: p.horodatage.slice(5, 16),
      cpu: p.cpu, memoire: p.memoire, disque_pct: p.disque_pct,
      batterie: p.batterie, paquets_perdus: p.paquets_perdus, nb_processus: p.nb_processus,
    }));
    // Marqueurs positionnes sur les labels "MM-DD HH:MM" utilises par l'axe
    // X historique (distincts des horodatages complets utilises pour la
    // correlation temporelle) - voir marqueursSurLabels ci-dessous.
    graphique.data.datasets[2].data = [
      ...marqueursSurLabels(pointsMesures, data.incidents, {cpu: 'cpu'}, 90000),
      ...marqueursSurLabels(pointsMesures, data.incidents, {memoire: 'memoire'}, 90000),
    ];
    graphique.update();

    graphiqueCombine.data.labels = labels;
    CONFIG_METRIQUES_SECONDAIRES.forEach((cfg, i) => {
      graphiqueCombine.data.datasets[i].data = data.mesures.map(p => p[cfg.champ]);
    });
    const champsParTypePourcent = Object.fromEntries(
      CONFIG_METRIQUES_SECONDAIRES.filter(c => c.axe === 'y').map(c => [c.type, c.champ])
    );
    const champsParTypeCompte = Object.fromEntries(
      CONFIG_METRIQUES_SECONDAIRES.filter(c => c.axe === 'y1').map(c => [c.type, c.champ])
    );
    graphiqueCombine.data.datasets[IDX_INCIDENTS_POURCENT].data = marqueursSurLabels(pointsMesures, data.incidents, champsParTypePourcent, 90000);
    graphiqueCombine.data.datasets[IDX_INCIDENTS_COMPTE].data = marqueursSurLabels(pointsMesures, data.incidents, champsParTypeCompte, 90000);
    graphiqueCombine.update();
  } catch(err){
    console.error('Erreur chargement historique metriques:', err);
  }
}

// Comme marqueursIncidents, mais pour les graphiques historiques dont l'axe X
// utilise des labels "MM-DD HH:MM" (mesures 1/minute) au lieu des horodatages
// "HH:MM:SS" de la courbe live.
function marqueursSurLabels(pointsMesures, incidents, champParType, toleranceMs){
  if(!pointsMesures.length || !incidents.length) return [];
  const marqueurs = [];
  incidents.forEach(inc => {
    if(!['critique', 'warning'].includes(inc.niveau_max)) return;
    const champ = champParType[inc.type_anomalie];
    if(!champ) return;
    // derniere_occurrence, pas debut (voir marqueursIncidents ci-dessus
    // pour l'explication : debut ne bouge plus apres la creation initiale
    // de l'incident, meme quand il est reouvert plus tard).
    const dateRef = versDate(inc.derniere_occurrence);
    if(!dateRef) return;
    const point = pointLePlusProche(pointsMesures, dateRef, toleranceMs);
    if(point && point[champ] != null){
      const yMax = ['cpu','memoire','disque_pct','batterie'].includes(champ) ? 100 : point[champ] * 1.15 + 5;
      marqueurs.push({
        x: point.label,
        y: Math.min(yMax, point[champ] + Math.max(2, point[champ]*0.05)),
        niveau: inc.niveau_max,
      });
    }
  });
  return marqueurs;
}

let limiteAffichageIncidents = 4;

async function chargerIncidents(){
  if(!serveurActif) return;
  try{
    const [resListe, resCompte] = await Promise.all([
      fetch('/api/incidents?serveur=' + encodeURIComponent(serveurActif) + '&limite=200'),
      fetch('/api/incidents/compte?serveur=' + encodeURIComponent(serveurActif)),
    ]);
    const tousLesIncidents = await resListe.json();
    const compte = await resCompte.json();

    // Vue complete (jusqu'a 200) pour le bandeau et les marqueurs de la
    // courbe, qui doivent connaitre TOUS les incidents ouverts/en
    // observation, pas seulement ceux affiches dans la liste paginee.
    incidentsParServeur[serveurActif] = tousLesIncidents;

    const compteurEl = document.getElementById('compteur-incidents');
    compteurEl.innerHTML = `
      ${compte.ouvert ? `<span class="c-ouvert">${compte.ouvert} ouvert${compte.ouvert>1?'s':''}</span>` : ''}
      ${compte.surveillance ? `<span class="c-surveillance">${compte.surveillance} en observation</span>` : ''}
      ${compte.resolu ? `<span class="c-resolu">${compte.resolu} résolu${compte.resolu>1?'s':''}</span>` : ''}
    `;

    const incidentsAffiches = tousLesIncidents.slice(0, limiteAffichageIncidents);
    const liste = document.getElementById('liste-incidents');
    if(incidentsAffiches.length === 0){
      liste.innerHTML = '<div id="vide-incidents">Aucun incident pour ce serveur.</div>';
    } else {
      const totalConnu = compte.ouvert + compte.surveillance + compte.resolu;
      liste.innerHTML = incidentsAffiches.map(inc => `
        <div class="incident">
          <div class="info">
            <b>${inc.type_anomalie}</b> - ${inc.nb_occurrences}x
            <span class="badge ${inc.statut}">${inc.statut === 'surveillance' ? 'en observation' : inc.statut}</span>
            <div class="phrase">${phraseType(inc.type_anomalie)}</div>
            <div style="color:var(--muted); font-size:11px;">${inc.debut} -> ${inc.derniere_occurrence}</div>
          </div>
          <button ${inc.statut === 'resolu' ? 'disabled' : ''} onclick="resoudreIncident(${inc.id})">
            ${inc.statut === 'resolu' ? 'Resolu' : 'Marquer resolu'}
          </button>
        </div>`).join('')
        + (totalConnu > incidentsAffiches.length
            ? `<button id="btn-plus-incidents" onclick="afficherPlusIncidents()">Afficher plus (${totalConnu - incidentsAffiches.length} restants)</button>`
            : '');
    }
    renderBanniere();
    if(periodeActuelle === 'live') renderPrincipal(); // rafraichit les marqueurs live avec les incidents a jour
  } catch(err){
    console.error('Erreur chargement incidents:', err);
  }
}

function afficherPlusIncidents(){
  limiteAffichageIncidents += 4;
  chargerIncidents();
}

async function resoudreIncident(id){
  await fetch(`/api/incidents/${id}/resoudre`, {method:'POST'});
  incidentsAcquittes.delete(id);
  chargerIncidents();
}

socket.on('etat_initial', data => {
  Object.keys(data).forEach(nom => {
    data[nom].courbe = data[nom].courbe || [];
  });
  etatServeurs = data;
  if(!serveurActif) serveurActif = Object.keys(data)[0] || null;
  renderSidebar();
  renderPrincipal();
  chargerIncidents();
});

socket.on('maj_serveur', msg => {
  const nom = msg.serveur;
  if(!etatServeurs[nom]) etatServeurs[nom] = {metriques:null, anomalies:[], explication:null, courbe:[], score:null};
  etatServeurs[nom].metriques = msg.metriques;
  etatServeurs[nom].anomalies = msg.anomalies;
  etatServeurs[nom].explication = msg.explication;
  etatServeurs[nom].score = msg.score;
  etatServeurs[nom].courbe.push(msg.courbe_point);
  if(etatServeurs[nom].courbe.length > 120) etatServeurs[nom].courbe.shift();
  if(!serveurActif) serveurActif = nom;
  renderSidebar();
  if(nom === serveurActif) renderPrincipal();
  if(msg.anomalies && msg.anomalies.length > 0) chargerIncidents();
});

socket.on('maj_explication', msg => {
  const nom = msg.serveur;
  if(!etatServeurs[nom]) return;
  etatServeurs[nom].explication = msg.explication;
  if(nom === serveurActif){
    // A ce stade, historique.enregistrer_anomalie() (cote serveur) a fini
    // d'ecrire les incidents en base : c'est le moment fiable pour
    // rafraichir la liste. Avant, seul le tout premier signal (maj_serveur,
    // qui arrive AVANT cette ecriture) declenchait le rafraichissement, ce
    // qui pouvait faire manquer un incident tout juste cree (par ex. une
    // 2e anomalie simultanee qui semblait n'apparaitre qu'apres avoir
    // acquitte la premiere).
    chargerIncidents();
  }
});

socket.on('incident_resolu', id_msg => {
  if(id_msg && typeof id_msg.id !== 'undefined') incidentsAcquittes.delete(id_msg.id);
  chargerIncidents();
});

// Un ou plusieurs incidents viennent de passer 'ouvert' -> 'surveillance'
// (metrique revenue a la normale) : on rafraichit pour que le bandeau
// devienne moins alarmant sans attendre le prochain cycle d'anomalies.
socket.on('incident_stabilise', msg => {
  if(msg && msg.serveur === serveurActif) chargerIncidents();
});

// --- Historique detaille (bouton "Historique") ------------------------
// Pour un utilisateur qui n'est pas ingenieur/technicien : chaque fiche
// montre le moment, une phrase simple, une explication plus detaillee et
// une solution concrete a essayer, en plus de l'explication IA du moment.
async function ouvrirHistorique(){
  const modal = document.getElementById('modal-historique');
  const liste = document.getElementById('liste-historique');
  modal.classList.add('ouvert');
  liste.innerHTML = '<div style="color:var(--muted);">Chargement...</div>';

  if(!serveurActif) return;
  try{
    const params = new URLSearchParams({serveur: serveurActif, limite: '150'});
    const type = document.getElementById('filtre-type').value;
    const niveau = document.getElementById('filtre-niveau').value;
    const statut = document.getElementById('filtre-statut').value;
    const depuis = document.getElementById('filtre-depuis').value;
    const jusqua = document.getElementById('filtre-jusqua').value;
    if(type) params.set('type', type);
    if(niveau) params.set('niveau', niveau);
    if(statut) params.set('statut', statut);
    if(depuis) params.set('depuis', depuis + ' 00:00:00');
    if(jusqua) params.set('jusqua', jusqua + ' 23:59:59');

    const res = await fetch('/api/incidents?' + params.toString());
    const incidents = await res.json();

    if(incidents.length === 0){
      liste.innerHTML = '<div style="color:var(--muted);">Aucun incident ne correspond à ces filtres.</div>';
      return;
    }

    liste.innerHTML = incidents.map(inc => {
      const infos = INFOS_TYPES[inc.type_anomalie] || {};
      const periode = inc.statut === 'resolu'
        ? `${inc.debut} → ${inc.derniere_occurrence} (résolu)`
        : `${inc.debut} → en cours (${inc.nb_occurrences}x)`;
      return `
        <div class="fiche-incident">
          <div class="entete-fiche">
            <span class="titre-fiche">${inc.type_anomalie} <span class="badge ${inc.statut}">${inc.statut === 'surveillance' ? 'en observation' : inc.statut}</span></span>
            <span class="temps-fiche">${periode}</span>
          </div>
          <div class="bloc"><b>En bref</b>${infos.phrase || phraseType(inc.type_anomalie)}</div>
          <div class="bloc"><b>Explication détaillée</b>${infos.detaillee || ''}</div>
          <div class="bloc"><b>Ce que vous pouvez faire</b>${infos.solution || ''}</div>
          ${inc.derniere_explication ? `<div class="bloc"><b>Analyse du moment</b>${inc.derniere_explication}</div>` : ''}
        </div>`;
    }).join('');
  } catch(err){
    liste.innerHTML = `<div style="color:var(--crit);">Erreur de chargement de l'historique.</div>`;
    console.error('Erreur chargement historique:', err);
  }
}

function reinitialiserFiltresHistorique(){
  document.getElementById('filtre-type').value = '';
  document.getElementById('filtre-niveau').value = '';
  document.getElementById('filtre-statut').value = '';
  document.getElementById('filtre-depuis').value = '';
  document.getElementById('filtre-jusqua').value = '';
  ouvrirHistorique();
}

function fermerHistorique(){
  document.getElementById('modal-historique').classList.remove('ouvert');
}

// --- Bouton Rapport (PDF a la demande) ---------------------------------
function toggleMenuRapport(){
  document.getElementById('menu-rapport').classList.toggle('ouvert');
}
document.addEventListener('click', e => {
  const menu = document.getElementById('menu-rapport');
  const bouton = document.getElementById('btn-rapport');
  if(menu && menu.classList.contains('ouvert') && !menu.contains(e.target) && e.target !== bouton){
    menu.classList.remove('ouvert');
  }
});

async function genererRapport(jours){
  document.getElementById('menu-rapport').classList.remove('ouvert');
  const bouton = document.getElementById('btn-rapport');
  const texteInitial = bouton.textContent;
  bouton.textContent = '⏳ Generation...';
  bouton.classList.add('chargement');

  try{
    const params = new URLSearchParams({jours: jours});
    if(serveurActif) params.set('serveur', serveurActif);
    const res = await fetch('/api/rapport?' + params.toString());
    if(!res.ok){
      const err = await res.json().catch(() => ({}));
      throw new Error(err.erreur || 'Echec de generation du rapport');
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const cd = res.headers.get('Content-Disposition') || '';
    const nomMatch = cd.match(/filename="?([^"]+)"?/);
    a.download = nomMatch ? nomMatch[1] : 'rapport.pdf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch(err){
    alert('Impossible de generer le rapport : ' + err.message);
    console.error('Erreur generation rapport:', err);
  } finally {
    bouton.textContent = texteInitial;
    bouton.classList.remove('chargement');
  }
}

function toggleChat(){
  document.getElementById('chat-panel').classList.toggle('ouvert');
}

document.getElementById('chat-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const input = document.getElementById('chat-input');
  const question = input.value.trim();
  if(!question) return;
  const messages = document.getElementById('chat-messages');
  messages.innerHTML += `<div class="bulle moi">${question}</div>`;
  input.value = '';
  const idAttente = 'attente-' + Date.now();
  messages.innerHTML += `<div class="bulle bot" id="${idAttente}">...</div>`;
  messages.scrollTop = messages.scrollHeight;

  try{
    const res = await fetch('/api/chat', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({question, serveur: serveurActif})
    });
    const data = await res.json();
    document.getElementById(idAttente).textContent = data.reponse || data.erreur || 'Pas de reponse.';
  } catch(err){
    document.getElementById(idAttente).textContent = 'Erreur de connexion au serveur.';
  }
  messages.scrollTop = messages.scrollHeight;
});

// --- Menu utilisateur déroulant (hover) ---
document.addEventListener('DOMContentLoaded', function() {
    const wrapper = document.querySelector('.user-menu-wrapper');
    const dropdown = document.getElementById('userDropdown');
    
    if (wrapper && dropdown) {
        // Ouverture au survol
        wrapper.addEventListener('mouseenter', function() {
            dropdown.classList.add('ouvert');
        });
        
        // Fermeture quand la souris quitte le wrapper
        wrapper.addEventListener('mouseleave', function(e) {
            // Vérifier si on ne survole pas un enfant du wrapper
            if (!wrapper.contains(e.relatedTarget)) {
                dropdown.classList.remove('ouvert');
            }
        });
        
        // Fermeture si on clique ailleurs
        document.addEventListener('click', function(e) {
            if (!wrapper.contains(e.target)) {
                dropdown.classList.remove('ouvert');
            }
        });
    }
});
</script>

</body>
</html>
"""


if __name__ == "__main__":
    t = threading.Thread(target=boucle_surveillance_locale, daemon=True)
    t.start()
    t2 = threading.Thread(target=boucle_resolution_auto, daemon=True)
    t2.start()
    lancer_planificateur_en_arriere_plan()
    t3 = threading.Thread(target=boucle_nettoyage_notifications, daemon=True)
    t3.start()
    port = int(os.environ.get("PORT", 8080))
    print(f"Dashboard disponible sur http://localhost:{port}")
    print(f"Cle API pour les agents distants : {CLE_API}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)