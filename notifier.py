"""
Module 4 — Alertes automatiques (Slack via webhook)
-----------------------------------------------------
Envoie une alerte Slack dès qu'une anomalie est détectée, avec :
  - un anti-spam (cooldown) pour ne pas ré-alerter en boucle toutes les 5s
  - un message formaté (Slack "blocks") avec les métriques + l'explication du LLM
  - une gestion d'erreur réseau propre (le monitoring ne doit jamais planter
    à cause d'un souci Slack)
  - NOTIFICATIONS INTELLIGENTES : ne continue pas à alerter si l'anomalie
    est résolue (retour à la normale détecté)

Configuration :
    Crée un webhook entrant Slack : https://api.slack.com/messaging/webhooks
    Puis définis la variable d'environnement SLACK_WEBHOOK_URL, par ex. :

        export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"

    (Sur Windows PowerShell : $env:SLACK_WEBHOOK_URL="https://hooks.slack.com/...")
"""

import os
import time
import json
import smtplib
import threading
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
from historique import metrique_est_normale, a_une_metrique
import destinataires

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Anti-spam : on ne renvoie pas la même alerte plus d'1 fois toutes les X secondes
COOLDOWN_SECONDES = 300  # 5 minutes

# Mémorise le dernier envoi par "type d'anomalie" (ex: "cpu", "memoire", "ia")
_dernier_envoi = {}

# --- ÉTAT DES ANOMALIES ACTIVES ---
# Pour suivre si une anomalie est encore active ou si elle est résolue
_anomalies_actives = {}  # cle_anomalie -> datetime de début
_anomalies_lock = threading.Lock()

# --- ACQUITTEMENT DEPUIS LE DASHBOARD ---
# Quand l'utilisateur clique "J'ai vu ✓" dans le dashboard web, on veut que
# les rappels de notification Windows s'arrêtent aussi (au lieu d'avoir deux
# systèmes d'acquittement indépendants qui s'ignorent). Mais si le problème
# n'est TOUJOURS PAS résolu après un moment, on doit quand même relancer un
# rappel — sinon un incident non traité pourrait être oublié.
_acquittements = {}  # cle -> datetime d'acquittement
DELAI_RAPPEL_APRES_ACQUITTEMENT_SECONDES = 15 * 60  # 15 minutes


def acquitter(cle: str):
    """A appeler quand l'utilisateur clique 'J'ai vu ✓' dans le dashboard
    (voir /api/acquitter dans dash.py). Met en pause les rappels de
    notification bureau pour ce type d'anomalie, MAIS le rappel reprendra
    automatiquement si le problème est toujours actif après
    DELAI_RAPPEL_APRES_ACQUITTEMENT_SECONDES (voir _boucle_escalade)."""
    with _anomalies_lock:
        _acquittements[cle] = datetime.now()


def _est_acquittee_recemment(cle: str) -> bool:
    with _anomalies_lock:
        t = _acquittements.get(cle)
    if not t:
        return False
    return (datetime.now() - t).total_seconds() < DELAI_RAPPEL_APRES_ACQUITTEMENT_SECONDES


# --- SOURCE DE MÉTRIQUES "FRAÎCHES" ---
# BUG CORRIGÉ : _boucle_escalade tournait sur plusieurs minutes (rappels
# toutes les ~45s) mais ne vérifiait la résolution de l'anomalie que sur le
# `m` figé au moment où la notification a démarré. Si le problème se
# résolvait entre-temps, ça ne changeait rien : les rappels continuaient
# jusqu'au max de tentatives. On permet maintenant à l'appelant (dash.py)
# d'enregistrer une fonction qui retourne les métriques ACTUELLES.
_obtenir_metriques_actuelles = None


def definir_source_metriques(fonction):
    """Enregistre une fonction sans argument qui retourne les métriques
    actuelles (dict) du serveur local, pour que les rappels bureau vérifient
    l'état réel du système plutôt qu'un instantané périmé."""
    global _obtenir_metriques_actuelles
    _obtenir_metriques_actuelles = fonction


def _metriques_fraiches(m_repli: dict) -> dict:
    if _obtenir_metriques_actuelles:
        try:
            fraiches = _obtenir_metriques_actuelles()
            if fraiches:
                return fraiches
        except Exception:
            pass
    return m_repli


def _marquer_anomalies_actives(anomalies: list[str]):
    """Enregistre chaque anomalie comme "active" - INDÉPENDAMMENT du canal
    d'envoi (Slack / WhatsApp / bureau) et de sa configuration.

    BUG CORRIGÉ : avant, seul envoyer_alerte_slack() remplissait
    _anomalies_actives (via _doit_envoyer), et seulement si
    SLACK_WEBHOOK_URL était configurée. Résultat : sans webhook Slack,
    _anomalies_actives restait vide, et notifier_bureau_persistant()
    (qui dépend de cet état pour savoir quand une anomalie est encore en
    cours) s'arrêtait immédiatement sans jamais afficher de notification.
    Cette fonction est maintenant appelée en premier par les 3 canaux
    d'alerte, pour que le suivi fonctionne même si Slack n'est pas configuré."""
    with _anomalies_lock:
        for a in anomalies:
            cle = _cle_anomalie(a)
            if cle not in _anomalies_actives:
                _anomalies_actives[cle] = datetime.now()


def _cle_anomalie(texte_anomalie: str) -> str:
    """Regroupe les anomalies par type (cpu / mémoire / disque / réseau / processus / ia)
    pour que le cooldown s'applique par type de problème, et pas message pour message."""
    texte = texte_anomalie.lower()
    if "cpu" in texte:
        return "cpu"
    if "mémoire" in texte or "memoire" in texte:
        return "memoire"
    if "disque" in texte:
        return "disque"
    if "réseau" in texte or "paquets" in texte:
        return "reseau"
    if "processus" in texte:
        return "processus"
    if "batterie" in texte:
        return "batterie"
    if "ia" in texte:
        return "ia"
    return "autre"


def _est_anomalie_resolue(cle: str, m: dict) -> bool:
    """Vérifie si l'anomalie est résolue en fonction des métriques actuelles.

    Délègue maintenant à historique.metrique_est_normale(), la SEULE
    implémentation de cette règle. Avant, ce fichier avait sa propre copie
    des seuils de résolution, séparée de celle utilisée pour faire évoluer
    le statut des incidents (historique.py) — c'est exactement ce genre de
    duplication qui avait causé le bug de la batterie (sens inversé dans une
    copie mais pas l'autre). Une seule source de vérité, partagée partout."""
    if not a_une_metrique(cle):
        # Types "ia"/"autre" : pas de métrique correspondante, donc rien à
        # bloquer côté rappels de notification.
        return True
    return metrique_est_normale(cle, m)


def _doit_envoyer(anomalies: list[str], m: dict) -> list[str]:
    """Filtre la liste d'anomalies pour ne garder que celles qui sont hors
    cooldown, pour l'envoi Slack. Le suivi "actif/résolu" partagé entre
    canaux est géré séparément par _marquer_anomalies_actives() /
    _nettoyer_anomalies_resolues(), donc cette fonction ne s'occupe plus
    que du cooldown anti-spam Slack."""
    maintenant = time.time()
    a_envoyer = []

    with _anomalies_lock:
        for a in anomalies:
            cle = _cle_anomalie(a)
            dernier = _dernier_envoi.get(cle, 0)
            if maintenant - dernier >= COOLDOWN_SECONDES:
                a_envoyer.append(a)
                _dernier_envoi[cle] = maintenant

    return a_envoyer


def _nettoyer_anomalies_resolues(m: dict):
    """Retire de _anomalies_actives les anomalies dont la métrique est
    repassée sous le seuil de résolution. Appelé à chaque cycle par les
    fonctions d'alerte, indépendamment du canal."""
    with _anomalies_lock:
        for cle in [c for c in _anomalies_actives if _est_anomalie_resolue(c, m)]:
            print(f"✅ Anomalie '{cle}' résolue (métrique normale)")
            del _anomalies_actives[cle]


def envoyer_alerte_slack(m: dict, anomalies: list[str], explication: str) -> bool:
    """
    Envoie une alerte Slack pour les anomalies détectées.

    Args:
        m: dict des métriques (sortie de lire_metriques())
        anomalies: liste des anomalies détectées (sortie de detecter_anomalies())
        explication: texte généré par le LLM (module 3)

    Returns:
        True si un message a été envoyé, False sinon (cooldown actif, pas de
        webhook configuré, ou erreur réseau).
    """
    if not anomalies:
        return False

    _nettoyer_anomalies_resolues(m)
    _marquer_anomalies_actives(anomalies)

    if not SLACK_WEBHOOK_URL:
        print("⚠️  SLACK_WEBHOOK_URL non configurée — alerte Slack ignorée.")
        return False

    a_notifier = _doit_envoyer(anomalies, m)
    if not a_notifier:
        # Toutes les anomalies sont encore en cooldown ou déjà actives
        print("⏳ Alerte déjà envoyée récemment pour ce type d'anomalie "
              f"(cooldown {COOLDOWN_SECONDES}s) ou toujours active — envoi ignoré.")
        return False

    couleur = "#e01e5a" if any("🔴" in a for a in a_notifier) else "#f2c744"

    # Ajouter un message si c'est une nouvelle alerte vs une résolution
    message_alerte = "🚨 Anomalie détectée" if a_notifier else "✅ Retour à la normale"

    payload = {
        "attachments": [
            {
                "color": couleur,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{message_alerte} — {m['timestamp']}",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\n".join(f"• {a}" for a in a_notifier),
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*CPU:*\n{m['cpu']}%"},
                            {"type": "mrkdwn", "text": f"*Mémoire:*\n{m['memoire']}%"},
                            {"type": "mrkdwn", "text": f"*Disque:*\n{m['disque_pct']}%"},
                            {"type": "mrkdwn", "text": f"*Processus:*\n{m['nb_processus']}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*💬 Analyse :*\n{explication}",
                        },
                    },
                ],
            }
        ]
    }

    try:
        resp = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            print("📩 Alerte Slack envoyée.")
            return True
        print(f"⚠️  Slack a répondu {resp.status_code} : {resp.text}")
        return False
    except requests.RequestException as e:
        print(f"⚠️  Échec envoi Slack (réseau) : {e}")
        return False


# ---------------------------------------------------------------------------
# Alerte email (SMTP) — anti-spam par type d'anomalie
# ---------------------------------------------------------------------------
# Même philosophie anti-spam que Slack/toast, mais suivi INDÉPENDANT (son
# propre cooldown, son propre état actif/résolu) : on ne veut pas qu'un
# email dépende de si Slack est configuré ou non, ni l'inverse.
#
#   - 1 email par type de problème (pas un email par ligne d'anomalie)
#   - au premier dépassement de seuil : email immédiat
#   - tant que le problème persiste : au plus 1 rappel toutes les
#     EMAIL_COOLDOWN_SECONDES (10 min par défaut) — pas à chaque cycle
#   - dès que la métrique repasse sous le seuil de résolution
#     (historique.metrique_est_normale, même règle que le reste de l'appli) :
#     UN SEUL email "c'est réglé", puis silence

COOLDOWN_EMAIL_SECONDES = int(os.environ.get("EMAIL_COOLDOWN_SECONDES", "600"))  # 10 min

_email_actifs = {}          # cle_anomalie -> True tant qu'un email "problème" a été envoyé et pas encore suivi d'un email "résolu"
_dernier_envoi_email = {}   # cle_anomalie -> timestamp du dernier envoi (cooldown)
_email_lock = threading.Lock()


def _envoyer_email_brut(sujet: str, corps: str, pieces_jointes: list = None) -> bool:
    """Envoi SMTP bas niveau, avec pièces jointes optionnelles. Ne lève
    JAMAIS d'exception vers l'appelant (même règle que Slack/WhatsApp : un
    souci email ne doit jamais faire planter le cycle de surveillance).
    Les identifiants SMTP sont lus DYNAMIQUEMENT depuis parametres.py
    (réglé une fois via la page /admin/parametres-email) à CHAQUE envoi,
    pas figés au démarrage : un changement de mot de passe depuis le
    navigateur prend effet immédiatement, sans redémarrer le pod.

    `pieces_jointes` (optionnel) : liste de chemins de fichiers à joindre
    (ex: le PDF du rapport hebdomadaire de fiabilité). Sans pièce jointe,
    le comportement est identique à l'ancien _envoyer_email() (MIMEText
    simple) — c'est le SEUL point d'envoi SMTP bas niveau du module,
    utilisé aussi bien par les alertes d'anomalie que par les emails
    utilitaires (ticket créé, rapport hebdo)."""
    liste_destinataires = destinataires.emails_actifs()
    if not liste_destinataires:
        return False

    import parametres
    config = parametres.obtenir_config_email()
    if not (config["host"] and config["utilisateur"] and config["mot_de_passe"]):
        print("⚠️  Aucune configuration email (voir /admin/parametres-email) — envoi ignoré.")
        return False

    if pieces_jointes:
        msg = MIMEMultipart()
        msg.attach(MIMEText(corps, "plain", "utf-8"))
        for chemin in pieces_jointes:
            try:
                with open(chemin, "rb") as f:
                    piece = MIMEApplication(f.read(), Name=os.path.basename(chemin))
                piece["Content-Disposition"] = f'attachment; filename="{os.path.basename(chemin)}"'
                msg.attach(piece)
            except OSError as e:
                print(f"⚠️  Impossible de joindre {chemin} à l'email : {e}")
    else:
        msg = MIMEText(corps, "plain", "utf-8")

    msg["Subject"] = sujet
    msg["From"] = config["utilisateur"]
    msg["To"] = ", ".join(liste_destinataires)

    try:
        if config["port"] == 465:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=15) as serveur:
                serveur.login(config["utilisateur"], config["mot_de_passe"])
                serveur.sendmail(config["utilisateur"], liste_destinataires, msg.as_string())
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=15) as serveur:
                serveur.starttls()
                serveur.login(config["utilisateur"], config["mot_de_passe"])
                serveur.sendmail(config["utilisateur"], liste_destinataires, msg.as_string())
        return True
    except Exception as e:
        print(f"⚠️  Échec envoi email : {e}")
        return False


def _envoyer_email(sujet: str, corps: str) -> bool:
    """Compatibilité : ancien point d'entrée sans pièce jointe, utilisé par
    les alertes d'anomalie (envoyer_email_alerte). Délègue à
    _envoyer_email_brut()."""
    return _envoyer_email_brut(sujet, corps)


def envoyer_email_generique(sujet: str, corps: str, pieces_jointes: list = None) -> bool:
    """Envoi email 'utilitaire', hors boucle d'alerte d'anomalie (donc sans
    le cooldown ni le suivi actif/résolu de envoyer_email_alerte) — utilisé
    par exemple pour notifier la création d'un ticket de maintenance
    (voir provisionnement.py, /provisionnement/api/creer-ticket) ou tout
    autre message ponctuel destiné aux mêmes responsables."""
    return _envoyer_email_brut(sujet, corps, pieces_jointes)


def envoyer_rapport_fiabilite_email(chemin_pdf: str) -> bool:
    """Envoie le rapport hebdomadaire de fiabilité (généré par
    rapport_pdf.generer_rapport_fiabilite) aux responsables, en pièce
    jointe. Réutilise l'infra email déjà en place (mêmes destinataires,
    même configuration SMTP que les alertes) — pas de nouveau canal à
    maintenir pour ce rapport."""
    sujet = f"📊 Rapport hebdomadaire de fiabilité — {datetime.now().strftime('%d/%m/%Y')}"
    corps = (
        "Le rapport hebdomadaire de fiabilité du système de surveillance est en pièce jointe.\n\n"
        "Il résume, par serveur : le nombre d'alertes préventives lancées, le taux de fiabilité "
        "(prévisions confirmées vs fausses alertes vs résorbées seules), et la tendance par "
        "rapport à la semaine précédente — pas seulement la fenêtre glissante des 30 derniers "
        "jours affichée sur le dashboard."
    )
    if _envoyer_email_brut(sujet, corps, pieces_jointes=[chemin_pdf]):
        print("📧 Rapport de fiabilité hebdomadaire envoyé par email.")
        return True
    print("⚠️  Échec de l'envoi du rapport de fiabilité hebdomadaire par email.")
    return False


def envoyer_email_alerte(m: dict, anomalies: list[str], explication: str,
                          explications_par_type: dict = None) -> bool:
    """
    Envoie une alerte email UNIQUEMENT pour les anomalies critiques (🔴) —
    même filtre que envoyer_sms_alerte(), les 🟠 ne déclenchent jamais
    d'email. Anti-spam : un email à l'apparition du problème, puis au plus
    un rappel toutes les COOLDOWN_EMAIL_SECONDES tant qu'il persiste, puis
    un seul email de résolution quand la métrique redevient normale.

    Args:
        m: dict des métriques (sortie de lire_metriques())
        anomalies: liste des anomalies détectées ce cycle (peut être vide —
            utile pour laisser passer les emails de résolution)
        explication: texte de repli si aucune explication par type n'est fournie
        explications_par_type: dict optionnel {type: explication}, pour que
            chaque email porte l'explication qui correspond VRAIMENT à son
            problème (voir monitoring_core.expliquer_par_type)

    Returns:
        True si au moins un email a été envoyé, False sinon.
    """
    critiques = [a for a in anomalies if a.startswith("🔴")]

    import parametres
    if not (parametres.config_email_complete() and destinataires.emails_actifs()):
        if critiques:
            print("⚠️  Configuration email incomplète (voir /admin/parametres-email) ou "
                  "aucun responsable email actif (voir /admin/responsables) — alerte ignorée.")
        return False

    au_moins_un_envoi = False

    # 1) Résolutions : un email "c'est réglé" une seule fois par type, même
    #    si aucune nouvelle anomalie critique n'est présente ce cycle.
    #    (_email_actifs ne contient que des types déjà notifiés en critique,
    #    voir étape 2, donc cette boucle reste correcte sans filtre en plus.)
    with _email_lock:
        actifs_snapshot = list(_email_actifs)
    for cle in actifs_snapshot:
        if _est_anomalie_resolue(cle, m):
            with _email_lock:
                _email_actifs.pop(cle, None)
            sujet = f"✅ Résolu : {cle} — {m['timestamp']}"
            corps = (
                f"L'anomalie '{cle}' est revenue à la normale.\n\n"
                f"CPU: {m['cpu']}% | Mémoire: {m['memoire']}% | "
                f"Disque: {m['disque_pct']}% | Processus: {m['nb_processus']}"
            )
            if _envoyer_email(sujet, corps):
                au_moins_un_envoi = True
                print(f"📧 Email de résolution envoyé ({cle}).")

    if not critiques:
        return au_moins_un_envoi

    # 2) Nouvelles alertes / rappels : regroupées par type, sous cooldown —
    #    seulement pour les types marqués critiques (🔴).
    par_type = {}
    for a in critiques:
        par_type.setdefault(_cle_anomalie(a), []).append(a)

    maintenant = time.time()
    for cle, messages in par_type.items():
        with _email_lock:
            dernier = _dernier_envoi_email.get(cle, 0)
            if maintenant - dernier < COOLDOWN_EMAIL_SECONDES:
                continue  # déjà notifié récemment pour ce type — on n'envoie pas à chaque cycle
            _dernier_envoi_email[cle] = maintenant
            _email_actifs[cle] = True

        exp = (explications_par_type or {}).get(cle) or explication or ""
        sujet = f"🚨 {messages[0].lstrip('🔴🟠 ')} — {m['timestamp']}"
        corps = (
            "\n".join(messages)
            + f"\n\nCPU: {m['cpu']}% | Mémoire: {m['memoire']}% | "
              f"Disque: {m['disque_pct']}% | Processus: {m['nb_processus']}"
            + (f"\n\n💬 Analyse : {exp}" if exp else "")
        )
        if _envoyer_email(sujet, corps):
            au_moins_un_envoi = True
            print(f"📧 Alerte email envoyée ({cle}).")

    return au_moins_un_envoi


# ---------------------------------------------------------------------------
# Alerte WhatsApp pour les anomalies CRITIQUES uniquement (🔴) — via CallMeBot
# ---------------------------------------------------------------------------
# Pourquoi WhatsApp plutôt que SMS : Twilio impose une vérification par SMS à
# l'inscription qui échoue pour certains numéros/régions. CallMeBot évite ce
# problème : pas de vérification téléphonique, juste un message WhatsApp à
# envoyer une fois pour récupérer une clé API gratuite.
#
# Configuration (5 minutes, gratuit) :
#   1. Ajoute ce contact dans WhatsApp : +34 644 59 71 67
#   2. Envoie-lui exactement : "I allow callmebot to send me messages"
#   3. Tu reçois ta clé API en réponse automatique
#   4. Définis les variables d'environnement :
#        export CALLMEBOT_PHONE="+21612345678"   # TON numéro (avec indicatif)
#        export CALLMEBOT_APIKEY="123456"        # la clé reçue par WhatsApp

CALLMEBOT_PHONE = os.environ.get("CALLMEBOT_PHONE", "")
CALLMEBOT_APIKEY = os.environ.get("CALLMEBOT_APIKEY", "")

COOLDOWN_SMS_SECONDES = 900  # 15 min : plus strict que Slack, réservé au critique
_dernier_sms = {}
_sms_actifs = {}  # Pour suivre les alertes SMS actives


def _envoyer_whatsapp(texte: str, telephone: str = None, apikey: str = None):
    """Envoie un message WhatsApp via CallMeBot a UN destinataire donne
    (chaque responsable a sa propre cle CallMeBot — pas de cle partagee).
    Leve une exception si l'envoi echoue. Repli sur les env vars
    CALLMEBOT_PHONE/APIKEY si aucun destinataire n'est passe explicitement
    (compatibilite avec l'ancien comportement / les tests manuels)."""
    import urllib.parse
    telephone = telephone or CALLMEBOT_PHONE
    apikey = apikey or CALLMEBOT_APIKEY
    texte_encode = urllib.parse.quote(texte)
    url = (
        f"https://api.callmebot.com/whatsapp.php"
        f"?phone={telephone}&text={texte_encode}&apikey={apikey}"
    )
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200 or "queued" not in resp.text.lower():
        raise requests.RequestException(f"CallMeBot a répondu {resp.status_code} — {resp.text[:200]}")


def _envoyer_whatsapp_a_tous(texte: str) -> bool:
    """Envoie le meme message a tous les responsables WhatsApp actifs
    (table geree via /admin/responsables, avec repli sur les env vars si la
    table est vide). Retourne True si au moins un envoi a reussi."""
    destinataires_wa = destinataires.whatsapp_actifs()
    if not destinataires_wa:
        return False
    au_moins_un_ok = False
    for d in destinataires_wa:
        try:
            _envoyer_whatsapp(texte, d["telephone"], d["apikey"])
            au_moins_un_ok = True
        except requests.RequestException as e:
            print(f"⚠️  Échec envoi WhatsApp vers {d['telephone']} : {e}")
    return au_moins_un_ok


def envoyer_sms_alerte(m: dict, anomalies: list[str], explication: str) -> bool:
    """Envoie une alerte WhatsApp (via CallMeBot) pour les anomalies marquées
    critiques (🔴). Les 🟠 ne déclenchent jamais ça.

    BUG CORRIGÉ : avant, seule `critiques[0]` (la première anomalie critique
    de la liste) était prise en compte. Si CPU ET Mémoire étaient critiques
    en même temps, Mémoire ne recevait AUCUNE alerte tant que CPU n'était
    pas résolue (à ce moment-là Mémoire devenait "la première" et recevait
    enfin son tour). Maintenant chaque TYPE critique est suivi et notifié
    indépendamment."""
    critiques = [a for a in anomalies if a.startswith("🔴")]

    if anomalies:
        _nettoyer_anomalies_resolues(m)
        _marquer_anomalies_actives(anomalies)

    if not destinataires.whatsapp_actifs():
        if critiques:
            print("⚠️  Aucun responsable WhatsApp actif (voir /admin/responsables ou "
                  "CALLMEBOT_PHONE/APIKEY) — alerte WhatsApp ignorée.")
        return False

    maintenant = time.time()
    au_moins_un_envoi = False

    # 1) Types précédemment actifs côté WhatsApp mais redevenus normaux :
    #    notification de résolution, un message par type résolu.
    for cle in [c for c in list(_sms_actifs) if _est_anomalie_resolue(c, m)]:
        _sms_actifs.pop(cle, None)
        texte = f"✅ ALERTE RÉSOLUE ({cle}) {m['timestamp']}\nCPU: {m['cpu']}%\nMémoire: {m['memoire']}%"
        if _envoyer_whatsapp_a_tous(texte):
            print(f"📱 Alerte WhatsApp de résolution envoyée ({cle}).")
            au_moins_un_envoi = True

    if not critiques:
        return au_moins_un_envoi

    # 2) Types critiques à notifier maintenant : pas déjà actifs, et hors cooldown.
    types_a_notifier = []
    for a in critiques:
        cle = _cle_anomalie(a)
        if cle in _sms_actifs:
            continue
        if maintenant - _dernier_sms.get(cle, 0) < COOLDOWN_SMS_SECONDES:
            continue
        if cle not in types_a_notifier:
            types_a_notifier.append(cle)

    if not types_a_notifier:
        print("⏳ Alerte(s) WhatsApp critique(s) déjà active(s) ou en cooldown — envoi ignoré.")
        return au_moins_un_envoi

    texte = (
        f"🚨 ALERTE CRITIQUE {m['timestamp']}\n"
        + "\n".join(critiques)
        + f"\n{explication[:300]}"
    )
    if _envoyer_whatsapp_a_tous(texte):
        for cle in types_a_notifier:
            _dernier_sms[cle] = maintenant
            _sms_actifs[cle] = datetime.now()
        print("📱 Alerte WhatsApp envoyée.")
        return True
    return au_moins_un_envoi


# ---------------------------------------------------------------------------
# Notification bureau persistante (Windows) — avec résolution automatique
# ---------------------------------------------------------------------------
# Amélioration : La notification s'arrête automatiquement quand l'anomalie
# est résolue, même sans clic sur "Vu ✓".

INTERVALLE_RAPPEL_SECONDES = 45
MAX_TENTATIVES_BUREAU = 8  # ~6 minutes d'insistance avant abandon

_escalades_actives = {}  # cle_anomalie -> {'thread': thread, 'active': True, 'debut': datetime}


def _boucle_escalade(cle: str, titre: str, corps: str, m: dict):
    """Tourne dans un thread séparé : réaffiche la notification tant que
    personne n'a cliqué sur 'Vu ✓' (toast) OU 'J'ai vu ✓' (dashboard) ET que
    l'anomalie est toujours active. Si acquittée mais toujours active après
    DELAI_RAPPEL_APRES_ACQUITTEMENT_SECONDES, un rappel repart automatiquement."""
    from win11toast import toast

    acquitte = threading.Event()

    def au_clic(args):
        acquitte.set()
        acquitter(cle)  # un clic sur le toast compte aussi comme "J'ai vu" côté dashboard

    try:
        for tentative in range(1, MAX_TENTATIVES_BUREAU + 1):
            if acquitte.is_set():
                break

            m_actuel = _metriques_fraiches(m)

            # Vérifier si l'anomalie est toujours active avant chaque notification
            if not _est_anomalie_encore_active(cle, m_actuel):
                print(f"✅ Notification bureau '{cle}' arrêtée (anomalie résolue)")
                break

            # Acquittée récemment depuis le dashboard : on ne réaffiche pas
            # le toast ce tour-ci, mais on continue de surveiller pour
            # relancer un rappel si le problème persiste trop longtemps.
            if _est_acquittee_recemment(cle):
                time.sleep(5)
                continue

            suffixe = "" if tentative == 1 else f" (rappel {tentative}/{MAX_TENTATIVES_BUREAU})"
            toast(
                titre + suffixe,
                corps,
                buttons=["Vu ✓"],
                on_click=au_clic,
                duration="long",
            )

            if acquitte.is_set():
                break

            # Attendre mais vérifier périodiquement si l'anomalie est résolue
            # ou si un acquittement dashboard doit suspendre les rappels.
            for _ in range(INTERVALLE_RAPPEL_SECONDES // 5):
                if acquitte.is_set() or _est_acquittee_recemment(cle) or not _est_anomalie_encore_active(cle, _metriques_fraiches(m)):
                    break
                time.sleep(5)

    finally:
        with _anomalies_lock:
            if cle in _escalades_actives:
                del _escalades_actives[cle]
        print(f"🔕 Notification bureau '{cle}' terminée.")


def _est_anomalie_encore_active(cle: str, m: dict) -> bool:
    """Vérifie si l'anomalie est toujours active (pas résolue)."""
    with _anomalies_lock:
        if cle not in _anomalies_actives:
            return False
        return not _est_anomalie_resolue(cle, m)


def notifier_bureau_persistant(m: dict, anomalies: list[str], explication: str,
                                explications_par_type: dict = None) -> bool:
    """Déclenche une notification Windows par TYPE d'anomalie critique (🔴),
    chacune avec son propre thread de rappel jusqu'à acquittement ou résolution.

    `explications_par_type` (optionnel) : dict {type: explication}, pour que
    chaque toast affiche l'explication qui correspond VRAIMENT à son
    problème (plutôt qu'un texte générique partagé entre des anomalies
    différentes)."""
    critiques = [a for a in anomalies if a.startswith("🔴")]
    if not critiques:
        return False

    _nettoyer_anomalies_resolues(m)
    _marquer_anomalies_actives(anomalies)

    try:
        import win11toast  # noqa: F401
    except ImportError:
        print("⚠️  Le package 'win11toast' n'est pas installé "
              "(pip install win11toast) — notification bureau ignorée.")
        return False

    # Regroupe les anomalies critiques par type ("cpu", "memoire", ...).
    par_type = {}
    for a in critiques:
        par_type.setdefault(_cle_anomalie(a), []).append(a)

    au_moins_une = False
    for cle, messages in par_type.items():
        with _anomalies_lock:
            if cle in _escalades_actives:
                if _est_anomalie_resolue(cle, m):
                    del _escalades_actives[cle]
                    print(f"✅ Anomalie '{cle}' résolue, arrêt de la notification")
                else:
                    print(f"⏳ Notification bureau '{cle}' déjà en cours")
                continue
            _escalades_actives[cle] = True

        titre = f"🚨 Anomalie critique — {m['timestamp']}"
        exp = (explications_par_type or {}).get(cle) or explication or ""
        corps = "\n".join(messages) + "\n\n" + exp[:300]
        thread = threading.Thread(
            target=_boucle_escalade,
            args=(cle, titre, corps, m),
            daemon=True
        )
        thread.start()
        au_moins_une = True

    if au_moins_une:
        print("🖥️  Notification(s) bureau lancée(s) (s'arrêteront automatiquement à la résolution).")
    return au_moins_une


def nettoyer_anomalies_obsoletes(duree_max_minutes: int = 30):
    """Nettoie les anomalies actives trop vieilles (pour éviter les fuites mémoire)."""
    with _anomalies_lock:
        maintenant = datetime.now()
        a_supprimer = []
        for cle, debut in _anomalies_actives.items():
            if (maintenant - debut).total_seconds() > duree_max_minutes * 60:
                a_supprimer.append(cle)
        for cle in a_supprimer:
            del _anomalies_actives[cle]
            if cle in _escalades_actives:
                del _escalades_actives[cle]
            print(f"🧹 Anomalie '{cle}' nettoyée (trop vieille)")

        a_supprimer_acq = [
            cle for cle, t in _acquittements.items()
            if (maintenant - t).total_seconds() > duree_max_minutes * 60
        ]
        for cle in a_supprimer_acq:
            del _acquittements[cle]


if __name__ == "__main__":
    # Test manuel : python notifier.py
    faux_metriques = {
        "timestamp": "14:32:00",
        "cpu": 97.0,
        "memoire": 92.5,
        "disque_pct": 60,
        "nb_processus": 310,
    }
    fausses_anomalies = ["🔴 CPU critique : 97.0%"]
    fausse_explication = (
        "Le CPU est saturé depuis plusieurs minutes, probablement à cause "
        "d'un processus bloqué. Redémarrez le service concerné."
    )
    envoyer_alerte_slack(faux_metriques, fausses_anomalies, fausse_explication)
    envoyer_sms_alerte(faux_metriques, fausses_anomalies, fausse_explication)
    envoyer_email_alerte(faux_metriques, fausses_anomalies, fausse_explication)
    notifier_bureau_persistant(faux_metriques, fausses_anomalies, fausse_explication)