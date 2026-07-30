# -*- coding: utf-8 -*-
"""
Module Provisionnement — alerter AVANT que l'anomalie ne se produise
---------------------------------------------------------------------------
Jusqu'ici, SENTINEL reagit une fois qu'un seuil est deja depasse (CPU >= 85%,
disque >= 90%, ...). Ce module ajoute une couche PREVENTIVE : a partir de la
tendance recente d'un serveur (les points stockes par
historique.enregistrer_mesure, ~1 par minute), on estime SI et QUAND une
metrique va franchir son seuil d'alerte si rien ne change — et on previent
les employes PENDANT qu'il est encore temps d'agir (liberer de la memoire,
planifier un redemarrage, nettoyer un disque...) plutot que de subir
l'incident une fois qu'il est deja la.

Principe (regression lineaire simple sur les dernieres minutes, sans
dependance supplementaire) :
  1) On prend les N dernieres minutes de mesures d'un serveur pour une
     metrique (cpu / memoire / disque_pct).
  2) On calcule la pente (progression par heure) et la qualite de
     l'ajustement (R^2) : une courbe qui zigzague sans direction claire ne
     doit pas declencher de fausse alerte.
  3) Si la pente est positive et l'ajustement fiable, on projette le
     moment ou la metrique atteindrait le seuil warning / critique.
  4) Si cette echeance tombe dans l'horizon de vigilance
     (HORIZON_ALERTE_HEURES), on enregistre/actualise une "prevision"
     (voir historique.py) et on notifie les employes AVANT le depassement.

Boucle de confiance : chaque prevision est ensuite confrontee au reel
(historique.confirmer_previsions_pour_anomalies / expirer_previsions_perimees)
pour savoir si elle s'est realisee ou non. statistiques_fiabilite_previsions
donne un taux de fiabilite dans le temps : un outil preventif qui "crie au
loup" sans jamais avoir raison finit ignore, autant le mesurer explicitement
et le montrer aux responsables plutot que le cacher.
"""

from datetime import datetime, timedelta

from flask import Blueprint, render_template_string
from flask_login import login_required, current_user

import historique
import monitoring_core
from auth import TOKENS_CSS, JS_TEMA_ET_MENU, render_topbar

# --- Parametres reglables --------------------------------------------------
FENETRE_TENDANCE_MINUTES = 30    # historique regarde en arriere pour calculer la pente
POINTS_MINIMUM = 6               # en dessous, tendance jugee non fiable (pas assez de recul)
HORIZON_ALERTE_HEURES = 6        # ne prevenir que si l'echeance projetee est proche
R2_MINIMUM = 0.5                 # qualite d'ajustement minimale (0 = aucune tendance nette, 1 = parfait)

# Metrique correspondante dans les lignes de `mesures` (voir historique.py).
# Le reseau/processus/batterie ne sont volontairement pas provisionnes :
# trop erratiques (pics ponctuels) pour qu'une regression lineaire ait un
# sens, contrairement a cpu/memoire/disque qui montent souvent de facon
# progressive avant de franchir un seuil.
_CHAMP_MESURE = {"cpu": "cpu", "memoire": "memoire", "disque": "disque_pct"}


def _regression_lineaire(xs, ys):
    """Regression lineaire (moindres carres) ecrite a la main pour ne pas
    ajouter de dependance. xs/ys : listes de meme taille (>= 2).
    Retourne (pente, ordonnee_origine, r2)."""
    n = len(xs)
    moy_x = sum(xs) / n
    moy_y = sum(ys) / n
    var_x = sum((x - moy_x) ** 2 for x in xs)
    if var_x == 0:
        return 0.0, moy_y, 0.0
    cov_xy = sum((x - moy_x) * (y - moy_y) for x, y in zip(xs, ys))
    pente = cov_xy / var_x
    ordonnee = moy_y - pente * moy_x

    ss_tot = sum((y - moy_y) ** 2 for y in ys)
    if ss_tot == 0:
        r2 = 1.0 if pente == 0 else 0.0
    else:
        ss_res = sum((y - (pente * x + ordonnee)) ** 2 for x, y in zip(xs, ys))
        r2 = max(0.0, 1 - ss_res / ss_tot)
    return pente, ordonnee, r2


def calculer_tendance(serveur: str, type_anomalie: str, fenetre_minutes: int = FENETRE_TENDANCE_MINUTES):
    """Calcule la tendance recente d'une metrique pour un serveur donne.
    Retourne None si le type n'est pas provisionnable ou si on n'a pas
    assez de points recents pour degager une tendance fiable."""
    champ = _CHAMP_MESURE.get(type_anomalie)
    if not champ:
        return None

    mesures = historique.recuperer_mesures(serveur, heures=fenetre_minutes / 60)
    points = [(m["horodatage"], m.get(champ)) for m in mesures if m.get(champ) is not None]
    if len(points) < POINTS_MINIMUM:
        return None

    t0 = datetime.strptime(points[0][0], "%Y-%m-%d %H:%M:%S")
    xs = [(datetime.strptime(h, "%Y-%m-%d %H:%M:%S") - t0).total_seconds() / 3600 for h, _ in points]
    ys = [v for _, v in points]

    pente_par_heure, _ordonnee, r2 = _regression_lineaire(xs, ys)

    return {
        "pente_par_heure": pente_par_heure,
        "valeur_actuelle": ys[-1],
        "confiance": round(r2, 2),
        "nb_points": len(points),
    }


def _projeter_echeance(valeur_actuelle, pente_par_heure, seuil):
    """Nombre d'heures avant d'atteindre `seuil` au rythme actuel, ou None
    si la tendance est nulle/negative ou si le seuil est deja depasse
    (dans ce cas c'est deja une vraie anomalie, pas une prevision)."""
    if pente_par_heure <= 0 or valeur_actuelle >= seuil:
        return None
    return (seuil - valeur_actuelle) / pente_par_heure


def generer_previsions(serveur: str) -> list:
    """Genere les previsions actuelles pour un serveur (au plus une par
    type de metrique concerne). Ne remonte que les tendances jugees
    fiables (assez de points, R^2 suffisant) et dont l'echeance projetee
    tombe dans l'horizon de vigilance HORIZON_ALERTE_HEURES."""
    resultats = []
    for type_anomalie in _CHAMP_MESURE:
        tendance = calculer_tendance(serveur, type_anomalie)
        if not tendance or tendance["confiance"] < R2_MINIMUM:
            continue

        valeur = tendance["valeur_actuelle"]
        pente = tendance["pente_par_heure"]

        # On teste le seuil critique en premier : si sa trajectoire est
        # deja pertinente, c'est la prevision la plus utile a remonter
        # (pas la peine d'alerter EN PLUS sur le warning, moins parlant).
        for niveau_cible, seuils in (("critique", monitoring_core.SEUILS),
                                      ("warning", monitoring_core.SEUILS_WARNING)):
            seuil = seuils.get(type_anomalie)
            if seuil is None:
                continue
            heures_avant = _projeter_echeance(valeur, pente, seuil)
            if heures_avant is None or heures_avant > HORIZON_ALERTE_HEURES:
                continue
            resultats.append({
                "serveur": serveur,
                "type_anomalie": type_anomalie,
                "niveau_cible": niveau_cible,
                "valeur_actuelle": valeur,
                "pente_par_heure": pente,
                "confiance": tendance["confiance"],
                "seuil_cible": seuil,
                "heures_avant": round(heures_avant, 2),
            })
            break
    return resultats


def phrase_prevision(p: dict) -> str:
    """Message en langage simple, dans le meme esprit que les explications
    LLM de monitoring_core (pas de jargon, une action implicite : agir
    maintenant plutot que d'attendre l'incident)."""
    infos = historique.infos_type(p["type_anomalie"])
    delai = p["heures_avant"]
    delai_txt = f"{max(1, int(delai * 60))} min" if delai < 1 else f"{delai:.1f} h"
    mot_niveau = "critique" if p["niveau_cible"] == "critique" else "élevé"
    phrase_courte = infos["phrase"].split(" —")[0]
    return (f"🟡 Prévision : {phrase_courte.rstrip('.')} pourrait devenir {mot_niveau} "
            f"dans environ {delai_txt} si la tendance actuelle continue "
            f"({p['valeur_actuelle']:.1f}% → seuil {p['seuil_cible']}%).")


def traiter_previsions_serveur(serveur: str, envoyer_alerte_preventive=None) -> list:
    """A appeler periodiquement (voir boucle_provisionnement dans
    dashboard.py). Calcule les previsions actuelles pour ce serveur, les
    enregistre/actualise en base, et declenche
    `envoyer_alerte_preventive(serveur, prevision, phrase)` UNIQUEMENT
    pour les previsions nouvellement creees (pas a chaque cycle : la
    dedup vit dans historique.enregistrer_ou_maj_prevision). Retourne la
    liste des previsions actuelles, pour pousser une mise a jour live au
    dashboard si besoin."""
    previsions = generer_previsions(serveur)
    types_actifs = {p["type_anomalie"] for p in previsions}

    resultats = []
    for p in previsions:
        echeance = (historique.maintenant_local() + timedelta(hours=p["heures_avant"])).strftime("%Y-%m-%d %H:%M:%S")
        _id, est_nouvelle = historique.enregistrer_ou_maj_prevision(
            serveur=serveur, type_anomalie=p["type_anomalie"], niveau_cible=p["niveau_cible"],
            valeur_actuelle=p["valeur_actuelle"], pente_par_heure=p["pente_par_heure"],
            confiance=p["confiance"], seuil_cible=p["seuil_cible"], echeance_estimee=echeance,
        )
        p["id"] = _id
        p["echeance_estimee"] = echeance
        resultats.append(p)
        if est_nouvelle and envoyer_alerte_preventive:
            try:
                envoyer_alerte_preventive(serveur, p, phrase_prevision(p))
            except Exception as e:
                print(f"[provisionnement] Erreur envoi alerte preventive (ignoree) : {e}")

    # Les types qui ne sont plus en tendance haussiere n'ont plus lieu
    # d'etre surveilles : la metrique s'est stabilisee/redescendue avant
    # l'echeance projetee (bonne nouvelle, pas une prevision ratee).
    historique.annuler_previsions_hors_tendance(serveur, types_actifs)
    return resultats


# ---------------------------------------------------------------------------
# Page web "/provisionnement" — vue d'ensemble pour tous les utilisateurs
# ---------------------------------------------------------------------------
provisionnement_bp = Blueprint("provisionnement", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Provisionnement - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
  .bilan-fiabilite{display:grid; grid-template-columns:repeat(auto-fit, minmax(160px,1fr)); gap:14px; margin-bottom:22px;}
  .chiffre-fiabilite{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center;}
  .chiffre-fiabilite .valeur{font-size:24px; font-weight:700;}
  .chiffre-fiabilite .libelle{font-size:11.5px; color:var(--muted); margin-top:4px;}
  .grille-previsions{display:grid; grid-template-columns:repeat(auto-fill, minmax(320px,1fr)); gap:16px;}
  .carte-prevision{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px;
                    border-left:4px solid #e6b800;}
  .carte-prevision.critique{border-left-color:var(--crit, #e5484d);}
  .carte-prevision .entete-prevision{display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;}
  .carte-prevision h3{margin:0; font-size:15px;}
  .carte-prevision .serveur-nom{font-size:11.5px; color:var(--muted);}
  .carte-prevision .delai{font-size:12.5px; background:var(--panel2); border:1px solid var(--border);
                            border-radius:10px; padding:2px 10px;}
  .carte-prevision .phrase{font-size:12.5px; line-height:1.55; margin:0;}
  .carte-prevision .barre-progression{background:var(--panel2); border-radius:6px; height:8px; margin-top:12px; overflow:hidden;}
  .carte-prevision .barre-remplie{background:#e6b800; height:100%;}
  .carte-prevision.critique .barre-remplie{background:var(--crit, #e5484d);}
  .vide-etat{color:var(--muted); font-size:13px;}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>Provisionnement</h1>
    <p>Detection des tendances en cours, avant que le seuil ne soit reellement franchi : de quoi agir pendant qu'il est encore temps.</p>
  </div>

  <div class="bilan-fiabilite">
    <div class="chiffre-fiabilite">
      <div class="valeur">{{ fiabilite.fiabilite_pct if fiabilite.fiabilite_pct is not none else '—' }}{{ '%' if fiabilite.fiabilite_pct is not none else '' }}</div>
      <div class="libelle">Fiabilite des previsions (30j)</div>
    </div>
    <div class="chiffre-fiabilite">
      <div class="valeur">{{ fiabilite.nb_confirmees }}</div>
      <div class="libelle">Previsions confirmees</div>
    </div>
    <div class="chiffre-fiabilite">
      <div class="valeur">{{ fiabilite.nb_fausses_alertes }}</div>
      <div class="libelle">Fausses alertes</div>
    </div>
    <div class="chiffre-fiabilite">
      <div class="valeur">{{ fiabilite.delai_moyen_anticipation_min if fiabilite.delai_moyen_anticipation_min is not none else '—' }}{{ ' min' if fiabilite.delai_moyen_anticipation_min is not none else '' }}</div>
      <div class="libelle">Anticipation moyenne obtenue</div>
    </div>
  </div>

  {% if not previsions %}
  <div class="carte">
    <div class="vide-etat">Aucune tendance preoccupante detectee pour l'instant. Cette page se remplira automatiquement des qu'une metrique commence a deriver de facon soutenue vers un seuil d'alerte.</div>
  </div>
  {% else %}
  <div class="grille-previsions">
    {% for p in previsions %}
    <div class="carte-prevision {{ p.niveau_cible }}">
      <div class="entete-prevision">
        <div>
          <h3>{{ p.type_anomalie|capitalize }}</h3>
          <div class="serveur-nom">{{ p.serveur }}</div>
        </div>
        <span class="delai">~{{ '%.0f'|format(p.heures_avant * 60) if p.heures_avant < 1 else '%.1f h'|format(p.heures_avant) }}{{ ' min' if p.heures_avant < 1 else '' }}</span>
      </div>
      <p class="phrase">{{ p.phrase }}</p>
      <div class="barre-progression">
        <div class="barre-remplie" style="width: {{ [100, (p.valeur_actuelle / p.seuil_cible * 100)|round(0, 'floor')]|min }}%;"></div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}
</main>

<script>""" + JS_TEMA_ET_MENU + """</script>
</body></html>
"""


@provisionnement_bp.route("/provisionnement")
@login_required
def page_provisionnement():
    import assignations  # import tardif pour eviter tout souci d'ordre d'import avec dashboard.py
    autorisees = assignations.machines_autorisees(current_user)
    kwargs = {"serveurs": list(autorisees)} if autorisees is not None else {}

    maintenant = historique.maintenant_local()
    brutes = historique.previsions_actives(**kwargs)
    previsions = []
    for p in brutes:
        try:
            echeance = datetime.strptime(p["echeance_estimee"], "%Y-%m-%d %H:%M:%S")
            p["heures_avant"] = max(0.0, (echeance - maintenant).total_seconds() / 3600)
        except (ValueError, TypeError):
            p["heures_avant"] = 0.0
        p["phrase"] = phrase_prevision(p)
        previsions.append(p)

    serveur_unique = list(autorisees)[0] if autorisees is not None and len(autorisees) == 1 else None
    fiabilite = historique.statistiques_fiabilite_previsions(serveur=serveur_unique)

    return render_template_string(
        _PAGE, previsions=previsions, fiabilite=fiabilite,
        topbar=render_topbar("provisionnement"),
    )