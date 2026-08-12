"""
Module 5 - Rapport PDF hebdomadaire
----------------------------------------
Lit l'historique SQLite (historique.py) et genere un rapport PDF resumant
les incidents des 7 derniers jours : nombre total, repartition par type,
evolution jour par jour, et liste des incidents critiques.

Utilisation manuelle :
    python rapport_pdf.py

Utilisation automatique (hebdomadaire, sans intervention humaine) :
    python rapport_pdf.py --planifier
    (tourne en continu, genere un rapport chaque dimanche a 23h55)

Extension - Rapport de FIABILITE hebdomadaire (branche a notifier.py)
----------------------------------------------------------------------
En plus du rapport d'anomalies ci-dessus, generer_rapport_fiabilite()
produit un mini-rapport hebdomadaire dedie a la fiabilite du systeme de
prevision (combien d'alertes, taux de fiabilite, tendance par serveur),
historise semaine apres semaine dans un fichier JSONL (pas seulement la
fenetre glissante des 30 derniers jours deja affichee sur le dashboard),
puis envoye automatiquement par email aux responsables via
notifier.envoyer_rapport_fiabilite_email().

Utilisation manuelle :
    python rapport_pdf.py --fiabilite

Utilisation automatique (chaque lundi 08h00, depuis dashboard.py) :
    import rapport_pdf
    rapport_pdf.lancer_planificateur_fiabilite_en_arriere_plan()
"""

import os
import sys
import json
import sqlite3
import argparse
import threading
import time
from datetime import datetime, timedelta

import matplotlib
matplotlib.use("Agg")  # pas d'affichage interactif, juste generer des images
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)

from historique import CHEMIN_DB, initialiser_db

DOSSIER_SCRIPT = os.path.dirname(os.path.abspath(__file__))
DOSSIER_RAPPORTS = os.path.join(DOSSIER_SCRIPT, "rapports")


def _requete(sql, params=()):
    with sqlite3.connect(CHEMIN_DB) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, params)]


def generer_graphique_par_jour(donnees_jour, chemin_sortie):
    jours = [d["jour"] for d in donnees_jour]
    valeurs = [d["total"] for d in donnees_jour]

    fig, ax = plt.subplots(figsize=(6.5, 2.8))
    ax.bar(jours, valeurs, color="#4C6EF5")
    ax.set_title("Anomalies par jour", fontsize=11)
    ax.set_ylabel("Nombre")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.xticks(rotation=30, ha="right", fontsize=8)
    plt.tight_layout()
    fig.savefig(chemin_sortie, dpi=150)
    plt.close(fig)


def generer_graphique_par_type(donnees_type, chemin_sortie):
    types = [d["type_anomalie"] for d in donnees_type]
    valeurs = [d["total"] for d in donnees_type]
    couleurs = {
        "cpu": "#F03E3E", "memoire": "#F76707", "disque": "#F59F00",
        "reseau": "#1971C2", "processus": "#7048E8", "batterie": "#37B24D",
        "ia": "#495057", "autre": "#868E96",
    }
    barres_couleurs = [couleurs.get(t, "#868E96") for t in types]

    fig, ax = plt.subplots(figsize=(6.5, 2.8))
    ax.barh(types, valeurs, color=barres_couleurs)
    ax.set_title("Repartition par type d'anomalie", fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    fig.savefig(chemin_sortie, dpi=150)
    plt.close(fig)


def generer_rapport(jours_historique: int = 7, serveur: str = None) -> str:
    """Genere le PDF et retourne le chemin du fichier cree.

    `serveur` (optionnel) : si fourni, le rapport ne couvre QUE ce serveur.
    Avant, le rapport melangeait toujours TOUS les serveurs sans distinction
    (aucun filtre "serveur" dans les requetes), ce qui n'a pas de sens des
    qu'on surveille plusieurs machines : impossible de savoir laquelle a eu
    des problemes. Si `serveur` est omis, le comportement precedent
    (tous les serveurs confondus) est conserve, avec une mention explicite
    dans le titre pour que ce soit clair."""
    initialiser_db()
    os.makedirs(DOSSIER_RAPPORTS, exist_ok=True)

    date_fin = datetime.now()
    date_debut = date_fin - timedelta(days=jours_historique)
    debut_str = date_debut.strftime("%Y-%m-%d %H:%M:%S")

    condition_serveur = " AND serveur = ?" if serveur else ""
    params_base = (debut_str, serveur) if serveur else (debut_str,)

    total = _requete(
        f"SELECT COUNT(*) AS total FROM anomalies WHERE horodatage >= ?{condition_serveur}", params_base
    )[0]["total"]

    par_type = _requete(f"""
        SELECT type_anomalie, COUNT(*) AS total
        FROM anomalies WHERE horodatage >= ?{condition_serveur}
        GROUP BY type_anomalie ORDER BY total DESC
    """, params_base)

    par_niveau = _requete(f"""
        SELECT niveau, COUNT(*) AS total
        FROM anomalies WHERE horodatage >= ?{condition_serveur}
        GROUP BY niveau ORDER BY total DESC
    """, params_base)

    par_jour = _requete(f"""
        SELECT substr(horodatage, 1, 10) AS jour, COUNT(*) AS total
        FROM anomalies WHERE horodatage >= ?{condition_serveur}
        GROUP BY jour ORDER BY jour
    """, params_base)

    critiques = _requete(f"""
        SELECT horodatage, message, explication
        FROM anomalies WHERE horodatage >= ? AND niveau = 'critique'{condition_serveur}
        ORDER BY horodatage DESC LIMIT 20
    """, params_base)

    # --- Graphiques ---
    chemin_graph_jour = os.path.join(DOSSIER_RAPPORTS, "_tmp_graph_jour.png")
    chemin_graph_type = os.path.join(DOSSIER_RAPPORTS, "_tmp_graph_type.png")
    if par_jour:
        generer_graphique_par_jour(par_jour, chemin_graph_jour)
    if par_type:
        generer_graphique_par_type(par_type, chemin_graph_type)

    # --- Construction du PDF ---
    libelles_periode = {1: "jour", 7: "semaine", 30: "mois", 90: "trimestre"}
    libelle_periode = libelles_periode.get(jours_historique, f"{jours_historique}j")
    suffixe_serveur = f"_{serveur}" if serveur else "_tous-serveurs"
    nom_fichier = f"rapport_{libelle_periode}{suffixe_serveur}_{date_fin.strftime('%Y-%m-%d')}.pdf"
    chemin_pdf = os.path.join(DOSSIER_RAPPORTS, nom_fichier)

    doc = SimpleDocTemplate(
        chemin_pdf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    style_titre = ParagraphStyle("TitrePerso", parent=styles["Title"], textColor=HexColor("#1B1F24"))
    style_soustitre = ParagraphStyle("SousTitre", parent=styles["Heading2"], textColor=HexColor("#4C6EF5"),
                                      spaceBefore=14, spaceAfter=6)
    style_normal = styles["Normal"]

    story = []
    titre_periode = {1: "journalier", 7: "hebdomadaire", 30: "mensuel", 90: "trimestriel"}.get(
        jours_historique, f"({jours_historique} jours)"
    )
    story.append(Paragraph(f"Rapport {titre_periode} de surveillance", style_titre))
    story.append(Paragraph(
        f"Serveur : <b>{serveur or 'tous les serveurs'}</b> — "
        f"Periode : {date_debut.strftime('%d/%m/%Y')} au {date_fin.strftime('%d/%m/%Y')}",
        style_normal
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Resume", style_soustitre))
    story.append(Paragraph(f"<b>{total}</b> anomalie(s) detectee(s) durant la periode.", style_normal))
    nb_critiques = sum(d["total"] for d in par_niveau if d["niveau"] == "critique")
    story.append(Paragraph(f"Dont <b>{nb_critiques}</b> classee(s) critique(s).", style_normal))

    if par_jour:
        story.append(Paragraph("Evolution par jour", style_soustitre))
        story.append(Image(chemin_graph_jour, width=15 * cm, height=6.5 * cm))

    if par_type:
        story.append(Paragraph("Repartition par type", style_soustitre))
        story.append(Image(chemin_graph_type, width=15 * cm, height=6.5 * cm))

        data_table = [["Type", "Nombre"]] + [[d["type_anomalie"], str(d["total"])] for d in par_type]
        table = Table(data_table, colWidths=[9 * cm, 4 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1B1F24")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DEE2E6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#F1F3F5")]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(Spacer(1, 8))
        story.append(table)

    if critiques:
        story.append(PageBreak())
        story.append(Paragraph("Incidents critiques recents", style_soustitre))
        for c in critiques:
            story.append(Paragraph(f"<b>{c['horodatage']}</b> - {c['message']}", style_normal))
            if c["explication"]:
                story.append(Paragraph(f"<i>{c['explication'][:400]}</i>", style_normal))
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("Aucun incident critique durant cette periode.", style_normal))

    doc.build(story)

    for f in (chemin_graph_jour, chemin_graph_type):
        if os.path.exists(f):
            os.remove(f)

    return chemin_pdf


# ---------------------------------------------------------------------------
# Rapport de fiabilité hebdomadaire — historisé et envoyé par email
# ---------------------------------------------------------------------------
# Contrairement à historique.statistiques_fiabilite_previsions(jours=30)
# (fenêtre glissante, sans mémoire du passé), on garde ici un instantané
# par semaine dans un fichier JSONL séparé, pour pouvoir dire "la fiabilité
# de PC-Farah est en baisse depuis 3 semaines" plutôt que juste "elle est
# de X% en ce moment".

CHEMIN_HISTO_FIABILITE = os.path.join(DOSSIER_RAPPORTS, "historique_fiabilite.jsonl")


def _lister_serveurs() -> list:
    """Liste des serveurs distincts déjà vus dans l'historique des
    anomalies (exclut 'local', qui n'est pas un serveur surveillé au sens
    du provisionnement — même exclusion que provisionnement.page_provisionnement())."""
    lignes = _requete("SELECT DISTINCT serveur FROM anomalies")
    return sorted({r["serveur"] for r in lignes if r["serveur"] and r["serveur"] != "local"})


def _snapshot_fiabilite_semaine(jours: int = 7) -> dict:
    """Calcule un instantané de fiabilité (global + par serveur) via
    historique.statistiques_fiabilite_previsions(), et l'ajoute à la fin du
    fichier JSONL d'historique — une ligne par semaine, jamais réécrite."""
    from historique import statistiques_fiabilite_previsions

    snapshot = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "periode_jours": jours,
        "global": statistiques_fiabilite_previsions(jours=jours),
        "par_serveur": {
            serveur: statistiques_fiabilite_previsions(serveur=serveur, jours=jours)
            for serveur in _lister_serveurs()
        },
    }

    os.makedirs(DOSSIER_RAPPORTS, exist_ok=True)
    with open(CHEMIN_HISTO_FIABILITE, "a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")
    return snapshot


def _historique_fiabilite(n_dernieres: int = 12) -> list:
    """Relit les N derniers instantanés hebdomadaires enregistrés (ordre
    chronologique croissant)."""
    if not os.path.exists(CHEMIN_HISTO_FIABILITE):
        return []
    with open(CHEMIN_HISTO_FIABILITE, "r", encoding="utf-8") as f:
        lignes = [json.loads(l) for l in f if l.strip()]
    return lignes[-n_dernieres:]


def _tendance_fiabilite(serveur: str, snapshots: list) -> str:
    """Compare la fiabilité de cette semaine à celle de la semaine
    précédente pour ce serveur. Nécessite au moins 2 instantanés — avant
    ça, impossible de parler de tendance, seulement d'un chiffre isolé."""
    valeurs = [
        s["par_serveur"].get(serveur, {}).get("fiabilite_pct")
        for s in snapshots
        if s["par_serveur"].get(serveur, {}).get("fiabilite_pct") is not None
    ]
    if len(valeurs) < 2:
        return "→ pas encore assez d'historique"
    delta = valeurs[-1] - valeurs[-2]
    if delta > 2:
        return f"↗️ en hausse (+{delta:.0f} pts)"
    if delta < -2:
        return f"↘️ en baisse ({delta:.0f} pts)"
    return "→ stable"


def generer_rapport_fiabilite(jours_historique: int = 7) -> str:
    """Génère le rapport HEBDOMADAIRE de fiabilité (distinct du rapport
    d'anomalies de generer_rapport()) : nombre d'alertes, taux de
    fiabilité et tendance par serveur vs la semaine précédente. Historise
    systématiquement un instantané avant de construire le PDF. Retourne le
    chemin du PDF créé."""
    os.makedirs(DOSSIER_RAPPORTS, exist_ok=True)
    snapshot = _snapshot_fiabilite_semaine(jours=jours_historique)
    tous_snaps = _historique_fiabilite(n_dernieres=12)

    date_fin = datetime.now()
    nom_fichier = f"fiabilite_hebdo_{date_fin.strftime('%Y-%m-%d')}.pdf"
    chemin_pdf = os.path.join(DOSSIER_RAPPORTS, nom_fichier)

    doc = SimpleDocTemplate(
        chemin_pdf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    style_titre = ParagraphStyle("TitreFiab", parent=styles["Title"], textColor=HexColor("#1B1F24"))
    style_soustitre = ParagraphStyle("SousTitreFiab", parent=styles["Heading2"], textColor=HexColor("#4C6EF5"),
                                      spaceBefore=14, spaceAfter=6)
    style_normal = styles["Normal"]

    story = [
        Paragraph("Rapport hebdomadaire de fiabilité", style_titre),
        Paragraph(f"Semaine se terminant le {date_fin.strftime('%d/%m/%Y')}", style_normal),
        Spacer(1, 16),
    ]

    g = snapshot["global"]
    story.append(Paragraph("Résumé global", style_soustitre))
    if g.get("fiabilite_pct") is not None:
        total = g.get("nb_confirmees", 0) + g.get("nb_fausses_alertes", 0) + g.get("nb_annulees", 0)
        story.append(Paragraph(
            f"{total} alerte(s) préventive(s) sur les {jours_historique} derniers jours — "
            f"<b>{g['fiabilite_pct']}% de fiabilité</b> "
            f"({g.get('nb_confirmees', 0)} juste(s), {g.get('nb_fausses_alertes', 0)} fausse(s), "
            f"{g.get('nb_annulees', 0)} résorbée(s) seule(s)).",
            style_normal
        ))
    else:
        story.append(Paragraph(
            "Pas encore assez d'alertes cette semaine pour calculer une fiabilité.", style_normal
        ))

    story.append(Paragraph("Détail par serveur", style_soustitre))
    data_table = [["Serveur", "Alertes", "Fiabilité", "Tendance vs semaine précédente"]]
    for serveur, stats in sorted(snapshot["par_serveur"].items()):
        nb = stats.get("nb_confirmees", 0) + stats.get("nb_fausses_alertes", 0) + stats.get("nb_annulees", 0)
        fiab = f"{stats['fiabilite_pct']}%" if stats.get("fiabilite_pct") is not None else "—"
        data_table.append([serveur, str(nb), fiab, _tendance_fiabilite(serveur, tous_snaps)])

    if len(data_table) > 1:
        table = Table(data_table, colWidths=[5.5 * cm, 2.5 * cm, 2.5 * cm, 5.5 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1B1F24")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#DEE2E6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#F1F3F5")]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(Spacer(1, 8))
        story.append(table)
    else:
        story.append(Paragraph("Aucun serveur avec de l'historique pour le moment.", style_normal))

    chemin_graph = os.path.join(DOSSIER_RAPPORTS, "_tmp_graph_fiabilite.png")
    if len(tous_snaps) >= 2:
        story.append(Paragraph("Évolution de la fiabilité globale", style_soustitre))
        semaines = [s["date"] for s in tous_snaps]
        valeurs = [s["global"].get("fiabilite_pct") or 0 for s in tous_snaps]
        fig, ax = plt.subplots(figsize=(6.5, 2.8))
        ax.plot(semaines, valeurs, marker="o", color="#4C6EF5")
        ax.set_ylim(0, 105)
        ax.set_ylabel("Fiabilité (%)")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        plt.xticks(rotation=30, ha="right", fontsize=8)
        plt.tight_layout()
        fig.savefig(chemin_graph, dpi=150)
        plt.close(fig)
        story.append(Image(chemin_graph, width=15 * cm, height=6.5 * cm))

    doc.build(story)

    if os.path.exists(chemin_graph):
        os.remove(chemin_graph)

    return chemin_pdf


def _planificateur_fiabilite_hebdomadaire(jour_cible: int = 0, heure_cible: str = "08:00"):
    """jour_cible : 0=lundi (bilan de la semaine écoulée, envoyé au début
    de la semaine suivante). Génère le rapport de fiabilité ET l'envoie
    directement par email aux responsables (notifier.py) : contrairement
    au rapport d'anomalies de _planificateur_hebdomadaire(), personne ne
    va cliquer pour aller le consulter — il doit arriver dans la boîte
    mail sans action humaine."""
    deja_genere_cette_semaine = None
    while True:
        maintenant = datetime.now()
        cle_semaine = maintenant.strftime("%Y-W%W")
        if (maintenant.weekday() == jour_cible
                and maintenant.strftime("%H:%M") == heure_cible
                and deja_genere_cette_semaine != cle_semaine):
            try:
                chemin = generer_rapport_fiabilite()
                print(f"[Rapport fiabilité] Généré automatiquement : {chemin}")
                import notifier
                notifier.envoyer_rapport_fiabilite_email(chemin)
            except Exception as e:
                print(f"⚠️  Échec génération/envoi du rapport de fiabilité hebdo : {e}")
            deja_genere_cette_semaine = cle_semaine
        time.sleep(30)


def lancer_planificateur_fiabilite_en_arriere_plan():
    """A appeler depuis dashboard.py (comme lancer_planificateur_en_arriere_plan()
    pour le rapport d'anomalies), pour que le rapport de fiabilité parte
    tout seul chaque lundi matin tant que le dashboard tourne 24/7."""
    t = threading.Thread(target=_planificateur_fiabilite_hebdomadaire, daemon=True)
    t.start()


def _planificateur_hebdomadaire(jour_cible: int = 6, heure_cible: str = "23:55"):
    """jour_cible : 0=lundi ... 6=dimanche (norme datetime.weekday()).
    Verifie une fois par minute si c'est l'heure de generer le rapport."""
    deja_genere_cette_semaine = None
    while True:
        maintenant = datetime.now()
        cle_semaine = maintenant.strftime("%Y-W%W")
        if (maintenant.weekday() == jour_cible
                and maintenant.strftime("%H:%M") == heure_cible
                and deja_genere_cette_semaine != cle_semaine):
            chemin = generer_rapport()
            print(f"[Rapport hebdo] Genere automatiquement : {chemin}")
            deja_genere_cette_semaine = cle_semaine
        time.sleep(30)


def lancer_planificateur_en_arriere_plan():
    """A appeler depuis dashboard.py pour que le rapport se genere tout seul,
    sans intervention humaine, tant que le dashboard tourne 24/7."""
    t = threading.Thread(target=_planificateur_hebdomadaire, daemon=True)
    t.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--planifier", action="store_true",
                         help="Tourne en continu et genere le rapport chaque dimanche 23h55")
    parser.add_argument("--jours", type=int, default=7,
                         help="Nombre de jours a couvrir (defaut : 7)")
    parser.add_argument("--fiabilite", action="store_true",
                         help="Genere (et envoie par email) le rapport de fiabilite hebdomadaire au lieu du rapport d'anomalies")
    parser.add_argument("--planifier-fiabilite", action="store_true",
                         help="Tourne en continu et genere+envoie le rapport de fiabilite chaque lundi 08h00")
    args = parser.parse_args()

    if args.planifier_fiabilite:
        print("Planificateur de fiabilite demarre (CTRL+C pour arreter). Rapport genere et envoye chaque lundi a 08h00.")
        _planificateur_fiabilite_hebdomadaire()
    elif args.fiabilite:
        chemin = generer_rapport_fiabilite(args.jours)
        print(f"Rapport de fiabilite genere : {chemin}")
    elif args.planifier:
        print("Planificateur demarre (CTRL+C pour arreter). Rapport genere chaque dimanche a 23h55.")
        _planificateur_hebdomadaire()
    else:
        chemin = generer_rapport(args.jours)
        print(f"Rapport genere : {chemin}")