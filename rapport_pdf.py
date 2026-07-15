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
"""

import os
import sys
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
    args = parser.parse_args()

    if args.planifier:
        print("Planificateur demarre (CTRL+C pour arreter). Rapport genere chaque dimanche a 23h55.")
        _planificateur_hebdomadaire()
    else:
        chemin = generer_rapport(args.jours)
        print(f"Rapport genere : {chemin}")