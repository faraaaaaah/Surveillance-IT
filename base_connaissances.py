# -*- coding: utf-8 -*-
"""
Module Base de connaissances — capitaliser sur l'experience des incidents
---------------------------------------------------------------------------
Pour chaque type d'anomalie deja rencontre (CPU, memoire, disque, ...), on
regroupe l'explication generale (deja presente dans historique.py) avec les
solutions concretes notees par les employes au moment de fermer un incident
(colonne `incidents.solution`, voir historique.py).

Interet :
- Employes  : reagir plus vite face a une anomalie deja vue, sans repartir
              de zero a chaque fois.
- Responsables : reperer d'un coup d'oeil les types de problemes qui
                 reviennent le plus souvent (candidats a un vrai correctif
                 plutot qu'a une solution repetee).
- Entreprise : le savoir-faire reste dans l'outil, meme si la personne qui
               a resolu le probleme la premiere fois n'est plus la.

Accessible a TOUS les utilisateurs connectes (pas reserve aux admins) :
c'est un outil d'aide au travail quotidien, pas une page d'administration.
"""

from flask import Blueprint, render_template_string
from flask_login import login_required

import historique
from auth import TOKENS_CSS, JS_TEMA_ET_MENU, render_topbar

base_connaissances_bp = Blueprint("base_connaissances", __name__)


_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Base de connaissances - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
  .grille-types{display:grid; grid-template-columns:repeat(auto-fill, minmax(300px,1fr)); gap:16px;}
  .carte-type{background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:20px;}
  .carte-type .entete-type{display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;}
  .carte-type h3{margin:0; font-size:15px;}
  .carte-type .compteur{font-size:11px; color:var(--muted); background:var(--panel2); padding:2px 9px; border-radius:10px; border:1px solid var(--border);}
  .carte-type .phrase{color:var(--muted); font-size:12.5px; margin:0 0 12px; line-height:1.5;}
  .carte-type .solution-generale{background:var(--panel2); border-left:3px solid var(--accent); padding:9px 12px;
                                  border-radius:6px; font-size:12.5px; margin-bottom:12px; line-height:1.5;}
  .liste-solutions{display:flex; flex-direction:column; gap:8px;}
  .liste-solutions .titre-liste{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; margin-bottom:2px;}
  .solution-vecue{background:var(--bg); border:1px solid var(--border); border-radius:7px; padding:8px 11px; font-size:12.5px; line-height:1.5;}
  .solution-vecue .meta{color:var(--muted); font-size:11px; margin-top:3px;}
  .vide-solutions{color:var(--muted); font-size:12px; font-style:italic;}
</style></head><body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>Base de connaissances</h1>
    <p>Pour chaque type d'anomalie deja rencontre : l'explication generale, et ce que les employes ont deja fait pour resoudre le probleme.</p>
  </div>

  {% if not stats %}
  <div class="carte">
    <div class="vide-etat">Aucun incident enregistre pour l'instant. La base de connaissances se remplira automatiquement au fil des anomalies detectees et resolues.</div>
  </div>
  {% else %}
  <div class="grille-types">
    {% for s in stats %}
    <div class="carte-type">
      <div class="entete-type">
        <h3>{{ s.type_anomalie|capitalize }}</h3>
        <span class="compteur">{{ s.nb_incidents }} incident{{ 's' if s.nb_incidents > 1 else '' }}</span>
      </div>
      <p class="phrase">{{ s.infos.phrase }}</p>
      <div class="solution-generale">💡 <b>Reflexe general :</b> {{ s.infos.solution }}</div>

      <div class="liste-solutions">
        <div class="titre-liste">Ce qui a deja marche ({{ s.nb_solutions }} note{{ 's' if s.nb_solutions > 1 else '' }})</div>
        {% set sols = solutions[s.type_anomalie] %}
        {% if sols %}
          {% for sol in sols %}
          <div class="solution-vecue">
            {{ sol.solution }}
            <div class="meta">{{ sol.serveur }} — {{ sol.fin or sol.derniere_occurrence }}</div>
          </div>
          {% endfor %}
        {% else %}
          <div class="vide-solutions">Aucune solution notee pour l'instant. La prochaine fois qu'un employe resout ce type d'incident, sa solution apparaitra ici.</div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}
</main>

<script>""" + JS_TEMA_ET_MENU + """</script>
</body></html>
"""


@base_connaissances_bp.route("/base-connaissances")
@login_required
def page_base_connaissances():
    stats = historique.statistiques_base_connaissances()
    solutions = {
        s["type_anomalie"]: historique.solutions_deja_vues(s["type_anomalie"], limite=5)
        for s in stats
    }
    return render_template_string(
        _PAGE, stats=stats, solutions=solutions,
        topbar=render_topbar("base_connaissances"),
    )