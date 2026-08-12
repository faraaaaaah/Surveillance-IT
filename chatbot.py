"""
Fonctionnalite originale - Chatbot IA sur l'historique
------------------------------------------------------------
Permet de poser des questions en langage naturel sur l'historique des
incidents (ex: "pourquoi le serveur a plante hier ?"), en reutilisant le
meme LLM local (Ollama/Mistral) que pour les explications d'anomalies
(module 3), mais applique cette fois a la base d'incidents plutot qu'a
une seule anomalie ponctuelle.

Principe (RAG simplifie) :
    1. On recupere le contexte pertinent depuis la base SQLite (historique.py)
    2. On l'injecte dans le prompt envoye au LLM
    3. Le LLM repond en se basant UNIQUEMENT sur ces faits reels

Extension - Questions sur les PREVISIONS ML (provisionnement.py)
------------------------------------------------------------
Ce module etait jusqu'ici uniquement branche sur l'historique des
incidents PASSES. repondre_question_provisionnement() applique le meme
principe (RAG + LLM local) mais au contexte des PREVISIONS ACTUELLES
(page /provisionnement) : probabilite, confiance, facteurs determinants,
fiabilite historique du modele. Cela evite a un admin non-technique de
devoir interpreter lui-meme probabilite/confiance/feature_importance, en
posant simplement une question du type "Pourquoi PC-Farah est a 8% de
risque ?".
"""

import ollama
from historique import contexte_pour_chatbot


def repondre_question(question: str, serveur: str = None, jours: int = 7) -> str:
    """Repond a une question en langage naturel sur l'historique des incidents."""
    contexte = contexte_pour_chatbot(serveur=serveur, jours=jours)

    prompt = f"""Tu es un assistant IT qui repond a des questions sur l'historique
de surveillance d'une infrastructure. Voici les incidents enregistres
sur la periode recente :

{contexte}

Question de l'utilisateur : {question}

IMPORTANT :
- Reponds UNIQUEMENT a partir des informations ci-dessus, n'invente rien
- Si l'information demandee n'est pas dans l'historique, dis-le clairement
- Sois concis (3-4 phrases maximum)
- Reponds en francais
"""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"Le service IA (Ollama) n'est pas joignable pour repondre a cette question : {e}"


def _contexte_previsions(serveur: str = None, serveurs_disponibles: list = None) -> str:
    """Construit un contexte textuel a partir des VRAIES previsions ML
    actuellement calculees par provisionnement.apercu_serveur() — jamais
    de chiffres inventes. L'import de provisionnement est fait ICI (pas en
    tete de module) pour eviter tout souci d'import circulaire : c'est
    provisionnement.py qui appelle chatbot.py depuis sa route /api/chat,
    pas l'inverse."""
    import provisionnement

    if serveur:
        serveurs = [serveur]
    elif serveurs_disponibles:
        serveurs = list(serveurs_disponibles)
    else:
        return "Aucun serveur specifie et aucune liste de serveurs disponible."

    blocs = []
    for s in serveurs:
        try:
            p = provisionnement.apercu_serveur(s)
        except Exception:
            continue

        bloc = [f"Serveur {s} :", f"  Statut actuel : {p.get('niveau_label')}"]
        if p.get('niveau_cible') == 'collecte':
            bloc.append("  Pas encore assez de donnees pour une prediction fiable.")
            blocs.append("\n".join(bloc))
            continue

        bloc.append(f"  Probabilite d'anomalie : {round(p.get('probabilite', 0))}%")
        bloc.append(f"  Confiance du modele dans cette estimation : {round(p.get('confiance', 0) * 100)}%")
        bloc.append(
            f"  Metrique la plus a risque : {p.get('metrique_critique_label')} "
            f"(actuellement {round(p.get('valeur_actuelle', 0), 1)}%)"
        )
        if p.get('temps_estime'):
            bloc.append(f"  Temps estime avant d'atteindre le seuil critique : {p.get('temps_estime')}h")
        if p.get('feature_importance_display'):
            facteurs = ", ".join(f"{f['label']} ({f['pct']}%)" for f in p['feature_importance_display'])
            bloc.append(f"  Facteurs determinants de cette prediction : {facteurs}")
        if p.get('recommandation'):
            bloc.append(f"  Action recommandee : {p['recommandation']}")
        fiab = p.get('fiabilite') or {}
        if fiab.get('fiabilite_pct') is not None:
            bloc.append(
                f"  Fiabilite historique du modele sur ce serveur (30 derniers jours) : "
                f"{fiab['fiabilite_pct']}% ({fiab.get('nb_confirmees', 0)} alerte(s) juste(s), "
                f"{fiab.get('nb_fausses_alertes', 0)} fausse(s) alerte(s))"
            )
        if p.get('risque_combine'):
            bloc.append(f"  {p['risque_combine']['message']}")
        if p.get('maintenance_suggestion') and p['maintenance_suggestion'].get('disponible'):
            sug = p['maintenance_suggestion']
            bloc.append(f"  Fenetre de maintenance suggeree : {sug['debut_label']} -> {sug['fin_label']}")
        if p.get('correlations'):
            autres = ", ".join(
                srv for c in p['correlations'] for srv in c['serveurs'] if srv != s
            )
            bloc.append(f"  Derive corrélée avec : {autres} (cause commune probable)")

        blocs.append("\n".join(bloc))

    return "\n\n".join(blocs) if blocs else "Aucune donnee de prevision disponible pour ce(s) serveur(s)."


def repondre_question_provisionnement(question: str, serveur: str = None,
                                       serveurs_disponibles: list = None) -> str:
    """Repond en langage naturel a une question sur les PREVISIONS ML
    actuelles de provisionnement.py (ex: "Pourquoi PC-Farah est a 8% de
    risque ?", "Quel serveur est le plus a risque ?"), en se basant
    UNIQUEMENT sur les chiffres reels du modele. Reutilise le meme LLM
    local (Ollama/Mistral) et le meme principe RAG que repondre_question(),
    applique cette fois aux previsions plutot qu'a l'historique brut."""
    contexte = _contexte_previsions(serveur=serveur, serveurs_disponibles=serveurs_disponibles)

    prompt = f"""Tu es un assistant qui explique des predictions de panne informatique
a un administrateur non-technique. Voici l'etat actuel des previsions du
modele de machine learning :

{contexte}

Question de l'utilisateur : {question}

IMPORTANT :
- Reponds UNIQUEMENT a partir des chiffres ci-dessus, n'invente aucune
  valeur ni aucun serveur qui n'y figure pas
- Explique le "pourquoi" en termes simples (pas de jargon type "feature
  importance" ou "ensemble" : dis plutot "c'est surtout du a...")
- Si l'information demandee n'est pas dans les donnees ci-dessus, dis-le
  clairement plutot que de deviner
- Sois concis (3-4 phrases maximum)
- Reponds en francais
"""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"Le service IA (Ollama) n'est pas joignable pour repondre a cette question : {e}"


if __name__ == "__main__":
    # Test manuel : necessite Ollama installe et lance en local
    print(repondre_question("Quels problemes ont ete detectes recemment ?"))