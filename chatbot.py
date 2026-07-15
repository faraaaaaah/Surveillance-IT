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


if __name__ == "__main__":
    # Test manuel : necessite Ollama installe et lance en local
    print(repondre_question("Quels problemes ont ete detectes recemment ?"))