import ollama

def expliquer_anomalie(cpu, memoire, erreurs):
    prompt = f"""
    Tu es un expert en infrastructure informatique.
    Une anomalie a été détectée sur une application :
    - CPU : {cpu}%
    - Mémoire : {memoire}%
    - Nombre d'erreurs : {erreurs}
    
    En 2 phrases maximum, explique ce qui se passe 
    et ce qu'il faut faire. Réponds en français.
    """
    
    response = ollama.chat(
        model="mistral",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return response["message"]["content"]

# Test avec une vraie anomalie détectée
print("🔍 Analyse de l'anomalie en cours...\n")
explication = expliquer_anomalie(cpu=97.0, memoire=97.3, erreurs=11)
print("💬 Explication :", explication)