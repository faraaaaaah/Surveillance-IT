import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

# Charger les logs
df = pd.read_csv("logs.csv")

# Entraîner le modèle
modele = IsolationForest(contamination=0.02, random_state=42)
modele.fit(df[["cpu", "memoire", "erreurs"]])

# Détecter les anomalies
df["score"] = modele.decision_function(df[["cpu", "memoire", "erreurs"]])
df["anomalie"] = modele.predict(df[["cpu", "memoire", "erreurs"]])
# -1 = anomalie, 1 = normal

# Sauvegarder le modèle
with open("modele.pkl", "wb") as f:
    pickle.dump(modele, f)

# Afficher les résultats
anomalies = df[df["anomalie"] == -1]
print(f"✅ Modèle entraîné sur {len(df)} logs")
print(f"⚠️  {len(anomalies)} anomalies détectées")
print("\nAnomalies trouvées :")
print(anomalies[["id", "cpu", "memoire", "erreurs"]].to_string())