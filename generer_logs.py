import pandas as pd
import random

def generer_logs(n=500):
    logs = []
    
    # Logs normaux
    for i in range(n):
        logs.append({
            "id": i,
            "cpu": round(random.uniform(10, 60), 2),
            "memoire": round(random.uniform(20, 70), 2),
            "erreurs": random.randint(0, 2),
            "type": "normal"
        })
    
    # Logs anormaux (pannes simulées)
    for i in range(10):
        logs.append({
            "id": n + i,
            "cpu": round(random.uniform(85, 100), 2),
            "memoire": round(random.uniform(85, 100), 2),
            "erreurs": random.randint(8, 20),
            "type": "anomalie"
        })
    
    return pd.DataFrame(logs)

df = generer_logs()
df.to_csv("logs.csv", index=False)
print(f"✅ {len(df)} logs générés dont 10 anomalies")
print(df.tail(5))