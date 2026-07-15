import psutil
import time
from datetime import datetime

def lire_metriques():
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "cpu": psutil.cpu_percent(interval=1),
        "memoire": psutil.virtual_memory().percent,
        "disque": psutil.disk_usage('/').percent,
        "erreurs": 0  # sera enrichi plus tard
    }

# Surveillance en temps réel
print("Surveillance en temps réel démarrée...")
print("Appuie sur CTRL+C pour arrêter\n")

while True:
    metriques = lire_metriques()
    print(f"[{metriques['timestamp']}] "
          f"CPU: {metriques['cpu']}% | "
          f"Mémoire: {metriques['memoire']}% | "
          f"Disque: {metriques['disque']}%")
    time.sleep(5)