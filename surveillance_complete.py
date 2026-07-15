"""
Surveillance console (module 1+2+3+4)
----------------------------------------
Version terminal : affiche tout dans la console.
Pour la version dashboard web, voir dashboard.py.
"""

import time
from monitoring_core import lire_metriques, detecter_anomalies, expliquer
from notifier import envoyer_alerte_slack, envoyer_sms_alerte, notifier_bureau_persistant
from historique import enregistrer_anomalie


def afficher(m):
    print(f"\n{'='*55}")
    print(f"🕐 {m['timestamp']}")
    print(f"🖥️  CPU        : {m['cpu']}%")
    print(f"🧠 Mémoire    : {m['memoire']}% ({m['memoire_gb']} GB)")
    print(f"💾 Disque     : {m['disque_pct']}%")
    print(f"🌐 Réseau     : ↓{m['download_mb']} MB | ↑{m['upload_mb']} MB | Perdus: {m['paquets_perdus']}")
    print(f"📋 Processus  : {m['nb_processus']} | Top: {m['top_processus']}")
    print(f"🔋 Batterie   : {m['batterie']}% | En charge: {m['en_charge']}")


if __name__ == "__main__":
    print("🖥️  Surveillance complète démarrée...")
    print("Appuie sur CTRL+C pour arrêter\n")

    while True:
        try:
            m = lire_metriques()
            afficher(m)

            anomalies = detecter_anomalies(m)

            if anomalies:
                print(f"\n🚨 {len(anomalies)} ANOMALIE(S) DÉTECTÉE(S) :")
                for a in anomalies:
                    print(f"   {a}")
                print("\n   💬 Analyse en cours...")
                explication = expliquer(m, anomalies)
                print(f"   {explication}")

                # Module 4 - Alertes (Slack toujours, WhatsApp+bureau seulement si critique 🔴)
                envoyer_alerte_slack(m, anomalies, explication)
                envoyer_sms_alerte(m, anomalies, explication)
                notifier_bureau_persistant(m, anomalies, explication)

                # Module 5 - Historique (sauvegarde pour le rapport hebdomadaire)
                enregistrer_anomalie(m, anomalies, explication)
            else:
                print("✅ Statut : Normal")

        except Exception as e:
            print(f"⚠️  Erreur dans le cycle de surveillance (ignoree, on continue) : {e}")

        time.sleep(5)