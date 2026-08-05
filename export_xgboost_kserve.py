# -*- coding: utf-8 -*-
"""
Exporte le xgb_classifier entraîné (sauvegardé en .pkl) vers le format
natif XGBoost (.bst), requis par le runtime KServe intégré à OpenShift AI,
puis l'upload dans le bucket Minio.

À lancer avec :
  oc exec deployment/surveillance-dash -n farah-boubaker-dev -- python3 export_xgboost_kserve.py
(après avoir copié ce fichier dans le pod, ou via oc cp)
"""

import pickle
import boto3

# --- Config : adapte si besoin ---
MODEL_PKL_PATH = "/data/models/xgb_classifier.pkl"
LOCAL_EXPORT_PATH = "/tmp/model.bst"

S3_ENDPOINT = "http://minio.farah-boubaker-dev.svc.cluster.local:9000"
S3_ACCESS_KEY = "minioadmin"
S3_SECRET_KEY = "change-moi-en-un-mot-de-passe-solide"
S3_BUCKET = "provisionnement-modeles"
S3_KEY = "xgboost/model.bst"  # KServe attend model.bst dans un "dossier" xgboost/

# --- 1. Charger le modèle pickle existant ---
with open(MODEL_PKL_PATH, "rb") as f:
    xgb_classifier = pickle.load(f)

print(f"✅ Modèle chargé depuis {MODEL_PKL_PATH}")

# --- 2. Exporter au format natif XGBoost (booster) ---
booster = xgb_classifier.get_booster()
booster.save_model(LOCAL_EXPORT_PATH)
print(f"✅ Exporté au format natif : {LOCAL_EXPORT_PATH}")

# --- 3. Upload vers Minio ---
s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)
s3.upload_file(LOCAL_EXPORT_PATH, S3_BUCKET, S3_KEY)
print(f"✅ Uploadé vers s3://{S3_BUCKET}/{S3_KEY}")
print()
print("Rappel de l'ordre des features attendu par ce modèle (30 valeurs, DÉJÀ standardisées via le scaler) :")
print("""
cpu, memoire, disque_pct, hour, day_of_week, minute, is_weekend,
is_business_hours, cpu_rolling_mean_5, cpu_rolling_std_5,
memoire_rolling_mean_5, memoire_rolling_std_5, disque_pct_rolling_mean_5,
disque_pct_rolling_std_5, cpu_rolling_mean_15, memoire_rolling_mean_15,
disque_pct_rolling_mean_15, cpu_diff_1, memoire_diff_1, disque_pct_diff_1,
cpu_pct_change, memoire_pct_change, disque_pct_pct_change, cpu_memory_ratio,
cpu_disk_ratio, memory_disk_ratio, hour_sin, hour_cos, day_sin, day_cos
""")