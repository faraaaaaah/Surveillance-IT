# -*- coding: utf-8 -*-
"""
Convertit le xgb_classifier entraîné (.pkl) en ONNX, puis l'upload dans
Minio avec la structure de dossiers attendue par OpenVINO Model Server
(<nom_modele>/<version>/model.onnx).

Prérequis dans le pod : pip install onnxmltools onnx --break-system-packages

À lancer avec :
  oc exec deployment/surveillance-dash -n farah-boubaker-dev -- python3 /tmp/export_xgboost_onnx.py
"""

import pickle
import boto3
from onnxmltools.convert import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

# --- Config : adapte si besoin ---
MODEL_PKL_PATH = "/data/models/xgb_classifier.pkl"
LOCAL_EXPORT_PATH = "/tmp/model.onnx"
NB_FEATURES = 30  # doit correspondre exactement à feature_names dans provisionnement.py

S3_ENDPOINT = "http://minio.farah-boubaker-dev.svc.cluster.local:9000"
S3_ACCESS_KEY = "minioadmin"
S3_SECRET_KEY = "change-moi-en-un-mot-de-passe-solide"
S3_BUCKET = "provisionnement-modeles"

# OpenVINO Model Server attend : <nom_modele>/<version>/model.onnx
MODEL_NAME = "xgb-anomaly-classifier"
MODEL_VERSION = "1"
S3_KEY = f"{MODEL_NAME}/{MODEL_VERSION}/model.onnx"

# --- 1. Charger le modèle pickle existant ---
with open(MODEL_PKL_PATH, "rb") as f:
    xgb_classifier = pickle.load(f)

print(f"✅ Modèle chargé depuis {MODEL_PKL_PATH}")

# --- 2. Convertir en ONNX ---
initial_type = [('input', FloatTensorType([None, NB_FEATURES]))]
onnx_model = convert_xgboost(xgb_classifier, initial_types=initial_type)

with open(LOCAL_EXPORT_PATH, "wb") as f:
    f.write(onnx_model.SerializeToString())
print(f"✅ Converti en ONNX : {LOCAL_EXPORT_PATH}")

# --- 3. Upload vers Minio, structure OVMS ---
s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)
s3.upload_file(LOCAL_EXPORT_PATH, S3_BUCKET, S3_KEY)
print(f"✅ Uploadé vers s3://{S3_BUCKET}/{S3_KEY}")
print()
print(f"Dans OpenShift AI, déploie avec :")
print(f"  - Data connection : minio-provisionnement")
print(f"  - Path            : {MODEL_NAME}")
print(f"  - Runtime         : OpenVINO Model Server")
print()
print("Rappel technique (vérifié empiriquement) :")
print("  - Nom du tenseur d'entrée ONNX : 'input', shape [None, 30], type FP32")
print("  - Sorties : 'label' (classe prédite) et 'probabilities' (proba par classe)")
print("  - La probabilité d'anomalie = probabilities[1] (classe positive)")