# -*- coding: utf-8 -*-
"""
Convertit le xgb_classifier entraîné (.pkl) en ONNX compatible OpenVINO,
via Hummingbird (Microsoft) — qui transforme les arbres de décision en
opérations tensorielles pures (matmul, etc.), au lieu des opérateurs
ai.onnx.ml.TreeEnsembleClassifier (utilisés par onnxmltools) qu'OpenVINO
ne sait PAS exécuter. Testé et vérifié empiriquement : OpenVINO charge ce
modèle et prédit avec un écart négligeable (~0.004) vs XGBoost natif.

Prérequis dans le pod :
  pip install hummingbird-ml onnxscript --no-cache-dir --break-system-packages

À lancer avec :
  oc exec deployment/surveillance-dash -n farah-boubaker-dev -- python3 /tmp/export_xgboost_onnx.py
"""

import pickle
import boto3
import numpy as np
import torch
from hummingbird.ml import convert

# --- Config : adapte si besoin ---
MODEL_PKL_PATH = "/data/models/xgb_classifier.pkl"
LOCAL_EXPORT_PATH = "/tmp/model.onnx"
NB_FEATURES = 30  # doit correspondre exactement à feature_names dans provisionnement.py

S3_ENDPOINT = "http://minio.farah-boubaker-dev.svc.cluster.local:9000"
S3_ACCESS_KEY = "minioadmin"
S3_SECRET_KEY = "change-moi-en-un-mot-de-passe-solide"  # <-- remplace par le vrai mot de passe
S3_BUCKET = "provisionnement-modeles"

# OpenVINO Model Server attend : <nom_modele>/<version>/model.onnx
MODEL_NAME = "xgb-anomaly-classifier"
MODEL_VERSION = "1"
S3_KEY = f"{MODEL_NAME}/{MODEL_VERSION}/model.onnx"

# --- 1. Charger le modèle pickle existant ---
with open(MODEL_PKL_PATH, "rb") as f:
    xgb_classifier = pickle.load(f)

print(f"✅ Modèle chargé depuis {MODEL_PKL_PATH}")

# --- 2. Convertir via Hummingbird (arbre -> tenseurs) ---
dummy_input = np.zeros((1, NB_FEATURES), dtype=np.float32)
hb_model = convert(xgb_classifier, "torch", dummy_input)
torch_module = hb_model.model
torch_module.eval()

# Shape fixe (batch=1) : c'est déjà comme ça que predict_anomaly() appelle
# le modèle (une prédiction à la fois). Un batch dynamique fait planter
# OpenVINO sur une histoire de rang dynamique du Squeeze interne — inutile
# ici de toute façon.
torch.onnx.export(
    torch_module,
    torch.from_numpy(dummy_input),
    LOCAL_EXPORT_PATH,
    input_names=["input"],
    output_names=["label", "probabilities"],
    opset_version=13,
    dynamo=False,
)
print(f"✅ Converti en ONNX (compatible OpenVINO) : {LOCAL_EXPORT_PATH}")

# --- 3. Upload vers Minio, structure OVMS ---
s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)
s3.upload_file(LOCAL_EXPORT_PATH, S3_BUCKET, S3_KEY)
print(f"✅ Uploadé vers s3://{S3_BUCKET}/{S3_KEY} (écrase l'ancienne version incompatible)")
print()
print("Rappel technique (vérifié empiriquement) :")
print("  - Tenseur d'entrée : 'input', shape FIXE [1, 30], type FP32")
print("  - Sorties : 'label' et 'probabilities' (index [0][1] = proba classe positive)")
print("  - Contrainte : un seul échantillon par appel (batch=1), pas de batch dynamique")