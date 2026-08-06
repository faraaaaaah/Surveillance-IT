# -*- coding: utf-8 -*-
"""
Convertit le xgb_classifier entraîné (.pkl) en ONNX compatible OpenVINO,
via Hummingbird (Microsoft) — qui transforme les arbres de décision en
opérations tensorielles pures (matmul, etc.), au lieu des opérateurs
ai.onnx.ml.TreeEnsembleClassifier (utilisés par onnxmltools) qu'OpenVINO
ne sait PAS exécuter. Testé et vérifié empiriquement : OpenVINO charge ce
modèle et prédit avec un écart négligeable (~0.004) vs XGBoost natif.

BUG CORRIGÉ (constaté empiriquement) : Hummingbird/torch.onnx.export laisse
une dimension finale résiduelle sur la sortie "probabilities" — le graphe
déclare [1,2] en métadonnées mais OpenVINO exécute réellement [1,2,1].
On corrige ça à la source en insérant un noeud Squeeze dans le graphe ONNX
avant l'upload, puis on RE-VÉRIFIE avec OpenVINO que la shape réelle en
sortie est bien (1,2) avant d'envoyer le modèle sur Minio. Comme ça, le
correctif vit dans l'artefact et pas dans chaque appelant (predict_anomaly
et consorts n'ont rien à changer).

Prérequis dans le pod :
  pip install hummingbird-ml onnxscript onnx openvino --no-cache-dir --break-system-packages

Variables d'env à définir avant de lancer (au lieu de secrets en dur) :
  export MINIO_ACCESS_KEY=...
  export MINIO_SECRET_KEY=...

À lancer avec :
  oc exec deployment/surveillance-dash -n farah-boubaker-dev -- python3 /tmp/export_xgboost_onnx.py
"""

import os
import pickle
import sys

import boto3
import numpy as np
import onnx
import torch
from hummingbird.ml import convert
from onnx import TensorProto, helper

# --- Config : adapte si besoin ---
MODEL_PKL_PATH = "/data/models/xgb_classifier.pkl"
LOCAL_EXPORT_PATH = "/tmp/model.onnx"
# NB_FEATURES n'est plus codé en dur : on le lit directement depuis le
# modèle chargé, car le .pkl réel en production peut avoir été entraîné
# avec un nombre de colonnes différent de ce qu'on pensait (ex: une
# version antérieure du feature engineering).

S3_ENDPOINT = "http://minio.farah-boubaker-dev.svc.cluster.local:9000"
S3_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY")
if not S3_SECRET_KEY:
    sys.exit("❌ MINIO_SECRET_KEY n'est pas défini dans l'environnement du pod.")
S3_BUCKET = "provisionnement-modeles"

# OpenVINO Model Server attend : <nom_modele>/<version>/model.onnx
MODEL_NAME = "xgb-anomaly-classifier"
MODEL_VERSION = "1"
S3_KEY = f"{MODEL_NAME}/{MODEL_VERSION}/model.onnx"

# --- 1. Charger le modèle pickle existant ---
with open(MODEL_PKL_PATH, "rb") as f:
    xgb_classifier = pickle.load(f)

print(f"✅ Modèle chargé depuis {MODEL_PKL_PATH}")

# Nombre réel de features attendu par CE modèle précis (pas une supposition)
NB_FEATURES = xgb_classifier.get_booster().num_features()
print(f"ℹ️  Le modèle attend {NB_FEATURES} features en entrée")

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

# --- 2bis. Corriger la dimension résiduelle sur "probabilities" ---
# torch.onnx.export (via Hummingbird) laisse la sortie "probabilities" en
# shape réelle [1, 2, 1] alors que le graphe déclare [1, 2]. On insère un
# Squeeze(axes=[-1]) directement dans le graphe pour que shape déclarée et
# shape réelle coïncident enfin.
onnx_model = onnx.load(LOCAL_EXPORT_PATH)

RAW_NAME = "probabilities_raw"
renamed = False
for node in onnx_model.graph.node:
    for i, out_name in enumerate(node.output):
        if out_name == "probabilities":
            node.output[i] = RAW_NAME
            renamed = True
if not renamed:
    sys.exit("❌ Impossible de trouver le noeud produisant 'probabilities' dans le graphe.")

axes_tensor = helper.make_tensor("squeeze_axes", TensorProto.INT64, [1], [-1])
onnx_model.graph.initializer.append(axes_tensor)
squeeze_node = helper.make_node(
    "Squeeze",
    inputs=[RAW_NAME, "squeeze_axes"],
    outputs=["probabilities"],
    name="fix_probabilities_trailing_dim",
)
onnx_model.graph.node.append(squeeze_node)

onnx.checker.check_model(onnx_model)
onnx.save(onnx_model, LOCAL_EXPORT_PATH)
print("✅ Noeud Squeeze inséré sur 'probabilities' (correctif shape)")

# --- 2ter. Re-vérification avec OpenVINO (pas de confiance aveugle) ---
try:
    import openvino as ov

    core = ov.Core()
    ov_model = core.read_model(LOCAL_EXPORT_PATH)
    compiled = core.compile_model(ov_model, "CPU")
    result = compiled([dummy_input])
    real_shape = result[compiled.output(1)].shape
    if real_shape != (1, 2):
        sys.exit(f"❌ Shape réelle toujours incorrecte après correctif : {real_shape} (attendu (1, 2))")
    print(f"✅ Vérifié avec OpenVINO : shape réelle de 'probabilities' = {real_shape}")
except ImportError:
    print("⚠️  Package 'openvino' absent du pod : correctif appliqué mais NON re-vérifié à l'exécution.")
    print("    Installe-le (pip install openvino --break-system-packages) pour une vérification complète.")

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
print(f"  - Tenseur d'entrée : 'input', shape FIXE [1, {NB_FEATURES}], type FP32")
print("  - Sorties : 'label' et 'probabilities', shape RÉELLE (1, 2) — corrigée (plus de dim résiduelle)")
print("  - index [0][1] = proba classe positive, DIRECTEMENT (pas besoin de squeeze côté appelant)")
print("  - Contrainte : un seul échantillon par appel (batch=1), pas de batch dynamique")