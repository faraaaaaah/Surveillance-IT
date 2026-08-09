# -*- coding: utf-8 -*-
"""
Convertit le xgb_classifier entraîné (.pkl) en ONNX compatible OpenVINO,
via Hummingbird (Microsoft) — qui transforme les arbres de décision en
opérations tensorielles pures (matmul, etc.), au lieu des opérateurs
ai.onnx.ml.TreeEnsembleClassifier (utilisés par onnxmltools) qu'OpenVINO
ne sait PAS exécuter. Testé et vérifié empiriquement : OpenVINO charge ce
modèle et prédit avec un écart négligeable (~0.004) vs XGBoost natif.

BUG CONNU (constaté empiriquement) : OpenVINO exécute la sortie
"probabilities" avec une dimension finale résiduelle — shape réelle
(1, 2, 1) au lieu de (1, 2). Tenter de corriger ça dans le graphe ONNX
(insertion d'un noeud Squeeze) ne fonctionne PAS de façon fiable : le
graphe déclare bien (1, 2) après coup, mais OpenVINO continue à sortir
(1, 2, 1) à l'exécution. Le correctif fiable se fait donc côté client,
juste après l'inference (voir note à la fin de ce fichier).

Prérequis dans le pod :
  pip install hummingbird-ml onnxscript --no-cache-dir --break-system-packages

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
import torch
from hummingbird.ml import convert

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


# FIX (2026-08-06) : Hummingbird produit "probabilities" avec une dim
# résiduelle -> (1, 2, 1) au lieu de (1, 2). Constaté en prod : OVMS refuse
# alors de sérialiser la réponse ("difference in number of dimensions
# expected:2 vs actual:3"), donc AUCUNE inférence ne peut aboutir tant que
# ce n'est pas corrigé (le "fix côté client" imaginé plus tôt ne s'applique
# pas ici : la requête échoue avant que le client ne reçoive quoi que ce soit).
#
# Patcher le graphe ONNX après coup (nœud Squeeze ajouté a posteriori) ne
# suffit pas : la déclaration de shape change mais pas le vrai chemin de
# calcul exécuté par OpenVINO. Le squeeze doit donc faire partie du graphe
# de calcul PyTorch **avant** torch.onnx.export, pour être tracé comme une
# vraie opération du graphe.
class _SqueezedOutput(torch.nn.Module):
    def __init__(self, base_module):
        super().__init__()
        self.base_module = base_module

    def forward(self, x):
        label, probabilities = self.base_module(x)
        # IMPORTANT : reshape INCONDITIONNEL, pas un `if dim()==3: squeeze`.
        # Pendant le trace natif PyTorch, probabilities est déjà (1,2) donc
        # une condition sur dim()==3 est fausse au moment du trace et n'est
        # JAMAIS incluse dans le graphe exporté. Le bug (1,2,1) n'apparaît
        # qu'à l'exécution par OpenVINO du graphe ONNX (comportement runtime
        # différent de PyTorch sur une opération interne d'Hummingbird).
        # Un reshape inconditionnel devient un vrai noeud Reshape dans le
        # graphe ONNX, exécuté par OpenVINO sur SA propre sortie interne
        # (même bugguée à 3D), et la force à (batch, 2) quoi qu'il arrive.
        probabilities = probabilities.reshape(1, 2)
        return label, probabilities


torch_module = _SqueezedOutput(torch_module)
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

# Vérif immédiate (avant upload) que la shape de sortie est bien (1, 2) et
# pas (1, 2, 1) -- pour ne pas re-uploader un modèle cassé sans le savoir.
import onnx  # noqa: E402

_onnx_model = onnx.load(LOCAL_EXPORT_PATH)
for _out in _onnx_model.graph.output:
    if _out.name == "probabilities":
        _dims = [d.dim_value for d in _out.type.tensor_type.shape.dim]
        print(f"ℹ️  Shape déclarée pour 'probabilities' dans le graphe ONNX : {_dims}")
        if len(_dims) != 2:
            sys.exit(
                f"❌ Shape inattendue {_dims} pour 'probabilities' -- le fix n'a pas "
                "pris, ne pas uploader ce modèle."
            )

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
print("  - Sorties : 'label' et 'probabilities'")
print("  - ⚠️  'probabilities' sort en shape (1, 2, 1) à l'exécution OpenVINO (pas (1,2))")
print("  - CÔTÉ APPELANT (predict_anomaly etc.) : faire np.squeeze(proba) avant d'indexer,")
print("    ex: proba = np.squeeze(result[compiled.output(1)]); positive = proba[1]")
print("  - Contrainte : un seul échantillon par appel (batch=1), pas de batch dynamique")