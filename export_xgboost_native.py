import os, pickle, sys
import boto3

MODEL_PKL_PATH = "/data/models/xgb_classifier.pkl"
LOCAL_EXPORT_PATH = "/tmp/model.bst"

S3_ENDPOINT = "http://minio.farah-boubaker-dev.svc.cluster.local:9000"
S3_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY")
if not S3_SECRET_KEY:
    sys.exit("MINIO_SECRET_KEY manquant")
S3_BUCKET = "provisionnement-modeles"
S3_KEY = "xgb-anomaly-classifier-native/1/model.bst"

with open(MODEL_PKL_PATH, "rb") as f:
    xgb_classifier = pickle.load(f)
print("Modele charge")

# Format natif XGBoost (pas pickle) -- exact, aucune conversion/approximation
xgb_classifier.get_booster().save_model(LOCAL_EXPORT_PATH)
print("Booster sauvegarde en natif:", LOCAL_EXPORT_PATH)

s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)
s3.upload_file(LOCAL_EXPORT_PATH, S3_BUCKET, S3_KEY)
print("Uploade vers s3://" + S3_BUCKET + "/" + S3_KEY)
