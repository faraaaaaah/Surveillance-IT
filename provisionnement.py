# -*- coding: utf-8 -*-
"""
Module Provisionnement — Version Production OpenShift
Avec gestion robuste des permissions et des chemins
---------------------------------------------------
SENTINEL provisionne AVANT que l'anomalie ne se produise en utilisant
un ensemble de modèles ML (XGBoost, LSTM, Prophet) déployés sur OpenShift AI.
"""

import os
import sys
import json
import pickle
import warnings
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import threading
import logging
from collections import deque
import time
import tempfile

# Data processing
import numpy as np
import pandas as pd

# ML Libraries
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score, accuracy_score

# Deep Learning
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

# XGBoost
from xgboost import XGBClassifier, XGBRegressor

# Prophet (optionnel)
try:
    from prophet import Prophet
    PROPHET_AVAILABLE = True
except ImportError:
    PROPHET_AVAILABLE = False
    print("⚠️ Prophet non disponible, utilisation de modèles alternatifs")

# OpenShift AI / Cloud Storage
try:
    import boto3
    from botocore.exceptions import ClientError
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False
    print("⚠️ boto3 non disponible, S3 désactivé")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️ requests non disponible, appels API désactivés")

try:
    from kubernetes import client, config
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    print("⚠️ kubernetes non disponible, déploiement KServe désactivé")

# Flask
from flask import Blueprint, render_template_string, jsonify, request
from flask_login import login_required, current_user

# Internal imports
import historique
import monitoring_core
from auth import TOKENS_CSS, JS_TEMA_ET_MENU, render_topbar

# ============================================================================
# CONFIGURATION DURABLE POUR OPENSHIFT
# ============================================================================

class ProductionConfig:
    """
    Configuration robuste pour OpenShift
    Gère automatiquement les permissions et les chemins
    """
    
    # Variables d'environnement
    ENV_PREFIX = "SURVEILLANCE_"
    
    @classmethod
    def get_env(cls, name: str, default: Any = None) -> str:
        """Récupère une variable d'environnement avec préfixe"""
        return os.getenv(f"{cls.ENV_PREFIX}{name}", os.getenv(name, default))
    
    @classmethod
    def get_path(cls, name: str, default: str) -> Path:
        """Retourne un chemin valide avec vérification des permissions"""
        path_str = cls.get_env(name, default)
        path = Path(path_str)
        
        # Vérifier si on peut créer le répertoire
        try:
            path.mkdir(parents=True, exist_ok=True)
            # Tester l'écriture
            test_file = path / ".write_test"
            test_file.touch()
            test_file.unlink()
            print(f"✅ Répertoire accessible: {path}")
            return path
        except (PermissionError, OSError) as e:
            # Fallback sur /tmp
            fallback_path = Path("/tmp") / path.name
            fallback_path.mkdir(parents=True, exist_ok=True)
            print(f"⚠️ Permission refusée sur {path}, utilisation de {fallback_path}")
            return fallback_path
    
    @classmethod
    def initialize(cls):
        """Initialise la configuration"""
        
        # === PATHS ===
        cls.BASE_DIR = cls.get_path("BASE_DIR", "/data")
        cls.MODEL_DIR = cls.get_path("MODEL_DIR", str(cls.BASE_DIR / "models"))
        cls.CACHE_DIR = cls.get_path("CACHE_DIR", str(cls.BASE_DIR / "cache"))
        cls.DATA_DIR = cls.get_path("DATA_DIR", str(cls.BASE_DIR / "input"))
        cls.LOG_DIR = cls.get_path("LOG_DIR", str(cls.BASE_DIR / "logs"))
        cls.TEMP_DIR = cls.get_path("TEMP_DIR", "/tmp/surveillance")
        
        # === MODE ===
        cls.OPENSHIFT_MODE = cls.get_env("OPENSHIFT_MODE", "false").lower() == "true"
        cls.DEPLOYMENT_MODE = cls.get_env("DEPLOYMENT_MODE", "standalone")
        
        # === S3 ===
        cls.S3_ENDPOINT = cls.get_env("S3_ENDPOINT")
        cls.S3_BUCKET = cls.get_env("S3_BUCKET", "surveillance-models")
        cls.S3_ACCESS_KEY = cls.get_env("S3_ACCESS_KEY")
        cls.S3_SECRET_KEY = cls.get_env("S3_SECRET_KEY")
        
        # === KServe ===
        cls.KSERVE_ENDPOINT = cls.get_env("KSERVE_ENDPOINT", "http://kserve.model-serving.svc.cluster.local")
        cls.KSERVE_NAMESPACE = cls.get_env("KSERVE_NAMESPACE", "model-serving")
        
        # === LOGGING ===
        log_level = cls.get_env("LOG_LEVEL", "INFO")
        cls.LOG_LEVEL = getattr(logging, log_level.upper(), logging.INFO)
        
        # === PERFORMANCE ===
        cls.WINDOW_SIZE = int(cls.get_env("WINDOW_SIZE", "60"))
        cls.PREDICTION_HORIZON = int(cls.get_env("PREDICTION_HORIZON", "24"))
        cls.RETRAINING_INTERVAL = int(cls.get_env("RETRAINING_INTERVAL", "24"))
        cls.MIN_SAMPLES_FOR_TRAINING = int(cls.get_env("MIN_SAMPLES", "100"))
        
        # === MÉTRIQUES ===
        cls.METRICS = cls.get_env("METRICS", "cpu,memoire,disque_pct").split(",")
        cls.THRESHOLDS = {
            'cpu': float(cls.get_env("CPU_THRESHOLD", "85")),
            'memoire': float(cls.get_env("MEMORY_THRESHOLD", "90")),
            'disque_pct': float(cls.get_env("DISK_THRESHOLD", "90"))
        }
        
        # === CONFIDENCE ===
        # Seuil de confiance en dessous duquel une prévision n'est PAS
        # considérée comme fiable : elle n'est ni envoyée en alerte, ni
        # affichée comme un vrai risque (Vigilance/Critique) sur la page.
        # Objectif : ne montrer que des prévisions quasi sûres, pas du bruit.
        cls.CONFIDENCE_THRESHOLD = float(cls.get_env("CONFIDENCE_THRESHOLD", "0.6"))
        cls.ANOMALY_PROB_THRESHOLD = float(cls.get_env("ANOMALY_PROB_THRESHOLD", "0.6"))
        # Seuil (en %) en dessous duquel aucune prévision n'est créée dans
        # generer_previsions(). Configurable pour ajuster la sensibilité
        # sans avoir à modifier le code / rebuild.
        cls.PREVISION_MIN_PROBABILITE = float(cls.get_env("PREVISION_MIN_PROBABILITE", "30"))

        # === FENÊTRE DE MAINTENANCE PRÉVENTIVE ===
        # Créneau quotidien (heure locale, "HH:MM-HH:MM") où une
        # intervention a le moins d'impact (trafic faible). Surchargeable
        # par serveur via MAINTENANCE_WINDOW_<NOM_SERVEUR> (ex :
        # MAINTENANCE_WINDOW_PC_FARAH="01:00-04:00"), sinon la valeur par
        # défaut ci-dessous s'applique à tous les serveurs.
        cls.MAINTENANCE_WINDOW_DEFAULT = cls.get_env("MAINTENANCE_WINDOW_DEFAULT", "02:00-05:00")

        # === TICKETING ===
        # URL de webhook optionnelle (Jira/GLPI/ServiceNow/...) recevant un
        # POST JSON à chaque ticket créé depuis une prévision. Si absente,
        # on retombe sur une notification email aux responsables.
        cls.TICKET_WEBHOOK_URL = cls.get_env("TICKET_WEBHOOK_URL", "")

        # === CORRÉLATION ENTRE SERVEURS ===
        cls.CORRELATION_SEUIL = float(cls.get_env("CORRELATION_SEUIL", "0.75"))
        cls.CORRELATION_FENETRE_MINUTES = int(cls.get_env("CORRELATION_FENETRE_MINUTES", "60"))
        
        # === XGBoost ===
        cls.XGB_LEARNING_RATE = float(cls.get_env("XGB_LEARNING_RATE", "0.1"))
        cls.XGB_MAX_DEPTH = int(cls.get_env("XGB_MAX_DEPTH", "6"))
        cls.XGB_N_ESTIMATORS = int(cls.get_env("XGB_N_ESTIMATORS", "100"))
        
        # === LSTM ===
        cls.LSTM_HIDDEN_SIZE = int(cls.get_env("LSTM_HIDDEN_SIZE", "64"))
        cls.LSTM_NUM_LAYERS = int(cls.get_env("LSTM_NUM_LAYERS", "2"))
        cls.LSTM_EPOCHS = int(cls.get_env("LSTM_EPOCHS", "50"))
        cls.LSTM_DROPOUT = float(cls.get_env("LSTM_DROPOUT", "0.2"))
        
        # Journaliser la configuration
        cls._log_config()
        
        return cls
    
    @classmethod
    def _log_config(cls):
        """Log la configuration"""
        print("=" * 60)
        print("🔧 CONFIGURATION SURVEILLANCE")
        print("=" * 60)
        print(f"Mode: {cls.DEPLOYMENT_MODE}")
        print(f"OpenShift: {cls.OPENSHIFT_MODE}")
        print(f"MODEL_DIR: {cls.MODEL_DIR}")
        print(f"CACHE_DIR: {cls.CACHE_DIR}")
        print(f"DATA_DIR: {cls.DATA_DIR}")
        print(f"LOG_DIR: {cls.LOG_DIR}")
        print(f"Metrics: {cls.METRICS}")
        print(f"Thresholds: {cls.THRESHOLDS}")
        if cls.S3_ENDPOINT:
            print(f"S3: {cls.S3_ENDPOINT}")
        if cls.KSERVE_ENDPOINT:
            print(f"KServe: {cls.KSERVE_ENDPOINT}")
        print("=" * 60)

# ============================================================================
# LOGGING DURABLE
# ============================================================================

class ProductionLogger:
    """Logger configuré pour la production"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_logger()
        return cls._instance
    
    def _init_logger(self):
        """Initialise le logger"""
        self.logger = logging.getLogger('surveillance')
        self.logger.setLevel(Config.LOG_LEVEL)
        
        # Supprimer les handlers existants
        self.logger.handlers.clear()
        
        # Format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler console
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        
        # Handler fichier
        log_file = Config.LOG_DIR / 'surveillance.log'
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            print(f"📝 Logs dans: {log_file}")
        except Exception as e:
            print(f"⚠️ Impossible d'écrire les logs: {e}")
    
    def get(self):
        return self.logger

# ============================================================================
# STOCKAGE DURABLE
# ============================================================================

class DurableStorage:
    """Stockage avec fallback et gestion d'erreurs"""
    
    def __init__(self):
        self.base_dir = Config.MODEL_DIR
        self.logger = ProductionLogger().get()
        self._init_storage()
    
    def _init_storage(self):
        """Initialise le stockage"""
        # S3
        self.s3 = None
        if Config.OPENSHIFT_MODE and Config.S3_ENDPOINT and S3_AVAILABLE:
            try:
                self.s3 = boto3.client(
                    's3',
                    endpoint_url=Config.S3_ENDPOINT,
                    aws_access_key_id=Config.S3_ACCESS_KEY,
                    aws_secret_access_key=Config.S3_SECRET_KEY
                )
                self.logger.info("✅ S3 initialisé")
            except Exception as e:
                self.logger.warning(f"⚠️ S3 indisponible: {e}")
        
        # Local
        self.local_dir = Config.MODEL_DIR
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"📁 Stockage local: {self.local_dir}")
        
        # Cache
        self.cache = {}
    
    @staticmethod
    def _json_default(obj):
        """Filet de sécurité pour json.dump : convertit les types numpy
        (float32/float64/int64/ndarray...) en types Python natifs, au cas
        où une future métrique/feature_importance ne serait pas castée en
        amont. Évite qu'un type non prévu ne corrompe metadata.json."""
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        raise TypeError(f"Objet de type {type(obj)} non sérialisable en JSON")

    def _ecrire_atomique(self, path: Path, data: Any, format: str):
        """Écrit dans un fichier temporaire puis renomme (os.replace, atomique
        sur un même filesystem). Si la sérialisation échoue en cours de
        route, le fichier temporaire est jeté et le fichier final (path)
        n'est jamais touché — donc jamais tronqué/corrompu."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            if format == 'pkl':
                with open(tmp_path, 'wb') as f:
                    pickle.dump(data, f)
            elif format == 'json':
                with open(tmp_path, 'w') as f:
                    json.dump(data, f, default=self._json_default)
            else:
                raise ValueError(f"Format inconnu: {format}")
            os.replace(tmp_path, path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
    
    def save(self, data: Any, name: str, format: str = 'pkl') -> Dict[str, str]:
        """Sauvegarde avec fallback. Écriture atomique (fichier temporaire
        + renommage) : si la sérialisation échoue en cours de route (ex:
        type non JSON-serializable), le fichier final n'est jamais touché
        et reste dans son dernier état valide au lieu d'être tronqué."""
        results = {'local': str(self.local_dir / f"{name}.{format}")}
        
        # Sauvegarde locale
        local_path = self.local_dir / f"{name}.{format}"
        try:
            self._ecrire_atomique(local_path, data, format)
            self.logger.info(f"✅ Sauvegarde locale: {local_path}")
        except Exception as e:
            self.logger.error(f"❌ Erreur sauvegarde locale: {e}")
            # Fallback /tmp
            fallback_path = Path('/tmp') / f"{name}.{format}"
            try:
                self._ecrire_atomique(fallback_path, data, format)
                results['fallback'] = str(fallback_path)
                self.logger.info(f"✅ Sauvegarde fallback: {fallback_path}")
            except Exception as e2:
                self.logger.error(f"❌ Erreur sauvegarde fallback: {e2}")
        
        # Sauvegarde S3
        if self.s3:
            try:
                key = f"models/{name}.{format}"
                self.s3.put_object(
                    Bucket=Config.S3_BUCKET,
                    Key=key,
                    Body=pickle.dumps(data),
                    Metadata={
                        'created_at': datetime.now().isoformat(),
                        'name': name,
                        'format': format
                    }
                )
                results['s3'] = f"s3://{Config.S3_BUCKET}/{key}"
                self.logger.info(f"✅ Sauvegarde S3: {results['s3']}")
            except Exception as e:
                self.logger.warning(f"⚠️ Sauvegarde S3 échouée: {e}")
        
        return results
    
    def load(self, name: str, format: str = 'pkl') -> Optional[Any]:
        """Charge avec fallback"""
        # Essayer S3 d'abord
        if self.s3:
            try:
                key = f"models/{name}.{format}"
                response = self.s3.get_object(Bucket=Config.S3_BUCKET, Key=key)
                raw = response['Body'].read()
                data = json.loads(raw) if format == 'json' else pickle.loads(raw)
                self.logger.info(f"✅ Chargé depuis S3: {name}")
                return data
            except Exception as e:
                self.logger.debug(f"S3 non disponible: {e}")
        
        # Essayer local
        local_path = self.local_dir / f"{name}.{format}"
        if local_path.exists():
            try:
                if format == 'json':
                    with open(local_path, 'r') as f:
                        data = json.load(f)
                else:
                    with open(local_path, 'rb') as f:
                        data = pickle.load(f)
                self.logger.info(f"✅ Chargé depuis local: {local_path}")
                return data
            except Exception as e:
                self.logger.error(f"❌ Erreur chargement local: {e}")
        
        # Essayer fallback /tmp
        fallback_path = Path('/tmp') / f"{name}.{format}"
        if fallback_path.exists():
            try:
                if format == 'json':
                    with open(fallback_path, 'r') as f:
                        data = json.load(f)
                else:
                    with open(fallback_path, 'rb') as f:
                        data = pickle.load(f)
                self.logger.info(f"✅ Chargé depuis fallback: {fallback_path}")
                return data
            except Exception as e:
                self.logger.error(f"❌ Erreur chargement fallback: {e}")
        
        return None
    
    def exists(self, name: str, format: str = 'pkl') -> bool:
        """Vérifie si un modèle existe"""
        # Vérifier local
        if (self.local_dir / f"{name}.{format}").exists():
            return True
        # Vérifier fallback
        if (Path('/tmp') / f"{name}.{format}").exists():
            return True
        # Vérifier S3
        if self.s3:
            try:
                key = f"models/{name}.{format}"
                self.s3.head_object(Bucket=Config.S3_BUCKET, Key=key)
                return True
            except:
                pass
        return False
    
    def list_models(self) -> List[str]:
        """Liste les modèles disponibles"""
        models = []
        
        # Local
        for f in self.local_dir.glob("*.pkl"):
            models.append(f.stem)
        
        # S3
        if self.s3:
            try:
                response = self.s3.list_objects_v2(
                    Bucket=Config.S3_BUCKET,
                    Prefix="models/"
                )
                for obj in response.get('Contents', []):
                    name = obj['Key'].split('/')[-1].replace('.pkl', '')
                    if name and name not in models:
                        models.append(name)
            except:
                pass
        
        return list(set(models))

# ============================================================================
# MODÈLES ML
# ============================================================================

class LSTMPredictor(nn.Module):
    """LSTM pour la prédiction de séries temporelles"""
    
    def __init__(self, input_size: int, hidden_size: int = 64, 
                 num_layers: int = 2, output_size: int = 1,
                 dropout: float = 0.2):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size, 
            hidden_size, 
            num_layers, 
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, output_size)
        
    def forward(self, x):
        lstm_out, (h_n, c_n) = self.lstm(x)
        last_output = lstm_out[:, -1, :]
        last_output = self.dropout(last_output)
        output = self.fc(last_output)
        return output


class ProphetWrapper:
    """Wrapper pour le modèle Prophet"""
    
    def __init__(self):
        self.model = None
        self.metric = None
        self.last_training = None
        
    def train(self, df: pd.DataFrame, metric: str):
        """Entraîne le modèle Prophet"""
        if not PROPHET_AVAILABLE:
            return
        
        self.metric = metric
        
        prophet_df = pd.DataFrame({
            'ds': df['horodatage'],
            'y': df[metric]
        })
        
        self.model = Prophet(
            yearly_seasonality=True,
            weekly_seasonality=True,
            daily_seasonality=True,
            changepoint_prior_scale=0.05,
            seasonality_prior_scale=10.0
        )
        
        if 'hour' in df.columns:
            prophet_df['hour'] = df['hour']
            self.model.add_regressor('hour')
        if 'day_of_week' in df.columns:
            prophet_df['day_of_week'] = df['day_of_week']
            self.model.add_regressor('day_of_week')
        
        self.model.fit(prophet_df)
        self.last_training = datetime.now()
        
    def predict(self, periods: int = 12, freq: str = 'H') -> pd.DataFrame:
        """Fait une prédiction"""
        if self.model is None or not PROPHET_AVAILABLE:
            return pd.DataFrame()
        
        future = self.model.make_future_dataframe(periods=periods, freq=freq)
        forecast = self.model.predict(future)
        return forecast

    def save(self, path):
        """Sauvegarde le wrapper (modèle Prophet inclus). Cette méthode
        n'existait pas alors qu'elle était déjà appelée après chaque
        entraînement, ce qui faisait échouer silencieusement la
        persistance de Prophet à chaque cycle."""
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'metric': self.metric,
                'last_training': self.last_training
            }, f)

    def load(self, path):
        """Recharge un wrapper précédemment sauvegardé par save()."""
        with open(path, 'rb') as f:
            state = pickle.load(f)
        self.model = state.get('model')
        self.metric = state.get('metric')
        self.last_training = state.get('last_training')


class SimpleProphetAlternative:
    """Alternative simple à Prophet"""
    
    @staticmethod
    def predict_trend(data: List[float], periods: int = 12) -> List[float]:
        """Prédiction de tendance simple"""
        if len(data) < 2:
            return [data[-1] if data else 0] * periods
        
        x = np.arange(len(data))
        slope, intercept = np.polyfit(x, data, 1)
        
        predictions = []
        for i in range(periods):
            base = slope * (len(data) + i) + intercept
            seasonal = np.sin(2 * np.pi * i / 24) * 5
            predictions.append(max(0, base + seasonal))
        
        return predictions

# ============================================================================
# SYSTÈME DE PROVISIONNEMENT ML
# ============================================================================

class ProvisionnementML:
    """Système de provisionnement utilisant le Machine Learning"""
    
    def __init__(self):
        # Configuration
        self.config = Config
        
        # Stockage
        self.storage = DurableStorage()
        self.logger = ProductionLogger().get()
        
        # Modèles
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        self.xgb_classifier = XGBClassifier(
            n_estimators=self.config.XGB_N_ESTIMATORS,
            max_depth=self.config.XGB_MAX_DEPTH,
            learning_rate=self.config.XGB_LEARNING_RATE,
            random_state=42,
            eval_metric='logloss',
            early_stopping_rounds=20
        )
        self.xgb_regressor = XGBRegressor(
            n_estimators=self.config.XGB_N_ESTIMATORS,
            max_depth=self.config.XGB_MAX_DEPTH,
            learning_rate=self.config.XGB_LEARNING_RATE,
            random_state=42,
            early_stopping_rounds=20
        )
        self.lstm_model = None
        self.prophet_models = {}
        
        # État
        self.last_training = None
        self.training_in_progress = False
        self.feature_importance = {}
        self.performance_metrics = {}
        
        # Cache
        self.prediction_cache = {}
        self.model_cache = {}
        
        # Thread lock
        self.training_lock = threading.Lock()
        
        # Initialisation
        self._load_or_init_models()
    
    def _load_or_init_models(self):
        """Charge les modèles existants ou initialise de nouveaux"""
        self.logger.info("Chargement des modèles...")
        
        # Charger les modèles
        self.scaler = self.storage.load('scaler') or StandardScaler()
        self.xgb_classifier = self.storage.load('xgb_classifier') or XGBClassifier()
        self.xgb_regressor = self.storage.load('xgb_regressor') or XGBRegressor()
        
        # Métadonnées (chargées avant le LSTM : on a besoin de
        # lstm_input_size pour reconstruire la bonne architecture avant
        # d'appliquer load_state_dict, sinon mismatch garanti si le nombre
        # de features a été autre chose que 1 à l'entraînement)
        metadata = self.storage.load('metadata', 'json')
        lstm_input_size = None
        if metadata:
            self.last_training = datetime.fromisoformat(metadata.get('last_training', '')) if metadata.get('last_training') else None
            self.performance_metrics = metadata.get('performance_metrics', {})
            self.feature_importance = metadata.get('feature_importance', {})
            lstm_input_size = metadata.get('lstm_input_size')
            self.logger.info("✅ Métadonnées chargées")
        
        # Charger LSTM si disponible
        if self.storage.exists('lstm_model'):
            if lstm_input_size:
                try:
                    # Reconstruire l'architecture LSTM avec la même taille
                    # d'entrée qu'à l'entraînement (sinon load_state_dict
                    # échoue avec un size mismatch)
                    self.lstm_model = LSTMPredictor(input_size=lstm_input_size)
                    model_data = self.storage.load('lstm_model')
                    if model_data:
                        self.lstm_model.load_state_dict(model_data)
                        self.logger.info("✅ LSTM chargé")
                except Exception as e:
                    self.logger.warning(f"⚠️ Erreur chargement LSTM: {e}")
                    self.lstm_model = None
            else:
                self.logger.warning("⚠️ LSTM sauvegardé mais lstm_input_size absent des métadonnées, rechargement ignoré (sera réentraîné)")
        
        # Charger Prophet
        if PROPHET_AVAILABLE:
            for metric in self.config.METRICS:
                if self.storage.exists(f'prophet_{metric}'):
                    try:
                        prophet_model = ProphetWrapper()
                        prophet_model.load(self.storage.local_dir / f'prophet_{metric}.pkl')
                        self.prophet_models[metric] = prophet_model
                        self.logger.info(f"✅ Prophet {metric} chargé")
                    except Exception as e:
                        self.logger.warning(f"⚠️ Erreur chargement Prophet {metric}: {e}")
    
    def _prepare_features(self, measures: List[Dict]) -> pd.DataFrame:
        """Prépare les features pour le ML"""
        if not measures:
            return pd.DataFrame()
        
        df = pd.DataFrame(measures)
        required_cols = ['horodatage'] + self.config.METRICS
        if not all(col in df.columns for col in required_cols):
            missing = [col for col in required_cols if col not in df.columns]
            self.logger.warning(f"Colonnes manquantes: {missing}")
            return pd.DataFrame()
        
        df['horodatage'] = pd.to_datetime(df['horodatage'])
        df = df.sort_values('horodatage')
        
        # Features temporelles
        df['hour'] = df['horodatage'].dt.hour
        df['day_of_week'] = df['horodatage'].dt.dayofweek
        df['minute'] = df['horodatage'].dt.minute
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 18)).astype(int)
        
        # Features statistiques glissantes
        for col in self.config.METRICS:
            for window in [5, 15, 30, 60]:
                df[f'{col}_rolling_mean_{window}'] = df[col].rolling(window).mean()
                df[f'{col}_rolling_std_{window}'] = df[col].rolling(window).std()
                df[f'{col}_rolling_min_{window}'] = df[col].rolling(window).min()
                df[f'{col}_rolling_max_{window}'] = df[col].rolling(window).max()
        
        # Features de tendance
        for col in self.config.METRICS:
            df[f'{col}_diff_1'] = df[col].diff()
            df[f'{col}_diff_5'] = df[col].diff(5)
            df[f'{col}_diff_15'] = df[col].diff(15)
            df[f'{col}_pct_change'] = df[col].pct_change()
            
            for window in [5, 15, 30]:
                df[f'{col}_growth_rate_{window}'] = (df[col] - df[col].shift(window)) / (df[col].shift(window) + 0.001)
        
        # Features de relation
        df['cpu_memory_ratio'] = df['cpu'] / (df['memoire'] + 1)
        df['cpu_disk_ratio'] = df['cpu'] / (df['disque_pct'] + 1)
        df['memory_disk_ratio'] = df['memoire'] / (df['disque_pct'] + 1)
        
        # Features de saisonnalité
        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        return df
    
    def _train_xgboost(self, X: np.ndarray, y_class: np.ndarray, y_reg: np.ndarray):
        """Entraîne les modèles XGBoost"""
        try:
            X_train, X_val, y_class_train, y_class_val, y_reg_train, y_reg_val = train_test_split(
                X, y_class, y_reg, test_size=0.2, random_state=42
            )
            
            self.xgb_classifier.fit(
                X_train, y_class_train,
                eval_set=[(X_val, y_class_val)],
                verbose=False
            )
            
            self.xgb_regressor.fit(
                X_train, y_reg_train,
                eval_set=[(X_val, y_reg_val)],
                verbose=False
            )
            
            # Feature importance
            feature_names = [
                'cpu', 'memoire', 'disque_pct',
                'hour', 'day_of_week', 'minute',
                'is_weekend', 'is_business_hours',
                'cpu_rolling_mean_5', 'cpu_rolling_std_5',
                'memoire_rolling_mean_5', 'memoire_rolling_std_5',
                'disque_pct_rolling_mean_5', 'disque_pct_rolling_std_5',
                'cpu_rolling_mean_15', 'memoire_rolling_mean_15',
                'disque_pct_rolling_mean_15',
                'cpu_diff_1', 'memoire_diff_1', 'disque_pct_diff_1',
                'cpu_pct_change', 'memoire_pct_change', 'disque_pct_pct_change',
                'cpu_memory_ratio', 'cpu_disk_ratio', 'memory_disk_ratio',
                'hour_sin', 'hour_cos', 'day_sin', 'day_cos'
            ]
            
            # float(...) : les valeurs de feature_importances_ sont en
            # numpy.float32, non sérialisable en JSON nativement — sans ce
            # cast, json.dump plante en cours d'écriture et laisse un
            # metadata.json tronqué/corrompu sur le disque.
            self.feature_importance = {
                name: float(importance) for name, importance in zip(
                    feature_names[:len(self.xgb_classifier.feature_importances_)],
                    self.xgb_classifier.feature_importances_
                )
            }
            
            # Métriques de performance
            y_class_pred = self.xgb_classifier.predict(X_val)
            y_reg_pred = self.xgb_regressor.predict(X_val)
            
            self.performance_metrics.update({
                'classification_accuracy': float(accuracy_score(y_class_val, y_class_pred)),
                'regression_rmse': float(np.sqrt(mean_squared_error(y_reg_val, y_reg_pred))),
                'regression_r2': float(r2_score(y_reg_val, y_reg_pred))
            })
            
            # Sauvegarder
            self._save_models()
                
        except Exception as e:
            self.logger.error(f"Erreur entraînement XGBoost: {e}")
            raise
    
    def _train_lstm(self, X_train: np.ndarray, y_train: np.ndarray,
                   X_val: np.ndarray, y_val: np.ndarray):
        """Entraîne le modèle LSTM"""
        try:
            X_scaled = self.scaler.fit_transform(X_train)
            X_val_scaled = self.scaler.transform(X_val)
            
            # Créer les séquences
            X_seq, y_seq = [], []
            for i in range(len(X_scaled) - self.config.WINDOW_SIZE):
                X_seq.append(X_scaled[i:i + self.config.WINDOW_SIZE])
                y_seq.append(y_train[i + self.config.WINDOW_SIZE])
            
            if len(X_seq) == 0:
                self.logger.warning("Pas assez de données pour LSTM")
                return
            
            X_seq = np.array(X_seq)
            y_seq = np.array(y_seq)
            
            X_val_seq, y_val_seq = [], []
            for i in range(len(X_val_scaled) - self.config.WINDOW_SIZE):
                X_val_seq.append(X_val_scaled[i:i + self.config.WINDOW_SIZE])
                y_val_seq.append(y_val[i + self.config.WINDOW_SIZE])
            
            if len(X_val_seq) == 0:
                X_val_seq, y_val_seq = X_seq, y_seq
            
            X_val_seq = np.array(X_val_seq)
            y_val_seq = np.array(y_val_seq)
            
            dataset = TensorDataset(
                torch.FloatTensor(X_seq),
                torch.FloatTensor(y_seq).reshape(-1, 1)
            )
            dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
            
            input_size = X_seq.shape[2]
            self.lstm_model = LSTMPredictor(
                input_size=input_size,
                hidden_size=self.config.LSTM_HIDDEN_SIZE,
                num_layers=self.config.LSTM_NUM_LAYERS,
                dropout=self.config.LSTM_DROPOUT
            )
            
            optimizer = optim.Adam(self.lstm_model.parameters(), lr=0.001)
            criterion = nn.MSELoss()
            
            best_val_loss = float('inf')
            patience = 10
            patience_counter = 0
            
            self.lstm_model.train()
            for epoch in range(self.config.LSTM_EPOCHS):
                epoch_loss = 0
                for X_batch, y_batch in dataloader:
                    optimizer.zero_grad()
                    output = self.lstm_model(X_batch)
                    loss = criterion(output, y_batch)
                    loss.backward()
                    optimizer.step()
                    epoch_loss += loss.item()
                
                self.lstm_model.eval()
                with torch.no_grad():
                    val_output = self.lstm_model(torch.FloatTensor(X_val_seq))
                    val_loss = criterion(val_output, torch.FloatTensor(y_val_seq).reshape(-1, 1))
                
                self.lstm_model.train()
                
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                    # Sauvegarder
                    self.storage.save(self.lstm_model.state_dict(), 'lstm_model')
                else:
                    patience_counter += 1
                    if patience_counter >= patience:
                        break
            
            # Charger le meilleur modèle
            model_data = self.storage.load('lstm_model')
            if model_data:
                self.lstm_model.load_state_dict(model_data)
                self.logger.info("✅ LSTM entraîné et sauvegardé")
                
        except Exception as e:
            self.logger.error(f"Erreur entraînement LSTM: {e}")
    
    def _train_prophet(self, df: pd.DataFrame):
        """Entraîne les modèles Prophet"""
        if not PROPHET_AVAILABLE:
            self.logger.warning("Prophet non disponible")
            return
        
        for metric in self.config.METRICS:
            try:
                prophet_model = ProphetWrapper()
                prophet_model.train(df, metric)
                self.prophet_models[metric] = prophet_model
                prophet_model.save(self.storage.local_dir / f'prophet_{metric}.pkl')
                self.logger.info(f"✅ Prophet entraîné pour {metric}")
            except Exception as e:
                self.logger.error(f"Erreur entraînement Prophet {metric}: {e}")
    
    def _save_models(self):
        """Sauvegarde tous les modèles"""
        try:
            # Sauvegarder les modèles
            self.storage.save(self.scaler, 'scaler')
            self.storage.save(self.xgb_classifier, 'xgb_classifier')
            self.storage.save(self.xgb_regressor, 'xgb_regressor')
            
            # Métadonnées
            metadata = {
                'last_training': self.last_training.isoformat() if self.last_training else None,
                'performance_metrics': self.performance_metrics,
                'feature_importance': self.feature_importance,
                'lstm_input_size': self.lstm_model.input_size if self.lstm_model else None
            }
            self.storage.save(metadata, 'metadata', 'json')
            
            self.logger.info("✅ Modèles sauvegardés")
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde modèles: {e}")
    
    def train_models(self, server: str, historical_data: List[Dict]) -> Dict:
        """Entraîne tous les modèles ML"""
        with self.training_lock:
            if self.training_in_progress:
                return {'status': 'training_in_progress'}
            
            self.training_in_progress = True
            
            try:
                self.logger.info(f"📊 Début entraînement ML pour {server}")
                
                df = self._prepare_features(historical_data)
                if df.empty:
                    return {'status': 'error', 'message': 'Données insuffisantes'}
                
                if len(df) < self.config.MIN_SAMPLES_FOR_TRAINING:
                    return {
                        'status': 'error',
                        'message': f'Pas assez de données: {len(df)}/{self.config.MIN_SAMPLES_FOR_TRAINING}'
                    }
                
                # Préparer les labels
                X = df.drop(['horodatage'], axis=1).values
                y_class = np.zeros(len(df))
                y_reg = np.zeros(len(df))
                
                lookahead = self.config.PREDICTION_HORIZON // 6
                for i in range(len(df) - lookahead):
                    for j in range(lookahead):
                        for metric in self.config.METRICS:
                            if i + j < len(df):
                                value = df.iloc[i + j][metric]
                                threshold = self.config.THRESHOLDS[metric]
                                if value >= threshold:
                                    y_class[i] = 1
                                    y_reg[i] = max(1, j + 1)
                                    break
                        if y_class[i] == 1:
                            break
                
                # XGBoost
                self._train_xgboost(X, y_class, y_reg)
                
                # LSTM
                if len(X) > self.config.WINDOW_SIZE * 2:
                    X_train, X_val, y_train, y_val = train_test_split(
                        X, y_class, test_size=0.2, random_state=42
                    )
                    self._train_lstm(X_train, y_train, X_val, y_val)
                
                # Prophet
                self._train_prophet(df)
                
                self.last_training = datetime.now()
                self._save_models()
                
                self.logger.info(f"✅ Entraînement terminé pour {server}")
                
                return {
                    'status': 'success',
                    'performance': self.performance_metrics,
                    'feature_importance': dict(list(self.feature_importance.items())[:10]),
                    'last_training': self.last_training.isoformat()
                }
                
            except Exception as e:
                self.logger.error(f"❌ Erreur entraînement: {e}")
                return {'status': 'error', 'message': str(e)}
            finally:
                self.training_in_progress = False
    
    def predict_anomaly(self, server: str, recent_measures: List[Dict]) -> Dict:
        """Prédit les anomalies futures"""
        try:
            if self.last_training is None:
                self.logger.warning("Modèles non entraînés, chargement...")
                self._load_or_init_models()

            if self.last_training is None:
                # Aucun entraînement n'a jamais eu lieu (ni en mémoire, ni sur
                # le stockage durable) : sans ce bloc, on ne rentre jamais dans
                # le "if self.last_training:" ci-dessous et l'entraînement
                # n'est donc JAMAIS déclenché automatiquement.
                if not self.training_in_progress:
                    historical_data = historique.recuperer_mesures(server, heures=168)
                    if len(historical_data) >= self.config.MIN_SAMPLES_FOR_TRAINING:
                        self.logger.info(f"🚀 Entraînement initial déclenché pour {server}")
                        threading.Thread(
                            target=self.train_models,
                            args=(server, historical_data),
                            daemon=True
                        ).start()
                        return {'error': f"Entraînement initial en cours pour {server}, réessayez dans quelques minutes"}
                    else:
                        return {'error': f"Modèles non entraînés et données insuffisantes pour {server} ({len(historical_data)}/{self.config.MIN_SAMPLES_FOR_TRAINING})"}
                else:
                    return {'error': f"Entraînement déjà en cours pour {server}"}

            if self.last_training:
                hours_since_training = (datetime.now() - self.last_training).total_seconds() / 3600
                if hours_since_training > self.config.RETRAINING_INTERVAL:
                    self.logger.info(f"Réentraînement automatique pour {server}")
                    threading.Thread(
                        target=self.train_models,
                        args=(server, historique.recuperer_mesures(server, heures=168)),
                        daemon=True
                    ).start()
            
            df = self._prepare_features(recent_measures)
            if df.empty:
                return {'error': 'Données insuffisantes'}
            
            # Normaliser
            X = self.scaler.transform(df.drop(['horodatage'], axis=1).values)
            
            # XGBoost
            anomaly_prob = self.xgb_classifier.predict_proba(X)[-1][1]
            time_to_anomaly = self.xgb_regressor.predict([X[-1]])[0]
            
            # LSTM
            lstm_prediction = None
            if self.lstm_model and len(X) >= self.config.WINDOW_SIZE:
                sequence = X[-self.config.WINDOW_SIZE:]
                sequence = sequence.reshape(1, self.config.WINDOW_SIZE, -1)
                tensor_sequence = torch.FloatTensor(sequence)
                
                self.lstm_model.eval()
                with torch.no_grad():
                    lstm_prediction = self.lstm_model(tensor_sequence).numpy()[0][0]
            
            # Prophet
            prophet_predictions = {}
            for metric, prophet_model in self.prophet_models.items():
                try:
                    if PROPHET_AVAILABLE and prophet_model.model:
                        forecast = prophet_model.predict(periods=12, freq='H')
                        if not forecast.empty:
                            prophet_predictions[metric] = float(forecast['yhat'].iloc[-1])
                    else:
                        values = df[metric].values[-30:] if len(df) >= 30 else df[metric].values
                        predictions = SimpleProphetAlternative.predict_trend(
                            list(values), periods=12
                        )
                        prophet_predictions[metric] = predictions[-1]
                except Exception as e:
                    self.logger.debug(f"Erreur prédiction Prophet {metric}: {e}")
                    prophet_predictions[metric] = df[metric].iloc[-1]
            
            # Consensus
            consensus = self._ensemble_prediction(
                xgb_prob=anomaly_prob,
                lstm_pred=lstm_prediction,
                prophet_preds=prophet_predictions,
                current_values=df[self.config.METRICS].iloc[-1].to_dict()
            )
            
            result = {
                'probabilite_anomalie': round(consensus['probability'] * 100, 2),
                'niveau_risque': consensus['risk_level'],
                'confiance': round(consensus['confidence'], 2),
                'temps_estime_avant_anomalie': round(time_to_anomaly, 1),
                'metrics_predites': prophet_predictions,
                'valeurs_actuelles': df[self.config.METRICS].iloc[-1].to_dict(),
                'feature_importance': dict(list(self.feature_importance.items())[:10]),
                'ensemble_details': {
                    'xgb_probability': round(anomaly_prob, 3),
                    'lstm_prediction': round(lstm_prediction, 3) if lstm_prediction else None,
                    'prophet_predictions': {k: round(v, 2) for k, v in prophet_predictions.items()}
                },
                'performance_metrics': self.performance_metrics
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Erreur prédiction: {e}")
            return {'error': str(e)}
    
    def _ensemble_prediction(self, xgb_prob: float, lstm_pred: Optional[float],
                           prophet_preds: Dict[str, float],
                           current_values: Dict[str, float]) -> Dict:
        """Fait un consensus des prédictions"""
        weights = {'xgb': 0.4, 'lstm': 0.3, 'prophet': 0.3}
        
        # XGBoost
        weighted_prob = weights['xgb'] * xgb_prob
        
        # LSTM
        lstm_risk = 0.5
        if lstm_pred is not None:
            lstm_risk = min(1.0, lstm_pred / max(self.config.THRESHOLDS.values()))
        weighted_prob += weights['lstm'] * lstm_risk
        
        # Prophet
        prophet_risk = self._prophet_risk_score(prophet_preds, current_values)
        weighted_prob += weights['prophet'] * prophet_risk
        
        # Contexte actuel
        current_risk = self._current_risk_score(current_values)
        weighted_prob = weighted_prob * 0.7 + current_risk * 0.3
        
        risk_level = self._determine_risk_level(weighted_prob)
        confidence = self._calculate_confidence([xgb_prob, lstm_risk, prophet_risk])
        
        return {
            'probability': min(1.0, weighted_prob),
            'risk_level': risk_level,
            'confidence': confidence,
            'current_risk': current_risk
        }
    
    def _prophet_risk_score(self, prophet_preds: Dict[str, float],
                           current_values: Dict[str, float]) -> float:
        """Calcule le score de risque Prophet"""
        if not prophet_preds:
            return 0.0
        
        risk_score = 0.0
        n_metrics = len(prophet_preds)
        
        for metric, pred_value in prophet_preds.items():
            threshold = self.config.THRESHOLDS.get(metric, 100)
            current = current_values.get(metric, 0)
            
            if current >= threshold * 0.8:
                risk_score += 0.8
            if pred_value >= threshold:
                risk_score += min(1.0, (pred_value - threshold) / threshold + 0.5)
            if pred_value > current * 1.2:
                risk_score += 0.3
        
        return min(1.0, risk_score / n_metrics) if n_metrics > 0 else 0.0
    
    def _current_risk_score(self, current_values: Dict[str, float]) -> float:
        """Évalue le risque actuel"""
        risk_score = 0.0
        n_metrics = len(current_values)
        
        for metric, value in current_values.items():
            threshold = self.config.THRESHOLDS.get(metric, 100)
            ratio = value / threshold
            if ratio >= 0.9:
                risk_score += 0.9
            elif ratio >= 0.8:
                risk_score += 0.7
            elif ratio >= 0.7:
                risk_score += 0.5
            elif ratio >= 0.6:
                risk_score += 0.3
        
        return min(1.0, risk_score / n_metrics) if n_metrics > 0 else 0.0
    
    def _determine_risk_level(self, probability: float) -> str:
        """Détermine le niveau de risque"""
        if probability >= 0.8:
            return 'CRITIQUE'
        elif probability >= 0.6:
            return 'ELEVE'
        elif probability >= 0.4:
            return 'MODERE'
        else:
            return 'FAIBLE'
    
    def _calculate_confidence(self, predictions: List[float]) -> float:
        """Calcule la confiance"""
        valid_preds = [p for p in predictions if p is not None]
        if len(valid_preds) < 2:
            return 0.5
        
        std_dev = np.std(valid_preds)
        mean_pred = np.mean(valid_preds)
        confidence = max(0.0, 1.0 - std_dev / max(mean_pred, 0.1))
        confidence *= (len(valid_preds) / len(predictions))
        
        return min(1.0, confidence)
    
    def health_check(self) -> Dict:
        """Vérifie l'état du système"""
        return {
            'status': 'healthy',
            'mode': self.config.DEPLOYMENT_MODE,
            'openshift': self.config.OPENSHIFT_MODE,
            'storage': {
                'local': str(self.config.MODEL_DIR),
                's3': self.config.S3_ENDPOINT is not None
            },
            'models': {
                'scaler': self.scaler is not None,
                'xgb_classifier': self.xgb_classifier is not None,
                'xgb_regressor': self.xgb_regressor is not None,
                'lstm': self.lstm_model is not None,
                'prophet': len(self.prophet_models) > 0
            },
            'last_training': self.last_training.isoformat() if self.last_training else None,
            'performance': self.performance_metrics
        }

# ============================================================================
# INTÉGRATION AVEC LE SYSTÈME EXISTANT
# ============================================================================

# Instance globale
_integrator = None
_storage = None

def get_integrator():
    """Récupère l'instance globale"""
    global _integrator
    if _integrator is None:
        _integrator = ProvisionnementML()
    return _integrator

def get_storage():
    """Récupère l'instance de stockage"""
    global _storage
    if _storage is None:
        _storage = DurableStorage()
    return _storage

def _num(value, default: float = 0.0) -> float:
    """Convertit une valeur en float de façon sûre (certaines valeurs
    peuvent arriver en str depuis le JSON/la base, ce qui casse les
    filtres Jinja `round()` du template)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# Traduction des noms techniques de features (utilisés en interne par le
# modèle) vers un libellé compréhensible par un employé/admin non technique.
FEATURE_LABELS = {
    'cpu': 'Utilisation CPU',
    'memoire': 'Utilisation mémoire',
    'disque_pct': 'Utilisation disque',
    'cpu_rolling_mean_5': 'Tendance CPU (moy. récente)',
    'memoire_rolling_mean_5': 'Tendance mémoire (moy. récente)',
    'disque_pct_rolling_mean_5': 'Tendance disque (moy. récente)',
    'is_weekend': 'Week-end',
    'is_business_hours': 'Heures ouvrées',
    'hour_of_day': "Heure de la journée",
    'nb_processus': 'Nombre de processus',
    'paquets_perdus': 'Paquets réseau perdus',
    'batterie': 'Niveau batterie',
}


def _label_feature(nom: str) -> str:
    return FEATURE_LABELS.get(nom, nom.replace('_', ' ').capitalize())


NIVEAU_LABELS = {
    'critique': ('🔴', 'Critique'),
    'warning': ('🟠', 'Vigilance'),
    'surveillance': ('🔵', 'À surveiller'),
    'incertain': ('🔵', 'Signal à confirmer'),
    'sain': ('🟢', 'Sain'),
    'collecte': ('⚪', 'Collecte en cours'),
}


def generer_previsions(serveur: str) -> List[Dict]:
    """Fonction de compatibilité"""
    integrator = get_integrator()
    recent_measures = historique.recuperer_mesures(serveur, heures=2)
    
    if len(recent_measures) < 10:
        return []
    
    prediction = integrator.predict_anomaly(serveur, recent_measures)
    
    if 'error' in prediction:
        # ML complet indisponible (historique < MIN_SAMPLES_FOR_TRAINING,
        # entraînement initial en cours, etc.) : on retombe sur une
        # estimation par régression linéaire simple plutôt que de ne
        # rien renvoyer. Moins précis que XGBoost+LSTM+Prophet, mais
        # utilisable dès 10 mesures récentes au lieu de 100.
        # On ne garde que les prévisions jugées assez fiables pour être
        # envoyées comme alerte réelle (pas de niveau 'incertain' ici).
        return [p for p in generer_previsions_simple(serveur) if p['niveau_cible'] != 'incertain']
    
    if prediction.get('probabilite_anomalie', 0) < Config.PREVISION_MIN_PROBABILITE:
        return []

    # Garde-fou fiabilité : une probabilité d'anomalie élevée ne veut rien
    # dire si le modèle n'est pas confiant dans son estimation. On ne
    # remonte une vraie alerte (email/WhatsApp) que si les deux sont réunis :
    # risque suffisant ET confiance suffisante. Sinon on préfère ne rien dire
    # plutôt que d'alerter sur du bruit.
    if _num(prediction.get('confiance', 0)) < Config.CONFIDENCE_THRESHOLD:
        return []
    
    valeurs_actuelles = prediction['valeurs_actuelles']
    metrics_predites = {
        k: _num(v) for k, v in prediction.get('metrics_predites', {}).items()
    }
    feature_importance = {
        k: _num(v) for k, v in prediction.get('feature_importance', {}).items()
    }

    prevision = {
        'serveur': serveur,
        'type_anomalie': 'multi',
        'niveau_cible': 'critique' if prediction['niveau_risque'] == 'CRITIQUE' else 'warning',
        'valeur_actuelle': _num(max(valeurs_actuelles.values(), key=_num)),
        'confiance': _num(prediction['confiance']),
        'probabilite': _num(prediction['probabilite_anomalie']),
        'temps_estime': _num(prediction['temps_estime_avant_anomalie']),
        'feature_importance': feature_importance,
        'ml_confidence': 'haute' if _num(prediction['confiance']) > 0.7 else 'moyenne',
        'metrics': valeurs_actuelles,
        'metrics_predites': metrics_predites,
        'ensemble_details': prediction.get('ensemble_details', {}),
        'performance_metrics': prediction.get('performance_metrics', {})
    }
    
    return [prevision]


def _metrique_critique(valeurs: dict) -> str:
    """La métrique (cpu/mémoire/disque...) la plus élevée actuellement —
    c'est celle qui pose le plus de risque, donc celle qu'on doit mettre
    en avant partout (valeur actuelle, prédiction, message) pour rester
    cohérent d'un bout à l'autre de la carte."""
    valeurs = {k: v for k, v in (valeurs or {}).items() if k in Config.METRICS}
    return max(valeurs, key=valeurs.get) if valeurs else 'cpu'


_RECOMMANDATIONS = {
    'cpu': {
        'critique': "Identifier tout de suite le(s) processus qui consomme(nt) le plus (top/htop), et envisager un redémarrage du service concerné ou une bascule de charge.",
        'warning': "Repérer les processus les plus gourmands et planifier une action (optimisation, redémarrage planifié) avant que ça ne devienne critique.",
        'incertain': "Garder un œil sur les processus actifs — pas d'action urgente, le signal n'est pas encore assez net pour agir.",
    },
    'memoire': {
        'critique': "Redémarrer le ou les services suspectés de fuite mémoire dès que possible, ou libérer de la RAM (fermer des processus inutiles).",
        'warning': "Vérifier s'il y a une fuite mémoire progressive (un service qui grossit sans jamais redescendre) et planifier un redémarrage préventif.",
        'incertain': "Surveiller l'évolution de la mémoire dans les prochaines heures avant d'agir.",
    },
    'disque_pct': {
        'critique': "Libérer de l'espace disque en urgence (logs, fichiers temporaires, sauvegardes anciennes) ou étendre le volume.",
        'warning': "Planifier un nettoyage (logs, caches, anciens fichiers) ou une extension de stockage avant d'atteindre la limite.",
        'incertain': "Pas d'action requise dans l'immédiat — vérifier simplement que rien d'inhabituel ne remplit le disque.",
    },
}


def _recommandation_action(metrique: str, niveau: str) -> str:
    """Traduit une alerte en action concrète à faire, pas juste un chiffre.
    C'est ce qui rend une prévision réellement utile pour un responsable :
    pas seulement 'il y a un risque', mais 'voilà quoi faire'."""
    return _RECOMMANDATIONS.get(metrique, {}).get(niveau, "")


def _valeurs_metriques_brutes(recent_measures: list) -> dict:
    """Dernières valeurs connues de chaque métrique surveillée (cpu,
    mémoire, disque...), indépendamment du statut du modèle ML. Sert de
    base commune à la vue d'ensemble et à la détection de risque combiné."""
    if not recent_measures:
        return {}
    derniere = recent_measures[-1]
    return {m: _num(derniere.get(m, 0)) for m in Config.METRICS if m in derniere}


RATIO_METRIQUE_ELEVEE = 0.75  # 75% du seuil : on considère la métrique "sous tension"


def _risque_combine(valeurs_metriques: dict) -> Optional[dict]:
    """Détecte quand plusieurs métriques sont sous tension EN MÊME TEMPS
    sur un même serveur. Un CPU élevé tout seul, ou un disque élevé tout
    seul, c'est gérable. Les deux à la fois, c'est souvent le signe d'un
    vrai incident qui couve (ex: un processus qui boucle et remplit les
    logs) — un risque qu'aucune métrique isolée ne fait ressortir."""
    elevees = []
    for m, v in valeurs_metriques.items():
        seuil = Config.THRESHOLDS.get(m)
        if seuil and v >= seuil * RATIO_METRIQUE_ELEVEE:
            elevees.append((m, v))
    if len(elevees) < 2:
        return None
    elevees.sort(key=lambda x: x[1], reverse=True)
    noms = " et ".join(_label_feature(m) for m, _ in elevees)
    detail = ", ".join(f"{_label_feature(m)} à {v:.0f}%" for m, v in elevees)
    return {
        'metriques': [m for m, _ in elevees],
        'message': f"⚠️ Risque combiné : {noms} sont élevés en même temps sur ce serveur ({detail}). "
                   f"C'est souvent le signe d'un incident réel qui couve, pas juste un indicateur isolé qui dérive.",
    }


def _classe_valeur(valeur: float, seuil: float) -> str:
    """Classe une valeur par rapport à son seuil, pour la vue d'ensemble."""
    if not seuil:
        return 'ok'
    ratio = valeur / seuil
    if ratio >= 1.0:
        return 'critique'
    if ratio >= RATIO_METRIQUE_ELEVEE:
        return 'alerte'
    if ratio >= 0.5:
        return 'attention'
    return 'ok'


_COULEUR_NIVEAU = {
    'critique': '#ef4444',
    'warning': '#f59e0b',
    'incertain': '#3b82f6',
    'surveillance': '#3b82f6',
    'sain': '#22c55e',
}


def _graphique_tendance_svg(valeurs_recentes: list, valeur_predite: float,
                             temps_estime_h: float, seuil: float, niveau: str) -> str:
    """Mini-graphique SVG : historique récent (ligne pleine) + projection
    jusqu'à l'échéance estimée (ligne pointillée) + seuil critique (ligne
    horizontale). Généré côté serveur, aucune librairie JS nécessaire.
    Objectif : remplacer des chiffres isolés par une image qu'on comprend
    en un coup d'œil ("ça monte, et voilà où ça va taper le seuil")."""
    if not valeurs_recentes or len(valeurs_recentes) < 3:
        return ""

    W, H, PAD = 320, 110, 10
    # On garde au plus 20 points pour rester lisible (échantillonnage régulier)
    if len(valeurs_recentes) > 20:
        pas = len(valeurs_recentes) / 20
        valeurs_recentes = [valeurs_recentes[int(i * pas)] for i in range(20)]

    plafond = max(seuil, max(valeurs_recentes), valeur_predite) * 1.12
    plafond = max(plafond, 10)

    def y_de(v):
        return H - PAD - (max(0, min(v, plafond)) / plafond) * (H - 2 * PAD)

    n = len(valeurs_recentes)
    # L'historique occupe les 2/3 gauches, la projection le 1/3 droit
    x_hist_fin = W * 0.62
    x_proj_fin = W - PAD

    pts_hist = [(PAD + i * (x_hist_fin - PAD) / (n - 1), y_de(v)) for i, v in enumerate(valeurs_recentes)]
    poly_hist = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts_hist)

    x_last, y_last = pts_hist[-1]
    x_pred, y_pred = x_proj_fin, y_de(valeur_predite)

    couleur = _COULEUR_NIVEAU.get(niveau, '#3b82f6')
    y_seuil = y_de(seuil)

    delai_txt = f"+{temps_estime_h:.1f}h".replace(".0h", "h")

    return f"""
    <svg viewBox="0 0 {W} {H}" width="100%" height="{H}" style="display:block; margin-top:10px;">
      <line x1="{PAD}" y1="{y_seuil:.1f}" x2="{x_proj_fin}" y2="{y_seuil:.1f}"
            stroke="{couleur}" stroke-width="1" stroke-dasharray="3,4" opacity="0.55"/>
      <text x="{x_proj_fin}" y="{y_seuil - 4:.1f}" text-anchor="end" font-size="9"
            fill="{couleur}" opacity="0.8">seuil {seuil:.0f}%</text>

      <polyline points="{poly_hist}" fill="none" stroke="var(--muted)" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round"/>

      <line x1="{x_last:.1f}" y1="{y_last:.1f}" x2="{x_pred:.1f}" y2="{y_pred:.1f}"
            stroke="{couleur}" stroke-width="2" stroke-dasharray="4,4" stroke-linecap="round"/>

      <circle cx="{x_last:.1f}" cy="{y_last:.1f}" r="3" fill="var(--text)"/>
      <circle cx="{x_pred:.1f}" cy="{y_pred:.1f}" r="4" fill="{couleur}"/>

      <text x="{x_last:.1f}" y="{H - 1}" text-anchor="middle" font-size="9" fill="var(--muted)">maintenant</text>
      <text x="{x_pred:.1f}" y="{H - 1}" text-anchor="end" font-size="9" fill="{couleur}">{delai_txt}</text>
    </svg>
    """


def _feature_importance_display(feature_importance: dict) -> list:
    """Top 3 features avec une contribution significative (>= 2%), en
    langage clair. Le reste (bruit, quasi nul) est masqué : peu de valeur
    informative pour un humain et donne une fausse impression de précision."""
    items = sorted(feature_importance.items(), key=lambda kv: kv[1], reverse=True)
    return [
        {'label': _label_feature(k), 'pct': round(v * 100)}
        for k, v in items if v >= 0.02
    ][:3]


def _metrics_predites_display(metrics_predites: dict, metrique_prioritaire: str = None) -> list:
    items = list(metrics_predites.items())
    if metrique_prioritaire and metrique_prioritaire in metrics_predites:
        items.sort(key=lambda kv: 0 if kv[0] == metrique_prioritaire else 1)
    return [
        {'label': _label_feature(k), 'valeur': round(v, 1)}
        for k, v in items
    ]


def _fenetre_maintenance_serveur(serveur: str) -> Tuple[int, int]:
    """Renvoie (heure_debut, heure_fin) en heures locales (0-23) de la
    fenêtre de maintenance connue pour ce serveur. Configurable par
    serveur via MAINTENANCE_WINDOW_<NOM_SERVEUR> (ex: '01:00-04:00'),
    sinon on retombe sur MAINTENANCE_WINDOW_DEFAULT (voir ProductionConfig)."""
    cle_env = "MAINTENANCE_WINDOW_" + "".join(
        c if c.isalnum() else "_" for c in serveur.upper()
    )
    brute = ProductionConfig.get_env(cle_env, Config.MAINTENANCE_WINDOW_DEFAULT)
    try:
        debut_str, fin_str = brute.split("-")
        return int(debut_str.split(":")[0]), int(fin_str.split(":")[0])
    except Exception:
        return 2, 5  # repli raisonnable : nuit, trafic minimal


def _prochaine_fenetre_maintenance(depuis: datetime, heure_debut: int, heure_fin: int) -> Tuple[datetime, datetime]:
    """Calcule le prochain créneau [début, fin] de la fenêtre de
    maintenance quotidienne à partir de `depuis`. Si `depuis` tombe déjà
    dans la fenêtre d'aujourd'hui, renvoie ce qu'il en reste ; sinon
    renvoie la fenêtre du jour suivant."""
    debut = depuis.replace(hour=heure_debut, minute=0, second=0, microsecond=0)
    fin = depuis.replace(hour=heure_fin, minute=0, second=0, microsecond=0)
    if fin <= depuis:
        debut += timedelta(days=1)
        fin += timedelta(days=1)
    elif debut < depuis < fin:
        debut = depuis
    return debut, fin


def _suggestion_maintenance(p: Dict) -> Optional[Dict]:
    """Transforme une prévision fiable en action concrète et datée : 'voici
    le créneau où intervenir', pas seulement 'il y a un risque'.

    Les 3 conditions doivent être réunies :
      - modèle fiable : confiance du modèle >= CONFIDENCE_THRESHOLD ET
        fiabilité historique du serveur >= 60% (si déjà mesurée — un
        serveur tout juste mis en surveillance n'a pas encore d'historique,
        on ne le bloque pas pour autant)
      - tendance claire : niveau 'warning' ou 'critique' (jamais
        'incertain' ni 'surveillance', qui ne sont pas des risques confirmés)
      - une fenêtre de maintenance connue existe pour ce serveur

    Ne suggère un créneau que s'il tombe AVANT l'échéance estimée : proposer
    un créneau trop tardif serait pire que de ne rien proposer."""
    if p.get('niveau_cible') not in ('warning', 'critique'):
        return None
    if _num(p.get('confiance')) < Config.CONFIDENCE_THRESHOLD:
        return None
    fiabilite_pct = (p.get('fiabilite') or {}).get('fiabilite_pct')
    if fiabilite_pct is not None and fiabilite_pct < 60:
        return None

    temps_estime_h = _num(p.get('temps_estime'))
    if temps_estime_h <= 0:
        return None

    maintenant = historique.maintenant_local()
    echeance = maintenant + timedelta(hours=temps_estime_h)

    heure_debut, heure_fin = _fenetre_maintenance_serveur(p['serveur'])
    creneau_debut, creneau_fin = _prochaine_fenetre_maintenance(maintenant, heure_debut, heure_fin)

    if creneau_debut >= echeance:
        return {
            'disponible': False,
            'echeance': echeance.strftime("%Y-%m-%d %H:%M"),
            'message': (
                f"⏱️ Le créneau de maintenance habituel ({heure_debut:02d}h-{heure_fin:02d}h) tombe "
                f"APRÈS l'échéance estimée ({echeance.strftime('%d/%m %H:%M')}). "
                f"Une action est nécessaire avant, pas d'attente possible jusqu'au prochain créneau."
            ),
        }

    marge_min = max(0, int((echeance - creneau_fin).total_seconds() / 60))
    return {
        'disponible': True,
        'debut': creneau_debut.strftime("%Y-%m-%d %H:%M"),
        'fin': creneau_fin.strftime("%Y-%m-%d %H:%M"),
        'debut_label': creneau_debut.strftime("%A %d/%m à %Hh%M").capitalize(),
        'fin_label': creneau_fin.strftime("%Hh%M"),
        'echeance': echeance.strftime("%Y-%m-%d %H:%M"),
        'marge_min': marge_min,
        'message': (
            f"🛠️ Fenêtre de maintenance suggérée : {creneau_debut.strftime('%A %d/%m %Hh%M').capitalize()} "
            f"→ {creneau_fin.strftime('%Hh%M')}, soit {marge_min // 60}h{marge_min % 60:02d} d'avance "
            f"sur l'échéance estimée ({echeance.strftime('%d/%m %H:%M')})."
        ),
    }


def _donnees_ticket(p: Dict, suggestion: Optional[Dict]) -> Dict:
    """Construit le contenu pré-rempli d'un ticket de maintenance à partir
    d'une prévision : créer le ticket ne demande plus qu'un clic, sans
    ressaisir manuellement probabilité/confiance/métrique."""
    metrique_label = p.get('metrique_critique_label', '')
    lignes = [
        f"Serveur : {p['serveur']}",
        f"Métrique à risque : {metrique_label}",
        f"Niveau : {p.get('niveau_label', '')}",
        f"Probabilité : {round(_num(p.get('probabilite')))}%",
        f"Confiance du modèle : {round(_num(p.get('confiance')) * 100)}%",
        f"Échéance estimée : {(suggestion or {}).get('echeance', '')}",
    ]
    if p.get('recommandation'):
        lignes.append(f"Action recommandée : {p['recommandation']}")
    if suggestion and suggestion.get('disponible'):
        lignes.append(f"Créneau proposé : {suggestion['debut_label']} → {suggestion['fin_label']}")

    return {
        'titre': f"Maintenance préventive — {p['serveur']} ({metrique_label})",
        'description': "\n".join(lignes),
        'serveur': p['serveur'],
        'metrique': metrique_label,
        'priorite': 'haute' if p.get('niveau_cible') == 'critique' else 'normale',
        'creneau_debut': (suggestion or {}).get('debut'),
        'creneau_fin': (suggestion or {}).get('fin'),
    }


def _serie_alignee(mesures: list, metrique: str) -> list:
    """Suite triée par horodatage des valeurs d'une métrique (la plus
    récente en dernier), pour comparer deux serveurs sur une même fenêtre."""
    triees = sorted(mesures, key=lambda m: m.get('horodatage', ''))
    return [_num(m.get(metrique, 0)) for m in triees if metrique in m]


def detecter_correlations_serveurs(previsions: List[Dict]) -> List[Dict]:
    """Détecte les paires de serveurs qui DÉRIVENT ENSEMBLE sur la même
    métrique, dans la même fenêtre de temps — souvent le signe d'une cause
    commune (panne réseau, dépendance applicative partagée) plutôt que deux
    incidents indépendants à traiter séparément dans l'UI.

    Ne compare que les serveurs actuellement sous tension (pas 'sain'), pour
    éviter des corrélations sans intérêt sur du bruit constant (deux
    serveurs stables à 5% de CPU sont toujours "corrélés" sans que ça
    signifie quoi que ce soit)."""
    candidats = [p for p in previsions if p.get('niveau_cible') in ('warning', 'critique', 'surveillance')]
    resultats = []
    vus = set()

    for i, p1 in enumerate(candidats):
        for p2 in candidats[i + 1:]:
            if p1['serveur'] == p2['serveur']:
                continue
            metriques_communes = set(p1.get('valeurs_metriques', {})) & set(p2.get('valeurs_metriques', {}))
            for metrique in metriques_communes:
                paire = tuple(sorted([p1['serveur'], p2['serveur']]) + [metrique])
                if paire in vus:
                    continue

                heures = Config.CORRELATION_FENETRE_MINUTES / 60
                serie1 = _serie_alignee(historique.recuperer_mesures(p1['serveur'], heures=heures), metrique)
                serie2 = _serie_alignee(historique.recuperer_mesures(p2['serveur'], heures=heures), metrique)
                n = min(len(serie1), len(serie2))
                if n < 8:
                    continue
                serie1, serie2 = np.array(serie1[-n:]), np.array(serie2[-n:])
                if serie1.std() < 1e-6 or serie2.std() < 1e-6:
                    continue

                coeff = float(np.corrcoef(serie1, serie2)[0, 1])
                if coeff >= Config.CORRELATION_SEUIL:
                    vus.add(paire)
                    resultats.append({
                        'serveurs': [p1['serveur'], p2['serveur']],
                        'metrique': metrique,
                        'metrique_label': _label_feature(metrique),
                        'coefficient': round(coeff, 2),
                        'message': (
                            f"🔗 {p1['serveur']} et {p2['serveur']} dérivent ensemble sur "
                            f"{_label_feature(metrique)} (corrélation {coeff:.0%}) : cause commune "
                            f"probable (réseau, dépendance partagée) plutôt que deux incidents "
                            f"indépendants à traiter séparément."
                        ),
                    })
    return resultats


def apercu_serveur(serveur: str) -> Dict:
    """Statut ML toujours renvoyé pour un serveur, utilisé uniquement pour
    l'affichage de la page /provisionnement (contrairement à
    generer_previsions(), utilisée par la boucle d'alerting toutes les 5
    minutes, qui ne renvoie que les vrais risques pour ne pas spammer de
    fausses alertes). Ici on veut TOUJOURS montrer où en est le modèle sur
    chaque serveur, même quand tout va bien.
    """
    integrator = get_integrator()
    recent_measures = historique.recuperer_mesures(serveur, heures=2)

    # Fiabilité réelle mesurée sur les prévisions passées de ce serveur
    # (confirmées vs fausses alertes) — c'est la seule mesure honnête de
    # "est-ce que je peux faire confiance à ce que le modèle dit", par
    # opposition aux pourcentages bruts du modèle lui-même qui ne disent
    # rien sur sa fiabilité réelle en conditions réelles.
    fiabilite = historique.statistiques_fiabilite_previsions(serveur=serveur, jours=30)

    valeurs_metriques = _valeurs_metriques_brutes(recent_measures)
    risque_combine = _risque_combine(valeurs_metriques)

    base = {
        'serveur': serveur,
        'feature_importance_display': [],
        'metrics_predites_display': [],
        'metrics': {},
        'temps_estime': 0.0,
        'probabilite': 0.0,
        'confiance': 0.0,
        'valeur_actuelle': 0.0,
        'metrique_critique_label': _label_feature('cpu'),
        'chart_svg': '',
        'recommandation': '',
        'valeurs_metriques': valeurs_metriques,
        'risque_combine': risque_combine,
        'fiabilite': fiabilite,
        'metrique_critique': None,
        'maintenance_suggestion': None,
        'ticket_data': None,
        'correlations': [],
    }

    if len(recent_measures) < 10:
        niveau = 'collecte'
        base.update({
            'niveau_cible': niveau,
            'niveau_emoji': NIVEAU_LABELS[niveau][0],
            'niveau_label': NIVEAU_LABELS[niveau][1],
            'ml_confidence': f"Collecte de données en cours ({len(recent_measures)}/10 mesures)",
        })
        return base

    prediction = integrator.predict_anomaly(serveur, recent_measures)

    if 'error' in prediction:
        # Modèle complet pas encore entraîné : on affiche quand même un
        # statut basé sur la régression simple si elle donne quelque
        # chose, sinon un statut "sain" par défaut (pas assez de recul
        # pour dire qu'il y a un risque).
        simples = generer_previsions_simple(serveur)
        if simples:
            p = simples[0]
            niveau = p['niveau_cible']
            metrique = p.get('type_anomalie', 'cpu')
            historique_metrique = [_num(m.get(metrique, 0)) for m in recent_measures]
            # 'temps_estime' est par construction le délai avant d'atteindre
            # le seuil (voir generer_previsions_simple) : la valeur prédite
            # à cette échéance est donc simplement le seuil lui-même.
            valeur_predite = Config.THRESHOLDS.get(metrique, 90)
            base.update({
                'niveau_cible': niveau,
                'niveau_emoji': NIVEAU_LABELS.get(niveau, ('⚪', niveau))[0],
                'niveau_label': NIVEAU_LABELS.get(niveau, ('⚪', niveau))[1],
                'valeur_actuelle': _num(p.get('valeur_actuelle')),
                'metrique_critique_label': _label_feature(metrique),
                'confiance': _num(p.get('confiance')),
                'probabilite': _num(p.get('probabilite')),
                'temps_estime': _num(p.get('temps_estime')),
                'metrics': p.get('metrics', {}),
                'ml_confidence': p.get('ml_confidence', 'estimation simple'),
                'chart_svg': _graphique_tendance_svg(
                    historique_metrique, valeur_predite, _num(p.get('temps_estime')),
                    Config.THRESHOLDS.get(metrique, 90), niveau,
                ),
                'recommandation': _recommandation_action(metrique, niveau),
                'metrique_critique': metrique,
            })
            base['maintenance_suggestion'] = _suggestion_maintenance(base)
            base['ticket_data'] = (
                _donnees_ticket(base, base['maintenance_suggestion'])
                if base['maintenance_suggestion'] else None
            )
            return base
        niveau = 'sain'
        base.update({
            'niveau_cible': niveau,
            'niveau_emoji': NIVEAU_LABELS[niveau][0],
            'niveau_label': NIVEAU_LABELS[niveau][1],
            'ml_confidence': "estimation simple (historique insuffisant pour le ML complet)",
        })
        return base

    proba = _num(prediction.get('probabilite_anomalie', 0))
    confiance_brute = _num(prediction.get('confiance'))
    if proba >= 70:
        niveau = 'critique'
    elif proba >= Config.PREVISION_MIN_PROBABILITE:
        niveau = 'warning'
    elif proba >= 15:
        niveau = 'surveillance'
    else:
        niveau = 'sain'

    # Une probabilité élevée avec une confiance trop basse n'est pas une
    # prévision fiable — on ne veut pas afficher "Vigilance"/"Critique"
    # (ça a l'air d'un fait certain) quand le modèle n'est en réalité pas
    # sûr de lui. On déclasse honnêtement plutôt que d'alarmer pour rien.
    if niveau in ('critique', 'warning') and confiance_brute < Config.CONFIDENCE_THRESHOLD:
        niveau = 'incertain'

    valeurs_actuelles = prediction.get('valeurs_actuelles', {})
    metrics_predites = {
        k: _num(v) for k, v in prediction.get('metrics_predites', {}).items()
    }
    feature_importance = {
        k: _num(v) for k, v in prediction.get('feature_importance', {}).items()
    }
    confiance = _num(prediction.get('confiance'))
    metrique_critique = _metrique_critique(valeurs_actuelles)

    valeur_metrique_critique = _num(valeurs_actuelles.get(metrique_critique, 0))
    valeur_predite_critique = metrics_predites.get(metrique_critique, valeur_metrique_critique)
    historique_metrique = [_num(m.get(metrique_critique, 0)) for m in recent_measures]

    base.update({
        'niveau_cible': niveau,
        'niveau_emoji': NIVEAU_LABELS[niveau][0],
        'niveau_label': NIVEAU_LABELS[niveau][1],
        'valeur_actuelle': _num(max(valeurs_actuelles.values(), key=_num)) if valeurs_actuelles else 0.0,
        'metrique_critique_label': _label_feature(metrique_critique),
        'confiance': confiance,
        'probabilite': proba,
        'temps_estime': _num(prediction.get('temps_estime_avant_anomalie')),
        'feature_importance_display': _feature_importance_display(feature_importance),
        'ml_confidence': 'haute' if confiance > 0.7 else 'moyenne' if confiance > 0.4 else 'basse',
        'metrics_predites_display': _metrics_predites_display(metrics_predites, metrique_critique),
        'metrics': valeurs_actuelles,
        'chart_svg': _graphique_tendance_svg(
            historique_metrique, valeur_predite_critique,
            _num(prediction.get('temps_estime_avant_anomalie')),
            Config.THRESHOLDS.get(metrique_critique, 90), niveau,
        ),
        'recommandation': _recommandation_action(metrique_critique, niveau),
        'metrique_critique': metrique_critique,
    })
    base['maintenance_suggestion'] = _suggestion_maintenance(base)
    base['ticket_data'] = (
        _donnees_ticket(base, base['maintenance_suggestion'])
        if base['maintenance_suggestion'] else None
    )
    return base


def generer_previsions_simple(serveur: str) -> List[Dict]:
    """Prévisions de secours par régression linéaire (calculer_tendance),
    utilisées tant qu'il n'y a pas assez d'historique pour entraîner
    l'ensemble ML complet. Actives dès 10 mesures récentes (fenêtre de
    30 min) au lieu des MIN_SAMPLES_FOR_TRAINING (100 par défaut)
    nécessaires au ML complet."""
    previsions = []
    for metrique in Config.METRICS:
        seuil = Config.THRESHOLDS.get(metrique)
        if seuil is None:
            continue

        tendance = calculer_tendance(serveur, metrique, fenetre_minutes=30)
        if not tendance:
            continue

        pente = _num(tendance['pente_par_heure'])
        valeur_actuelle = _num(tendance['valeur_actuelle'])
        confiance = _num(tendance['confiance'])

        # Pas de tendance à la hausse exploitable, régression trop
        # bruitée pour dire quoi que ce soit (r2 quasi nul), ou déjà
        # au-dessus du seuil (ce n'est plus une prévision mais un
        # incident réel) : rien à signaler ici.
        if pente <= 0 or confiance < 0.15 or valeur_actuelle >= seuil:
            continue

        heures_avant = (seuil - valeur_actuelle) / pente
        if heures_avant <= 0 or heures_avant > Config.PREDICTION_HORIZON:
            continue

        # Une régression peu fiable (r2 faible) ne doit pas s'afficher
        # comme "Critique"/"Vigilance" — ce serait présenter une estimation
        # bruitée comme un fait établi. On la déclasse en 'incertain'.
        if confiance < Config.CONFIDENCE_THRESHOLD:
            niveau_cible = "incertain"
        else:
            niveau_cible = "critique" if heures_avant <= 4 else "warning"

        previsions.append({
            'serveur': serveur,
            'type_anomalie': metrique,
            'niveau_cible': niveau_cible,
            'valeur_actuelle': valeur_actuelle,
            'confiance': confiance,
            'probabilite': min(95, round(confiance * 100)),
            'temps_estime': round(heures_avant, 1),
            'feature_importance': {},
            'ml_confidence': 'estimation simple (historique insuffisant pour le ML complet)',
            'metrics': {metrique: valeur_actuelle},
            'metrics_predites': {},
            'ensemble_details': {'methode': 'regression_lineaire', 'nb_points': tendance['nb_points']},
            'performance_metrics': {}
        })

    return previsions

# provisionnement.py - Extension pour filtrer par groupes

def generer_previsions_serveur(serveur: str, utilisateur) -> List[Dict]:
    """Génère les prévisions pour un serveur si l'utilisateur y a accès"""
    
    # Vérifier l'accès via les groupes
    autorisees = assignations.machines_autorisees(utilisateur)
    if autorisees is not None and serveur not in autorisees:
        return []  # Pas autorisé
    
    # Générer les prévisions normalement
    return generer_previsions(serveur)

def calculer_tendance(serveur: str, type_anomalie: str, fenetre_minutes: int = 30) -> Optional[Dict]:
    """Fonction de compatibilité"""
    try:
        recent_measures = historique.recuperer_mesures(serveur, heures=fenetre_minutes/60)
        if len(recent_measures) < 10:
            return None
        
        df = pd.DataFrame(recent_measures)
        df = df.sort_values('horodatage')
        
        if type_anomalie not in Config.METRICS:
            return None
        
        values = df[type_anomalie].values
        if len(values) < 2:
            return None
        
        x = np.arange(len(values))
        slope, intercept = np.polyfit(x, values, 1)
        r2 = r2_score(values, slope * x + intercept)
        
        return {
            'pente_par_heure': slope * 60,
            'valeur_actuelle': values[-1],
            'confiance': round(r2, 2),
            'nb_points': len(values),
            'ml_available': True
        }
    except Exception as e:
        Logger.error(f"Erreur calcul tendance: {e}")
        return None

def traiter_previsions_serveur(serveur: str, envoyer_alerte_preventive=None) -> List[Dict]:
    """Fonction de compatibilité"""
    previsions = generer_previsions(serveur)
    
    if not previsions:
        return []
    
    resultats = []
    for p in previsions:
        heures_avant = p.get('temps_estime', 1)
        echeance = (historique.maintenant_local() + timedelta(hours=heures_avant)).strftime("%Y-%m-%d %H:%M:%S")
        
        _id, est_nouvelle = historique.enregistrer_ou_maj_prevision(
            serveur=serveur,
            type_anomalie=p['type_anomalie'],
            niveau_cible=p['niveau_cible'],
            valeur_actuelle=p['valeur_actuelle'],
            pente_par_heure=0,
            confiance=p['confiance'],
            seuil_cible=Config.THRESHOLDS.get('cpu', 85),
            echeance_estimee=echeance,
            ml_data={
                'probabilite': p['probabilite'],
                'feature_importance': p.get('feature_importance', {}),
                'metrics': p.get('metrics', {}),
                'metrics_predites': p.get('metrics_predites', {})
            }
        )
        
        p['id'] = _id
        p['echeance_estimee'] = echeance
        resultats.append(p)
        
        if est_nouvelle and envoyer_alerte_preventive:
            try:
                phrase = phrase_prevision_ml(p)
                envoyer_alerte_preventive(serveur, p, phrase)
            except Exception as e:
                logger.error(f"Erreur envoi alerte: {e}")
    
    return resultats

def phrase_prevision_ml(p: Dict) -> str:
    """Génère un message pour une prévision ML, en langage clair (noms de
    métriques traduits, pas de jargon technique)."""
    proba = p.get('probabilite', 0)
    delai = p.get('temps_estime', 1)
    niveau = p['niveau_cible']
    
    if delai < 1:
        delai_txt = f"{max(1, int(delai * 60))} min"
    else:
        delai_txt = f"{delai:.1f} h"
    
    metrics = p.get('metrics', {})
    valeurs = {k: v for k, v in metrics.items() if k in Config.METRICS}
    metric_critique = max(valeurs, key=valeurs.get) if valeurs else 'cpu'
    valeur_actuelle = valeurs.get(metric_critique, 0)
    metric_label = _label_feature(metric_critique)
    niveau_label = NIVEAU_LABELS.get(niveau, ('⚪', niveau))[1]
    
    msg = f"🟡 Prévision ML : {metric_label} pourrait atteindre un niveau « {niveau_label} » "
    msg += f"dans environ {delai_txt} (probabilité {proba:.0f}%, confiance {p['confiance']*100:.0f}%). "
    msg += f"Valeur actuelle : {valeur_actuelle:.1f}%. "
    
    if p.get('feature_importance_display'):
        top = p['feature_importance_display'][:2]
        features_str = ", ".join([f"{f['label']} ({f['pct']}%)" for f in top])
        msg += f"Facteurs clés : {features_str}."
    
    return msg

# ============================================================================
# PAGE WEB
# ============================================================================

provisionnement_bp = Blueprint("provisionnement", __name__)

_PAGE = """
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Provisionnement ML - SENTINEL</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
""" + TOKENS_CSS + """
  .heatmap-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .heatmap-table th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px;
                      text-transform: uppercase; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  .heatmap-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
  .heatmap-serveur { font-weight: 600; white-space: nowrap; }
  .heatmap-cell { text-align: center; }
  .heatmap-pill { display: inline-block; min-width: 42px; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .heatmap-ok { background: rgba(34,197,94,0.15); color: #22c55e; }
  .heatmap-attention { background: rgba(59,130,246,0.15); color: #3b82f6; }
  .heatmap-alerte { background: rgba(245,158,11,0.18); color: #f59e0b; }
  .heatmap-critique { background: rgba(239,68,68,0.18); color: #ef4444; }
  .heatmap-inconnu { background: var(--panel2); color: var(--muted); }
  .ml-dashboard {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
    margin: 20px 0;
  }
  .ml-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: all 0.3s ease;
  }
  .ml-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  }
  .ml-card.risk-critical { border-left: 4px solid #ef4444; }
  .ml-card.risk-high { border-left: 4px solid #f59e0b; }
  .ml-card.risk-moderate { border-left: 4px solid #3b82f6; }
  .ml-card.risk-low { border-left: 4px solid #22c55e; }
  
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin: 12px 0;
  }
  .metric-item {
    text-align: center;
    padding: 8px;
    background: var(--panel2);
    border-radius: 8px;
  }
  .metric-value {
    font-size: 20px;
    font-weight: bold;
  }
  .metric-label {
    font-size: 11px;
    color: var(--muted);
  }
  .feature-importance {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 10px 0;
  }
  .feature-tag {
    background: var(--panel2);
    padding: 4px 10px;
    border-radius: 16px;
    font-size: 11px;
    border: 1px solid var(--border);
  }
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    margin: 2px;
  }
  .badge-critical { background: #ef4444; color: white; }
  .badge-high { background: #f59e0b; color: white; }
  .badge-moderate { background: #3b82f6; color: white; }
  .badge-low { background: #22c55e; color: white; }
  .badge-high-confidence { background: #22c55e; color: white; }
  .badge-medium-confidence { background: #f59e0b; color: white; }
  .badge-low-confidence { background: #ef4444; color: white; }
  
  .model-status {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin: 20px 0;
  }
  .status-item {
    background: var(--panel2);
    padding: 12px;
    border-radius: 8px;
    text-align: center;
  }
  .status-value {
    font-size: 18px;
    font-weight: bold;
  }
  .status-label {
    font-size: 11px;
    color: var(--muted);
  }
  
  .progress-bar {
    background: var(--panel2);
    border-radius: 6px;
    height: 6px;
    overflow: hidden;
    margin: 8px 0;
  }
  .progress-fill {
    height: 100%;
    border-radius: 6px;
    transition: width 0.5s ease;
  }
  .progress-fill.green { background: #22c55e; }
  .progress-fill.yellow { background: #f59e0b; }
  .progress-fill.red { background: #ef4444; }
  
  .ensemble-details {
    margin-top: 12px;
    padding: 12px;
    background: var(--panel2);
    border-radius: 8px;
    font-size: 12px;
  }
  .ensemble-details table {
    width: 100%;
    border-collapse: collapse;
  }
  .ensemble-details td {
    padding: 4px 8px;
  }
  .ensemble-details .label {
    color: var(--muted);
  }
  
  .openshift-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 16px;
    font-size: 12px;
    font-weight: 600;
    background: #0066cc;
    color: white;
  }
  
  @media (max-width: 768px) {
    .ml-dashboard {
      grid-template-columns: 1fr;
    }
    .metric-grid {
      grid-template-columns: 1fr 1fr;
    }
  }
</style>
</head>
<body>
<script>(function(){ if(localStorage.getItem('sentinel-theme') === 'light'){ document.body.classList.add('light'); } })();</script>

""" + "{{ topbar|safe }}" + """

<main class="contenu">
  <div class="page-entete">
    <h1>🔮 Provisionnement ML</h1>
    <p>Le système analyse en continu vos serveurs pour anticiper les problèmes avant qu'ils n'arrivent.</p>
    <div style="margin-top: 8px;">
      <span class="badge badge-high">{{ stats.active_predictions|default(0) }} prévisions actives</span>
      {% if openshift_mode %}
      <span class="openshift-badge">☁️ OpenShift AI</span>
      {% endif %}
    </div>
  </div>

  <!-- Statistiques -->
  <div class="model-status">
    <div class="status-item">
      <div class="status-value">{{ stats.total_servers|default(0) }}</div>
      <div class="status-label">Serveurs surveillés</div>
    </div>
    <div class="status-item">
      <div class="status-value">{{ stats.active_predictions|default(0) }}</div>
      <div class="status-label">Prédictions actives</div>
    </div>
  </div>

  <!-- Vue d'ensemble comparative -->
  {% if vue_ensemble %}
  <div class="carte" style="margin: 16px 0; overflow-x: auto;">
    <h3 style="margin: 0 0 12px; font-size: 14px;">Vue d'ensemble</h3>
    <table class="heatmap-table">
      <thead>
        <tr>
          <th>Serveur</th>
          {% for col in colonnes_metriques %}
          <th>{{ col.label }}</th>
          {% endfor %}
        </tr>
      </thead>
      <tbody>
        {% for ligne in vue_ensemble %}
        <tr>
          <td class="heatmap-serveur">{{ ligne.serveur }}</td>
          {% for col in colonnes_metriques %}
          {% set cell = ligne.cellules.get(col.cle) %}
          <td class="heatmap-cell">
            {% if cell %}
            <span class="heatmap-pill heatmap-{{ cell.classe }}">{{ cell.valeur|round(0)|int }}%</span>
            {% else %}
            <span class="heatmap-pill heatmap-inconnu">—</span>
            {% endif %}
          </td>
          {% endfor %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div style="margin-top: 10px; font-size: 11.5px; color: var(--muted); display:flex; gap:14px; flex-wrap:wrap;">
      <span><span class="heatmap-pill heatmap-ok" style="padding:1px 8px;">·</span> Normal</span>
      <span><span class="heatmap-pill heatmap-attention" style="padding:1px 8px;">·</span> À surveiller</span>
      <span><span class="heatmap-pill heatmap-alerte" style="padding:1px 8px;">·</span> Sous tension</span>
      <span><span class="heatmap-pill heatmap-critique" style="padding:1px 8px;">·</span> Au-dessus du seuil</span>
    </div>
  </div>
  {% endif %}

  <!-- Corrélation entre serveurs : cause commune probable -->
  {% if correlations %}
  <div style="margin: 16px 0;">
    {% for c in correlations %}
    <div style="padding: 14px 16px; background: rgba(124,58,237,0.10); border: 1px solid rgba(124,58,237,0.35);
                border-radius: 8px; font-size: 13.5px; margin-bottom: 8px;">
      {{ c.message }}
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Chatbot sur les prévisions -->
  <div class="carte" style="margin: 16px 0;">
    <h3 style="margin: 0 0 10px; font-size: 14px;">💬 Poser une question sur vos prévisions</h3>
    <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
      <select id="chat-serveur" style="padding:8px; border-radius:6px; border:1px solid var(--border); background:var(--panel2); color:var(--text);">
        <option value="">Tous les serveurs</option>
        {% for s in serveurs_disponibles %}
        <option value="{{ s }}">{{ s }}</option>
        {% endfor %}
      </select>
      <input id="chat-question" type="text" placeholder="Ex : Pourquoi PC-Farah est à 8% de risque ?"
             style="flex:1; min-width:220px; padding:8px 10px; border-radius:6px; border:1px solid var(--border); background:var(--panel2); color:var(--text);">
      <button id="chat-envoyer" onclick="envoyerQuestionPrevisions()"
              style="padding:8px 16px; border-radius:6px; border:none; background:#3b82f6; color:white; cursor:pointer;">Demander</button>
    </div>
    <div id="chat-reponse" style="margin-top:10px; font-size:13.5px; color: var(--text); display:none;
                                   padding:12px; background: var(--panel2); border-radius:8px;"></div>
  </div>

  <!-- Prévisions -->
  {% if previsions %}

  {% if fiabilite_globale.fiabilite_pct is not none %}
  <div style="margin: 16px 0; padding: 14px 16px; background: var(--panel2); border-radius: 8px; font-size: 14px;">
    📊 <strong>Sur les 30 derniers jours</strong> : le système a lancé
    {{ fiabilite_globale.nb_confirmees + fiabilite_globale.nb_fausses_alertes + fiabilite_globale.nb_annulees|default(0) }}
    alerte(s) préventive(s). Résultat :
    <strong>{{ fiabilite_globale.nb_confirmees }} juste(s)</strong> (le problème s'est vraiment produit),
    <strong>{{ fiabilite_globale.nb_fausses_alertes }} fausse(s) alerte(s)</strong> (rien ne s'est passé).
    {% if fiabilite_globale.nb_annulees %}
    {{ fiabilite_globale.nb_annulees }} de plus se sont résorbée(s) toute(s) seule(s) avant l'échéance (ni une réussite, ni une erreur).
    {% endif %}
    →  <strong>{{ fiabilite_globale.fiabilite_pct }}% de fiabilité.</strong>
    {% if fiabilite_globale.delai_moyen_anticipation_min %}
    Quand l'alerte était juste, elle a prévenu en moyenne {{ fiabilite_globale.delai_moyen_anticipation_min|round(0)|int }} min à l'avance.
    {% endif %}
  </div>
  {% else %}
  <div style="margin: 16px 0; padding: 14px 16px; background: var(--panel2); border-radius: 8px; font-size: 14px; color: var(--muted);">
    ℹ️ Pas encore assez d'historique pour mesurer la fiabilité réelle du système sur vos serveurs.
    Les probabilités affichées ci-dessous sont les estimations du modèle, pas encore confirmées par l'expérience.
  </div>
  {% endif %}

  <div class="ml-dashboard">
    {% for p in previsions %}
    {% set risk_class = 'risk-critical' if p.niveau_cible == 'critique' else 'risk-high' if p.niveau_cible == 'warning' else 'risk-moderate' if p.niveau_cible == 'surveillance' else 'risk-low' %}
    {% set confidence_class = 'badge-high-confidence' if p.ml_confidence == 'haute' else 'badge-medium-confidence' if p.ml_confidence == 'moyenne' else 'badge-low-confidence' %}
    <div class="ml-card {{ risk_class }}">
      <div style="display: flex; justify-content: space-between; align-items: start;">
        <div>
          <h3 style="margin: 0;">{{ p.serveur }}</h3>
          <div style="font-size: 12px; color: var(--muted);">
            {{ p.niveau_emoji }} {{ p.niveau_label }}
            {% if p.correlations %}
            <span class="badge" style="background: rgba(124,58,237,0.18); color:#7c3aed;" title="{{ p.correlations[0].message }}">
              🔗 corrélé
            </span>
            {% endif %}
          </div>
        </div>
        <div>
          <span class="badge {{ confidence_class }}">Confiance modèle : {{ ((p.confiance|float) * 100)|round(0) }}%</span>
        </div>
      </div>

      <div style="margin: 12px 0;">
        <div style="display: flex; justify-content: space-between; font-size: 13px;">
          <span>Probabilité</span>
          <span><strong>{{ (p.probabilite|float)|round(0)|int }}%</strong></span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill {% if p.probabilite > 70 %}red{% elif p.probabilite > 40 %}yellow{% else %}green{% endif %}" 
               style="width: {{ [p.probabilite, 100]|min }}%;"></div>
        </div>
      </div>

      <div class="metric-grid">
        <div class="metric-item">
          <div class="metric-value">{{ (p.temps_estime|float)|round(1) }}h</div>
          <div class="metric-label">Temps estimé</div>
        </div>
        <div class="metric-item">
          <div class="metric-value">{{ (p.valeur_actuelle|float)|round(1) }}%</div>
          <div class="metric-label">{{ p.metrique_critique_label }} actuelle</div>
        </div>
        {% if p.metrics_predites_display and (p.metrics_predites_display[0].valeur - p.valeur_actuelle)|abs >= 1 %}
        <div class="metric-item">
          <div class="metric-value">{{ p.metrics_predites_display[0].valeur }}%</div>
          <div class="metric-label">{{ p.metrics_predites_display[0].label }} dans {{ (p.temps_estime|float)|round(1) }}h</div>
        </div>
        {% endif %}
      </div>

      {% if p.chart_svg %}
      <div id="chart-container-{{ loop.index }}">{{ p.chart_svg|safe }}</div>
      {% endif %}

      {% if p.metrique_critique and p.niveau_cible in ('warning', 'critique', 'surveillance') %}
      <div style="margin-top: 6px; padding: 10px 12px; background: var(--panel2); border-radius: 8px; font-size: 12.5px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span>🔮 Simuler : et si la tendance changeait ?</span>
          <span id="sim-facteur-{{ loop.index }}" style="font-weight:600;">1.0×</span>
        </div>
        <input type="range" min="0.25" max="3" step="0.25" value="1"
               id="sim-slider-{{ loop.index }}"
               oninput="simulerTendance('{{ p.serveur }}', '{{ p.metrique_critique }}', {{ loop.index }})"
               style="width:100%;">
        <div id="sim-message-{{ loop.index }}" style="margin-top:6px; color: var(--muted);"></div>
      </div>
      {% endif %}

      {% if p.risque_combine %}
      <div style="margin-top: 10px; padding: 10px 12px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 8px; font-size: 12.5px; color: var(--text);">
        {{ p.risque_combine.message }}
      </div>
      {% endif %}

      {% if p.feature_importance_display %}
      <div class="feature-importance">
        {% for f in p.feature_importance_display %}
        <span class="feature-tag">{{ f.label }} : {{ f.pct }}%</span>
        {% endfor %}
      </div>
      {% endif %}

      <div style="margin-top: 12px; padding: 12px; background: var(--panel2); border-radius: 8px; font-size: 13px;">
        {{ p.phrase|default('Prédiction ML générée automatiquement') }}
      </div>

      {% if p.recommandation %}
      <div style="margin-top: 8px; padding: 12px; background: rgba(59,130,246,0.08); border-left: 3px solid #3b82f6; border-radius: 6px; font-size: 13px;">
        🛠️ <strong>À faire :</strong> {{ p.recommandation }}
      </div>
      {% endif %}

      {% if p.maintenance_suggestion %}
      <div style="margin-top: 8px; padding: 12px; background: {{ 'rgba(34,197,94,0.10)' if p.maintenance_suggestion.disponible else 'rgba(239,68,68,0.10)' }};
                  border-left: 3px solid {{ '#22c55e' if p.maintenance_suggestion.disponible else '#ef4444' }};
                  border-radius: 6px; font-size: 13px;">
        {{ p.maintenance_suggestion.message }}
        {% if p.maintenance_suggestion.disponible and p.ticket_data %}
        <div style="margin-top: 8px;">
          <button onclick='creerTicket({{ p.ticket_data|tojson }}, this)'
                  style="padding:6px 14px; border-radius:6px; border:none; background:#22c55e; color:white; cursor:pointer; font-size:12.5px;">
            🎫 Créer un ticket pour ce créneau
          </button>
        </div>
        {% endif %}
      </div>
      {% endif %}

      {% if p.fiabilite.fiabilite_pct is not none %}
      <div style="margin-top: 8px; font-size: 12px; color: var(--muted);">
        ✅ Sur ce serveur (30 derniers jours) : {{ p.fiabilite.nb_confirmees }} alerte(s) juste(s),
        {{ p.fiabilite.nb_fausses_alertes }} fausse(s) alerte(s)
        {%- if p.fiabilite.nb_annulees %}, {{ p.fiabilite.nb_annulees }} résorbée(s) seule(s){% endif %}.
        Fiabilité : {{ p.fiabilite.fiabilite_pct }}%.
      </div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="carte">
    <div style="text-align: center; padding: 40px 20px;">
      <div style="font-size: 48px; margin-bottom: 16px;">🔮</div>
      <h3 style="color: var(--muted);">Aucune prévision active</h3>
      <p style="color: var(--muted); font-size: 14px;">
        Le système analyse en continu les tendances de vos serveurs.
        Des prévisions apparaîtront automatiquement lorsqu'une anomalie est probable.
      </p>
    </div>
  </div>
  {% endif %}
</main>

<script>""" + JS_TEMA_ET_MENU + """

// --- Simulateur "et si" sur la tendance -------------------------------
async function simulerTendance(serveur, metrique, index) {
  const slider = document.getElementById('sim-slider-' + index);
  const facteurLabel = document.getElementById('sim-facteur-' + index);
  const message = document.getElementById('sim-message-' + index);
  const chartContainer = document.getElementById('chart-container-' + index);
  const multiplicateur = parseFloat(slider.value);
  facteurLabel.textContent = multiplicateur.toFixed(2) + '×';
  message.textContent = 'Calcul en cours...';

  try {
    const url = '/provisionnement/api/simuler?serveur=' + encodeURIComponent(serveur) +
                '&metrique=' + encodeURIComponent(metrique) +
                '&multiplicateur=' + multiplicateur;
    const resp = await fetch(url);
    const data = await resp.json();
    if (data.error) {
      message.textContent = data.error;
      return;
    }
    message.textContent = data.message;
    if (data.chart_svg && chartContainer) {
      chartContainer.innerHTML = data.chart_svg;
    }
  } catch (e) {
    message.textContent = "Erreur lors de la simulation.";
  }
}

// --- Création de ticket depuis une prévision ---------------------------
async function creerTicket(donneesTicket, boutonEl) {
  boutonEl.disabled = true;
  boutonEl.textContent = 'Création...';
  try {
    const resp = await fetch('/provisionnement/api/creer-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(donneesTicket),
    });
    const data = await resp.json();
    if (data.ok) {
      boutonEl.textContent = '✅ Ticket créé';
    } else {
      boutonEl.textContent = '⚠️ Échec — réessayer';
      boutonEl.disabled = false;
    }
  } catch (e) {
    boutonEl.textContent = '⚠️ Échec — réessayer';
    boutonEl.disabled = false;
  }
}

// --- Chatbot sur les prévisions -----------------------------------------
async function envoyerQuestionPrevisions() {
  const question = document.getElementById('chat-question').value.trim();
  const serveur = document.getElementById('chat-serveur').value;
  const zoneReponse = document.getElementById('chat-reponse');
  const bouton = document.getElementById('chat-envoyer');
  if (!question) return;

  bouton.disabled = true;
  zoneReponse.style.display = 'block';
  zoneReponse.textContent = '💭 Réflexion en cours...';

  try {
    const resp = await fetch('/provisionnement/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: question, serveur: serveur || null }),
    });
    const data = await resp.json();
    zoneReponse.textContent = data.error ? ('⚠️ ' + data.error) : data.reponse;
  } catch (e) {
    zoneReponse.textContent = "⚠️ Impossible de contacter l'assistant pour le moment.";
  } finally {
    bouton.disabled = false;
  }
}
</script>
</body></html>
"""

@provisionnement_bp.route("/provisionnement")
@login_required
def page_provisionnement():
    """Page principale de provisionnement"""
    import assignations
    
    autorisees = assignations.machines_autorisees(current_user)
    # 'local' n'est pas un serveur a surveiller a proprement parler
    # (pas assez d'historique / pas pertinent pour le provisionnement ML) :
    # on le retire de l'affichage de cette page.
    autorisees = {m for m in autorisees if m != "local"}
    if not autorisees:
        return render_template_string(
            _PAGE,
            previsions=[],
            stats={},
            openshift_mode=Config.OPENSHIFT_MODE,
            topbar=render_topbar("provisionnement")
        )
    
    integrator = get_integrator()
    all_previsions = []
    stats = {
        'total_servers': len(autorisees),
        'active_predictions': 0,
        'avg_confidence': 0,
        'performance': {}
    }
    
    for serveur in autorisees:
        apercu = apercu_serveur(serveur)
        if apercu['niveau_cible'] == 'collecte':
            apercu['phrase'] = f"🔵 Collecte de données en cours pour {serveur} — pas encore assez d'historique pour une prédiction fiable."
        elif apercu['niveau_cible'] == 'sain':
            apercu['phrase'] = f"🟢 {serveur} : aucune tendance à risque détectée actuellement."
        elif apercu['niveau_cible'] == 'incertain':
            apercu['phrase'] = (
                f"🔵 {serveur} : un signal de risque est détecté sur {apercu.get('metrique_critique_label', 'une métrique')}, "
                f"mais le modèle n'a pas encore assez de recul pour l'affirmer avec certitude. "
                f"À surveiller, pas encore une alerte confirmée."
            )
        else:
            apercu['phrase'] = phrase_prevision_ml(apercu)
        all_previsions.append(apercu)
        
        status = integrator.health_check()
        if status.get('performance'):
            stats['performance'] = status['performance']
    
    stats['active_predictions'] = sum(1 for p in all_previsions if p['niveau_cible'] in ('warning', 'critique'))
    if all_previsions:
        stats['avg_confidence'] = sum(p.get('confiance', 0) for p in all_previsions) / len(all_previsions)

    fiabilite_globale = historique.statistiques_fiabilite_previsions(jours=30)

    # Détection de corrélation entre serveurs : regroupe les prévisions
    # concernées par une dérive partagée, pour que l'UI affiche "cause
    # commune probable" plutôt que 2 cartes traitées comme 2 problèmes
    # sans lien apparent.
    correlations = detecter_correlations_serveurs(all_previsions)
    correles_par_serveur = {}
    for c in correlations:
        for s in c['serveurs']:
            correles_par_serveur.setdefault(s, []).append(c)
    for apercu in all_previsions:
        apercu['correlations'] = correles_par_serveur.get(apercu['serveur'], [])

    # Vue d'ensemble comparative : une ligne par serveur, une colonne par
    # métrique, basée sur les valeurs déjà calculées ci-dessus (pas de
    # nouvelle requête). Donne en un coup d'œil ce qu'un tableau de
    # chiffres serveur par serveur ne permet pas de voir : qui, parmi
    # tous les serveurs, est réellement sous tension, sur quoi.
    colonnes_metriques = [{'cle': m, 'label': _label_feature(m)} for m in Config.METRICS]
    vue_ensemble = []
    for apercu in all_previsions:
        cellules = {}
        for m in Config.METRICS:
            if m in apercu.get('valeurs_metriques', {}):
                v = apercu['valeurs_metriques'][m]
                cellules[m] = {'valeur': v, 'classe': _classe_valeur(v, Config.THRESHOLDS.get(m))}
        vue_ensemble.append({'serveur': apercu['serveur'], 'cellules': cellules})

    return render_template_string(
        _PAGE,
        previsions=all_previsions,
        stats=stats,
        fiabilite_globale=fiabilite_globale,
        vue_ensemble=vue_ensemble,
        colonnes_metriques=colonnes_metriques,
        correlations=correlations,
        serveurs_disponibles=sorted(autorisees),
        openshift_mode=Config.OPENSHIFT_MODE,
        topbar=render_topbar("provisionnement")
    )

@provisionnement_bp.route("/provisionnement/api/status")
@login_required
def api_status():
    """API pour le statut des modèles"""
    integrator = get_integrator()
    return jsonify(integrator.health_check())

@provisionnement_bp.route("/provisionnement/api/train")
@login_required
def api_train():
    """API pour déclencher un entraînement"""
    serveur = request.args.get('serveur')
    if not serveur:
        return jsonify({'error': 'Serveur requis'}), 400
    
    historical_data = historique.recuperer_mesures(serveur, heures=168)
    if not historical_data:
        return jsonify({'error': 'Pas assez de données historiques'}), 400
    
    integrator = get_integrator()
    result = integrator.train_models(serveur, historical_data)
    return jsonify(result)

@provisionnement_bp.route("/provisionnement/api/health")
def api_health():
    """API de santé"""
    integrator = get_integrator()
    return jsonify(integrator.health_check())


@provisionnement_bp.route("/provisionnement/api/simuler")
@login_required
def api_simuler():
    """Simulateur "et si" : recalcule le temps estimé avant anomalie si la
    tendance actuelle accélérait ou ralentissait d'un facteur choisi par
    l'utilisateur. Réutilise directement calculer_tendance() (régression
    déjà en place pour les prévisions de secours) — aucun nouveau modèle à
    entraîner, juste une re-projection de la pente mesurée."""
    import assignations
    serveur = request.args.get('serveur', '')
    metrique = request.args.get('metrique', '')

    autorisees = assignations.machines_autorisees(current_user)
    if autorisees is not None and serveur not in autorisees:
        return jsonify({'error': 'Serveur non autorisé'}), 403

    try:
        multiplicateur = float(request.args.get('multiplicateur', '1'))
    except ValueError:
        return jsonify({'error': 'Multiplicateur invalide'}), 400
    multiplicateur = max(0.1, min(multiplicateur, 5.0))

    if not serveur or metrique not in Config.METRICS:
        return jsonify({'error': 'Paramètres invalides'}), 400

    tendance = calculer_tendance(serveur, metrique, fenetre_minutes=30)
    if not tendance:
        return jsonify({'error': "Pas assez de données récentes sur ce serveur pour simuler."}), 400

    seuil = Config.THRESHOLDS.get(metrique, 90)
    valeur_actuelle = _num(tendance['valeur_actuelle'])
    pente = _num(tendance['pente_par_heure']) * multiplicateur

    if pente <= 0:
        return jsonify({
            'temps_estime': None,
            'multiplicateur': multiplicateur,
            'message': "À cette vitesse, le seuil ne serait jamais atteint (tendance nulle ou négative).",
        })

    heures = 0.0 if valeur_actuelle >= seuil else (seuil - valeur_actuelle) / pente
    heures = min(heures, Config.PREDICTION_HORIZON * 5)  # borne d'affichage raisonnable
    echeance = (historique.maintenant_local() + timedelta(hours=heures)).strftime("%Y-%m-%d %H:%M")

    recent_measures = historique.recuperer_mesures(serveur, heures=2)
    historique_metrique = [_num(m.get(metrique, 0)) for m in recent_measures]
    niveau = 'critique' if heures <= 4 else 'warning' if heures <= Config.PREDICTION_HORIZON else 'surveillance'
    valeur_predite = min(seuil * 1.1, valeur_actuelle + pente * min(heures, Config.PREDICTION_HORIZON))
    chart_svg = _graphique_tendance_svg(historique_metrique, valeur_predite, heures, seuil, niveau)

    return jsonify({
        'temps_estime': round(heures, 1),
        'echeance': echeance,
        'multiplicateur': multiplicateur,
        'chart_svg': chart_svg,
        'message': (
            f"À {multiplicateur:.2f}× la tendance actuelle, le seuil ({seuil:.0f}%) serait atteint "
            f"dans environ {heures:.1f}h (~{echeance})."
        ),
    })


@provisionnement_bp.route("/provisionnement/api/creer-ticket", methods=["POST"])
@login_required
def api_creer_ticket():
    """Crée un ticket de maintenance pré-rempli à partir d'une prévision.
    Envoie vers TICKET_WEBHOOK_URL si configuré (webhook Jira/GLPI/
    ServiceNow/...), sinon notifie les responsables par email — jamais
    d'erreur bloquante si le système de ticketing externe est indisponible,
    même philosophie défensive que les canaux d'alerte de notifier.py."""
    import assignations

    data = request.get_json(force=True, silent=True) or {}
    if not all(data.get(k) for k in ('titre', 'description', 'serveur')):
        return jsonify({'error': 'Données de ticket incomplètes'}), 400

    autorisees = assignations.machines_autorisees(current_user)
    if autorisees is not None and data['serveur'] not in autorisees:
        return jsonify({'error': 'Serveur non autorisé'}), 403

    ticket = {
        'titre': data['titre'],
        'description': data['description'],
        'serveur': data['serveur'],
        'metrique': data.get('metrique', ''),
        'priorite': data.get('priorite', 'normale'),
        'creneau_debut': data.get('creneau_debut'),
        'creneau_fin': data.get('creneau_fin'),
        'cree_par': getattr(current_user, 'email', None) or getattr(current_user, 'username', 'inconnu'),
        'cree_le': historique.maintenant_local().strftime("%Y-%m-%d %H:%M:%S"),
    }

    envoye_webhook = False
    if Config.TICKET_WEBHOOK_URL and REQUESTS_AVAILABLE:
        try:
            resp = requests.post(Config.TICKET_WEBHOOK_URL, json=ticket, timeout=5)
            envoye_webhook = resp.status_code < 300
        except Exception as e:
            Logger.warning(f"Échec envoi ticket vers webhook : {e}")

    if not envoye_webhook:
        try:
            import notifier
            notifier.envoyer_email_generique(
                sujet=f"🎫 Nouveau ticket de maintenance — {ticket['serveur']}",
                corps=ticket['description'] + f"\n\nCréé par : {ticket['cree_par']} le {ticket['cree_le']}",
            )
        except Exception as e:
            Logger.warning(f"Échec notification du ticket par email : {e}")

    Logger.info(f"🎫 Ticket de maintenance créé pour {ticket['serveur']} : {ticket['titre']}")
    return jsonify({'ok': True, 'webhook': envoye_webhook, 'ticket': ticket})


@provisionnement_bp.route("/provisionnement/api/chat", methods=["POST"])
@login_required
def api_chat_previsions():
    """Questions en langage naturel sur les prévisions ML actuelles.
    Réutilise chatbot.py (déjà utilisé pour expliquer les anomalies du
    module 3) plutôt que d'ajouter un nouveau module séparé — voir
    chatbot.repondre_question_provisionnement()."""
    import assignations
    import chatbot

    data = request.get_json(force=True, silent=True) or {}
    question = (data.get('question') or '').strip()
    if not question:
        return jsonify({'error': 'Question vide'}), 400

    serveur = data.get('serveur') or None
    autorisees = assignations.machines_autorisees(current_user)
    autorisees = [m for m in autorisees if m != 'local'] if autorisees is not None else None
    if serveur and autorisees is not None and serveur not in autorisees:
        return jsonify({'error': 'Serveur non autorisé'}), 403

    reponse = chatbot.repondre_question_provisionnement(
        question, serveur=serveur, serveurs_disponibles=autorisees
    )
    return jsonify({'reponse': reponse})

# ============================================================================
# INITIALISATION
# ============================================================================

# Initialiser la configuration
Config = ProductionConfig.initialize()

# Initialiser le logger
Logger = ProductionLogger().get()

# Initialiser les modèles
provisionnement = ProvisionnementML()

Logger.info("🚀 Module Provisionnement ML initialisé")
Logger.info(f"📁 MODE: {Config.DEPLOYMENT_MODE}")
Logger.info(f"☁️ OpenShift: {Config.OPENSHIFT_MODE}")
Logger.info(f"📂 MODEL_DIR: {Config.MODEL_DIR}")
Logger.info(f"📊 Métriques: {Config.METRICS}")
Logger.info(f"🎯 Seuils: {Config.THRESHOLDS}")

# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'provisionnement_bp',
    'generer_previsions',
    'calculer_tendance',
    'traiter_previsions_serveur',
    'get_integrator',
    'get_storage',
    'Config',
    'Logger',
    'ProvisionnementML',
    'DurableStorage'
]