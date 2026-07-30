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
        cls.CONFIDENCE_THRESHOLD = float(cls.get_env("CONFIDENCE_THRESHOLD", "0.6"))
        cls.ANOMALY_PROB_THRESHOLD = float(cls.get_env("ANOMALY_PROB_THRESHOLD", "0.6"))
        
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
    
    def save(self, data: Any, name: str, format: str = 'pkl') -> Dict[str, str]:
        """Sauvegarde avec fallback"""
        results = {'local': str(self.local_dir / f"{name}.{format}")}
        
        # Sauvegarde locale
        local_path = self.local_dir / f"{name}.{format}"
        try:
            if format == 'pkl':
                with open(local_path, 'wb') as f:
                    pickle.dump(data, f)
            elif format == 'json':
                with open(local_path, 'w') as f:
                    json.dump(data, f)
            self.logger.info(f"✅ Sauvegarde locale: {local_path}")
        except Exception as e:
            self.logger.error(f"❌ Erreur sauvegarde locale: {e}")
            # Fallback /tmp
            fallback_path = Path('/tmp') / f"{name}.{format}"
            try:
                if format == 'pkl':
                    with open(fallback_path, 'wb') as f:
                        pickle.dump(data, f)
                elif format == 'json':
                    with open(fallback_path, 'w') as f:
                        json.dump(data, f)
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
                data = pickle.loads(response['Body'].read())
                self.logger.info(f"✅ Chargé depuis S3: {name}")
                return data
            except Exception as e:
                self.logger.debug(f"S3 non disponible: {e}")
        
        # Essayer local
        local_path = self.local_dir / f"{name}.{format}"
        if local_path.exists():
            try:
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
            use_label_encoder=False,
            eval_metric='logloss'
        )
        self.xgb_regressor = XGBRegressor(
            n_estimators=self.config.XGB_N_ESTIMATORS,
            max_depth=self.config.XGB_MAX_DEPTH,
            learning_rate=self.config.XGB_LEARNING_RATE,
            random_state=42
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
        
        # Charger LSTM si disponible
        if self.storage.exists('lstm_model'):
            try:
                # Reconstruire l'architecture LSTM
                self.lstm_model = LSTMPredictor(input_size=1)
                model_data = self.storage.load('lstm_model')
                if model_data:
                    self.lstm_model.load_state_dict(model_data)
                    self.logger.info("✅ LSTM chargé")
            except Exception as e:
                self.logger.warning(f"⚠️ Erreur chargement LSTM: {e}")
        
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
        
        # Métadonnées
        metadata = self.storage.load('metadata', 'json')
        if metadata:
            self.last_training = datetime.fromisoformat(metadata.get('last_training', '')) if metadata.get('last_training') else None
            self.performance_metrics = metadata.get('performance_metrics', {})
            self.feature_importance = metadata.get('feature_importance', {})
            self.logger.info("✅ Métadonnées chargées")
    
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
                early_stopping_rounds=20,
                verbose=False
            )
            
            self.xgb_regressor.fit(
                X_train, y_reg_train,
                eval_set=[(X_val, y_reg_val)],
                early_stopping_rounds=20,
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
            
            self.feature_importance = dict(zip(
                feature_names[:len(self.xgb_classifier.feature_importances_)],
                self.xgb_classifier.feature_importances_
            ))
            
            # Métriques de performance
            y_class_pred = self.xgb_classifier.predict(X_val)
            y_reg_pred = self.xgb_regressor.predict(X_val)
            
            self.performance_metrics.update({
                'classification_accuracy': accuracy_score(y_class_val, y_class_pred),
                'regression_rmse': np.sqrt(mean_squared_error(y_reg_val, y_reg_pred)),
                'regression_r2': r2_score(y_reg_val, y_reg_pred)
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
                'feature_importance': self.feature_importance
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
            
            if self.last_training:
                hours_since_training = (datetime.now() - self.last_training).total_seconds() / 3600
                if hours_since_training > self.config.RETRAINING_INTERVAL:
                    self.logger.info(f"Réentraînement automatique pour {server}")
                    threading.Thread(
                        target=self.train_models,
                        args=(server, historique.recuperer_mesures(server, heures=168))
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

def generer_previsions(serveur: str) -> List[Dict]:
    """Fonction de compatibilité"""
    integrator = get_integrator()
    recent_measures = historique.recuperer_mesures(serveur, heures=2)
    
    if len(recent_measures) < 10:
        return []
    
    prediction = integrator.predict_anomaly(serveur, recent_measures)
    
    if 'error' in prediction:
        return []
    
    if prediction.get('probabilite_anomalie', 0) < 30:
        return []
    
    prevision = {
        'serveur': serveur,
        'type_anomalie': 'multi',
        'niveau_cible': 'critique' if prediction['niveau_risque'] == 'CRITIQUE' else 'warning',
        'valeur_actuelle': max(prediction['valeurs_actuelles'].values()),
        'confiance': prediction['confiance'],
        'probabilite': prediction['probabilite_anomalie'],
        'temps_estime': prediction['temps_estime_avant_anomalie'],
        'feature_importance': prediction['feature_importance'],
        'ml_confidence': 'haute' if prediction['confiance'] > 0.7 else 'moyenne',
        'metrics': prediction['valeurs_actuelles'],
        'metrics_predites': prediction['metrics_predites'],
        'ensemble_details': prediction.get('ensemble_details', {}),
        'performance_metrics': prediction.get('performance_metrics', {})
    }
    
    return [prevision]

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
        logger.error(f"Erreur calcul tendance: {e}")
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
    """Génère un message pour une prévision ML"""
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
    
    msg = f"🟡 Prévision ML: {metric_critique} pourrait atteindre un niveau {niveau} "
    msg += f"dans environ {delai_txt} (probabilité {proba:.0f}%, confiance {p['confiance']*100:.0f}%). "
    msg += f"Valeur actuelle: {valeur_actuelle:.1f}%. "
    
    if p.get('feature_importance'):
        top_features = sorted(p['feature_importance'].items(), key=lambda x: x[1], reverse=True)[:2]
        if top_features:
            features_str = ", ".join([f"{k}: {v*100:.0f}%" for k, v in top_features])
            msg += f"Facteurs clés: {features_str}."
    
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
    <p>Prédictions avancées basées sur un ensemble de modèles (XGBoost + LSTM + Prophet)</p>
    <div style="margin-top: 8px;">
      <span class="badge badge-low">Modèles entraînés</span>
      <span class="badge badge-moderate">Auto-adaptatif</span>
      <span class="badge badge-high">{{ previsions|length }} prévisions actives</span>
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
    <div class="status-item">
      <div class="status-value">{{ "%.1f"|format(stats.avg_confidence|default(0)*100) }}%</div>
      <div class="status-label">Confiance moyenne</div>
    </div>
    <div class="status-item">
      <div class="status-value">{{ stats.features_importance|default(0) }}</div>
      <div class="status-label">Features analysées</div>
    </div>
  </div>

  <!-- Prévisions -->
  {% if previsions %}
  <div class="ml-dashboard">
    {% for p in previsions %}
    {% set risk_class = 'risk-critical' if p.niveau_cible == 'critique' else 'risk-high' if p.niveau_cible == 'warning' else 'risk-moderate' %}
    {% set confidence_class = 'badge-high-confidence' if p.ml_confidence == 'haute' else 'badge-medium-confidence' if p.ml_confidence == 'moyenne' else 'badge-low-confidence' %}
    <div class="ml-card {{ risk_class }}">
      <div style="display: flex; justify-content: space-between; align-items: start;">
        <div>
          <h3 style="margin: 0;">{{ p.serveur }}</h3>
          <div style="font-size: 12px; color: var(--muted);">
            {{ p.type_anomalie|upper }} - {{ p.niveau_cible|upper }}
          </div>
        </div>
        <div>
          <span class="badge {{ confidence_class }}">{{ (p.confiance * 100)|round(0) }}%</span>
        </div>
      </div>

      <div style="margin: 12px 0;">
        <div style="display: flex; justify-content: space-between; font-size: 13px;">
          <span>Probabilité</span>
          <span><strong>{{ p.probabilite }}%</strong></span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill {% if p.probabilite > 70 %}red{% elif p.probabilite > 40 %}yellow{% else %}green{% endif %}" 
               style="width: {{ [p.probabilite, 100]|min }}%;"></div>
        </div>
      </div>

      <div class="metric-grid">
        <div class="metric-item">
          <div class="metric-value">{{ p.temps_estime|round(1) }}h</div>
          <div class="metric-label">Temps estimé</div>
        </div>
        <div class="metric-item">
          <div class="metric-value">{{ p.valeur_actuelle|round(1) }}%</div>
          <div class="metric-label">Valeur actuelle</div>
        </div>
        <div class="metric-item">
          <div class="metric-value">{{ p.metrics_predites|first|last|round(1) if p.metrics_predites else '—' }}%</div>
          <div class="metric-label">Valeur prédite</div>
        </div>
      </div>

      {% if p.feature_importance %}
      <div class="feature-importance">
        {% for feature, importance in p.feature_importance.items()|sort(by='value', reverse=true)|slice(5) %}
        <span class="feature-tag">{{ feature }}: {{ (importance * 100)|round(0) }}%</span>
        {% endfor %}
      </div>
      {% endif %}

      {% if p.ensemble_details %}
      <div class="ensemble-details">
        <table>
          <tr>
            <td class="label">XGBoost</td>
            <td>{{ "%.1f"|format(p.ensemble_details.xgb_probability * 100) }}%</td>
          </tr>
          {% if p.ensemble_details.lstm_prediction %}
          <tr>
            <td class="label">LSTM</td>
            <td>{{ "%.1f"|format(p.ensemble_details.lstm_prediction * 100) }}%</td>
          </tr>
          {% endif %}
          {% if p.ensemble_details.prophet_predictions %}
          <tr>
            <td class="label">Prophet</td>
            <td>{{ p.ensemble_details.prophet_predictions|join(', ') }}</td>
          </tr>
          {% endif %}
        </table>
      </div>
      {% endif %}

      <div style="margin-top: 12px; padding: 12px; background: var(--panel2); border-radius: 8px; font-size: 13px;">
        {{ p.phrase|default('Prédiction ML générée automatiquement') }}
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="carte">
    <div style="text-align: center; padding: 40px 20px;">
      <div style="font-size: 48px; margin-bottom: 16px;">🔮</div>
      <h3 style="color: var(--muted);">Aucune prévision active</h3>
      <p style="color: var(--muted); font-size: 14px;">
        Les modèles ML analysent en continu les tendances de vos serveurs.
        Des prévisions apparaîtront automatiquement lorsqu'une anomalie est probable.
      </p>
    </div>
  </div>
  {% endif %}

  <!-- Performance des modèles -->
  {% if stats.performance %}
  <div style="margin-top: 24px;">
    <h2>📊 Performance des Modèles</h2>
    <div class="model-status">
      {% for model, value in stats.performance.items() %}
      <div class="status-item">
        <div class="status-value">{{ "%.1f"|format(value * 100) }}%</div>
        <div class="status-label">{{ model|replace('_', ' ')|title }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}
</main>

<script>""" + JS_TEMA_ET_MENU + """</script>
</body></html>
"""

@provisionnement_bp.route("/provisionnement")
@login_required
def page_provisionnement():
    """Page principale de provisionnement"""
    import assignations
    
    autorisees = assignations.machines_autorisees(current_user)
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
        'features_importance': 0,
        'performance': {}
    }
    
    for serveur in autorisees:
        previsions = generer_previsions(serveur)
        if previsions:
            for p in previsions:
                p['phrase'] = phrase_prevision_ml(p)
            all_previsions.extend(previsions)
        
        status = integrator.health_check()
        if status.get('performance'):
            stats['performance'] = status['performance']
        if status.get('feature_importance'):
            stats['features_importance'] = max(stats['features_importance'], len(status.get('feature_importance', {})))
    
    stats['active_predictions'] = len(all_previsions)
    if all_previsions:
        stats['avg_confidence'] = sum(p.get('confiance', 0) for p in all_previsions) / len(all_previsions)
    
    return render_template_string(
        _PAGE,
        previsions=all_previsions,
        stats=stats,
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