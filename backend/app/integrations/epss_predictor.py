"""EPSS Prediction Model - Predicts exploitation probability for CVEs"""
import logging
import numpy as np
from typing import Dict, Optional, Tuple
from datetime import datetime
import pickle
import os

logger = logging.getLogger(__name__)

# Try to import ML libraries
try:
    from sklearn.ensemble import GradientBoostingRegressor
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    logger.warning("scikit-learn not available, using rule-based EPSS prediction")
    ML_AVAILABLE = False


class EPSSPredictor:
    """
    EPSS (Exploit Prediction Scoring System) Predictor

    Predicts the probability of exploitation for a CVE based on its characteristics.
    Uses a Gradient Boosting model trained on historical EPSS data.

    Features used for prediction:
    - CVSS Base Score
    - CVSS Exploitability Score
    - CVSS Impact Score
    - Attack Vector (Network/Adjacent/Local/Physical)
    - Attack Complexity (Low/High)
    - Privileges Required (None/Low/High)
    - CWE Category
    - Days since publication
    - Vendor/Product characteristics
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize EPSS predictor

        Args:
            model_path: Path to saved model file (optional)
        """
        self.model = None
        self.scaler = None
        self.model_path = model_path or "models/epss_predictor.pkl"

        if ML_AVAILABLE and os.path.exists(self.model_path):
            self.load_model(self.model_path)
            logger.info(f"Loaded EPSS model from {self.model_path}")
        elif ML_AVAILABLE:
            logger.info("No pre-trained model found, using untrained model")
            self.model = GradientBoostingRegressor(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
            self.scaler = StandardScaler()
        else:
            logger.warning("ML libraries not available, using rule-based prediction")

    def extract_features(self, cve_data: Dict) -> np.ndarray:
        """
        Extract features from CVE data for prediction

        Args:
            cve_data: Dictionary containing CVE information

        Returns:
            Feature vector as numpy array
        """
        try:
            features = []

            # CVSS Scores
            cvss_base = float(cve_data.get('cvss_score', 0) or 0)
            features.append(cvss_base)

            # Get exploitability and impact scores from cve_details if available
            cve_details = cve_data.get('cve_details', {})
            exploitability = float(cve_details.get('maxCvssExploitabilityScore', cvss_base * 0.4) or cvss_base * 0.4)
            impact = float(cve_details.get('maxCvssImpactScore', cvss_base * 0.6) or cvss_base * 0.6)

            features.append(exploitability)
            features.append(impact)

            # Attack Vector encoding (higher = more remote)
            attack_vector = self._extract_attack_vector(cve_data)
            features.append(attack_vector)

            # Attack Complexity (0 = High, 1 = Low)
            attack_complexity = self._extract_attack_complexity(cve_data)
            features.append(attack_complexity)

            # Privileges Required (0 = High, 1 = Low, 2 = None)
            privileges = self._extract_privileges_required(cve_data)
            features.append(privileges)

            # User Interaction (0 = Required, 1 = None)
            user_interaction = self._extract_user_interaction(cve_data)
            features.append(user_interaction)

            # Days since publication
            days_since_pub = self._calculate_days_since_publication(cve_data)
            features.append(days_since_pub)

            # CWE category (encoded as integer, 0 if unknown)
            cwe_encoded = self._encode_cwe(cve_data)
            features.append(cwe_encoded)

            # Severity level (0-3: Unknown/Low/Medium/High/Critical)
            severity = self._encode_severity(cve_data.get('severity', 'UNKNOWN'))
            features.append(severity)

            # Binary flags
            features.append(1.0 if cve_data.get('is_code_execution', False) else 0.0)
            features.append(1.0 if cve_data.get('exploit_exists', False) else 0.0)
            features.append(1.0 if cve_data.get('is_in_cisa_kev', False) else 0.0)

            return np.array(features).reshape(1, -1)

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return a default feature vector
            return np.zeros((1, 13))

    def _extract_attack_vector(self, cve_data: Dict) -> float:
        """Extract and encode attack vector (0=Physical, 1=Local, 2=Adjacent, 3=Network)"""
        vector_str = str(cve_data.get('cve_details', {}).get('cvssVector', ''))

        if 'AV:N' in vector_str:
            return 3.0  # Network
        elif 'AV:A' in vector_str:
            return 2.0  # Adjacent
        elif 'AV:L' in vector_str:
            return 1.0  # Local
        elif 'AV:P' in vector_str:
            return 0.0  # Physical
        else:
            # Default based on CVSS score
            cvss = float(cve_data.get('cvss_score', 0) or 0)
            return 3.0 if cvss >= 7.0 else 1.0

    def _extract_attack_complexity(self, cve_data: Dict) -> float:
        """Extract attack complexity (0=High, 1=Low)"""
        vector_str = str(cve_data.get('cve_details', {}).get('cvssVector', ''))

        if 'AC:L' in vector_str:
            return 1.0  # Low complexity
        elif 'AC:H' in vector_str:
            return 0.0  # High complexity
        else:
            return 0.5  # Unknown, assume medium

    def _extract_privileges_required(self, cve_data: Dict) -> float:
        """Extract privileges required (0=High, 1=Low, 2=None)"""
        vector_str = str(cve_data.get('cve_details', {}).get('cvssVector', ''))

        if 'PR:N' in vector_str:
            return 2.0  # None
        elif 'PR:L' in vector_str:
            return 1.0  # Low
        elif 'PR:H' in vector_str:
            return 0.0  # High
        else:
            return 1.0  # Default to Low

    def _extract_user_interaction(self, cve_data: Dict) -> float:
        """Extract user interaction requirement (0=Required, 1=None)"""
        vector_str = str(cve_data.get('cve_details', {}).get('cvssVector', ''))

        if 'UI:N' in vector_str:
            return 1.0  # None required
        elif 'UI:R' in vector_str:
            return 0.0  # Required
        else:
            return 0.5  # Unknown

    def _calculate_days_since_publication(self, cve_data: Dict) -> float:
        """Calculate days since CVE publication"""
        try:
            pub_date_str = cve_data.get('cve_details', {}).get('publishDate')
            if pub_date_str:
                pub_date = datetime.strptime(pub_date_str.split()[0], '%Y-%m-%d')
                days = (datetime.now() - pub_date).days
                return float(max(0, days))
        except Exception:
            pass

        # Default to 180 days if unknown
        return 180.0

    def _encode_cwe(self, cve_data: Dict) -> float:
        """Encode CWE ID to numeric value"""
        try:
            cwe_str = str(cve_data.get('cve_details', {}).get('cwe', ''))
            if cwe_str and 'CWE-' in cwe_str:
                # Extract CWE number
                cwe_num = int(cwe_str.split('CWE-')[1].split()[0].split(',')[0])
                return float(cwe_num)
        except Exception:
            pass

        return 0.0  # Unknown CWE

    def _encode_severity(self, severity: str) -> float:
        """Encode severity to numeric value"""
        severity_map = {
            'CRITICAL': 4.0,
            'HIGH': 3.0,
            'MEDIUM': 2.0,
            'LOW': 1.0,
            'UNKNOWN': 0.0
        }
        return severity_map.get(severity.upper(), 0.0)

    def predict(self, cve_data: Dict) -> Tuple[float, Dict]:
        """
        Predict EPSS score for a CVE

        Args:
            cve_data: Dictionary containing CVE information

        Returns:
            Tuple of (epss_score, metadata)
            - epss_score: Predicted exploitation probability (0-1)
            - metadata: Additional information about the prediction
        """
        if not ML_AVAILABLE or self.model is None:
            return self._rule_based_prediction(cve_data)

        try:
            # Extract features
            features = self.extract_features(cve_data)

            # Scale features if scaler is fitted
            if self.scaler is not None and hasattr(self.scaler, 'mean_'):
                features_scaled = self.scaler.transform(features)
            else:
                features_scaled = features

            # Make prediction
            epss_score = self.model.predict(features_scaled)[0]

            # Clip to valid range [0, 1]
            epss_score = float(np.clip(epss_score, 0.0, 1.0))

            metadata = {
                'method': 'ml_model',
                'features_used': features.shape[1],
                'model_type': 'GradientBoosting'
            }

            logger.info(f"Predicted EPSS {epss_score:.4f} for {cve_data.get('cve_id', 'unknown')}")
            return epss_score, metadata

        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return self._rule_based_prediction(cve_data)

    def _rule_based_prediction(self, cve_data: Dict) -> Tuple[float, Dict]:
        """
        Fallback rule-based EPSS prediction when ML model is not available

        Uses heuristics based on:
        - CVSS score
        - Attack vector
        - Exploit availability
        - CISA KEV status
        """
        try:
            cvss = float(cve_data.get('cvss_score', 0) or 0)
            exploit_exists = cve_data.get('exploit_exists', False)
            in_cisa_kev = cve_data.get('is_in_cisa_kev', False)
            is_code_exec = cve_data.get('is_code_execution', False)

            # Get attack vector
            vector_str = str(cve_data.get('cve_details', {}).get('cvssVector', ''))
            is_network = 'AV:N' in vector_str

            # Base score from CVSS (normalized to 0-1)
            base_epss = cvss / 10.0

            # Adjust based on factors
            if in_cisa_kev:
                base_epss = min(base_epss * 2.0, 0.95)  # High probability
            elif exploit_exists:
                base_epss = min(base_epss * 1.5, 0.85)
            elif is_code_exec and is_network:
                base_epss = min(base_epss * 1.3, 0.75)
            elif is_network:
                base_epss = min(base_epss * 1.1, 0.65)
            else:
                base_epss = min(base_epss * 0.8, 0.50)

            # Ensure minimum values
            if in_cisa_kev:
                base_epss = max(base_epss, 0.50)
            elif exploit_exists:
                base_epss = max(base_epss, 0.30)
            elif cvss >= 9.0:
                base_epss = max(base_epss, 0.20)

            epss_score = float(np.clip(base_epss, 0.0, 1.0))

            metadata = {
                'method': 'rule_based',
                'cvss_score': cvss,
                'exploit_exists': exploit_exists,
                'in_cisa_kev': in_cisa_kev,
                'is_network': is_network
            }

            logger.info(f"Rule-based EPSS {epss_score:.4f} for {cve_data.get('cve_id', 'unknown')}")
            return epss_score, metadata

        except Exception as e:
            logger.error(f"Error in rule-based prediction: {e}")
            # Conservative default
            return 0.05, {'method': 'default', 'error': str(e)}

    def save_model(self, path: str):
        """Save trained model to disk"""
        if not ML_AVAILABLE:
            logger.warning("Cannot save model: ML libraries not available")
            return

        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)

            model_data = {
                'model': self.model,
                'scaler': self.scaler
            }

            with open(path, 'wb') as f:
                pickle.dump(model_data, f)

            logger.info(f"Model saved to {path}")

        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def load_model(self, path: str):
        """Load trained model from disk"""
        if not ML_AVAILABLE:
            logger.warning("Cannot load model: ML libraries not available")
            return

        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)

            self.model = model_data['model']
            self.scaler = model_data['scaler']

            logger.info(f"Model loaded from {path}")

        except Exception as e:
            logger.error(f"Error loading model: {e}")

    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> Dict:
        """
        Train the EPSS prediction model

        Args:
            X_train: Training features (N x num_features)
            y_train: Training labels (N,) - EPSS scores between 0 and 1

        Returns:
            Training metrics dictionary
        """
        if not ML_AVAILABLE:
            logger.error("Cannot train model: ML libraries not available")
            return {'error': 'ML libraries not available'}

        try:
            logger.info(f"Training EPSS model with {len(X_train)} samples")

            # Fit scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X_train)

            # Train model
            self.model.fit(X_scaled, y_train)

            # Calculate training score
            train_score = self.model.score(X_scaled, y_train)

            logger.info(f"Model trained successfully. R² score: {train_score:.4f}")

            return {
                'train_score': train_score,
                'n_samples': len(X_train),
                'n_features': X_train.shape[1]
            }

        except Exception as e:
            logger.error(f"Error training model: {e}")
            return {'error': str(e)}
