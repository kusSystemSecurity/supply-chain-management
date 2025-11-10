"""Training script for EPSS prediction model"""
import logging
import numpy as np
import pandas as pd
from typing import Tuple
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import matplotlib.pyplot as plt
from epss_predictor import EPSSPredictor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_training_data(data_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and prepare training data for EPSS model

    Expected CSV format:
    cve_id,cvss_score,exploitability_score,impact_score,attack_vector,
    attack_complexity,privileges_required,user_interaction,days_since_pub,
    cwe,severity,is_code_execution,exploit_exists,is_in_cisa_kev,epss_score

    Args:
        data_path: Path to training data CSV file

    Returns:
        Tuple of (X_train, y_train)
    """
    logger.info(f"Loading training data from {data_path}")

    try:
        df = pd.read_csv(data_path)

        # Feature columns
        feature_cols = [
            'cvss_score', 'exploitability_score', 'impact_score',
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'days_since_pub', 'cwe', 'severity',
            'is_code_execution', 'exploit_exists', 'is_in_cisa_kev'
        ]

        # Target column
        target_col = 'epss_score'

        # Extract features and target
        X = df[feature_cols].values
        y = df[target_col].values

        logger.info(f"Loaded {len(X)} samples with {X.shape[1]} features")

        return X, y

    except Exception as e:
        logger.error(f"Error loading training data: {e}")
        raise


def generate_synthetic_training_data(n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data for demonstration purposes

    In production, use real EPSS historical data from:
    https://api.first.org/data/v1/epss

    Args:
        n_samples: Number of samples to generate

    Returns:
        Tuple of (X, y)
    """
    logger.info(f"Generating {n_samples} synthetic training samples")

    np.random.seed(42)

    # Generate features
    cvss_scores = np.random.uniform(0, 10, n_samples)
    exploitability = cvss_scores * np.random.uniform(0.3, 0.5, n_samples)
    impact = cvss_scores * np.random.uniform(0.5, 0.7, n_samples)
    attack_vector = np.random.choice([0, 1, 2, 3], n_samples, p=[0.05, 0.15, 0.10, 0.70])
    attack_complexity = np.random.choice([0, 1], n_samples, p=[0.3, 0.7])
    privileges = np.random.choice([0, 1, 2], n_samples, p=[0.2, 0.3, 0.5])
    user_interaction = np.random.choice([0, 1], n_samples, p=[0.4, 0.6])
    days_since_pub = np.random.exponential(180, n_samples)
    cwe = np.random.choice([0, 79, 89, 119, 200, 287, 352, 416, 787], n_samples)
    severity = np.clip((cvss_scores / 2.5).astype(int), 0, 4)
    is_code_exec = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
    exploit_exists = np.random.choice([0, 1], n_samples, p=[0.85, 0.15])
    in_cisa_kev = np.random.choice([0, 1], n_samples, p=[0.97, 0.03])

    # Stack features
    X = np.column_stack([
        cvss_scores, exploitability, impact, attack_vector,
        attack_complexity, privileges, user_interaction, days_since_pub,
        cwe, severity, is_code_exec, exploit_exists, in_cisa_kev
    ])

    # Generate target EPSS scores with realistic distribution
    base_epss = cvss_scores / 10.0
    base_epss *= (1 + attack_vector / 4.0)  # Network attacks more likely
    base_epss *= (1 + attack_complexity * 0.2)  # Low complexity more likely
    base_epss *= (1 + privileges / 3.0)  # No privileges more likely
    base_epss *= (1 + user_interaction * 0.3)  # No UI more likely
    base_epss *= np.exp(-days_since_pub / 365)  # Decay over time
    base_epss[exploit_exists == 1] *= 2.5
    base_epss[in_cisa_kev == 1] *= 3.0
    base_epss[is_code_exec == 1] *= 1.5

    # Add noise and clip to [0, 1]
    y = np.clip(base_epss + np.random.normal(0, 0.05, n_samples), 0, 1)

    logger.info("Synthetic data generated successfully")

    return X, y


def train_epss_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray = None,
    y_test: np.ndarray = None,
    save_path: str = "models/epss_predictor.pkl"
) -> EPSSPredictor:
    """
    Train EPSS prediction model

    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Test features (optional)
        y_test: Test labels (optional)
        save_path: Path to save trained model

    Returns:
        Trained EPSSPredictor instance
    """
    logger.info("Initializing EPSS predictor")

    predictor = EPSSPredictor()

    # Train model
    metrics = predictor.train(X_train, y_train)
    logger.info(f"Training metrics: {metrics}")

    # Evaluate on test set if provided
    if X_test is not None and y_test is not None:
        logger.info("Evaluating on test set")

        # Predict
        y_pred = []
        for i in range(len(X_test)):
            # Create mock CVE data for prediction
            cve_data = {
                'cvss_score': X_test[i, 0],
                'cve_details': {
                    'maxCvssExploitabilityScore': X_test[i, 1],
                    'maxCvssImpactScore': X_test[i, 2],
                    'cvssVector': f"AV:{'N' if X_test[i, 3] == 3 else 'L'}/AC:{'L' if X_test[i, 4] == 1 else 'H'}"
                },
                'is_code_execution': X_test[i, 10] == 1,
                'exploit_exists': X_test[i, 11] == 1,
                'is_in_cisa_kev': X_test[i, 12] == 1
            }
            pred, _ = predictor.predict(cve_data)
            y_pred.append(pred)

        y_pred = np.array(y_pred)

        # Calculate metrics
        mse = mean_squared_error(y_test, y_pred)
        mae = mean_absolute_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)

        logger.info(f"Test MSE: {mse:.6f}")
        logger.info(f"Test MAE: {mae:.6f}")
        logger.info(f"Test R²: {r2:.4f}")

        # Plot predictions vs actual
        plt.figure(figsize=(10, 6))
        plt.scatter(y_test, y_pred, alpha=0.5)
        plt.plot([0, 1], [0, 1], 'r--', lw=2)
        plt.xlabel('Actual EPSS Score')
        plt.ylabel('Predicted EPSS Score')
        plt.title(f'EPSS Prediction Results (R²={r2:.4f})')
        plt.grid(True)
        plt.savefig('epss_predictions.png')
        logger.info("Saved prediction plot to epss_predictions.png")

    # Save model
    predictor.save_model(save_path)
    logger.info(f"Model saved to {save_path}")

    return predictor


def main():
    """Main training script"""
    logger.info("Starting EPSS model training")

    # Option 1: Load real training data
    # X, y = load_training_data('path/to/epss_training_data.csv')

    # Option 2: Generate synthetic data for demonstration
    X, y = generate_synthetic_training_data(n_samples=5000)

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    logger.info(f"Training set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")

    # Train model
    predictor = train_epss_model(
        X_train, y_train,
        X_test, y_test,
        save_path="../../../models/epss_predictor.pkl"
    )

    logger.info("Training complete!")

    # Test a few predictions
    logger.info("\nTesting predictions on sample CVEs:")

    test_cves = [
        {
            'cve_id': 'CVE-2024-TEST-1',
            'cvss_score': 9.8,
            'cve_details': {
                'maxCvssExploitabilityScore': 3.9,
                'maxCvssImpactScore': 5.9,
                'cvssVector': 'AV:N/AC:L/PR:N/UI:N',
                'publishDate': '2024-01-01'
            },
            'is_code_execution': True,
            'exploit_exists': False,
            'is_in_cisa_kev': False,
            'severity': 'CRITICAL'
        },
        {
            'cve_id': 'CVE-2024-TEST-2',
            'cvss_score': 5.5,
            'cve_details': {
                'maxCvssExploitabilityScore': 1.8,
                'maxCvssImpactScore': 3.6,
                'cvssVector': 'AV:L/AC:L/PR:L/UI:N',
                'publishDate': '2023-06-01'
            },
            'is_code_execution': False,
            'exploit_exists': False,
            'is_in_cisa_kev': False,
            'severity': 'MEDIUM'
        }
    ]

    for cve in test_cves:
        epss_score, metadata = predictor.predict(cve)
        logger.info(f"{cve['cve_id']}: EPSS = {epss_score:.4f} (method: {metadata['method']})")


if __name__ == "__main__":
    main()
