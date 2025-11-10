# EPSS Prediction Model - Implementation Guide

## Overview

The EPSS (Exploit Prediction Scoring System) prediction model predicts the probability that a CVE will be exploited in the wild within the next 30 days. This is a critical component for threat prioritization.

## What is EPSS?

EPSS is a data-driven effort to estimate the likelihood (probability) that a software vulnerability will be exploited in the wild. The EPSS model produces scores between 0 and 1 (0% to 100% probability).

- **Low EPSS (< 0.10)**: Low probability of exploitation
- **Medium EPSS (0.10 - 0.40)**: Moderate probability
- **High EPSS (0.40 - 0.70)**: High probability
- **Critical EPSS (> 0.70)**: Very high probability

## Model Architecture

Our EPSS predictor uses a **Gradient Boosting Regressor** with the following features:

### Features (13 total):

1. **CVSS Base Score** (0-10) - Overall severity
2. **Exploitability Score** (0-10) - How easy to exploit
3. **Impact Score** (0-10) - Severity of impact
4. **Attack Vector** (0-3):
   - 0 = Physical
   - 1 = Local
   - 2 = Adjacent Network
   - 3 = Network
5. **Attack Complexity** (0-1):
   - 0 = High complexity
   - 1 = Low complexity
6. **Privileges Required** (0-2):
   - 0 = High privileges
   - 1 = Low privileges
   - 2 = None
7. **User Interaction** (0-1):
   - 0 = Required
   - 1 = None
8. **Days Since Publication** - Age of vulnerability
9. **CWE ID** - Weakness category
10. **Severity** (0-4) - UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL
11. **Is Code Execution** (0/1) - Binary flag
12. **Exploit Exists** (0/1) - Public exploit available
13. **In CISA KEV** (0/1) - Listed in CISA Known Exploited Vulnerabilities

## Implementation

### 1. Basic Usage

```python
from app.integrations.epss_predictor import EPSSPredictor

# Initialize predictor
predictor = EPSSPredictor()

# Prepare CVE data
cve_data = {
    'cve_id': 'CVE-2024-12345',
    'cvss_score': 9.8,
    'cve_details': {
        'maxCvssExploitabilityScore': 3.9,
        'maxCvssImpactScore': 5.9,
        'cvssVector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'publishDate': '2024-01-15',
        'cwe': 'CWE-787'
    },
    'is_code_execution': True,
    'exploit_exists': False,
    'is_in_cisa_kev': False,
    'severity': 'CRITICAL'
}

# Predict EPSS score
epss_score, metadata = predictor.predict(cve_data)

print(f"Predicted EPSS: {epss_score:.4f}")
print(f"Method: {metadata['method']}")
```

### 2. Training the Model

```python
from app.integrations.train_epss_model import train_epss_model, generate_synthetic_training_data
import numpy as np
from sklearn.model_selection import train_test_split

# Option 1: Generate synthetic data for testing
X, y = generate_synthetic_training_data(n_samples=5000)

# Option 2: Load real EPSS data (from FIRST.org API)
# X, y = load_real_epss_data()

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
predictor = train_epss_model(
    X_train, y_train,
    X_test, y_test,
    save_path="models/epss_predictor.pkl"
)
```

### 3. Automatic Integration with CVE Enrichment

The EPSS predictor is automatically used when enriching CVEs:

```python
from app.integrations.cvedetails import CVEDetailsClient

client = CVEDetailsClient(api_key="your_key")

# Enrich vulnerability
vulnerability = {
    "cve_id": "CVE-2024-12345",
    "package_name": "example-package",
    "severity": "HIGH"
}

# This will automatically use EPSS prediction if CVEDetails doesn't have EPSS
enriched = client.enrich_vulnerability(vulnerability)

print(f"EPSS Score: {enriched['epss_score']}")
print(f"Was Predicted: {enriched.get('epss_predicted', False)}")
print(f"Method: {enriched.get('epss_prediction_method', 'N/A')}")
```

## Training with Real Data

### Step 1: Download EPSS Historical Data

```bash
# EPSS data is available from FIRST.org
curl "https://api.first.org/data/v1/epss?date=2024-01-01" -o epss_2024-01-01.json

# Or download CSV format
curl "https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz" -o epss.csv.gz
gunzip epss.csv.gz
```

### Step 2: Download NVD CVE Data

```bash
# NVD provides CVE details with CVSS vectors
curl "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz" -o nvd-2024.json.gz
gunzip nvd-2024.json.gz
```

### Step 3: Prepare Training Dataset

Create a CSV with columns:
```
cve_id,cvss_score,exploitability_score,impact_score,attack_vector,
attack_complexity,privileges_required,user_interaction,days_since_pub,
cwe,severity,is_code_execution,exploit_exists,is_in_cisa_kev,epss_score
```

### Step 4: Train Model

```bash
cd backend/app/integrations
python train_epss_model.py
```

## Prediction Methods

The predictor uses two methods:

### 1. Machine Learning (Primary)
When a trained model is available, uses Gradient Boosting with 13 features.

**Advantages:**
- More accurate predictions
- Learns complex patterns from historical data
- Can capture interactions between features

**Requirements:**
- scikit-learn installed
- Trained model file available

### 2. Rule-Based (Fallback)
When ML is not available, uses heuristic rules:

```python
base_epss = cvss_score / 10.0

# Adjust for factors
if in_cisa_kev:
    epss *= 2.0  # Known to be exploited
elif exploit_exists:
    epss *= 1.5  # Public exploit available
elif is_code_execution and is_network:
    epss *= 1.3  # Remote code execution
elif is_network:
    epss *= 1.1  # Network accessible

# Clip to [0, 1] range
```

**Advantages:**
- Works without training data
- No ML dependencies required
- Provides reasonable estimates

## Model Evaluation

After training, the model is evaluated with:

### Metrics:
- **MSE (Mean Squared Error)**: Average squared prediction error
- **MAE (Mean Absolute Error)**: Average absolute prediction error
- **R² Score**: Proportion of variance explained

### Expected Performance:
- **R² > 0.70**: Good predictive power
- **MAE < 0.10**: Average error within ±10%
- **MSE < 0.02**: Low squared error

## Integration with SecureChain AI

### Automatic Usage

1. **During CVE Enrichment:**
   ```
   Trivy Scan → Extract CVE IDs
   ↓
   CVEDetails API → Fetch CVE details
   ↓
   If EPSS missing → EPSS Predictor → Predict EPSS
   ↓
   AI Agents → Use EPSS in prioritization
   ```

2. **In AI Agents:**
   The predicted EPSS score is used by:
   - **Prioritization Agent**: Weights EPSS at 25% in priority score
   - **Supply Chain Agent**: Identifies high-risk CVEs across layers
   - **Remediation Agent**: Prioritizes fixes for high EPSS scores

## File Structure

```
backend/
├── app/
│   └── integrations/
│       ├── epss_predictor.py       # Main predictor class
│       ├── train_epss_model.py     # Training script
│       └── cvedetails.py           # Integration point
└── models/
    └── epss_predictor.pkl          # Trained model (after training)
```

## Configuration

### Environment Variables

No special configuration needed. The model is automatically used when:
1. A vulnerability is being enriched
2. EPSS score is not available from CVEDetails API

### Model Location

Default: `models/epss_predictor.pkl`

To use a custom path:
```python
predictor = EPSSPredictor(model_path="/path/to/model.pkl")
```

## Troubleshooting

### Issue: "ML libraries not available"
**Solution:** Install scikit-learn
```bash
pip install scikit-learn numpy pandas
```

### Issue: "Model file not found"
**Solution:** Either:
1. Train a model: `python train_epss_model.py`
2. Use rule-based prediction (automatic fallback)

### Issue: "Prediction seems inaccurate"
**Solution:**
1. Retrain with more recent data
2. Increase training samples
3. Verify feature extraction is correct

### Issue: "Import errors"
**Solution:** Ensure you're in the correct directory
```bash
cd backend/app/integrations
python -c "from epss_predictor import EPSSPredictor; print('OK')"
```

## API Endpoint

Test the EPSS predictor via API:

```bash
# Predict EPSS for a CVE
curl -X POST "http://localhost:8000/api/ai/prioritize?cve_id=CVE-2024-12345" \
  -H "Content-Type: application/json"
```

The response will include the EPSS score and whether it was predicted:
```json
{
  "priorityScore": 9,
  "likelihood": "High",
  "epss_score": 0.4567,
  "epss_predicted": true,
  "epss_prediction_method": "ml_model"
}
```

## Future Improvements

1. **Deep Learning**: Use neural networks for better accuracy
2. **Temporal Features**: Add time-series features (exploit trends)
3. **Ensemble Methods**: Combine multiple models
4. **Online Learning**: Update model with new EPSS data daily
5. **Feature Engineering**: Add more contextual features
6. **Uncertainty Quantification**: Provide confidence intervals

## References

- **EPSS Project**: https://www.first.org/epss/
- **EPSS API**: https://api.first.org/data/v1/epss
- **NVD**: https://nvd.nist.gov/
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities

## Support

For questions or issues with the EPSS predictor:
1. Check logs: `docker-compose logs -f backend | grep EPSS`
2. Review training metrics in `epss_predictions.png`
3. Verify feature extraction with debug logging

---

**Note**: The EPSS predictor is now fully integrated into the SecureChain AI platform. CVEs without EPSS scores from CVEDetails will automatically get predicted scores.
