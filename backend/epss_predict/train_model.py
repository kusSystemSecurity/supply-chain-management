import os
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score
from category_encoders import TargetEncoder
import matplotlib.pyplot as plt
from scipy.stats import spearmanr
import joblib
import re

# ==========================================
# 1. 데이터 로드 및 청소
# ==========================================
print(">>> Loading and Cleaning Data...")
df = pd.read_csv('Final_Dataset_with_EPSS.csv')

# 'Unnamed'로 시작하는 불필요한 인덱스 컬럼들 싹 제거
df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

# EPSS 점수가 없는 행(혹시 있다면) 제거
df = df.dropna(subset=['epss_score'])

print(f"Cleaned Data Shape: {df.shape}")
print("Columns:", df.columns.tolist())

# ==========================================
# 2. 피처 엔지니어링 (Feature Engineering)
# ==========================================
print("\n>>> Feature Engineering...")

# 2-1. 날짜 처리 (오래된 취약점일수록 점수가 다를 수 있음)
df['Publication'] = pd.to_datetime(df['Publication'])
current_date = pd.to_datetime('today')
df['days_since_published'] = (current_date - df['Publication']).dt.days
df['pub_month'] = df['Publication'].dt.month # [NEW] 월(Month) 정보 추가 (계절성)

# 2-2. CWE ID 추출 및 정제
# CWE 컬럼이 지저분할 수 있으므로 첫 번째 ID만 깔끔하게 가져옵니다.
def extract_cwe(cwe_str):
    if pd.isna(cwe_str) or not isinstance(cwe_str, str):
        return 'Unknown'
    # 숫자만 추출하거나 'CWE-123' 형식 유지
    match = re.search(r'(CWE-\d+)', cwe_str)
    if match:
        return match.group(1)
    return 'Unknown'

df['CWE_Clean'] = df['CWE'].apply(extract_cwe)

# 2-3. 위험 키워드 추출 (Simple NLP)
# 설명(Description)에 이 단어들이 있으면 위험도가 급상승합니다.
danger_keywords = ['remote', 'execution', 'code', 'command', 'admin', 'root', 'unauthenticated', 'injection', 'overflow']

print("   Extracting Danger Keywords...")
# 대소문자 무시하고 단어가 포함되어 있으면 1, 없으면 0
for word in danger_keywords:
    df[f'keyword_{word}'] = df['DESCRIPTION'].str.contains(word, case=False, na=False).astype(int)

# 2-4. [NEW] 벤더/제품 빈도수 (Frequency Encoding)
# "해커들은 인기 있는 제품을 노린다"는 가설
print("   Calculating Vendor Popularity...")
vendor_counts = df['Vendor'].value_counts()
df['vendor_count'] = df['Vendor'].map(vendor_counts).fillna(0)

# 2-4. CVSS v3 벡터 파싱 (핵심 정보 추출)
# 예: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

def parse_cvss_vector(vector_str):
    if pd.isna(vector_str) or not isinstance(vector_str, str):
        return {}
    
    # 정규식으로 항목 추출 (AV:N, AC:L 등)
    parts = vector_str.split('/')
    parsed = {}
    for part in parts:
        if ':' in part:
            key, val = part.split(':')
            parsed[key] = val
    return parsed

# 벡터 분해해서 새로운 컬럼으로 추가
vector_df = df['v3 Vector'].apply(parse_cvss_vector).apply(pd.Series)
# 필요한 핵심 항목만 선택 (Attack Vector, Complexity, Privileges, User Interaction, Scope)
cols_to_use = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
vector_df = vector_df.reindex(columns=cols_to_use, fill_value='Unknown')

# 원본 데이터와 합치기
df = pd.concat([df, vector_df], axis=1)

# 치명적 조합 (Easy RCE Flag)
# ----------------------------------------------------------------
# AV:N (네트워크) + AC:L (복잡도 낮음) + PR:N (권한 필요없음)
# 이 조합은 해커가 가장 좋아하는 "자동화 공격" 대상
print("   Creating Interaction Features...")
df['is_critical_combo'] = (
    (df['AV'] == 'N') & 
    (df['AC'] == 'L') & 
    (df['PR'] == 'N')
).astype(int)

# ----------------------------------------------------------------
# 설명글 길이 (Meta Feature)
# ----------------------------------------------------------------
print("   Calculating Description Length...")
df['desc_length'] = df['DESCRIPTION'].str.len().fillna(0)

# ==========================================
# 3. 학습 데이터 준비
# ==========================================
# 학습에 사용할 피처 선택
features = [
    'v3 CVSS',             # 기본 점수
    'days_since_published',# 경과 일수
    'Vendor',      # 벤더 위험도
    'Product',     # 제품 위험도
    'CWE_Clean',         # 취약점 종류
    'vendor_count',      # 벤더 인기도
    'pub_month',
    'desc_length',
    'is_critical_combo'
] 
features += [f'keyword_{word}' for word in danger_keywords] # [NEW] 위험 키워드들
# 위에서 뽑은 벡터 항목들(AV, AC 등)을 One-Hot Encoding
categorical_features = ['AV', 'AC', 'PR', 'UI', 'S'] # C, I, A는 점수에 이미 반영됨
X = df[features]
X = pd.concat([X, pd.get_dummies(df[categorical_features], drop_first=True)], axis=1)

# 타겟 (EPSS Score)
y = df['epss_score']

# *** Logit 변환 *** (0~1 사이 확률값을 -무한대~+무한대 로 변환하여 회귀 성능 향상)
epsilon = 1e-6
y_transformed = np.log(np.clip(y, epsilon, 1-epsilon) / (1 - np.clip(y, epsilon, 1-epsilon)))

# Train/Test 분리
X_train, X_test, y_train, y_test = train_test_split(X, y_transformed, test_size=0.2, random_state=42)
# 평가용 원본 y (Logit 변환 전)
_, _, y_train_orig, y_test_orig = train_test_split(X, y, test_size=0.2, random_state=42)

print("   Calculating Vendor Stats (Train set only)...")

# Train 데이터의 Vendor별 CVSS 평균 계산
train_indices = X_train.index
train_vendor_stats = df.loc[train_indices].groupby('Vendor')['v3 CVSS'].mean()
global_cvss_mean = df.loc[train_indices]['v3 CVSS'].mean()

# Dictionary로 변환 (저장하기 위해)
vendor_cvss_map = train_vendor_stats.to_dict()

# Train에 매핑
X_train['vendor_mean_cvss'] = X_train['Vendor'].map(vendor_cvss_map).fillna(global_cvss_mean)

# Test에 매핑 (Train에서 구한 맵을 그대로 사용!)
X_test['vendor_mean_cvss'] = X_test['Vendor'].map(vendor_cvss_map).fillna(global_cvss_mean)

print("   Stats Feature Created.")

# 3-3. Target Encoding 적용
print("   Applying Target Encoding safely...")

# min_samples_leaf=20: 데이터가 20개 미만인 벤더는 전체 평균값으로 스무딩
encoder = TargetEncoder(cols=['Vendor', 'Product', 'CWE_Clean'], min_samples_leaf=20, smoothing=10)

# 학습 데이터(X_train)로만 학습(fit)하고 변환(transform)
X_train = encoder.fit_transform(X_train, y_train_orig) # 주의: y는 변환 전 원본 점수(0~1)를 쓰는 게 일반적임

# 테스트 데이터(X_test)는 학습된 규칙으로 변환(transform)만 함
X_test = encoder.transform(X_test)

print("   Encoding Completed.")

# ==========================================
# 4. 균형 잡힌 가중치 적용 (Balanced Tuning)
# ==========================================
print("\n>>> Training XGBoost Model with Balanced Weights...")

sample_weights = 1 + (y_train_orig * 10)

model = xgb.XGBRegressor(
    n_estimators=1000,
    learning_rate=0.03,
    max_depth=7,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=0.1,           # L1 규제: 불필요한 노이즈 무시
    reg_lambda=1.0,          # L2 규제: 과도한 점수 튀기 방지
    n_jobs=-1,
    random_state=42,
    objective='reg:squarederror'
)

# eval_set을 추가하여 학습 중간중간 점수를 기록합니다.
model.fit(
    X_train, y_train, 
    sample_weight=sample_weights,
    eval_set=[(X_train, y_train), (X_test, y_test)], # Train과 Test 둘 다 감시
    verbose=100 # 100번마다 로그 출력
)

# ==========================================
# 5. 예측 및 평가
# ==========================================
print("\n>>> Evaluating...")

# 예측 (Logit 값이 나오므로 Sigmoid로 다시 0~1 복원)
y_pred_logit = model.predict(X_test)
y_pred = 1 / (1 + np.exp(-y_pred_logit))

# 성능 지표
mae = mean_absolute_error(y_test_orig, y_pred)
r2 = r2_score(y_test_orig, y_pred)
spearman_corr, _ = spearmanr(y_test_orig, y_pred)

print(f"MAE (평균 오차): {mae:.4f}")
print(f"R2 Score (설명력): {r2:.4f}")
print(f"Spearman Corr (순위) : {spearman_corr:.4f}")

# 결과 샘플 확인
results = pd.DataFrame({'Actual': y_test_orig, 'Predicted': y_pred})
print("\n[예측 결과 샘플]")
print(results.head(10))

# 변수 중요도 시각화 (어떤 게 EPSS에 가장 큰 영향을 주는지?)
xgb.plot_importance(model, max_num_features=10)
plt.title("Top 10 Important Features for EPSS Prediction")
plt.show() # 혹은 plt.savefig('feature_importance.png')

def plot_actual_vs_predicted(y_true, y_pred):
    plt.figure(figsize=(10, 10))
    
    # 1. 산점도 그리기 (투명도 조절하여 밀집도 확인)
    plt.scatter(y_true, y_pred, alpha=0.3, color='blue', s=10, label='Data Points')
    
    # 2. 완벽한 예측선 (y=x) 그리기 (이 선 위에 점이 많을수록 좋음)
    plt.plot([0, 1], [0, 1], color='red', linestyle='--', label='Perfect Prediction')
    
    plt.title('Actual vs Predicted EPSS Scores')
    plt.xlabel('Actual EPSS (Fact)')
    plt.ylabel('Predicted EPSS (Model)')
    plt.xlim(0, 1)
    plt.ylim(0, 1)
    plt.legend()
    plt.grid(True)
    plt.show()

# 위에서 학습한 결과(y_test_orig, y_pred)를 넣어서 실행
plot_actual_vs_predicted(y_test_orig, y_pred)

def plot_rank_correlation(y_true, y_pred):
    # 데이터를 등수(Rank)로 변환
    # (점수가 높을수록 1등, method='min'은 동점 처리 방식)
    true_ranks = pd.Series(y_true).rank(ascending=False, method='min')
    pred_ranks = pd.Series(y_pred).rank(ascending=False, method='min')
    
    plt.figure(figsize=(10, 6))
    
    # 데이터가 너무 많으면 점이 겹치므로 투명도 조절 및 샘플링 고려
    plt.scatter(true_ranks, pred_ranks, alpha=0.1, s=3, color='purple')
    
    # 완벽한 예측선 (y=x)
    max_rank = max(true_ranks.max(), pred_ranks.max())
    plt.plot([1, max_rank], [1, max_rank], 'r--', label='Perfect Ranking')
    
    plt.title(f'Rank Correlation (Spearman: {spearman_corr:.4f})')
    plt.xlabel('Actual Rank')
    plt.ylabel('Predicted Rank')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.show() # 또는 plt.savefig('rank_correlation.png')

print("\n>>> Drawing Rank Plot...")
plot_rank_correlation(y_test_orig, y_pred)

# 변수 중요도 확인 (새로 넣은 게 쓸모 있었나?)
print("\n[Top 10 Feature Importance]")
importance = pd.Series(model.feature_importances_, index=X_train.columns).sort_values(ascending=False)
print(importance.head(10))

print("\n[과적합 자가진단]")
train_pred = model.predict(X_train)
test_pred = model.predict(X_test)

# Logit -> Sigmoid 복원
train_score = r2_score(y_train_orig, 1 / (1 + np.exp(-train_pred)))
test_score = r2_score(y_test_orig, 1 / (1 + np.exp(-test_pred)))

print(f"Train R2 : {train_score:.4f}")
print(f"Test  R2 : {test_score:.4f}")

diff = train_score - test_score
if diff > 0.15:
    print(f"경고: 차이가 {diff:.4f}로 큽니다. 과적합 의심! (max_depth를 줄이세요)")
elif diff < 0.05:
    print(f"안심: 차이가 {diff:.4f}로 매우 작습니다. 학습이 아주 잘 되었습니다.")
else:
    print(f"주의: 차이가 {diff:.4f}입니다. 약간의 과적합이 있지만 허용 범위입니다.")

print("\n>>> Saving Model & Metadata...")

# ==========================================
# 6. 모델 및 인코더 저장
# ==========================================
print("\n>>> Saving Model & Encoder...")

SAVE_DIR = 'backend/epss_predict'

if not os.path.exists(SAVE_DIR):
    os.makedirs(SAVE_DIR, exist_ok=True)

model_path = os.path.join(SAVE_DIR, 'xgboost_epss_model.pkl')
encoder_path = os.path.join(SAVE_DIR, 'target_encoder.pkl')
meta_path = os.path.join(SAVE_DIR, 'model_metadata.pkl')

# 1. 모델 저장
joblib.dump(model, model_path)

# 2. 인코더 저장 (딕셔너리 대신 이거 하나면 끝!)
# 이 파일 안에 벤더별 평균값, 스무딩 로직 등이 다 들어있음
joblib.dump(encoder, encoder_path)

# 3. 추가 메타데이터 (컬럼 순서 맞추기용)
# 메타데이터에 'vendor_cvss_map' 추가
meta_data = {
    'columns': X_train.columns.tolist(),
    'vendor_cvss_map': vendor_cvss_map,   # 벤더별 평균 점수표
    'global_cvss_mean': global_cvss_mean  # 전체 평균 점수
}
joblib.dump(meta_data, meta_path)

print("Save Complete!: xgboost_epss_model.pkl, target_encoder.pkl, model_metadata.pkl")