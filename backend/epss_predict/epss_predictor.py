import os
import joblib
import pandas as pd
import numpy as np

model_path = os.path.join(os.path.dirname(__file__), 'xgboost_epss_model.pkl')
meta_path = os.path.join(os.path.dirname(__file__), 'model_metadata.pkl')
encoder_path = os.path.join(os.path.dirname(__file__), 'target_encoder.pkl')

class EPSSPredictor:
    def __init__(self, model_path=model_path, meta_path=meta_path, encoder_path=encoder_path):
        # 클래스가 생성될 때 모델과 메타데이터를 로드합니다.
        print("Loading model and metadata...")
        self.model = joblib.load(model_path)
        self.meta = joblib.load(meta_path)
        self.encoder = joblib.load(encoder_path)
        self.model_cols = self.meta['columns']
        
    def _parse_cvss_vector(self, vector_str):
        """CVSS 벡터 문자열 파싱 (내부 함수)"""
        if pd.isna(vector_str) or not isinstance(vector_str, str):
            return {}
        parts = vector_str.split('/')
        parsed = {}
        for part in parts:
            if ':' in part:
                key, val = part.split(':')
                parsed[key] = val
        return parsed

    def predict(self, new_data_dict):
        """
        새로운 CVE 데이터 딕셔너리를 받아 EPSS 확률을 예측
        """
        # 1. 입력 데이터를 DataFrame으로 변환
        input_df = pd.DataFrame([new_data_dict])
        
        # 2. 날짜 계산 (days_since_published)
        if 'Publication' in input_df.columns:
            pub_date = pd.to_datetime(input_df['Publication'])
            input_df['days_since_published'] = (pd.to_datetime('today') - pub_date).dt.days
        else:
            input_df['days_since_published'] = 0 # 없으면 0 처리 (혹은 에러)
        
        # 3. CVSS Vector 파싱 및 One-Hot Encoding 처리
        if 'v3 Vector' in input_df.columns:
            vector_dict = self._parse_cvss_vector(input_df.iloc[0]['v3 Vector'])
            for key, val in vector_dict.items():
                # 예: AV:N -> AV_N 컬럼 생성 (학습 데이터와 포맷 맞춤)
                col_name = f"{key}_{val}"
                input_df[col_name] = 1

        # 4. 컬럼 줄세우기
        # 학습 때 썼던 컬럼들만 남기고, 없는 컬럼은 0으로 채워서 순서를 똑같이 맞춤
        inference_df = pd.DataFrame(0, index=[0], columns=self.model_cols)
        
        # 공통된 컬럼 값 업데이트
        common_cols = list(set(input_df.columns) & set(self.model_cols))
        inference_df[common_cols] = input_df[common_cols]

        # 5. Target Encoding
        encoded_df = self.encoder.transform(inference_df)
        
        # 6. 예측 실행
        pred_logit = self.model.predict(encoded_df)
        
        # 7. Logit -> Probability 변환 (Sigmoid)
        pred_prob = 1 / (1 + np.exp(-pred_logit))
        
        return float(pred_prob[0])