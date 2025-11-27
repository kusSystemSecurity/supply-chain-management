import joblib
import pandas as pd
import numpy as np
import re
import os

model_path = os.path.join(os.path.dirname(__file__), 'xgboost_epss_model.pkl')
meta_path = os.path.join(os.path.dirname(__file__), 'model_metadata.pkl')
encoder_path = os.path.join(os.path.dirname(__file__), 'target_encoder.pkl')

class EPSSPredictor:
    def __init__(self, model_path=model_path, meta_path=meta_path, encoder_path=encoder_path):
        print(f"Loading model from {model_path}...")
        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)
        self.meta = joblib.load(meta_path)
        
        # 학습 때 사용된 컬럼 순서
        self.model_cols = self.meta['columns']
        
        # 위험 키워드 목록 (학습 때와 동일해야 함)
        self.danger_keywords = ['remote', 'execution', 'code', 'command', 'admin', 'root', 'unauthenticated', 'injection']

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

    def _extract_cwe(self, cwe_str):
        if pd.isna(cwe_str) or not isinstance(cwe_str, str):
            return 'Unknown'
        match = re.search(r'(CWE-\d+)', cwe_str)
        if match:
            return match.group(1)
        return 'Unknown'

    def predict(self, new_data_dict):
        # 1. 입력 데이터 DF 변환
        input_df = pd.DataFrame([new_data_dict])

        # A. 날짜 계산
        if 'Publication' in input_df.columns:
            pub_date = pd.to_datetime(input_df['Publication'])
            input_df['days_since_published'] = (pd.to_datetime('today') - pub_date).dt.days
        else:
            input_df['days_since_published'] = 0

        # B. CWE ID 추출
        if 'CWE' in input_df.columns:
            input_df['CWE_Clean'] = input_df['CWE'].apply(self._extract_cwe)
        else:
            input_df['CWE_Clean'] = 'Unknown'

        # C. 위험 키워드 추출
        # Description이 없으면 빈 문자열로 처리
        desc_text = input_df.iloc[0].get('DESCRIPTION', '')
        if not isinstance(desc_text, str):
            desc_text = ''
            
        for word in self.danger_keywords:
            # 대소문자 무시하고 포함 여부 (1 or 0)
            col_name = f'keyword_{word}'
            input_df[col_name] = 1 if word.lower() in desc_text.lower() else 0

        # D. Vendor Count (실시간 예측에선 알 수 없으므로 0 처리)
        # (학습 때는 전체 통계가 있었지만, 단건 예측에선 0으로 채워도 무방함)
        input_df['vendor_count'] = 0 

        # E. CVSS Vector 파싱
        if 'v3 Vector' in input_df.columns:
            vector_dict = self._parse_cvss_vector(input_df.iloc[0]['v3 Vector'])
            for key, val in vector_dict.items():
                # 예: AV:N -> AV_N 컬럼 생성 (학습 데이터와 포맷 맞춤)
                col_name = f"{key}_{val}"
                input_df[col_name] = 1

        # ---------------------------------------------------------
        # 2. 컬럼 줄세우기 (Column Alignment)
        # ---------------------------------------------------------
        inference_df = pd.DataFrame(0, index=[0], columns=self.model_cols)
        
        # 공통 컬럼 복사
        common_cols = list(set(input_df.columns) & set(self.model_cols))
        inference_df[common_cols] = input_df[common_cols]
        
        # ---------------------------------------------------------
        # 3. Target Encoding 적용
        # ---------------------------------------------------------
        encoded_df = self.encoder.transform(inference_df)
        
        # ---------------------------------------------------------
        # 4. 예측 실행
        # ---------------------------------------------------------
        pred_logit = self.model.predict(encoded_df)
        
        # 7. Logit -> Probability 변환 (Sigmoid)
        pred_prob = 1 / (1 + np.exp(-pred_logit))
        
        return float(pred_prob[0])