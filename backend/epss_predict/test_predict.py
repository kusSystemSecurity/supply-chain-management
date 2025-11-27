import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
from epss_predictor import EPSSPredictor

# 1. 예측기 초기화 (모델 로드)
predictor = EPSSPredictor()

# 2. 테스트할 새로운 CVE 데이터
new_cve = {
    'ID': 'CVE-2025-9999',
    'Publication': '2025-11-20',
    'Vendor': 'microsoft',       
    'Product': 'office',         
    'v3 CVSS': 9.8,
    # 실제 벡터 문자열 예시를 넣어야 파싱이 동작합니다.
    'v3 Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' 
}

# 3. 예측 수행
try:
    probability = predictor.predict(new_cve)
    print("-" * 30)
    print(f"CVE ID: {new_cve['ID']}")
    print(f"예측된 EPSS 확률: {probability:.4f} ({probability*100:.2f}%)")
    
    if probability > 0.1:
        print("🚨 경고: 높은 위험도가 예측됩니다. 즉시 조치가 필요합니다.")
    else:
        print("✅ 정보: 현재로서는 위험도가 낮게 예측됩니다.")
    print("-" * 30)

except Exception as e:
    print(f"예측 중 에러 발생: {e}")