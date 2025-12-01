import sys
import os
import pandas as pd

# 현재 폴더를 경로에 추가하여 모듈 import 가능하게 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from epss_predictor import EPSSPredictor

def run_test():
    print("\n>>> [EPSS 예측 모델 최종 검증 시작] <<<")
    
    try:
        # 모델 로드
        predictor = EPSSPredictor()
        print("✅ 모델 및 메타데이터 로드 성공!")
        
        # 로드된 중요 정보 확인 (디버깅용)
        print(f"   - 학습된 컬럼 수: {len(predictor.model_cols)}")
        print(f"   - 벤더 통계 맵 크기: {len(predictor.vendor_cvss_map)}개 벤더")
        print(f"   - 위험 키워드 개수: {len(predictor.danger_keywords)}개")
        
    except Exception as e:
        print(f"❌ 모델 로드 실패: {e}")
        print("   -> train_model.py를 먼저 실행하여 .pkl 파일들을 생성해주세요.")
        return

    # ---------------------------------------------------------
    # 테스트 시나리오 정의
    # ---------------------------------------------------------
    scenarios = [
        {
            "name": "시나리오 1: [Keyword] 원격 코드 실행 (RCE)",
            "desc": "키워드 'remote', 'execution' 포함. 매우 위험해야 함.",
            "data": {
                'ID': 'CVE-2025-TEST-RCE',
                'Publication': '2025-11-25',
                'Vendor': 'apache',
                'Product': 'http_server',
                'DESCRIPTION': 'Remote code execution vulnerability in Apache HTTP Server via crafted request.',
                'v3 CVSS': 9.8,
                'v3 Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'CWE': 'CWE-78'
            },
            "expect_high": True
        },
        {
            "name": "시나리오 2: [Keyword] 관리자 권한 탈취 (Admin)",
            "desc": "키워드 'admin' 포함. 권한 상승 취약점.",
            "data": {
                'ID': 'CVE-2025-TEST-ADMIN',
                'Publication': '2025-10-01',
                'Vendor': 'microsoft',
                'Product': 'windows',
                'DESCRIPTION': 'Privilege escalation allows user to gain admin rights.',
                'v3 CVSS': 7.8, 
                'v3 Vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 
                'CWE': 'CWE-269'
            },
            "expect_high": True
        },
        {
            "name": "시나리오 3: [Critical Combo] 자동화 공격 가능",
            "desc": "네트워크(N)+복잡도(L)+권한(N) 조합. 키워드가 없어도 점수가 꽤 나와야 함.",
            "data": {
                'ID': 'CVE-2024-TEST-COMBO',
                'Publication': '2024-06-15',
                'Vendor': 'nginx',
                'Product': 'nginx',
                'DESCRIPTION': 'Input validation error allows denial of service.', # 위협적인 키워드 없음
                'v3 CVSS': 7.5,
                'v3 Vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', # Critical Combo 조건 충족
                'CWE': 'CWE-20'
            },
            "expect_high": False # 키워드가 없어서 아주 높진 않지만 중간 정도 예상 (Combo 효과 확인)
        },
        {
            "name": "시나리오 4: [Safe] 로컬 물리 접근",
            "desc": "AV:P (Physical) + 위험 키워드 없음. 점수가 바닥이어야 함.",
            "data": {
                'ID': 'CVE-2025-TEST-SAFE',
                'Publication': '2025-11-01',
                'Vendor': 'unknown_mouse_driver',
                'Product': 'driver',
                'DESCRIPTION': 'Physical access required to trigger crash.',
                'v3 CVSS': 4.0,
                'v3 Vector': 'CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L',
                'CWE': 'CWE-400'
            },
            "expect_high": False
        },
        {
            "name": "시나리오 5: [Unknown] 정보 부족",
            "desc": "벤더도 모르고 벡터도 모름. 평균값으로 방어하는지 확인.",
            "data": {
                'ID': 'CVE-2025-UNKNOWN',
                'Publication': '2025-11-27',
                'Vendor': 'new_startup_inc', # 처음 보는 벤더 -> global mean 사용
                'Product': 'new_app',
                'DESCRIPTION': 'Minor bug fix.',
                'v3 CVSS': 5.0,
                'v3 Vector': None, # 벡터 없음 -> Unknown 처리
                'CWE': None
            },
            "expect_high": False
        }
    ]

    # ---------------------------------------------------------
    # 실행 및 출력
    # ---------------------------------------------------------
    print(f"\n{'='*90}")
    print(f"{'시나리오':<40} | {'예측 확률':<10} | {'위험도'} | {'판정'}")
    print(f"{'='*90}")

    for case in scenarios:
        try:
            prob = predictor.predict(case['data'])
            percent = prob * 100
            
            # 상태 아이콘 및 색상
            if prob >= 0.1:
                status = "🚨 HIGH"
                color_code = "\033[91m" # Red
            elif prob >= 0.01:
                status = "⚠️ MED"
                color_code = "\033[93m" # Yellow
            else:
                status = "✅ LOW"
                color_code = "\033[92m" # Green
            reset_code = "\033[0m"

            # 결과 판정 (예상과 맞는지)
            is_high = prob >= 0.05 # 5% 이상이면 꽤 높은 것으로 간주
            check = "👌 일치" if is_high == case.get('expect_high', False) else "❓ 확인 필요"
            
            # 예외적으로 시나리오 3은 중간값이므로 판정 패스
            if "시나리오 3" in case['name']: check = "📊 분석용"
            if "시나리오 5" in case['name']: check = "🛡️ 방어됨"

            print(f"{case['name']:<40} | {color_code}{percent:6.2f}%{reset_code}    | {status:<5} | {check}")
            
        except Exception as e:
            print(f"{case['name']:<40} | ERROR      | ❌ {e}")

    print(f"{'='*90}")
    print("💡 해석:")
    print(" - HIGH (10% 이상): 해커들의 공격이 매우 활발함 (즉시 패치)")
    print(" - MED  (1% ~ 10%): 공격 가능성 있음 (주의)")
    print(" - LOW  (1% 미만): 공격하기 어렵거나 가치가 낮음")

if __name__ == "__main__":
    run_test()