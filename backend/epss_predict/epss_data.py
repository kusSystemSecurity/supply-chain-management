# main.py
import pandas as pd

# 1. 우리가 만든 파일들에서 함수 불러오기
from .nvd_fetcher import fetch_nvd_data
from .nvd_processor import process_nvd_data
from ..cve import fetch_epss_scores

def epss_data():
    # -------------------------------------------------------
    # Step 1: NVD 데이터 수집
    # -------------------------------------------------------
    print(">>> Step 1: Starting NVD Data Collection...")
    fetch_nvd_data()
    
    # -------------------------------------------------------
    # Step 2: NVD 데이터 가공 (JSON -> DataFrame)
    # -------------------------------------------------------
    print("\n>>> Step 2: Processing NVD Data...")
    nvd_df = process_nvd_data()
    print(f"   Processed NVD Data Shape: {nvd_df.shape}")
    
    # -------------------------------------------------------
    # Step 3: EPSS 점수 수집
    # -------------------------------------------------------
    print("\n>>> Step 3: Fetching EPSS Scores...")
    # 중복 제거된 CVE ID 목록 추출
    # ID가 인덱스로 숨어있으면 컬럼으로 꺼내줌
    if 'ID' not in nvd_df.columns:
        print("⚠️ 'ID' column not found. Resetting index...")
        nvd_df.reset_index(inplace=True)
    
    # 확실하게 하기 위해 컬럼명 출력 (디버깅용)
    print(f"Current Columns: {nvd_df.columns.tolist()}")

    # CVE ID 추출
    unique_ids = nvd_df['ID'].dropna().astype(str).unique().tolist()

    # 확실하게 하기 위해 'CVE-'로 시작하는 것만 남기기
    unique_ids = [x for x in unique_ids if x.startswith('CVE-')]

    print(f"Cleaned IDs count: {len(unique_ids)}") # 개수 확인
    
    # EPSS API 호출
    epss_dict = fetch_epss_scores(unique_ids)
    
    # -------------------------------------------------------
    # Step 4: 병합 및 최종 저장
    # -------------------------------------------------------
    print("\n>>> Step 4: Merging and Saving...")
    
    # EPSS 딕셔너리를 DataFrame으로 변환
    epss_df = pd.DataFrame.from_dict(epss_dict, orient='index')
    epss_df.index.name = 'ID'
    epss_df.reset_index(inplace=True)
    
    # NVD + EPSS 병합 (Inner Join)
    final_df = pd.merge(nvd_df, epss_df, on='ID', how='inner')
    
    # CSV 저장
    output_filename = 'Final_Dataset_with_EPSS.csv'
    final_df.to_csv(output_filename, index=False)
    
    print(f"✅ All Done! Final dataset saved to: {output_filename}")
    print(final_df.head())

if __name__ == "__main__":
    epss_data()