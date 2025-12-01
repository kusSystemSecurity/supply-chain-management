import pandas as pd
from tqdm import tqdm
import os
import jq
import json

# Combined jq query to extract all relevant vulnerability data
vuln_query = jq.compile("""
.vulnerabilities[] | {
    "ID": .cve.id,
    "Publication": .cve.published,
    "ASSIGNER": .cve.sourceIdentifier,
    "DESCRIPTION": [.cve.descriptions[].value],
    "v2 CVSS": (if .cve.metrics.cvssMetricV2 and (.cve.metrics.cvssMetricV2 | length > 0) 
                    then .cve.metrics.cvssMetricV2[0].cvssData.baseScore 
                    else null end),
    "v2 Exploitability Score": (if .cve.metrics.cvssMetricV2 and (.cve.metrics.cvssMetricV2 | length > 0) 
                                    then .cve.metrics.cvssMetricV2[0].exploitabilityScore 
                                    else null end),
    "v2 Vector": (if .cve.metrics.cvssMetricV2 and (.cve.metrics.cvssMetricV2 | length > 0) 
                    then .cve.metrics.cvssMetricV2[0].cvssData.vectorString 
                    else null end),
    "v3 CVSS": (if .cve.metrics.cvssMetricV31 and (.cve.metrics.cvssMetricV31 | length > 0) 
                    then .cve.metrics.cvssMetricV31[0].cvssData.baseScore
                    elif .cve.metrics.cvssMetricV30 and (.cve.metrics.cvssMetricV30 | length > 0) 
                    then .cve.metrics.cvssMetricV30[0].cvssData.baseScore 
                    else null end),
    "v3 Vector": (if .cve.metrics.cvssMetricV31 and (.cve.metrics.cvssMetricV31 | length > 0) 
                    then .cve.metrics.cvssMetricV31[0].cvssData.vectorString 
                    elif .cve.metrics.cvssMetricV30 and (.cve.metrics.cvssMetricV30 | length > 0) 
                    then .cve.metrics.cvssMetricV30[0].cvssData.vectorString 
                    else null end),
    "v3 Exploitability Score": (if .cve.metrics.cvssMetricV31 and (.cve.metrics.cvssMetricV31 | length > 0) 
                                then .cve.metrics.cvssMetricV31[0].exploitabilityScore 
                                    elif .cve.metrics.cvssMetricV30 and (.cve.metrics.cvssMetricV30 | length > 0) 
                                    then .cve.metrics.cvssMetricV30[0].exploitabilityScore 
                                    else null end),
    "v2.3 CPE": [.cve.configurations[]?.nodes[].cpeMatch[]? | select(.vulnerable == true) | .criteria] // [],
    "CWE": [.cve.weaknesses[]?.description[].value],
    "VulnStatus": .cve.vulnStatus
}
""")

# Function to process a single file and extract vulnerabilities
def process_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)  # Load the JSON data from the file
    
    # Apply the jq query to extract vulnerabilities
    vuln_data = vuln_query.input(data).all()  # List of dictionaries for each vulnerability
    
    return vuln_data

# Function to process multiple files in a directory with progress bar
def process_directory(directory_path):
    all_vulns = []  # List to hold vulnerabilities from all files
    json_files = [f for f in os.listdir(directory_path) if f.endswith('.json')]  # Filter JSON files
    
    # Use tqdm to create a progress bar for file processing
    for filename in tqdm(json_files, desc="Processing Files", unit="file"):
        file_path = os.path.join(directory_path, filename)
        
        # Process each file
        vuln_data = process_file(file_path)
        all_vulns.extend(vuln_data)  # Append the extracted data from this file
    
    # Return a list of all vulnerabilities found
    return all_vulns

def process_nvd_data():
    # Define the directory where your JSON files are stored
    json_dir = 'CVE-NVD/JSON/'

    # Process all JSON files in the directory
    vulnerabilities = process_directory(json_dir)

    # Convert the list of dictionaries to a pandas DataFrame
    df = pd.DataFrame(vulnerabilities)

    # Optional: Clean up list-based fields (like 'description', 'cpe_criteria', 'cwe')
    df['DESCRIPTION'] = df['DESCRIPTION'].apply(lambda x: ', '.join(x) if isinstance(x, list) else '')
    #df['v2.3 CPE'] = df['v2.3 CPE'].apply(lambda x: ', '.join(x) if isinstance(x, list) else '')
    df['CWE'] = df['CWE'].apply(lambda x: ', '.join(x) if isinstance(x, list) else '')
    # Add a 'Count' column with all values set to 1 (syntactic sugar to make counts and sums and forecasting easy)
    df['Count'] = 1

    # Show the last few rows of the DataFrame
    print(df.tail)

    # Check if the directory for the CSV file exists, and create it if necessary
    csv_file_path = 'NVD-Vulnerability-Volumes.csv'

    # Check if the file already exists
    if os.path.exists(csv_file_path):
        # If the file exists, read it into a DataFrame
        existing_data = pd.read_csv(csv_file_path, index_col='ID')

        # Merge the existing data with the new data
        all_items = pd.concat([existing_data, df.set_index('ID')])

        # Drop duplicate rows based on the 'cve_id' column, keeping the latest entry
        all_items = all_items[~all_items.index.duplicated(keep='last')]

    # Reset the index to publication after dedupping based on IDs
    all_items = df.set_index('Publication')

    # Sort the data by the index (published date)
    all_items.sort_index(inplace=True)

    # Save the merged data back to the CSV file
    all_items.to_csv(csv_file_path)

    def process_cpe_dataframe(df):
        # Explode the 'v2.3 CPE' column to create a new row for each CPE string
        df = df.explode('v2.3 CPE')
    
        def extract_cpe_parts(cpe_str):
            if pd.isna(cpe_str) or not isinstance(cpe_str, str):
                return pd.Series({
                    'Part': None, 'Vendor': None, 'Product': None,
                    'Version': None, 'Update': None, 'Edition': None,
                    'Language': None, 'SW_Edition': None, 'Target_SW': None,
                    'Target_HW': None, 'Other': None
                })
        
            cpe_str = cpe_str.strip('"')
            parts = cpe_str.split(':')
        
            # Ensure we have enough parts
            if len(parts) >= 13:
                return pd.Series({
                    'Part': parts[2],
                    'Vendor': parts[3],
                    'Product': parts[4],
                    'Version': parts[5],
                    'Update': parts[6],
                    'Edition': parts[7],
                    'Language': parts[8],
                    'SW_Edition': parts[9],
                    'Target_SW': parts[10],
                    'Target_HW': parts[11],
                    'Other': parts[12] if len(parts) > 12 else None
                })
        
            return pd.Series({
                'Part': None, 'Vendor': None, 'Product': None,
                'Version': None, 'Update': None, 'Edition': None,
                'Language': None, 'SW_Edition': None, 'Target_SW': None,
                'Target_HW': None, 'Other': None
            })
    
        # Apply the extraction function to each row in the DataFrame with a progress bar
        tqdm.pandas(desc="Processing CPEs")
        extracted_parts = df['v2.3 CPE'].progress_apply(lambda x: extract_cpe_parts(x))
    
        # Concatenate the original DataFrame with the extracted parts
        df = pd.concat([df, extracted_parts], axis=1)
        return df

    # Re-run the function with the corrected implementation
    cpe_df = process_cpe_dataframe(all_items)
    cpe_df.head()

    # Remove rows where 'v2.3 CPE' column is NaN
    cpe_df = cpe_df.dropna(subset=['v2.3 CPE'])

    # Remove rows where 'VulnStatus' column is 'Rejected'
    cpe_df = cpe_df[cpe_df['VulnStatus'] != 'Rejected']

    # Reset the index to make 'Publication' a column
    cpe_df.reset_index(inplace=True)

    # Set a multi-index with 'ID' and 'v2.3 CPE'
    cpe_df.set_index(['ID', 'v2.3 CPE'], inplace=True)

    # 데이터프레임에 'ID'와 'v2.3 CPE' 컬럼이 확실히 있는지 확인
    # 만약 set_index가 앞에서 이미 되어있다면 reset_index()를 한 번 더 호출해서 컬럼으로 끄집어냄
    if 'ID' not in cpe_df.columns or 'v2.3 CPE' not in cpe_df.columns:
        cpe_df.reset_index(inplace=True)

    # Check if the file already exists
    csv_file_path = 'Vendor-Product-Vulnerability-Volumes.csv'
    if os.path.exists(csv_file_path):
        # If the file exists, read it into a DataFrame
        existing_data = pd.read_csv(csv_file_path, low_memory=False)

        # Merge the existing data with the new data on ID and CPE
        merged_cpe_df = pd.concat([existing_data, cpe_df], ignore_index=True)

        # Ensure uniqueness by considering both ID and CPE columns
        merged_cpe_df = merged_cpe_df.drop_duplicates(subset=['ID', 'v2.3 CPE'], keep='last')
    else:
        # If the file doesn't exist, use the new data as is
        merged_cpe_df = cpe_df.copy()

    # Sort the data by the ID column
    merged_cpe_df.sort_values(by='ID', inplace=True)

    # Save the merged data back to the CSV file
    merged_cpe_df.to_csv(csv_file_path, index=False)
    return merged_cpe_df