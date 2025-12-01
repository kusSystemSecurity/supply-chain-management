import requests
from tqdm import tqdm
import os
import time


def fetch_nvd_data():
    """
    Fetch CVE data from NVD API with pagination and rate limiting.
    Saves each page of results as a JSON file in 'CVE-NVD/JSON/' directory.
    """
    # Placeholder for your API key from NVD
    API_KEY = "3dc0ad37-8642-46fe-bce4-c35420dba183"

    # Base URL for the NVD API
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Create directories if they don't exist
    file_exists = os.path.exists('CVE-NVD')
    if not file_exists:
        os.mkdir('CVE-NVD')
        os.mkdir('CVE-NVD/JSON')

    # Rate limit: 50 requests per 30 seconds
    RATE_LIMIT = 50
    RATE_LIMIT_WINDOW = 30  # seconds

    # Counter for requests
    request_count = 0
    start_time = time.time()

    # Pagination parameters
    start_index = 0
    results_per_page = 2000  # Maximum allowed by the API
    total_results = 0 # Initialize total_results
    pbar = None # Initialize pbar
    
    while True:
        params = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        headers = {'apiKey': API_KEY}

        response = requests.get(BASE_URL, params=params, headers=headers)

        # Rate limiting logic
        request_count += 1
        if request_count >= RATE_LIMIT:
            elapsed_time = time.time() - start_time
            if elapsed_time < RATE_LIMIT_WINDOW:
                time.sleep(RATE_LIMIT_WINDOW - elapsed_time)
            request_count = 0
            start_time = time.time()

        if response.status_code == 200:
            data = response.json()
            
            if total_results == 0: # First request, initialize total_results and pbar
                total_results = data.get("totalResults", 0)
                pbar = tqdm(total=total_results, unit="CVEs", desc="Fetching NVD Data")
            
            # Save the current page of results
            with open(f'CVE-NVD/JSON/cve_data_{start_index}.json', 'w') as f:
                f.write(response.text)

            pbar.update(len(data.get("vulnerabilities", []))) # Update pbar with actual number of vulnerabilities fetched

            # Check if we have fetched all results
            if start_index + results_per_page >= total_results:
                print("All data has been fetched succesfully.")
                if pbar:
                    pbar.close()
                break

            # Update the start index for the next page
            start_index += results_per_page
        elif response.status_code == 522:
            print('Network issues trying this request again.')
            response = requests.get(BASE_URL, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if total_results == 0:
                    total_results = data.get("totalResults", 0)
                    pbar = tqdm(total=total_results, unit="CVEs", desc="Fetching NVD Data")

                # Save the current page of results
                with open(f'CVE-NVD/JSON/cve_data_{start_index}.json', 'w') as f:
                    f.write(response.text)
                pbar.update(len(data.get("vulnerabilities", [])))
            else:
                print("Two network failures in a row, quitting datafetch. Please re-run the code later.")
                if pbar:
                    pbar.close()
                break
        elif response.status_code == 401:
            print('Check your API key')
            if pbar:
                pbar.close()
            break
        else:
            print(f"Failed to fetch data: {response.status_code}")
            if pbar:
                pbar.close()
            break
