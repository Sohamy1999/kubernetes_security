import requests
import json
import subprocess
import time

# Constants
CACHE_FILE = "vulnerability_cache.json"
RESULTS_FILE = "scan_results.json"  # Output file for vulnerabilities storage
MAX_RETRIES = 3
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

# Load or initialize cache
def load_cache():
    try:
        with open(CACHE_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as file:
        json.dump(cache, file, indent=4)

# Save scan results to a file
def save_results(results):
    with open(RESULTS_FILE, "w") as file:
        json.dump(results, file, indent=4)

# Enrich vulnerability data using NVD API
def enrich_with_nvd(cve_id):
    url = f"{NVD_API_BASE_URL}{cve_id}"
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                impact = data.get("impact", {})
                base_metric = impact.get("baseMetricV3", {}) or impact.get("baseMetricV2", {})
                severity = base_metric.get("cvssV3", {}).get("baseSeverity") or base_metric.get("severity", "UNKNOWN")
                return severity
            elif response.status_code in [429, 503]:
                print(f"NVD API unavailable for {cve_id}. Retrying...")
                time.sleep(2 ** attempt)
            else:
                print(f"Unexpected response from NVD API for {cve_id}: {response.status_code}")
                break
        except requests.exceptions.RequestException as e:
            print(f"NVD API request failed for {cve_id}: {e}. Retrying...")
            time.sleep(2 ** attempt)
    return "UNKNOWN"

# Check vulnerabilities
def check_vulnerabilities(packages, cache):
    all_vulnerabilities = []

    for package_name, version in packages:
        cache_key = f"{package_name}@{version}"
        if cache_key in cache:
            print(f"Cache hit for {cache_key}.")
            all_vulnerabilities.extend(cache[cache_key])
            continue

        print(f"Checking vulnerabilities for package: {package_name}, version: {version}...")
        # Replace with your primary API call logic to fetch CVE data
        cve_list = [{"id": "CVE-2022-1234", "description": "Sample vulnerability"}]  # Placeholder for actual API results
        vulnerabilities = []

        for cve in cve_list:
            cve_id = cve["id"]
            severity = enrich_with_nvd(cve_id)
            vulnerabilities.append({
                "package": package_name,
                "version": version,
                "cve_id": cve_id,
                "severity": severity,
                "description": cve.get("description", "N/A"),
                "published_date": cve.get("publishedDate", "N/A"),
            })

        cache[cache_key] = vulnerabilities
        all_vulnerabilities.extend(vulnerabilities)

    save_cache(cache)
    return all_vulnerabilities

# Example function to simulate vulnerability checking
def run_security_scan(image_name):
    try:
        print(f"Starting security scan for image: {image_name}...")
        packages = [("openssl", "1.1.1"), ("gzip", "1.10")]  # Placeholder for actual packages
        cache = load_cache()
        vulnerabilities = check_vulnerabilities(packages, cache)

        if vulnerabilities:
            print("\nVulnerabilities found:")
            for vuln in vulnerabilities:
                print(json.dumps(vuln, indent=4))
            # Save results to the file
            save_results(vulnerabilities)
            print(f"Scan results saved to {RESULTS_FILE}.")
        else:
            print("No vulnerabilities found.")
    except Exception as e:
        print(f"Error during security scan: {e}")

# Run the script
if __name__ == "__main__":
    run_security_scan("example-image:latest")
