import requests
import json
import subprocess
import time
from datetime import datetime

# Constants
CACHE_FILE = "vulnerability_cache.json"
RESULTS_FILE = "scan_results.json"
MAX_RETRIES = 3
OSV_API_BASE_URL = "https://api.osv.dev/v1/query"

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

def save_results(results):
    # Add the latest updated timestamp
    results_metadata = {
        "last_updated": datetime.now().isoformat(),
        "scan_results": results
    }
    with open(RESULTS_FILE, "w") as file:
        json.dump(results_metadata, file, indent=4)

# Remove duplicate vulnerabilities
def remove_duplicates(vulnerabilities):
    unique_vulns = {json.dumps(v, sort_keys=True): v for v in vulnerabilities}
    return list(unique_vulns.values())

# Enrich vulnerability data using OSV API
def enrich_with_osv(package_name, version):
    payload = {
        "package": {
            "name": package_name,
            "version": version
        }
    }
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(OSV_API_BASE_URL, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulns", [])
                if vulnerabilities:
                    print(f"Found vulnerabilities for {package_name}@{version}")
                    return [
                        {
                            "cve_id": vuln.get("id", "N/A"),
                            "description": vuln.get("details", "No description provided."),
                            "cvss_score": vuln.get("score", {}).get("baseScore", "N/A"),
                            "severity": vuln.get("severity", "UNKNOWN"),
                            "published_date": vuln.get("published", "N/A"),
                        }
                        for vuln in vulnerabilities
                    ]
                else:
                    print(f"No vulnerabilities found for {package_name}@{version}")
                    return []
            else:
                print(f"Error querying OSV API: {response.status_code}. Retrying...")
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            print(f"OSV API request failed: {e}. Retrying...")
            time.sleep(2 ** attempt)

    print(f"Falling back for {package_name}@{version}: No vulnerabilities retrieved.")
    return []

# Extract installed packages from Docker image
def extract_packages_from_image(image_name):
    try:
        sanitized_image_name = image_name.strip().strip("'").strip('"')
        print(f"Extracting installed packages from image: {sanitized_image_name}...")
        cmd = f"docker run --rm --entrypoint bash {sanitized_image_name} -c \"dpkg-query -W -f='${{Package}}=${{Version}}\\n'\""
        result = subprocess.check_output(cmd, shell=True, text=True)
        packages = [line.strip().split("=") for line in result.strip().split("\n")]
        return packages
    except subprocess.CalledProcessError as e:
        print(f"Error extracting packages: {e}")
        return []

# Retrieve the image name from a Kubernetes deployment
def get_image_name_from_deployment(deployment_name, namespace="default"):
    try:
        cmd = f"kubectl get deployment {deployment_name} -n {namespace} -o jsonpath='{{.spec.template.spec.containers[0].image}}'"
        image_name = subprocess.check_output(cmd, shell=True, text=True).strip()
        print(f"Retrieved image name: {image_name}")
        return image_name
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving image name: {e}")
        return None

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
        vulnerabilities = enrich_with_osv(package_name, version)
        cache[cache_key] = vulnerabilities
        all_vulnerabilities.extend(vulnerabilities)

    save_cache(cache)
    return all_vulnerabilities

# Main function to run the security scan
def run_security_scan(image_name):
    try:
        print(f"Starting security scan for image: {image_name}...")
        packages = extract_packages_from_image(image_name)
        if not packages:
            print("No packages found in the image.")
            return
        cache = load_cache()
        vulnerabilities = check_vulnerabilities(packages, cache)
        vulnerabilities = remove_duplicates(vulnerabilities)

        if vulnerabilities:
            print("\nVulnerabilities found:")
            for vuln in vulnerabilities:
                print(json.dumps(vuln, indent=4))
            save_results(vulnerabilities)
            print(f"Scan results saved to {RESULTS_FILE}.")
        else:
            print("No vulnerabilities found.")
    except Exception as e:
        print(f"Error during security scan: {e}")

if __name__ == "__main__":
    deployment_name = "k8ssecframework-deployment"
    image_name = get_image_name_from_deployment(deployment_name)
    if image_name:
        run_security_scan(image_name)
    else:
        print("Failed to retrieve image name. Exiting...")
