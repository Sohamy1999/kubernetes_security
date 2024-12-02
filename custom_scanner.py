import requests
import json
import subprocess
import time
from datetime import datetime

# Constants
RESULTS_FILE = "scan_results.json"
MAX_RETRIES = 3
OSV_API_BASE_URL = "https://api.osv.dev/v1/query"

def save_results(results):
    """
    Save scan results to a JSON file with metadata.
    """
    results_metadata = {
        "last_updated": datetime.now().isoformat(),
        "scan_results": results
    }
    with open(RESULTS_FILE, "w") as file:
        json.dump(results_metadata, file, indent=4)

def remove_duplicates(vulnerabilities):
    """
    Remove duplicate vulnerabilities from the list.
    """
    unique_vulns = {json.dumps(v, sort_keys=True): v for v in vulnerabilities}
    return list(unique_vulns.values())

def enrich_with_osv(package_name, version):
    """
    Query the OSV API for vulnerabilities in the specified package and version.
    """
    payload = {
        "version": version,
        "package": {
            "ecosystem": "Debian",
            "name": package_name
        }
    }
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Payload for {package_name}@{version}: {payload}")
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
                            "cvss_score": vuln.get("databaseSpecific", {}).get("cvss", {}).get("score", "N/A"),
                            "severity": vuln.get("severity", "UNKNOWN"),
                            "published_date": vuln.get("published", "N/A"),
                        }
                        for vuln in vulnerabilities
                    ]
                else:
                    print(f"No vulnerabilities found for {package_name}@{version}")
                    return []
            else:
                print(f"OSV API returned {response.status_code} for {package_name}@{version}: {response.text}")
                if response.status_code == 400:
                    print("Likely cause: Incorrect package name, version, or ecosystem.")
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as req_error:
            print(f"OSV API request failed: {req_error}. Retrying...")
            time.sleep(2 ** attempt)

    print(f"Falling back for {package_name}@{version}: No vulnerabilities retrieved.")
    return []

def extract_packages_from_image(image_name):
    """
    Extract installed packages and versions from a Docker image.
    """
    try:
        sanitized_image_name = image_name.strip().strip("'").strip('"')
        print(f"Extracting installed packages from image: {sanitized_image_name}...")
        cmd = f"docker run --rm --entrypoint bash {sanitized_image_name} -c \"dpkg-query -W -f='${{Package}}=${{Version}}\\n'\""
        result = subprocess.check_output(cmd, shell=True, text=True)
        print(f"dpkg-query output:\n{result}")  # Log the raw output for debugging
        packages = [line.strip().split("=") for line in result.strip().split("\n") if line.strip()]
        return packages
    except subprocess.CalledProcessError as e:
        print(f"Error extracting packages: {e}")
        return []

def get_image_name_from_deployment(deployment_name, namespace="default"):
    """
    Retrieve the Docker image name from a Kubernetes deployment.
    """
    try:
        cmd = f"kubectl get deployment {deployment_name} -n {namespace} -o jsonpath='{{.spec.template.spec.containers[0].image}}'"
        image_name = subprocess.check_output(cmd, shell=True, text=True).strip()
        print(f"Retrieved image name: {image_name}")
        return image_name
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving image name: {e}")
        return None

def check_vulnerabilities(packages):
    """
    Check vulnerabilities for each package using the OSV API.
    """
    all_vulnerabilities = []
    for package_name, version in packages:
        print(f"Checking vulnerabilities for package: {package_name}, version: {version}...")
        vulnerabilities = enrich_with_osv(package_name, version)
        all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities

def run_security_scan(image_name):
    """
    Run a security scan for a specified Docker image.
    """
    try:
        print(f"Starting security scan for image: {image_name}...")
        packages = extract_packages_from_image(image_name)
        if not packages:
            print("No packages found in the image. Ensure the base image supports dpkg or contains packages to scan.")
            return
        vulnerabilities = check_vulnerabilities(packages)
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
