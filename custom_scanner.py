import requests
import json
import subprocess
import time
from datetime import datetime

# Constants
RESULTS_FILE = "scan_results.json"
MAX_RETRIES = 3
API_KEY = "df242858-4a62-43cd-b04c-a46bf838f48f"  # Replace with your NVD API key
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

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

# Functions for severity evaluation
def evaluate_severity_from_description(description):
    """
    Determine severity based on keywords in the description.
    """
    high_keywords = ["remote code execution", "privilege escalation", "arbitrary code execution", "critical"]
    medium_keywords = ["denial of service", "out-of-bounds", "information disclosure", "memory corruption"]

    description = description.lower()

    if any(keyword in description for keyword in high_keywords):
        return "HIGH"
    elif any(keyword in description for keyword in medium_keywords):
        return "MEDIUM"
    else:
        return "LOW"

def fallback_severity_by_package(package_name):
    """
    Determine severity based on package importance.
    """
    package_importance = {
        "openssl": "HIGH",
        "util-linux": "HIGH",
        "systemd": "HIGH",
        "gzip": "MEDIUM",
        "tar": "MEDIUM",
        # Add more packages as necessary
    }
    return package_importance.get(package_name, "LOW")

def determine_severity(vulnerability):
    """
    Determine severity using description and package importance.
    """
    severity = evaluate_severity_from_description(vulnerability.get("description", ""))
    if severity == "LOW":  # If description analysis yields low, fallback to package importance
        severity = fallback_severity_by_package(vulnerability["package"])
    return severity

# Generate fallback CVE data
def generate_fallback_cve(package_name, version):
    return {
        "cve_id": "N/A",
        "description": f"A potential vulnerability identified in {package_name} version {version}. Details are under analysis.",
        "published_date": datetime.now().isoformat() + "Z",  # Fallback uses the current timestamp
        "cvss_score": "N/A",
        "severity": fallback_severity_by_package(package_name),
    }

# Enrich vulnerability data using NVD API
def enrich_with_nvd(cve_id, package_name, version):
    url = f"{NVD_API_BASE_URL}?cveId={cve_id}&apiKey={API_KEY}"
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                cve_items = data.get("result", {}).get("CVE_Items", [])
                if cve_items:
                    impact = cve_items[0].get("impact", {})
                    base_metric_v3 = impact.get("baseMetricV3", {})
                    cvss_score = base_metric_v3.get("cvssV3", {}).get("baseScore", "N/A")
                    severity = base_metric_v3.get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
                    published_date = cve_items[0].get("publishedDate", "N/A")
                    
                    print(f"Enriched CVE {cve_id}: CVSS Score={cvss_score}, Severity={severity}")
                    return cvss_score, severity, published_date

            elif response.status_code in [429, 503]:
                print(f"NVD API unavailable for {cve_id}. Retrying ({attempt + 1}/{MAX_RETRIES})...")
                time.sleep(2 ** attempt)
            else:
                print(f"Unexpected response from NVD API for {cve_id}: {response.status_code}")
                break

        except requests.exceptions.RequestException as e:
            print(f"NVD API request failed for {cve_id}: {e}. Retrying ({attempt + 1}/{MAX_RETRIES})...")
            time.sleep(2 ** attempt)

    fallback_cve = generate_fallback_cve(package_name, version)
    print(f"Falling back for CVE {cve_id}: CVSS Score={fallback_cve['cvss_score']}, Severity={fallback_cve['severity']}")
    return fallback_cve["cvss_score"], fallback_cve["severity"], fallback_cve["published_date"]

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
def check_vulnerabilities(packages):
    all_vulnerabilities = []
    for package_name, version in packages:
        print(f"Checking vulnerabilities for package: {package_name}, version: {version}...")
        cve_list = [{"id": "N/A"}]  # Placeholder for CVE fetch
        vulnerabilities = []

        for cve in cve_list:
            cve_id = cve["id"]
            cvss_score, severity, published_date = enrich_with_nvd(cve_id, package_name, version)
            
            if severity == "UNKNOWN":
                severity = determine_severity({
                    "package": package_name,
                    "description": cve.get("description", "N/A")
                })

            vulnerabilities.append({
                "package": package_name,
                "version": version,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "description": cve.get("description", "N/A"),
                "published_date": published_date,
            })

        all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities

# Main function to run the security scan
def run_security_scan(image_name):
    try:
        print(f"Starting security scan for image: {image_name}...")
        packages = extract_packages_from_image(image_name)
        if not packages:
            print("No packages found in the image.")
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
