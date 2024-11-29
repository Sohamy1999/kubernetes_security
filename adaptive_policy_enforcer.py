import json
import subprocess

# Path to the scan results file
SCAN_RESULTS_FILE = "scan_results.json"

def load_scan_results():
    """
    Load scan results from a JSON file.
    """
    try:
        with open(SCAN_RESULTS_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Scan results file '{SCAN_RESULTS_FILE}' not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error decoding JSON from '{SCAN_RESULTS_FILE}'.")
        return []

def analyze_scan_results(scan_results):
    """
    Filter scan results to find vulnerabilities with CRITICAL or HIGH severity.
    """
    critical_vulnerabilities = [
        vuln for vuln in scan_results if vuln["severity"] in ["CRITICAL", "HIGH"]
    ]
    return critical_vulnerabilities

def get_affected_pods():
    """
    Retrieve pod names dynamically from the Kubernetes cluster.
    """
    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", "default", "-o", "json"],
            capture_output=True, text=True, check=True
        )
        pods = json.loads(result.stdout)
        pod_names = [pod["metadata"]["name"] for pod in pods["items"]]
        return pod_names
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve pod names: {e}")
        return []

def label_pod(vulnerability, pod_name):
    """
    Label a Kubernetes pod based on the detected vulnerability.
    """
    try:
        label_key = "vulnerability"
        label_value = vulnerability['package'].replace('.', '-')

        print(f"Labeling pod '{pod_name}' with label '{label_key}={label_value}'...")
        subprocess.run(["kubectl", "label", "pods", pod_name, f"{label_key}={label_value}", "--overwrite"], check=True)
        print(f"Pod '{pod_name}' labeled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to label pod '{pod_name}': {e}")

def apply_namespace_label(vulnerability):
    """
    Apply a Pod Security Admission label to the namespace for enforcing security constraints.
    """
    try:
        print("Applying Pod Security Admission policy label to namespace...")
        subprocess.run(
            ["kubectl", "label", "namespace", "default", "pod-security.kubernetes.io/enforce=restricted", "--overwrite"],
            check=True
        )
        print("Pod Security Admission policy applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply Pod Security Admission policy: {e}")

def generate_policy_yaml(policy_type, vulnerability, label_value):
    """
    Generate YAML for a specified policy type (network policy, resource quota).
    """
    if policy_type == "network":
        return f"""
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: block-external-traffic-{label_value}
          namespace: default
        spec:
          podSelector:
            matchLabels:
              vulnerability: {label_value}
          policyTypes:
          - Ingress
          ingress: []
        """
    elif policy_type == "resource_quota":
        return f"""
        apiVersion: v1
        kind: ResourceQuota
        metadata:
          name: restrict-resource-usage-{label_value}
          namespace: default
        spec:
          hard:
            cpu: "2"
            memory: "4Gi"
        """
    else:
        print(f"Unknown policy type: {policy_type}")
        return None

def apply_policy(policy_yaml, policy_type):
    """
    Apply a policy to Kubernetes using the generated YAML.
    """
    try:
        with open("dynamic-policy.yaml", "w") as file:
            file.write(policy_yaml)

        subprocess.run(["kubectl", "apply", "-f", "dynamic-policy.yaml"], check=True)
        print(f"{policy_type.capitalize()} policy applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply {policy_type} policy: {e}")

def enforce_policies(vulnerabilities):
    """
    Enforce multiple types of policies for pods with critical vulnerabilities.
    """
    if vulnerabilities:
        print(f"Critical vulnerabilities detected: {len(vulnerabilities)}. Enforcing policies...")
        affected_pods = get_affected_pods()

        if not affected_pods:
            print("No pods found in the cluster to label. Skipping pod labeling.")
            return

        for vulnerability in vulnerabilities:
            label_value = vulnerability['package'].replace('.', '-')
            for pod_name in affected_pods:
                label_pod(vulnerability, pod_name)

            # Apply network policy
            network_policy_yaml = generate_policy_yaml("network", vulnerability, label_value)
            if network_policy_yaml:
                apply_policy(network_policy_yaml, "network")

            # Apply resource quota policy
            resource_quota_yaml = generate_policy_yaml("resource_quota", vulnerability, label_value)
            if resource_quota_yaml:
                apply_policy(resource_quota_yaml, "resource_quota")

        # Apply Pod Security Admission policy
        apply_namespace_label(vulnerabilities[0])
    else:
        print("No critical vulnerabilities found. No policy changes required.")

def run_policy_enforcement():
    """
    Main workflow to load scan results, analyze vulnerabilities, and enforce policies.
    """
    print("Starting adaptive policy enforcement...")
    scan_results = load_scan_results()

    if not scan_results:
        print("No scan results available. Exiting.")
        return

    critical_vulnerabilities = analyze_scan_results(scan_results)
    enforce_policies(critical_vulnerabilities)

if __name__ == "__main__":
    run_policy_enforcement()
