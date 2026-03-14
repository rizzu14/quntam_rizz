from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import time
import re
import os
import sys

# Make sure api folder is in path for _scanner_engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))
from _scanner_engine import CryptoScanner

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# --- QUANTUM-GRADE FIREWALL CONFIG ---
THREAT_JAIL = {}
MAX_REQUESTS = 10
WINDOW_SECONDS = 60
IPS_LOG = {}

def is_malicious(data):
    patterns = [r"<script", r"UNION SELECT", r"OR 1=1", r"DROP TABLE", r"javascript:"]
    input_str = str(data).upper()
    return any(re.search(p.upper(), input_str) for p in patterns)

@app.before_request
def firewall_check():
    ip = request.remote_addr
    if ip in THREAT_JAIL and time.time() < THREAT_JAIL[ip]:
        return jsonify({"status": "blocked", "message": "INTRUSION DETECTED: IP JAIL ACTIVE"}), 403
    now = time.time()
    IPS_LOG.setdefault(ip, [])
    IPS_LOG[ip] = [t for t in IPS_LOG[ip] if t > now - WINDOW_SECONDS]
    if len(IPS_LOG[ip]) >= MAX_REQUESTS:
        THREAT_JAIL[ip] = now + 300
        return jsonify({"status": "blocked", "message": "DDOS ATTEMPT BLOCKED: IP JAILED"}), 429
    IPS_LOG[ip].append(now)
    if request.is_json:
        if is_malicious(request.get_json()):
            THREAT_JAIL[ip] = now + 3600
            return jsonify({"status": "blocked", "message": "SENSORY FIREWALL: EXPLOIT BLOCKED"}), 403

@app.route("/")
def index():
    return send_from_directory('.', 'index.html')

@app.route("/api/scan", methods=["POST"])
@app.route("/scan", methods=["POST"])
def scan_endpoint():
    try:
        data = request.json or {}
        target = data.get("target")
        port = data.get("port", 443)

        if not target:
            return jsonify({"error": "Target is required"}), 400

        if "://" in target:
            target = target.split("://")[1]
        if "/" in target:
            target = target.split("/")[0]
        if ":" in target:
            parts = target.split(":")
            target = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                port = int(parts[1])

        try:
            scanner = CryptoScanner(target, port)
        except (ValueError, PermissionError) as e:
            return jsonify({"status": "error", "message": str(e)}), 400

        scanner.scan_tls()

        if "error" in scanner.results:
            return jsonify({"status": "error", "message": scanner.results["error"]}), 502

        cbom = scanner.generate_cbom()
        is_safe = scanner.results.get("quantum_readiness") == "High"
        label = "Fully Quantum Safe" if is_safe else "Non-PQC Ready"

        recommendations = []
        if is_safe:
            recommendations.append({
                "title": "Quantum Hygiene Maintenance",
                "steps": [
                    "Continue monitoring for new NIST-standardized updates to ML-KEM/ML-DSA.",
                    "Ensure backup classical algorithms are maintained for backward compatibility (Hybrid Approach).",
                    "Verify all interconnected microservices also implement PQC headers."
                ]
            })
        else:
            recommendations.append({
                "title": "Urgent HNDL Mitigation",
                "steps": [
                    "Migrate to NIST-standardized FIPS-203 (ML-KEM) and FIPS-204 (ML-DSA) algorithms.",
                    "Implement 'Hybrid Cryptography' to wrap existing RSA/ECC traffic in PQC tunnels.",
                    "Audit data-at-rest encryption longevity for sensitive bank records."
                ]
            })
            recommendations.append({
                "title": "Cloud Migration Roadmap (AWS/GCP/Azure)",
                "steps": [
                    "AWS: Enable Hybrid Post-Quantum TLS in AWS KMS and ACM. Update SDKs to use AWS-LC libraries.",
                    "Google Cloud: Opt-in for PQC-safe Cloud KMS digital signatures (ML-DSA preview). Use X-Wing hybrid KEM for ALB traffic.",
                    "Azure: Integrate SymCrypt PQC-enabled libraries into AKS workloads and utilize Azure Key Vault hybrid endpoints."
                ]
            })

        response = {
            "status": "success",
            "target": target,
            "label": label,
            "q_score": scanner.results.get("q_score", 0),
            "forensics": scanner.results.get("forensics", {}),
            "threat_intel": scanner.results.get("threat_intel", {}),
            "service_discovery": scanner.results.get("service_type", "Unknown"),
            "recommendations": recommendations,
            "scanner_results": scanner.results,
            "cbom": cbom,
            "inventory": {
                "tls_version": scanner.results.get("tls_details", {}).get("protocol_version", "Unknown"),
                "cipher_suite": scanner.results.get("tls_details", {}).get("cipher_suite", "Unknown"),
                "key_exchange": scanner.results.get("tls_details", {}).get("key_exchange_bits", "Unknown"),
                "subject": scanner.results.get("certificate_inventory", {}).get("subject", "Unknown"),
                "signature_algorithm": scanner.results.get("certificate_inventory", {}).get("signature_algorithm", "Unknown"),
                "validity": scanner.results.get("certificate_inventory", {}).get("not_valid_after", "Unknown")
            }
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
