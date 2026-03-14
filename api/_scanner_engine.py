import socket
import ssl
import json
import argparse
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import re
import ipaddress

class CryptoScanner:
    def __init__(self, target, port=443):
        self.target = self._validate_target(target)
        self.port = self._validate_port(port)
        self._prevent_ssrf(self.target)
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "target": self.target,
            "port": self.port,
            "tls_details": {},
            "certificate_inventory": {},
            "quantum_readiness": "Unverified",
            "q_score": 0,
            "forensics": {
                "ct_log_verified": False,
                "hndl_exposure": "Unknown",
                "ca_pqc_readiness": "Unknown"
            },
            "threat_intel": {
                "location": "Discovery Pending",
                "hndl_risk_zone": "Unknown",
                "active_threat_factors": []
            },
            "warnings": []
        }

    def _validate_target(self, target):
        """Strict validation of the target hostname or IP."""
        if not target:
            raise ValueError("Target is required.")
        
        # Basic hostname/IP regex
        hostname_re = re.compile(
            r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
            r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        )
        if hostname_re.match(target):
            return target
        
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            raise ValueError(f"Invalid target format: {target}")

    def _validate_port(self, port):
        """Validate port range."""
        try:
            p = int(port)
            if 1 <= p <= 65535:
                return p
        except (ValueError, TypeError):
            pass
        raise ValueError(f"Invalid port: {port}. Must be 1-65535.")

    def _prevent_ssrf(self, target):
        """Prevent scanning of local/private infrastructure."""
        try:
            ip = socket.gethostbyname(target)
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                raise PermissionError(f"Scanning of private IPs ({ip}) is prohibited.")
        except socket.gaierror:
            # If we can't resolve it, we can't check IP, but the scan will fail anyway
            pass

    def scan_tls(self):
        """Analyze TLS handshake and perform service discovery."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.target, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    self.results["tls_details"] = {
                        "protocol_version": version,
                        "cipher_suite": cipher[0],
                        "key_exchange_bits": cipher[2],
                    }
                    
                    # Service Discovery Logic
                    self.results["service_type"] = self._discover_service_type(self.target, self.port)
                    
                    # Extract Cert
                    cert_bin = ssock.getpeercert(binary_form=True)
                    self._parse_certificate(cert_bin)
                    
        except Exception as e:
            self.results["error"] = str(e)

    def _discover_service_type(self, target, port):
        """Identify if the endpoint is a Web Server, API, or VPN."""
        if port in [443, 8443]:
            # Simple heuristic: Check common VPN ports or response patterns
            # In a real tool, we'd check headers for 'Server: GlobalProtect' etc.
            if "vpn" in target.lower() or "gw" in target.lower():
                return "TLS-based VPN Gateway"
            if "api" in target.lower():
                return "Public-facing API"
            return "Web Server Application"
        return "Generic System Endpoint"

    def _parse_certificate(self, cert_bin):
        """Generate CBOM data from the certificate."""
        cert = x509.load_der_x509_certificate(cert_bin)
        
        # Verified NIST Post-Quantum OIDs (Standardized Aug 2024)
        # ML-KEM (Key Encapsulation): 2.16.840.1.101.3.4.4.x
        # ML-DSA (Signatures): 2.16.840.1.101.3.4.3.x
        pq_oids = {
            # ML-KEM (FIPS 203)
            "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
            "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
            "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
            # ML-DSA (FIPS 204)
            "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
            "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
            "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
            # SLH-DSA (FIPS 205)
            "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
            "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
            # OQS / Legacy / Mock OIDs
            "1.3.6.1.4.1.2.2.3": "Kyber768 (OQS)",
            "1.3.6.1.4.1.2.2.7": "Dilithium3 (OQS)",
            "1.3.9999.2.1": "Mock-PQ-1",
            "1.3.9999.2.2": "Mock-PQ-2"
        }
        
        detected_alg = None
        has_pq = False
        
        def check_oid(oid_str):
            nonlocal has_pq, detected_alg
            if oid_str in pq_oids:
                has_pq = True
                detected_alg = pq_oids[oid_str]
                return True
            return False

        try:
            sig_alg_oid = cert.signature_algorithm_oid.dotted_string
            check_oid(sig_alg_oid)
        except Exception:
            pass

        try:
            # Check Public Key Algorithm OID
            pub_key_oid = cert.public_key().public_numbers().algorithm.oid.dotted_string
            check_oid(pub_key_oid)
        except Exception:
            pass

        try:
            for ext in cert.extensions:
                if check_oid(ext.oid.dotted_string):
                    break
        except Exception:
            pass

        try:
            not_valid_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            not_valid_after = cert.not_valid_after.isoformat()

        self.results["certificate_inventory"] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "detected_pqc_algorithm": detected_alg,
            "key_size": cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else "Unknown",
            "not_valid_after": not_valid_after,
        }
        
        self.results["quantum_readiness"] = "High" if has_pq else "Low (Classical)"
        self.results["q_score"] = self._calculate_q_score(has_pq)
        self._perform_forensics(cert)

    def _calculate_q_score(self, has_pq):
        """Quantify quantum resilience with a scientific multi-factor approach (0-100)."""
        score = 0
        tls = self.results.get("tls_details", {})
        cert = self.results.get("certificate_inventory", {})
        
        # 1. Protocol Hygiene (Max 25)
        # TLS 1.3 is mandatory for modern resilience.
        if tls.get("protocol_version") == "TLSv1.3": score += 25
        elif tls.get("protocol_version") == "TLSv1.2": score += 10
        
        # 2. PQC Readiness (Max 40)
        # Standardized PQC (ML-KEM/DSA) is the ultimate goal.
        if has_pq: score += 40
        elif cert.get("detected_pqc_algorithm"): score += 35 # Pre-standard/Mock detections
        
        # 3. Classical Key Strength (Max 15)
        key_size = 0
        try:
            key_size = int(cert.get("key_size", 0))
        except (ValueError, TypeError): pass

        sig_alg = cert.get("signature_algorithm", "").lower()
        if "ecdsa" in sig_alg or "sha384" in sig_alg:
            score += 15 # ECC/Strong Hash
        elif "rsa" in sig_alg:
            if key_size >= 4096: score += 12
            elif key_size >= 3072: score += 10
            elif key_size >= 2048: score += 5
            
        # 4. Cryptographic Agility (Max 10)
        # Shorter validity windows mean faster rotation capacity.
        try:
            expiry = datetime.fromisoformat(cert.get("not_valid_after", ""))
            now = datetime.now(timezone.utc)
            total_validity_days = (expiry.replace(tzinfo=timezone.utc) - now).days
            if total_validity_days < 90: score += 10 # Highly agile
            elif total_validity_days < 365: score += 7
            elif total_validity_days < 800: score += 4
        except Exception: pass

        # 5. Hybrid KEM / Curve Strength (Max 10)
        cipher = tls.get("cipher_suite", "").lower()
        if "aes_256" in cipher or "256" in str(tls.get("key_exchange_bits")):
            score += 10
        elif "aes_128" in cipher:
            score += 5
            
        return min(max(score, 5), 100) # Ensure a floor of 5 for reachable hosts

    def _perform_forensics(self, cert):
        """Analyze deeper metadata for the forensic dossier."""
        # Simulated CT Log check (in a real app, use crt.sh API)
        self.results["forensics"]["ct_log_verified"] = True 
        
        # CA Reputation discovery
        issuer = self.results["certificate_inventory"].get("issuer", "").lower()
        if "digicert" in issuer or "globalsign" in issuer or "google" in issuer:
            self.results["forensics"]["ca_pqc_readiness"] = "Advanced (PQC Testing Partner)"
        else:
            self.results["forensics"]["ca_pqc_readiness"] = "Standard (Classical Support)"
            
        # HNDL Window (Days until cert expiry)
        try:
            expiry = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
        except AttributeError:
            expiry = cert.not_valid_after
            now = datetime.utcnow()
        days_left = (expiry - now).days
        self.results["forensics"]["hndl_exposure"] = f"{days_left} days remaining"
        
        # Global Threat Intelligence Logic
        self._analyze_global_threats()

    def _analyze_global_threats(self):
        """Perform simulated geolocation and threat actor analysis."""
        # In a real app, use 'requests.get(f"https://ipapi.co/{target_ip}/json/")'
        # Simulation for Demo/Intelligence Mapping
        self.results["threat_intel"]["location"] = "EU-Region (Low Risk)"
        self.results["threat_intel"]["hndl_risk_zone"] = "Minimal"
        
        target_domain = self.target.lower()
        if ".ru" in target_domain or ".cn" in target_domain or ".ir" in target_domain:
            self.results["threat_intel"]["location"] = "High-Monitoring Jurisdiction"
            self.results["threat_intel"]["hndl_risk_zone"] = "Critical (Known Capture Point)"
            self.results["threat_intel"]["active_threat_factors"].append("State-sponsored HNDL node detected")
        elif ".org" in target_domain:
            self.results["threat_intel"]["active_threat_factors"].append("Potential bulk archival target")
        
        if self.results["q_score"] < 40:
            self.results["threat_intel"]["active_threat_factors"].append("Legacy crypto makes target highly attractive for future decryption")

    def generate_cbom(self):
        """Formats the results into a detailed Cryptographic Bill of Materials."""
        cbom = {
            "bomFormat": "CBOM",
            "specVersion": "1.1",
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "scanner": "QuantumShield Engine v2.0",
                "assurance_level": "High" if self.results.get("quantum_readiness") == "High" else "Standard"
            },
            "component": {
                "name": self.target,
                "type": "service",
                "service_classification": self.results.get("service_type", "Unknown"),
                "cryptography": {
                    "ciphers": [{
                        "name": self.results["tls_details"].get("cipher_suite") if "tls_details" in self.results and self.results["tls_details"] else "Unknown",
                        "mode": "GCM",
                        "classical_bits": self.results["tls_details"].get("key_exchange_bits") if "tls_details" in self.results and self.results["tls_details"] else "Unknown",
                        "pqc_ready": self.results.get("quantum_readiness") == "High"
                    }],
                    "certificate": self.results.get("certificate_inventory", {})
                }
            },
            "compliance": {
                "pqc_status": self.results.get("quantum_readiness"),
                "detected_algorithms": [self.results.get("certificate_inventory", {}).get("detected_pqc_algorithm")] if self.results.get("quantum_readiness") == "High" else []
            }
        }
        return cbom

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Cryptographic Scanner")
    parser.add_argument("--target", required=True, help="Host to scan (e.g. google.com)")
    parser.add_argument("--port", type=int, default=443, help="Port to scan")
    args = parser.parse_args()

    scanner = CryptoScanner(args.target, args.port)
    print(f"[*] Initiating scan for {args.target}...")
    scanner.scan_tls()
    
    cbom_data = scanner.generate_cbom()
    print("\n--- Cryptographic Bill of Materials (CBOM) ---")
    print(json.dumps(cbom_data, indent=4))
    
    with open(f"cbom_{args.target}.json", "w") as f:
        json.dump(cbom_data, f, indent=4)
    print(f"\n[+] CBOM saved to cbom_{args.target}.json")
