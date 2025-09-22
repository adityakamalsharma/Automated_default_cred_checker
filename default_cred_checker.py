#!/usr/bin/env python3
"""
default_cred_checker.py

Purpose:
  - For authorized penetration-testing labs only.
  - Run nmap service/version scan on a target (IP or CIDR), parse results,
    and attempt default-credential checks for certain services (SSH, FTP, SMB, RDP,
    HTTP(S) with login form) using Hydra (and CrackMapExec for SMB).
  - Saves successes to JSON and CSV.

Requirements (install before running):
  - nmap
  - hydra
  - crackmapexec (for SMB) [optional but recommended for SMB]
  - python3 packages: requests, beautifulsoup4
    -> pip3 install requests beautifulsoup4

IMPORTANT:
  Use this script ONLY on systems you have explicit permission to test.
  Misuse against unauthorized systems may be illegal.

Author: Generated for an authorized pentesting lab (Aditya)
"""

import argparse
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import os
import sys
import shutil
import time
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Optional imports for HTTP form detection
try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

# -------------------------
# Configuration / Defaults
# -------------------------
SECLISTS_DEFAULTS_DIR = "/usr/share/seclists/Passwords/Default-Credentials/"
OUTPUT_DIR = "default_cred_results"
NMAP_BINARY = shutil.which("nmap") or "nmap"
HYDRA_BINARY = shutil.which("hydra") or "hydra"
CME_BINARY = shutil.which("crackmapexec") or "crackmapexec"

# Services we will check (keys are normalized service identifiers)
SERVICE_CHECKS = {
    "ssh": "handle_ssh",
    "ftp": "handle_ftp",
    "smb": "handle_smb",
    "ms-wbt" : "handle_rdp",  # nmap sometimes reports ms-wbt-server or ms-wbt
    "rdp": "handle_rdp",
    "http": "handle_http",
    "https": "handle_http"
}

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -------------------------
# Utility functions
# -------------------------
def run_command(cmd: List[str], capture_output: bool = False, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run a subprocess command and return CompletedProcess. Logs command."""
    logging.debug("Running command: %s", " ".join(cmd))
    try:
        if capture_output:
            return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            return subprocess.run(cmd, check=False, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        logging.warning("Command timed out: %s", e)
        raise

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def timestamp_now() -> str:
    return datetime.utcnow().isoformat() + "Z"

# -------------------------
# Nmap scan and parsing
# -------------------------
def run_nmap_service_scan(target: str, extra_args: Optional[List[str]] = None) -> str:
    """
    Run nmap service/version scan and write XML to a temp file.
    Returns path to XML file.
    """
    ensure_output_dir()
    xml_path = os.path.join(OUTPUT_DIR, f"nmap_{target.replace('/', '_')}_{int(time.time())}.xml")
    cmd = [NMAP_BINARY, "-sV", "-p-", "-T4", "-oX", xml_path, target]
    if extra_args:
        cmd[1:1] = extra_args  # insert extra args after binary
    logging.info("Starting nmap scan (this may take a while). Output: %s", xml_path)
    res = run_command(cmd)
    if res.returncode != 0:
        logging.warning("nmap finished with non-zero return code (%s). Check nmap output.", res.returncode)
    else:
        logging.info("nmap scan complete.")
    return xml_path

def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    """
    Parse nmap XML and return a list of services as dicts:
    {host, ip, port, protocol, state, service_name, product, version, tunnel}
    """
    if not os.path.exists(xml_path):
        raise FileNotFoundError(xml_path)
    tree = ET.parse(xml_path)
    root = tree.getroot()
    services = []
    for host in root.findall("host"):
        # Find address
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None
        hostnames_el = host.find("hostnames")
        hostname = None
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port.find("service")
            service = service_el.get("name") if service_el is not None and service_el.get("name") else ""
            product = service_el.get("product") if service_el is not None else ""
            version = service_el.get("version") if service_el is not None else ""
            tunnel = service_el.get("tunnel") if service_el is not None else ""
            services.append({
                "host": hostname or ip,
                "ip": ip,
                "port": int(portid),
                "protocol": protocol,
                "state": state_el.get("state"),
                "service": service.lower() if service else "",
                "product": product,
                "version": version,
                "tunnel": tunnel
            })
    logging.info("Parsed %d open TCP service(s) from nmap XML.", len(services))
    return services

# -------------------------
# Build combos file from Seclists
# -------------------------
def build_combo_file_from_seclists(seclists_dir: str = SECLISTS_DEFAULTS_DIR) -> str:
    """
    Scan the seclists default creds directory for files containing 'user:pass' combos,
    collect lines that look like username:password, and write them to a temp file suitable for hydra -C.
    Returns path to combos file.
    """
    combos = []
    dirpath = Path(seclists_dir)
    if not dirpath.exists():
        logging.warning("Seclists directory '%s' not found. No combos created.", seclists_dir)
        # create empty combos file
        fd, path = tempfile.mkstemp(prefix="combos_", text=True)
        os.close(fd)
        return path

    logging.info("Building combos file from Seclists directory: %s", seclists_dir)
    for f in dirpath.rglob("*"):
        if f.is_file():
            try:
                with f.open("r", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # basic detection of user:pass formatted lines
                        if ":" in line:
                            # sometimes files contain many formats; accept lines with exactly one colon or multiple (we'll use first two fields)
                            parts = line.split(":")
                            username = parts[0].strip()
                            password = ":".join(parts[1:]).strip()
                            if username and password:
                                combos.append(f"{username}:{password}")
            except Exception as e:
                logging.debug("Skipping file %s due to read error: %s", f, e)
    combos = list(dict.fromkeys(combos))  # deduplicate while preserving order
    logging.info("Collected %d combos.", len(combos))
    # write to temp file
    fd, path = tempfile.mkstemp(prefix="combos_", text=True)
    with os.fdopen(fd, "w") as fh:
        for c in combos:
            fh.write(c + "\n")
    logging.info("Combos written to %s", path)
    return path

# -------------------------
# Credential checking helpers
# -------------------------
def run_hydra_combo(service_proto: str, target_ip: str, port: int, combo_file: str, extra_hydra_args: Optional[List[str]] = None, timeout: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Run hydra using a combo file (-C). Returns list of found creds dicts.
    Note: service_proto is hydra's service string, e.g., 'ssh', 'ftp', 'http-get', 'http-post-form', etc.
    """
    found = []
    if not shutil.which(HYDRA_BINARY):
        logging.warning("Hydra not found. Skipping hydra checks for %s:%d", target_ip, port)
        return found

    # Construct hydra command
    cmd = [HYDRA_BINARY, "-C", combo_file, "-s", str(port), "-f", "-o", os.path.join(OUTPUT_DIR, f"hydra_{service_proto}_{target_ip}_{port}.txt")]
    # For some services hydra needs the target format (e.g., ssh://ip)
    target_spec = f"{service_proto}://{target_ip}"
    cmd.append(target_spec)
    if extra_hydra_args:
        cmd[1:1] = extra_hydra_args  # insert after hydra binary
    logging.info("Running hydra against %s:%d (service: %s)", target_ip, port, service_proto)
    try:
        res = run_command(cmd, capture_output=True, timeout=timeout)
    except Exception as e:
        logging.warning("Hydra run failed/timeout: %s", e)
        return found

    # Parse hydra output file for successful logins (hydra prints 'login:' lines to output file)
    outpath = os.path.join(OUTPUT_DIR, f"hydra_{service_proto}_{target_ip}_{port}.txt")
    if os.path.exists(outpath):
        with open(outpath, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                # hydra success lines often look like: "[80][ssh] host: 10.0.0.1   login: root   password: toor"
                if "login:" in line and "password:" in line:
                    # naive parse
                    try:
                        parts = line.split()
                        login_idx = parts.index("login:") if "login:" in parts else None
                        passwd_idx = parts.index("password:") if "password:" in parts else None
                        if login_idx is not None and passwd_idx is not None:
                            username = parts[login_idx + 1]
                            password = parts[passwd_idx + 1]
                            found.append({
                                "service": service_proto,
                                "ip": target_ip,
                                "port": port,
                                "username": username,
                                "password": password,
                                "timestamp": timestamp_now()
                            })
                    except Exception:
                        continue
    else:
        logging.debug("Hydra output file not found: %s", outpath)
    return found

def run_cme_smb(target_ip: str, port: int, combos_file: str, timeout: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Use crackmapexec (cme) for SMB enumeration / default creds check.
    This will iterate combos from combos_file and try them. CME can be invoked per combo.
    Returns list of found creds.
    NOTE: CME is powerful and may be noisy; use only in authorized labs.
    """
    found = []
    if not shutil.which(CME_BINARY):
        logging.warning("CrackMapExec not found. Skipping SMB checks for %s:%d", target_ip, port)
        return found

    # Read combos and try them one by one with CME (this is not the most efficient but is straightforward)
    try:
        with open(combos_file, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                user, password = line.split(":", 1)
                cmd = [CME_BINARY, "smb", f"{target_ip}", "-u", user, "-p", password, "--no-bruteforce"]
                # if non-standard port:
                if port and port != 445:
                    cmd.extend(["-p", str(port)])
                logging.debug("Running CME for SMB combo %s:%s", user, "****")
                try:
                    res = run_command(cmd, capture_output=True, timeout=timeout)
                    out = res.stdout or ""
                    # naive detection: look for "SUCCESS" or "Authenticated" in output
                    if "Authenticated" in out or "SUCCESS" in out or "SMB" in out and "Sign/Seal" in out:
                        logging.info("Successful SMB auth: %s:%s", user, "****")
                        found.append({
                            "service": "smb",
                            "ip": target_ip,
                            "port": port,
                            "username": user,
                            "password": password,
                            "timestamp": timestamp_now()
                        })
                except Exception as e:
                    logging.debug("CME call error: %s", e)
    except FileNotFoundError:
        logging.warning("Combos file not found for CME: %s", combos_file)
    return found

# -------------------------
# Service handlers (modular)
# -------------------------
def handle_ssh(svc: Dict[str, Any], combos_file: str) -> List[Dict[str, Any]]:
    # Use hydra with ssh
    return run_hydra_combo("ssh", svc["ip"], svc["port"], combos_file)

def handle_ftp(svc: Dict[str, Any], combos_file: str) -> List[Dict[str, Any]]:
    return run_hydra_combo("ftp", svc["ip"], svc["port"], combos_file)

def handle_smb(svc: Dict[str, Any], combos_file: str) -> List[Dict[str, Any]]:
    # For SMB prefer crackmapexec
    return run_cme_smb(svc["ip"], svc["port"], combos_file)

def handle_rdp(svc: Dict[str, Any], combos_file: str) -> List[Dict[str, Any]]:
    # hydra has an rdp module (rdp) on some systems; using hydra - but many setups don't support rdp via hydra due to protocol limitations.
    # We'll try hydra if available; else just log.
    return run_hydra_combo("rdp", svc["ip"], svc["port"], combos_file)

def detect_http_login_form(ip: str, port: int, use_https: bool = False, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Try to fetch the root page and heuristically detect a login form.
    Returns a dict with keys: 'path', 'user_field', 'pass_field', 'failure_regex' to use with hydra http-post-form,
    or None if no reasonable form found.
    This is heuristic and not guaranteed; in lab it often helps for common apps.
    """
    if requests is None or BeautifulSoup is None:
        logging.debug("requests/BeautifulSoup not available; skipping HTTP form detection.")
        return None
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=timeout, verify=False)
    except Exception as e:
        logging.debug("HTTP fetch failed for %s: %s", url, e)
        return None
    if r.status_code >= 400:
        logging.debug("HTTP status %d for %s", r.status_code, url)
    html = r.text
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return None
    action = form.get("action") or "/"
    # find input fields
    inputs = form.find_all("input")
    user_field = None
    pass_field = None
    for inp in inputs:
        t = (inp.get("type") or "").lower()
        name = inp.get("name") or inp.get("id") or ""
        if not name:
            continue
        if t in ("password",):
            pass_field = name
        elif any(k in name.lower() for k in ("user", "email", "login", "username")) or t in ("text", "email"):
            user_field = name
    # try to find a failure string (common patterns)
    fail_candidates = []
    for s in ["invalid", "incorrect", "failed", "error", "unauthorized", "try again", "login"]:
        if s in html.lower():
            fail_candidates.append(s)
    failure_regex = fail_candidates[0] if fail_candidates else "invalid"
    if user_field and pass_field:
        logging.info("Detected login form at %s (action=%s) user_field=%s pass_field=%s", url, action, user_field, pass_field)
        return {
            "action": action,
            "user_field": user_field,
            "pass_field": pass_field,
            "failure": failure_regex,
            "url": url
        }
    return None

def handle_http(svc: Dict[str, Any], combos_file: str) -> List[Dict[str, Any]]:
    """
    For HTTP(S) attempt to detect a login form. If detected, construct hydra http-post-form invocation.
    This is heuristic; for complex apps you will need a custom module.
    """
    use_https = (svc["service"] == "https") or (svc["port"] == 443)
    detected = detect_http_login_form(svc["ip"], svc["port"], use_https=use_https)
    if not detected:
        logging.info("No obvious login form detected at %s:%d", svc["ip"], svc["port"])
        return []
    # Build hydra http-post-form string:
    # path:params:failure
    path = detected["action"]
    # ensure path begins with /
    if not path.startswith("/"):
        # if action is relative, prefix with '/'
        path = "/" + path
    # Construct param string like: "username=^USER^&password=^PASS^"
    param = f"{detected['user_field']}=^USER^&{detected['pass_field']}=^PASS^"
    hydra_form_arg = f"{path}:{param}:{detected['failure']}"
    logging.debug("Hydra http-post-form parameter: %s", hydra_form_arg)
    # hydra service name for HTTP POST form:
    return run_hydra_combo("http-post-form", svc["ip"], svc["port"], combos_file, extra_hydra_args=[hydra_form_arg])

# Map handler name to function object for modularity
HANDLER_MAP = {
    "handle_ssh": handle_ssh,
    "handle_ftp": handle_ftp,
    "handle_smb": handle_smb,
    "handle_rdp": handle_rdp,
    "handle_http": handle_http
}

# -------------------------
# Result saving
# -------------------------
def save_results(found: List[Dict[str, Any]]):
    """Append found credentials to JSON and CSV files."""
    if not found:
        logging.info("No credentials found to save.")
        return
    ensure_output_dir()
    json_path = os.path.join(OUTPUT_DIR, "credentials_found.json")
    csv_path = os.path.join(OUTPUT_DIR, "credentials_found.csv")
    # Load existing JSON
    existing = []
    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as fh:
                existing = json.load(fh)
        except Exception:
            existing = []
    existing.extend(found)
    with open(json_path, "w") as fh:
        json.dump(existing, fh, indent=2)
    # Write CSV (overwrite with aggregated JSON content to avoid duplicates)
    with open(csv_path, "w", newline="") as csvfile:
        fieldnames = ["service", "ip", "port", "username", "password", "timestamp"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in existing:
            writer.writerow({k: item.get(k, "") for k in fieldnames})
    logging.info("Saved %d credential(s). JSON: %s CSV: %s", len(found), json_path, csv_path)

# -------------------------
# Main orchestration
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Default credential checker — authorized pentesting only.")
    parser.add_argument("target", help="Target IP or CIDR (authorized testing only)")
    parser.add_argument("--nmap-args", nargs="*", help="Extra nmap args to insert (e.g., -Pn)", default=[])
    parser.add_argument("--skip-http-detect", action="store_true", help="Skip HTTP login form detection")
    parser.add_argument("--seclists-dir", default=SECLISTS_DEFAULTS_DIR, help="Path to Seclists default-credentials directory")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout for external tool runs (seconds)")
    args = parser.parse_args()

    # Safety reminder
    logging.info("=== AUTHORIZATION REMINDER ===")
    logging.info("Run this script only against targets you have explicit permission to test.")
    logging.info("Target provided: %s", args.target)

    # Check dependencies
    logging.info("Checking external tools...")
    logging.info("nmap: %s", NMAP_BINARY if shutil.which(NMAP_BINARY) else "NOT FOUND")
    logging.info("hydra: %s", HYDRA_BINARY if shutil.which(HYDRA_BINARY) else "NOT FOUND")
    logging.info("crackmapexec: %s", CME_BINARY if shutil.which(CME_BINARY) else "NOT FOUND")
    if requests is None or BeautifulSoup is None:
        logging.info("Note: requests/beautifulsoup4 not installed — HTTP form auto-detection will be disabled.")
        logging.info("Install with: pip3 install requests beautifulsoup4")

    # 1) Run nmap
    try:
        xml_path = run_nmap_service_scan(args.target, extra_args=args.nmap_args)
    except Exception as e:
        logging.error("Failed to run nmap: %s", e)
        sys.exit(1)

    # 2) Parse nmap XML
    try:
        services = parse_nmap_xml(xml_path)
    except Exception as e:
        logging.error("Failed to parse nmap XML: %s", e)
        sys.exit(1)

    if not services:
        logging.info("No open TCP services discovered by nmap. Exiting.")
        sys.exit(0)

    # 3) Build combos file
    combos_file = build_combo_file_from_seclists(args.seclists_dir)

    # 4) For each service, decide whether to run default-cred check
    aggregated_found = []
    for svc in services:
        svc_name = svc.get("service", "")
        port = svc.get("port")
        ip = svc.get("ip")
        logging.info("Service discovered: %s on %s:%d (product=%s version=%s)", svc_name, ip, port, svc.get("product"), svc.get("version"))

        # map nmap service names to our check list heuristically
        normalized = svc_name.lower()
        # also check product string for clues (e.g., 'http' may be reported differently)
        if "http" in normalized or svc.get("tunnel") == "ssl" or port in (80, 443, 8080, 8443):
            handler_key = "handle_http"
        elif "ssh" in normalized:
            handler_key = "handle_ssh"
        elif "ftp" in normalized:
            handler_key = "handle_ftp"
        elif "smb" in normalized or "microsoft-ds" in normalized or port == 445:
            handler_key = "handle_smb"
        elif "rdp" in normalized or "ms-wbt" in normalized or port == 3389:
            handler_key = "handle_rdp"
        else:
            logging.debug("No default-cred module for service: %s", svc_name)
            continue

        # Skip http detection if flag is set
        if handler_key == "handle_http" and args.skip_http_detect:
            logging.info("Skipping HTTP detection for %s:%d due to --skip-http-detect", ip, port)
            continue

        handler_fn = HANDLER_MAP.get(handler_key)
        if not handler_fn:
            logging.debug("Handler not implemented for key %s", handler_key)
            continue

        try:
            found = handler_fn(svc, combos_file)
            if found:
                logging.info("Found %d credential(s) for %s:%d", len(found), ip, port)
                aggregated_found.extend(found)
            else:
                logging.info("No credentials found for %s:%d", ip, port)
        except Exception as e:
            logging.warning("Error when running handler %s for %s:%d : %s", handler_key, ip, port, e)

    # 5) Save results
    save_results(aggregated_found)

    # Clean up combos file
    try:
        os.remove(combos_file)
    except Exception:
        pass

    logging.info("Done. Check %s for results and hydra/CME output files.", OUTPUT_DIR)
    # Print quick dependency & run instructions
    print("\n=== Quick install & run instructions ===")
    print("Install system dependencies (Debian/Ubuntu example):")
    print("  sudo apt update && sudo apt install -y nmap hydra crackmapexec")
    print("Install python deps:")
    print("  pip3 install requests beautifulsoup4")
    print("Run (authorized target):")
    print("  python3 default_cred_checker.py 10.0.0.5")
    print("Optional: pass extra nmap args (e.g., -Pn):")
    print("  python3 default_cred_checker.py 10.0.0.0/24 --nmap-args -Pn")
    print("Results saved in the 'default_cred_results' directory.\n")

if __name__ == "__main__":
    main()
