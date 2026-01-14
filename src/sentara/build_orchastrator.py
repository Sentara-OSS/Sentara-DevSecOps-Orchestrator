import argparse
import subprocess
import os
import sys
import requests
import hashlib
import re  # Needed for Unicode sanitization
from pathlib import Path

# --- COLORS FOR TERMINAL OUTPUT ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def log(message, level="INFO"):
    if level == "INFO":
        print(f"{Colors.OKBLUE}[INFO]{Colors.ENDC} {message}")
    elif level == "SUCCESS":
        print(f"{Colors.OKGREEN}[SUCCESS]{Colors.ENDC} {message}")
    elif level == "ERROR":
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {message}")

import subprocess
import sys
import json
import os
from datetime import datetime

def log_phase(message):
    YELLOW = "\033[1;33m"
    CYAN = "\033[1;36m"
    RESET = "\033[0m"
    width = 65
    line = "-" * width
    padding = (width - len(message)) // 2
    centered_msg = " " * padding + message
    
    # Adding flush=True ensures the message hits the terminal IMMEDIATELY
    print(f"\n{CYAN}{line}{RESET}", flush=True)
    print(f"{YELLOW}{centered_msg}{RESET}", flush=True)
    print(f"{CYAN}{line}{RESET}\n", flush=True)

# Check all tools readiness
def check_readiness():
    """Validates that all security engines are installed and logs their versions."""
    tools = {
        "semgrep": ["semgrep", "--version"],
        "syft": ["syft", "--version"],
        "grype": ["grype", "--version"],
        "detect-secrets": ["detect-secrets", "--version"]
    }
    
    audit_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "Initializing",
        "engines": {}
    }

    print("🛡️  Starting Sentara System Readiness Check...")
    
    all_passed = True
    for tool, version_cmd in tools.items():
        try:
            result = subprocess.run(version_cmd, capture_output=True, text=True, check=True)
            version_info = result.stdout.strip()
            audit_log["engines"][tool] = {"status": "INSTALLED", "version": version_info}
            print(f"✅ {tool.capitalize()} Verified: {version_info}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            audit_log["engines"][tool] = {"status": "MISSING"}
            print(f"❌ {tool.capitalize()} NOT FOUND")
            all_passed = False

    if not all_passed:
        print("🛑 SYSTEM ERROR: One or more security engines are missing. Aborting build.")
        sys.exit(1)

    # Save the Audit Manifest (This is key evidence for your NIW exhibit)
    with open("build_environment_audit.json", "w") as f:
        json.dump(audit_log, f, indent=4)
    
    print("📋 Environment Audit Log generated: build_environment_audit.json")
    return True

# This would be called at the very start of your main()
# --- HELPER: Path Sanitization ---
def sanitize_path(path_str, is_url=False):
    if not path_str:
        return path_str
    
    # Nuclear Option: Keep ONLY standard ASCII characters (letters, numbers, basic symbols)
    # This deletes \u202a, \ufeff, and any other hidden Unicode garbage
    path_str = "".join(char for char in path_str if ord(char) < 128)
    
    # Strip quotes and whitespace
    path_str = path_str.strip().replace('"', '').replace("'", "")
    
 # 3. Handle Normalization based on type
    if is_url:
        # For URLs, ensure forward slashes and no trailing slash
        return path_str.replace('\\', '/').rstrip('/')
    else:
        # For Files, use standard OS normalization (backslashes on Windows)
        return os.path.normpath(path_str)

# --- 1. CORE EXECUTION ---
def run_command(command, cwd):
    # 1. Force the command string to be pure ASCII to kill the \u202a for good
    clean_command = "".join(char for char in command if ord(char) < 128)
    
    # 2. Prepare a clean environment for the subprocess
    # We take the current OS environment and inject the UTF8 flag properly
    sub_env = os.environ.copy()
    sub_env["PYTHONUTF8"] = "1"
    
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"\n[{timestamp}] [INFO] Launching Security Task: {clean_command}")
    
    try:
        with subprocess.Popen(
            clean_command,
            shell=True,
            cwd=cwd,
            env=sub_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        ) as process:
            
            for line in process.stdout:
                # Real-time streaming for the demo
                print(f"  > {line.strip()}", flush=True)

            process.wait()

        if process.returncode == 0:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [SUCCESS] Task Passed.")
            return True
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [FAILURE] Task failed with code {process.returncode}")
            return False

    except Exception as e:
        print(f"[!] SYSTEM CRITICAL: {str(e)}")
        return False
    
def execute_build(build_cmd, cwd):
    log(f"Executing Build Command: '{build_cmd}'")
    return run_command(build_cmd, cwd)

def get_context(artifact_path):
    log("🔍 Extracting SCM and Artifact metadata...")
    branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).decode().strip()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    repo_url = subprocess.check_output(["git", "config", "--get", "remote.origin.url"]).decode().strip()
    
    with open(artifact_path, "rb") as f:
        artifact_hash = hashlib.sha256(f.read()).hexdigest()
    
    return branch, commit, repo_url, artifact_hash

# --- 2. SCANNERS ---
def run_security_scans(args, report_dir):
    cwd = args.repo_path
    reports = Path(report_dir)

    run_command("git config --global --add safe.directory /src_to_scan", cwd)
    
    if args.enable_sast:
        log("Running SAST (Semgrep)...")
        log_phase("SAST ANALYSIS")
        report_file = reports / "sast_report.json"
        cmd = f'semgrep scan . --config auto --json -o "{report_file}"'
        run_command(cmd, cwd)

    if args.enable_sca:
        log("Running SCA/SBOM (Syft)...")
        log_phase("SCA/SBOM ANALYSIS")
        sbom_file = reports / "sbom.json"
        vuln_file = reports / "vulnerability_report.json"
        
        # Syft command
        run_command(f'syft dir:. -o cyclonedx-json --file "{sbom_file}"', cwd)
        
        # Grype command (uses the SBOM we just made)
        log("Running Vulnerability Analysis (Grype)...")
        log_phase("VULNERABILITY ANALYSIS")
        run_command(f'grype sbom:"{sbom_file}" -o json > "{vuln_file}"', cwd)

    if args.enable_secrets:
        log("Running Secret Detection...")
        log_phase("SECRETS ANALYSIS")
        secret_file = reports / "secrets_report.json"
        cmd = f'detect-secrets scan . --all-files > "{secret_file}"'
        run_command(cmd, cwd)

# --- 3. UPLOADERS ---
def upload_to_repository(args, report_dir):
    log("🚀 Starting Artifactory Upload process...")
    if not args.artifactory_url:
        log("⚠️ Skipping Artifact Upload: No Repo URL provided.", "WARNING")
        return

    target_path = f"{args.artifactory_url.rstrip('/')}/{args.project_name}/{args.version}"
    sbom_path = Path(report_dir) / "sbom.json"
    
    for file_to_upload in [args.artifact_path, str(sbom_path)]:
        if not os.path.exists(file_to_upload): continue
        
        filename = os.path.basename(file_to_upload)
        dest_url = f"{target_path}/{filename}"
        
        log(f"📦 Uploading {filename} to Artifactory...")
        with open(file_to_upload, "rb") as f:
            r = requests.put(dest_url, data=f, auth=(args.artifactory_user, args.artifactory_pass))
            if r.status_code not in [200, 201]:
                log(f"❌ Upload failed: {r.status_code}", "ERROR")

def push_to_dojo(args, branch, commit, repo_url, artifact_hash, report_dir):
    log("🚀 Starting DefectDojo Sync...")
    if not args.dojo_token:
        log("⚠️ Skipping Dojo Upload: No Token provided.", "WARNING")
        return

    headers = {"Authorization": f"Token {args.dojo_token}"}
    reports = Path(report_dir)
    
    scan_configs = [
        (reports / "vulnerability_report.json", "Anchore Grype"),
        (reports / "sast_report.json", "Semgrep JSON Report"),
        (reports / "secrets_report.json", "Detect-secrets Scan")
    ]
    
    for file_path, scan_type in scan_configs:
        if not file_path.exists(): continue
        
        log(f"📤 Pushing {scan_type} to DefectDojo...")
        with open(file_path, "rb") as f:
            data = {
                "scan_type": scan_type,
                "product_type_name": args.product_type,
                "product_name": args.product,
                "engagement_name": f"Sentara-{branch}",
                "version": artifact_hash[:12],
                "commit_hash": commit,
                "branch_tag": branch,
                "source_code_management_uri": repo_url,
                "tags": f"build-{artifact_hash[:12]}",
                "apply_tags_to_findings": "true",
                "apply_tags_to_endpoints": "true",
                "auto_create_context": "true"
            }
            requests.post(f"{args.dojo_url}/import-scan/", headers=headers, data=data, files={'file': f})

# --- 4. MAIN ---
def main():
    parser = argparse.ArgumentParser(description="Senatara DevSecOps Build Orchestrator")
    parser.add_argument("--check-only", action="store_true", help="Check if all security tools are installed and exit.")
    parser.add_argument('--repo-path', default='.')
    parser.add_argument('--output-dir', default='./reports')
    parser.add_argument('--build-command', required=True)
    parser.add_argument('--project-name', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--artifact-path', required=True)
    parser.add_argument('--artifactory-url', default=os.getenv("ARTIFACTORY_REPO_URL"))
    parser.add_argument('--artifactory-user', default=os.getenv("ARTIFACTORY_USER"))
    parser.add_argument('--artifactory-pass', default=os.getenv("ARTIFACTORY_PASS"))
    parser.add_argument("--dojo-url", default=os.getenv("DEFECT_DOJO_URL"))
    parser.add_argument("--dojo-token", default=os.getenv("DEFECT_DOJO_TOKEN"))
    parser.add_argument("--product", default=os.getenv("DEFECT_DOJO_PRODUCT"))
    parser.add_argument("--product-type", default=os.getenv("DEFECT_DOJO_PRODUCT_TYPE", "Research and Development"))
    parser.add_argument('--no-sast', action='store_true')
    parser.add_argument('--no-sca', action='store_true')
    parser.add_argument('--no-secrets', action='store_true')

    args = parser.parse_args()

    # LOGIC: If the check-only flag is present, only run the readiness check
    if args.check_only:
        success = check_readiness() # Using the function we built earlier
        sys.exit(0 if success else 1)

    # Sanitization
    args.repo_path = sanitize_path(args.repo_path)
    args.artifact_path = sanitize_path(args.artifact_path)
    args.build_command = sanitize_path(args.build_command)
    args.output_dir = sanitize_path(args.output_dir)
    if args.artifactory_url: args.artifactory_url = sanitize_path(args.artifactory_url, is_url=True)
    if args.dojo_url: args.dojo_url = sanitize_path(args.dojo_url, is_url=True)

    args.enable_sast = not args.no_sast
    args.enable_sca = not args.no_sca
    args.enable_secrets = not args.no_secrets

    abs_report_dir = os.path.abspath(args.output_dir)
    os.makedirs(abs_report_dir, exist_ok=True)

    log("--- Senatara Orchestrator Started ---")

    if not execute_build(args.build_command, args.repo_path):
        sys.exit(1)

    # Context extracted AFTER build
    branch, commit, repo_url, artifact_hash = get_context(args.artifact_path)

    run_security_scans(args, abs_report_dir)
    upload_to_repository(args, abs_report_dir)
    push_to_dojo(args, branch, commit, repo_url, artifact_hash, abs_report_dir)

    log("--- Senatara Pipeline Finished Successfully ---", "SUCCESS")

if __name__ == "__main__":
    main()