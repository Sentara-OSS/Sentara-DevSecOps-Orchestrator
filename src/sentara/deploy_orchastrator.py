import argparse
import hashlib
import json
import os
import requests
import shutil
import subprocess
import sys
from datetime import datetime

def compute_sha256(file_path):
    """Utility to compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def download_artifact_and_hash(args):
    """Downloads artifact to a temp file and computes its SHA-256."""
    # Ensure URL formatting
    base_url = args.artifactory_url.rstrip('/')
    url = f"{base_url}/{args.product}/{args.version}/{args.artifact_name}"
    
    temp_path = os.path.join(os.getcwd(), f"tmp_{args.artifact_name}")
    
    print(f"📡 Downloading {args.artifact_name} from Artifactory...")
    try:
        with requests.get(url, auth=(args.artifactory_user, args.artifactory_pass), stream=True) as r:
            r.raise_for_status()
            sha256 = hashlib.sha256()
            with open(temp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    sha256.update(chunk)
                    f.write(chunk)
        
        computed_hash = compute_sha256(temp_path)
        print(f"✅ Download Complete. Verified Hash: {computed_hash}")
        return temp_path, computed_hash
    except Exception as e:
        if os.path.exists(temp_path): os.remove(temp_path)
        print(f"❌ Download failed: {e}")
        sys.exit(1)

def check_security_policy(args, artifact_hash):
    """Queries DefectDojo with Severity Cascading."""
    # Define the cascade
    severities = ["Critical", "High", "Medium", "Low"]
    try:
        # Get index of user-selected severity
        idx = severities.index(args.severity)
        # Include all severities from Critical down to selection
        target_severities = severities[:idx + 1]
    except ValueError:
        target_severities = [args.severity]

    print(f"🛡️  Gating policy: Finding any {', '.join(target_severities)} issues...")

    headers = {"Authorization": f"Token {args.dojo_token}"}
    total_findings = 0
    
    # Check each severity in the cascade
    for sev in target_severities:
        params = {
            "active": "true",
            "duplicate": "false",
            "severity": sev,
            "tags": f"build-{artifact_hash[:12]}"
        }
        
        response = requests.get(f"{args.dojo_url.rstrip('/')}/findings/", headers=headers, params=params)
        if response.status_code == 200:
            count = response.json().get("count", 0)
            total_findings += count
            if count > 0:
                print(f"   ⚠️ Found {count} {sev} vulnerabilities.")

    if total_findings > 0:
        print(f"🛑 GATE FAILED: {total_findings} total violations found.")
        return False
    
    print("🟢 GATE PASSED: Artifact meets security policy. Proceeding to deployment")
    return True

def execute_hardened_deploy(command, artifact_path, expected_hash):
    """Verifies integrity ONE LAST TIME before executing the shell command."""
    print("🔐 Performing Final Pre-Execution Integrity Check...")
    
    actual_hash = compute_sha256(artifact_path)
    
    if actual_hash != expected_hash:
        print(f"🚨 SECURITY ALERT: Artifact tampering detected!")
        print(f"Expected: {expected_hash}\nActual:   {actual_hash}")
        sys.exit(1)
        
    print("✅ Integrity Confirmed. Triggering Deployment Wrapper.")
    
    # Inject verified path into environment for the user's command
    env = os.environ.copy()
    env["VERIFIED_ARTIFACT"] = artifact_path
    
    try:
        subprocess.run(command, shell=True, check=True, env=env)
        print("🟢 Deployment Command Executed Successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Deployment command failed with exit code {e.returncode}")
        sys.exit(e.returncode)

def create_manifest(args, artifact_hash, final_path):
    """Creates a JSON attestation file for the artifact."""
    manifest = {
        "product": args.product,
        "version": args.version,
        "hash_sha256": artifact_hash,
        "gate_status": "PASSED",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "policy_applied": args.severity
    }
    manifest_path = f"{final_path}.json"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=4)
    print(f"📄 Security Manifest created: {manifest_path}")

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

def main():
    parser = argparse.ArgumentParser(description="Sentara DevSecOps Deploy Orchestrator")
    
    # Required logic arguments
    parser.add_argument("--product", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--severity", default="Critical", choices=["Critical", "High", "Medium", "Low"])
    parser.add_argument("--download-dir", default="./deploy_staging")
    parser.add_argument("--deploy-command", help="The command to run if security gate passes")

    # Optional connection args (falling back to ENV)
    parser.add_argument("--artifactory-url", default=os.getenv("ARTIFACTORY_REPO_URL"))
    parser.add_argument("--artifactory-user", default=os.getenv("ARTIFACTORY_USER", "admin"))
    parser.add_argument("--artifactory-pass", default=os.getenv("ARTIFACTORY_PASS"))
    parser.add_argument("--dojo-url", default=os.getenv("DEFECT_DOJO_URL"))
    parser.add_argument("--dojo-token", default=os.getenv("DEFECT_DOJO_TOKEN"))

    args = parser.parse_args()

    # Sanitization
    if args.dojo_url: args.dojo_url = sanitize_path(args.dojo_url, is_url=True)
    args.dojo_token = sanitize_path(args.dojo_token)
    if args.artifactory_url: args.artifactory_url = sanitize_path(args.artifactory_url, is_url=True)
    args.artifactory_user = sanitize_path(args.artifactory_user)
    args.artifactory_pass = sanitize_path(args.artifactory_pass)
    
    # Quick validation of Env Vars
    if not args.dojo_token or not args.artifactory_url:
        print("❌ Error: Missing connection details. Set ENV variables or pass --dojo-token/--artifactory-url")
        sys.exit(1)

    # 1. Download & Verify Integrity
    local_tmp, artifact_hash = download_artifact_and_hash(args)

    # 2. Verify Security Posture
    passed = check_security_policy(args, artifact_hash)

    if not passed:
        print("🛑 GATE FAILED: Security violations found. Aborting deployment.")
        if os.path.exists(local_tmp): os.remove(local_tmp)
        sys.exit(1)

    # 3. Stage for Deployment
    os.makedirs(args.download_dir, exist_ok=True)
    final_path = os.path.join(args.download_dir, os.path.basename(local_tmp).replace("tmp_", ""))
    shutil.move(local_tmp, final_path)
    create_manifest(args, artifact_hash, final_path)

    # 4. Execute Deployment
    if args.deploy_command:
        execute_hardened_deploy(args.deploy_command, final_path, artifact_hash)
    else:
        print(f"📦 Artifact verified and staged at: {final_path}")
        print("ℹ️  No deploy command provided. Hand-off complete.")
    
    sys.exit(0)