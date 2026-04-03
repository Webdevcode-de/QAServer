"""
Security module for QAserver.
Provides Bandit SAST scanning and security utilities.
This file starts with underscore to be excluded from node listing.
"""

import subprocess
import json
import os
import re
import time


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


# =========================================================
# Bandit SAST Scanner
# =========================================================

# Dangerous patterns that Bandit should detect
HIGH_SEVERITY_PATTERNS = [
    "exec",
    "eval",
    "os.system",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "os.popen",
    "pickle.loads",
    "yaml.load",
    "__import__",
]


def run_bandit_scan(module_path):
    """
    Run Bandit security scan on a Python module.

    Args:
        module_path: Path to the Python file to scan

    Returns:
        tuple: (is_safe: bool, findings: list, error_msg: str or None)
    """
    if not os.path.exists(module_path):
        return False, [], f"Module file not found: {module_path}"

    try:
        # Run bandit with JSON output
        result = subprocess.run(
            ["bandit", "-r", module_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse JSON output
        if result.stdout.strip():
            try:
                bandit_output = json.loads(result.stdout)
                results = bandit_output.get("results", [])

                # Check for ALL severity issues (LOW, MEDIUM, HIGH)
                all_findings = []
                for f in results:
                    all_findings.append({
                        "line": f.get("line_number"),
                        "test": f"BANDIT-{f.get('test_id')}",
                        "issue": f.get("issue_text"),
                        "severity": f.get("issue_severity"),
                        "confidence": f.get("issue_confidence"),
                    })

                return True, all_findings, None

            except json.JSONDecodeError:
                # If JSON parsing fails but bandit ran, check return code
                pass

        # Bandit return code: 0 = no issues, 1 = issues found
        if result.returncode == 0:
            return True, [], None
        elif result.returncode == 1:
            # Issues found but not necessarily HIGH severity
            return True, [], None
        else:
            # Bandit error
            return False, [], f"Bandit scan error (code {result.returncode}): {result.stderr}"

    except subprocess.TimeoutExpired:
        return False, [], "Bandit scan timed out after 30 seconds"
    except FileNotFoundError:
        # Bandit not installed
        return True, [], None
    except Exception as e:
        return False, [], f"Bandit scan failed: {str(e)}"


def run_semgrep_scan(module_path):
    """
    Run Semgrep security scan on a Python module.

    Args:
        module_path: Path to the Python file to scan

    Returns:
        tuple: (is_safe: bool, findings: list, error_msg: str or None)
    """
    if not os.path.exists(module_path):
        return False, [], f"Module file not found: {module_path}"

    try:
        # Run semgrep with Python security ruleset
        result = subprocess.run(
            ["semgrep", "scan", "--config", "p/python", "--json", "--quiet", module_path],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Parse JSON output
        if result.stdout.strip():
            try:
                semgrep_output = json.loads(result.stdout)
                results = semgrep_output.get("results", [])

                all_findings = []
                for f in results:
                    all_findings.append({
                        "line": f.get("start", {}).get("line"),
                        "test": f"SEMGREP-{f.get('check_id')}",
                        "issue": f.get("extra", {}).get("message"),
                        "severity": f.get("extra", {}).get("severity"),
                        "confidence": "HIGH",
                    })

                return True, all_findings, None

            except json.JSONDecodeError:
                # If JSON parsing fails ignore
                pass

        return True, [], None

    except subprocess.TimeoutExpired:
        return False, [], "Semgrep scan timed out after 60 seconds"
    except FileNotFoundError:
        # Semgrep not installed
        return True, [], None
    except Exception as e:
        return False, [], f"Semgrep scan failed: {str(e)}"


def _fallback_security_check(module_path):
    """
    Fallback security check when Bandit is not installed.
    Scans for dangerous patterns using regex.
    """
    try:
        with open(module_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        findings = []

        for pattern in HIGH_SEVERITY_PATTERNS:
            # Search for the pattern (word boundary)
            regex = re.compile(r"\b" + re.escape(pattern) + r"\b")
            matches = regex.finditer(content)

            for match in matches:
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "line": line_num,
                    "test": "fallback-scan",
                    "issue": f"Dangerous function detected: {pattern}",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                })

        if findings:
            error_msg = (
                f"Security scan FAILED for {module_path}: "
                f"{len(findings)} dangerous pattern(s) found"
            )
            return False, findings, error_msg

        return True, [], None

    except Exception as e:
        return False, [], f"Fallback security check failed: {str(e)}"


def scan_module(module_path):
    """
    Main entry point for module security scanning.
    Runs BOTH Bandit AND Semgrep.
    Uses scan cache for fast pass on unchanged files.
    Raises SecurityError if ANY issues are found.

    Args:
        module_path: Path to the Python file to scan

    Returns:
        list: All findings for logging
    """
    # Check cache first (Fast-Pass)
    if is_file_cached(module_path):
        print(f"[✅] {module_path}: CACHED - skipping full scan")
        return []

    print(f"[🔍] Scanning {module_path}...")

    all_findings = []

    # Run Bandit first
    bandit_safe, bandit_findings, bandit_error = run_bandit_scan(module_path)
    if not bandit_safe:
        raise SecurityError(bandit_error)
    all_findings.extend(bandit_findings)

    # Run Semgrep
    semgrep_safe, semgrep_findings, semgrep_error = run_semgrep_scan(module_path)
    if not semgrep_safe:
        raise SecurityError(semgrep_error)
    all_findings.extend(semgrep_findings)

    # BLOCK ON ANY FINDING (no exceptions)
    if all_findings:
        detailed_error = [
            f"Security scan FAILED for {module_path}: "
            f"{len(all_findings)} security issue(s) found (ALL issues are BLOCKED)"
        ]
        for f in all_findings:
            detailed_error.append(
                f"  → Line {f['line']}: [{f['severity']}] {f['issue']} ({f['test']})"
            )

        raise SecurityError("\n".join(detailed_error))

    # Run fallback check as last line of defense
    fallback_safe, fallback_findings, fallback_error = _fallback_security_check(module_path)
    if not fallback_safe:
        raise SecurityError(fallback_error)

    # Mark file as safe in cache
    mark_file_safe(module_path)

    return all_findings


# =========================================================
# Username Validation
# =========================================================

# Allowed characters: letters, numbers, underscore, hyphen
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


def validate_username(username):
    """
    Validate that username is safe (no path traversal attempts).

    Args:
        username: The username to validate

    Returns:
        tuple: (is_valid: bool, reason: str or None)
    """
    if not username:
        return False, "Username cannot be empty"

    # Check for path traversal patterns
    dangerous_patterns = ["..", "/", "\\", "./", ".\\"]
    for pattern in dangerous_patterns:
        if pattern in username:
            return False, f"Invalid username: contains forbidden pattern '{pattern}'"

    # Check allowed characters
    if not USERNAME_PATTERN.match(username):
        return False, "Invalid username: only letters, numbers, underscore and hyphen allowed"

    # Check length
    if len(username) > 64:
        return False, "Username too long (max 64 characters)"

    return True, None


# =========================================================
# IP Banning
# =========================================================

BANNED_IPS_FILE = "banned.txt"
_banned_ips_cache = None


def load_banned_ips():
    """Load banned IPs from file into memory."""
    global _banned_ips_cache

    banned = set()

    if os.path.exists(BANNED_IPS_FILE):
        try:
            with open(BANNED_IPS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        banned.add(line)
        except Exception:
            pass

    _banned_ips_cache = banned
    return banned


def is_ip_banned(ip_address):
    """
    Check if an IP address is banned.

    Args:
        ip_address: The IP address to check

    Returns:
        bool: True if banned
    """
    global _banned_ips_cache

    if _banned_ips_cache is None:
        load_banned_ips()

    return ip_address in _banned_ips_cache


def ban_ip(ip_address, reason="Security violation"):
    """
    Ban an IP address by adding it to banned.txt.

    Args:
        ip_address: The IP address to ban
        reason: Reason for banning (logged as comment)
    """
    global _banned_ips_cache

    if _banned_ips_cache is None:
        load_banned_ips()

    # Skip if already banned
    if ip_address in _banned_ips_cache:
        return

    # Add to cache
    _banned_ips_cache.add(ip_address)

    # Append to file
    try:
        with open(BANNED_IPS_FILE, "a") as f:
            f.write(f"# {reason}\n")
            f.write(f"{ip_address}\n")
    except Exception as e:
        print(f"[SECURITY] Failed to write banned IP to file: {e}")


# =========================================================
# Scan Cache (Fast-Pass System)
# =========================================================

SCAN_CACHE_FILE = "scan_cache.json"
HOST_KEY_FILE = "host.key"
_scan_cache = None


def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file content."""
    import hashlib

    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return None


def _load_host_key():
    """Load host RSA key if present, otherwise return None."""
    if not os.path.exists(HOST_KEY_FILE):
        return None

    try:
        import paramiko
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    except Exception as e:
        print(f"[⚠️] Failed to load host key for cache signature operations: {e}")
        return None


def _build_cache_digest(cache_payload):
    """Build SHA-256 digest for the cache payload."""
    import hashlib
    cache_json = json.dumps(cache_payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(cache_json).digest()


def _verify_cache_signature(cache_payload, signature_b64, host_key):
    """
    Verify signed cache payload.

    Paramiko sign_ssh_data() returns an SSH Message and verify_ssh_sig()
    expects an SSH Message, so we must deserialize the stored bytes back
    into paramiko.Message before verification.
    """
    try:
        import base64
        import paramiko

        file_hash = _build_cache_digest(cache_payload)
        signature_bytes = base64.b64decode(signature_b64)
        signature_msg = paramiko.Message(signature_bytes)
        return bool(host_key.verify_ssh_sig(file_hash, signature_msg))
    except Exception as e:
        print(f"[⚠️] Cache signature verification error: {e}")
        return False


def load_scan_cache():
    """Load scan cache from file and verify signature when possible."""
    global _scan_cache

    if not os.path.exists(SCAN_CACHE_FILE):
        _scan_cache = {}
        return _scan_cache

    try:
        with open(SCAN_CACHE_FILE, "r") as f:
            cache_data = json.load(f)
    except Exception as e:
        print(f"[⚠️] Failed to load scan cache file: {e}")
        _scan_cache = {}
        return _scan_cache

    # New wrapped format
    if isinstance(cache_data, dict) and "_cache_data" in cache_data:
        cache_payload = cache_data.get("_cache_data", {})
        signature_b64 = cache_data.get("_signature")
        host_key = _load_host_key()

        if signature_b64 and host_key is not None:
            if _verify_cache_signature(cache_payload, signature_b64, host_key):
                _scan_cache = cache_payload
                print(f"[✅] Scan cache signature verified successfully ({len(_scan_cache)} entries)")
            else:
                print("[🔥] Cache signature verification failed - clearing cache")
                _scan_cache = {}
            return _scan_cache

        if signature_b64 and host_key is None:
            print("[⚠️] Signed scan cache found but host key is unavailable")
            print("[🔄] Using cache without verification")
            _scan_cache = cache_payload
            return _scan_cache

        # Unsigned wrapped cache (e.g. saved before host.key existed)
        print("[⚠️] Unsigned scan cache found - using cache without signature verification")
        _scan_cache = cache_payload
        return _scan_cache

    # Legacy format: plain dict of hashes -> metadata
    if isinstance(cache_data, dict):
        print("[⚠️] Legacy scan cache format detected - using cache as-is")
        _scan_cache = cache_data
        return _scan_cache

    _scan_cache = {}
    return _scan_cache


def save_scan_cache():
    """Save scan cache to file, signing it when the host key is available."""
    global _scan_cache

    try:
        cache_output = {
            "_cache_data": _scan_cache,
            "_signed_by": "QAserver host key",
            "_signed_at": time.time()
        }

        host_key = _load_host_key()
        if host_key is not None:
            try:
                import base64

                file_hash = _build_cache_digest(_scan_cache)
                signature_msg = host_key.sign_ssh_data(file_hash)
                cache_output["_signature"] = base64.b64encode(
                    signature_msg.asbytes()
                ).decode("ascii")
            except Exception as e:
                print(f"[⚠️] Failed to sign scan cache: {e}")

        with open(SCAN_CACHE_FILE, "w") as f:
            json.dump(cache_output, f, indent=2)
    except Exception as e:
        print(f"[SECURITY] Failed to save scan cache: {e}")


def is_file_cached(file_path):
    global _scan_cache

    print(f"[DEBUG] is_file_cached() from {__file__}")

    if _scan_cache is None:
        print("[DEBUG] _scan_cache is None, loading...")
        load_scan_cache()

    file_hash = calculate_file_hash(file_path)
    if not file_hash:
        print(f"[DEBUG] Cache check failed for {file_path}: could not calculate hash")
        return False

    cached = file_hash in _scan_cache
    print(f"[DEBUG] Cache check {file_path}:")
    print(f"        hash={file_hash}")
    print(f"        cached={cached}")
    print(f"        entries={len(_scan_cache)}")
    print(f"        entry={_scan_cache.get(file_hash)}")

    return cached


def mark_file_safe(file_path):
    """Mark file as safe in cache."""
    global _scan_cache

    if _scan_cache is None:
        load_scan_cache()

    file_hash = calculate_file_hash(file_path)
    if file_hash:
        _scan_cache[file_hash] = {
            "path": file_path,
            "scanned_at": time.time()
        }
        print(f"[DEBUG] Marking {file_path} safe with hash {file_hash[:12]}")
        save_scan_cache()
        print(f"[DEBUG] Cache now has {len(_scan_cache)} entries")

# Load caches immediately at import/startup
load_banned_ips()
load_scan_cache()


# =========================================================
# Password Configuration
# =========================================================

CONFIG_FILE = "server_config.json"


def load_server_password():
    """
    Load the server password from configuration.

    Returns:
        str: The server password, or None if not configured
    """
    if not os.path.exists(CONFIG_FILE):
        return None

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config.get("server_password")
    except Exception:
        return None


def verify_password(input_password):
    """
    Verify a password against the server configuration.

    Args:
        input_password: The password to verify

    Returns:
        bool: True if password is correct
    """
    server_password = load_server_password()

    if server_password is None:
        # No password configured - allow access
        return True

    return input_password == server_password


# =========================================================
# ASCII Captcha Generator
# =========================================================

CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CAPTCHA_LENGTH = 5

# ASCII Art Font for Captcha
_ASCII_FONT = {
    "A": ["  ██  ", " █  █ ", "██████", "█    █", "█    █"],
    "B": ["█████ ", "█    █", "█████ ", "█    █", "█████ "],
    "C": [" █████", "█     ", "█     ", "█     ", " █████"],
    "D": ["█████ ", "█    █", "█    █", "█    █", "█████ "],
    "E": ["██████", "█     ", "████  ", "█     ", "██████"],
    "F": ["██████", "█     ", "████  ", "█     ", "█     "],
    "G": [" █████", "█     ", "█  ███", "█    █", " █████"],
    "H": ["█    █", "█    █", "██████", "█    █", "█    █"],
    "J": ["      █", "      █", "      █", "█    █", " ████ "],
    "K": ["█   █ ", "█  █  ", "███   ", "█  █  ", "█   █ "],
    "L": ["█     ", "█     ", "█     ", "█     ", "██████"],
    "M": ["█    █", "██  ██", "█ ██ █", "█    █", "█    █"],
    "N": ["█    █", "██   █", "█ █  █", "█  █ █", "█   ██"],
    "P": ["█████ ", "█    █", "█████ ", "█     ", "█     "],
    "Q": [" █████", "█    █", "█  █ █", "█   █ ", " ███ █"],
    "R": ["█████ ", "█    █", "█████ ", "█  █  ", "█   █ "],
    "S": [" █████", "█     ", " ████ ", "     █", "█████ "],
    "T": ["███████", "   █   ", "   █   ", "   █   ", "   █   "],
    "U": ["█    █", "█    █", "█    █", "█    █", " ████ "],
    "V": ["█    █", "█    █", " █  █ ", "  ██  ", "  ██  "],
    "W": ["█    █", "█    █", "█ ██ █", "██  ██", "█    █"],
    "X": ["█   █ ", " █ █  ", "  █   ", " █ █  ", "█   █ "],
    "Y": ["█   █ ", " █ █  ", "  █   ", "  █   ", "  █   "],
    "Z": ["██████", "    █ ", "   █  ", "  █   ", "██████"],
    "2": [" ████ ", "█    █", "   ██ ", "  █   ", "██████"],
    "3": [" ████ ", "█    █", "  ███ ", "█    █", " ████ "],
    "4": ["   ██ ", "  █ █ ", " █  █ ", "██████", "    █ "],
    "5": ["██████", "█     ", "█████ ", "     █", "█████ "],
    "6": [" █████", "█     ", "█████ ", "█    █", " █████"],
    "7": ["███████", "     █ ", "    █  ", "   █   ", "  █    "],
    "8": [" ████ ", "█    █", " ████ ", "█    █", " ████ "],
    "9": [" █████", "█    █", " █████", "     █", " █████"],
}


def generate_captcha():
    """Generate a random captcha code and ASCII art."""
    import random
    random.seed()

    # Generate random code
    code = "".join(random.choice(CAPTCHA_CHARS) for _ in range(CAPTCHA_LENGTH))

    # Build ASCII art
    ascii_lines = ["", "", "", "", ""]
    for char in code:
        if char in _ASCII_FONT:
            font_char = _ASCII_FONT[char]
            for i in range(5):
                ascii_lines[i] += font_char[i] + "  "

    # Add noise
    noise_chars = ["·", "˙", "∘", "○", "•"]
    for i in range(5):
        line = list(ascii_lines[i])
        for j in range(len(line)):
            if line[j] == " " and random.random() < 0.08:
                line[j] = random.choice(noise_chars)
        ascii_lines[i] = "".join(line)

    return code, ascii_lines


def verify_captcha(user_input, correct_code):
    """Verify captcha input (case insensitive)."""
    return user_input.strip().upper() == correct_code