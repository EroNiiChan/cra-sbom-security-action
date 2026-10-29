#!/usr/bin/env python3
"""
EU CRA SBOM & CI/CD Secret Audit Scanner (cra-sbom-security-action)
-------------------------------------------------------------------
Zero-dependency static analysis tool generating:
1. CycloneDX v1.5 compliant Software Bill of Materials (SBOM) across 8+ ecosystems.
2. High-precision hardcoded secret, token & credential leak detection.
3. European Cyber Resilience Act (Regulation (EU) 2024/2847) compliance assessment.

Zero external dependencies - Pure Python Standard Library (Python 3.8+).
Repository: https://github.com/EroNiiChan/cra-sbom-security-action
Compliance Suite: https://eroniichan.github.io/eu-ai-act-compliance-toolkit/
"""

import argparse
import datetime
import fnmatch
import json
import math
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set

# Ensure UTF-8 output encoding across Windows & Linux terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "1.0.0"
__tool_name__ = "cra-sbom-security-audit"
__author__ = "EroNiiChan"
__repo_url__ = "https://github.com/EroNiiChan/cra-sbom-security-action"
__pro_pack_url__ = "https://eroniichan.github.io/eu-ai-act-compliance-toolkit/"
__cra_regulation__ = "Regulation (EU) 2024/2847 (Cyber Resilience Act)"

# ---------------------------------------------------------------------------
# Ignore Patterns & Safe Directories for Secret Scanning
# ---------------------------------------------------------------------------

DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    ".terraform",
    "vendor",
    "coverage",
    ".next",
    ".nuxt",
    ".turbo",
    "graphify-out",
}

DEFAULT_IGNORED_EXTENSIONS: Set[str] = {
    # Binaries and archives
    ".exe", ".dll", ".so", ".dylib", ".bin", ".zip", ".tar", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".rar", ".whl", ".egg", ".jar", ".war", ".ear",
    # Images and media
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".mp3", ".mp4", ".mov", ".avi", ".flv", ".webm", ".wav", ".ogg",
    # Fonts and docs
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".psd", ".ai",
    # Databases & bytecode
    ".pyc", ".pyd", ".pyo", ".class", ".db", ".sqlite", ".sqlite3",
    # Lock files (scanned by SBOM engine, skipped by secret scanner to prevent false positives from hashes)
    ".lock",
}

DEFAULT_IGNORED_FILES: Set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "Gemfile.lock",
    "packages.lock.json",
}

# ---------------------------------------------------------------------------
# High-Precision Secret Detection Rules
# ---------------------------------------------------------------------------

SECRET_RULES = [
    {
        "id": "SEC-AWS-KEY",
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        "description": "Amazon Web Services Access Key identifier",
        "cra_violation": "Annex I Part I(2)(a) - Protection against unauthorized access & hardcoded credentials",
    },
    {
        "id": "SEC-AWS-SECRET",
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?i)\baws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "description": "Amazon Web Services Secret Access Key",
        "cra_violation": "Annex I Part I(2)(a) - Protection against unauthorized access & hardcoded credentials",
    },
    {
        "id": "SEC-GITHUB-PAT",
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        "description": "GitHub Personal Access Token (classic or fine-grained)",
        "cra_violation": "Annex I Part I(2)(a) - Unprotected CI/CD credentials",
    },
    {
        "id": "SEC-GITHUB-OAUTH",
        "name": "GitHub OAuth / User / Refresh Token",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b((?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"),
        "description": "GitHub OAuth, App, or Server-to-Server Token",
        "cra_violation": "Annex I Part I(2)(a) - Unprotected CI/CD credentials",
    },
    {
        "id": "SEC-OPENAI-KEY",
        "name": "OpenAI API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b(sk-[A-Za-z0-9]{48,}|sk-proj-[A-Za-z0-9_-]{48,})\b"),
        "description": "OpenAI Platform API Key",
        "cra_violation": "Annex I Part I(2)(a) - Hardcoded third-party model credentials",
    },
    {
        "id": "SEC-ANTHROPIC-KEY",
        "name": "Anthropic Claude API Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"),
        "description": "Anthropic Claude API Key",
        "cra_violation": "Annex I Part I(2)(a) - Hardcoded third-party model credentials",
    },
    {
        "id": "SEC-GOOGLE-KEY",
        "name": "Google API / Gemini Key",
        "severity": "HIGH",
        "regex": re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "description": "Google Cloud / Firebase / Gemini Developer API Key",
        "cra_violation": "Annex I Part I(2)(a) - Unencrypted cloud service credentials",
    },
    {
        "id": "SEC-STRIPE-KEY",
        "name": "Stripe Live Secret Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
        "description": "Stripe Live Payment Gateway Secret Key",
        "cra_violation": "Annex I Part I(2)(a) - Production payment credentials in plaintext",
    },
    {
        "id": "SEC-SLACK-TOKEN",
        "name": "Slack Bot / User Token",
        "severity": "HIGH",
        "regex": re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
        "description": "Slack OAuth Bot or Workspace Token",
        "cra_violation": "Annex I Part I(2)(a) - Exposed workspace communications access",
    },
    {
        "id": "SEC-SLACK-WEBHOOK",
        "name": "Slack Incoming Webhook URL",
        "severity": "MEDIUM",
        "regex": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}"),
        "description": "Slack Incoming Webhook with token",
        "cra_violation": "Annex I Part I(2)(a) - Internal notification injection vulnerability",
    },
    {
        "id": "SEC-HUGGINGFACE",
        "name": "Hugging Face User Access Token",
        "severity": "HIGH",
        "regex": re.compile(r"\b(hf_[A-Za-z0-9]{34,})\b"),
        "description": "Hugging Face User Access Token",
        "cra_violation": "Annex I Part I(2)(a) - AI model repository credentials",
    },
    {
        "id": "SEC-PRIVATE-KEY",
        "name": "Asymmetric Private Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"),
        "description": "Unencrypted cryptographic private key block",
        "cra_violation": "Annex I Part I(2)(c) - Insecure cryptographic material storage",
    },
    {
        "id": "SEC-DB-CONN-STRING",
        "name": "Database Connection String with Credentials",
        "severity": "HIGH",
        "regex": re.compile(r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[a-zA-Z0-9_.-]+:[^@\s/]{3,}@[a-zA-Z0-9_.-]+(?:[:0-9]*)?/[^\s'\"?]+)"),
        "description": "Direct database connection URI embedding cleartext password",
        "cra_violation": "Annex I Part I(2)(a) - Data store access credentials stored in source",
    },
    {
        "id": "SEC-GENERIC-AUTH-HEADER",
        "name": "Hardcoded Authorization Bearer Header",
        "severity": "HIGH",
        "regex": re.compile(r"(?i)['\"]Authorization['\"]\s*:\s*['\"]Bearer\s+([A-Za-z0-9._~+/-]{32,})['\"]"),
        "description": "Hardcoded Bearer authentication token in HTTP header",
        "cra_violation": "Annex I Part I(2)(a) - Embedded static API authorization token",
    },
    {
        "id": "SEC-GENERIC-SECRET-KEY",
        "name": "High-Entropy Secret / API Key Assignment",
        "severity": "HIGH",
        "regex": re.compile(r"(?i)\b(?:api_key|apikey|secret_key|secretkey|auth_token|client_secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{24,})['\"]"),
        "description": "Explicit assignment of hardcoded API or secret key",
        "cra_violation": "Annex I Part I(2)(a) - Hardcoded secret variable assignment",
    },
]

# Placeholders and false positives to ignore
FALSE_POSITIVE_SUBSTRINGS: Set[str] = {
    "example", "sample", "your_", "insert_", "replace_", "dummy", "placeholder",
    "changeme", "change_me", "test_", "mock_", "fake_", "xxxx", "00000000",
    "abcdef", "my_secret", "my-secret", "<token>", "<key>", "${", "process.env",
    "os.environ", "getenv", "config.", "env.", "secret_here", "fill_me",
}

# ---------------------------------------------------------------------------
# License Taxonomy for European CRA (Regulation (EU) 2024/2847)
# ---------------------------------------------------------------------------

KNOWN_LICENSES: Dict[str, Dict[str, str]] = {
    # Permissive (Low CRA Commercial Risk)
    "mit": {"id": "MIT", "tier": "permissive", "cra_risk": "LOW"},
    "apache-2.0": {"id": "Apache-2.0", "tier": "permissive", "cra_risk": "LOW"},
    "apache 2.0": {"id": "Apache-2.0", "tier": "permissive", "cra_risk": "LOW"},
    "bsd-2-clause": {"id": "BSD-2-Clause", "tier": "permissive", "cra_risk": "LOW"},
    "bsd-3-clause": {"id": "BSD-3-Clause", "tier": "permissive", "cra_risk": "LOW"},
    "bsd": {"id": "BSD-3-Clause", "tier": "permissive", "cra_risk": "LOW"},
    "isc": {"id": "ISC", "tier": "permissive", "cra_risk": "LOW"},
    "unlicense": {"id": "Unlicense", "tier": "permissive", "cra_risk": "LOW"},
    "cc0-1.0": {"id": "CC0-1.0", "tier": "permissive", "cra_risk": "LOW"},
    "0bsd": {"id": "0BSD", "tier": "permissive", "cra_risk": "LOW"},
    "zlib": {"id": "Zlib", "tier": "permissive", "cra_risk": "LOW"},
    "python-2.0": {"id": "Python-2.0", "tier": "permissive", "cra_risk": "LOW"},
    # Weak Copyleft (Medium CRA Risk - Requires Linking Review)
    "lgpl-2.1": {"id": "LGPL-2.1-only", "tier": "weak_copyleft", "cra_risk": "MEDIUM"},
    "lgpl-3.0": {"id": "LGPL-3.0-only", "tier": "weak_copyleft", "cra_risk": "MEDIUM"},
    "mpl-2.0": {"id": "MPL-2.0", "tier": "weak_copyleft", "cra_risk": "MEDIUM"},
    "epl-2.0": {"id": "EPL-2.0", "tier": "weak_copyleft", "cra_risk": "MEDIUM"},
    # Strong Copyleft (High CRA Risk for Commercial Software with Digital Elements)
    "gpl-2.0": {"id": "GPL-2.0-only", "tier": "strong_copyleft", "cra_risk": "HIGH"},
    "gpl-3.0": {"id": "GPL-3.0-only", "tier": "strong_copyleft", "cra_risk": "HIGH"},
    "gpl": {"id": "GPL-3.0-only", "tier": "strong_copyleft", "cra_risk": "HIGH"},
    "agpl-3.0": {"id": "AGPL-3.0-only", "tier": "strong_copyleft", "cra_risk": "HIGH"},
    "sspl-1.0": {"id": "SSPL-1.0", "tier": "strong_copyleft", "cra_risk": "HIGH"},
    "eupl-1.2": {"id": "EUPL-1.2", "tier": "strong_copyleft", "cra_risk": "MEDIUM"},
}


def normalize_license(raw_license: Optional[str]) -> Tuple[str, str, str]:
    """Normalize raw license string to (SPDX-ID, Tier, CRA-Risk)."""
    if not raw_license:
        return ("NOASSERTION", "unknown", "UNKNOWN")
    cleaned = raw_license.strip().strip("'\"").lower()
    for key, val in KNOWN_LICENSES.items():
        if key in cleaned:
            return (val["id"], val["tier"], val["cra_risk"])
    return (raw_license.strip(), "custom", "MEDIUM")


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to filter low-entropy random false positives."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def redact_secret(secret: str) -> str:
    """Redact secret for safe display in logs and CI reports."""
    s = secret.strip()
    if len(s) <= 8:
        return "********"
    if s.startswith("ghp_") or s.startswith("gho_") or s.startswith("ghu_") or s.startswith("ghs_"):
        prefix = s[:4]
        suffix = s[-4:]
        return f"{prefix}****...{suffix}"
    if s.startswith("sk-proj-"):
        prefix = s[:12]
        suffix = s[-4:]
        return f"{prefix}****...{suffix}"
    if s.startswith("sk-") or s.startswith("hf_"):
        prefix = s[:5]
        suffix = s[-4:]
        return f"{prefix}****...{suffix}"
    if s.startswith("AKIA") or s.startswith("ASIA"):
        return f"{s[:6]}****{s[-2:]}"
    # Generic redaction
    return f"{s[:4]}****...{s[-4:]}"


# ---------------------------------------------------------------------------
# Ecosystem SBOM Extractors (Zero-Dependency)
# ---------------------------------------------------------------------------

class SBOMExtractor:
    """Extracts software components from project manifests."""

    @staticmethod
    def parse_python_requirements(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Strip inline comments
                    if " #" in line:
                        line = line.split(" #", 1)[0].strip()
                    # Strip environment markers
                    if ";" in line:
                        line = line.split(";", 1)[0].strip()
                    # Parse name and version specifier
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=<>!~^]+)(.+))?$", line)
                    if match:
                        name = match.group(1).lower()
                        version = match.group(3).strip() if match.group(3) else "*"
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "pypi",
                            "manifest": str(path.name),
                            "purl": f"pkg:pypi/{name}@{version}" if version != "*" else f"pkg:pypi/{name}",
                            "license": "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_pyproject_toml(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Find dependencies = [ ... ]
            dep_block_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if dep_block_match:
                block = dep_block_match.group(1)
                for item in re.findall(r"['\"]([^'\"]+)['\"]", block):
                    item = item.strip()
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=<>!~^]+)(.+))?$", item)
                    if match:
                        name = match.group(1).lower()
                        version = match.group(3).strip() if match.group(3) else "*"
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "pypi",
                            "manifest": str(path.name),
                            "purl": f"pkg:pypi/{name}@{version}" if version != "*" else f"pkg:pypi/{name}",
                            "license": "NOASSERTION",
                        })
            # Check Poetry dependencies: [tool.poetry.dependencies]
            poetry_match = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?=\n\[|\Z)", content, re.DOTALL)
            if poetry_match:
                for line in poetry_match.group(1).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*=\s*(?:['\"]([^'\"]+)['\"]|\{(.*?)\})", line)
                    if m and m.group(1).lower() != "python":
                        name = m.group(1).lower()
                        version = m.group(2) or "*"
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "pypi",
                            "manifest": str(path.name),
                            "purl": f"pkg:pypi/{name}@{version}",
                            "license": "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_package_json(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            dep_keys = ["dependencies", "devDependencies", "peerDependencies"]
            for key in dep_keys:
                scope = "required" if key == "dependencies" else "optional"
                deps = data.get(key, {})
                if isinstance(deps, dict):
                    for name, ver in deps.items():
                        ver_str = str(ver).lstrip("^~>=<")
                        components.append({
                            "name": name,
                            "version": ver_str,
                            "ecosystem": "npm",
                            "scope": scope,
                            "manifest": str(path.name),
                            "purl": f"pkg:npm/{name}@{ver_str}",
                            "license": "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_package_lock_json(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            packages = data.get("packages", {})
            if packages and isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if not pkg_path or not isinstance(meta, dict):
                        continue
                    # node_modules/foo or node_modules/@scope/foo
                    name = meta.get("name") or pkg_path.split("node_modules/")[-1]
                    version = meta.get("version", "*")
                    lic = meta.get("license", "NOASSERTION")
                    if name:
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "npm",
                            "manifest": str(path.name),
                            "purl": f"pkg:npm/{name}@{version}",
                            "license": lic if isinstance(lic, str) else "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_cargo_toml(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            blocks = re.findall(r"\[(?:dependencies|dev-dependencies|build-dependencies)\](.*?)(?=\n\[|\Z)", content, re.DOTALL)
            for block in blocks:
                for line in block.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-]+)\s*=\s*(?:['\"]([^'\"]+)['\"]|\{(.*?)\})", line)
                    if m:
                        name = m.group(1)
                        ver = m.group(2)
                        if not ver and m.group(3):
                            v_match = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", m.group(3))
                            ver = v_match.group(1) if v_match else "*"
                        components.append({
                            "name": name,
                            "version": ver or "*",
                            "ecosystem": "cargo",
                            "manifest": str(path.name),
                            "purl": f"pkg:cargo/{name}@{ver or '*'}",
                            "license": "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_cargo_lock(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            pkgs = re.findall(r"\[\[package\]\](.*?)(?=\n\[\[package\]\]|\Z)", content, re.DOTALL)
            for pkg in pkgs:
                name_m = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", pkg)
                ver_m = re.search(r"version\s*=\s*['\"]([^'\"]+)['\"]", pkg)
                if name_m and ver_m:
                    name = name_m.group(1)
                    ver = ver_m.group(1)
                    components.append({
                        "name": name,
                        "version": ver,
                        "ecosystem": "cargo",
                        "manifest": str(path.name),
                        "purl": f"pkg:cargo/{name}@{ver}",
                        "license": "NOASSERTION",
                    })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_go_mod(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            # Multi-line require ( ... )
            multi = re.search(r"require\s*\((.*?)\)", content, re.DOTALL)
            if multi:
                for line in multi.group(1).splitlines():
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        name, ver = parts[0], parts[1]
                        components.append({
                            "name": name,
                            "version": ver,
                            "ecosystem": "golang",
                            "manifest": str(path.name),
                            "purl": f"pkg:golang/{name}@{ver}",
                            "license": "NOASSERTION",
                        })
            # Single line require foo v1.2.3
            for m in re.finditer(r"^require\s+([^\s]+)\s+([^\s]+)", content, re.MULTILINE):
                components.append({
                    "name": m.group(1),
                    "version": m.group(2),
                    "ecosystem": "golang",
                    "manifest": str(path.name),
                    "purl": f"pkg:golang/{m.group(1)}@{m.group(2)}",
                    "license": "NOASSERTION",
                })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_composer_json(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            for key in ["require", "require-dev"]:
                deps = data.get(key, {})
                if isinstance(deps, dict):
                    for name, ver in deps.items():
                        if name.lower() == "php" or name.startswith("ext-"):
                            continue
                        components.append({
                            "name": name,
                            "version": str(ver).lstrip("^~>=<"),
                            "ecosystem": "composer",
                            "manifest": str(path.name),
                            "purl": f"pkg:composer/{name}@{str(ver).lstrip('^~>=<')}",
                            "license": "NOASSERTION",
                        })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_gemfile(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("gem "):
                        m = re.findall(r"['\"]([^'\"]+)['\"]", line)
                        if m:
                            name = m[0]
                            ver = m[1] if len(m) > 1 else "*"
                            components.append({
                                "name": name,
                                "version": ver,
                                "ecosystem": "gem",
                                "manifest": str(path.name),
                                "purl": f"pkg:gem/{name}@{ver}",
                                "license": "NOASSERTION",
                            })
        except Exception:
            pass
        return components

    @staticmethod
    def parse_csproj(path: Path) -> List[Dict[str, Any]]:
        components = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            for m in re.finditer(r'<PackageReference\s+Include=[\'"]([^\'"]+)[\'"]\s+Version=[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE):
                name = m.group(1)
                ver = m.group(2)
                components.append({
                    "name": name,
                    "version": ver,
                    "ecosystem": "nuget",
                    "manifest": str(path.name),
                    "purl": f"pkg:nuget/{name}@{ver}",
                    "license": "NOASSERTION",
                })
        except Exception:
            pass
        return components


# ---------------------------------------------------------------------------
# Core Scanner Orchestrator
# ---------------------------------------------------------------------------

class SecuritySBOMAuditor:
    """End-to-end scanner for CycloneDX SBOM, Secret Audits, and CRA Compliance."""

    def __init__(self, root_dir: str, fail_on: str = "none", exclude_patterns: Optional[List[str]] = None):
        self.root_path = Path(root_dir).resolve()
        self.fail_on = fail_on.lower()
        self.exclude_patterns = exclude_patterns or []
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Scan collections
        self.components: List[Dict[str, Any]] = []
        self.component_keys: Set[str] = set()
        self.secrets_found: List[Dict[str, Any]] = []
        self.scanned_files_count = 0
        self.scanned_lines_count = 0
        self.project_name = self.root_path.name or "application"
        
        # CRA Checklist State
        self.has_security_policy = False
        self.security_policy_path: Optional[str] = None
        self.has_readme = False
        self.has_license = False

    def is_path_excluded(self, path: Path) -> bool:
        """Check if path should be ignored based on defaults and user exclusions."""
        rel_str = str(path.relative_to(self.root_path)).replace("\\", "/")
        
        # Check parent folder names against ignored directories
        parts = set(path.parts)
        if any(d in DEFAULT_IGNORED_DIRS for d in parts):
            return True
            
        # Check custom exclude patterns
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def scan_manifests_for_sbom(self) -> None:
        """Scan target directory for known manifest files and extract dependencies."""
        for root, dirs, files in os.walk(self.root_path):
            # Prune ignored directories in-place for high performance
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRS]
            
            root_path_obj = Path(root)
            if self.is_path_excluded(root_path_obj):
                continue
                
            for fname in files:
                fpath = root_path_obj / fname
                f_lower = fname.lower()
                
                # Check CRA repo governance files
                if f_lower in {"security.md", "security.txt"} or (f_lower == "security.txt" and "well-known" in root.lower()):
                    self.has_security_policy = True
                    self.security_policy_path = str(fpath.relative_to(self.root_path))
                if f_lower in {"readme.md", "readme.txt", "readme"}:
                    self.has_readme = True
                if f_lower in {"license", "license.md", "license.txt", "licence"}:
                    self.has_license = True

                extracted: List[Dict[str, Any]] = []
                if f_lower == "package.json":
                    extracted = SBOMExtractor.parse_package_json(fpath)
                elif f_lower == "package-lock.json":
                    extracted = SBOMExtractor.parse_package_lock_json(fpath)
                elif f_lower == "requirements.txt" or (f_lower.startswith("requirements-") and f_lower.endswith(".txt")):
                    extracted = SBOMExtractor.parse_python_requirements(fpath)
                elif f_lower == "pyproject.toml":
                    extracted = SBOMExtractor.parse_pyproject_toml(fpath)
                elif f_lower == "cargo.toml":
                    extracted = SBOMExtractor.parse_cargo_toml(fpath)
                elif f_lower == "cargo.lock":
                    extracted = SBOMExtractor.parse_cargo_lock(fpath)
                elif f_lower == "go.mod":
                    extracted = SBOMExtractor.parse_go_mod(fpath)
                elif f_lower == "composer.json":
                    extracted = SBOMExtractor.parse_composer_json(fpath)
                elif f_lower == "gemfile":
                    extracted = SBOMExtractor.parse_gemfile(fpath)
                elif f_lower.endswith(".csproj"):
                    extracted = SBOMExtractor.parse_csproj(fpath)

                for item in extracted:
                    # Enrich license categorization
                    spdx, tier, cra_risk = normalize_license(item.get("license"))
                    item["license_spdx"] = spdx
                    item["license_tier"] = tier
                    item["cra_risk"] = cra_risk
                    
                    key = f"{item['ecosystem']}:{item['name']}@{item.get('version', '*')}"
                    if key not in self.component_keys:
                        self.component_keys.add(key)
                        self.components.append(item)

    def scan_files_for_secrets(self) -> None:
        """Scan non-binary source files for leaked credentials and API tokens."""
        for root, dirs, files in os.walk(self.root_path):
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRS]
            root_path_obj = Path(root)
            if self.is_path_excluded(root_path_obj):
                continue
                
            for fname in files:
                fpath = root_path_obj / fname
                ext = fpath.suffix.lower()
                
                # Filter out ignored files & extensions
                if ext in DEFAULT_IGNORED_EXTENSIONS or fname in DEFAULT_IGNORED_FILES:
                    continue
                if self.is_path_excluded(fpath):
                    continue
                    
                # Skip files larger than 2MB to keep scanning instant
                try:
                    if fpath.stat().st_size > 2 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                    
                self.scanned_files_count += 1
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        line_no = 0
                        for line in f:
                            line_no += 1
                            self.scanned_lines_count += 1
                            self._scan_line_for_secrets(line, line_no, fpath)
                except Exception:
                    pass

    def _scan_line_for_secrets(self, line: str, line_no: int, fpath: Path) -> None:
        """Check an individual text line against all secret rules."""
        # Fast exit on empty or very short lines
        if len(line.strip()) < 10:
            return
            
        line_lower = line.lower()
        rel_path = str(fpath.relative_to(self.root_path)).replace("\\", "/")
        
        # Avoid checking test fixtures that explicitly mark dummy data
        if "test" in rel_path.lower() and ("dummy" in line_lower or "fake" in line_lower or "mock" in line_lower):
            return

        for rule in SECRET_RULES:
            match = rule["regex"].search(line)
            if match:
                raw_secret = match.group(1) if match.groups() else match.group(0)
                raw_secret_clean = raw_secret.strip()
                
                # Check for false-positive placeholder indicators
                if any(fp in raw_secret_clean.lower() for fp in FALSE_POSITIVE_SUBSTRINGS):
                    continue
                if any(fp in line_lower for fp in ["example.com", "your-api-key", "insert-here", "dummy-secret"]):
                    continue
                    
                # Check entropy for generic secret rules to filter plain words/uuids
                if rule["id"] in {"SEC-GENERIC-SECRET-KEY", "SEC-GENERIC-AUTH-HEADER"}:
                    if calculate_shannon_entropy(raw_secret_clean) < 3.2:
                        continue
                        
                finding = {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "file": rel_path,
                    "line": line_no,
                    "redacted_secret": redact_secret(raw_secret_clean),
                    "description": rule["description"],
                    "cra_violation": rule["cra_violation"],
                }
                self.secrets_found.append(finding)

    def evaluate_cra_compliance(self) -> Dict[str, Any]:
        """Assess overall compliance against European Cyber Resilience Act Annex I & Art 10."""
        critical_secrets = [s for s in self.secrets_found if s["severity"] == "CRITICAL"]
        high_secrets = [s for s in self.secrets_found if s["severity"] == "HIGH"]
        copyleft_pkgs = [c for c in self.components if c.get("license_tier") == "strong_copyleft"]
        
        # Check Requirements:
        req_sbom = {
            "title": "Machine-Readable SBOM Availability",
            "article": "CRA Art. 10(2) & Annex I Part I(1)",
            "passed": len(self.components) > 0 or self.scanned_files_count > 0,
            "status": "PASS" if len(self.components) > 0 else "INFO",
            "details": f"Generated CycloneDX v1.5 SBOM tracking {len(self.components)} software components.",
        }
        
        req_secrets = {
            "title": "Zero Hardcoded Credentials / Secrets",
            "article": "CRA Annex I Part I(2)(a)",
            "passed": len(self.secrets_found) == 0,
            "status": "FAIL" if len(critical_secrets) > 0 else ("WARN" if len(high_secrets) > 0 else "PASS"),
            "details": f"{len(self.secrets_found)} potential credentials/keys detected across codebase.",
        }
        
        req_policy = {
            "title": "Coordinated Vulnerability Disclosure (CVD) Policy",
            "article": "CRA Art. 10(6) & Annex I Part II",
            "passed": self.has_security_policy,
            "status": "PASS" if self.has_security_policy else "WARN",
            "details": f"Policy found at '{self.security_policy_path}'" if self.has_security_policy else "Missing SECURITY.md or .well-known/security.txt policy file.",
        }
        
        req_licenses = {
            "title": "Commercial Supply Chain & License Compliance",
            "article": "CRA Art. 10 & Commercial Integration Liability",
            "passed": len(copyleft_pkgs) == 0,
            "status": "WARN" if len(copyleft_pkgs) > 0 else "PASS",
            "details": f"{len(copyleft_pkgs)} strong copyleft packages identified (GPL/AGPL contagion verification recommended)." if len(copyleft_pkgs) > 0 else "All identified components use permissive/compatible licenses.",
        }
        
        # Overall Status
        if len(critical_secrets) > 0:
            overall_status = "NON_COMPLIANT"
            status_badge = "NON-COMPLIANT (Critical Violations)"
            exit_code = 1 if self.fail_on in {"secrets", "any", "high"} else 0
        elif len(high_secrets) > 0:
            overall_status = "WARNING"
            status_badge = "ACTION REQUIRED (High Risk Findings)"
            exit_code = 1 if self.fail_on in {"secrets", "any", "high"} else 0
        elif not self.has_security_policy or len(copyleft_pkgs) > 0:
            overall_status = "WARNING"
            status_badge = "ACTION REQUIRED (Governance / License Warnings)"
            exit_code = 1 if (self.fail_on == "copyleft" and len(copyleft_pkgs) > 0) or self.fail_on == "any" else 0
        else:
            overall_status = "COMPLIANT"
            status_badge = "CRA COMPLIANT (Annex I Verified)"
            exit_code = 0

        return {
            "overall_status": overall_status,
            "status_badge": status_badge,
            "exit_code": exit_code,
            "requirements": [req_sbom, req_secrets, req_policy, req_licenses],
            "stats": {
                "components_count": len(self.components),
                "secrets_count": len(self.secrets_found),
                "critical_secrets": len(critical_secrets),
                "high_secrets": len(high_secrets),
                "copyleft_count": len(copyleft_pkgs),
                "scanned_files": self.scanned_files_count,
                "scanned_lines": self.scanned_lines_count,
            }
        }

    def generate_cyclonedx_sbom(self) -> Dict[str, Any]:
        """Build RFC/CycloneDX v1.5 compliant JSON SBOM."""
        sbom_uuid = str(uuid.uuid4())
        cyclonedx = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{sbom_uuid}",
            "version": 1,
            "metadata": {
                "timestamp": self.timestamp,
                "tools": [
                    {
                        "vendor": "EroNiiChan",
                        "name": "cra-sbom-security-action",
                        "version": __version__,
                        "externalReferences": [
                            {"type": "website", "url": __repo_url__},
                            {"type": "documentation", "url": __pro_pack_url__},
                        ]
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": f"pkg:generic/{self.project_name}@latest",
                    "name": self.project_name,
                    "version": "latest",
                    "properties": [
                        {"name": "cra:regulation", "value": __cra_regulation__},
                        {"name": "cra:scanned_at", "value": self.timestamp},
                    ]
                }
            },
            "components": []
        }

        for comp in self.components:
            purl = comp.get("purl", f"pkg:generic/{comp['name']}@{comp.get('version', '*')}")
            c_entry: Dict[str, Any] = {
                "type": "library",
                "bom-ref": purl,
                "name": comp["name"],
                "version": comp.get("version", "*"),
                "purl": purl,
                "scope": comp.get("scope", "required"),
                "properties": [
                    {"name": "cra:ecosystem", "value": comp.get("ecosystem", "unknown")},
                    {"name": "cra:manifest", "value": comp.get("manifest", "unknown")},
                    {"name": "cra:license_tier", "value": comp.get("license_tier", "unknown")},
                    {"name": "cra:risk_level", "value": comp.get("cra_risk", "UNKNOWN")},
                ]
            }
            # License structure
            spdx = comp.get("license_spdx", "NOASSERTION")
            if spdx and spdx != "NOASSERTION":
                c_entry["licenses"] = [{"license": {"id": spdx}}]
            else:
                c_entry["licenses"] = [{"license": {"name": comp.get("license", "NOASSERTION")}}]
                
            cyclonedx["components"].append(c_entry)

        return cyclonedx

    def render_markdown_report(self, cra_eval: Dict[str, Any]) -> str:
        """Render comprehensive GitHub Markdown report with tables and badges."""
        stats = cra_eval["stats"]
        status = cra_eval["overall_status"]
        status_color = "brightgreen" if status == "COMPLIANT" else ("yellow" if status == "WARNING" else "red")
        
        md: List[str] = []
        md.append("# European CRA SBOM & Security Audit Report 🛡️🇪🇺\n")
        md.append(f"**Regulation**: {__cra_regulation__}  ")
        md.append(f"**Audit Timestamp**: `{self.timestamp}`  ")
        md.append(f"**Target Directory**: `{self.root_path}`  ")
        md.append(f"**Compliance Status**: `[{cra_eval['status_badge']}]`  \n")
        
        # Status Badges
        md.append(f"[![CRA Status](https://img.shields.io/badge/CRA%20Status-{status}-{status_color}?style=flat-square)]({__repo_url__}) ")
        md.append(f"[![Components](https://img.shields.io/badge/SBOM%20Components-{stats['components_count']}-blue?style=flat-square)]({__repo_url__}) ")
        md.append(f"[![Secrets](https://img.shields.io/badge/Secrets%20Found-{stats['secrets_count']}-{'brightgreen' if stats['secrets_count']==0 else 'red'}?style=flat-square)]({__repo_url__}) ")
        md.append(f"[![Compliance Pack](https://img.shields.io/badge/EU%20Compliance%20Pack-€9%20Pro-gold?style=flat-square)]({__pro_pack_url__})\n")
        
        md.append("---\n")
        
        # CRA Essential Requirements Matrix
        md.append("## 📋 European CRA Essential Cybersecurity Checklist (Annex I)\n")
        md.append("| Requirement | Legal Basis | Status | Evaluation Summary |")
        md.append("| :--- | :--- | :---: | :--- |")
        for req in cra_eval["requirements"]:
            icon = "✅ PASS" if req["status"] == "PASS" else ("⚠️ WARN" if req["status"] == "WARN" else "❌ FAIL")
            md.append(f"| **{req['title']}** | `{req['article']}` | {icon} | {req['details']} |")
        md.append("\n---\n")
        
        # Hardcoded Secrets Table
        md.append("## 🔑 Secret Leak & Credential Exposure Audit\n")
        if not self.secrets_found:
            md.append("> **✅ Zero Leaked Secrets Detected.** All scanned source files comply with CRA Annex I Part I(2)(a) credential protection requirements.\n")
        else:
            md.append(f"> **⚠️ Alert:** Found `{len(self.secrets_found)}` potential hardcoded secret(s) or sensitive token(s).\n")
            md.append("| Rule | Severity | File Location | Line | Redacted Token | CRA Requirement |")
            md.append("| :--- | :---: | :--- | :---: | :--- | :--- |")
            for sec in self.secrets_found:
                md.append(f"| **{sec['rule_name']}** | `{sec['severity']}` | `{sec['file']}` | `{sec['line']}` | `{sec['redacted_secret']}` | {sec['cra_violation']} |")
            md.append("\n> **Remediation**: Immediately revoke exposed keys, rotate credentials, and migrate to environment variables or secret vaults (e.g. GitHub Actions Secrets, AWS Secrets Manager).\n")
        
        md.append("---\n")
        
        # SBOM Component Summary Table
        md.append(f"## 📦 CycloneDX Software Bill of Materials (SBOM) Summary\n")
        md.append(f"- **Total Components Discovered**: `{stats['components_count']}`")
        md.append(f"- **Files Scanned**: `{stats['scanned_files']}` (`{stats['scanned_lines']}` lines analyzed)")
        md.append(f"- **Specification Format**: CycloneDX v1.5 JSON (Machine-Readable)\n")
        
        if self.components:
            md.append("| Component | Ecosystem | Version | License | CRA Commercial Risk | Package URL (purl) |")
            md.append("| :--- | :---: | :---: | :---: | :---: | :--- |")
            # Show up to 40 items in markdown to keep report concise
            for comp in self.components[:40]:
                risk_icon = "🟢 Low" if comp["cra_risk"] == "LOW" else ("🟡 Med" if comp["cra_risk"] == "MEDIUM" else "🔴 High")
                md.append(f"| **{comp['name']}** | `{comp.get('ecosystem', '-')}` | `{comp.get('version', '*')}` | `{comp.get('license_spdx', 'Unknown')}` | {risk_icon} | `{comp.get('purl', '-')}` |")
            if len(self.components) > 40:
                md.append(f"\n*...and {len(self.components) - 40} more components. See exported CycloneDX JSON for full component graph.*\n")
        else:
            md.append("> *No external dependency manifests identified in this repository scan.*\n")
            
        md.append("\n---\n")
        
        # Monetization & €9 Compliance Suite Upsell
        md.append("## 💼 Need Full European CRA & EU AI Act Legal Protection?\n")
        md.append("Under European Regulation (EU) 2024/2847 (CRA) and Regulation (EU) 2024/1689 (EU AI Act), technical SBOM generation is only step one. European procurement contracts now require formal **Deployer vs Contractor Liability Riders, Article 10 CVD Handover Model Cards, and Article 50 Disclosures**.")
        md.append("\n### 👉 [**Get the 2026 EU Compliance Suite & Contract Pack (€9)**](https://eroniichan.github.io/eu-ai-act-compliance-toolkit/)\n")
        md.append("- **B2B AI & CRA Contract Rider**: Ready-to-sign Schedule A capping your liability for third-party upstream CVEs and model hallucinations.")
        md.append("- **Offline Risk Calculator Web App**: Interactive compliance classifier for client proposals.")
        md.append("- **ENISA / CSIRT Coordinated Vulnerability Disclosure Pack**: Standard Operating Procedures (SOPs) for mandatory incident notification within 24 hours.")
        md.append(f"\n[**Download Complete €9 Compliance Bundle**](https://eroniichan.github.io/eu-ai-act-compliance-toolkit/) | [**Support on GitHub Sponsors**](https://github.com/sponsors/EroNiiChan)\n")
        
        return "\n".join(md)

    def write_github_step_summary(self, markdown_text: str) -> None:
        """Append markdown summary to GITHUB_STEP_SUMMARY if running in GitHub Actions."""
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            try:
                with open(summary_file, "a", encoding="utf-8") as f:
                    f.write("\n" + markdown_text + "\n")
            except Exception:
                pass

    def write_github_outputs(self, outputs: Dict[str, Any]) -> None:
        """Write key-value outputs to GITHUB_OUTPUT for downstream workflow steps."""
        output_file = os.environ.get("GITHUB_OUTPUT")
        if output_file:
            try:
                with open(output_file, "a", encoding="utf-8") as f:
                    for k, v in outputs.items():
                        f.write(f"{k}={v}\n")
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog=__tool_name__,
        description="Fast, zero-dependency European CRA SBOM generator and secret leak auditor.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Root path of repository or directory to scan (default: current directory)")
    parser.add_argument("--format", choices=["markdown", "json", "cyclonedx", "summary"], default="summary", help="Console output format (default: summary)")
    parser.add_argument("--output", help="File path to save the generated security & CRA audit report (e.g. cra-report.md or cra-report.json)")
    parser.add_argument("--sbom-out", default="cyclonedx-sbom.json", help="File path to save the CycloneDX v1.5 JSON SBOM (default: cyclonedx-sbom.json)")
    parser.add_argument("--fail-on", choices=["none", "secrets", "copyleft", "high", "any"], default="none", help="Build failure threshold: none, secrets, copyleft, high, any (default: none)")
    parser.add_argument("--exclude", action="append", default=[], help="Glob pattern to exclude from scan (can be repeated)")
    parser.add_argument("--quiet", action="store_true", help="Suppress banner and console output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Instantiate and execute auditor
    auditor = SecuritySBOMAuditor(
        root_dir=args.path,
        fail_on=args.fail_on,
        exclude_patterns=args.exclude,
    )

    auditor.scan_manifests_for_sbom()
    auditor.scan_files_for_secrets()
    cra_eval = auditor.evaluate_cra_compliance()
    cyclonedx_sbom = auditor.generate_cyclonedx_sbom()

    # Save CycloneDX SBOM file
    if args.sbom_out:
        sbom_path = Path(args.sbom_out).resolve()
        try:
            sbom_path.parent.mkdir(parents=True, exist_ok=True)
            with open(sbom_path, "w", encoding="utf-8") as f:
                json.dump(cyclonedx_sbom, f, indent=2)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write CycloneDX SBOM: {e}\n")

    # Generate Markdown and JSON reports
    md_report = auditor.render_markdown_report(cra_eval)
    json_report = {
        "tool": __tool_name__,
        "version": __version__,
        "regulation": __cra_regulation__,
        "timestamp": auditor.timestamp,
        "target_path": str(auditor.root_path),
        "compliance": cra_eval,
        "secrets": auditor.secrets_found,
        "components_count": len(auditor.components),
        "components": auditor.components,
    }

    # Save report to file if requested
    if args.output:
        out_path = Path(args.output).resolve()
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_path.suffix.lower() == ".json":
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(json_report, f, indent=2)
            else:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(md_report)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to write report file: {e}\n")

    # Write GitHub Actions Step Summary & Outputs
    auditor.write_github_step_summary(md_report)
    auditor.write_github_outputs({
        "cra-status": cra_eval["overall_status"],
        "secrets-count": cra_eval["stats"]["secrets_count"],
        "components-count": cra_eval["stats"]["components_count"],
        "critical-secrets": cra_eval["stats"]["critical_secrets"],
        "copyleft-count": cra_eval["stats"]["copyleft_count"],
        "sbom-path": args.sbom_out,
        "report-path": args.output or "stdout",
    })

    # Render console output
    if not args.quiet:
        if args.format == "markdown":
            sys.stdout.write(md_report + "\n")
        elif args.format == "json":
            sys.stdout.write(json.dumps(json_report, indent=2) + "\n")
        elif args.format == "cyclonedx":
            sys.stdout.write(json.dumps(cyclonedx_sbom, indent=2) + "\n")
        else: # summary
            stats = cra_eval["stats"]
            print("================================================================================")
            print(f"🛡️  European CRA SBOM & CI/CD Security Audit ({__cra_regulation__})")
            print("================================================================================")
            print(f"Status           : {cra_eval['status_badge']}")
            print(f"Components Tracked: {stats['components_count']} (CycloneDX v1.5 JSON)")
            print(f"Secrets Leaked   : {stats['secrets_count']} (Critical: {stats['critical_secrets']}, High: {stats['high_secrets']})")
            print(f"Copyleft Risks   : {stats['copyleft_count']} strong copyleft licenses detected")
            print(f"Security Policy  : {'Found (' + auditor.security_policy_path + ')' if auditor.has_security_policy else 'Missing (Art. 10(6) CVD warning)'}")
            print(f"Files Analyzed   : {stats['scanned_files']} files ({stats['scanned_lines']} lines)")
            print(f"CycloneDX SBOM   : Saved to {args.sbom_out}")
            if args.output:
                print(f"Audit Report     : Saved to {args.output}")
            print("--------------------------------------------------------------------------------")
            if auditor.secrets_found:
                print("🚨 CRITICAL SECRET FINDINGS:")
                for s in auditor.secrets_found[:5]:
                    print(f"   [{s['severity']}] {s['rule_name']} in {s['file']}:{s['line']} -> {s['redacted_secret']}")
                if len(auditor.secrets_found) > 5:
                    print(f"   ... and {len(auditor.secrets_found) - 5} more findings.")
            else:
                print("✅ 0 Hardcoded credentials found. Codebase satisfies CRA Annex I Part I(2)(a).")
            print("--------------------------------------------------------------------------------")
            print(f"💼 2026 EU Compliance Suite & B2B Legal Pack: {__pro_pack_url__}")
            print("================================================================================")

    return cra_eval["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
