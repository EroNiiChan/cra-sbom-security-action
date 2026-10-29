# European CRA CycloneDX SBOM & CI/CD Secret Audit Action 🛡️🇪🇺

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Composite-purple?logo=githubactions)](https://github.com/EroNiiChan/cra-sbom-security-action)
[![CycloneDX 1.5](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5%20JSON-blue?logo=cyclonedx)](https://cyclonedx.org/)
[![EU CRA: Regulation (EU) 2024/2847](https://img.shields.io/badge/EU%20CRA-Regulation%20(EU)%202024%2F2847-informational)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib)-brightgreen)](sec_sbom_audit.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-pink?logo=githubsponsors)](https://github.com/sponsors/EroNiiChan)
[![Pro Pack](https://img.shields.io/badge/EU%20Compliance%20Pack-€9%20Pro-gold)](https://eroniichan.github.io/eu-ai-act-compliance-toolkit/)

> **Fast, zero-dependency CI/CD security scanner generating CycloneDX-lite SBOMs and detecting credential leaks for European Cyber Resilience Act (Regulation (EU) 2024/2847) compliance.**

Built for developers, SaaS maintainers, and digital agencies shipping products with digital elements into the European Union.

---

## ⚡ Key Capabilities

- 📦 **Automated CycloneDX v1.5 SBOM Generation**:
  - Full Package URL (`purl`) support across **8+ language ecosystems**: Python (`pip`, `poetry`, `pipenv`), Node.js (`npm`, `yarn`, `pnpm`), Rust (`cargo`), Go (`go.mod`), PHP (`composer`), Ruby (`bundler`), Java (`maven`, `gradle`), and .NET (`nuget`).
  - RFC/CycloneDX v1.5 compliant machine-readable JSON satisfying **CRA Article 10(2)** and **Annex I Part I(1)**.
- 🔑 **High-Precision Secret & Token Leak Audit**:
  - Scans for 15+ critical secret types: AWS access keys & secrets, GitHub PATs & OAuth tokens, OpenAI & Anthropic Claude keys, Google/Gemini API keys, Stripe live keys, Slack tokens & webhooks, asymmetric private keys (`RSA`, `OPENSSH`, `EC`), and embedded database connection URIs.
  - Built-in Shannon entropy heuristics and false-positive filter. Redacts credentials in CI output (`sk-proj-****...abcd`).
- ⚖️ **Commercial License & Copyleft Contagion Triage**:
  - Classifies dependency licenses into Permissive (MIT, Apache 2.0, BSD), Weak Copyleft (MPL, LGPL), and Strong Copyleft (GPL, AGPL) to prevent upstream licensing liability.
- 📜 **CRA Annex I Compliance Health-Check**:
  - Evaluates repository against essential cybersecurity requirements: SBOM availability, zero hardcoded credentials, Coordinated Vulnerability Disclosure policy (`SECURITY.md`), and reproducible lockfiles.
- 🚀 **100% Zero External Dependencies**:
  - Pure Python Standard Library (Python 3.8+). Runs in milliseconds without `pip install`, heavy Docker images, or external network calls.
- 📊 **Native GitHub Actions Integration**:
  - Renders visual summaries directly in `$GITHUB_STEP_SUMMARY`, sets machine-readable `$GITHUB_OUTPUT` variables, and exports downloadable audit reports.

---

## 🚀 Quick Start: GitHub Actions

Add the action to your `.github/workflows/ci.yml`:

```yaml
name: CRA Security & SBOM Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  cra-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run CRA SBOM & Secret Scan
        uses: EroNiiChan/cra-sbom-security-action@v1
        with:
          path: '.'
          fail-on: 'secrets' # Options: none, secrets, copyleft, high, any
          output-file: 'cra-security-audit.md'
          sbom-file: 'cyclonedx-sbom.json'

      - name: Upload CycloneDX SBOM Artifact
        uses: actions/upload-artifact@v4
        with:
          name: cyclonedx-sbom
          path: cyclonedx-sbom.json
```

---

## 💻 Standalone CLI Usage (Local or CI)

Run `sec_sbom_audit.py` directly with zero setup:

```bash
# Display summary in terminal
python sec_sbom_audit.py .

# Generate CycloneDX v1.5 JSON SBOM and Markdown audit report
python sec_sbom_audit.py . \
  --format summary \
  --sbom-out cyclonedx-sbom.json \
  --output cra-audit-report.md \
  --fail-on secrets

# Output raw CycloneDX JSON to stdout (for piping into jq or trivy)
python sec_sbom_audit.py . --format cyclonedx > sbom.json
```

---

## 📋 Action Inputs & Outputs

### Inputs

| Input | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `path` | Path to repository root or directory to scan | No | `.` |
| `format` | Terminal log output format (`summary`, `markdown`, `json`, `cyclonedx`) | No | `summary` |
| `output-file` | Path to save markdown or JSON security audit report | No | `cra-security-audit.md` |
| `sbom-file` | Path to save the CycloneDX v1.5 JSON SBOM | No | `cyclonedx-sbom.json` |
| `fail-on` | Fail build with non-zero exit code on condition: `none`, `secrets`, `copyleft`, `high`, `any` | No | `none` |
| `exclude` | Optional file or directory pattern to exclude from scanning | No | `""` |

### Outputs

| Output | Description |
| :--- | :--- |
| `cra-status` | Overall CRA compliance tier: `COMPLIANT`, `WARNING`, `NON_COMPLIANT` |
| `secrets-count` | Total detected credential exposures and leaked keys |
| `components-count` | Total software components cataloged in the CycloneDX SBOM |
| `critical-secrets` | Number of critical exposed credentials (AWS, GitHub, Stripe, OpenAI, Private Keys) |
| `copyleft-count` | Number of strong copyleft packages identified (GPL, AGPL) |
| `sbom-path` | Path where the CycloneDX JSON SBOM was saved |
| `report-path` | Path where the security audit report was saved |

---

## 🇪🇺 European Cyber Resilience Act (Regulation (EU) 2024/2847) Mapping

| CRA Article / Annex | Statutory Requirement | How This Action Verifies |
| :--- | :--- | :--- |
| **Article 10(2)** & **Annex I Part I(1)** | Maintain a machine-readable Software Bill of Materials (SBOM) covering all direct and indirect dependencies | Catalogs components into CycloneDX v1.5 JSON format with standard package URLs (`purl`). |
| **Annex I Part I(2)(a)** | Deliver products without known exploitable vulnerabilities or hardcoded credentials | Scans codebase for 15+ secret patterns, API tokens, and plaintext database URIs. |
| **Article 10(6)** & **Annex I Part II** | Implement a Coordinated Vulnerability Disclosure (CVD) policy with rapid reporting | Audits repository for `SECURITY.md` or `.well-known/security.txt` and flags missing policies. |
| **Article 10(4)** | Ensure cryptographic integrity and safe default configuration | Validates private key safety and scans for unencrypted connection strings. |

---

## 💼 Full Legal Protection: 2026 EU Compliance Suite (€9)

Under European Regulation (EU) 2024/2847 (Cyber Resilience Act) and Regulation (EU) 2024/1689 (EU AI Act), static CI/CD scanning is only technical pre-flight.

If you deliver code, freelance AI automations, or SaaS platforms to European enterprise clients, you are legally exposed without contractual liability caps and formal handover documentation.

### 👉 [**Get the 2026 EU Compliance Suite & B2B Legal Pack (€9)**](https://eroniichan.github.io/eu-ai-act-compliance-toolkit/)

Included in the Pro Pack:
1. **B2B AI & CRA Liability Indemnity Contract Rider (`02_B2B_Contract_Indemnity_Rider.md`)**:
   - Ready-to-sign Schedule A for your MSA / SOW.
   - Legally designates the client as the "Deployer" under Art. 3(4).
   - Disclaims liability for third-party LLM hallucinations and upstream open-source CVEs.
2. **Interactive Offline Risk Calculator (`index.html`)**:
   - Zero-dependency browser web app to classify client projects in 30 seconds and generate branded PDF/Markdown compliance reports.
3. **Article 50 Transparency Notices & Model Cards**:
   - Copy-paste UI disclosure banners and client handover sheets.
4. **ENISA Coordinated Vulnerability Disclosure SOP**:
   - Standard Operating Procedure for CRA 24-hour vulnerability notification.

📥 [**Download Pro Bundle on Gumroad / GitHub**](https://eroniichan.github.io/eu-ai-act-compliance-toolkit/) | 💖 [**Sponsor on GitHub**](https://github.com/sponsors/EroNiiChan)

---

## 🛡️ License

Released under the [MIT License](LICENSE). Copyright © 2026 [EroNiiChan](https://github.com/EroNiiChan).
