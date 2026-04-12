# unisupply

Supply chain security analysis for Go projects.

Scans your Go module dependencies for vulnerabilities, maintainer health, typosquatting, AI-generated code risks, and CI/CD pipeline issues. Generates enterprise-grade PDF reports, JSON output, and SBOM (CycloneDX/SPDX).

## Quick Start

```bash
# Scan current project
unisupply ./

# Full scan with PDF report
unisupply ./ --format pdf --output report.pdf --github-token $GITHUB_TOKEN

# CI/CD with policy enforcement (exit code 2 on violation)
unisupply ./ --policy strict --format json --output results.json
```

## Features

- **9 security scanners** — vulnerabilities, maintenance, maintainer analysis, typosquatting, resilience, AI-generated code, CI/CD pipelines, build files, trust index
- **Risk scoring** — weighted composite score (0-100) per dependency
- **4 output formats** — terminal, JSON, PDF (via UniPDF), SBOM
- **Policy engine** — organizational compliance with built-in and custom policies
- **Trust Index** — optional integration with [unitrust](https://github.com/unidoc/unitrust) for curated trust data

## License

```
Copyright (c) UniDoc ehf. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
