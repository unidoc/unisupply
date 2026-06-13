# Third-Party Licenses

This file lists the direct dependencies of UniSupply and their licenses.

## Commercial dependencies (UniDoc EULA)

| Module | License | Notes |
|--------|---------|-------|
| github.com/unidoc/unipdf/v3 | [UniDoc EULA](https://unidoc.io/eula/) (Commercial) | Used by `pkg/report/pdf` for PDF report generation. Requires a license key — set `UNIDOC_LICENSE_API_KEY` (see [unidoc.io](https://unidoc.io) for licensing options). Library use of `pkg/report/pdf` in your own application is governed by the UniDoc EULA. |

### Transitively commercial (pulled in via UniPDF, same EULA applies)

| Module | Notes |
|--------|-------|
| github.com/unidoc/unitype | Font rendering library bundled with UniPDF. |

## Permissive dependencies (Apache-2.0 / MIT / BSD)

| Module | License |
|--------|---------|
| github.com/spf13/pflag | BSD-3-Clause |
| golang.org/x/term | BSD-3-Clause |
| golang.org/x/vuln | BSD-3-Clause |
| gopkg.in/yaml.v3 | MIT and Apache-2.0 |

All other indirect dependencies are permissively licensed, including
github.com/unidoc/unichart (MIT), github.com/unidoc/pkcs7 (MIT),
github.com/unidoc/timestamp (BSD-2-Clause), and github.com/unidoc/freetype
(FreeType License).

For a machine-readable full list, run:

```bash
go-licenses report github.com/unidoc/unisupply/cmd/unisupply
```

<!-- Apache NOTICE audit (2026-06-13): all direct and indirect deps in go.mod checked;
     only yaml.v3 v3.0.1 ships a NOTICE file — preserved in repo-root NOTICE.
     Re-check when adding or upgrading deps. -->
