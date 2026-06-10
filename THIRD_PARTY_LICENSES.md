# Third-Party Licenses

This file lists the direct dependencies of UniSupply and their licenses.

## Commercial dependencies (UniDoc EULA)

| Module | License | Notes |
|--------|---------|-------|
| github.com/unidoc/unipdf/v3 | [UniDoc EULA](https://unidoc.io/eula/) (Commercial) | Used by `pkg/report/pdf` for PDF report generation. UniPDF is a commercial product and requires a license code to operate — set `UNIDOC_LICENSE_API_KEY` (free metered keys available at [unidoc.io](https://unidoc.io)). Library use of `pkg/report/pdf` in your own application is governed by the UniDoc EULA. |
| github.com/unidoc/unitype | [UniDoc EULA](https://unidoc.io/eula/) (Commercial) | Indirect dependency, pulled in via UniPDF. Same terms as above. |

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
