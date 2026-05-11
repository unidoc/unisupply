# Examples

Ready-to-copy artifacts for the most common `unisupply` use cases. Drop them into your project as-is, or use them as a starting point and tune the values for your own risk tolerance.

| File | What it is | When to use it |
| --- | --- | --- |
| [`policy-strict.json`](./policy-strict.json) | Runtime defaults of the `--policy-preset strict` preset, frozen as JSON. | Production / regulated environments. Mirror of `policy.DefaultStrictPolicy()` — keep edits minimal. |
| [`policy-moderate.json`](./policy-moderate.json) | Runtime defaults of the `--policy-preset moderate` preset. | General use. A reasonable starting point that fails on critical vulns and archived modules without blocking on every signal. |
| [`policy-custom.json`](./policy-custom.json) | Every supported policy field populated, ready to tailor. | Custom org policies. Pair with [`policy-custom.md`](./policy-custom.md) for per-field documentation. |
| [`policy-custom.md`](./policy-custom.md) | Per-field reference for the policy schema. | Read alongside `policy-custom.json` while building your own policy. |
| [`ci-integration.yml`](./ci-integration.yml) | Drop-in GitHub Actions workflow that scans every push and PR. | CI gating. Pins unisupply by release tag and pins every action by SHA. |

## About the policy JSON files

Per-field documentation lives in [`policy-custom.md`](./policy-custom.md), and the authoritative
schema is the `Policy` struct in [`pkg/policy/engine.go`](../pkg/policy/engine.go).

`policy-strict.json` and `policy-moderate.json` are byte-for-byte mirrors of `policy.DefaultStrictPolicy()` and `policy.DefaultModeratePolicy()` — if you
just want the preset values, prefer the `--policy-preset` flag (see below) so you do not have to keep a local copy in sync.

`policy-custom.json` populates every supported field at once as a starting point for your own policy. Delete the rules you do not need and tune the thresholds that remain; read each field's meaning in [`policy-custom.md`](./policy-custom.md) before editing.

## Running a scan with a policy file

The `*.json` files are loaded with the `--policy` flag:

```bash
unisupply ./ --policy ./examples/policy-strict.json
unisupply ./ --policy ./examples/policy-moderate.json
unisupply ./ --policy ./examples/policy-custom.json
```

Built-in presets (`--policy-preset strict` / `--policy-preset moderate`) are
identical to the JSON variants here, so prefer the preset flag unless you
need to track the policy as a file in your repo.

See the project [README](../README.md) for the full feature overview and the [policy engine documentation](../README.md#policy-engine) for how rules combine and which CLI flags they interact with.
