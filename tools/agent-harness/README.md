# Agent guide: historical MXC policy harness

> **Historical test prototype, not current NVX or a production MXC backend.**
> This branch tests its embedded **`0.9.0-dev`** contract and a custom Rust
> guest agent. It does not establish compatibility with released MXC
> `0.9.0-alpha`, current NVX `dev`, or MXC SDK/backend integration.

This guide is for a person or coding agent reproducing, inspecting or extending
the harness. Read the limitations before treating a passing report as evidence.

## What this is

The Rust `agent-harness` executable acts as a stand-in for an MXC backend:

```text
Historical MXC-style JSON
  -> embedded schema validation
  -> policy adapter and typed NVX requests
  -> real OpenVMM/WHP VM
  -> custom prototype PID-1 guest agent
  -> workload, output, terminal outcome and teardown
```

Static checks do not launch a VM. Live WHP checks do. The custom guest image is
not interchangeable with the current NVX managed-agent image.

## Source and artifact identity

| Item | Reference |
|---|---|
| Sharing branch | `user/modanish/nvx-prototype-harness-test` |
| Harness behavior baseline | `bbd397e3e528f822f31f159f05bafff08a319f26`; documentation-only commits may follow |
| OpenVMM gitlink | `c076186ef44728ef901ef7836aff9865009f4aae` |
| Embedded contract | [`schemas/mxc-config.schema.0.9.0-dev.json`](schemas/mxc-config.schema.0.9.0-dev.json) |
| Schema source/provenance | [`schemas/mxc-config.schema.0.9.0-dev.provenance.json`](schemas/mxc-config.schema.0.9.0-dev.provenance.json) |
| Guest/runtime notes | [MXC prototype agent](../../doc/mxc-prototype-agent.md) |
| Artifact build instructions | [Historical build guide](../../doc/build.md) |

Do not update the submodule to its latest branch or substitute a current release
bundle while claiming to reproduce this prototype. If an input is unavailable,
report it as a missing prerequisite.

Some historical design/build prose describes earlier scaffolding phases. Use
the implementation in this checkout and freshly observed results as authority;
do not assume every historical status paragraph describes the same revision.

## Start from a fresh checkout

Commands below run from the NVX repository root, not this directory.
These are Windows PowerShell examples.

```powershell
git clone --single-branch --branch user/modanish/nvx-prototype-harness-test https://github.com/microsoft/nvx.git nvx-harness
Set-Location .\nvx-harness
git submodule update --init openvmm
git rev-parse HEAD
git -C .\openvmm rev-parse HEAD
python scripts\nvx.py verify
cargo build --locked -p agent-harness
.\target\debug\agent-harness.exe --help
```

Use the existing Rust/Python and native build prerequisites described by the
repository. Live runs require usable Windows Hypervisor Platform. A clone alone
does not supply the compiled VMM, guest kernel or prototype guest image.

Build the host executable in the checkout where it will run. The harness embeds
`CARGO_MANIFEST_DIR` and checks source/schema freshness using that source tree.
Copying only `agent-harness.exe` to another machine is not a portable package.
Artifact override flags do not remove all source-tree dependencies.

### Required live artifacts

| Default location | Purpose |
|---|---|
| `openvmm\target\release\openvmm.exe` | Compatible pinned VMM |
| `build\vmlinux` | Matching guest kernel |
| `build\initramfs-mxc-agent.cpio.gz` | Custom prototype guest, not the ordinary Alpine/current NVX image |
| `build\nvx-agent-probe-mxc-prototype` | Host-side staged conformance probe used by the harness and freshness records |

The prototype initramfs embeds `/sbin/nvx-agent-probe` and the required shell.
Use the branch's existing build workflow. Relevant commands include:

```powershell
python scripts\nvx.py build-openvmm
python scripts\nvx.py build-mxc-prototype-initramfs
```

The latter uses the historical Docker workflow; its `--native` alternative is
for Linux. Kernel and other build prerequisites are documented in the build
guide. Do not automatically install Docker, enable WHP, change host settings or
replace an existing environment without authorization.

For supplied artifacts, record hashes and their provenance. Do not infer an
executable's revision from a neighboring sidecar whose hash does not match.
Generated binaries and prior machine-local test outputs are not distributed by
this README.

## Choose the correct execution mode

| Command shape | What it proves |
|---|---|
| `agent-harness conformance --backend whp` | The canonical predefined guest-agent conformance scenarios |
| `agent-harness mxc-policy --backend whp --static-only` | Static policy catalog/corpus checks, not live WHP conformance |
| `agent-harness mxc-policy --backend whp --static-only --config case.json` | Validation/adaptation of that supplied document |
| `agent-harness mxc-policy --backend whp` | Policy corpus plus predefined live policy profiles |
| `agent-harness mxc-policy --backend whp --config case.json` | Validates that document, then runs predefined profiles; **does not execute its command** |
| `agent-harness mxc-policy --backend whp --config case.json --execute-config` | Executes the supplied accepted **exec-phase** document in a dedicated live WHP session |

**For arbitrary supplied workload tests, use `--execute-config`.** It requires
`--config`, WHP, live mode and `phase: "exec"`. Do not combine it with
`--static-only`.

Python wrappers are also available:

```powershell
python scripts\nvx.py test-mxc-agent --backend whp
python scripts\nvx.py test-mxc-policy --backend whp --static-only
```

Apply an outer process-tree timeout to live commands using the execution
environment's supervisor. Use disposable, unique output/common-root directories.
The harness has internal bounds, but those are not permission for an unattended
unbounded parent process.

## Execute one real supplied config

Save this synthetic example as `build\harness-example.json`:

```json
{
  "version": "0.9.0-dev",
  "containment": "vm",
  "phase": "exec",
  "sandboxId": "example-harness-session",
  "process": {
    "commandLine": "printf 'HARNESS-HELLO\\n'",
    "env": [],
    "timeout": 5000
  }
}
```

With the matching artifacts present, run:

```powershell
$run = Join-Path (Get-Location) ("build\harness-runs\" + [guid]::NewGuid().ToString("N"))
.\target\debug\agent-harness.exe mxc-policy `
  --backend whp `
  --config .\build\harness-example.json `
  --execute-config `
  --openvmm-exe .\openvmm\target\release\openvmm.exe `
  --kernel .\build\vmlinux `
  --mxc-initramfs .\build\initramfs-mxc-agent.cpio.gz `
  --common-root (Join-Path $run "common") `
  --output-dir (Join-Path $run "evidence")
```

Require the actual stdout bytes `HARNESS-HELLO` followed by LF, empty stderr,
terminal exit code 0, and successful cleanup. Do not accept boot success or an
echoed command as evidence that the workload ran.

The `sandboxId` here satisfies prototype admission. This command creates its
own test session; it is not proof of lookup/binding to a previously provisioned
sandbox with that ID.

## Read the results correctly

| Artifact | What to inspect |
|---|---|
| `report.json` | Mode, freshness, static cases, live profiles, supplied execution, blocked/failed/unexpected results |
| `diagnostics.log` | Harness diagnostics; also preserve the CLI's stdout/stderr |
| `attestation-manifest.json` | Artifact sizes and hashes; do not hand-edit an attested report |
| `execute-config\stdout.bin` | Raw workload stdout |
| `execute-config\stderr.bin` | Raw workload stderr |
| `execute-config\outcome.json` | Evidence tier, exec ID, disposition, termination and cleanup |
| Guest/process logs beneath the output directory | Boot/control path and failure context |

For a successful supplied execution, inspect `tier: "live-whp"`,
`terminal.disposition` and `cleanup` rather than relying on one summary line.
Cleanup includes shutdown acknowledgment, channel closure, process exit and
explicit teardown, with any cleanup error reported separately.

Important interpretation rules:

- Static-only mode is not canonical live conformance and can exit nonzero.
- A deliberately nonzero workload exit or expected timeout can yield
  `passed: false` and harness exit 1. Judge the test against its expected typed
  outcome; do not confuse workload failure with a broken test.
- `CountingHostEffects` counters check an instrumented boundary. They are not a
  machine-wide claim that no diagnostic file or other effect occurred.
- Some early errors, including a relative-CWD failure observed in this branch,
  can return before the normal execution report is written. Preserve stderr,
  process outcome and cleanup evidence; missing output is not a pass.
- The supplied-exec collector itself is bounded. Use short test commands; an
  accepted long/no-timeout setting does not make this a long-running job service.

## Historical behavior to keep separate from current NVX

| Area | This prototype |
|---|---|
| Version | Requires `0.9.0-dev`, not `0.9.0-alpha` |
| Containment | Requires the historical `vm` selector |
| Environment | Explicit entries work; omitted, null and empty normalize to an empty exec environment; a shell may synthesize variables afterward |
| Inheritance | `process.inheritDefaultEnv` is absent from this schema and is rejected |
| CWD | Supports an absolute guest CWD; null is treated as omitted; invalid values fail at different layers |
| Timeout | Explicit values are limited to 1 through 86,400,000 ms; explicit 0 is rejected; omission/null maps to no protocol deadline |
| Unsupported policy | Includes supplied UI, fallback, lifecycle and telemetry sections |
| Lifecycle/IDs | Predefined profiles and admission checks are not a general arbitrary-JSON lifecycle service |

The current NVX managed implementation differs, including timeout behavior and
its request format. Do not use this table to report current NVX bugs.

## Agent working rules

1. Read [prototype runtime notes](../../doc/mxc-prototype-agent.md) and the
   relevant source before extending a scenario.
2. Use a separate worktree; do not overwrite another user's checkout or artifacts.
3. Make tests select the intended input and behavior. Never fix a failing test
   by silently changing the schema version, guest image or policy.
4. Use synthetic files, environment values and credentials. A test common root
   is disposable test data, not a real workspace, home directory or system root.
5. Preserve positive controls: a missing tool, mount, route or workload cannot
   demonstrate policy denial.
6. Stage complete LF-only guest scripts and run noninteractively when appropriate.
   Do not let console echo or interactive commands consume later test input.
7. Record exact source/artifact identities, executed commands, expected/observed
   results and cleanup. Keep static, local-runtime and live-WHP evidence distinct.
8. If parallel runs are authorized, use private output/common roots and a bounded
   VM gate. Do not kill unrelated processes by name.
9. Do not suppress stale-input checks or manually change attested reports.
10. Do not push, publish artifacts, file issues or modify host configuration
    without explicit authorization. Review logs before sharing them.

## Source map

| Path | Responsibility |
|---|---|
| [`src/main.rs`](src/main.rs) | CLI modes and argument validation |
| [`src/mxc_policy/schema.rs`](src/mxc_policy/schema.rs) | Embedded schema validation and provenance |
| [`src/mxc_policy/adapter.rs`](src/mxc_policy/adapter.rs) | Policy validation and typed execution/configuration plans |
| [`src/mxc_policy/effects.rs`](src/mxc_policy/effects.rs) | Instrumented host-effects boundary |
| [`src/mxc_policy/live.rs`](src/mxc_policy/live.rs) | Predefined profiles versus supplied-config execution |
| [`src/mxc_policy/report.rs`](src/mxc_policy/report.rs) | Outcome classification, freshness and artifact reports |
| [`src/launch.rs`](src/launch.rs) | Runtime discovery, VM launch and owned process cleanup |
| [`src/scenarios.rs`](src/scenarios.rs) | Real workload/control scenarios |
| [`../../agent-protocol`](../../agent-protocol) | Prototype message/state contracts |
| [`../../agent`](../../agent) | Custom Rust guest agent |

This README documents the current test branch. It does not implement the
portability, result-classification or error-reporting improvements described as
limitations above.
