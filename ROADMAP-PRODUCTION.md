# Production roadmap — agent-next/nvx fork

Goal: take microsoft/nvx from a research-grade microVM substrate to a production sandbox
substrate for large-scale, self-hosted agent workloads. Ordered by dependency; each item
names its acceptance oracle. Upstream capability gaps (their issues #158–#160) are noted
where our fork deliberately builds on their plan instead of diverging.

## Landed on this branch (prod/hybrid-cpu-affinity)

- Hybrid-CPU snapshot affinity (fix + NVX_CPU_CLASS; 26/26 test-microvm on i9-14900K).
- setup-submodule: release install no longer blocks submodule init.
- Test-suite stabilization (host-policy isolation, async-kill waits) — 506/506 green,
  3 consecutive full runs.
- **P0.2 restore-under-load SLO (measured)**: p50/p95 at measured P-core busy — ~24% →
  7.5/8.2 ms, 53% → 9.1/10.8, 78% → 12.1/16.0, 88% → 14.3/20.3 (n=30 each). The warm
  path holds p95 ≤ 21 ms at ~90% busy.
- **P1.4 warm-pool manager (`nvx.py warmpool` fill/acquire/release/prune/status/bench)**:
  oracle PASSED on i9-14900K — 6087 restores / 60 s = **101.4/s sustained** (bar ≥50/s),
  p50 7.0 / p95 8.6 ms (bar <50 ms), 0 failures, 0 leaked claims after churn.
- Two latent benchmark bugs fixed (guest-exit input race → SIGABRT under concurrency;
  doubled-CR marker miss) — see PRODUCTION-NOTES §6.

## P0 — substrate correctness under fleet conditions

1. **Core-type-aware snapshot pools** — today snapshots are portable only within one CPU
   core type (hybrid) and one host ABI. Oracle: restore-matrix test capturing on class A
   and restoring on class A/B fails ONLY on B with the documented contract error, plus a
   pool tag carrying the capture core type. (Partially covered: warmpool records the
   capture CPU affinity in pool.json.)
2. ~~Restore-under-load SLO~~ — landed, see above.
3. **Memory ceiling behavior** — overcommit bounds: what happens at RSS pressure (OOM
   guest vs host), and a per-VM memory.high watermark. Oracle: fault-injection test
   driving the host to the memory ceiling with N idle VMs. (Empirical boundary already
   measured on the pressure droplet: host OOM at 193 concurrent heavy-mix sandboxes.)

## P1 — large-scale operations

4. ~~Warm-pool manager~~ — landed, see above.
5. **E2B-compatible control adapter (in agent-infra, not here)** — NVX restore/exec/destroy
   behind the existing gateway; NVX stays substrate-only. Oracle: sandbank conformance +
   our humanload suite against the NVX backend.
6. **Node join/scale-out** — how fast a fresh node reaches service (image preload, snapshot
   distribution). Oracle: cold node → serving restores < 10 min.

## P2 — upstream alignment

7. Upstream PRs for the hybrid-affinity fix and setup-submodule (owner-gated decision).
8. Track their #158–#160 (replaceable config, production agent, control RPC) — adopt
   upstream when they land rather than forking those layers.
9. CI for the fork: unit tests on push (KVM-free) + a nightly self-hosted runner with KVM
   for test-microvm.

## Non-goals for this fork

- GPU/PCIe passthrough (kernel ABI change; not needed for agent CPU sandboxes).
- Multi-workload pods per VM (their single-workload design is the density win).
- A second control plane (belongs in the gateway above).
