# MXC prototype agent runtime status

The `mxc-prototype` guest image now runs an operational PID1 control runtime for
`nvx.mxc.agent.v1`.

## What is live now

- PID1 opens `/dev/hvc1` read/write, switches the device to raw mode, and
  exchanges encoded protocol frames through `HvcFramedChannel`.
- Launch authentication is launch-bound and must match protocol version, launch
  identity, and channel generation.
- Session configuration remains immutable after the first successful apply
  (idempotent replay only).
- The Task2 namespace-holder/container setup is built only after valid
  configuration input and is verified before readiness is emitted.
- Process execution is supervised with one active exec at a time, unlimited
  sequential execs, argv/env/cwd execution without shell expansion, bounded
  stdin queueing, and credit-aware output streaming.
- Cancellation, timeout escalation, descendant termination, channel-loss cleanup,
  and graceful shutdown all execute with fail-closed behavior.

## Scope notes

- The service still reserves `OPENVMM_OUTER_FRAME_OVERHEAD_BYTES = 64` as a
  conservative framing budget until OpenVMM framing metadata is imported
  directly.
- `legacy` and `broker-ttrpc` paths remain out of scope for this profile.
