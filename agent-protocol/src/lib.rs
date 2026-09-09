// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Wire format and message types for the NVX guest agent control channel.
//!
//! The channel is a single byte stream carrying framed messages in both directions. One
//! stream would normally force control traffic and workload output to take turns; a small
//! frame header with a stream id and a kind lets them interleave without corrupting each
//! other, so a long-running command can stream output while the host issues another
//! request.
//!
//! Every frame is:
//!
//! ```text
//! offset  size  field
//!      0     8  payload length, big-endian
//!      8     2  stream id (the exec id the frame belongs to; 0 for session control)
//!     10     1  kind (0 control, 1 stdout, 2 stderr, 3 stdin)
//!     11     1  flags (bit 0: end of stream)
//!     12     n  payload
//! ```
//!
//! The 8-byte big-endian length comes first and covers everything after it, so a reader can
//! bound its allocation before parsing anything else, and so the VMM's existing frame reader
//! needs no special case for this protocol.
//!
//! Control payloads are JSON. A binary encoding would be smaller, but the channel carries a
//! handful of messages per sandbox against multi-millisecond operations, and being able to
//! read a captured frame is worth more here than the bytes.

use ::serde::{Deserialize, Serialize};

pub mod e2e_profile;
pub mod mxc_extension;

/// Protocol version reported in [`AgentMessage::Ready`] and validated by the host.
///
/// The VMM, the agent initramfs, and the host runtime are three separately deployed
/// artifacts, so a mismatch is a real deployment state and must fail loudly rather than
/// producing a subtly wrong sandbox.
///
/// Version 2 added the workload-start checkpoint exchange ([`HostMessage::Checkpoint`],
/// [`AgentMessage::CheckpointPrepared`], [`AgentMessage::Restored`]). The addition is not
/// backwards compatible in the direction that matters: a version 1 agent silently fails to
/// parse a `Checkpoint` and would leave the host waiting for a barrier that is never raised,
/// so both ends reject a mismatch outright rather than negotiating down.
pub const PROTOCOL_VERSION: u32 = 2;

/// Whether this build can speak `version` with a peer.
///
/// Deliberately an equality test rather than a floor. The three artifacts are deployed
/// together, so the only correct answer to a mismatch is to fail the sandbox loudly; accepting
/// an older peer would mean silently running without the capture barrier, which is precisely
/// the failure the version exists to prevent.
pub fn is_supported_version(version: u32) -> bool {
    version == PROTOCOL_VERSION
}

/// Bytes of frame header preceding every payload.
pub const HEADER_LEN: usize = 12;

/// Largest payload accepted in one frame.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Stream id reserved for session-wide control traffic that belongs to no single exec.
pub const SESSION_STREAM: u16 = 0;

/// Flag marking the last frame of a stream.
pub const FLAG_END_OF_STREAM: u8 = 1;

/// What a frame carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    /// A JSON control message.
    Control = 0,
    /// Workload standard output.
    Stdout = 1,
    /// Workload standard error.
    Stderr = 2,
    /// Workload standard input.
    Stdin = 3,
}

impl FrameKind {
    /// Parses a wire kind, rejecting unknown values rather than ignoring them.
    pub fn from_u8(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Stdout),
            2 => Ok(Self::Stderr),
            3 => Ok(Self::Stdin),
            other => Err(ProtocolError::UnknownKind(other)),
        }
    }
}

/// One complete frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Exec this frame belongs to, or [`SESSION_STREAM`].
    pub stream: u16,
    /// What the payload is.
    pub kind: FrameKind,
    /// Frame flags, such as [`FLAG_END_OF_STREAM`].
    pub flags: u8,
    /// Frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Builds a control frame carrying `message`.
    pub fn control<T: Serialize>(stream: u16, message: &T) -> Result<Self, ProtocolError> {
        let payload = ::serde_json::to_vec(message).map_err(ProtocolError::Json)?;
        Ok(Self {
            stream,
            kind: FrameKind::Control,
            flags: 0,
            payload,
        })
    }

    /// Builds a data frame for one of the workload's streams.
    pub fn data(stream: u16, kind: FrameKind, payload: Vec<u8>) -> Self {
        Self {
            stream,
            kind,
            flags: 0,
            payload,
        }
    }

    /// Builds an empty end-of-stream marker.
    pub fn end_of_stream(stream: u16, kind: FrameKind) -> Self {
        Self {
            stream,
            kind,
            flags: FLAG_END_OF_STREAM,
            payload: Vec::new(),
        }
    }

    /// Whether this frame closes its stream.
    pub fn is_end_of_stream(&self) -> bool {
        self.flags & FLAG_END_OF_STREAM != 0
    }

    /// Serializes the frame, header first.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge(self.payload.len()));
        }
        let body_len = (HEADER_LEN - 8 + self.payload.len()) as u64;
        let mut bytes = Vec::with_capacity(8 + body_len as usize);
        bytes.extend_from_slice(&body_len.to_be_bytes());
        bytes.extend_from_slice(&self.stream.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Parses a complete frame, including its 8-byte length prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        let body_len = u64::from_be_bytes(bytes[..8].try_into().expect("checked 8 bytes"));
        let body_len = usize::try_from(body_len).map_err(|_| ProtocolError::PayloadTooLarge(0))?;
        if body_len + 8 != bytes.len() {
            return Err(ProtocolError::LengthMismatch {
                declared: body_len + 8,
                actual: bytes.len(),
            });
        }
        let payload_len = body_len
            .checked_sub(HEADER_LEN - 8)
            .ok_or(ProtocolError::Truncated)?;
        if payload_len > MAX_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge(payload_len));
        }
        Ok(Self {
            stream: u16::from_be_bytes(bytes[8..10].try_into().expect("checked 2 bytes")),
            kind: FrameKind::from_u8(bytes[10])?,
            flags: bytes[11],
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }

    /// Parses this frame's payload as a control message.
    pub fn parse_control<T: for<'de> Deserialize<'de>>(&self) -> Result<T, ProtocolError> {
        if self.kind != FrameKind::Control {
            return Err(ProtocolError::NotControl(self.kind));
        }
        ::serde_json::from_slice(&self.payload).map_err(ProtocolError::Json)
    }
}

/// Requests the host sends to the agent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HostMessage {
    /// Runs one command in the sandbox. Repeatable for the lifetime of the guest.
    #[serde(rename_all = "camelCase")]
    Exec {
        /// Correlates the reply and every stream frame of this command.
        id: u16,
        /// Argument vector; the first element is the program.
        argv: Vec<String>,
        /// Working directory inside the sandbox rootfs.
        #[serde(default)]
        cwd: Option<String>,
        /// Environment entries as `NAME=value`.
        #[serde(default)]
        env: Vec<String>,
        /// Wall-clock limit; the command is killed when it elapses.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// Whether the host intends to send standard input frames.
        #[serde(default)]
        stdin: bool,
    },
    /// Delivers a signal to a running command.
    #[serde(rename_all = "camelCase")]
    Signal {
        /// Command to signal.
        id: u16,
        /// Signal number.
        signal: i32,
    },
    /// Seeds the guest CSPRNG and clock for this launch.
    ///
    /// A restored guest replays the RNG state captured in the snapshot, so fresh entropy has
    /// to come from the host before anything security-sensitive is generated.
    #[serde(rename_all = "camelCase")]
    Reseed {
        /// 32 bytes of host entropy.
        entropy: Vec<u8>,
        /// Host wall-clock time in nanoseconds since the Unix epoch.
        unix_time_ns: u64,
        /// Epoch identifying this launch.
        ///
        /// Carried here rather than on the kernel command line because a restored guest reads
        /// back the command line that was captured: it lives in `mem.bin` along with everything
        /// else, so it describes the instance that took the snapshot and not this one. The
        /// channel is the only path by which a value can reach a restored guest freshly, which
        /// is the same reason the clock and entropy travel in this message.
        #[serde(default)]
        launch_epoch: Option<u64>,
    },
    /// Stops the workload and powers the guest off.
    #[serde(rename_all = "camelCase")]
    Shutdown {
        /// Grace period before running commands are killed.
        #[serde(default)]
        grace_ms: Option<u64>,
    },
    /// Requests a workload-start capture.
    ///
    /// The agent raises the capture barrier described in the filesystem and snapshot design
    /// (§8.5) — it stops accepting execs, parks its own workers, freezes the container cgroup,
    /// syncs and freezes the scratch filesystem — and only then asks the VMM to capture. The
    /// capturing instance does not survive: the VMM writes its artifacts and exits, so this
    /// request has no success reply from the guest. [`AgentMessage::CheckpointPrepared`] is the
    /// last thing the host hears from a capture that worked.
    #[serde(rename_all = "camelCase")]
    Checkpoint {
        /// Correlates the reply with this request.
        id: u16,
        /// How long the agent may wait for the container cgroup to reach `frozen 1`.
        ///
        /// A task in uninterruptible sleep keeps the cgroup in `FREEZING` until its I/O
        /// completes, so the wait must be bounded; exceeding it thaws and fails the capture
        /// with [`ErrorCode::CheckpointTimeout`] rather than hanging the sandbox.
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    /// Liveness check.
    Ping,
}

/// Replies and notifications the agent sends to the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AgentMessage {
    /// Sent once, when the sandbox filesystem is assembled and the agent can serve requests.
    #[serde(rename_all = "camelCase")]
    Ready {
        /// Wire protocol version, validated by the host.
        protocol_version: u32,
        /// Agent build identifier.
        agent_version: String,
        /// Guest kernel release.
        kernel: String,
        /// Where the sandbox rootfs was mounted.
        rootfs: String,
    },
    /// A command started.
    #[serde(rename_all = "camelCase")]
    Started {
        /// Command that started.
        id: u16,
        /// The command's pid inside the guest.
        pid: i32,
    },
    /// A command finished.
    #[serde(rename_all = "camelCase")]
    Exited {
        /// Command that finished.
        id: u16,
        /// Exit status, when the command exited normally.
        #[serde(default)]
        exit_code: Option<i32>,
        /// Signal number, when the command was killed.
        #[serde(default)]
        signal: Option<i32>,
        /// Whether the command hit its timeout.
        #[serde(default)]
        timed_out: bool,
    },
    /// A request failed. Errors are typed so the host can map them onto sandbox failure
    /// reasons instead of parsing log lines.
    #[serde(rename_all = "camelCase")]
    Error {
        /// Command the failure belongs to, when it belongs to one.
        #[serde(default)]
        id: Option<u16>,
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable detail.
        message: String,
    },
    /// Reply to [`HostMessage::Ping`].
    Pong,
    /// The guest is about to power off.
    ShuttingDown,
    /// The capture barrier is up and the VMM is about to be asked to capture.
    ///
    /// Sent *before* the control-port write, which is what makes it useful: a capture that
    /// fails inside the VMM leaves no guest to report it, so the host distinguishes "the agent
    /// never reached the barrier" (an [`AgentMessage::Error`] arrives instead) from "the
    /// barrier was up and the capture itself failed" (this arrives, then the VMM exits without
    /// publishing a generation).
    #[serde(rename_all = "camelCase")]
    CheckpointPrepared {
        /// The checkpoint request this belongs to.
        id: u16,
    },
    /// A restored sandbox has been fully repaired and thawed.
    ///
    /// Everything a clone must correct — wall clock, CRNG, identity — is already done when this
    /// is sent, the restore gate has been released and the container cgroup thawed, so this is
    /// the first point at which the workload is running on a sandbox that is whole.
    #[serde(rename_all = "camelCase")]
    Restored {
        /// Launch epoch of this restore, which is how a serving agent detects that it was
        /// restored at all: a capture leaves no observable trace in CPU or memory state, so the
        /// epoch supplied by the host for this launch is the only distinguishing evidence.
        launch_epoch: u64,
    },
}

/// Stable failure codes carried by [`AgentMessage::Error`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// The frame or message could not be decoded.
    BadRequest,
    /// The request names an exec id that does not exist.
    UnknownExec,
    /// The request reuses an exec id that is already in flight.
    DuplicateExec,
    /// The workload could not be started.
    ExecFailed,
    /// The sandbox filesystem could not be assembled.
    MountFailed,
    /// The request is well formed but not supported by this agent.
    Unsupported,
    /// The container cgroup did not reach `frozen 1` within the requested bound.
    ///
    /// Ordinarily a task in uninterruptible sleep: it holds the cgroup in `FREEZING` until its
    /// I/O completes and does not die promptly on `SIGKILL` either, so the sandbox is thawed
    /// and the capture abandoned rather than waited out.
    CheckpointTimeout,
    /// The workload is not in a state this agent can capture.
    ///
    /// Incompatible execs are in flight, or the workload is not in the supported
    /// single-threaded warm-shim state. Capturing anyway would produce clones whose peer
    /// threads resume holding state that only one of them is entitled to.
    WorkloadBusy,
    /// The container cgroup could not be frozen or thawed.
    FreezeFailed,
    /// The scratch filesystem could not be quiesced or resumed (`sync`, `FIFREEZE`, `FITHAW`).
    QuiesceFailed,
    /// The peer speaks a protocol version this build does not.
    UnsupportedProtocol,
    /// Something failed inside the agent itself.
    Internal,
}

/// Everything that can go wrong framing or parsing a message.
#[derive(Debug)]
pub enum ProtocolError {
    /// The buffer is shorter than a frame header.
    Truncated,
    /// The declared length does not match the buffer.
    LengthMismatch {
        /// Length the header declared.
        declared: usize,
        /// Length actually available.
        actual: usize,
    },
    /// The payload exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge(usize),
    /// The frame kind is not one this version defines.
    UnknownKind(u8),
    /// A control message was expected but the frame carries data.
    NotControl(FrameKind),
    /// The control payload is not valid JSON for the expected message.
    Json(::serde_json::Error),
}

impl ::std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            Self::Truncated => write!(formatter, "agent frame is truncated"),
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "agent frame declares {declared} bytes but {actual} are available"
            ),
            Self::PayloadTooLarge(len) => {
                write!(formatter, "agent frame payload of {len} bytes is too large")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown agent frame kind {kind}"),
            Self::NotControl(kind) => {
                write!(formatter, "expected a control frame but found {kind:?}")
            }
            Self::Json(error) => write!(formatter, "invalid agent control payload: {error}"),
        }
    }
}

impl ::std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_control_frame() {
        let message = HostMessage::Exec {
            id: 7,
            argv: vec!["/bin/python3".into(), "-c".into(), "print(1)".into()],
            cwd: Some("/".into()),
            env: vec!["PATH=/usr/bin".into()],
            timeout_ms: Some(5_000),
            stdin: false,
        };
        let encoded = Frame::control(7, &message).unwrap().encode().unwrap();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.stream, 7);
        assert_eq!(decoded.kind, FrameKind::Control);
        assert_eq!(decoded.parse_control::<HostMessage>().unwrap(), message);
    }

    #[test]
    fn round_trips_a_data_frame_and_its_end_marker() {
        let frame = Frame::data(3, FrameKind::Stdout, b"hello".to_vec());
        let decoded = Frame::decode(&frame.encode().unwrap()).unwrap();
        assert_eq!(decoded.payload, b"hello");
        assert!(!decoded.is_end_of_stream());

        let end = Frame::end_of_stream(3, FrameKind::Stdout);
        let decoded = Frame::decode(&end.encode().unwrap()).unwrap();
        assert!(decoded.is_end_of_stream());
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn declares_its_length_ahead_of_the_header() {
        let encoded = Frame::data(1, FrameKind::Stderr, b"abc".to_vec())
            .encode()
            .unwrap();
        let declared = u64::from_be_bytes(encoded[..8].try_into().unwrap()) as usize;

        assert_eq!(declared + 8, encoded.len());
        assert_eq!(declared, HEADER_LEN - 8 + 3);
    }

    #[test]
    fn rejects_a_truncated_frame() {
        let encoded = Frame::data(1, FrameKind::Stdout, b"abc".to_vec())
            .encode()
            .unwrap();
        assert!(matches!(
            Frame::decode(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::LengthMismatch { .. })
        ));
        assert!(matches!(
            Frame::decode(&encoded[..4]),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn rejects_an_unknown_frame_kind() {
        let mut encoded = Frame::data(1, FrameKind::Stdout, b"abc".to_vec())
            .encode()
            .unwrap();
        encoded[10] = 9;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(ProtocolError::UnknownKind(9))
        ));
    }

    #[test]
    fn rejects_an_unknown_control_message() {
        let frame = Frame {
            stream: SESSION_STREAM,
            kind: FrameKind::Control,
            flags: 0,
            payload: br#"{"type":"teleport"}"#.to_vec(),
        };
        assert!(matches!(
            frame.parse_control::<HostMessage>(),
            Err(ProtocolError::Json(_))
        ));
    }

    #[test]
    fn serializes_agent_replies_with_camel_case_tags() {
        let ready = AgentMessage::Ready {
            protocol_version: PROTOCOL_VERSION,
            agent_version: "1.0.0".into(),
            kernel: "6.18.38".into(),
            rootfs: "/rootfs".into(),
        };
        let json = ::serde_json::to_string(&ready).unwrap();

        assert!(json.contains("\"type\":\"ready\""));
        assert!(json.contains(&format!("\"protocolVersion\":{PROTOCOL_VERSION}")));
        assert_eq!(
            ::serde_json::from_str::<AgentMessage>(&json).unwrap(),
            ready
        );
    }

    #[test]
    fn serializes_typed_error_codes() {
        let error = AgentMessage::Error {
            id: Some(4),
            code: ErrorCode::MountFailed,
            message: "scratch is not formatted".into(),
        };
        let json = ::serde_json::to_string(&error).unwrap();

        assert!(json.contains("\"code\":\"mountFailed\""));
        assert_eq!(
            ::serde_json::from_str::<AgentMessage>(&json).unwrap(),
            error
        );
    }

    #[test]
    fn round_trips_a_checkpoint_request() {
        let message = HostMessage::Checkpoint {
            id: 11,
            timeout_ms: Some(30_000),
        };
        let json = ::serde_json::to_string(&message).unwrap();

        assert!(json.contains("\"type\":\"checkpoint\""));
        assert!(json.contains("\"timeoutMs\":30000"));
        assert_eq!(
            ::serde_json::from_str::<HostMessage>(&json).unwrap(),
            message
        );
    }

    #[test]
    fn a_checkpoint_may_omit_its_timeout() {
        let decoded: HostMessage =
            ::serde_json::from_str(r#"{"type":"checkpoint","id":3}"#).unwrap();

        assert_eq!(
            decoded,
            HostMessage::Checkpoint {
                id: 3,
                timeout_ms: None
            }
        );
    }

    #[test]
    fn round_trips_the_capture_barrier_replies() {
        let prepared = AgentMessage::CheckpointPrepared { id: 11 };
        let json = ::serde_json::to_string(&prepared).unwrap();
        assert!(json.contains("\"type\":\"checkpointPrepared\""));
        assert_eq!(
            ::serde_json::from_str::<AgentMessage>(&json).unwrap(),
            prepared
        );

        let restored = AgentMessage::Restored { launch_epoch: 7 };
        let json = ::serde_json::to_string(&restored).unwrap();
        assert!(json.contains("\"type\":\"restored\""));
        assert!(json.contains("\"launchEpoch\":7"));
        assert_eq!(
            ::serde_json::from_str::<AgentMessage>(&json).unwrap(),
            restored
        );
    }

    #[test]
    fn serializes_the_capture_error_codes() {
        for (code, tag) in [
            (ErrorCode::CheckpointTimeout, "checkpointTimeout"),
            (ErrorCode::WorkloadBusy, "workloadBusy"),
            (ErrorCode::FreezeFailed, "freezeFailed"),
            (ErrorCode::QuiesceFailed, "quiesceFailed"),
            (ErrorCode::UnsupportedProtocol, "unsupportedProtocol"),
        ] {
            let error = AgentMessage::Error {
                id: None,
                code,
                message: "detail".into(),
            };
            let json = ::serde_json::to_string(&error).unwrap();

            assert!(
                json.contains(&format!("\"code\":\"{tag}\"")),
                "{tag} in {json}"
            );
            assert_eq!(
                ::serde_json::from_str::<AgentMessage>(&json).unwrap(),
                error
            );
        }
    }

    #[test]
    fn accepts_only_its_own_protocol_version() {
        assert!(is_supported_version(PROTOCOL_VERSION));
        // Not a floor: an older peer cannot raise the capture barrier at all, so accepting it
        // would mean silently capturing without one.
        assert!(!is_supported_version(PROTOCOL_VERSION - 1));
        assert!(!is_supported_version(PROTOCOL_VERSION + 1));
    }

    #[test]
    fn the_checkpoint_exchange_is_version_two() {
        // Pins the bump against the message set it was introduced for: adding these to v1
        // would leave a v1 host waiting on a barrier a v1 agent never raises.
        assert_eq!(PROTOCOL_VERSION, 2);
    }
}
