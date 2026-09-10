use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;
use std::time::Instant;

use agent_protocol::codec::{InnerRecord, InnerRecordKind};
use agent_protocol::control_session::{
    HostAttachStatus, HostControlSession, HostEvent, SessionError,
};
use agent_protocol::messages::{AgentControlMessage, HostControlMessage};
use agent_protocol::service::{ServiceError, ServiceErrorCode};

const DEFAULT_MAX_INBOUND_QUEUE: usize = 256;
const DEFAULT_POLL_SLEEP: Duration = Duration::from_millis(5);

#[derive(Debug)]
pub enum ClientError {
    Control(SessionError),
    Timeout(&'static str),
    QueueOverflow(QueueOverflowDiagnostics),
    ClientInvalidated(QueueOverflowDiagnostics),
    Protocol(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueOverflowDiagnostics {
    pub queue: &'static str,
    pub bound: usize,
    pub dropped_count: usize,
    pub dropped_by_type: BTreeMap<&'static str, usize>,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Control(error) => write!(f, "control-session transport error: {error}"),
            Self::Timeout(operation) => {
                write!(f, "timed out waiting for {operation}")
            }
            Self::QueueOverflow(diagnostics) => {
                write!(
                    f,
                    "{} queue reached configured bound {} and dropped {} message(s) [{}]",
                    diagnostics.queue,
                    diagnostics.bound,
                    diagnostics.dropped_count,
                    format_dropped_types(&diagnostics.dropped_by_type)
                )
            }
            Self::ClientInvalidated(diagnostics) => {
                write!(
                    f,
                    "client invalidated after {} queue overflow at bound {}; dropped {} message(s) [{}]",
                    diagnostics.queue,
                    diagnostics.bound,
                    diagnostics.dropped_count,
                    format_dropped_types(&diagnostics.dropped_by_type)
                )
            }
            Self::Protocol(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<SessionError> for ClientError {
    fn from(value: SessionError) -> Self {
        match value {
            SessionError::DeadlineExceeded(context) => Self::Timeout(context),
            other => Self::Control(other),
        }
    }
}

pub struct MxcAgentClient<T: std::io::Read + std::io::Write> {
    control: HostControlSession<T>,
    inbound: VecDeque<AgentControlMessage>,
    max_inbound_queue: usize,
    overflow_diagnostics: Option<QueueOverflowDiagnostics>,
}

impl<T: std::io::Read + std::io::Write> MxcAgentClient<T> {
    pub fn new(control: HostControlSession<T>) -> Self {
        Self {
            control,
            inbound: VecDeque::new(),
            max_inbound_queue: DEFAULT_MAX_INBOUND_QUEUE,
            overflow_diagnostics: None,
        }
    }

    pub fn control_session_mut(&mut self) -> &mut HostControlSession<T> {
        &mut self.control
    }

    pub fn authenticate_launch(
        &mut self,
        capability: [u8; 32],
        hello: HostControlMessage,
        timeout: Duration,
    ) -> Result<(), ClientError> {
        self.ensure_valid()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "control receive deadline overflowed".to_string(),
            ))?;
        self.control
            .send_host_attach(capability)
            .map_err(ClientError::from)?;
        match self.control.recv_attach_status_until(deadline)? {
            HostAttachStatus::Wait => loop {
                match self.control.recv_event_until(deadline)? {
                    HostEvent::Ready => break,
                    HostEvent::Error(code) => {
                        return Err(ClientError::Protocol(format!(
                            "control-session broker rejected host attach with error code {code}"
                        )));
                    }
                    HostEvent::Wait => {}
                    HostEvent::Data(_) => {
                        return Err(ClientError::Protocol(
                            "received data before broker Ready".to_string(),
                        ));
                    }
                    HostEvent::Reset { .. } => {
                        return Err(ClientError::Protocol(
                            "received reset during host attach handshake".to_string(),
                        ));
                    }
                }
            },
            HostAttachStatus::Ready => {}
            HostAttachStatus::Error(code) => {
                return Err(ClientError::Protocol(format!(
                    "control-session broker rejected host attach with error code {code}"
                )));
            }
        }
        self.send_host_control(hello)?;
        let maybe_response = self.poll_agent_control(Duration::ZERO)?;
        if let Some(response) = maybe_response {
            return Err(ClientError::Protocol(format!(
                "unexpected response after HostHello; production does not send one before Configure: {response:?}"
            )));
        }
        Ok(())
    }

    pub fn send_host_control(&mut self, message: HostControlMessage) -> Result<u64, ClientError> {
        self.ensure_valid()?;
        let record = InnerRecord::control(&message).map_err(|error| {
            ClientError::Protocol(format!("failed to encode host control record: {error:?}"))
        })?;
        let encoded = record.encode().map_err(|error| {
            ClientError::Protocol(format!("failed to encode inner record bytes: {error:?}"))
        })?;
        self.control.send_data(encoded).map_err(ClientError::from)
    }

    pub fn send_raw_control_payload(&mut self, payload: &[u8]) -> Result<u64, ClientError> {
        self.ensure_valid()?;
        let record = InnerRecord {
            exec_id: 0,
            kind: InnerRecordKind::Control,
            end_of_stream: false,
            sequence: 0,
            payload: payload.to_vec(),
        };
        let encoded = record.encode().map_err(|error| {
            ClientError::Protocol(format!(
                "failed to encode raw inner record bytes: {error:?}"
            ))
        })?;
        self.control.send_data(encoded).map_err(ClientError::from)
    }

    pub fn recv_agent_control(
        &mut self,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        self.ensure_valid()?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "control receive deadline overflowed".to_string(),
            ))?;
        self.recv_next_until(deadline, "agent control message")
    }

    fn recv_next_until(
        &mut self,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<AgentControlMessage, ClientError> {
        self.ensure_valid()?;
        if let Some(message) = self.inbound.pop_front() {
            return Ok(message);
        }
        loop {
            match self.control.try_recv_event()? {
                Some(event) => {
                    self.handle_host_event(event)?;
                    if let Some(message) = self.inbound.pop_front() {
                        return Ok(message);
                    }
                }
                None => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(ClientError::Timeout(operation));
                    }
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(now)
                            .min(DEFAULT_POLL_SLEEP),
                    );
                }
            }
        }
    }

    pub fn poll_agent_control(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<AgentControlMessage>, ClientError> {
        self.ensure_valid()?;
        if let Some(message) = self.inbound.pop_front() {
            return Ok(Some(message));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "control poll deadline overflowed".to_string(),
            ))?;
        loop {
            match self.control.try_recv_event()? {
                Some(event) => {
                    self.handle_host_event(event)?;
                    if let Some(message) = self.inbound.pop_front() {
                        return Ok(Some(message));
                    }
                }
                None => {
                    if let Some(message) = self.inbound.pop_front() {
                        return Ok(Some(message));
                    }
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining.min(DEFAULT_POLL_SLEEP));
                }
            }
        }
    }

    pub fn send_host_hello(&mut self, message: HostControlMessage) -> Result<u64, ClientError> {
        self.send_host_control(message)
    }

    pub fn send_configure(&mut self, message: HostControlMessage) -> Result<u64, ClientError> {
        self.send_host_control(message)
    }

    pub fn send_create_process(&mut self, message: HostControlMessage) -> Result<u64, ClientError> {
        self.send_host_control(message)
    }

    pub fn send_cancel_execution(&mut self, exec_id: u32) -> Result<u64, ClientError> {
        self.send_host_control(HostControlMessage::CancelExecution { exec_id })
    }

    pub fn send_flow_credits(
        &mut self,
        request: agent_protocol::messages::FlowCreditRequest,
    ) -> Result<u64, ClientError> {
        self.send_host_control(HostControlMessage::FlowCredits(request))
    }

    pub fn send_stdin_chunk(
        &mut self,
        record: agent_protocol::messages::StdinChunkRecord,
    ) -> Result<u64, ClientError> {
        self.send_host_control(HostControlMessage::StdinChunk(record))
    }

    pub fn send_stdin_eof(
        &mut self,
        record: agent_protocol::messages::StdinEofRecord,
    ) -> Result<u64, ClientError> {
        self.send_host_control(HostControlMessage::StdinEof(record))
    }

    pub fn request_health(
        &mut self,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        self.request_health_observing_inbound(timeout, |_| Ok(()))
    }

    pub fn request_health_observing_inbound<F>(
        &mut self,
        timeout: Duration,
        mut observe_unrelated: F,
    ) -> Result<AgentControlMessage, ClientError>
    where
        F: FnMut(&AgentControlMessage) -> Result<(), ClientError>,
    {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "health request deadline overflowed".to_string(),
            ))?;
        self.send_host_control(HostControlMessage::Health)?;
        let mut deferred = VecDeque::new();
        loop {
            let message = match self.recv_next_until(deadline, "agent control response") {
                Ok(message) => message,
                Err(ClientError::Timeout(_)) => {
                    self.restore_deferred(deferred)?;
                    return Err(ClientError::Timeout("agent control response"));
                }
                Err(error) => {
                    self.restore_deferred(deferred)?;
                    return Err(error);
                }
            };
            if matches!(
                message,
                AgentControlMessage::Health(_) | AgentControlMessage::Error(_)
            ) {
                self.restore_deferred(deferred)?;
                return Ok(message);
            }
            if let Err(error) = observe_unrelated(&message) {
                self.restore_deferred(deferred)?;
                return Err(error);
            }
            self.push_deferred(&mut deferred, message)?;
        }
    }

    pub fn request_quiesce(
        &mut self,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "quiesce request deadline overflowed".to_string(),
            ))?;
        self.send_host_control(HostControlMessage::Quiesce)?;
        self.recv_matching_until(deadline, |message| {
            matches!(
                message,
                AgentControlMessage::Quiesced | AgentControlMessage::Error(_)
            )
        })
    }

    pub fn request_resume(
        &mut self,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "resume request deadline overflowed".to_string(),
            ))?;
        self.send_host_control(HostControlMessage::Resume)?;
        self.recv_matching_until(deadline, |message| {
            matches!(
                message,
                AgentControlMessage::Resumed | AgentControlMessage::Error(_)
            )
        })
    }

    pub fn request_shutdown(
        &mut self,
        grace_timeout_ms: u64,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "shutdown request deadline overflowed".to_string(),
            ))?;
        self.send_host_control(HostControlMessage::Shutdown { grace_timeout_ms })?;
        self.recv_matching_until(deadline, |message| {
            matches!(
                message,
                AgentControlMessage::ShuttingDown | AgentControlMessage::Error(_)
            )
        })
    }

    pub fn wait_ready(&mut self, timeout: Duration) -> Result<AgentControlMessage, ClientError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "wait_ready deadline overflowed".to_string(),
            ))?;
        self.recv_matching_until(deadline, |message| {
            matches!(
                message,
                AgentControlMessage::Ready { .. } | AgentControlMessage::Error(_)
            )
        })
    }

    pub fn wait_exec_terminal(
        &mut self,
        exec_id: u32,
        timeout: Duration,
    ) -> Result<AgentControlMessage, ClientError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ClientError::Protocol(
                "exec wait deadline overflowed".to_string(),
            ))?;
        let mut deferred = VecDeque::new();
        loop {
            let message = self.recv_next_until(deadline, "exec terminal message")?;
            match message {
                AgentControlMessage::ExecTerminal {
                    exec_id: terminal_exec_id,
                    ..
                } if terminal_exec_id == exec_id => {
                    self.restore_deferred(deferred)?;
                    return Ok(message);
                }
                AgentControlMessage::StdoutChunk(agent_protocol::messages::StdoutChunkRecord {
                    exec_id: chunk_exec_id,
                    ..
                }) if chunk_exec_id == exec_id => {
                    self.send_flow_credits(agent_protocol::messages::FlowCreditRequest {
                        exec_id,
                        stream: agent_protocol::messages::StreamName::Stdout,
                        credits: 1,
                    })?;
                }
                AgentControlMessage::StderrChunk(agent_protocol::messages::StderrChunkRecord {
                    exec_id: chunk_exec_id,
                    ..
                }) if chunk_exec_id == exec_id => {
                    self.send_flow_credits(agent_protocol::messages::FlowCreditRequest {
                        exec_id,
                        stream: agent_protocol::messages::StreamName::Stderr,
                        credits: 1,
                    })?;
                }
                AgentControlMessage::Error(_) => {
                    self.restore_deferred(deferred)?;
                    return Ok(message);
                }
                _ => self.push_deferred(&mut deferred, message)?,
            }
        }
    }

    fn recv_matching_until<F>(
        &mut self,
        deadline: Instant,
        mut predicate: F,
    ) -> Result<AgentControlMessage, ClientError>
    where
        F: FnMut(&AgentControlMessage) -> bool,
    {
        let mut deferred = VecDeque::new();
        loop {
            let message = match self.recv_next_until(deadline, "agent control response") {
                Ok(message) => message,
                Err(ClientError::Timeout(_)) => {
                    self.restore_deferred(deferred)?;
                    return Err(ClientError::Timeout("agent control response"));
                }
                Err(error) => {
                    self.restore_deferred(deferred)?;
                    return Err(error);
                }
            };
            if predicate(&message) {
                self.restore_deferred(deferred)?;
                return Ok(message);
            }
            self.push_deferred(&mut deferred, message)?;
        }
    }

    pub fn queue_agent_message_for_test(
        &mut self,
        message: AgentControlMessage,
    ) -> Result<(), ClientError> {
        self.ensure_valid()?;
        self.push_inbound(message)
    }

    fn handle_host_event(&mut self, event: HostEvent) -> Result<(), ClientError> {
        match event {
            HostEvent::Data(payload) => {
                let message = decode_control_message(&payload)?;
                self.push_inbound(message)
            }
            HostEvent::Error(code) => Err(ClientError::Protocol(format!(
                "control-session broker sent Error with code {code}"
            ))),
            HostEvent::Reset { .. } => Err(ClientError::Protocol(
                "control-session reset observed while waiting for agent control message"
                    .to_string(),
            )),
            HostEvent::Wait | HostEvent::Ready => Ok(()),
        }
    }

    fn push_inbound(&mut self, message: AgentControlMessage) -> Result<(), ClientError> {
        if self.inbound.len() == self.max_inbound_queue {
            return Err(self.invalidate_queue_overflow(
                "inbound",
                self.max_inbound_queue,
                vec![message],
            ));
        }
        self.inbound.push_back(message);
        Ok(())
    }

    fn push_deferred(
        &mut self,
        deferred: &mut VecDeque<AgentControlMessage>,
        message: AgentControlMessage,
    ) -> Result<(), ClientError> {
        if deferred.len() == self.max_inbound_queue {
            let mut dropped: Vec<AgentControlMessage> =
                std::mem::take(deferred).into_iter().collect();
            dropped.push(message);
            return Err(self.invalidate_queue_overflow(
                "deferred",
                self.max_inbound_queue,
                dropped,
            ));
        }
        deferred.push_back(message);
        Ok(())
    }

    fn restore_deferred(
        &mut self,
        mut deferred: VecDeque<AgentControlMessage>,
    ) -> Result<(), ClientError> {
        while let Some(message) = deferred.pop_back() {
            if self.inbound.len() == self.max_inbound_queue {
                let mut dropped = vec![message];
                dropped.extend(deferred);
                return Err(self.invalidate_queue_overflow(
                    "inbound",
                    self.max_inbound_queue,
                    dropped,
                ));
            }
            self.inbound.push_front(message);
        }
        Ok(())
    }

    fn ensure_valid(&self) -> Result<(), ClientError> {
        if let Some(diagnostics) = self.overflow_diagnostics.clone() {
            return Err(ClientError::ClientInvalidated(diagnostics));
        }
        Ok(())
    }

    fn invalidate_queue_overflow(
        &mut self,
        queue: &'static str,
        bound: usize,
        dropped_messages: Vec<AgentControlMessage>,
    ) -> ClientError {
        let mut dropped_by_type = BTreeMap::new();
        for message in &dropped_messages {
            let key = message_type_name(message);
            *dropped_by_type.entry(key).or_insert(0) += 1;
        }
        let diagnostics = QueueOverflowDiagnostics {
            queue,
            bound,
            dropped_count: dropped_messages.len(),
            dropped_by_type,
        };
        self.inbound.clear();
        self.overflow_diagnostics = Some(diagnostics.clone());
        ClientError::QueueOverflow(diagnostics)
    }
}

fn message_type_name(message: &AgentControlMessage) -> &'static str {
    match message {
        AgentControlMessage::Ready { .. } => "Ready",
        AgentControlMessage::Error(_) => "Error",
        AgentControlMessage::Health(_) => "Health",
        AgentControlMessage::Quiesced => "Quiesced",
        AgentControlMessage::Resumed => "Resumed",
        AgentControlMessage::ShuttingDown => "ShuttingDown",
        AgentControlMessage::StdoutChunk(_) => "StdoutChunk",
        AgentControlMessage::StdoutEof(_) => "StdoutEof",
        AgentControlMessage::StderrChunk(_) => "StderrChunk",
        AgentControlMessage::StderrEof(_) => "StderrEof",
        AgentControlMessage::StreamDrained { .. } => "StreamDrained",
        AgentControlMessage::DescendantsCleaned { .. } => "DescendantsCleaned",
        AgentControlMessage::ExecTerminal { .. } => "ExecTerminal",
    }
}

fn format_dropped_types(dropped_by_type: &BTreeMap<&'static str, usize>) -> String {
    dropped_by_type
        .iter()
        .map(|(kind, count)| format!("{kind}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn missing_ready_error() -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::ConfigurationRequired,
        message: "WaitReady was not observed".to_string(),
    }
}

fn decode_control_message(payload: &[u8]) -> Result<AgentControlMessage, ClientError> {
    let record = InnerRecord::decode(payload).map_err(|error| {
        ClientError::Protocol(format!(
            "failed to decode inner record from control payload: {error:?}"
        ))
    })?;
    if record.kind != InnerRecordKind::Control {
        return Err(ClientError::Protocol(format!(
            "expected control inner record from agent, got {:?}",
            record.kind
        )));
    }
    serde_json::from_slice::<AgentControlMessage>(&record.payload).map_err(|error| {
        ClientError::Protocol(format!("failed to decode agent control message: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_session::{HostControlSession, Record, RecordType, encode};
    use agent_protocol::mapping::{
        CanonicalHostMappingRoot, MappingContainmentPolicy, SymlinkContainmentPolicy,
    };
    use agent_protocol::messages::{CapabilityProofMaterial, NetworkMode, NetworkSetupState};
    use agent_protocol::messages::{LaunchIdentity, ReadyStatus, SERVICE_IDENTITY};
    use std::collections::VecDeque;
    use std::io::{Cursor, Read, Write};
    use std::sync::{Arc, Mutex};

    struct MockDuplex {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockDuplex {
        fn with_read_bytes(bytes: Vec<u8>) -> Self {
            Self {
                read: Cursor::new(bytes),
                written: vec![],
            }
        }
    }

    impl Read for MockDuplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for MockDuplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn inbound_queue_is_bounded() {
        let session = HostControlSession::new(Cursor::new(Vec::new()));
        let mut client = MxcAgentClient::new(session);
        for _ in 0..DEFAULT_MAX_INBOUND_QUEUE {
            client
                .queue_agent_message_for_test(AgentControlMessage::Quiesced)
                .expect("within bound");
        }
        let overflow = client.queue_agent_message_for_test(AgentControlMessage::Resumed);
        let details = match overflow {
            Err(ClientError::QueueOverflow(details)) => details,
            other => panic!("expected inbound queue overflow, got {other:?}"),
        };
        assert_eq!(details.queue, "inbound");
        assert_eq!(details.bound, DEFAULT_MAX_INBOUND_QUEUE);
        assert_eq!(details.dropped_count, 1);
        assert_eq!(details.dropped_by_type.get("Resumed"), Some(&1));

        let invalidated = client.queue_agent_message_for_test(AgentControlMessage::Quiesced);
        assert!(matches!(
            invalidated,
            Err(ClientError::ClientInvalidated(_))
        ));
    }

    #[test]
    fn fake_broker_frame_decodes_ready_message() {
        let ready = AgentControlMessage::Ready {
            launch: LaunchIdentity {
                generation: 7,
                nonce: [8; 16],
            },
            status: ReadyStatus {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: 1,
                build: agent_protocol::messages::BuildStatus {
                    agent_version: "x".to_string(),
                    kernel_release: "y".to_string(),
                    profile: "mxc-prototype".to_string(),
                },
                network: agent_protocol::messages::NetworkStatus {
                    mode: agent_protocol::messages::NetworkMode::NoNic,
                    setup_state: agent_protocol::messages::NetworkSetupState::Ready,
                    interface: None,
                    default_gateway: None,
                    dns: agent_protocol::messages::DnsStatus {
                        ready: true,
                        servers: vec![],
                    },
                    failure: None,
                },
                isolation: agent_protocol::messages::IsolationStatus {
                    pid_namespace: true,
                    mount_namespace: true,
                    uts_namespace: true,
                    ipc_namespace: true,
                    private_proc: true,
                    private_dev: true,
                    private_devpts: true,
                    private_shm: true,
                    read_only_sys: true,
                    capabilities_dropped: true,
                    no_new_privs: true,
                    cgroup_separation: true,
                    orphan_reaping: true,
                },
                workload_identity: agent_protocol::messages::WorkloadIdentityStatus::mxc_fixed(),
            },
        };
        let inner = InnerRecord::control(&ready).expect("encode control");
        let inner = inner.encode().expect("encode bytes");
        let outer = encode(&Record::session(RecordType::Data, [0xA5; 16], 3, 0, inner))
            .expect("encode outer");
        let session = HostControlSession::new(MockDuplex::with_read_bytes(outer));
        let mut client = MxcAgentClient::new(session);
        let decoded = client
            .recv_agent_control(Duration::from_secs(1))
            .expect("decoded message");
        assert!(matches!(decoded, AgentControlMessage::Ready { .. }));
    }

    #[test]
    fn fixture_broker_round_trips_auth_configure_and_health_over_outer_data() {
        let capability = [0x9A; 32];
        let fixture = Arc::new(Mutex::new(ClientFixtureBroker::new(capability)));
        let session = HostControlSession::new(ClientFixtureEndpoint::new(fixture.clone()));
        let mut client = MxcAgentClient::new(session);
        let launch = LaunchIdentity {
            generation: 22,
            nonce: [0xAB; 16],
        };

        client
            .authenticate_launch(
                capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: 1,
                    launch,
                    capability_proof: CapabilityProofMaterial::try_from(capability.to_vec())
                        .expect("capability proof"),
                },
                Duration::from_secs(1),
            )
            .expect("authenticated");

        let auth_phase_ready = client
            .wait_ready(Duration::from_millis(10))
            .expect_err("ready must not arrive before configure");
        assert!(matches!(auth_phase_ready, ClientError::Timeout(_)));

        let root = CanonicalHostMappingRoot::parse("/sandbox-root".to_string()).expect("root");
        client
            .send_configure(HostControlMessage::Configure {
                launch,
                root,
                mappings: vec![],
                containment: MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            })
            .expect("configure request");
        let ready = client.wait_ready(Duration::from_secs(1)).expect("ready");
        assert!(matches!(ready, AgentControlMessage::Ready { .. }));

        let health = client
            .request_health(Duration::from_secs(1))
            .expect("health");
        assert!(matches!(
            health,
            AgentControlMessage::Health(agent_protocol::messages::HealthStatus {
                quiesced: false,
                ..
            })
        ));
    }

    #[test]
    fn health_request_defers_terminal_and_preserves_it() {
        let capability = [0x9A; 32];
        let fixture = Arc::new(Mutex::new(ClientFixtureBroker::new(capability)));
        let session = HostControlSession::new(ClientFixtureEndpoint::new(fixture));
        let mut client = MxcAgentClient::new(session);
        client.max_inbound_queue = 8;
        let launch = LaunchIdentity {
            generation: 22,
            nonce: [0xAB; 16],
        };
        client
            .authenticate_launch(
                capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: 1,
                    launch,
                    capability_proof: CapabilityProofMaterial::try_from(capability.to_vec())
                        .expect("capability proof"),
                },
                Duration::from_secs(1),
            )
            .expect("authenticated");
        client
            .send_configure(HostControlMessage::Configure {
                launch,
                root: CanonicalHostMappingRoot::parse("/sandbox-root".to_string()).expect("root"),
                mappings: vec![],
                containment: MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            })
            .expect("configure request");
        let _ = client.wait_ready(Duration::from_secs(1)).expect("ready");
        client
            .queue_agent_message_for_test(AgentControlMessage::ExecTerminal {
                exec_id: 9,
                disposition: agent_protocol::messages::ExecDisposition::ExitCode(0),
                termination: None,
            })
            .expect("queue terminal");
        client
            .queue_agent_message_for_test(AgentControlMessage::Health(sample_health_status()))
            .expect("queue health");
        let health = client
            .request_health(Duration::from_millis(25))
            .expect("health response");
        assert!(matches!(health, AgentControlMessage::Health(_)));
        let preserved = client
            .wait_exec_terminal(9, Duration::from_millis(25))
            .expect("terminal preserved");
        assert!(matches!(
            preserved,
            AgentControlMessage::ExecTerminal { exec_id: 9, .. }
        ));
    }

    #[test]
    fn health_request_observer_can_reject_specific_pre_health_events_without_losing_unrelated() {
        let capability = [0x9A; 32];
        let fixture = Arc::new(Mutex::new(ClientFixtureBroker::new(capability)));
        let session = HostControlSession::new(ClientFixtureEndpoint::new(fixture));
        let mut client = MxcAgentClient::new(session);
        client.max_inbound_queue = 8;
        let launch = LaunchIdentity {
            generation: 22,
            nonce: [0xAB; 16],
        };
        client
            .authenticate_launch(
                capability,
                HostControlMessage::HostHello {
                    service: SERVICE_IDENTITY.to_string(),
                    protocol_version: 1,
                    launch,
                    capability_proof: CapabilityProofMaterial::try_from(capability.to_vec())
                        .expect("capability proof"),
                },
                Duration::from_secs(1),
            )
            .expect("authenticated");
        client
            .send_configure(HostControlMessage::Configure {
                launch,
                root: CanonicalHostMappingRoot::parse("/sandbox-root".to_string()).expect("root"),
                mappings: vec![],
                containment: MappingContainmentPolicy {
                    symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                    reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
                },
            })
            .expect("configure request");
        let _ = client.wait_ready(Duration::from_secs(1)).expect("ready");
        client
            .queue_agent_message_for_test(AgentControlMessage::StdoutChunk(
                agent_protocol::messages::StdoutChunkRecord {
                    exec_id: 77,
                    sequence: 0,
                    chunk: vec![1, 2, 3],
                },
            ))
            .expect("queue unrelated stream");
        client
            .queue_agent_message_for_test(AgentControlMessage::Health(sample_health_status()))
            .expect("queue health");

        let health = client
            .request_health_observing_inbound(Duration::from_millis(25), |message| match message {
                AgentControlMessage::StdoutChunk(record) if record.exec_id == 88 => Err(
                    ClientError::Protocol("unexpected target chunk before health".to_string()),
                ),
                _ => Ok(()),
            })
            .expect("health response");
        assert!(matches!(health, AgentControlMessage::Health(_)));
        let preserved = client
            .recv_agent_control(Duration::from_millis(25))
            .expect("preserved unrelated event");
        assert!(matches!(
            preserved,
            AgentControlMessage::StdoutChunk(agent_protocol::messages::StdoutChunkRecord {
                exec_id: 77,
                ..
            })
        ));
    }

    #[test]
    fn wait_exec_terminal_preserves_unrelated_exec_events() {
        let session = HostControlSession::new(Cursor::new(Vec::new()));
        let mut client = MxcAgentClient::new(session);
        client.max_inbound_queue = 8;
        client
            .queue_agent_message_for_test(AgentControlMessage::StdoutChunk(
                agent_protocol::messages::StdoutChunkRecord {
                    exec_id: 77,
                    sequence: 0,
                    chunk: vec![1, 2, 3],
                },
            ))
            .expect("queue unrelated stream");
        client
            .queue_agent_message_for_test(AgentControlMessage::ExecTerminal {
                exec_id: 7,
                disposition: agent_protocol::messages::ExecDisposition::ExitCode(0),
                termination: None,
            })
            .expect("queue target terminal");

        let terminal = client
            .wait_exec_terminal(7, Duration::from_millis(25))
            .expect("terminal");
        assert!(matches!(
            terminal,
            AgentControlMessage::ExecTerminal { exec_id: 7, .. }
        ));
        let preserved = client
            .recv_agent_control(Duration::from_millis(25))
            .expect("preserved unrelated event");
        assert!(matches!(
            preserved,
            AgentControlMessage::StdoutChunk(agent_protocol::messages::StdoutChunkRecord {
                exec_id: 77,
                ..
            })
        ));
    }

    #[test]
    fn unmatched_events_do_not_extend_absolute_deadline() {
        let session = HostControlSession::new(MockIdleDuplex);
        let mut client = MxcAgentClient::new(session);
        for _ in 0..128 {
            client
                .queue_agent_message_for_test(AgentControlMessage::Quiesced)
                .expect("queue unmatched");
        }
        let timeout = Duration::from_millis(40);
        let start = Instant::now();
        let result = client.wait_ready(timeout);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(ClientError::Timeout(_))),
            "unexpected result: {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "deadline overrun too large: {elapsed:?}"
        );
    }

    #[test]
    fn deferred_queue_overflow_returns_typed_error() {
        let session = HostControlSession::new(Cursor::new(Vec::new()));
        let mut client = MxcAgentClient::new(session);
        client.max_inbound_queue = 3;
        client
            .queue_agent_message_for_test(AgentControlMessage::Quiesced)
            .expect("queue 1");
        client
            .queue_agent_message_for_test(AgentControlMessage::Resumed)
            .expect("queue 2");
        client
            .queue_agent_message_for_test(AgentControlMessage::Quiesced)
            .expect("queue 3");
        client.max_inbound_queue = 2;
        let result = client.wait_ready(Duration::from_millis(10));
        let overflow = match result {
            Err(ClientError::QueueOverflow(details)) => details,
            other => panic!("expected queue overflow, got {other:?}"),
        };
        assert_eq!(overflow.queue, "deferred");
        assert_eq!(overflow.bound, 2);
        assert_eq!(overflow.dropped_count, 3);
        assert_eq!(overflow.dropped_by_type.get("Quiesced"), Some(&2));
        assert_eq!(overflow.dropped_by_type.get("Resumed"), Some(&1));

        let start = Instant::now();
        let invalidated = client.wait_ready(Duration::from_secs(1));
        let elapsed = start.elapsed();
        let invalidated_details = match invalidated {
            Err(ClientError::ClientInvalidated(details)) => details,
            other => panic!("expected invalidated client error, got {other:?}"),
        };
        assert_eq!(invalidated_details, overflow);
        assert!(
            elapsed < Duration::from_millis(100),
            "invalidated client must fail immediately, took {elapsed:?}"
        );
    }

    fn sample_health_status() -> agent_protocol::messages::HealthStatus {
        agent_protocol::messages::HealthStatus {
            agent_state: agent_protocol::messages::AgentSessionState::Active,
            quiesced: false,
            launch_admitted: true,
            shutting_down: false,
            channel_generation: 1,
            active_exec_id: Some(9),
            filesystem: Some(agent_protocol::messages::FilesystemHealthStatus {
                rootfs_ready: true,
                detail: "ready".to_string(),
            }),
            network: Some(agent_protocol::messages::NetworkStatus {
                mode: agent_protocol::messages::NetworkMode::PortableNetwork,
                setup_state: agent_protocol::messages::NetworkSetupState::Ready,
                interface: None,
                default_gateway: None,
                dns: agent_protocol::messages::DnsStatus {
                    ready: true,
                    servers: vec![],
                },
                failure: None,
            }),
            last_failure: None,
        }
    }

    #[derive(Clone)]
    struct ClientFixtureBroker {
        capability: [u8; 32],
        instance_id: [u8; 16],
        epoch: u64,
        host_sequence: u64,
        server_sequence: u64,
        inbound: VecDeque<u8>,
    }

    impl ClientFixtureBroker {
        fn new(capability: [u8; 32]) -> Self {
            Self {
                capability,
                instance_id: [0x5A; 16],
                epoch: 3,
                host_sequence: 0,
                server_sequence: 0,
                inbound: VecDeque::new(),
            }
        }

        fn handle_write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            let record = agent_protocol::control_session::decode_exact(bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            match record.record_type {
                RecordType::HostAttach => {
                    if record.payload != self.capability {
                        self.push_record(Record::session(
                            RecordType::Error,
                            self.instance_id,
                            self.epoch,
                            self.server_sequence,
                            1_u32.to_le_bytes().to_vec(),
                        ))?;
                        self.server_sequence += 1;
                        return Ok(());
                    }
                    self.push_record(Record::session(
                        RecordType::Wait,
                        self.instance_id,
                        self.epoch,
                        self.server_sequence,
                        vec![],
                    ))?;
                    self.server_sequence += 1;
                    self.push_record(Record::session(
                        RecordType::Ready,
                        self.instance_id,
                        self.epoch,
                        self.server_sequence,
                        vec![],
                    ))?;
                    self.server_sequence += 1;
                }
                RecordType::Data => {
                    if record.sequence != self.host_sequence {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "host data sequence mismatch",
                        ));
                    }
                    self.host_sequence += 1;
                    let inner = InnerRecord::decode(&record.payload).map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("inner decode failed: {error:?}"),
                        )
                    })?;
                    let host_message: HostControlMessage = serde_json::from_slice(&inner.payload)
                        .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("host message decode failed: {error}"),
                        )
                    })?;
                    self.respond_to_host_message(host_message)?;
                }
                _ => {}
            }
            Ok(())
        }

        fn respond_to_host_message(&mut self, message: HostControlMessage) -> std::io::Result<()> {
            let response = match message {
                HostControlMessage::HostHello { .. } => return Ok(()),
                HostControlMessage::Configure { launch, .. } => AgentControlMessage::Ready {
                    launch,
                    status: ReadyStatus {
                        service: SERVICE_IDENTITY.to_string(),
                        protocol_version: 1,
                        build: agent_protocol::messages::BuildStatus {
                            agent_version: "test".to_string(),
                            kernel_release: "test".to_string(),
                            profile: "mxc-prototype".to_string(),
                        },
                        network: agent_protocol::messages::NetworkStatus {
                            mode: NetworkMode::NoNic,
                            setup_state: NetworkSetupState::Ready,
                            interface: None,
                            default_gateway: None,
                            dns: agent_protocol::messages::DnsStatus {
                                ready: true,
                                servers: vec![],
                            },
                            failure: None,
                        },
                        isolation: agent_protocol::messages::IsolationStatus {
                            pid_namespace: true,
                            mount_namespace: true,
                            uts_namespace: true,
                            ipc_namespace: true,
                            private_proc: true,
                            private_dev: true,
                            private_devpts: true,
                            private_shm: true,
                            read_only_sys: true,
                            capabilities_dropped: true,
                            no_new_privs: true,
                            cgroup_separation: true,
                            orphan_reaping: true,
                        },
                        workload_identity:
                            agent_protocol::messages::WorkloadIdentityStatus::mxc_fixed(),
                    },
                },
                HostControlMessage::Health => {
                    AgentControlMessage::Health(agent_protocol::messages::HealthStatus {
                        agent_state: agent_protocol::messages::AgentSessionState::Active,
                        quiesced: false,
                        launch_admitted: true,
                        shutting_down: false,
                        channel_generation: 1,
                        active_exec_id: None,
                        filesystem: None,
                        network: None,
                        last_failure: None,
                    })
                }
                _ => return Ok(()),
            };
            let inner = InnerRecord::control(&response)
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?
                .encode()
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
            self.push_record(Record::session(
                RecordType::Data,
                self.instance_id,
                self.epoch,
                self.server_sequence,
                inner,
            ))?;
            self.server_sequence += 1;
            Ok(())
        }

        fn push_record(&mut self, record: Record) -> std::io::Result<()> {
            let encoded = encode(&record)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            self.inbound.extend(encoded);
            Ok(())
        }
    }

    struct ClientFixtureEndpoint {
        fixture: Arc<Mutex<ClientFixtureBroker>>,
    }

    impl ClientFixtureEndpoint {
        fn new(fixture: Arc<Mutex<ClientFixtureBroker>>) -> Self {
            Self { fixture }
        }
    }

    impl Read for ClientFixtureEndpoint {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut broker = self.fixture.lock().expect("fixture");
            let mut read = 0usize;
            while read < buf.len() {
                let Some(byte) = broker.inbound.pop_front() else {
                    break;
                };
                buf[read] = byte;
                read += 1;
            }
            if read == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "idle"));
            }
            Ok(read)
        }
    }

    impl Write for ClientFixtureEndpoint {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.fixture.lock().expect("fixture").handle_write(buf)?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockIdleDuplex;

    impl Read for MockIdleDuplex {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "idle"))
        }
    }

    impl Write for MockIdleDuplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
