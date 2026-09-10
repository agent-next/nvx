use std::collections::VecDeque;
use std::time::Duration;

use agent_protocol::codec::{InnerRecord, InnerRecordKind};
use agent_protocol::messages::{AgentControlMessage, HostControlMessage};
use agent_protocol::service::{ServiceError, ServiceErrorCode};

use crate::control_session::{ControlSession, ControlSessionError};

const DEFAULT_MAX_INBOUND_QUEUE: usize = 256;

pub struct MxcAgentClient<T: std::io::Read + std::io::Write> {
    control: ControlSession<T>,
    inbound: VecDeque<AgentControlMessage>,
    max_inbound_queue: usize,
}

impl<T: std::io::Read + std::io::Write> MxcAgentClient<T> {
    pub fn new(control: ControlSession<T>) -> Self {
        Self {
            control,
            inbound: VecDeque::new(),
            max_inbound_queue: DEFAULT_MAX_INBOUND_QUEUE,
        }
    }

    pub fn authenticate_launch(
        &mut self,
        capability: [u8; 32],
        hello: HostControlMessage,
        timeout: Duration,
    ) -> Result<(), String> {
        self.control
            .send_attach(capability)
            .map_err(control_error)?;
        self.send_host_control(hello)?;
        let response = self.recv_agent_control(timeout)?;
        if matches!(response, AgentControlMessage::Ready { .. }) {
            return Ok(());
        }
        Err(format!(
            "expected Ready during authentication, got {response:?}"
        ))
    }

    pub fn send_host_control(&mut self, message: HostControlMessage) -> Result<u64, String> {
        let record = InnerRecord::control(&message)
            .map_err(|error| format!("failed to encode host control record: {error:?}"))?;
        let encoded = record
            .encode()
            .map_err(|error| format!("failed to encode inner record bytes: {error:?}"))?;
        self.control.send_data(encoded).map_err(control_error)
    }

    pub fn recv_agent_control(&mut self, timeout: Duration) -> Result<AgentControlMessage, String> {
        if let Some(message) = self.inbound.pop_front() {
            return Ok(message);
        }
        let frame = self.control.read_frame(timeout).map_err(control_error)?;
        let record = InnerRecord::decode(&frame.payload).map_err(|error| {
            format!("failed to decode inner record from control payload: {error:?}")
        })?;
        if record.kind != InnerRecordKind::Control {
            return Err(format!(
                "expected control inner record from agent, got {:?}",
                record.kind
            ));
        }
        let message: AgentControlMessage = serde_json::from_slice(&record.payload)
            .map_err(|error| format!("failed to decode agent control message: {error}"))?;
        Ok(message)
    }

    pub fn queue_agent_message_for_test(
        &mut self,
        message: AgentControlMessage,
    ) -> Result<(), String> {
        if self.inbound.len() == self.max_inbound_queue {
            return Err("inbound agent queue reached configured bound".to_string());
        }
        self.inbound.push_back(message);
        Ok(())
    }
}

pub fn missing_ready_error() -> ServiceError {
    ServiceError {
        code: ServiceErrorCode::ConfigurationRequired,
        message: "WaitReady was not observed".to_string(),
    }
}

fn control_error(error: ControlSessionError) -> String {
    format!("control-session transport error: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_session::{CONTROL_PROTOCOL_MAGIC, CONTROL_PROTOCOL_VERSION};
    use agent_protocol::messages::{LaunchIdentity, ReadyStatus, SERVICE_IDENTITY};
    use std::io::{Cursor, Read, Write};

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
        let io = Cursor::new(Vec::new());
        let session = ControlSession::new(io, 1, [0; 16]);
        let mut client = MxcAgentClient::new(session);
        for _ in 0..DEFAULT_MAX_INBOUND_QUEUE {
            client
                .queue_agent_message_for_test(AgentControlMessage::Quiesced)
                .expect("within bound");
        }
        let overflow = client.queue_agent_message_for_test(AgentControlMessage::Resumed);
        assert!(overflow.is_err());
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
        let mut outer = Vec::new();
        outer.extend_from_slice(&CONTROL_PROTOCOL_MAGIC.to_be_bytes());
        outer.extend_from_slice(&CONTROL_PROTOCOL_VERSION.to_be_bytes());
        outer.extend_from_slice(&(5_u16).to_be_bytes()); // Data
        outer.extend_from_slice(&0_u64.to_be_bytes());
        outer.extend_from_slice(&1_u64.to_be_bytes());
        outer.extend_from_slice(&[0_u8; 16]);
        outer.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        outer.extend_from_slice(&inner);

        let session = ControlSession::new(MockDuplex::with_read_bytes(outer), 1, [0; 16]);
        let mut client = MxcAgentClient::new(session);
        let decoded = client
            .recv_agent_control(Duration::from_secs(1))
            .expect("decoded message");
        assert!(matches!(decoded, AgentControlMessage::Ready { .. }));
    }
}
