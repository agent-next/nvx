use ::std::collections::BTreeMap;
use ::std::collections::VecDeque;
use ::std::process::ExitCode;

use ::agent_protocol::mapping::{
    AccessMode, CanonicalHostMappingRoot, ChildMapping, MappingContainmentPolicy,
    RelativeChildPath, SymlinkContainmentPolicy,
};
use ::agent_protocol::messages::{
    FlowCreditRequest, LaunchIdentity, NetworkMode, NetworkStatus, SERVICE_IDENTITY, StreamName,
};
use ::agent_protocol::mxc_extension::{
    AciAdapterStatus, MODELED_REQUIREMENTS, MxcRequirement, UnsupportedAciAdapter,
};
use ::agent_protocol::service::{
    AuthenticateChannelRequest, CancelReason, ConfigureSessionRequest, CreateProcessRequest,
    FilesystemStatus, LaunchBinding, MxcControlService, ProcessSupervisor, ServiceError,
    ServiceErrorCode, SessionConfiguration, SupervisorEvent, WaitReadyRequest,
};
use ::agent_protocol::state::PROTOCOL_VERSION;
use ::serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementStatus {
    Pass,
    Fail,
    Blocked,
    NotImplemented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequirementResult {
    pub name: String,
    pub requirement: MxcRequirement,
    pub status: RequirementStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceReadiness {
    Ready,
    NotReady,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterState {
    pub kind: String,
    pub status: RequirementStatus,
    pub required_revision: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessReport {
    pub phase: String,
    pub service_readiness: ServiceReadiness,
    pub adapter: AdapterState,
    pub requirements: Vec<RequirementResult>,
}

fn launch_identity() -> LaunchIdentity {
    LaunchIdentity {
        generation: 7,
        nonce: [7; 16],
    }
}

fn launch_binding() -> LaunchBinding {
    LaunchBinding {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn session_configuration() -> SessionConfiguration {
    SessionConfiguration {
        root: CanonicalHostMappingRoot::parse("/sandbox".to_string()).expect("root"),
        mappings: vec![ChildMapping {
            child: RelativeChildPath::parse("runtime".to_string()).expect("child"),
            access: AccessMode::ReadOnly,
        }],
        containment: MappingContainmentPolicy {
            symlink_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
            reparse_policy: SymlinkContainmentPolicy::DeclaredForHostGuestEnforcement,
        },
        labels: vec!["runtime".to_string()],
        attributes: BTreeMap::from([("profile".to_string(), "mxc".to_string())]),
        filesystem: FilesystemStatus {
            rootfs_ready: true,
            detail: "sandbox layers mounted".to_string(),
        },
        network: NetworkStatus {
            mode: NetworkMode::PortableNetwork,
            detail: Some("10.0.0.2/24".to_string()),
        },
    }
}

fn wait_ready_request() -> WaitReadyRequest {
    WaitReadyRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
    }
}

fn configure_request(idempotent_replay: bool) -> ConfigureSessionRequest {
    ConfigureSessionRequest {
        protocol_version: PROTOCOL_VERSION,
        image_version: "mxc-prototype-v1".to_string(),
        launch: launch_identity(),
        channel_generation: 44,
        idempotent_replay,
        configuration: session_configuration(),
    }
}

fn authenticate(service: &mut MxcControlService) {
    service
        .authenticate_channel(
            AuthenticateChannelRequest {
                service: SERVICE_IDENTITY.to_string(),
                protocol_version: PROTOCOL_VERSION,
                launch: launch_identity(),
                channel_generation: 44,
                capability_proof: [7; 32],
            },
            1,
            session_configuration().network.clone(),
        )
        .expect("authenticate");
}

fn run_launch_bound_readiness() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let capabilities = service.get_capabilities();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");

    let wrong_nonce = WaitReadyRequest {
        launch: LaunchIdentity {
            generation: 7,
            nonce: [1; 16],
        },
        ..wait_ready_request()
    };
    let wrong_nonce_rejected = matches!(
        service.wait_ready(wrong_nonce).map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::LaunchNonceMismatch
    );
    let first = service.wait_ready(wait_ready_request());
    let second = service.wait_ready(wait_ready_request());
    let health = service.health();
    let unavailable_operations = capabilities
        .unavailable_operations
        .iter()
        .map(|entry| entry.operation.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let passed = wrong_nonce_rejected
        && capabilities.protocol_version == PROTOCOL_VERSION
        && capabilities.available_operations
            == vec![
                "GetCapabilities".to_string(),
                "AuthenticateChannel".to_string(),
                "ConfigureSession".to_string(),
                "WaitReady".to_string(),
                "Health".to_string(),
            ]
        && unavailable_operations
            == std::collections::BTreeSet::from([
                "Exec", "Streams", "Cancel", "Quiesce", "Resume", "Shutdown",
            ])
        && capabilities
            .unavailable_operations
            .iter()
            .all(|entry| !entry.capability_flag.is_empty() && !entry.reason.is_empty())
        && first.is_ok()
        && second.is_ok()
        && first == second
        && health.configured
        && health
            .filesystem
            .as_ref()
            .is_some_and(|status| status.rootfs_ready);
    RequirementResult {
        name: MxcRequirement::Ready.name().to_string(),
        requirement: MxcRequirement::Ready,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "WaitReady is launch-bound to nonce/version/channel generation and GetCapabilities truthfully reports the phase-0 operational slice.".to_string()
        } else {
            "WaitReady launch binding, level-trigger behavior, or capability truthfulness failed."
                .to_string()
        },
    }
}

fn run_immutable_configuration() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("first configure");
    let same_without_idempotent = service.configure_session(configure_request(false));
    let same_with_idempotent = service.configure_session(configure_request(true));
    let mut conflicting_request = configure_request(true);
    conflicting_request.configuration.filesystem.detail = "changed".to_string();
    let conflicting = service.configure_session(conflicting_request);
    let passed = matches!(
        same_without_idempotent.map(|_| ()),
        Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
    ) && same_with_idempotent.is_ok()
        && matches!(
            conflicting.map(|_| ()),
            Err(error) if error.code == ServiceErrorCode::ConfigurationConflict
        );
    RequirementResult {
        name: MxcRequirement::Bootstrap.name().to_string(),
        requirement: MxcRequirement::Bootstrap,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "ConfigureSession applies once; non-idempotent replay/conflict is rejected.".to_string()
        } else {
            "Immutable ConfigureSession rules failed.".to_string()
        },
    }
}

fn run_health_probe() -> RequirementResult {
    let mut service = MxcControlService::new(launch_binding());
    let before = service.health();
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");
    let after = service.health();
    let passed = !before.launch_admitted
        && !before.configured
        && after.launch_admitted
        && after.configured
        && after.network.is_some()
        && after.filesystem.is_some();
    RequirementResult {
        name: MxcRequirement::Probe.name().to_string(),
        requirement: MxcRequirement::Probe,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Health reports launch admission plus filesystem/network readiness snapshots."
                .to_string()
        } else {
            "Health readiness snapshot behavior failed.".to_string()
        },
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HarnessSupervisor {
    active_exec_id: Option<u32>,
    events: VecDeque<SupervisorEvent>,
    stdin_queue: Vec<Vec<u8>>,
    stdin_pending_bytes: usize,
    stdin_drained_bytes: usize,
    stdin_closed: bool,
    terminate_calls: usize,
}

impl ProcessSupervisor for HarnessSupervisor {
    fn spawn(&mut self, request: &CreateProcessRequest) -> Result<(), ServiceError> {
        self.active_exec_id = Some(request.exec_id);
        Ok(())
    }

    fn queue_stdin(&mut self, _exec_id: u32, chunk: Vec<u8>) -> Result<(), ServiceError> {
        self.stdin_pending_bytes = self.stdin_pending_bytes.saturating_add(chunk.len());
        self.stdin_queue.push(chunk);
        Ok(())
    }

    fn close_stdin(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        if self.stdin_pending_bytes != 0 {
            return Err(ServiceError {
                code: ServiceErrorCode::Backpressure,
                message: "stdin queue is not drained".to_string(),
            });
        }
        self.stdin_closed = true;
        Ok(())
    }

    fn take_stdin_drain_bytes(&mut self, _exec_id: u32) -> Result<usize, ServiceError> {
        let drained = self.stdin_drained_bytes;
        self.stdin_drained_bytes = 0;
        Ok(drained)
    }

    fn peek_event(&mut self, _exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        Ok(self.events.front().cloned())
    }

    fn ack_event(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        self.events.pop_front();
        Ok(())
    }

    fn terminate(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        self.terminate_calls = self.terminate_calls.saturating_add(1);
        Ok(())
    }

    fn kill(&mut self, _exec_id: u32) -> Result<(), ServiceError> {
        Ok(())
    }

    fn poll(&mut self, exec_id: u32) -> Result<Option<SupervisorEvent>, ServiceError> {
        let event = self.peek_event(exec_id)?;
        if event.is_some() {
            self.ack_event(exec_id)?;
        }
        Ok(event)
    }

    fn cleanup_for_disconnect(
        &mut self,
        _exec_id: u32,
        _deadline: ::std::time::Duration,
    ) -> Result<bool, ServiceError> {
        Ok(true)
    }
}

fn activated_service() -> MxcControlService {
    let mut service = MxcControlService::new_pid1_runtime(launch_binding(), 4242);
    authenticate(&mut service);
    service
        .configure_session(configure_request(false))
        .expect("configure");
    service.activate_full_lifecycle().expect("activate");
    service
}

fn drain_messages(
    service: &mut MxcControlService,
    supervisor: &mut HarnessSupervisor,
) -> Vec<agent_protocol::AgentControlMessage> {
    let mut out = Vec::new();
    for _ in 0..128 {
        let batch = service.pump_supervisor(supervisor).expect("pump");
        out.extend(batch);
        if supervisor.events.is_empty() && service.active_exec_id().is_none() {
            break;
        }
    }
    out
}

fn drain_one_stdin_chunk(supervisor: &mut HarnessSupervisor) {
    if let Some(chunk) = supervisor.stdin_queue.first() {
        let size = chunk.len();
        supervisor.stdin_queue.remove(0);
        supervisor.stdin_pending_bytes = supervisor.stdin_pending_bytes.saturating_sub(size);
        supervisor.stdin_drained_bytes = supervisor.stdin_drained_bytes.saturating_add(size);
    }
}

fn run_exec_sequencing() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = HarnessSupervisor::default();
    let mut sequential_ok = true;
    let mut saw_busy_rejection = false;

    for exec_id in [300_u32, 301_u32, 302_u32] {
        service
            .create_process(
                CreateProcessRequest {
                    exec_id,
                    argv: vec!["/bin/echo".to_string(), format!("exec-{exec_id}")],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            )
            .expect("create process");
        if exec_id == 300 {
            let busy = service.create_process(
                CreateProcessRequest {
                    exec_id: 399,
                    argv: vec!["/bin/echo".to_string(), "busy".to_string()],
                    cwd: Some("/".to_string()),
                    env: vec![],
                    timeout_ms: None,
                },
                &mut supervisor,
            );
            saw_busy_rejection = matches!(
                busy,
                Err(ServiceError {
                    code: ServiceErrorCode::LifecycleError,
                    ..
                })
            );
        }
        supervisor.events.push_back(SupervisorEvent::StdoutEof);
        supervisor.events.push_back(SupervisorEvent::StderrEof);
        supervisor
            .events
            .push_back(SupervisorEvent::DescendantsCleaned);
        supervisor.events.push_back(SupervisorEvent::Exited(0));
        let terminal_count = drain_messages(&mut service, &mut supervisor)
            .into_iter()
            .filter(|message| {
                matches!(
                    message,
                    agent_protocol::AgentControlMessage::ExecTerminal { .. }
                )
            })
            .count();
        if terminal_count != 1 {
            sequential_ok = false;
        }
    }

    let passed = sequential_ok && saw_busy_rejection;
    RequirementResult {
        name: MxcRequirement::ExecuteCommand.name().to_string(),
        requirement: MxcRequirement::ExecuteCommand,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "One active exec is enforced; concurrent create is rejected while allowing unlimited sequential unique execs.".to_string()
        } else {
            "Exec sequencing/busy rejection contract failed.".to_string()
        },
    }
}

fn run_binary_stream_separation() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = HarnessSupervisor::default();
    service
        .create_process(
            CreateProcessRequest {
                exec_id: 401,
                argv: vec!["/bin/cat".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        )
        .expect("create process");
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id: 401,
            stream: StreamName::Stdout,
            credits: 2,
        })
        .expect("stdout credit");
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id: 401,
            stream: StreamName::Stderr,
            credits: 2,
        })
        .expect("stderr credit");
    let stdout = vec![0, 1, 2, 0, 3, 255];
    let stderr = vec![7, 0, 8, 9, 0, 10];
    supervisor
        .events
        .push_back(SupervisorEvent::StdoutChunk(stdout.clone()));
    supervisor
        .events
        .push_back(SupervisorEvent::StderrChunk(stderr.clone()));
    supervisor.events.push_back(SupervisorEvent::StdoutEof);
    supervisor.events.push_back(SupervisorEvent::StderrEof);
    supervisor
        .events
        .push_back(SupervisorEvent::DescendantsCleaned);
    supervisor.events.push_back(SupervisorEvent::Exited(0));

    let mut saw_stdout = false;
    let mut saw_stderr = false;
    for message in drain_messages(&mut service, &mut supervisor) {
        match message {
            agent_protocol::AgentControlMessage::StdoutChunk(record) => {
                saw_stdout = record.chunk == stdout;
            }
            agent_protocol::AgentControlMessage::StderrChunk(record) => {
                saw_stderr = record.chunk == stderr;
            }
            _ => {}
        }
    }
    let passed = saw_stdout && saw_stderr;
    RequirementResult {
        name: MxcRequirement::InteractiveShell.name().to_string(),
        requirement: MxcRequirement::InteractiveShell,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Binary-safe stdout/stderr remain distinct and preserve arbitrary bytes including NUL."
                .to_string()
        } else {
            "Stdout/stderr separation or binary preservation failed.".to_string()
        },
    }
}

fn run_backpressure_contract() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = HarnessSupervisor::default();
    let exec_id = 501_u32;
    service
        .create_process(
            CreateProcessRequest {
                exec_id,
                argv: vec!["/bin/cat".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: None,
            },
            &mut supervisor,
        )
        .expect("create process");
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: StreamName::Stdin,
            credits: 4,
        })
        .expect("stdin credits");
    let max = agent_protocol::PROTOCOL_SAFE_STREAM_CHUNK_MAX_BYTES;
    let oversized = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id,
            sequence: 0,
            chunk: vec![1_u8; max + 1],
        },
        &mut supervisor,
    );
    let oversized_rejected = matches!(
        oversized,
        Err(ServiceError {
            code: ServiceErrorCode::StreamChunkTooLarge,
            ..
        })
    );
    service
        .stdin_chunk(
            agent_protocol::StdinChunkRecord {
                exec_id,
                sequence: 0,
                chunk: vec![2_u8; max],
            },
            &mut supervisor,
        )
        .expect("fill queue with one safe chunk");
    let saturated = service.stdin_chunk(
        agent_protocol::StdinChunkRecord {
            exec_id,
            sequence: 1,
            chunk: vec![3_u8; 1],
        },
        &mut supervisor,
    );
    let queue_saturated = matches!(
        saturated,
        Err(ServiceError {
            code: ServiceErrorCode::Backpressure,
            ..
        })
    );
    let health_responsive = service.health().configured;
    drain_one_stdin_chunk(&mut supervisor);
    service
        .stdin_chunk(
            agent_protocol::StdinChunkRecord {
                exec_id,
                sequence: 1,
                chunk: vec![3_u8; 1],
            },
            &mut supervisor,
        )
        .expect("retry after drain");
    let passed = oversized_rejected && queue_saturated && health_responsive;
    RequirementResult {
        name: MxcRequirement::StreamLogs.name().to_string(),
        requirement: MxcRequirement::StreamLogs,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "Chunk and queue bounds enforce deterministic backpressure with oversized input rejected before enqueue while control health remains responsive.".to_string()
        } else {
            "Backpressure/oversized-chunk contract failed.".to_string()
        },
    }
}

fn run_terminal_semantics() -> RequirementResult {
    let mut service = activated_service();
    let mut supervisor = HarnessSupervisor::default();
    let exec_id = 601_u32;
    service
        .create_process(
            CreateProcessRequest {
                exec_id,
                argv: vec!["/bin/sleep".to_string(), "10".to_string()],
                cwd: Some("/".to_string()),
                env: vec![],
                timeout_ms: Some(100),
            },
            &mut supervisor,
        )
        .expect("create process");
    service
        .cancel_exec(exec_id, CancelReason::TimedOut, &mut supervisor)
        .expect("cancel timed out");
    let terminated = supervisor.terminate_calls == 1;
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: StreamName::Stdout,
            credits: 1,
        })
        .expect("stdout credit");
    service
        .grant_flow_credits(FlowCreditRequest {
            exec_id,
            stream: StreamName::Stderr,
            credits: 1,
        })
        .expect("stderr credit");
    supervisor.events.push_back(SupervisorEvent::StdoutEof);
    supervisor.events.push_back(SupervisorEvent::StderrEof);
    supervisor
        .events
        .push_back(SupervisorEvent::DescendantsCleaned);
    supervisor.events.push_back(SupervisorEvent::Signaled(9));
    let messages = drain_messages(&mut service, &mut supervisor);
    let terminal_indices: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| {
            matches!(
                message,
                agent_protocol::AgentControlMessage::ExecTerminal { .. }
            )
            .then_some(index)
        })
        .collect();
    let descendants_index = messages
        .iter()
        .position(|message| {
            matches!(
                message,
                agent_protocol::AgentControlMessage::DescendantsCleaned { .. }
            )
        })
        .unwrap_or(usize::MAX);
    let passed = terminated
        && terminal_indices.len() == 1
        && descendants_index < terminal_indices[0]
        && matches!(
            messages[terminal_indices[0]],
            agent_protocol::AgentControlMessage::ExecTerminal {
                disposition: agent_protocol::ExecDisposition::TimedOut,
                ..
            }
        );
    RequirementResult {
        name: MxcRequirement::Signal.name().to_string(),
        requirement: MxcRequirement::Signal,
        status: if passed {
            RequirementStatus::Pass
        } else {
            RequirementStatus::Fail
        },
        reason: if passed {
            "EOF/cancel/timeout sequencing emits exactly one terminal event only after stream EOF and descendant cleanup.".to_string()
        } else {
            "Terminal ordering/uniqueness or timeout disposition contract failed.".to_string()
        },
    }
}

fn run_identity_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::WaitContainerExited.name().to_string(),
        requirement: MxcRequirement::WaitContainerExited,
        status: RequirementStatus::Blocked,
        reason:
            "Linux helper execution for uid/gid verification requires running the nvx-agent runtime/supervisor Linux path; blocked in this host-only harness binary."
                .to_string(),
    }
}

fn run_isolation_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::PrepareSnapshot.name().to_string(),
        requirement: MxcRequirement::PrepareSnapshot,
        status: RequirementStatus::Blocked,
        reason:
            "Namespace/capability/no_new_privs/root/orphan-reaping verification requires Linux helper process with namespace privileges; blocked here."
                .to_string(),
    }
}

fn run_mapping_install_verification() -> RequirementResult {
    RequirementResult {
        name: MxcRequirement::PostRestore.name().to_string(),
        requirement: MxcRequirement::PostRestore,
        status: RequirementStatus::Blocked,
        reason:
            "Mount-namespace mapping installation and readonly-hardening checks require Linux virtio-fs/mount privileges; blocked in this harness environment."
                .to_string(),
    }
}

fn unsupported_result(requirement: MxcRequirement) -> RequirementResult {
    RequirementResult {
        name: requirement.name().to_string(),
        requirement,
        status: RequirementStatus::NotImplemented,
        reason: "Operational slice intentionally excludes this runtime requirement.".to_string(),
    }
}

pub fn phase0_report() -> HarnessReport {
    let adapter = match UnsupportedAciAdapter::status() {
        AciAdapterStatus::Unsupported {
            required_revision,
            reason,
        } => AdapterState {
            kind: "aci".to_string(),
            status: RequirementStatus::Blocked,
            required_revision: required_revision.to_string(),
            reason: reason.to_string(),
        },
    };

    let readiness = run_launch_bound_readiness();
    let bootstrap = run_immutable_configuration();
    let probe = run_health_probe();
    let scenario3 = run_exec_sequencing();
    let scenario4 = run_binary_stream_separation();
    let scenario5 = run_backpressure_contract();
    let scenario6 = run_terminal_semantics();
    let scenario7 = run_identity_verification();
    let scenario8 = run_isolation_verification();
    let scenario9 = run_mapping_install_verification();

    let mut requirements = Vec::with_capacity(MODELED_REQUIREMENTS.len());
    for requirement in MODELED_REQUIREMENTS {
        if requirement == MxcRequirement::Ready {
            requirements.push(readiness.clone());
        } else if requirement == MxcRequirement::Bootstrap {
            requirements.push(bootstrap.clone());
        } else if requirement == MxcRequirement::ExecuteCommand {
            requirements.push(scenario3.clone());
        } else if requirement == MxcRequirement::InteractiveShell {
            requirements.push(scenario4.clone());
        } else if requirement == MxcRequirement::StreamLogs {
            requirements.push(scenario5.clone());
        } else if requirement == MxcRequirement::Signal {
            requirements.push(scenario6.clone());
        } else if requirement == MxcRequirement::WaitContainerExited {
            requirements.push(scenario7.clone());
        } else if requirement == MxcRequirement::Probe {
            requirements.push(probe.clone());
        } else if requirement == MxcRequirement::PrepareSnapshot {
            requirements.push(scenario8.clone());
        } else if requirement == MxcRequirement::PostRestore {
            requirements.push(scenario9.clone());
        } else {
            requirements.push(unsupported_result(requirement));
        }
    }

    let service_readiness = if requirements
        .iter()
        .any(|result| result.status != RequirementStatus::Pass)
    {
        ServiceReadiness::NotReady
    } else {
        ServiceReadiness::Ready
    };

    HarnessReport {
        phase: "phase0-operational-slice".to_string(),
        service_readiness,
        adapter,
        requirements,
    }
}

pub fn is_passing_report(report: &HarnessReport) -> bool {
    if report.service_readiness != ServiceReadiness::Ready {
        return false;
    }
    if report.requirements.len() != MODELED_REQUIREMENTS.len() {
        return false;
    }
    report
        .requirements
        .iter()
        .all(|result| result.status == RequirementStatus::Pass)
}

pub fn report_exit_code(report: &HarnessReport) -> ExitCode {
    if is_passing_report(report) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::std::collections::BTreeSet;

    #[test]
    fn phase0_report_has_exactly_twelve_named_results() {
        let report = phase0_report();
        assert_eq!(report.requirements.len(), 12);
        let names: BTreeSet<_> = report
            .requirements
            .iter()
            .map(|result| result.name.as_str())
            .collect();
        let expected_names: BTreeSet<_> = MODELED_REQUIREMENTS
            .iter()
            .map(|requirement| requirement.name())
            .collect();
        assert_eq!(names, expected_names);
    }

    #[test]
    fn phase0_report_remains_nonzero_until_all_requirements_pass() {
        let report = phase0_report();
        assert_eq!(report.service_readiness, ServiceReadiness::NotReady);
        assert_eq!(report_exit_code(&report), ExitCode::FAILURE);
    }

    #[test]
    fn harness_executes_real_launch_configure_and_probe_scenarios() {
        let report = phase0_report();
        let readiness = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Ready)
            .unwrap();
        assert_eq!(readiness.status, RequirementStatus::Pass);

        let bootstrap = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Bootstrap)
            .unwrap();
        assert_eq!(bootstrap.status, RequirementStatus::Pass);

        let probe = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Probe)
            .unwrap();
        assert_eq!(probe.status, RequirementStatus::Pass);

        let exec = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::ExecuteCommand)
            .unwrap();
        assert_eq!(exec.status, RequirementStatus::Pass);

        let streams = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::InteractiveShell)
            .unwrap();
        assert_eq!(streams.status, RequirementStatus::Pass);

        let backpressure = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::StreamLogs)
            .unwrap();
        assert_eq!(backpressure.status, RequirementStatus::Pass);

        let terminal = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::Signal)
            .unwrap();
        assert_eq!(terminal.status, RequirementStatus::Pass);

        let uid_gid = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::WaitContainerExited)
            .unwrap();
        assert_eq!(uid_gid.status, RequirementStatus::Blocked);

        let isolation = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::PrepareSnapshot)
            .unwrap();
        assert_eq!(isolation.status, RequirementStatus::Blocked);

        let mappings = report
            .requirements
            .iter()
            .find(|result| result.requirement == MxcRequirement::PostRestore)
            .unwrap();
        assert_eq!(mappings.status, RequirementStatus::Blocked);
    }
}
