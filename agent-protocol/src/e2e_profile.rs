// Copyright(c) The microvm authors.
// Licensed under the MIT License.

//! Low-overhead startup profiling shared by the VMM and guest agent.

use ::std::io::Write;
use ::std::sync::Mutex;
use ::std::sync::atomic::{AtomicBool, Ordering};
use ::std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum correlation identifier length accepted on a command line or profile line.
pub const MAX_CORRELATION_LEN: usize = 128;

/// Maximum guest records retained before a post-Ready flush.
const MAX_BUFFERED_RECORDS: usize = 256;

/// Process producing an E2E profile event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Component {
    /// The host-side NVX VMM.
    NvxVmm,
    /// The initramfs guest agent.
    NvxGuest,
}

impl Component {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NvxVmm => "nvx_vmm",
            Self::NvxGuest => "nvx_guest",
        }
    }
}

/// Timestamp origin for one process or guest run.
struct Profiler {
    component: Component,
    correlation: String,
    started: Instant,
    output: Output,
}

enum Output {
    Immediate,
    Buffered(Vec<String>),
}

impl Profiler {
    fn new(component: Component, correlation: &str, started: Instant) -> Self {
        let output = match component {
            Component::NvxVmm => Output::Immediate,
            Component::NvxGuest => Output::Buffered(Vec::with_capacity(MAX_BUFFERED_RECORDS)),
        };
        Self {
            component,
            correlation: correlation.to_string(),
            started,
            output,
        }
    }

    fn elapsed_us_at(&self, now: Instant) -> u128 {
        now.saturating_duration_since(self.started).as_micros()
    }

    fn record(
        &mut self,
        event: &str,
        now: Instant,
        unix_us: u128,
        duration: Option<Duration>,
    ) -> Option<String> {
        let line = format_line(
            self.component,
            event,
            &self.correlation,
            unix_us,
            self.elapsed_us_at(now),
            duration.map(|duration| duration.as_micros()),
        );
        match &mut self.output {
            Output::Immediate => Some(line),
            Output::Buffered(records) => {
                if records.len() < MAX_BUFFERED_RECORDS {
                    records.push(line);
                }
                None
            }
        }
    }

    fn drain_buffer(&mut self) -> Option<String> {
        let Output::Buffered(records) = &mut self.output else {
            return None;
        };
        if records.is_empty() {
            return None;
        }
        let capacity = records.iter().map(|line| line.len() + 1).sum();
        let mut batch = String::with_capacity(capacity);
        for line in records.drain(..) {
            batch.push_str(&line);
            batch.push('\n');
        }
        Some(batch)
    }

    fn flush_to(&mut self, writer: &mut impl Write) -> ::std::io::Result<()> {
        if let Some(batch) = self.drain_buffer() {
            writer.write_all(batch.as_bytes())?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct State {
    profiler: Option<Profiler>,
}

static STATE: Mutex<State> = Mutex::new(State { profiler: None });
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether `value` is safe in a command-line token and one-line profile record.
pub fn is_safe_correlation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CORRELATION_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Enables profiling with a process-relative monotonic origin.
pub fn enable(
    component: Component,
    correlation: &str,
    started: Instant,
) -> Result<(), &'static str> {
    if !is_safe_correlation(correlation) {
        return Err("profile correlation is not a safe identifier");
    }
    STATE
        .lock()
        .expect("E2E profiler state lock poisoned")
        .profiler = Some(Profiler::new(component, correlation, started));
    ENABLED.store(true, Ordering::Release);
    Ok(())
}

/// Clears state captured in a guest snapshot.
///
/// A restored guest has neither the current launch's correlation id nor a repaired wall clock.
/// Until a fresh out-of-band configuration mechanism exists, emitting nothing is safer than
/// attributing events to the snapshot creator or reporting its captured realtime value.
pub fn reset_for_restore() {
    ENABLED.store(false, Ordering::Release);
    STATE
        .lock()
        .expect("E2E profiler state lock poisoned")
        .profiler = None;
}

/// Emits an instantaneous event.
pub fn event(event: &'static str) {
    emit(event, None);
}

/// Emits a completed phase and its duration.
pub fn phase(event: &'static str, started: Instant) {
    emit(event, Some(started.elapsed()));
}

/// Emits a completed phase whose duration was measured inside another API.
pub fn duration(event: &'static str, duration: Duration) {
    emit(event, Some(duration));
}

/// Writes all buffered guest records as one newline-delimited stderr batch.
///
/// Immediate VMM profiling has nothing to flush. A disabled profiler returns without locking,
/// allocating, or writing.
pub fn flush() -> ::std::io::Result<()> {
    if !ENABLED.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut state = STATE.lock().expect("E2E profiler state lock poisoned");
    if let Some(profiler) = state.profiler.as_mut() {
        let stderr = ::std::io::stderr();
        let mut stderr = stderr.lock();
        profiler.flush_to(&mut stderr)?;
    }
    Ok(())
}

fn emit(event: &str, duration: Option<Duration>) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let now = Instant::now();
    let unix_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let line = {
        let mut state = STATE.lock().expect("E2E profiler state lock poisoned");
        record_event(state.profiler.as_mut(), event, now, unix_us, duration)
    };
    if let Some(line) = line {
        eprintln!("{line}");
    }
}

fn record_event(
    profiler: Option<&mut Profiler>,
    event: &str,
    now: Instant,
    unix_us: u128,
    duration: Option<Duration>,
) -> Option<String> {
    profiler.and_then(|profiler| profiler.record(event, now, unix_us, duration))
}

fn format_line(
    component: Component,
    event: &str,
    correlation: &str,
    unix_us: u128,
    elapsed_us: u128,
    duration_us: Option<u128>,
) -> String {
    let mut line = format!(
        "E2E_PROFILE component={} event={event} correlation={correlation} \
         unix_us={unix_us} elapsed_us={elapsed_us}",
        component.as_str()
    );
    if let Some(duration_us) = duration_us {
        line.push_str(&format!(" duration_us={duration_us}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_stable_profile_lines() {
        assert_eq!(
            format_line(
                Component::NvxVmm,
                "kernel_load_complete",
                "sandbox-123",
                1_700_000_000_000_123,
                42,
                None,
            ),
            "E2E_PROFILE component=nvx_vmm event=kernel_load_complete correlation=sandbox-123 \
             unix_us=1700000000000123 elapsed_us=42"
        );
        assert_eq!(
            format_line(
                Component::NvxGuest,
                "layer_mount_complete",
                "sandbox_456",
                1_700_000_000_000_456,
                900,
                Some(73),
            ),
            "E2E_PROFILE component=nvx_guest event=layer_mount_complete correlation=sandbox_456 \
             unix_us=1700000000000456 elapsed_us=900 duration_us=73"
        );
    }

    #[test]
    fn elapsed_time_is_monotonic() {
        let profiler = Profiler::new(Component::NvxGuest, "sandbox", Instant::now());
        let first = profiler.elapsed_us_at(Instant::now());
        ::std::thread::sleep(Duration::from_millis(2));
        let second = profiler.elapsed_us_at(Instant::now());

        assert!(second >= first);
    }

    #[test]
    fn disabled_profiler_formats_no_output() {
        assert!(
            record_event(
                None,
                "pid1_entry",
                Instant::now(),
                1_700_000_000_000_000,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn correlation_ids_are_command_line_safe() {
        assert!(is_safe_correlation("runtimeSandbox-0123_ab.cd"));
        assert!(!is_safe_correlation(""));
        assert!(!is_safe_correlation("sandbox id"));
        assert!(!is_safe_correlation("sandbox=other"));
        assert!(!is_safe_correlation(&"x".repeat(MAX_CORRELATION_LEN + 1)));
    }

    #[test]
    fn guest_records_are_buffered_until_flush_and_keep_order() {
        let started = Instant::now();
        let mut profiler = Profiler::new(Component::NvxGuest, "sandbox-123", started);
        let mut output = Vec::new();
        let first_at = started + Duration::from_micros(10);
        let second_at = started + Duration::from_micros(20);

        assert!(
            profiler
                .record("first_event", first_at, 1_000, None)
                .is_none()
        );
        assert!(
            profiler
                .record(
                    "second_event",
                    second_at,
                    2_000,
                    Some(Duration::from_micros(7)),
                )
                .is_none()
        );
        assert!(output.is_empty());
        profiler.flush_to(&mut output).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "E2E_PROFILE component=nvx_guest event=first_event correlation=sandbox-123 \
             unix_us=1000 elapsed_us=10\n\
             E2E_PROFILE component=nvx_guest event=second_event correlation=sandbox-123 \
             unix_us=2000 elapsed_us=20 duration_us=7\n"
        );
        assert!(profiler.drain_buffer().is_none());
    }

    #[test]
    fn vmm_records_remain_immediate() {
        let started = Instant::now();
        let mut profiler = Profiler::new(Component::NvxVmm, "sandbox", started);

        assert_eq!(
            profiler.record("vm_event", started, 123, None).unwrap(),
            "E2E_PROFILE component=nvx_vmm event=vm_event correlation=sandbox \
             unix_us=123 elapsed_us=0"
        );
        assert!(profiler.drain_buffer().is_none());
    }

    #[test]
    fn guest_buffer_is_bounded() {
        let started = Instant::now();
        let mut profiler = Profiler::new(Component::NvxGuest, "sandbox", started);
        for index in 0..=MAX_BUFFERED_RECORDS {
            assert!(
                profiler
                    .record("event", started, index as u128, None)
                    .is_none()
            );
        }
        let batch = profiler.drain_buffer().unwrap();

        assert_eq!(batch.lines().count(), MAX_BUFFERED_RECORDS);
    }
}
