//! Host TSC probe for NVX time ABI host qualification.
//!
//! `nvx.py doctor` builds this file with `rustc` and runs it for the host
//! checks of doc/design/time-abi.md: H2 (the CPU identity and the host's
//! invariant-TSC bit), H4 (the TSC rate against host monotonic time), and H5
//! (cross-CPU TSC skew between pinned threads). It has no dependencies and
//! prints `NVX-HOST-TIME-PROBE` lines of `key=value` fields; the doctor
//! applies the bounds.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PREFIX: &str = "NVX-HOST-TIME-PROBE";
const STALL: Duration = Duration::from_secs(2);
const EXIT_USAGE: u8 = 2;
const EXIT_ERROR: u8 = 3;

#[inline(always)]
fn tsc() -> u64 {
    // SAFETY: LFENCE and RDTSC are baseline x86-64 instructions.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let value = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        value
    }
}

fn cpuid(leaf: u32) -> [u32; 4] {
    // SAFETY: CPUID is a baseline x86-64 instruction. Newer Rust releases
    // declare the intrinsic safe, older ones unsafe.
    #[allow(unused_unsafe)]
    let result = unsafe { core::arch::x86_64::__cpuid_count(leaf, 0) };
    [result.eax, result.ebx, result.ecx, result.edx]
}

#[cfg(target_os = "linux")]
mod affinity {
    const SET_BYTES: usize = 128;

    unsafe extern "C" {
        fn sched_setaffinity(pid: i32, size: usize, mask: *const u8) -> i32;
        fn sched_getaffinity(pid: i32, size: usize, mask: *mut u8) -> i32;
    }

    pub fn allowed() -> Result<Vec<usize>, String> {
        let mut mask = [0u8; SET_BYTES];
        // SAFETY: the mask buffer holds SET_BYTES bytes.
        if unsafe { sched_getaffinity(0, SET_BYTES, mask.as_mut_ptr()) } != 0 {
            return Err(format!(
                "sched_getaffinity failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok((0..SET_BYTES * 8)
            .filter(|cpu| mask[cpu / 8] & (1 << (cpu % 8)) != 0)
            .collect())
    }

    /// Pins the calling thread to one CPU.
    pub fn pin(cpu: usize) -> Result<(), String> {
        if cpu >= SET_BYTES * 8 {
            return Err(format!("CPU {cpu} is out of range"));
        }
        let mut mask = [0u8; SET_BYTES];
        mask[cpu / 8] |= 1 << (cpu % 8);
        // SAFETY: pid 0 selects the calling thread; the mask holds SET_BYTES.
        if unsafe { sched_setaffinity(0, SET_BYTES, mask.as_ptr()) } != 0 {
            return Err(format!(
                "cannot pin to CPU {cpu}: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::thread::yield_now();
        Ok(())
    }
}

#[cfg(windows)]
mod affinity {
    type Handle = *mut core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThread() -> Handle;
        fn GetCurrentProcess() -> Handle;
        fn SetThreadAffinityMask(thread: Handle, mask: usize) -> usize;
        fn GetProcessAffinityMask(process: Handle, process_mask: *mut usize, system_mask: *mut usize) -> i32;
    }

    pub fn allowed() -> Result<Vec<usize>, String> {
        let mut process = 0usize;
        let mut system = 0usize;
        // SAFETY: both outputs point to valid usize values.
        if unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process, &mut system) } == 0 {
            return Err(format!(
                "GetProcessAffinityMask failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok((0..usize::BITS as usize)
            .filter(|cpu| process & (1usize << cpu) != 0)
            .collect())
    }

    /// Pins the calling thread to one CPU of the process's processor group.
    pub fn pin(cpu: usize) -> Result<(), String> {
        if cpu >= usize::BITS as usize {
            return Err(format!("CPU {cpu} is out of range"));
        }
        // SAFETY: GetCurrentThread returns a pseudo-handle for this thread.
        if unsafe { SetThreadAffinityMask(GetCurrentThread(), 1usize << cpu) } == 0 {
            return Err(format!(
                "cannot pin to CPU {cpu}: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::thread::yield_now();
        Ok(())
    }
}

fn option<'a>(arguments: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    let mut value = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == name {
            let next = arguments
                .get(index + 1)
                .ok_or_else(|| format!("{name} requires a value"))?;
            value = Some(next.as_str());
            index += 2;
        } else if arguments[index].starts_with("--") {
            index += 2;
        } else {
            return Err(format!("unexpected argument {}", arguments[index]));
        }
    }
    Ok(value)
}

fn number<T: std::str::FromStr>(arguments: &[String], name: &str, default: T) -> Result<T, String> {
    match option(arguments, name)? {
        Some(text) => text
            .parse()
            .map_err(|_| format!("{name} has an invalid value {text:?}")),
        None => Ok(default),
    }
}

fn check_options(arguments: &[String], known: &[&str]) -> Result<(), String> {
    for argument in arguments.iter().step_by(2) {
        if !known.contains(&argument.as_str()) {
            return Err(format!("unknown option {argument}"));
        }
    }
    Ok(())
}

fn parse_cpus(text: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for part in text.split(',') {
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (start, end),
            None => (part, part),
        };
        let start: usize = start.parse().map_err(|_| format!("invalid CPU list {text:?}"))?;
        let end: usize = end.parse().map_err(|_| format!("invalid CPU list {text:?}"))?;
        if end < start {
            return Err(format!("invalid CPU range {part:?}"));
        }
        cpus.extend(start..=end);
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

fn format_cpus(cpus: &[usize]) -> String {
    let mut parts = Vec::new();
    let mut index = 0;
    while index < cpus.len() {
        let start = cpus[index];
        let mut end = start;
        while index + 1 < cpus.len() && cpus[index + 1] == end + 1 {
            index += 1;
            end = cpus[index];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        index += 1;
    }
    parts.join(",")
}

fn cpu() -> Result<(), String> {
    let [max_basic, ebx, ecx, edx] = cpuid(0);
    let mut vendor = Vec::new();
    for register in [ebx, edx, ecx] {
        vendor.extend_from_slice(&register.to_le_bytes());
    }
    let [signature, _, features_ecx, _] = if max_basic >= 1 { cpuid(1) } else { [0; 4] };
    let base_family = (signature >> 8) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((signature >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        ((signature >> 4) & 0xf) | (((signature >> 16) & 0xf) << 4)
    } else {
        (signature >> 4) & 0xf
    };
    let max_extended = cpuid(0x8000_0000)[0];
    let invariant_tsc = max_extended >= 0x8000_0007 && (cpuid(0x8000_0007)[3] >> 8) & 1 == 1;
    let mut brand = Vec::new();
    if max_extended >= 0x8000_0004 {
        for leaf in 0x8000_0002..=0x8000_0004 {
            for register in cpuid(leaf) {
                brand.extend_from_slice(&register.to_le_bytes());
            }
        }
    }
    let brand: String = String::from_utf8_lossy(&brand)
        .trim_matches(char::from(0))
        .trim()
        .replace(' ', "_");
    println!(
        "{PREFIX} cpu vendor={} family={family} model={model} stepping={} signature=0x{signature:08x} \
         invariant_tsc={} hypervisor={} brand={brand}",
        String::from_utf8_lossy(&vendor),
        signature & 0xf,
        u8::from(invariant_tsc),
        (features_ecx >> 31) & 1,
    );
    Ok(())
}

/// Pairs a TSC reading with host monotonic time; returns the narrowest of
/// several brackets as (TSC at the midpoint, instant, bracket width).
fn paired_sample() -> (u64, Instant, u64) {
    let mut best: Option<(u64, Instant, u64)> = None;
    for _ in 0..64 {
        let before = tsc();
        let now = Instant::now();
        let after = tsc();
        let width = after.wrapping_sub(before);
        if best.is_none_or(|(_, _, narrowest)| width < narrowest) {
            best = Some((before.wrapping_add(width / 2), now, width));
        }
    }
    best.expect("at least one sample")
}

fn rate(arguments: &[String]) -> Result<(), String> {
    check_options(arguments, &["--measure-ms", "--count"])?;
    let measure_ms: u64 = number(arguments, "--measure-ms", 1000)?;
    let count: u32 = number(arguments, "--count", 2)?;
    if measure_ms == 0 || count == 0 {
        return Err("--measure-ms and --count must be positive".into());
    }
    // One CPU's TSC against host monotonic time; cross-CPU skew is H5's.
    let first = *affinity::allowed()?.first().ok_or("no CPU is allowed")?;
    affinity::pin(first)?;
    for index in 1..=count {
        let (start_tsc, start, start_width) = paired_sample();
        thread::sleep(Duration::from_millis(measure_ms));
        let (end_tsc, end, end_width) = paired_sample();
        let elapsed_ns = end.duration_since(start).as_nanos();
        let cycles = end_tsc.wrapping_sub(start_tsc);
        let hz = cycles as f64 * 1e9 / elapsed_ns as f64;
        println!(
            "{PREFIX} rate index={index} cpu={first} tsc_hz={hz:.3} elapsed_ns={elapsed_ns} \
             cycles={cycles} bracket_cycles={}",
            start_width.max(end_width),
        );
    }
    Ok(())
}

struct Shared {
    sequence: AtomicU64,
    responder_tsc: AtomicU64,
    ready: AtomicBool,
    stop: AtomicBool,
}

struct Pair {
    rounds: u64,
    offset_cycles: f64,
    uncertainty_cycles: f64,
    min_rtt_cycles: u64,
    consistent: bool,
    stalled: bool,
}

impl Pair {
    fn stalled(rounds: u64) -> Self {
        Pair {
            rounds,
            offset_cycles: 0.0,
            uncertainty_cycles: 0.0,
            min_rtt_cycles: 0,
            consistent: false,
            stalled: true,
        }
    }
}

/// Answers ping-pong rounds on CPU `cpu` until the initiator stops.
fn respond(shared: &Shared, cpu: usize) -> Result<(), String> {
    affinity::pin(cpu)?;
    shared.ready.store(true, Ordering::Release);
    let mut expected = 1u64;
    loop {
        while shared.sequence.load(Ordering::Acquire) != expected {
            if shared.stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::hint::spin_loop();
        }
        shared.responder_tsc.store(tsc(), Ordering::Relaxed);
        shared.sequence.store(expected + 1, Ordering::Release);
        expected += 2;
    }
}

/// Spins until `done` returns true; false if `STALL` passed first.
fn spin_until(mut done: impl FnMut() -> bool) -> bool {
    let mut spins = 0u32;
    let mut started: Option<Instant> = None;
    while !done() {
        spins = spins.wrapping_add(1);
        if spins & 0xffff == 0 && started.get_or_insert_with(Instant::now).elapsed() > STALL {
            return false;
        }
        std::hint::spin_loop();
    }
    true
}

/// Estimates the responder's TSC offset from CPU `cpu`. Each round bounds it
/// to [t2 - t3, t2 - t1]; consistent rounds intersect to a tight interval,
/// otherwise the minimum round trip gives the estimate.
fn initiate(shared: &Shared, cpu: usize, duration: Duration) -> Result<Pair, String> {
    affinity::pin(cpu)?;
    if !spin_until(|| shared.ready.load(Ordering::Acquire)) {
        return Ok(Pair::stalled(0));
    }
    let deadline = Instant::now() + duration;
    let mut sequence = 1u64;
    let mut rounds = 0u64;
    let mut lower = i128::MIN;
    let mut upper = i128::MAX;
    let mut min_rtt = u64::MAX;
    let mut min_rtt_offset = 0.0;
    loop {
        let t1 = tsc();
        shared.sequence.store(sequence, Ordering::Release);
        if !spin_until(|| shared.sequence.load(Ordering::Acquire) == sequence + 1) {
            return Ok(Pair::stalled(rounds));
        }
        let t3 = tsc();
        let t2 = shared.responder_tsc.load(Ordering::Relaxed);
        sequence += 2;
        rounds += 1;
        let (t1, t2, t3) = (i128::from(t1), i128::from(t2), i128::from(t3));
        lower = lower.max(t2 - t3);
        upper = upper.min(t2 - t1);
        let rtt = (t3 - t1) as u64;
        if rtt < min_rtt {
            min_rtt = rtt;
            min_rtt_offset = (2 * t2 - t1 - t3) as f64 / 2.0;
        }
        if rounds % 256 == 0 && Instant::now() >= deadline {
            break;
        }
    }
    let consistent = lower <= upper;
    let (offset_cycles, uncertainty_cycles) = if consistent {
        ((lower + upper) as f64 / 2.0, (upper - lower) as f64 / 2.0)
    } else {
        (min_rtt_offset, min_rtt as f64 / 2.0)
    };
    Ok(Pair {
        rounds,
        offset_cycles,
        uncertainty_cycles,
        min_rtt_cycles: min_rtt,
        consistent,
        stalled: false,
    })
}

fn measure_pair(initiator: usize, responder: usize, duration: Duration) -> Result<Pair, String> {
    let shared = Arc::new(Shared {
        sequence: AtomicU64::new(0),
        responder_tsc: AtomicU64::new(0),
        ready: AtomicBool::new(false),
        stop: AtomicBool::new(false),
    });
    let peer = Arc::clone(&shared);
    let handle = thread::spawn(move || respond(&peer, responder));
    let result = initiate(&shared, initiator, duration);
    shared.stop.store(true, Ordering::Relaxed);
    handle
        .join()
        .map_err(|_| String::from("the responder thread panicked"))??;
    result
}

fn skew(arguments: &[String]) -> Result<(), String> {
    check_options(arguments, &["--duration-ms", "--cpus", "--tsc-hz", "--bound-ns"])?;
    let duration_ms: u64 = number(arguments, "--duration-ms", 5)?;
    let bound_ns: f64 = number(arguments, "--bound-ns", 1000.0)?;
    let allowed = affinity::allowed()?;
    let cpus = match option(arguments, "--cpus")? {
        Some(text) => parse_cpus(text)?,
        None => allowed.clone(),
    };
    if let Some(cpu) = cpus.iter().find(|cpu| !allowed.contains(cpu)) {
        return Err(format!("CPU {cpu} is not in the process affinity mask"));
    }
    let tsc_hz = match option(arguments, "--tsc-hz")? {
        Some(text) => text
            .parse::<f64>()
            .map_err(|_| format!("--tsc-hz has an invalid value {text:?}"))?,
        None => {
            affinity::pin(cpus[0])?;
            let (start_tsc, start, _) = paired_sample();
            thread::sleep(Duration::from_millis(100));
            let (end_tsc, end, _) = paired_sample();
            end_tsc.wrapping_sub(start_tsc) as f64 * 1e9 / end.duration_since(start).as_nanos() as f64
        }
    };
    let to_ns = |cycles: f64| cycles * 1e9 / tsc_hz;
    let duration = Duration::from_millis(duration_ms.max(1));
    let mut pairs = 0;
    let mut stalled = 0;
    let mut inconsistent = 0;
    let mut max_offset = 0.0f64;
    let mut max_uncertainty = 0.0f64;
    for (index, &first) in cpus.iter().enumerate() {
        for &second in &cpus[index + 1..] {
            let pair = measure_pair(first, second, duration)?;
            pairs += 1;
            if pair.stalled {
                stalled += 1;
                println!("{PREFIX} pair cpus={first}-{second} rounds={} stalled=1", pair.rounds);
                continue;
            }
            inconsistent += usize::from(!pair.consistent);
            max_offset = max_offset.max(to_ns(pair.offset_cycles).abs());
            max_uncertainty = max_uncertainty.max(to_ns(pair.uncertainty_cycles));
            println!(
                "{PREFIX} pair cpus={first}-{second} rounds={} offset_ns={:.1} uncertainty_ns={:.1} \
                 min_rtt_ns={:.1} consistent={} stalled=0",
                pair.rounds,
                to_ns(pair.offset_cycles),
                to_ns(pair.uncertainty_cycles),
                to_ns(pair.min_rtt_cycles as f64),
                u8::from(pair.consistent),
            );
        }
    }
    let conclusive = stalled == 0 && max_uncertainty < bound_ns;
    println!(
        "{PREFIX} skew pairs={pairs} cpus={} max_abs_offset_ns={:.0} max_uncertainty_ns={:.0} \
         stalled_pairs={stalled} inconsistent_pairs={inconsistent} duration_ms={duration_ms} \
         tsc_hz={tsc_hz:.0} conclusive={}",
        format_cpus(&cpus),
        max_offset.round(),
        max_uncertainty.round(),
        u8::from(conclusive),
    );
    Ok(())
}

fn usage() -> String {
    format!(
        "usage: {} cpu\n       {} rate [--measure-ms N] [--count K]\n       \
         {} skew [--duration-ms N] [--cpus LIST] [--tsc-hz HZ] [--bound-ns N]",
        "nvx-host-time-probe", "nvx-host-time-probe", "nvx-host-time-probe"
    )
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        eprintln!("{}", usage());
        return ExitCode::from(EXIT_USAGE);
    };
    let options = &arguments[1..];
    let result = match command.as_str() {
        "cpu" if options.is_empty() => cpu(),
        "rate" => rate(options),
        "skew" => skew(options),
        _ => {
            eprintln!("{}", usage());
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nvx-host-time-probe: {error}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
