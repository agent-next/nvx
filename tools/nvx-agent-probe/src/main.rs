use std::io::{Read, Write};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(std::io::stderr(), "nvx-agent-probe error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Err("missing subcommand".to_string());
    };
    match command.as_str() {
        "seq" => run_seq(args.collect()),
        "stream-split" => run_stream_split(),
        "stdin-roundtrip" => run_stdin_roundtrip(),
        "flood" => run_flood(args.collect()),
        "wait-stdin-eof" => run_wait_stdin_eof(),
        "signal-self" => run_signal_self(args.collect()),
        "spawn-tree" => run_spawn_tree(args.collect()),
        "check-pids-gone" => run_check_pids_gone(args.collect()),
        "child-loop" => run_child_loop(args.collect()),
        "grandchild-loop" => run_grandchild_loop(args.collect()),
        other => Err(format!("unknown subcommand {other:?}")),
    }
}

fn run_seq(args: Vec<String>) -> Result<()> {
    let mut token = "default".to_string();
    let mut exit_code = 0_i32;
    let mut sleep_ms = 0_u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--token" => {
                token = required_value(&args, index + 1, "--token")?.to_string();
                index += 2;
            }
            "--exit" => {
                exit_code = required_value(&args, index + 1, "--exit")?
                    .parse::<i32>()
                    .map_err(|error| format!("invalid --exit value: {error}"))?;
                index += 2;
            }
            "--sleep-ms" => {
                sleep_ms = required_value(&args, index + 1, "--sleep-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --sleep-ms value: {error}"))?;
                index += 2;
            }
            flag => return Err(format!("unknown seq flag {flag:?}")),
        }
    }
    if sleep_ms > 0 {
        thread::sleep(Duration::from_millis(sleep_ms));
    }
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    stdout
        .write_all(format!("seq:{token}\n").as_bytes())
        .map_err(|error| format!("writing stdout: {error}"))?;
    stderr
        .write_all(format!("seq-err:{token}\n").as_bytes())
        .map_err(|error| format!("writing stderr: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    stderr
        .flush()
        .map_err(|error| format!("flushing stderr: {error}"))?;
    process::exit(exit_code);
}

fn run_stream_split() -> Result<()> {
    let stdout_bytes = [b'A', 0, b'B', 0xff, b'C'];
    let stderr_bytes = [b'X', 0, b'Y', 0xfe, b'Z'];
    std::io::stdout()
        .write_all(&stdout_bytes)
        .map_err(|error| format!("writing stdout: {error}"))?;
    std::io::stderr()
        .write_all(&stderr_bytes)
        .map_err(|error| format!("writing stderr: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    std::io::stderr()
        .flush()
        .map_err(|error| format!("flushing stderr: {error}"))?;
    Ok(())
}

fn run_stdin_roundtrip() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|error| format!("reading stdin: {error}"))?;
    std::io::stdout()
        .write_all(&input)
        .map_err(|error| format!("writing stdout: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))?;
    Ok(())
}

fn run_flood(args: Vec<String>) -> Result<()> {
    let mut total = 0_usize;
    let mut chunk = 4096_usize;
    let mut stream = "stdout";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bytes" => {
                total = required_value(&args, index + 1, "--bytes")?
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --bytes value: {error}"))?;
                index += 2;
            }
            "--chunk" => {
                chunk = required_value(&args, index + 1, "--chunk")?
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --chunk value: {error}"))?;
                index += 2;
            }
            "--stream" => {
                stream = required_value(&args, index + 1, "--stream")?;
                index += 2;
            }
            flag => return Err(format!("unknown flood flag {flag:?}")),
        }
    }
    if total == 0 || chunk == 0 {
        return Err("flood requires --bytes > 0 and --chunk > 0".to_string());
    }
    let mut sent = 0_usize;
    let mut pattern_index = 0_u8;
    let mut writer: Box<dyn Write> = match stream {
        "stdout" => Box::new(std::io::stdout().lock()),
        "stderr" => Box::new(std::io::stderr().lock()),
        other => return Err(format!("unsupported --stream value {other:?}")),
    };
    while sent < total {
        let take = chunk.min(total - sent);
        let mut buffer = vec![0_u8; take];
        for byte in &mut buffer {
            *byte = pattern_index;
            pattern_index = pattern_index.wrapping_add(1);
        }
        writer
            .write_all(&buffer)
            .map_err(|error| format!("writing flood bytes: {error}"))?;
        sent += take;
    }
    writer
        .flush()
        .map_err(|error| format!("flushing flood bytes: {error}"))?;
    Ok(())
}

fn run_wait_stdin_eof() -> Result<()> {
    let mut sink = Vec::new();
    std::io::stdin()
        .read_to_end(&mut sink)
        .map_err(|error| format!("reading stdin to EOF: {error}"))?;
    std::io::stdout()
        .write_all(b"stdin-eof-observed\n")
        .map_err(|error| format!("writing EOF marker: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing EOF marker: {error}"))?;
    Ok(())
}

fn run_signal_self(args: Vec<String>) -> Result<()> {
    if args.len() != 2 || args[0] != "--signal" {
        return Err("signal-self requires --signal <number>".to_string());
    }
    let signal = args[1]
        .parse::<i32>()
        .map_err(|error| format!("invalid signal value: {error}"))?;
    // SAFETY: raising a caller-provided signal on this process.
    let rc = unsafe { libc::raise(signal) };
    if rc != 0 {
        return Err(format!("raise({signal}) failed with {rc}"));
    }
    Ok(())
}

fn run_spawn_tree(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            flag => return Err(format!("unknown spawn-tree flag {flag:?}")),
        }
    }
    let exe = std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))?;
    let mut child = Command::new(&exe)
        .arg("child-loop")
        .arg("--hold-ms")
        .arg(hold_ms.to_string())
        .arg(if ignore_term {
            "--ignore-term"
        } else {
            "--respect-term"
        })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("spawning child-loop failed: {error}"))?;
    let child_pid = child.id();
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child-loop stdout was unavailable".to_string())?;
    let mut reader = std::io::BufReader::new(child_stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line)
        .map_err(|error| format!("reading child-loop pid line failed: {error}"))?;
    if line.trim().is_empty() {
        return Err("child-loop did not publish grandchild pid".to_string());
    }
    let grandchild_pid = parse_keyed_u32(&line, "grandchild")
        .ok_or_else(|| format!("invalid child-loop pid line: {:?}", line.trim_end()))?;
    let parent_pid = process::id();
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "tree parent={parent_pid} child={child_pid} grandchild={grandchild_pid}"
    )
    .map_err(|error| format!("writing tree line failed: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing tree line failed: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    Ok(())
}

fn run_child_loop(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            "--respect-term" => {
                index += 1;
            }
            flag => return Err(format!("unknown child-loop flag {flag:?}")),
        }
    }
    if ignore_term {
        // SAFETY: process-global handler set for this helper process only.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    }
    let exe = std::env::current_exe().map_err(|error| format!("current_exe failed: {error}"))?;
    let mut grandchild = Command::new(&exe)
        .arg("grandchild-loop")
        .arg("--hold-ms")
        .arg(hold_ms.to_string())
        .arg(if ignore_term {
            "--ignore-term"
        } else {
            "--respect-term"
        })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawning grandchild-loop failed: {error}"))?;
    let pid = process::id();
    let grandchild_pid = grandchild.id();
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "child={pid} grandchild={grandchild_pid}")
        .map_err(|error| format!("writing child line failed: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing child line failed: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = grandchild.wait();
    Ok(())
}

fn run_grandchild_loop(args: Vec<String>) -> Result<()> {
    let mut hold_ms = 30_000_u64;
    let mut ignore_term = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hold-ms" => {
                hold_ms = required_value(&args, index + 1, "--hold-ms")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --hold-ms value: {error}"))?;
                index += 2;
            }
            "--ignore-term" => {
                ignore_term = true;
                index += 1;
            }
            "--respect-term" => {
                index += 1;
            }
            flag => return Err(format!("unknown grandchild-loop flag {flag:?}")),
        }
    }
    if ignore_term {
        // SAFETY: process-global handler set for this helper process only.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(hold_ms))
        .ok_or_else(|| "hold-ms deadline overflowed".to_string())?;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn run_check_pids_gone(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        return Err("check-pids-gone requires one or more pid values".to_string());
    }
    for raw in &args {
        let pid = raw
            .parse::<u32>()
            .map_err(|error| format!("invalid pid {raw:?}: {error}"))?;
        let probe = format!("/proc/{pid}");
        if std::path::Path::new(&probe).exists() {
            return Err(format!("pid {pid} is still alive"));
        }
    }
    std::io::stdout()
        .write_all(b"pids-gone\n")
        .map_err(|error| format!("writing pid check output failed: {error}"))?;
    std::io::stdout()
        .flush()
        .map_err(|error| format!("flushing pid check output failed: {error}"))?;
    Ok(())
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_keyed_u32(input: &str, key: &str) -> Option<u32> {
    input
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&format!("{key}=")))
        .and_then(|value| value.parse::<u32>().ok())
}
