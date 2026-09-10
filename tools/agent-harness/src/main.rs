use std::path::PathBuf;
use std::process::ExitCode;

use agent_harness::{HarnessBackend, HarnessMode, HarnessOptions, execute_harness};

fn print_usage() {
    eprintln!(
        "usage: agent-harness --backend whp [--static-only] [--output-dir <path>] [--openvmm-exe <path>] [--kernel <path>] [--mxc-initramfs <path>] [--common-root <path>]"
    );
    eprintln!(
        "  --static-only runs validation/static checks only; canonical WHP conformance remains non-passing by design"
    );
}

fn parse_args() -> Result<HarnessOptions, String> {
    let mut backend: Option<HarnessBackend> = None;
    let mut mode = HarnessMode::LiveWhp;
    let mut output_dir = PathBuf::from("build").join("mxc-agent-harness");
    let mut launch_overrides = agent_harness::launch::LaunchOverrides::default();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--backend" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--backend requires a value".to_string())?;
                backend = Some(HarnessBackend::parse(&value)?);
            }
            "--static-only" => mode = HarnessMode::StaticOnly,
            "--output-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-dir requires a value".to_string())?;
                output_dir = PathBuf::from(value);
            }
            "--openvmm-exe" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--openvmm-exe requires a value".to_string())?;
                launch_overrides.openvmm_exe = Some(PathBuf::from(value));
            }
            "--kernel" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--kernel requires a value".to_string())?;
                launch_overrides.kernel = Some(PathBuf::from(value));
            }
            "--mxc-initramfs" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--mxc-initramfs requires a value".to_string())?;
                launch_overrides.mxc_initramfs = Some(PathBuf::from(value));
            }
            "--common-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--common-root requires a value".to_string())?;
                launch_overrides.common_root = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(HarnessOptions {
        backend: backend.ok_or_else(|| "--backend is required".to_string())?,
        mode,
        output_dir,
        launch_overrides: Some(launch_overrides),
    })
}

fn print_summary(run: &agent_harness::HarnessRun) {
    println!(
        "mode={:?} backend={} platform={} report={}",
        run.report.mode,
        run.report.backend,
        run.report.platform,
        run.report_path.display()
    );
    for scenario in &run.report.scenarios {
        let conformance = format!("{:?}", scenario.status);
        let check = format!("{:?}", scenario.check_status);
        let evidence = format!("{:?}", scenario.evidence_source);
        let required = format!("{:?}", scenario.required_evidence_source);
        println!(
            "req{:02} {:<36} conformance={:<9} check={:<7} evidence={:<20} required={} {}",
            scenario.requirement_number,
            scenario.id,
            conformance,
            check,
            evidence,
            required,
            scenario.error.as_deref().unwrap_or("ok"),
        );
    }
}

fn main() -> ExitCode {
    let options = match parse_args() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match execute_harness(options) {
        Ok(run) => {
            print_summary(&run);
            run.exit_code()
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
