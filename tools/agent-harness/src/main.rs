use std::path::PathBuf;
use std::process::ExitCode;

use agent_harness::mxc_policy::{PolicyHarnessMode, PolicyHarnessOptions, execute_policy_harness};
use agent_harness::{HarnessBackend, HarnessMode, HarnessOptions, execute_harness};

fn print_usage() {
    eprintln!("usage:");
    eprintln!(
        "  agent-harness [conformance] --backend whp [--static-only] [--output-dir <path>] [artifact overrides]"
    );
    eprintln!(
        "  agent-harness mxc-policy --backend whp [--config <json>] [--execute-config] [--static-only] [--output-dir <path>] [artifact overrides]"
    );
}

struct ParsedCommon {
    backend: HarnessBackend,
    static_only: bool,
    output_dir: PathBuf,
    launch_overrides: agent_harness::launch::LaunchOverrides,
    config: Option<PathBuf>,
    execute_config: bool,
}

fn parse_common(
    arguments: impl IntoIterator<Item = String>,
    default_output: PathBuf,
) -> Result<ParsedCommon, String> {
    let mut backend = None;
    let mut static_only = false;
    let mut output_dir = default_output;
    let mut launch_overrides = agent_harness::launch::LaunchOverrides::default();
    let mut config = None;
    let mut execute_config = false;
    let mut args = arguments.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--backend" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--backend requires a value".to_string())?;
                backend = Some(HarnessBackend::parse(&value)?);
            }
            "--static-only" => static_only = true,
            "--output-dir" => {
                output_dir = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--output-dir requires a value".to_string())?,
                );
            }
            "--openvmm-exe" => {
                launch_overrides.openvmm_exe =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--openvmm-exe requires a value".to_string()
                    })?));
            }
            "--kernel" => {
                launch_overrides.kernel = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--kernel requires a value".to_string())?,
                ));
            }
            "--mxc-initramfs" => {
                launch_overrides.mxc_initramfs =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--mxc-initramfs requires a value".to_string()
                    })?));
            }
            "--common-root" => {
                launch_overrides.common_root =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--common-root requires a value".to_string()
                    })?));
            }
            "--config" => {
                config = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--config requires a value".to_string())?,
                ));
            }
            "--execute-config" => execute_config = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(ParsedCommon {
        backend: backend.ok_or_else(|| "--backend is required".to_string())?,
        static_only,
        output_dir,
        launch_overrides,
        config,
        execute_config,
    })
}

fn run_conformance(arguments: Vec<String>) -> ExitCode {
    let ParsedCommon {
        backend,
        static_only,
        output_dir,
        launch_overrides,
        config,
        execute_config,
    } =
        match parse_common(arguments, PathBuf::from("build").join("mxc-agent-harness")) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("error: {error}");
                print_usage();
                return ExitCode::FAILURE;
            }
        };
    if config.is_some() {
        eprintln!("error: --config is valid only for mxc-policy");
        return ExitCode::FAILURE;
    }
    if execute_config {
        eprintln!("error: --execute-config is valid only for mxc-policy");
        return ExitCode::FAILURE;
    }
    let options = HarnessOptions {
        backend,
        mode: if static_only {
            HarnessMode::StaticOnly
        } else {
            HarnessMode::LiveWhp
        },
        output_dir,
        launch_overrides: Some(launch_overrides),
    };
    match execute_harness(options) {
        Ok(run) => {
            println!(
                "mode={:?} backend={} platform={} report={}",
                run.report.mode,
                run.report.backend,
                run.report.platform,
                run.report_path.display()
            );
            for scenario in &run.report.scenarios {
                println!(
                    "req{:02} {:<36} conformance={:?} check={:?} evidence={:?} required={:?} {}",
                    scenario.requirement_number,
                    scenario.id,
                    scenario.status,
                    scenario.check_status,
                    scenario.evidence_source,
                    scenario.required_evidence_source,
                    scenario.error.as_deref().unwrap_or("ok"),
                );
            }
            run.exit_code()
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_policy(arguments: Vec<String>) -> ExitCode {
    let ParsedCommon {
        backend,
        static_only,
        output_dir,
        launch_overrides,
        config,
        execute_config,
    } =
        match parse_common(arguments, PathBuf::from("build").join("mxc-policy-harness")) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("error: {error}");
                print_usage();
                return ExitCode::FAILURE;
            }
        };
    let options = PolicyHarnessOptions {
        backend,
        mode: if static_only {
            PolicyHarnessMode::StaticOnly
        } else {
            PolicyHarnessMode::LiveWhp
        },
        output_dir,
        config,
        execute_config,
        launch_overrides,
    };
    match execute_policy_harness(options) {
        Ok(run) => {
            println!(
                "mode={:?} backend={} report={} passed={} uncovered={} unexpected={} blocked={} failed={}",
                run.report.mode,
                run.report.backend,
                run.report_path.display(),
                run.report.passed,
                run.report.uncovered.len(),
                run.report.unexpected.len(),
                run.report.blocked.len(),
                run.report.failed.len()
            );
            run.exit_code()
        }
        Err(error) => {
            eprintln!(
                "error: code={} path={} message={}",
                error.code, error.instance_path, error.message
            );
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("mxc-policy") => {
            arguments.remove(0);
            run_policy(arguments)
        }
        Some("conformance") => {
            arguments.remove(0);
            run_conformance(arguments)
        }
        _ => run_conformance(arguments),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_common;

    #[test]
    fn parse_common_defaults_execute_config_to_false() {
        let parsed = parse_common(
            vec!["--backend".to_string(), "whp".to_string()],
            PathBuf::from("default-output"),
        )
        .expect("parsed");
        assert_eq!(parsed.backend.as_str(), "whp");
        assert!(!parsed.static_only);
        assert_eq!(parsed.output_dir, PathBuf::from("default-output"));
        assert!(parsed.config.is_none());
        assert!(!parsed.execute_config);
    }

    #[test]
    fn parse_common_accepts_execute_config_and_config_together() {
        let parsed = parse_common(
            vec![
                "--backend".to_string(),
                "whp".to_string(),
                "--config".to_string(),
                "policy.json".to_string(),
                "--execute-config".to_string(),
            ],
            PathBuf::from("default-output"),
        )
        .expect("parsed");
        assert_eq!(parsed.config, Some(PathBuf::from("policy.json")));
        assert!(parsed.execute_config);
    }
}
