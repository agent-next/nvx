use ::std::process::ExitCode;

use ::agent_harness::{HarnessReport, report_exit_code};

fn print_report(report: &HarnessReport) {
    println!(
        "phase={} service_readiness={:?} adapter={} ({})",
        report.phase, report.service_readiness, report.adapter.kind, report.adapter.reason
    );
    println!("{:<24} {:<16} reason", "requirement", "status");
    for result in &report.requirements {
        println!(
            "{:<24} {:<16} {}",
            result.name,
            format!("{:?}", result.status),
            result.reason
        );
    }
}

fn main() -> ExitCode {
    let report = agent_harness::phase0_report();
    print_report(&report);
    report_exit_code(&report)
}
