// Copyright(c) The microvm authors.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
#[test]
fn spawn_tree_forks_child_and_grandchild_after_executable_path_is_hidden() {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    let root = std::env::temp_dir().join(format!(
        "nvx-agent-probe-process-tree-{}",
        std::process::id()
    ));
    let visible = root.join("visible");
    let hidden = root.join("hidden");
    fs::create_dir_all(&visible).expect("create visible probe directory");
    let probe = visible.join("nvx-agent-probe");
    fs::copy(env!("CARGO_BIN_EXE_nvx-agent-probe"), &probe).expect("copy probe executable");

    let child = Command::new(&probe)
        .args(["spawn-tree", "--hold-ms", "10"])
        .env("NVX_AGENT_PROBE_TEST_TREE_FORK_DELAY_MS", "250")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch copied probe");

    thread::sleep(Duration::from_millis(50));
    fs::rename(&visible, &hidden).expect("hide original executable pathname");

    let output = child.wait_with_output().expect("wait for probe tree");
    let _ = fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "probe failed after path hiding: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("probe output is utf-8");
    assert!(stdout.contains("child="), "missing child PID: {stdout}");
    assert!(
        stdout.contains("grandchild="),
        "missing grandchild PID: {stdout}"
    );
}
