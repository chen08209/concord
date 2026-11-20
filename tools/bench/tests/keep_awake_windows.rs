//! The busy loop behind `run --keep-awake` on Windows: where it runs, at what priority, and that
//! it ends once the harness lets go of its stdin.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "reads a child's priority class and affinity mask through its process handle"
)]

use std::io::{BufRead, BufReader};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetPriorityClass, GetProcessAffinityMask, IDLE_PRIORITY_CLASS,
};

const BENCH: &str = env!("CARGO_BIN_EXE_concord-bench");

fn affinity(process: windows_sys::Win32::Foundation::HANDLE) -> usize {
    let (mut mask, mut system) = (0usize, 0usize);
    // SAFETY: both masks are locals that outlive the call, and the handle is open.
    assert_ne!(
        unsafe { GetProcessAffinityMask(process, &mut mask, &mut system) },
        0
    );
    mask
}

fn an_allowed_cpu() -> usize {
    // SAFETY: the pseudo-handle of the current process is always valid.
    affinity(unsafe { GetCurrentProcess() }).trailing_zeros() as usize
}

fn spinning(cpu: usize) -> Child {
    let mut child = Command::new(BENCH)
        .args(["spin", "--cpu", &cpu.to_string(), "--parent", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "spinning");
    child
}

#[test]
fn the_loop_runs_idle_priority_on_its_cpu() {
    let cpu = an_allowed_cpu();
    let mut child = spinning(cpu);
    let process = child.as_raw_handle();

    assert_eq!(affinity(process), 1 << cpu);
    // SAFETY: the child is alive and `Child` keeps its handle open.
    assert_eq!(unsafe { GetPriorityClass(process) }, IDLE_PRIORITY_CLASS);

    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn the_loop_ends_when_its_stdin_closes() {
    let mut child = spinning(an_allowed_cpu());
    drop(child.stdin.take());

    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
}
