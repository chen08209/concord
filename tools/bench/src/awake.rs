//! `--keep-awake`: an idle-priority busy loop on every CPU, so none of them sleeps between the
//! short bursts of a lightly loaded run. A control for a VM, where that sleep is charged to the
//! processes measured; see `.agents/benchmarking.md`.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

const READY: &str = "spinning";
const UNSUPPORTED: &str = "--keep-awake needs Linux or Windows";

pub struct Awake {
    loops: Vec<Loop>,
}

struct Loop {
    cpu: usize,
    child: Child,
}

impl Awake {
    pub fn start(cpus: &[usize]) -> Result<Awake, String> {
        if !cfg!(any(target_os = "linux", windows)) {
            return Err(UNSUPPORTED.into());
        }
        let exe = std::env::current_exe().map_err(|e| format!("--keep-awake: {e}"))?;
        let mut awake = Awake { loops: Vec::new() };
        for &cpu in cpus {
            let mut child = Command::new(&exe)
                .args(["spin", "--cpu", &cpu.to_string()])
                .args(["--parent", &std::process::id().to_string()])
                .stdin(if cfg!(windows) {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| format!("--keep-awake: {e}"))?;
            let stdout = child.stdout.take();
            awake.loops.push(Loop { cpu, child });
            let mut line = String::new();
            let read = stdout.map(|s| BufReader::new(s).read_line(&mut line));
            if !matches!(read, Some(Ok(_))) || line.trim() != READY {
                return Err(format!("--keep-awake: the loop on CPU {cpu} did not start"));
            }
        }
        Ok(awake)
    }

    pub fn describe(&self) -> serde_json::Value {
        self.loops
            .iter()
            .map(|l| serde_json::json!({"cpu": l.cpu, "pid": l.child.id()}))
            .collect()
    }

    /// Kills and reaps every loop; the count is of those still running when it did.
    pub fn stop(mut self) -> usize {
        self.loops.drain(..).map(end).filter(|&ran| ran).count()
    }
}

impl Drop for Awake {
    fn drop(&mut self) {
        for l in self.loops.drain(..) {
            end(l);
        }
    }
}

fn end(mut l: Loop) -> bool {
    let running = matches!(l.child.try_wait(), Ok(None));
    let _ = l.child.kill();
    let _ = l.child.wait();
    running
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "prctl and sched_setscheduler act on the calling process and take plain values"
)]
pub fn spin(cpu: usize, parent: u32) -> Result<(), String> {
    use std::io::Write;

    // The signal follows the thread that spawned this process, which is the harness's main
    // thread and lives as long as the harness does.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(format!("prctl: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::getppid() } as u32 != parent {
        return Err("the harness is gone".into());
    }
    crate::isolate::pin_self(&[cpu])?;
    let param = libc::sched_param { sched_priority: 0 };
    if unsafe { libc::sched_setscheduler(0, libc::SCHED_IDLE, &param) } != 0 {
        return Err(format!(
            "sched_setscheduler: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{READY}")
        .and_then(|()| stdout.flush())
        .map_err(|e| e.to_string())?;
    // With lazy preemption a woken task only gets in when the loop enters the kernel. A loop that
    // never does holds every wakeup to the next tick and batches the run it should only keep awake.
    loop {
        unsafe { libc::sched_yield() };
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "SetPriorityClass takes the current-process pseudo-handle and a constant"
)]
pub fn spin(cpu: usize, _parent: u32) -> Result<(), String> {
    use std::io::{Read, Write};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, IDLE_PRIORITY_CLASS, SetPriorityClass,
    };

    crate::isolate::pin_self(&[cpu])?;
    if unsafe { SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS) } == 0 {
        return Err(format!(
            "SetPriorityClass: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Windows has no parent-death signal. The harness holds the other end of stdin and never
    // writes to it, so this read returns only once the harness is gone.
    std::thread::spawn(|| {
        let _ = std::io::stdin().read(&mut [0]);
        std::process::exit(0);
    });
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{READY}")
        .and_then(|()| stdout.flush())
        .map_err(|e| e.to_string())?;
    // A ready thread of a higher priority preempts this one at once, so the loop needs no system
    // call to let it in.
    loop {
        std::hint::spin_loop();
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn spin(_: usize, _: u32) -> Result<(), String> {
    Err(UNSUPPORTED.into())
}
