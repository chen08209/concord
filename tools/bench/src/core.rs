//! The cores under test: Concord as the shipped `concord` over its control
//! connection, mihomo through `-d <home> -f <config>`. Each runs from a copy of
//! the binary taken when the run began, so a rebuild halfway through changes nothing.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Child;

use crate::control::{self, Control, Endpoint};
use crate::isolate::{self, Placement};
use crate::socks::{self, Entry};

const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// The end of a core's output kept in a startup error, enough for a panic or a config error.
const OUTPUT_TAIL: usize = 4096;

/// Appends the end of the core's output to a startup error, so the job's log shows why the core failed.
fn with_output(err: String, log: &Path) -> String {
    let Ok(bytes) = std::fs::read(log) else {
        return err;
    };
    let tail = String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(OUTPUT_TAIL)..]);
    match tail.trim_end() {
        "" => format!("{err}; the core wrote nothing"),
        tail => format!("{err}; the core's last output:\n{tail}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Concord,
    Mihomo,
    Singbox,
    Ssrust,
}

/// What a core's figures stand for in a comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Subject,
    Reference,
    /// Measured, but not what the run is judged against.
    Diagnostic,
}

impl Role {
    /// On the TUN path the reference is sing-box's Go stack, so a mihomo TUN arm decides nothing.
    pub fn of(kind: Kind, tun: bool) -> Role {
        match kind {
            Kind::Concord => Role::Subject,
            Kind::Mihomo if tun => Role::Diagnostic,
            Kind::Mihomo | Kind::Singbox | Kind::Ssrust => Role::Reference,
        }
    }
}

/// A mihomo core takes the TUN entry only when asked for by name.
pub fn check_tun_cores(cores: &[CoreSpec], tun: bool, mihomo_allowed: bool) -> Result<(), String> {
    match cores.iter().find(|core| core.kind == Kind::Mihomo) {
        Some(core) if tun && !mihomo_allowed => Err(format!(
            "--tun is judged against sing-box's Go stack: give the Go arm as NAME=singbox:PATH, \
             or pass --tun-mihomo to keep `{}` as a diagnostic arm",
            core.name
        )),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CoreSpec {
    pub name: String,
    pub kind: Kind,
    pub role: Role,
    pub source: String,
    pub binary: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub version: Option<String>,
}

impl CoreSpec {
    /// `NAME=concord:PATH`, `NAME=mihomo:PATH`, `NAME=singbox:PATH`, `NAME=ssrust:PATH`, or
    /// `NAME=rev:GITREV` for Concord built from that commit.
    pub fn parse(text: &str, snapshot_dir: &Path, tun: bool) -> Result<CoreSpec, String> {
        let (name, spec) = text
            .split_once('=')
            .ok_or(format!("--core {text}: expected NAME=KIND:PATH"))?;
        let (kind, value) = spec
            .split_once(':')
            .ok_or(format!("--core {text}: expected KIND:PATH"))?;
        let (kind, path) = match kind {
            "concord" => (Kind::Concord, PathBuf::from(value)),
            "mihomo" | "go" => (Kind::Mihomo, PathBuf::from(value)),
            "singbox" | "sing-box" => (Kind::Singbox, PathBuf::from(value)),
            "ssrust" => (Kind::Ssrust, PathBuf::from(value)),
            "rev" => (Kind::Concord, crate::revs::build(value)?),
            other => return Err(format!("--core {text}: unknown kind {other}")),
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(format!(
                "--core {text}: names are letters, digits, '-', '_' or '.'"
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::create_dir_all(snapshot_dir).map_err(|e| e.to_string())?;
        let binary = snapshot_dir.join(name);
        std::fs::write(&binary, &bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        let version = match kind {
            Kind::Mihomo | Kind::Singbox | Kind::Ssrust => std::process::Command::new(&binary)
                .arg(match kind {
                    Kind::Ssrust => "--version",
                    Kind::Singbox => "version",
                    Kind::Concord | Kind::Mihomo => "-v",
                })
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.lines().next().map(str::to_string)),
            Kind::Concord => None,
        };
        Ok(CoreSpec {
            name: name.to_string(),
            kind,
            role: Role::of(kind, tun),
            source: spec.to_string(),
            binary,
            sha256: hex::encode(Sha256::digest(&bytes)),
            size: bytes.len() as u64,
            version,
        })
    }
}

fn ssrust_profile(proxy: Option<&Value>, mixed: u16) -> Result<Value, String> {
    let proxy = proxy
        .filter(|node| node["type"].as_str() == Some("ss") && node.get("plugin").is_none())
        .ok_or("ssrust requires a plain Shadowsocks case")?;
    let method = proxy["cipher"]
        .as_str()
        .filter(|method| matches!(*method, "aes-128-gcm" | "chacha20-ietf-poly1305"))
        .ok_or("ssrust supports ss-aes128 and ss-chacha")?;
    let server = proxy["server"].as_str().ok_or("ssrust: missing server")?;
    let port = proxy["port"]
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .ok_or("ssrust: invalid server port")?;
    let password = proxy["password"]
        .as_str()
        .ok_or("ssrust: missing password")?;
    Ok(json!({
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
        "local_address": "127.0.0.1",
        "local_port": mixed,
        "protocol": "socks",
        "mode": "tcp_and_udp",
        "no_delay": true,
    }))
}

/// The case's node as a sing-box client: a mixed inbound for the readiness probe and the SOCKS entry, and
/// with `tun` a TUN inbound. That inbound names no `stack`, so sing-box runs sing-tun's default, its Go stack.
fn singbox_profile(
    proxy: Option<&Value>,
    mixed: u16,
    tun: Option<&Value>,
) -> Result<Value, String> {
    let outbound = match proxy {
        None => json!({"type": "direct", "tag": "out"}),
        Some(node)
            if node["type"].as_str() == Some("trojan")
                && node.get("client-fingerprint").is_none() =>
        {
            json!({
                "type": "trojan",
                "tag": "out",
                "server": node["server"],
                "server_port": node["port"],
                "password": node["password"],
                "tls": {
                    "enabled": true,
                    "server_name": node["sni"],
                    "insecure": node["skip-cert-verify"],
                },
            })
        }
        Some(node)
            if node["type"].as_str() == Some("ss")
                && node.get("smux").is_none()
                && node.get("plugin").is_none() =>
        {
            json!({
                "type": "shadowsocks",
                "tag": "out",
                "server": node["server"],
                "server_port": node["port"],
                "method": node["cipher"],
                "password": node["password"],
            })
        }
        Some(_) => {
            return Err(
                "a sing-box core runs the direct, trojan-tls and plain Shadowsocks cases only"
                    .into(),
            );
        }
    };
    let mut inbounds = vec![json!({
        "type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": mixed,
    })];
    if let Some(tun) = tun {
        inbounds.push(json!({
            "type": "tun",
            "tag": "tun",
            "interface_name": tun["device"],
            "mtu": tun["mtu"],
            "address": ["172.19.0.1/30"],
            "auto_route": true,
            "strict_route": false,
        }));
    }
    Ok(json!({
        "log": {"level": "error"},
        "inbounds": inbounds,
        "outbounds": [outbound],
        "route": {"auto_detect_interface": true, "final": "out"},
    }))
}

pub struct Launch<'a> {
    pub spec: &'a CoreSpec,
    pub home: PathBuf,
    pub profile: String,
    pub proxy: Option<Value>,
    /// Concord takes the TUN section as an overlay; mihomo reads it from the profile; sing-box gets its own.
    pub tun: Option<Value>,
    pub mitm: Option<Value>,
    pub mixed: u16,
    pub placement: Placement,
    pub log: PathBuf,
    pub probe: SocketAddr,
    pub entry: Entry,
}

pub struct Running {
    pub name: String,
    pub pid: u32,
    pub entry: Entry,
    pub ready: Duration,
    child: Child,
    control: Option<Control>,
}

impl Running {
    pub async fn start(launch: Launch<'_>) -> Result<Running, String> {
        std::fs::create_dir_all(&launch.home).map_err(|e| e.to_string())?;
        // Concord writes its effective config to `<home>/config.yaml`.
        let profile = launch.home.join("profile.yaml");
        std::fs::write(&profile, &launch.profile).map_err(|e| e.to_string())?;
        let log = std::fs::File::create(&launch.log).map_err(|e| e.to_string())?;
        let started = Instant::now();
        let mut setup = None;
        let (child, control) = match launch.spec.kind {
            Kind::Ssrust => {
                if launch.tun.is_some() {
                    return Err("ssrust does not support the benchmark TUN entry".into());
                }
                let config = ssrust_profile(launch.proxy.as_ref(), launch.mixed)?;
                let path = launch.home.join("sslocal.json");
                std::fs::write(&path, config.to_string()).map_err(|e| e.to_string())?;
                let mut command = isolate::command(&launch.spec.binary, &launch.placement);
                command
                    .arg("-c")
                    .arg(path)
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().map_err(|e| e.to_string())?)
                    .stderr(log);
                (
                    isolate::spawn(&mut command, &launch.placement)
                        .map_err(|e| format!("spawn sslocal: {e}"))?,
                    None,
                )
            }
            Kind::Singbox => {
                let config =
                    singbox_profile(launch.proxy.as_ref(), launch.mixed, launch.tun.as_ref())?;
                let path = launch.home.join("sing-box.json");
                std::fs::write(&path, config.to_string()).map_err(|e| e.to_string())?;
                let mut command = isolate::command(&launch.spec.binary, &launch.placement);
                command
                    .arg("run")
                    .arg("-c")
                    .arg(path)
                    .arg("-D")
                    .arg(&launch.home)
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().map_err(|e| e.to_string())?)
                    .stderr(log);
                (
                    isolate::spawn(&mut command, &launch.placement)
                        .map_err(|e| format!("spawn sing-box: {e}"))?,
                    None,
                )
            }
            Kind::Mihomo => {
                let mut command = isolate::command(&launch.spec.binary, &launch.placement);
                command
                    .arg("-d")
                    .arg(&launch.home)
                    .arg("-f")
                    .arg(&profile)
                    .env("DISABLE_LOOPBACK_DETECTOR", "true")
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().map_err(|e| e.to_string())?)
                    .stderr(log);
                (
                    isolate::spawn(&mut command, &launch.placement)
                        .map_err(|e| format!("spawn mihomo: {e}"))?,
                    None,
                )
            }
            Kind::Concord => {
                let endpoint = Endpoint::bind()?;
                let text = control::token();
                let mut command = isolate::command(&launch.spec.binary, &launch.placement);
                // Without it an embedded core keeps its error log, such as a listener that failed
                // to bind, on the control connection, and a startup error has nothing to quote.
                command
                    .arg(&endpoint.address)
                    .env("CONCORD_DEBUG", "1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(log);
                let mut child = isolate::spawn(&mut command, &launch.placement)
                    .map_err(|e| format!("spawn concord: {e}"))?;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin
                        .write_all(format!("{text}\n").as_bytes())
                        .await
                        .map_err(|e| format!("token: {e}"))?;
                }
                let mut control = Control::open(endpoint.accept().await?, &text).await?;
                let home = launch.home.to_string_lossy().into_owned();
                control.call("core.init", json!({"home": home})).await?;
                // The app's settings win over the profile's for these keys, as in the embedding app.
                let mut overlay = json!({
                    "mixed-port": launch.mixed,
                    "allow-lan": false,
                    "log-level": "error",
                    "ipv6": false,
                    "find-process-mode": "off",
                });
                if let Some(tun) = &launch.tun {
                    overlay["tun"] = tun.clone();
                }
                if let Some(mitm) = &launch.mitm {
                    overlay["mitm"] = mitm.clone();
                }
                control
                    .call(
                        "config.apply",
                        json!({"profile": {"path": profile.to_string_lossy()}, "overlay": overlay}),
                    )
                    .await?;
                control.call("engine.start", json!({})).await?;
                setup = Some(started.elapsed());
                (child, Some(control))
            }
        };
        // `ip netns exec` execs in place, so this is the core's pid either way.
        let pid = child.id().ok_or("the core exited at once")?;

        let mut running = Running {
            name: launch.spec.name.clone(),
            pid,
            entry: launch.entry,
            ready: Duration::ZERO,
            child,
            control,
        };
        if launch.tun.is_some() {
            wait_for_device(&launch.tun)
                .await
                .map_err(|e| with_output(e, &launch.log))?;
        }
        running
            .wait_ready(launch.probe, started, setup)
            .await
            .map_err(|e| with_output(e, &launch.log))?;
        running.ready = started.elapsed();
        Ok(running)
    }

    /// `setup` is how long a Concord core took to answer its config and start, which tells a
    /// slow start from a port that never opened.
    async fn wait_ready(
        &mut self,
        probe: SocketAddr,
        started: Instant,
        setup: Option<Duration>,
    ) -> Result<(), String> {
        let mut last = String::new();
        while started.elapsed() < READY_TIMEOUT {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("{} exited during start: {status}", self.name));
            }
            match echo_once(self.entry, probe).await {
                Ok(()) => return Ok(()),
                Err(err) => last = err.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let setup = setup.map_or(String::new(), |took| {
            format!(
                " ({} ms of it before engine.start returned)",
                took.as_millis()
            )
        });
        Err(format!(
            "{} not ready after {READY_TIMEOUT:?}{setup}: {last}",
            self.name
        ))
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Asks the core to exit and returns how long it took: Concord leaves when its
    /// control connection closes, as it does when the app quits; the others on SIGTERM.
    pub async fn stop(mut self) -> Duration {
        let started = Instant::now();
        let concord = self.control.take().is_some();
        #[cfg(unix)]
        if !concord && let Some(pid) = self.child.id() {
            #[allow(
                unsafe_code,
                reason = "kill takes a pid this process spawned and still owns"
            )]
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        if !concord {
            let _ = self.child.start_kill();
        }
        if tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
        started.elapsed()
    }
}

#[cfg(not(unix))]
async fn wait_for_device(_: &Option<Value>) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
async fn wait_for_device(tun: &Option<Value>) -> Result<(), String> {
    let Some(device) = tun.as_ref().and_then(|t| t["device"].as_str()) else {
        return Ok(());
    };
    // Not /sys/class/net: sysfs shows the namespace it was mounted in, not the one
    // the harness entered with --link.
    let name = std::ffi::CString::new(device).map_err(|e| e.to_string())?;
    for _ in 0..600 {
        #[allow(
            unsafe_code,
            reason = "if_nametoindex reads the NUL-terminated name and keeps no pointer"
        )]
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("TUN device {device} never appeared"))
}

pub async fn echo_once(entry: Entry, target: SocketAddr) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let work = async {
        let mut stream = socks::connect(entry, target).await?;
        stream.write_all(b"r").await?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        socks::abort(stream);
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(3), work)
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("probe timed out")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrust_uses_the_case_endpoint_and_cipher_in_its_own_config() {
        for method in ["aes-128-gcm", "chacha20-ietf-poly1305"] {
            let proxy = json!({"type":"ss", "server":"peer.test", "port":1234,
                               "password":"secret", "cipher":method});
            let config = ssrust_profile(Some(&proxy), 4321).unwrap();
            assert_eq!(config["server"], "peer.test");
            assert_eq!(config["server_port"], 1234);
            assert_eq!(config["password"], "secret");
            assert_eq!(config["method"], method);
            assert_eq!(config["local_address"], "127.0.0.1");
            assert_eq!(config["local_port"], 4321);
            assert_eq!(config["protocol"], "socks");
            assert_eq!(config["mode"], "tcp_and_udp");
            assert_eq!(config["no_delay"], true);
        }
    }

    #[test]
    fn singbox_takes_the_tun_entry_on_its_default_stack() {
        let tun = json!({"device": "cbtun0", "mtu": 1500, "stack": "system"});
        let config = singbox_profile(None, 4321, Some(&tun)).unwrap();
        assert_eq!(config["inbounds"][0]["type"], "mixed");
        assert_eq!(config["inbounds"][0]["listen_port"], 4321);
        let inbound = &config["inbounds"][1];
        assert_eq!(inbound["type"], "tun");
        assert_eq!(inbound["interface_name"], "cbtun0");
        assert_eq!(inbound["mtu"], 1500);
        assert_eq!(inbound["auto_route"], true);
        assert!(inbound.get("stack").is_none());
        assert_eq!(config["outbounds"][0]["type"], "direct");
        assert_eq!(config["route"]["final"], config["outbounds"][0]["tag"]);
        let socks_only = singbox_profile(None, 4321, None).unwrap();
        assert_eq!(socks_only["inbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn singbox_translates_trojan_and_shadowsocks_and_rejects_what_it_cannot_represent() {
        let mut proxy = json!({"name": "trojan-tls", "type": "trojan", "server": "peer.test",
                               "port": 1234, "password": "secret", "sni": "localhost",
                               "skip-cert-verify": true});
        let config = singbox_profile(Some(&proxy), 4321, None).unwrap();
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["server"], "peer.test");
        assert_eq!(outbound["server_port"], 1234);
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "localhost");
        assert_eq!(outbound["tls"]["insecure"], true);
        proxy["client-fingerprint"] = json!("chrome");
        assert!(singbox_profile(Some(&proxy), 4321, None).is_err());
        let mut proxy = json!({"name": "ss-aes128", "type": "ss", "server": "peer.test", "port": 1234,
                               "cipher": "aes-128-gcm", "password": "pw"});
        let config = singbox_profile(Some(&proxy), 4321, None).unwrap();
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "shadowsocks");
        assert_eq!(outbound["server_port"], 1234);
        assert_eq!(outbound["method"], "aes-128-gcm");
        assert_eq!(outbound["password"], "pw");
        proxy["smux"] = json!({"enabled": true});
        assert!(singbox_profile(Some(&proxy), 4321, None).is_err());
        assert!(singbox_profile(Some(&json!({"type": "vmess"})), 4321, None).is_err());
    }

    #[test]
    fn a_mihomo_core_on_the_tun_entry_is_refused_unless_named_and_then_decides_nothing() {
        let core = |kind, tun| CoreSpec {
            name: "arm".into(),
            kind,
            role: Role::of(kind, tun),
            source: String::new(),
            binary: PathBuf::new(),
            sha256: String::new(),
            size: 0,
            version: None,
        };
        let on_tun = [core(Kind::Concord, true), core(Kind::Mihomo, true)];
        assert!(check_tun_cores(&on_tun, true, false).is_err());
        assert!(check_tun_cores(&on_tun, true, true).is_ok());
        assert!(check_tun_cores(&on_tun, false, false).is_ok());
        let reference = [core(Kind::Concord, true), core(Kind::Singbox, true)];
        assert!(check_tun_cores(&reference, true, false).is_ok());
        assert_eq!(on_tun[0].role, Role::Subject);
        assert_eq!(on_tun[1].role, Role::Diagnostic);
        assert_eq!(reference[1].role, Role::Reference);
        assert_eq!(core(Kind::Mihomo, false).role, Role::Reference);
    }

    #[test]
    fn ssrust_rejects_profiles_it_cannot_represent() {
        assert!(ssrust_profile(None, 4321).is_err());
        let mut proxy = json!({"type":"trojan", "server":"peer.test", "port":1234,
                               "password":"secret", "cipher":"aes-128-gcm"});
        assert!(ssrust_profile(Some(&proxy), 4321).is_err());
        proxy["type"] = json!("ss");
        proxy["plugin"] = json!("obfs");
        assert!(ssrust_profile(Some(&proxy), 4321).is_err());
        proxy.as_object_mut().unwrap().remove("plugin");
        proxy["port"] = json!(0);
        assert!(ssrust_profile(Some(&proxy), 4321).is_err());
        proxy["port"] = json!(1234);
        proxy["cipher"] = json!("unsupported");
        assert!(ssrust_profile(Some(&proxy), 4321).is_err());
    }
}

#[cfg(test)]
mod output_tests {
    use super::with_output;

    #[test]
    fn a_startup_error_carries_the_end_of_the_core_output() {
        let dir = std::env::temp_dir().join(format!("bench-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("core.log");
        let long = format!("{}panic: bad config\n", "x".repeat(10_000));
        std::fs::write(&log, long).unwrap();
        let err = with_output("main not ready".into(), &log);
        assert!(err.starts_with("main not ready; the core's last output:\n"));
        assert!(err.ends_with("panic: bad config"));
        assert!(err.len() < 4200);
        std::fs::write(&log, "").unwrap();
        assert_eq!(with_output("e".into(), &log), "e; the core wrote nothing");
        assert_eq!(with_output("e".into(), &dir.join("missing")), "e");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
