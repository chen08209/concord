# Performance

Concord is measured against upstream mihomo, both acting as the client in front of the same proxy server, on five
representative cases: `direct` (no proxy protocol), `ss-aes128` (Shadowsocks AES-128-GCM), `trojan-tls`,
`vmess-grpc-tls` and `hysteria2`. Every figure is Concord relative to mihomo, as a percentage.

## How It Is Measured

The bench tool in `tools/bench` runs four processes on one machine over loopback: a load client, the core under test
(Concord or mihomo, taking the load on its SOCKS5 port), a mihomo server for the case's protocol, and an origin that
sends, receives and echoes.

| Workload | What it does |
|---|---|
| Download, upload | One TCP flow at full speed, origin to client or client to origin |
| Request/response | One connection exchanging 64-byte requests and replies, one at a time |
| New connections | 1,500 connections, 16 at a time, each opened, used for one byte and closed |
| UDP | UDP echo through SOCKS5 UDP ASSOCIATE, 1,200-byte datagrams with 64 in flight |

- On Linux the client, the core, the server and the origin are pinned to separate CPUs (2 for the core, 2 for the
  server, 1 for the origin, 3 for the client), and both cores run as many worker threads as they have CPUs.
- Each of six rounds starts fresh processes for both cores, and the order alternates between rounds. Throughput and
  latency windows last 3 s after 0.7 s of warm-up.
- CPU per GB, per transaction and per connection is the core's own CPU time, each core at its own top speed. Server
  CPU is the mihomo server's, the same binary in both arms, so it shows what the client's framing costs the server.
- Linux: the figure is the ratio of the medians over rounds, with a 95% bootstrap interval. It counts as a lead or a
  deficit only when the interval excludes no change and a Mann-Whitney test gives p < 0.05; otherwise it is a tie.
- macOS: there is no CPU pinning, so all four processes share the VM's CPUs and whole rounds move together. The ratio
  is taken within each round and averaged, with a 95% bootstrap interval. It counts only when the interval excludes
  no change and the difference is larger than the resolution: the smallest difference a run of Concord against
  itself could tell from noise. Rounds disturbed by other work on the host are dropped (one `hysteria2` round).

## Setup

- Concord: a pre-release build of 0.1.0. The Linux and macOS builds differ on the measured paths only in zeroing
  cipher keys when they are freed. Changes to the data path made after these runs are not measured on this page.
- mihomo: `v1.19.33`, built from upstream with `CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags '-s -w'`.
- Linux: an Ubuntu 26.04 arm64 VM with 8 vCPUs, 7.2 GiB and kernel 7.0, on an Apple M4 Pro.
- macOS: a macOS 27.2 arm64 VM with 4 vCPUs and 6 GiB, on the same machine.

Absolute numbers depend on the machine and are not given; compare ratios only within one platform.

## Linux

Higher is better for rates, lower for CPU, latency and memory. "tie" means no significant difference.

| Metric | `direct` | `ss-aes128` | `trojan-tls` | `vmess-grpc-tls` | `hysteria2` |
|---|---|---|---|---|---|
| Download, Gbit/s | tie (+1.5%) | +30.7% | +44.0% | +5.1% | tie (+7.2%) |
| Download, CPU per GB | -5.1% | -20.2% | -31.4% | -21.2% | -38.5% |
| Download, server CPU per GB | | -6.1% | tie (-4.9%) | -3.1% | -10.0% |
| Upload, Gbit/s | tie (+2.7%) | +2.2% | tie (+2.2%) | +16.9% | tie (-0.3%) |
| Upload, CPU per GB | -5.4% | tie (+3.1%) | tie (-2.9%) | -23.7% | tie (-2.5%) |
| Upload, server CPU per GB | | -2.8% | tie (-2.1%) | -13.2% | tie (-4.4%) |
| Request/response, transactions/s | +4.3% | +2.0% | tie (+1.2%) | +3.6% | +8.6% |
| Request/response, CPU per transaction | -24.3% | -29.0% | -27.6% | -43.9% | -47.8% |
| Request/response, p99 latency | -27.1% | tie (-1.8%) | tie (+1.2%) | tie (+0.1%) | -9.0% |
| New connections/s | +36.7% | +23.7% | +41.3% | +13.3% | tie (+2.5%) |
| CPU per connection | -19.9% | -15.0% | -37.0% | -19.0% | tie (+0.5%) |
| Connection p99 latency | -56.6% | -34.4% | -31.6% | -21.8% | tie (-13.9%) |
| UDP, Mbit/s | +29.2% | +58.9% | +60.5% | | +35.4% |
| UDP, CPU per GB | -25.6% | -41.1% | -33.5% | | -52.0% |
| UDP, server CPU per GB | | -9.4% | -8.9% | | -11.2% |
| UDP, round-trip p99 | -38.8% | -25.4% | -41.5% | | -20.3% |
| Peak memory during download | -40.3% | -49.4% | -48.5% | -52.5% | -52.3% |

`direct` has no proxy server, and `vmess-grpc-tls` has no UDP workload in this set.

## macOS

The last column is the resolution for `direct` and for the proxied cases (measured on `ss-aes128`). "not judged"
marks a metric whose run of Concord against itself varied too much between rounds to decide anything (12% for
`direct` new connections, 31% for download server CPU). The server spent more CPU per GB on Concord's `ss-aes128` and
`trojan-tls` downloads, but within that variation. Peak memory is the ratio of the medians.

| Metric | `direct` | `ss-aes128` | `trojan-tls` | `vmess-grpc-tls` | `hysteria2` | Resolution |
|---|---|---|---|---|---|---|
| Download, Gbit/s | tie (+0.3%) | +20.7% | tie (+1.1%) | tie (+7.0%) | +21.2% | 4.8% / 17.2% |
| Download, CPU per GB | tie (-3.0%) | -34.4% | -17.0% | -36.1% | -46.6% | 3.9% / 5.0% |
| Download, server CPU per GB | | +58.1% not judged | +25.4% not judged | -7.5% not judged | -1.8% not judged | 61.9% |
| Upload, Gbit/s | tie (-0.5%) | tie (+0.8%) | tie (+3.9%) | +17.6% | +45.7% | 6.4% / 17.1% |
| Upload, CPU per GB | tie (-2.5%) | -18.6% | -32.5% | -31.3% | -45.5% | 5.9% / 16.4% |
| Upload, server CPU per GB | | tie (+1.9%) | tie (+6.6%) | tie (-9.1%) | -16.4% | 15.2% |
| Request/response, transactions/s | +9.1% | tie (-2.4%) | tie (-3.9%) | tie (+1.2%) | +9.8% | 5.5% / 7.8% |
| Request/response, CPU per transaction | -41.2% | -39.4% | -37.8% | -50.2% | -56.7% | 5.1% / 6.8% |
| Request/response, p99 latency | tie (-5.7%) | tie (-5.1%) | tie (+5.8%) | tie (+13.7%) | tie (-10.4%) | 34.4% / 16.6% |
| New connections/s | -7.8% not judged | tie (+9.2%) | +30.8% | +15.0% | tie (+0.3%) | 23.9% / 9.9% |
| CPU per connection | -7.1% not judged | -33.5% | -48.2% | -38.2% | -20.4% | 8.3% / 17.7% |
| Connection p99 latency | -30.9% not judged | tie (+5.0%) | tie (-31.2%) | tie (+22.1%) | tie (-10.3%) | 330.1% / 69.6% |
| UDP, Mbit/s | +20.9% | tie (+13.7%) | +27.1% | | +39.1% | 12.7% / 14.0% |
| UDP, CPU per GB | -28.6% | -37.0% | -47.9% | | -50.1% | 16.3% / 11.9% |
| UDP, server CPU per GB | | tie (+2.3%) | tie (-7.8%) | | -14.0% | 12.8% |
| UDP, round-trip p99 | -19.4% | -25.4% | -21.5% | | -32.8% | 19.4% / 15.7% |
| Peak memory during download | -72.8% | -70.4% | -69.6% | -55.8% | -66.4% | |

## Android

Concord inside the FlClash Android app, against the same app on its Go core (a mihomo fork), on a Xiaomi Mi 11
(Snapdragon 888, Android 14), with a later pre-release build of Concord. Each app carries the load through its own VPN
(`VpnService`) with no proxy (`direct`) and its default TUN settings. The bench attaches to the running app
(`concord-bench run --attach … --via tun`) and sends as another app's uid; the origin is another machine reached over
a Wi-Fi hotspot of about 230 Mbit/s.

So every rate is bound by the link: the comparison is CPU per byte, latency and memory, and the throughput ceiling is
not measured here. Each app ran eight rounds of 5 s, in four sessions that alternate the order, on charge with the
screen off and no thermal throttling. CPU is the app process's own CPU time. Figures are the ratio of the medians with
a 95% bootstrap interval, judged as on Linux. "Four flows" is four parallel downloads.

| Metric | Concord against the Go core |
|---|---|
| Download, CPU per GB | -37.1% |
| Upload, CPU per GB | -59.2% |
| Four flows, CPU per GB | -39.7% (fairness 1.000 in both) |
| UDP, CPU per GB | -48.6% |
| UDP, round-trip p99 | -11.6% |
| Request/response, CPU per transaction | -37.4% |
| Request/response, p50 latency | -3.7% |
| Request/response, p99 latency | tie (-6.0%) |
| UDP request/response, round-trip p50 | -3.9% |
| UDP request/response, round-trip p99 | tie (-6.8%) |
| Rates | link-bound: TCP ties, UDP +3.8%, transactions/s +3.6% |
| Memory 30 s after a cold start (PSS) | 30.0 against 66.4 MiB (-55%) |

For the cold start both apps were force-stopped and started by their start action with no UI, so neither had the
Flutter engine loaded; PSS is read from `smaps_rollup`, in two passes of opposite order.

## Not Covered Yet

- Windows.
- TUN, which is being worked on; these results are through the SOCKS5 port only.
- The other protocols and workloads (several flows at once, idle connections, large profiles), and links with added
  delay or loss.
- On Android: proxy protocols, new connections, and a link fast enough to load the core.

## Reproducing

Build mihomo as above, then from the repository root:

```sh
cargo xtask bench --quick --no-baseline --mihomo /path/to/mihomo \
  --rounds 6 --fresh-cores --cpus core=0-1,server=2-3,origin=4,client=5-7
```

Leave out `--cpus` on macOS. `xtask bench` builds Concord and the bench tool in release and writes the run to
`target/bench/runs/<time>/`: `report.md` gives each metric's median and Concord's ratio to mihomo with its interval,
and `results.json` holds every trial. Run nothing else on the machine while it measures.
