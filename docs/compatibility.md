# Compatibility With mihomo

Concord reads the configuration mihomo reads and aims to behave as mihomo does. This file lists where it does not:
deliberate differences, what is left out, and what is supported only in part.

## How Unsupported Input Is Handled

| Handling | When |
|---|---|
| The profile is rejected, and the built-in empty config runs instead, routing everything direct | The profile is wrong: an unknown or malformed rule, an illegal field, a reference to something that does not exist |
| The node is set aside with a warning | The node uses something Concord does not support, or its options cannot be built into a working node (a certificate that cannot be read, a malformed fingerprint pin, REALITY over `ws`). A group left empty by this, or whose selected node was set aside, refuses connections instead of falling back to another member; `empty-fallback` applies when given |
| The key is ignored with a warning | It does not change where traffic goes |
| The key is accepted with no effect and no warning | It changes nothing mihomo's results depend on either, or the host owns it: `geodata-loader` (how much of a `.dat` file mihomo keeps in memory while reading it) and `profile.store-selected` (see Not Supported) |

A key that a node's type does not have in mihomo, such as `reality-opts` on `hysteria2` or `alpn` on `socks5`, is
ignored with a warning, as is a `smux` that is not a map. A number mihomo keeps without checking its range, such as
`mixed-port: 70000`, `dns.fake-ip-ttl: -1` or a negative `heartbeat-interval` on a node, is ignored with a warning
(`out_of_range` for the general, `dns` and `ntp` settings): a port leaves its listener closed and any other number takes
its default. A number that picks a protocol version, such as `version` on `snell`, is still refused. Warnings carry a
stable `code` and are returned by
`config.warnings`. Settings whose loss would change routing or
widen exposure are never ignored silently, and keys that name a server's identity (`fingerprint`, `certificate`,
`reality-opts`) are never dropped while the node keeps working.

## Deliberate Differences

| Behaviour | mihomo | Concord |
|---|---|---|
| A node of an unsupported type, or one whose options cannot be built | The whole profile fails, or, for options checked when connecting, the node's connections fail | The node is set aside with a warning |
| `listeners`, `tunnels`, `external-controller-tls`, `-unix`, `-pipe`, `external-ui` and `external-doh-server` | Opened | Never opened; the host opens listeners through the API |
| `external-controller`, `secret` and `external-controller-cors` | Read from the profile | Read from the profile when Concord runs on its own (`concord run`). An app that embeds Concord sets them itself, and the profile's values are ignored with a warning |
| Dashboard changes in an app that embeds Concord | mihomo's embedded builds refuse `PUT`/`PATCH /configs` and the geo update | Allowed, except `PUT /configs` and `tun` in `PATCH /configs`, which belong to the app; the app is told of every change so it stays in step |
| Dial retries | Up to 10 per connection within 5 s | None: one dial per connection, as sing-box does; a failed dial fails the connection |
| UDP routing | The first packet from a source decides the route for all its destinations | Each destination is routed by the rules; flows that reach one outbound share its session, so the external mapping stays endpoint-independent. Single-destination protocols such as plain VMess are the exception |
| `GEOIP` | Reads the mmdb or `GeoIP.dat` | Reads the mmdb only; `geodata-mode: true` and `geox-url.geoip` are ignored with a warning, and a code that only a custom `GeoIP.dat` held does not match. `GEOIP,!cn` negates against the mmdb |
| `IP-ASN` and `SRC-IP-ASN` without `ASN.mmdb` | The apply downloads the file and fails if the download does | The apply goes ahead; the rules match nothing until the file, fetched in the background and retried, loads, and a `NOT` around one does not turn that into a match |
| `dns.fallback-filter` left out | `geoip: true`, `geoip-code: CN` | `geoip: false` and no code, so no region is singled out; `geoip: true` without a `geoip-code` skips the GeoIP filter with a warning |
| The process name of connections the core opens itself (provider updates, health checks, DNS through the tunnel) | `mihomo`, in the connections API, the routing log and `PROCESS-NAME` | `concord` |
| The hop a node's `dialer-proxy` dials | Listed as a connection of its own, so the bytes count once for it and once for the outer connection | Not listed; the outer connection is listed and its bytes count once |
| File providers | Reloaded on file-system events | Reloaded by polling the file every 2 s |
| A provider `path` outside the home directory, or one that passes through a symlink | Read when `SAFE_PATHS` lists the directory; a symlink is followed | Refused: the apply fails, naming the provider and the path |
| A `hosts` entry that maps a name to itself, such as `a.example: a.example` | Loaded; an address lookup of the name never returns, nor does loading a later entry that points at the name | Loaded; the entry is skipped with a warning and the name is resolved by DNS. A cycle through two or more entries is refused, as in mihomo |
| A regular expression with .NET-only syntax, such as `\p{IsCJKUnifiedIdeographs}`, in a group `filter`, `DOMAIN-REGEX`, `PROCESS-NAME-REGEX` or `override.proxy-name` | Accepted | Refused when loading |
| A number too wide for its field in a rule or group, such as `DST-PORT,70000`, `DSCP,300` or `tolerance: -1` | Cut to the field's width without a warning | Refused when loading |
| The replacement text of `override.proxy-name` | .NET rules: `$1x` is group 1 followed by `x` | Rust `regex` rules: `$1x` names a group called `1x`, so write `${1}x` |
| The TUN keys that choose what is captured: `route-address-set`, `route-exclude-address-set`, `include-uid-range`, `exclude-uid-range`, `exclude-src-port-range`, `exclude-dst-port-range`, `include-android-user`, `include-package`, `exclude-package`, `include-mac-address` and `exclude-mac-address` | Applied | Ignored with a warning that the TUN captures other traffic than the profile says; an app that embeds Concord picks the apps itself |
| `iptables` | Installs redirect rules on Linux | Ignored with a warning; Concord does not run as a Linux router |
| `dns.append-system` | Not a key | A Concord key: `true` puts `system://` last in `nameserver` unless the list already has it, after the MITM modules have edited the list, so a module that replaces the list keeps it. An app sets it for its user |
| Picking a dead `fallback` member | Stores the pick, then tests the member; a connection during the test drops the pick (`adapter/outboundgroup/fallback.go:105-145`) | Stores the pick, then tests the member; a connection during the test uses another member, and the pick stays until the test decides |

TCP JLS does not resume sessions. Its native Hello matches the AES-capable Go jls-tls default
(the cipher order can differ from Go on CPUs without AES acceleration), including TLS 1.2 in the offer,
but this handshake engine only completes TLS 1.3 with X25519 or X25519MLKEM768. A peer selecting TLS 1.2,
a P-curve retry or HelloRetryRequest is rejected; Go can continue the ordinary TLS fallback after HRR.
Explicit fingerprints preserve their browser offers. Authentication failures still validate the real
certificate and hostname; only an explicit fingerprint sends an HTTP fallback request. Handshake and
fallback together have a five-second deadline, and caller cancellation can stop them earlier.

XHTTP over HTTP/3 waits for the QUIC handshake before sending requests and does not send 0-RTT data.
mihomo Alpha `3c0d10a5` can use early data through `DialEarly` (`adapter/outbound/vless.go:690-708`).
Concord's shared QUIC link does not expose early connections or cache resumable sessions for this transport;
connection reuse works after the handshake. QUIC DATAGRAM advertisement and HTTP/3 grease are disabled,
as in mihomo's default xhttp HTTP/3 transport (`transport/xhttp/client.go:167-176`). Keepalive is capped
at half the local 300-second idle timeout, but cannot follow a shorter peer idle timeout: Quinn exposes
neither the negotiated idle timeout nor a way to change keepalive after connecting. With a peer timeout
shorter than twice the keepalive period, an idle connection can close despite keepalive; configure a
shorter positive keepalive period for that peer. quic-go applies the cap to the negotiated timeout.

## Routing

`rematch` outbounds support `target-rematch-name` and `target-sub-rule`, including empty strings that clear a
previous value. `REMATCH-NAME` matches case-sensitive names separated by `/`. Matching restarts after selecting a
rematch node, including through a group; unknown sub-rule names use the main rules, and cycles close the flow.

`URL-REGEX` and `USER-AGENT`, which mihomo does not have, match an HTTP request as Surge's do: the first finds its
regex, read as MITM patterns are, anywhere in the full URL, and the second matches the User-Agent header against a
case-sensitive `*` and `?` pattern. Either payload may be double-quoted to hold commas. Until a request is read
they are undecided: they do not match, a `NOT` around one does not turn that into a match, and matching goes on
to the rules after them.

Surge's and Loon's REJECT variants are built-in policies: `REJECT-NO-DROP`, `REJECT-TINYGIF`, `REJECT-IMG`,
`REJECT-DICT`, `REJECT-ARRAY`, `REJECT-200` and `REJECT-VIDEO` reject a connection as `REJECT` does, and keep
their names in the connection's chain. They are not listed among the proxies.

## External Controller

Concord serves the Clash REST and WebSocket API, in mihomo's shapes, for dashboards such as metacubexd, zashboard and yacd, with the same
paths, fields, status codes, `Authorization: Bearer` secret and CORS. The differences:

- Not served, answered with status 501: `/restart`, `/upgrade` (core, UI and geo), `/debug`, `/storage`, `/ui`
  (there is no `external-ui`) and `PATCH /rules/disable`.
- `PATCH /configs` changes what Concord changes live: `mode`, `log-level`, `ipv6`, `allow-lan`, `bind-address`,
  `lan-allowed-ips`, `lan-disallowed-ips`, `mixed-port`, `tcp-concurrent`, `find-process-mode` and, when Concord runs
  on its own, `tun`. A request that names any other setting (ports other than `mixed-port`, `interface-name`,
  `sniffing`, `skip-auth-prefixes` and the like) is refused with status 400 naming the settings, and nothing in it is
  applied; mihomo applies them.
- `PUT /configs` reads a `path` only inside the home directory; `SAFE_PATHS` is not read. The profile, given by
  `path` or `payload` or, with neither, the file `concord run` started with, replaces the working `config.yaml`.
- Connection `id`s are decimal numbers, not UUIDs.
- `GET /` answers `{"hello":"concord"}`. metacubexd and zashboard check the backend with `/version` and do not read
  it.
- `/version` reports Concord's version with `meta: true`. Dashboards compare it with mihomo's releases, so they may
  offer a core update; the update itself answers 501.
- `/rules` has no hit counters (`extra`), and `size` is always -1.
- The `tun` object of `GET /configs` carries `enable`, `device`, `stack`, `dns-hijack`, `auto-route`,
  `auto-detect-interface` and `mtu`; settings Concord does not have keep mihomo's zero values, and mihomo's defaults
  for the TUN addresses, `recvmsgx` and `processors-per-channel` are not reported.
- An empty list is `[]` where mihomo writes `null` (`authentication`, `skip-auth-prefixes`, `lan-disallowed-ips`,
  `dns-hijack`, and `connections` with none open).

## Not Supported

- Outbound types, networks, TLS options and Shadowsocks plugins outside Concord's scope (among them tailscale,
  easytier, zerotier, openvpn, sudoku, kcp, restls and kcptun): the node is set aside with a warning,
  also when the TLS option is given in xhttp `download-settings`. The full lists are the `T2_*` constants in
  `crates/config/src/proxy/parse.rs`.
- A provider's `override.override-expr`: the provider gets no proxies and a warning, because its nodes must not run
  without the expressions.
- A rule provider's `path-in-bundle`: `BundleMRS.7z` is not read, so a provider whose local file is missing loads
  from its `url` or fails to load, as in mihomo when the home directory has no `BundleMRS.7z`. The key is ignored
  with a warning.
- `profile.store-selected`: Concord does not save the selected nodes itself. The host saves them and hands them back
  with each profile it applies, so the key is accepted and has no effect.
- The `relay` group type, which mihomo also removed; use `dialer-proxy`.
- Shadowsocks ciphers that only `sing-shadowsocks2` has: `aes-192-gcm`, `aes-192-ccm`, `chacha8-ietf-poly1305`,
  `xchacha8-ietf-poly1305`, `rabbit128-poly1305`, `aegis-128l`, `aegis-256`, `aez-384`, `deoxys-ii-256-128`,
  `lea-{128,192,256}-gcm`, `ascon128`, `ascon128a` and `2022-blake3-aes-{128,256}-ccm`; the node is set aside with a
  warning.
- Hysteria `faketcp`; ShadowQUIC over QUIC v2.
- sing-mux brutal on the client's own socket, which needs a Linux kernel module. The sing-mux exchange is done, so
  the server still paces its sends.
- A node's `tfo` on Windows, where it does nothing. On macOS it works as in mihomo, which also means a SYN carrying
  Fast Open data that the path drops is sent again unchanged rather than as a plain SYN, so such a path fails the
  connection where Linux falls back to an ordinary handshake. With `tfo`, as in mihomo, a dial also counts as
  connected before its handshake (on macOS always, on Linux once the server's cookie is cached): of several server
  addresses the first is used, and one that does not answer holds the connection until the system's connect timeout
  instead of handing over to the next address.
- SSH RSA host keys. Modern servers offer ed25519; RSA client keys are supported.
- `global-client-fingerprint`, which mihomo also removed, and a node's `ws-path` and `ws-headers`, which it removed
  in favour of `ws-opts`; a node that writes them gets a warning.

## Partial Support

- **MASQUE:** Cloudflare WARP CONNECT-IP over H3 and H2 capsules, and TCP-only `h3-l4proxy`, with
  ECDSA client authentication and endpoint SPKI pinning. H3 IP advertises the 10 MiB header limit and both
  standard and legacy datagram settings; L4 advertises only the header limit. Grease and disabled extension
  settings are omitted. IP requests wait for peer SETTINGS and require both HTTP and QUIC datagram support.
  A peer advertising only the legacy datagram setting is accepted; mihomo requires the standard setting.
  Local loopback tests cover both IP families, TCP half-close, UDP, remote DNS, reconnect and rejection;
  a live WARP enrollment is not part of those tests. `remote-dns-resolve` currently accepts literal UDP/TCP
  nameservers (L4 requires `tcp://`); encrypted or hostname nameservers are rejected when building the node.
  The native IP stack implements Cubic/Reno; `bbr`/`bbr3` select Cubic with a warning, and stack mode names use
  the same native stack. The IP stack keeps the configured MTU; each H3 packet is checked against the current
  QUIC datagram capacity and oversized packets are dropped without retiring the tunnel or returning PMTU ICMP.
  H2 drops received capsules larger than the configured MTU. The `masque-l4` benchmark uses a local H3
  CONNECT peer and covers TCP.
- **mieru:** both transports work against mihomo's mieru listener; the UDP transport with a `dialer-proxy` is
  rejected when the node is built, and padding statistics are approximated.
- **Hysteria2 `realm-opts`:** works against mihomo's `hysteria2-realm` listener, including through two NATs; it speaks
  HTTP/1.1 to the control server (the realm `alpn` is ignored and redirects are not followed), and a node that also
  sets `dialer-proxy` is rejected when built.
- **ECH (`ech-opts`):** works from a `config` or an HTTPS record lookup, on both TLS backends and over QUIC; a
  Shadowsocks `v2ray-plugin` node with `ech-opts` is rejected when built.
  A server that rejects the ECH offer and sends `retry_configs` gets one more TCP connection with that list (as in
  sing-box, unlike mihomo); QUIC nodes do not retry.
- **sing-mux `brutal-opts`:** performs the exchange so the server paces its sends; see above for the client side.
- **`bbr-profile`:** `standard` is quinn's BBR; `conservative` and `aggressive` apply the profile's gains, startup
  length and drain rule, without overshoot detection or overestimate avoidance.
- **WireGuard `amnezia-wg-option`:** runs against amneziawg-go as the server, legacy and version 3. Version 3's
  content-padding addition, the rekey, reject, keepalive and handshake-attempt timings, and the transport-message part
  of random trailers are not applied; the node works and `config.warnings` names the options it sets.
- **Snell `obfs-opts` `shadow-tls`:** works against mihomo's Snell listener with ShadowTLS v2 and v3, over TCP and
  UDP, including Snell v6. Version 6 supports `default`, `unshaped` and `unsafe-raw` modes and an optional
  `userkey` (up to 255 bytes); its PSK must contain 12–255 bytes. Simple-obfs `tls`/`http` is rejected for v6.
  Snell with `restls` is rejected when built. On versions 1–5, `mode` and `userkey` are
  ignored with a warning; mihomo rejects nonempty values for these versions.
- **Snell connection reuse:** `reuse` selects CONNECT_V2 and its zero-chunk end marker, but Concord does not pool
  Snell connections; each dial opens a new connection. This also applies to Snell v4/v5.
- **TUN:** ICMP echo is forwarded from an unprivileged ICMP socket on Unix and a raw ICMP socket on Windows; only echo
  replies come back, so `traceroute` through the TUN shows no hops. On Linux the TUN uses offload whenever
  the device supports it, whatever `tun.gso` says (mihomo uses it only with `gso: true`); `gso: false` gets a warning
  that offload stays on. Other platforms have no offload in either core. On Windows
  the interface's forwarding, router-discovery, DAD and DNS-registration options are not set. `tun.dns-mode` is not
  read: with `auto-route` the TUN becomes the system resolver on every desktop platform, macOS included, where mihomo
  leaves it off unless `dns-mode` asks; the macOS entry lives in the dynamic store and goes away with the process.
  The keys that narrow what the TUN captures by package, Android user, uid range, port range, MAC address or route
  set are ignored, so the TUN captures other traffic than they say; the warning says so. An app that embeds Concord
  picks the apps that go through its TUN itself.
- **DNS:** a `dhcp://<interface>` upstream runs as `system://` with a warning. A `ts://`, `tailscale://`, `et://` or
  `easytier://` server is skipped with a warning, as its tailscale or easytier node is set aside; a list, such as one
  `nameserver-policy` entry, left with no other server answers REFUSED, so those names do not go to another resolver.
- **Accepted without effect:** `skip-auth-prefixes` and `inbound-tfo` (a non-empty value gets a warning).
- **Deprecated fingerprint names:** `chrome_psk`, the other `chrome_*` variants and `randomized` are read as `chrome`
  and `random` with a warning.
- **TProxy UDP** does not carry DSCP.
- **MITM:** `cron` scripts are not exercised end to end; WebSocket over HTTP/2, reclaiming upstream connections after
  90 s idle, and a per-chunk limit against zip bombs are not implemented. Body rewrites run on the blocking pool and
  give up after 5 s (the Surge script default), leaving the body as it came; a jq filter that never ends, such as
  `until(false; .)`, keeps its blocking thread busy until the process exits, as jaq cannot be interrupted.

A `domain` rule provider takes `format: domain-set`, Concord's own name for Surge's DOMAIN-SET files. It reads as
`text` does, but for one difference: a leading dot, as in `.example.com`, covers `example.com` itself too, where
mihomo's `text` reads it as the names under `example.com` only (Clash writes the Surge meaning `+.example.com`).

MITM header and body rewrites take two conditions of Concord's own after the URL, beyond Surge's form:
`request-head <re>`, and on an `http-response` rule `response-head <re>`. Each is matched against a head as Quantumult
X's `url-and-header` reads it: the request or status line, then every header as `Name: value`, each line ending in CRLF.
The rules of a phase are picked as it begins, so a rewrite earlier in the phase does not change what a condition sees.
`header-text-replace <re> <replacement>` rewrites that whole head, as Quantumult X's `request-header` and
`response-header` do. It may change a request's method, path and headers and a response's status and headers, but not
the host a request goes to (a `Host` line naming another host is put back), `Content-Length` or `Transfer-Encoding`; a
result that is not a head leaves the head as it was. A body rewrite whose first regex is literally `request-head` or
`response-head` reads as a condition; write it another way, such as `request-hea[d]`.
On a connection opened by an HTTP proxy CONNECT, USER-AGENT reads the CONNECT request's User-Agent until a
request is read, as Surge does, so it decides such a connection without decryption.
Requests the MITM engine reads are routed one by one when the rules may tell them apart: when a URL-REGEX or
USER-AGENT rule ahead of the one that decided the connection was undecided, or when a rewrite sends a request to
another server while the rules read requests. Each such request is routed with its URL, as rewrites, Map Local and
the request script left it, and its User-Agent; it reuses only a connection that leaves through the same chain. A
host the rules reject only until its requests are read is still decrypted, and a request a REJECT variant decides
gets the variant's reply (`REJECT-TINYGIF` a GIF, `REJECT-DICT` `{}`, `REJECT-DROP` no answer). While the rules
read requests, plain HTTP on port 80 is read for any host.
A `map-local` line takes `request-head <re>` after its URL as well. `request-body-mock`, a list of Concord's own for
Loon's `mock-request-body`, takes `map-local`'s parameters but `status-code`: the first line whose URL and condition
match sends its data upstream in place of the request's body, a request that had none included, with `header=`
set over the request's headers; the header and body rewrites and the script after it see the mocked body.
An `http-request` or `http-response` script takes the same conditions as parameters, `request-head=<re>` and on
an `http-response` script `response-head=<re>`. The first script whose URL and conditions match runs, so one whose
conditions fail leaves the turn to the next.
`client-source-address` takes Surge's comma-separated addresses and CIDRs, `-` before one left out, and decrypts
only for the clients it names, all of them while it is empty. Under a TUN the device's own apps reach Concord from the
TUN's address, so a list that names only other clients leaves them as they are, as Surge does on a Mac.
`skip-server-cert-verify-hostname`, a list of Concord's own in `hostname`'s syntax, leaves the certificates of the
servers it names unchecked while `skip-server-cert-verify` is off, so an app can grant a module that asks for it no
more than its own hostnames.
MITM lines split on spaces, and a double-quoted run stays one field. As modules written for Surge expect, a quoted
value after `=` ends only at a quote followed by a space or the end of the line, so `data="{"code":0}"` keeps the
JSON's own quotes, and a field that starts with a quote not closed that way is taken as written, so a body rewrite's
`"key":\{.+\}` matches the key with its quotes.

A host reads a module (a Surge `.sgmodule`, a Loon plugin, a Quantumult X snippet or a Stash override) with
`mitm.readModule`, which answers with each line by its line number: what goes into the MITM lists, the rules and rule sets with their policies for the host to map, the
DNS, hosts and route changes in mihomo's keys, the remote files it reads, and every line Concord does not take with the
reason. A module's `force-http-engine-hosts` comes back as a list of its own, `force-http-hostname`, for the host to
decide on. A rule's `extended-matching` is read and reported as `extendedMatching`, but not applied: the rule
matches the domain only, not the SNI or the Host header. A `map-local` line's `data-type=json`, which Loon writes and Surge's manual does not list, reads as text
sent as `application/json`.
A Loon plugin's `[Rewrite]` and `[Script]` lines read in both of Loon's syntaxes. In the `if … then` form the
`[Argument]` values come in with their types: a test on arguments alone is decided as the module is read, a line
whose test fails is left out as `disabled`, and a header test's `^` and `$` stand for the start and end of that
header's value. A value known only per request, such as a header written into an action's text or a capture outside
a URL rewrite, leaves its line out as `runtimeValue`; a condition the MITM lists cannot hold, such as `||` across
the URL and the method, as `condition`. A batch of JSON edits becomes one jq filter and a batch of body replacements
one rewrite; a batch of header edits is one rewrite per header. `reject_video` answers with an empty `video/mp4`
body, `response.json.jq_file` names a jq file fetched as a script is, and a mock whose file is base64 is decoded when
the rules are built. In Loon's old syntax a script's URL regex ignores case, as Loon's does, and
`argument=[{a},{b}]` hands the script its arguments as a JSON object. A JSON key path that starts with `$.`, which
authors write though Loon does not document it, starts at the body's root.
A Quantumult X snippet reads with or without its `[rewrite_local]`, `[filter_local]`, `[task_local]` and `[mitm]`
headers. Every rewrite type of its sample.conf is read; `request-header` and `response-header` rewrite the whole head
and `echo-response` sends a file the host fetches, with the type and headers written before it. A filter's
`force-cellular`, `multi-interface` and `via-interface` are dropped, as Concord does not pick interfaces. A task has
no time limit in Quantumult X and gets Concord's longest, 60 s; one with `require-devices` is left out as
`requirement`. `skip_src_ip` leaves those clients out of decryption; `skip_dst_ip`, which needs the address a host
resolves to, is left out as `setting`. `[rewrite_remote]` and `[filter_remote]` name files the host fetches itself.
A Stash override (`.stoverride`) reads its `http` lists, `cron` scripts, `rules`, `rule-providers`,
`script-providers`, `dns` and `hosts`, with `${args.name}` filled in as Stash's override arguments are, a lone
reference keeping the argument's type. An `http.mitm` host without a port covers 443 only, as Stash's does, and
`host:*` every port; `force-http-engine` comes back as `force-http-hostname`. Its JSON edits keep Stash's reading:
`replace` and `del` touch a value that is neither null nor false, and `add` writes one that is missing or null. A
rule provider is read when it is a classical list, inline or fetched as text; the domain and CIDR behaviors and the YAML
and MRS formats are left out as `ruleType`, and a script provider with only `payload` as `noAttachment`.

A profile puts modules in force under `mitm.modules`: each has a `name` and either `text` or a `path` inside the
MITM directory (`mitm/` under the home directory), with `arguments` and `attachments` as `mitm.readModule` takes
them. `mitm.module-policy` maps a module's policy names to the profile's outbounds; a name it does not map is taken
as an outbound of that name, and a rule whose policy names none is left out, not sent to `MATCH`'s. The modules'
rules go ahead of the profile's in module order, their rule sets become rule providers, their DNS and hosts entries
edit the profile's, and their MITM lines follow the profile's; their `%INSERT%` hostnames come before the rest. A
module that cannot be read or repeats a name takes no effect and the profile still loads. Routes and the proxy bypass
list are the host's to apply. The remote files a module reads are fetched through the core, in the background after
an apply, and stored in `mitm/resources/` under names their content gives, with `mitm/module-resources.json`
mapping each URL to its file; a line whose file is not stored yet takes effect once it is, and a failed fetch keeps
the file an earlier one stored. `adopt-resources` hands over, by URL, files the host stored itself. A module with
`enabled: false` is read but takes no effect and its files are not fetched; a host lists it so that they are kept.
With MITM on and a `modules` list, which then names every module the host has, each apply removes the files Concord
stored, fetched, adopted or written from a module's text, that no listed module reads any longer. Attached files are
the host's and stay, and nothing is removed while a listed module cannot be read.
`mitm.moduleStatus` answers whether each module is on, how it and each of its files stand, with why a fetch failed (`http` with its
status, `dns`, `tls`, `timeout`, `connection` or `other`), and `mitm.fetchModule` fetches one module's files
again, or every module's; each module's fetch is a `resourceUpdate` of kind `mitmModule`. Nothing fetches them
again on a timer.

Shadowsocks supports `gost-plugin` in WebSocket mode, including TLS and its default per-connection smux v1 stream.
Gost relay supports TCP, destination-bound UDP, forward mode, TLS and per-connection smux v1.
As with mihomo, its relay server needs `nodelay: true` so CONNECT is answered before application data,
and `mux.version: 1` when multiplexing is enabled.
