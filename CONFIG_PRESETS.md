# CottenDNS Config Presets

These paired configs are bundled for common network conditions:

- `speed`: UDP-first with TCP fallback, lower base duplication, MTU-weighted resolver selection, LZ4, and four-sample MTU probing that tolerates one transient miss without permanently rejecting an otherwise-fast UDP path.
- `udp-only`: the `speed` profile pinned to plain UDP/53. No TCP/DoT/DoH candidate is probed or raced and the background transport sweep never starts, so nothing can migrate the data plane off UDP. Use where UDP/53 is known to reach the resolvers; if UDP is blocked or truncated, use `speed` or `tcp-survival` instead. The UDP pin is **forced**: unlike every other preset value, an explicit `RESOLVER_TRANSPORT` (or a non-UDP `RESOLVER_TRANSPORT_PATHS` entry) does not override it, so a tool that renders a complete config cannot silently turn the profile back into `auto`.
- `survival`: more duplication, smaller/stubbier DNS shape, lower MTU ceilings, and earlier auto-FEC for restrictive lossy UDP networks.
- `tcp-survival`: forces DNS-over-TCP/53 on the client and keeps the server TCP listener tuned for long-lived fallback connections.

Client-only adaptive starting profiles are also bundled:

- `iran`: UDP-first, smaller DNS shape, loss-tolerant MTU discovery, poison handling, and conservative background exploration.
- `china`: UDP-first poison-resistant baseline with conservative DNS sizing and per-resolver TCP fallback.
- `russia`: speed-oriented UDP-first baseline with patient DPI-stall detection and per-resolver fallback.
- `venezuela`: poison-resistant, moderately loss-tolerant baseline for unstable resolver paths.
- `cuba`: low-bandwidth, high-latency baseline with reduced probing and setup duplication.
- `low-bandwidth`: generic bandwidth-constrained profile; `africa` and `africa-low-bandwidth` are accepted aliases.

Country profiles are not permanent transport locks. They provide safe initial
values while authenticated runtime measurements continue selecting transport
independently for each resolver. Explicit TOML values always override them.
They do not require a matching server preset and do not change the tunnel wire
protocol, so CottenDNS and legacy MasterDNS/StormDNS servers remain compatible.

All client presets inherit the unified path controller and comparable-path
striping defaults. Set `PATH_CONTROLLER_MODE = "legacy"` explicitly for an
immediate client-only rollback; no server setting or protocol change is needed.

Use matching pairs:

```text
client_config.speed.toml        + server_config.speed.toml
client_config.udp-only.toml     + server_config.speed.toml
client_config.survival.toml     + server_config.survival.toml
client_config.tcp-survival.toml + server_config.tcp-survival.toml
```

Fill the delegated domain on both sides and paste the generated server key into
the client config. The client files expect `client_resolvers.txt` beside the
config, same as `client_config.toml.simple`.

## Android engine

The Android app consumes this repository as a pinned source snapshot (vendored
or checked out at an immutable commit) and builds the engine itself; no Android
artifact is released here. It loads the same presets —
the app passes the preset name through as `CONFIG_PRESET`, so every name listed
above (including `udp-only`) works there as soon as the engine pin is advanced,
with no Kotlin port. `scripts/build-android-client.sh` cross-compiles
the four ABIs the app bundles and CI validates that build on every push; see
`docs/ANDROID_ENGINE_INTEGRATION.md`. The preset *picker* in the Android app
carries its own list, so adding a preset here does not add it to that menu.

Note for config renderers: through the file path, any key present in the TOML
outranks the preset. A renderer that always emits a complete config therefore
pins every value it writes and the preset only fills gaps. Emit `CONFIG_PRESET`
plus the keys the user actually chose, not the whole schema, or the preset
becomes decorative. `udp-only`'s transport pin is the one deliberate exception.
