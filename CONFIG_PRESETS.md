# CottenDNS Config Presets

These paired configs are bundled for common network conditions:

- `speed`: lower base duplication, MTU-weighted resolver selection, LZ4, and loss-aware MTU probing for faster clean or moderately lossy DNS paths.
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
client_config.survival.toml     + server_config.survival.toml
client_config.tcp-survival.toml + server_config.tcp-survival.toml
```

Fill the delegated domain on both sides and paste the generated server key into
the client config. The client files expect `client_resolvers.txt` beside the
config, same as `client_config.toml.simple`.
