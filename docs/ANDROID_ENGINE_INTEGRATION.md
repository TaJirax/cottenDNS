# Android external-engine integration

The CottenDNS client engine is owned and versioned by this repository. The
WhiteDNS Android application consumes it as source at a pinned commit and builds
the native binaries itself. This repository ships no Android application.
Vendored snapshots and submodules are both valid, but the application must
record the exact upstream revision and must not carry unreviewed engine edits.

## Pinned-source contract

The personal Android repository currently vendors an immutable snapshot and
records its source revision:

```bash
git archive --format=tar <reviewed-engine-sha> | tar -xf - -C third_party/CottenDns
printf 'repository=https://github.com/TaJirax/cottenDNS\ncommit=%s\n' \
  <reviewed-engine-sha> > third_party/CottenDns.UPSTREAM
```

A submodule consumer may instead pin the same immutable revision:

```bash
git submodule add https://github.com/TaJirax/cottenDNS .engine/CottenDns
git -C .engine/CottenDns checkout <reviewed-engine-sha>
git add .gitmodules .engine/CottenDns
```

What this repository guarantees so that works:

- `go build ./cmd/client` is the only entry point needed. The module is
  self-contained; there are no submodules of its own and no generated artifacts
  are tracked (built binaries and `dist/` are gitignored), so the checkout stays
  small.
- `scripts/build-android-client.sh` resolves its own module root, so the Android
  workspace can invoke it by path from anywhere without `cd`.
- Advancing the recorded source revision is the only step needed to pick up
  engine behavior; there is no Kotlin-side port.
- CI here cross-compiles all four ABIs through that script on every push, so a
  commit that stops being a valid Android engine source cannot reach the branch
  the app pins against.

Release CI must verify the recorded revision before building so a stale or
locally modified engine cannot silently enter an APK.

## CI contract

1. Check out the Android application repository.
2. Check out `TaJirax/cottenDNS` at a pinned full commit SHA as vendored source,
   a submodule, or into a sibling directory. Do not track a moving branch for release
   builds.
3. Install the Go version from `go.mod` and Android NDK `29.0.14206865`.
4. From the CottenDNS checkout, run:

   ```bash
   NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865" \
     OUTPUT_DIR="$GITHUB_WORKSPACE/app/src/main/jniLibs" \
     bash scripts/build-android-client.sh all
   ```

5. Package the generated `libcottendns_client.so` under `arm64-v8a`,
   `armeabi-v7a`, `x86_64`, and `x86`.
6. Record and verify the pinned CottenDNS SHA in Android build metadata.

Example GitHub Actions checkout (replace the placeholder with the reviewed
engine commit):

```yaml
- uses: actions/checkout@v4
- uses: actions/checkout@v4
  with:
    repository: TaJirax/cottenDNS
    ref: 0123456789abcdef0123456789abcdef01234567
    path: .engine/CottenDns
- uses: actions/setup-go@v5
  with:
    go-version-file: .engine/CottenDns/go.mod
- name: Build CottenDNS Android engine
  working-directory: .engine/CottenDns
  run: |
    NDK_ROOT="$ANDROID_HOME/ndk/29.0.14206865" \
      OUTPUT_DIR="$GITHUB_WORKSPACE/app/src/main/jniLibs" \
      bash scripts/build-android-client.sh all
```

The outputs are Android executables with a `.so` packaging name, matching the
existing launcher contract. The linker flags provide 16 KiB page compatibility.

## Android-facing engine features

- `FAST_CONNECT` releases startup after a safe resolver pool is ready and keeps
  scanning the remaining fleet at background priority.
- `LEGACY_SESSION_ID` selects legacy one-byte framing per client while the
  server continues accepting native and legacy clients simultaneously.
- `MAX_ACTIVE_STREAMS` and `LOCAL_HANDSHAKE_TIMEOUT_SECONDS` bound stalled or
  excessive local SOCKS clients.
- `-scan-only` performs resolver/MTU discovery without starting the tunnel.
- Machine output is emitted at every log level: `WD_PROGRESS`, `WD_RESOLVERS`,
  and `WD_SCAN`.
- Generic SOCKS5 UDP, DNS fallback, loss recovery, adaptive duplication, and
  server-advertised fairness remain part of this source tree.
- Poison-aware question validation, per-resolver transport selection,
  packet-size-aware narrow-MTU routing, and rotating background path discovery
  are implemented inside this engine. Android receives the same behavior without
  a Kotlin port when its pinned CottenDNS SHA is advanced.

Pinning the engine SHA makes debug and release builds use identical engine code
and prevents stale prebuilt binaries from silently surviving an app merge.
