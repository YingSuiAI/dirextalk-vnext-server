# Android acceptance harness

`scripts/android-acceptance.sh` owns only disposable emulator and local-stack
setup. It intentionally stops after the Connector transport is reachable;
the Direct/Group product scenario runner is not part of this harness.

The production-safe defaults are two exact API 35 `aosp_atd` x86_64 AVDs, software
acceleration (`-accel off`), two cores, 2048 MiB per AVD, SwiftShader GPU, and
an explicit `-writable-system`. The reservation records 4300 MiB empirical RSS
per AVD (8600 MiB for the pair). CI may override only the closed values below:

```text
DTX_ANDROID_SYSTEM_IMAGE=system-images;android-35;aosp_atd;x86_64  # exact, not overridable
DTX_ANDROID_ACCELERATION=off|on
DTX_ANDROID_GPU=swiftshader_indirect|software|host
DTX_ANDROID_CORES=1..8
DTX_ANDROID_MEMORY_MIB=1536..8192
DTX_ANDROID_BOOT_TIMEOUT_SECONDS=30..900
DTX_ANDROID_AVD_RSS_MIB=3000..12000
DTX_ANDROID_TRUST_PROBE_DEX=/path/to/PlatformTrustProbe.dex
```

Build the fixed probe with the API 35 platform jar and Android `d8`, then pass
the resulting dex through `DTX_ANDROID_TRUST_PROBE_DEX`; the harness rejects a
missing, symlinked, or implicit probe path.

The writable-system prerequisite is fail-closed. Each emulator is mapped to
its recorded PID and exact AVD reply (`<name>` followed by a separate `OK`),
then `ro.kernel.qemu=1` and `id -u=0` are rechecked after every reboot or
reconnect. If the first `adb remount` disables verity, the harness reboots,
repeats those ownership gates, and requires the second remount plus a real
write probe under `/system/etc/security/cacerts`.

Before CA installation, each owned emulator connects to the fixed local node
endpoint and is expected to fail platform trust. After installation and reboot,
the same HTTPS connection is made by `HttpsURLConnection` in the fixed
`scripts/android-platform-trust-probe.java` probe. It uses the Android default
platform TrustManager and must print `TRUSTED`; no custom trust store,
hostname-verifier override, or insecure TLS flag is accepted.

The bootstrap CA is installed at its OpenSSL subject-hash filename and checked
for byte content, `0644`, `root:root`, and `u:object_r:system_file:s0` context.
Presence is rechecked after reboot. Cleanup removes the exact hash and pushed
temporary file, remounts `/system` read-only, removes reverse mappings, stops
owned processes, deletes both AVDs, and tears down only the owned Compose
project. A failed cleanup retains the private run record for diagnosis.

Run deterministic shell checks without launching an emulator:

```bash
bash scripts/test-android-acceptance.sh
```
