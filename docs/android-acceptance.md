# Android acceptance harness

The required Internal Test Alpha outcome is a real three-device scenario:
three clients provision and contact, complete Direct Pull+ACK, complete Group
invite/join/owner approval with B+C ACK, and retain the evidence bundle. That
scenario is not implemented by the current server-local harness.

## Current executable surface

`scripts/android-acceptance.sh` currently owns disposable emulator and
local-stack setup, platform-CA trust probing, and shell cleanup checks. It
terminates before the Direct/Group product scenario. It has no supported
three-serial or client-checkout interface, so these setup commands must not be
reported as full Internal Test acceptance:

```bash
bash scripts/android-acceptance.sh --run
bash scripts/test-android-acceptance.sh
```

The three-device Direct/Group runner, device/client wiring, and corresponding
evidence publication are a missing target capability. Until that capability is
implemented and independently evidenced, Android acceptance remains pending.

## Setup contract

The current setup uses two exact API 35 `aosp_atd` x86_64 disposable AVDs,
software acceleration (`-accel off`), two cores, 2048 MiB per AVD, SwiftShader
GPU, and explicit `-writable-system`. CI may override only these closed values:

```text
DTX_ANDROID_SYSTEM_IMAGE=system-images;android-35;aosp_atd;x86_64  # exact
DTX_ANDROID_ACCELERATION=off|on
DTX_ANDROID_GPU=swiftshader_indirect|software|host
DTX_ANDROID_CORES=1..8
DTX_ANDROID_MEMORY_MIB=1536..8192
DTX_ANDROID_BOOT_TIMEOUT_SECONDS=30..900
DTX_ANDROID_AVD_RSS_MIB=3000..12000
```

The setup harness compiles the checked-in Java trust probe in a private run
directory with the API 35 platform jar, JDK 17 `javac`, and SDK `d8`, then
validates the non-symlinked dex size and SHA-256. No caller-supplied dex or
probe path is accepted. Before CA installation each owned emulator must fail
platform trust; after installation and reboot the same `HttpsURLConnection`
probe must report `TRUSTED <nonce>` over the fixed local endpoint. Connect,
hostname, timeout, response, class, and lost-result failures are terminal.

CA installation is checked for byte content, `0644`, `root:root`, and
`u:object_r:system_file:s0` context, then rechecked after reboot. Cleanup
removes only the owned CA, reverse mappings, processes, run record, and
disposable stack; a failed cleanup retains the private run record.

These setup and shell checks are useful boundary evidence, but they cannot
substitute for the missing three-device Direct/Group runner.
