# Building & Running Matter lighting-app on ESP32 with PQC-hybrid CASE

This guide covers how to build and flash the Matter `lighting-app` example to
an ESP32, and commission/control it with `chip-tool`, with the post-quantum
hybrid CASE handshake from this branch (`pqc-integration`) active on both
sides.

It's written as a corrected companion to `PQC_NOW_ACTIVE.md` / `PQC_USAGE.md`
at the repo root — those docs overstate the current state (they claim a
"real, production-ready" implementation backed by BoringSSL's Dilithium).
What's actually true, verified against the code:

## What the PQC integration actually does

- `src/protocols/secure_channel/CASESession.cpp` (guarded by
  `#if CHIP_CRYPTO_PQC`) layers **Kyber-768 KEM** and **Dilithium-3
  signatures** additively onto the classical ECDH/ECDSA CASE handshake
  (Sigma1/2/3). Both peers advertise Kyber pubkeys and Dilithium
  signatures as new *optional* TLV tags — a non-PQC peer still
  interoperates fine, just without the PQC contribution.
- The resulting session key mixes in the PQC shared secret:
  `SHA-256(ECDH_secret || Kyber_secret)` replaces the ECDH-only secret used
  for all downstream HKDF derivation.
- **This only covers CASE** — the operational session established at the
  final `CommissioningComplete` step, and every later reconnect. It does
  **not** touch PASE (the initial BLE/passcode commissioning channel) or
  NOC/DAC certificate verification (`CHIPCryptoPALmbedTLSCert.cpp` is
  untouched) — those remain fully classical.
- The crypto backend is **not** BoringSSL. `third_party/oqs/BUILD.gn`
  compiles the real Kyber-768 and Dilithium-3 **pq-crystals reference
  implementations** from two sibling directories outside this repo:
  `../../../kyber-reference` and `../../../dilithium-reference` (relative to
  `third_party/oqs/`, i.e. `/home/j4yj4y/master/kyber-reference` and
  `/home/j4yj4y/master/dilithium-reference` on this machine). This is **not
  self-contained** — a plain clone of connectedhomeip alone will fail to
  build with `chip_crypto_pqc=true` unless those directories are present
  alongside it. On this machine they already exist, with `KYBER_K=3` /
  `DILITHIUM_MODE=3` (Kyber-768 / Dilithium-3), matching the sizes hardcoded
  in `src/crypto/CHIPCryptoPALPQC.h`.
- `config/esp32/components/chip/CMakeLists.txt` forces
  `chip_crypto_pqc=true` for **every** ESP32 example app. Only
  `examples/lighting-app/esp32/CMakeLists.txt` additionally force-defines
  `-DCHIP_CRYPTO_PQC=1` globally across *all* ESP-IDF components (not just
  the GN-built CHIP lib) and bumps `sdkconfig.defaults` (mbedTLS TLS buffers
  to 16 KB, task stacks to 8 KB) to fit the much larger Sigma messages
  (Dilithium sig + pubkey alone is ~5 KB). Other ESP32 examples get the GN
  flag forced on without the matching global define/buffer bumps, which
  risks a struct-layout mismatch between the CHIP lib and other components
  that include `CASESession.h` — **use lighting-app**, not another example,
  until that's fixed upstream.

There's also a proven **host-side (Linux) reference build** already present
at `out/pqc_host/` in this checkout (`chip_crypto="mbedtls"
chip_crypto_pqc=true chip_external_pqc=false target_os="linux"
target_cpu="x64"`), containing a working `chip-tool` built with the same PQC
flags. This guide reuses/refreshes that rather than re-deriving GN args.

## 1. Install ESP-IDF

No ESP-IDF install was found on this machine (`idf.py` not in `PATH`,
`IDF_PATH` unset). Matter's own environment (`scripts/bootstrap.sh`) has
already been bootstrapped in this repo, so only ESP-IDF itself is needed:

```bash
git clone -b v5.5.1 --recursive --depth 1 --shallow-submodule \
  https://github.com/espressif/esp-idf.git ~/esp-idf
cd ~/esp-idf && ./install.sh
```

v5.5.1 is the documented/supported version for this SDK. Avoid ESP-IDF ≥
v6.0 for now — `config/esp32/components/chip/CMakeLists.txt` switches the
crypto backend to PSA Crypto on IDF ≥ v6.0, which is an untested combination
with this PQC branch.

## 2. Activate environments (every new shell)

```bash
source ~/esp-idf/export.sh
source /home/j4yj4y/master/connectedhomeip/scripts/activate.sh
export IDF_CCACHE_ENABLE=1
```

## 3. Build lighting-app for ESP32

```bash
cd /home/j4yj4y/master/connectedhomeip/examples/lighting-app/esp32
idf.py set-target esp32
idf.py build
```

PQC is already force-enabled for this target — no extra flags needed. If the
build can't find the Kyber/Dilithium reference sources, confirm
`/home/j4yj4y/master/kyber-reference` and
`/home/j4yj4y/master/dilithium-reference` still exist (see "What the PQC
integration actually does" above for why those paths matter).

## 4. Flash and monitor

```bash
idf.py -p /dev/ttyUSB0 erase_flash
idf.py -p /dev/ttyUSB0 flash monitor
```

Adjust `/dev/ttyUSB0` to your device's actual serial port. `Ctrl+]` exits the
monitor.

Watch the serial log for `[PQC]`-tagged lines once commissioning starts
(e.g. `CASE Sigma1: generating Kyber-768 initiator keypair`) — these confirm
the hybrid handshake is actually running on-device rather than silently
falling back to classical-only.

## 5. Build/refresh chip-tool with matching PQC support

Both sides of a CASE handshake need `CHIP_CRYPTO_PQC` enabled to actually
exercise the Kyber/Dilithium path (it's optional/additive, so a
classical-only `chip-tool` would still interoperate — it just wouldn't do
the PQC exchange). Reuse the existing proven build:

```bash
cd /home/j4yj4y/master/connectedhomeip
ninja -C out/pqc_host chip-tool
```

Or build clean if you'd rather not reuse it:

```bash
scripts/examples/gn_build_example.sh examples/chip-tool out/chip-tool-pqc \
  "chip_crypto=\"mbedtls\"" "chip_crypto_pqc=true" "chip_external_pqc=false" \
  "target_os=\"linux\"" "target_cpu=\"x64\""
```

## 6. Commission the device (BLE + Wi-Fi)

```bash
out/pqc_host/chip-tool pairing ble-wifi 1 <YOUR_WIFI_SSID> <YOUR_WIFI_PASSWORD> 20202021 3840
```

Node id `1`, setup PIN `20202021`, discriminator `3840` are the standard
Matter example defaults — `examples/lighting-app/esp32/sdkconfig.defaults`
doesn't override them.

## 7. Control it

```bash
out/pqc_host/chip-tool onoff on 1 1
out/pqc_host/chip-tool onoff off 1 1
```

## 8. Verify PQC actually engaged

Cross-check `[PQC]`-tagged log lines on **both** sides:

- **ESP32 serial monitor** (device/responder side): Kyber keypair
  generation, Kyber decapsulation, Dilithium sign/verify, and the final
  `"mixed Kyber-768 shared secret into session-key input material"` line.
- **chip-tool stdout** (controller/initiator side): the mirrored
  Kyber/Dilithium log lines (`ChipLogProgress` output is visible by
  default, no extra verbosity flags needed).

These `[PQC]` lines only appear during the CASE handshake — i.e. at the
`CommissioningComplete` step and on later reconnects, not during the initial
BLE/PASE pairing. If they never appear:

- Confirm the flashed binary was actually rebuilt after the PQC commit
  (`idf.py build` should have picked up `-DCHIP_CRYPTO_PQC=1`).
- Confirm `out/pqc_host/chip-tool` is the freshly-ninja'd binary from step 5,
  not a stale one predating this commit.

## Known limitations (accurate as of this branch)

- PASE and certificate/attestation chains (NOC, DAC, PAA) are unaffected —
  fully classical ECDH/ECDSA. Only the CASE operational session gets the
  PQC overlay.
- The Kyber/Dilithium reference-implementation sources live outside this
  repo (sibling directories, not a git submodule) — not reproducible from a
  clean `git clone` of connectedhomeip alone.
- Non-lighting-app ESP32 examples get `chip_crypto_pqc=true` forced on
  without the matching global define/buffer bumps that lighting-app has;
  avoid them for PQC testing until that's fixed.
- No CI coverage: the PQC unit tests in `TestChipCryptoPAL.cpp`
  (`TestDilithium_SignVerify`, `TestKyber_EncapsulateDecapsulate`) are
  skipped unless `CHIP_CRYPTO_PQC` is defined, and CI doesn't build with
  that flag.
