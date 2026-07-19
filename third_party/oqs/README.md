# Vendored liboqs Integration for Matter PQC Support

This directory provides a minimal stub and GN build integration for liboqs (Open Quantum Safe library).

## Quick Start

To enable Kyber (KEM) and Dilithium (signatures) in Matter:

```bash
cd connectedhomeip
source scripts/activate.sh

# Build host with PQC enabled using vendored stub
gn gen out/pqc_host --args='chip_crypto="mbedtls" chip_crypto_pqc=true chip_external_pqc=false target_os="linux" target_cpu="x64"'
ninja -C out/pqc_host crypto
```

## File Structure

- `include/oqs/oqs.h` — Minimal header exposing liboqs KEM and SIG APIs
- `stub/oqs_stub.c` — Stub implementations that return failure codes
- `BUILD.gn` — GN target exporting `include/` to dependent targets

## Using Real liboqs

To build with actual post-quantum crypto:

1. **Clone upstream liboqs** and place sources in `repo/` (or wherever your build expects them):
   ```bash
   cd third_party/oqs
   git clone https://github.com/open-quantum-safe/liboqs.git repo
   ```

2. **Update `stub/oqs_stub.c`** with real implementations or link against liboqs shared/static library:
   - Build liboqs (`./liboqs/scripts/build_linux.sh` or similar).
   - Modify `BUILD.gn` to compile liboqs sources or link pre-built libraries.
   - Replace stub implementations in `stub/oqs_stub.c` with actual liboqs function calls.

3. **Test the build**:
   ```bash
   gn gen out/pqc_real --args='chip_crypto="mbedtls" chip_crypto_pqc=true chip_external_pqc=false target_os="linux" target_cpu="x64"'
   ninja -C out/pqc_real crypto
   ```

## Algorithms Supported (in this integration)

- **Kyber-768** — NIST Level 3 KEM, used for key establishment (replaces ECDH)
- **Dilithium-3** — NIST Level 3 signature scheme (replaces ECDSA-P256)

## Known Limitations

- **Stub implementations return failure** (all OQS_KEM/OQS_SIG functions in `oqs_stub.c` return -1).
- **CSR/X.509 paths** in Matter currently validate for ECDSA only. To support Dilithium certificates:
  - Add Dilithium OIDs to `src/crypto/CHIPCryptoPALmbedTLSCert.cpp`.
  - Implement Dilithium signature parsing/verification in CSR/cert validation code.
  - Update certificate size buffers and ASN.1 encoding (Dilithium sigs are ~3300 bytes vs ECDSA 64 bytes).

## GN Build Arguments

- `chip_crypto_pqc=true` — Enable PQC crypto backend (adds sources, creates `cryptopal_pqc` target)
- `chip_external_pqc=true` — Use system `liboqs` via pkg-config; `false` → vendor from `//third_party/oqs:oqs`

See also: [PQC_README.md](../src/crypto/PQC_README.md) for architecture overview.
