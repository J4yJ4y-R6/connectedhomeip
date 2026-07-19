# Running Matter with PQC Enabled

## Quick Start: PQC-Enabled Server

To build and run a Matter server with **Kyber-768 and Dilithium-3 support**:

```bash
cd /home/j4yj4y/master/connectedhomeip
source scripts/activate.sh

# Build with PQC enabled (includes real Kyber + Dilithium)
gn gen out/pqc_server --args='\
  chip_crypto="mbedtls" \
  chip_crypto_pqc=true \
  chip_external_pqc=false \
  target_os="linux" \
  target_cpu="x64" \
  chip_enable_dbus=false'

ninja -C out/pqc_server chip-tool

# Run the server
./out/pqc_server/chip-tool server
```

## What's Now Using PQC

When compiled with `chip_crypto_pqc=true`, the server includes:

✅ **Kyber-768** — Post-quantum Key Encapsulation Mechanism (KEM)
- Used for session key establishment alongside ECDH
- Ciphertext size: 1088 bytes
- Shared secret: 32 bytes

✅ **Dilithium-3** — Post-quantum Digital Signature
- Used for device attestation and message signing
- Signature size: 3293 bytes
- Public key size: 1952 bytes

✅ **Hybrid Mode** — Combines classical ECDH + quantum-safe Kyber
- Final session key = ECDH secret (32B) || Kyber secret (32B) = 64 bytes
- Backwards compatible: if peer doesn't support Kyber, falls back to ECDH alone
- Quantum-resistant even if ECDH is broken

## How It Works

### Session Establishment (CASE Protocol)

```
Initiator                         Responder
   |                               |
   |-------- Sigma 1 ------->|  (Send ephemeral ECDH + Kyber pubkeys)
   |                         |
   |<------- Sigma 2 --------|  (Send responder pubkeys + Kyber ciphertext)
   |                         |
   |-------- Sigma 3 ------->|  (Send confirmation)
   |
   v (Shared secret = ECDH || Kyber)
```

**Sigma 1** (Initiator → Responder):
- Initiator ephemeral ECDH public key (65 bytes)
- Initiator ephemeral Kyber public key (1184 bytes)
- Random nonce, session ID, etc.

**Sigma 2** (Responder → Initiator):
- Responder ephemeral ECDH public key (65 bytes)
- Responder ephemeral Kyber encapsulation ciphertext (1088 bytes)
- Encrypted certificate chain + Dilithium signature

**Sigma 3** (Initiator → Responder):
- Confirmation that key agreement succeeded

### Device Attestation

When provisioning or verifying device identity:

✅ **Certificate Signing** — Uses Dilithium instead of ECDSA
- Operational certificates signed with Dilithium-3
- NOC (Node Operational Certificate): 3293-byte signature
- Supports hybrid chains: Root → Intermediate → Device

✅ **Signature Verification** — All signatures verified with Dilithium
- Validates message authenticity using quantum-safe scheme
- Protects against future cryptanalytic breaks

## Protocol Compatibility

### PQC to PQC (Full quantum safety):
- Both peers support Kyber + Dilithium
- Session uses hybrid ECDH+Kyber key agreement
- Signatures verified with Dilithium
- ✅ Quantum-resistant

### PQC to Non-PQC (Graceful degradation):
- PQC server can communicate with ECDH-only clients
- Falls back to ECDH-only key agreement (no Kyber)
- Uses ECDSA signatures (no Dilithium)
- ⚠️ Classically secure but not quantum-resistant

### Forcing PQC-Only Mode (Future):
- Set `chip_crypto_pqc_mandatory=true` (not yet implemented)
- Rejects connections that don't support Kyber/Dilithium
- Ensures quantum-safe communications

## Verifying PQC is Active

Check that real crypto is compiled in (not stubs):

```bash
# Should show Kyber symbols from reference implementation
nm ./out/pqc_server/libChipCrypto.a | grep pqcrystals

# Should show Dilithium symbols from BoringSSL
nm ./out/pqc_server/libChipCrypto.a | grep DILITHIUM
```

Output shows functions like:
```
pqcrystals_kyber768_ref_keypair
pqcrystals_kyber768_ref_enc
pqcrystals_kyber768_ref_dec
```

## Performance Considerations

**Kyber Performance** (on typical x64 host):
- Keypair generation: ~1ms
- Encapsulation: ~1ms
- Decapsulation: ~1ms

**Dilithium Performance** (on typical x64 host):
- Keypair generation: ~5-10ms
- Signing: ~5-10ms per message
- Verification: ~2-5ms per signature

**Network Impact**:
- Sigma 1 message: ~1300 bytes (vs ~200 for ECDH-only)
- Sigma 2 message: ~1300 bytes (vs ~300 for ECDH-only)
- Certificate chain size: 3x larger (Dilithium signatures)

## Build Options Reference

| Flag | Value | Effect |
|------|-------|--------|
| `chip_crypto_pqc` | `true` / `false` | Enable PQC crypto layer |
| `chip_external_pqc` | `true` / `false` | Use system liboqs (true) vs vendored (false) |
| `chip_enable_dbus` | `true` / `false` | Enable D-Bus support (requires libglib2.0) |
| `target_os` | `linux` / `esp32` | Platform |
| `target_cpu` | `x64` / `arm64` / etc | CPU architecture |

## Example: Building for Different Platforms

### Linux x64 (Host/Development)
```bash
gn gen out/host_pqc --args='\
  chip_crypto="mbedtls" chip_crypto_pqc=true chip_external_pqc=false \
  target_os="linux" target_cpu="x64" chip_enable_dbus=false'
```

### Linux ARM64 (e.g., Raspberry Pi)
```bash
gn gen out/arm64_pqc --args='\
  chip_crypto="mbedtls" chip_crypto_pqc=true chip_external_pqc=false \
  target_os="linux" target_cpu="arm64" chip_enable_dbus=false'
```

### ESP32 (Embedded)
```bash
export IDF_PATH=/path/to/esp-idf
gn gen out/esp32_pqc --args='\
  chip_crypto="mbedtls" chip_crypto_pqc=true chip_external_pqc=false \
  target_os="esp32" target_cpu="x64"'
```

## Troubleshooting

### "gdbus-codegen not found"
→ Use `chip_enable_dbus=false` or install libglib2.0-dev

### Build fails with Kyber symbol errors
→ Ensure kyber-reference is available in workspace at: `../../../kyber-reference/`

### Build fails with Dilithium symbol errors  
→ Ensure BoringSSL is correctly configured: `third_party/boringssl/repo:boringssl`

### Crypto operations slow
→ Normal for first-time PQC operations. Performance improves with hardware acceleration (future work).

## Next Steps

1. **Run a basic server** — Try the quick start command above
2. **Commission a device** — Use `chip-tool` to join a Matter network
3. **Monitor performance** — Check `/memories/repo/pqc_performance.md` for benchmarks
4. **Test inter-operability** — Connect PQC and non-PQC devices to verify fallback

## References

- **Kyber**: https://pq-crystals.org/kyber/
- **Dilithium**: https://pq-crystals.org/dilithium/
- **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography/
