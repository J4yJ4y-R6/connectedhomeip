PQC (Kyber / Dilithium) integration notes
=======================================

This directory contains small stub scaffolding to enable adding a PQC backend (Kyber for KEM, Dilithium for signatures).

How to provide a real implementation

- Option A — Vendor / system library (recommended for development):
  - Build or install a PQC provider such as liboqs or a vendor-provided library that exposes POSIX-style linkable targets.
  - Add a GN target for the library (e.g. `//third_party/oqs:oqs`) that builds the library and exports a target name.
  - In `connectedhomeip/src/crypto/BUILD.gn` add the provider target to `cryptopal_pqc` `public_deps`.
  - Set `chip_crypto_pqc = true` (and `chip_external_pqc = true` if using an external tree) in GN args.

- Option B — pkg-config: provide a `.pc` file for your PQC library and update `BUILD.gn` to use `pkg_config()` and `public_configs` similarly to OpenSSL.

GN args example (in your top-level args.gn or gn args):

```
chip_crypto_pqc = true
chip_external_pqc = true
```

Example GN snippet to add a provider target (in this repo's third_party):

```
import("//build_overrides/xxx.gni")

static_library("oqs") {
  sources = [ ... ]
  public_configs = [ ":oqs_config" ]
}

# then in src/crypto/BUILD.gn:
source_set("cryptopal_pqc") {
  sources = [ "CHIPCryptoPALPQC.cpp", "CHIPCryptoPALPQC.h" ]
  public_deps = [ ":public_headers", "//third_party/oqs:oqs" ]
}
```

Important notes
- PQC signature and ciphertext sizes are significantly larger than P-256/ECDSA; you must audit message, CSR, and certificate size handling.
- Consider hybrid modes (classical + PQC) for compatibility and transitional deployments.
- The provided `CHIPCryptoPALPQC.*` files are stubs and return `CHIP_ERROR_NOT_IMPLEMENTED`. Replace calls with real library invocations.
