# GridCrypt-PKI (SubstationShield-PKI)

An enterprise/defense-grade Air-Gapped Substation Cryptographic Signing, Authentication & PKI Gateway. Engineered for Tier-1 Energy Utilities (TSOs/DSOs), Nuclear/Hydro Power Plants, and Military Defense Grids to cryptographically sign, authenticate, and enforce Zero-Trust validation on SCADA and Telecontrol protocols.

Strictly compliant with **IEC 62351-3/5/8** standards and **NERC-CIP** reliability requirements in completely air-gapped environments without introducing telemetry packet latency (<100μs per packet).

## 🚀 3-Line Quickstart

```rust
use gridcrypt_community::proxy::Iec104Interceptor;

// 1. Initialize the Zero-Allocation Air-Gapped Interceptor
let proxy = Iec104Interceptor::new(b"enterprise-scada-secret-key");

// 2. Intercept IEC 60870-5-104 APDU Command (e.g., C_SC_NA_1 Breaker Trip)
let packet = &[
    0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, // APCI (I-Frame)
    0x2D, 0x01, 0x03, 0x00, 0x01, 0x00, // ASDU (Type 45)
]; 

// 3. Verify hardware cryptographic signature (<100µs latency)
let is_valid = proxy.verify_packet(packet, &[0u8; 32]).is_ok();
```

## ⚖️ Dual-Licensing Model

This project follows an Open-Core / Dual-Licensing model:

| Feature | Community Edition (AGPLv3) | Utility Enterprise Tier |
|---------|---------------------------|-------------------------|
| **Core IEC 104 Interceptor** | ✅ Yes | ✅ Yes |
| **Zero-Allocation (no_std)** | ✅ Yes | ✅ Yes |
| **Cryptography** | Software HMAC (SHA256) | Hardware HSM/TPM 2.0 Acceleration |
| **Latency / Throughput** | ~1,000 pkts/sec | Sub-100µs Hardware Offload |
| **Compliance** | Basic | NERC-CIP, IEC 62351-3/5/8 |
| **Offline PKI (Air-Gapped)** | ❌ No | ✅ Yes (X.509, Offline CRL) |
| **Audit Logging** | ❌ No | ✅ Yes (BLAKE3 Tamper-Proof Log) |

## 💎 Get the Enterprise Tier (Proprietary B2B License)

The proprietary defense & utility enterprise license provides hardware cryptoprocessor integration (PKCS#11), IEC 62351 compliance, and NERC-CIP tamper-proof auditing for strictly air-gapped grids.

[**Purchase Enterprise License via Polar.sh ($300,000 - $800,000/year)**](https://polar.sh/)

### Author & Copyright Metadata
- **Author:** Emirhan CAMCI
- **Email:** byemir@live.com
- **Year:** 2026
- **Open Source License:** AGPLv3 (Community)
- **Commercial License:** Proprietary Utility & Defense Enterprise License (Enterprise)

## 🏗 Architecture & Offline Attestation

GridCrypt-PKI utilizes offline Ed25519 asymmetric cryptography to validate enterprise licenses strictly **on-device** without phoning home to external servers. This guarantees full compliance for air-gapped defense networks.
