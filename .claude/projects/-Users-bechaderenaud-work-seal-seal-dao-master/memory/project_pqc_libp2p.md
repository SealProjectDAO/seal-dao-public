---
name: PQC libp2p fork
description: Vendorize and modify libp2p for full PQC support — peer IDs, key exchange, signatures
type: project
---

TODO: Fork and vendorize libp2p with full PQC modifications:
- Peer IDs: ML-DSA public keys (replace Ed25519)
- Key exchange: ML-KEM-768 (replace X25519 in Noise)
- Signatures: ML-DSA-65 (replace Ed25519 in Noise XX handshake)
- Transport encryption: derive symmetric key from ML-KEM shared secret

**Why:** Current libp2p uses classical crypto for transport and identity. Our ML-KEM application layer is a stopgap. A full PQC libp2p is needed for mainnet.

**How to apply:** Fork libp2p into vendor/, modify libp2p-noise + libp2p-core identity. Track upstream for eventual native PQC support. Document all changes for auditability.
