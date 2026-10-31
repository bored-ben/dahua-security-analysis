# Dahua P2P / SDK — Security Analysis & Hardening Audit

A defensive security‑research project on Dahua‑style IP cameras and NVRs:

1. **[A technical analysis](docs/dahua-p2p-security-analysis.md)** of the Dahua
   P2P cloud and SDK login protocols — how serial‑based cloud reachability works,
   how the layered MD5 login hashing is constructed, and how three already‑patched
   CVEs (CVE‑2021‑33044, CVE‑2021‑33045, CVE‑2024‑39943) fit into that
   architecture. Written to explain mechanism and defense, not to weaponize.

2. **[`cmd/dahua-audit`](cmd/dahua-audit)** — a small Go tool that checks a
   **single device you own** for the most common real‑world weakness: factory
   **default credentials** still being active on the web interface.

## Scope and ethics

This repository is for **defensive use on your own equipment** (or equipment you
have written authorization to test). It contains:

- **No** P2P / cloud reachability and **no** serial‑number enumeration.
- **No** exploitation of any CVE, no authentication bypass, no account creation.
- **No** mass or multi‑target capability — the audit tool handles exactly one
  `host:port` per run and refuses to start without an explicit ownership
  attestation.

The vulnerabilities discussed in the analysis are public and vendor‑patched; the
point of the write‑up is understanding and hardening, not attack.

## Build

```sh
go build ./cmd/dahua-audit
```

## Usage

```sh
# Check a camera you own on your LAN for default credentials:
./dahua-audit --target 192.168.1.108:80 --i-own-this-device

# HTTPS web interface:
./dahua-audit --target 192.168.1.108:443 --scheme https --i-own-this-device
```

The tool reports reachability and whether any well‑known Dahua factory‑default
credential pair is still accepted, then points you at the hardening checklist in
the analysis document. It will refuse ranges, lists, or serial numbers by design.

## Hardening summary

If you run Dahua gear, the high‑value steps (full list in
[the analysis, §6](docs/dahua-p2p-security-analysis.md#6-defensive-recommendations)):

1. Disable P2P / cloud access if you don't use it; reach cameras over a VPN.
2. Patch firmware — every CVE referenced here is already fixed upstream.
3. Replace default credentials with long, unique passwords.
4. Put cameras on an isolated VLAN; block TCP/37777 at the perimeter.
5. Audit local accounts and remove any you didn't create.

## Credits & attribution

This project builds on the original **[GhostCam](https://github.com/eekeri/GhostCam)**
by **eekeri ("badinteger")** (GPL‑3.0). The understanding of Dahua's P2P
signaling, the SDK login‑hash scheme, and the referenced CVEs that informs the
analysis here was derived from that original project — credit for the protocol
reverse‑engineering belongs to its author.

The defensive write‑up in [`docs/`](docs/dahua-p2p-security-analysis.md) and the
[`dahua-audit`](cmd/dahua-audit) hardening tool are original work and contain no
offensive capability. See [NOTICE](NOTICE) for full attribution.

## License

GPL‑3.0, as a derivative of the original GPL‑3.0 project. See [LICENSE](LICENSE).
