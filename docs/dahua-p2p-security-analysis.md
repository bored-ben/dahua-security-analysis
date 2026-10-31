# Dahua P2P Cloud & SDK Protocol — A Security Analysis

> **Scope & ethics.** This document is a defensive security analysis written from
> study of Dahua's publicly documented P2P/SDK behaviour and already‑published
> CVEs. It describes *mechanisms and impact* so that owners and defenders can
> assess and harden their own devices. It intentionally contains **no working
> exploit code, payloads, or step‑by‑step compromise instructions**, and nothing
> here should be used against devices you do not own or lack written authorization
> to test. The vulnerabilities discussed were assigned CVEs and patched by the
> vendor; the value here is in understanding *why* they happened and how to defend.

---

## 1. Why this is interesting

Most "camera security" write‑ups stop at "the device had default credentials."
The more interesting story for Dahua's ecosystem is **architectural**: the P2P
cloud makes a device reachable *by serial number* from anywhere on the internet,
without the attacker ever needing the device's IP address or an open inbound
port. That single design choice changes the threat model more than any individual
bug, because it removes the usual friction (IP scanning, NAT traversal) between an
attacker and millions of devices.

This analysis walks the stack from the cloud rendezvous down to the device login
protocol, then looks at the published CVEs in that context, and ends with concrete
hardening and detection guidance.

---

## 2. The P2P cloud architecture

Dahua devices with "P2P" enabled register themselves with a set of vendor‑operated
rendezvous servers using a **device serial number** as their global identity. A
client that wants to reach a device asks the rendezvous infrastructure for that
serial; the infrastructure helps the two sides establish a tunnel, either:

- **Direct (hole‑punched) P2P** — the server coordinates a UDP hole punch so the
  client and device talk directly, or
- **Relayed** — when direct traversal fails, traffic is relayed through vendor
  infrastructure.

Security‑relevant consequences:

1. **Identity is a serial number, not a network location.** Serials are
   structured (a fixed vendor/model *prefix* plus a sequential *suffix*). The
   suffix space per prefix is small enough to enumerate. Reachability therefore
   scales with *guessing serials*, not with scanning IP ranges — a qualitatively
   easier problem for an attacker and a qualitatively harder one for a defender who
   assumes "I'm not port‑forwarded, so I'm safe."
2. **The cloud is in the trust path.** The rendezvous layer brokers who can reach
   whom. Weaknesses in that brokering (or in the on‑device services it exposes)
   have internet‑wide blast radius.

### 2.1 Signaling authentication (DHP2P)

The P2P signaling channel authenticates with a WSSE‑style `UsernameToken`: a SHA‑1
digest over `nonce + created + "DHP2P:" + username + userkey`. In practice the
*client‑side* username/userkey used to talk to the rendezvous layer are **static,
embedded constants** shared across the ecosystem rather than per‑user secrets:

```
Username : cba1b29e32cb17aa46b8ff9e73c7f40b
UserKey  : 996103384cdf19179e19243e959bbf8b
```

Hardcoded shared secrets in a signaling layer mean the "authentication" on that
layer gates nothing an attacker can't trivially satisfy — a recurring pattern in
embedded device ecosystems, and a useful **detection signature** (see §6).

---

## 3. The on‑device protocols

Once a tunnel exists, the device exposes the same services it would on a LAN:

### 3.1 CGI / web (HTTP)

The web management interface authenticates with **HTTP Digest**. Digest avoids
sending the cleartext password, but it does nothing about *weak or default*
passwords, and the challenge/response can be replayed within a nonce's lifetime.

### 3.2 SDK binary protocol (TCP/37777)

The native "SDK" port speaks a length‑prefixed binary protocol with an MD5‑based
challenge‑response login. Reconstructing it from observed traffic shows three
hashing primitives layered together:

- **`StandardRPCHash`** — the standard digest‑style construction:
  `MD5( user : random : MD5(user:realm:pass) )`, uppercased hex.
- **`Gen1Hash`** — a vendor‑specific reduction of `MD5(password)` down to an
  8‑character alphanumeric string. Collapsing a 128‑bit hash into ~48 bits of
  alphabet‑restricted output **reduces entropy** and makes offline guessing of the
  derived value easier than the password length would suggest.
- **`SDKLoginHash`** — concatenates the standard hash with a second block derived
  from `Gen1Hash`, producing the final login token.

The takeaway is not "here's how to log in" — it's that a **weak, custom hash
reduction** sits beside a standard one. Home‑grown cryptographic reductions like
`Gen1Hash` are a classic source of weakness and worth flagging in any review of
embedded auth.

---

## 4. The published vulnerabilities, in context

All three are **already assigned and patched**. They are discussed here only to
explain impact and defense.

| CVE | Class | Impact (high level) | Fixed by |
|-----|-------|---------------------|----------|
| **CVE‑2021‑33044** | Identity authentication bypass | A crafted login flow is accepted without valid credentials, allowing unauthenticated access / credential disclosure on affected firmware. | Vendor firmware update (2021). |
| **CVE‑2021‑33045** | Identity authentication bypass | Companion bypass in the same family; same practical impact. | Vendor firmware update (2021). |
| **CVE‑2024‑39943** | Improper authorization | On affected builds an authenticated/authorization flaw allows actions beyond the caller's intended privilege. | Vendor firmware update (2024). |

Two structural themes connect them:

1. **Authentication‑bypass bugs are catastrophic over P2P.** A bypass that would
   require LAN access on a well‑segmented camera becomes internet‑wide when the
   same service is reachable by serial through the cloud.
2. **Patched ≠ fixed in the field.** Consumer/SMB cameras are rarely updated.
   Years‑old CVEs remain exploitable at scale not because they're unknown but
   because deployment hygiene is poor. That is the real, *disclosable* story — and
   it's a deployment/lifecycle problem, not a new vulnerability.

### 4.1 On "reporting this to the vendor"

Because these CVEs are public and patched, there is nothing novel to disclose to
Dahua about them. A responsible‑disclosure report only makes sense if a **new**
issue is found — for example a patch bypass, a weakness in the P2P rendezvous
brokering itself, or a serial‑enumeration/rate‑limiting gap in the cloud. If you
believe you've found something new, see §7.

---

## 5. Why serial enumeration is the systemic risk

Combine the pieces:

- Devices are addressable by a **guessable serial**, not an IP.
- The **cloud will help you reach** any live serial.
- A meaningful fraction of fielded devices run **unpatched firmware** and/or
  **default credentials**.

The result is that the *population* is exposed even though each individual owner
believes their device is "behind NAT." The correct mitigations therefore live at
two levels: **the vendor's cloud** (rate‑limiting, anomaly detection, and
authenticated device‑to‑owner binding) and **the owner's configuration**
(disable P2P, patch, set strong credentials). The second is the only one an
individual can control — which is what the audit tool in this repository checks.

---

## 6. Defensive recommendations

**For device owners / operators**

1. **Disable P2P / "cloud access" if you don't use it.** This removes the
   serial‑reachability path entirely. Reach your cameras over a VPN instead.
2. **Patch firmware.** Every CVE above is fixed in current firmware.
3. **Replace default credentials** with long, unique passwords. Disable or rename
   the stock `admin`/`888888`/`666666` accounts where the firmware allows it.
4. **Segment the network.** Put cameras on an isolated VLAN with no outbound
   internet except what's strictly required; block TCP/37777 at the perimeter.
5. **Audit for unexpected accounts.** A device that was compromised via an
   authorization bug may have had extra accounts added — enumerate local users and
   remove anything you didn't create.

**For defenders / blue teams (detection ideas)**

- Alert on outbound connections to known Dahua P2P rendezvous infrastructure from
  segments where cloud access should be disabled.
- The **static WSSE username** (`cba1b29e…`) and the `DHP2P:` digest construction
  are fingerprintable on the wire and in logs.
- Watch for **new local accounts** on NVR/camera management interfaces and for
  logins immediately following firmware‑version‑specific request patterns.

---

## 7. Responsible disclosure

If you discover something genuinely new (a patch bypass or a cloud‑side flaw):

1. Do **not** test it against devices you don't own. Reproduce only on your own
   hardware.
2. Report to the vendor's PSIRT (Dahua maintains a security contact / advisory
   page) with a clear technical description and affected versions, and give them a
   reasonable remediation window before any public write‑up.
3. Request a CVE through the vendor or a CNA.
4. Publish the analysis — not a weaponized tool — once a fix is available.

---

## 8. What a portfolio reader should take from this

The engineering worth showcasing here is: reconstructing a multi‑layer proprietary
protocol (cloud signaling → tunnel → binary SDK login) from observation,
recognizing a weak custom hash reduction, and reasoning about how an architectural
choice (serial‑based cloud reachability) amplifies otherwise‑ordinary bugs into a
population‑scale risk. That analysis — plus the single‑device hardening checker in
[`cmd/dahua-audit`](../cmd/dahua-audit) — is the defensible, publishable form of
this work.
