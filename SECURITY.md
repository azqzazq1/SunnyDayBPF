# Security Policy

## Purpose

SunnyDayBPF is a security research project focused on **post-syscall user-buffer telemetry deception** and telemetry integrity analysis on Linux systems.

This repository is published for:

- authorized security research
- defensive detection engineering
- telemetry integrity analysis
- controlled lab experimentation
- academic and educational review
- understanding eBPF-related observability risks

SunnyDayBPF is **not** intended for unauthorized deployment, stealth persistence, production abuse, or bypassing security controls on systems without explicit permission.

---

## Supported Scope

Security reports are welcome for issues related to this repository, including:

- unsafe PoC behavior
- documentation that could be misleading or harmful
- accidental exposure of sensitive implementation details
- reproducibility issues in controlled lab environments
- incorrect assumptions in the threat model
- detection or mitigation improvements
- bugs in lab-only PoC code
- issues in diagrams, documentation, or citation metadata

---

## Out of Scope

The following are out of scope for this repository:

- requests to weaponize the PoC
- requests to bypass a specific EDR, SIEM, or security product
- requests to target third-party systems
- persistence mechanisms
- credential theft
- destructive payloads
- stealth deployment methods
- production abuse guidance
- evasion instructions against real organizations
- instructions for unauthorized use

---

## Responsible Use

All experiments should be performed only in environments where you have explicit authorization.

Acceptable environments include:

- your own local lab
- intentionally vulnerable test systems
- research VMs
- internal security labs
- systems where you have written permission to test
- educational sandbox environments

Do not run this project against systems you do not own or do not have permission to test.

---

## Reporting Security Issues

If you discover a security issue in this repository, please report it responsibly.

Preferred contact:

- LinkedIn: [linkedin.com/in/azqzazq](https://www.linkedin.com/in/azqzazq)
- GitHub: [github.com/azqzazq1](https://github.com/azqzazq1)

When reporting an issue, please include:

```text
Issue type:
Affected file:
Impact:
Reproduction steps:
Suggested fix:
Whether the issue affects only lab usage or broader research safety:
```

Please avoid publicly posting exploit-enhancing details before they can be reviewed.

---

## Disclosure Expectations

This project does not claim to disclose a vulnerability in a specific vendor product.

SunnyDayBPF is a research technique that explores a class of telemetry integrity risks involving eBPF, syscall return paths, and user-space telemetry consumers.

If you believe this research impacts a specific vendor product, please follow that vendor's responsible disclosure process.

---

## Research Safety

The public materials in this repository should remain focused on:

- telemetry integrity
- defensive implications
- detection engineering
- trust boundary analysis
- controlled lab reproduction
- conceptual understanding

The repository should avoid publishing materials whose primary purpose is:

- unauthorized evasion
- stealth deployment
- persistence
- credential access
- destructive behavior
- targeting named third-party environments

---

## PoC Safety Notice

Any proof-of-concept code in this repository is intended for controlled lab use only.

The PoC should be treated as a research artifact demonstrating a telemetry integrity concept, not as a production-ready tool or offensive framework.

Before running any PoC:

```text
1. Use an isolated lab system.
2. Understand what the code does.
3. Do not run it on production systems.
4. Do not run it against third-party systems.
5. Ensure you have explicit authorization.
6. Review kernel, eBPF, and BCC requirements.
7. Monitor and clean up loaded programs after testing.
```

---

## Defensive Recommendations

Defenders reviewing SunnyDayBPF should consider:

- monitoring loaded eBPF programs
- restricting BPF capabilities in production
- auditing unexpected tracepoint, kprobe, fentry, fexit, or LSM attachments
- monitoring helpers capable of writing into user memory
- correlating user-space telemetry with independent kernel-level sources
- validating telemetry pipelines across multiple sources
- hardening telemetry agents
- applying least privilege to monitoring components
- reviewing BPF-related kernel hardening options
- maintaining an allowlist of expected BPF programs

---

## Security Philosophy

SunnyDayBPF is based on a simple defensive question:

```text
Can defenders trust telemetry after it has crossed into a user-space collector?
```

The purpose of this research is to help defenders reason about telemetry trust boundaries, not to encourage misuse.

---
