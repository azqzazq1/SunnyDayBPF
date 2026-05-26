# SunnyDayBPF

**SunnyDayBPF** is an eBPF-based **post-syscall user-buffer telemetry deception** research technique originally proposed and researched by **Azizcan Dastan**.

The technique investigates whether data observed by user-space security, logging, or telemetry agents can be altered **after a read-like syscall has completed**, but **before the agent parses, analyzes, or forwards that data** to a downstream security pipeline.

The core idea is:

> The event still happens.  
> The monitoring agent still reads data.  
> But the data observed by the agent may no longer fully represent the original event.

SunnyDayBPF focuses on the gap between **ground truth** and **observed telemetry**.

---

## Architecture (v2.1)

```text
                          SunnyDayBPF Hook Points
                          ========================

  Telemetry Agent Process
  +---------------------------------------------------------+
  |                                                         |
  |   read()          pread64()         recvfrom()          |
  |     |                |                  |               |
  +-----|----------------|------------------|---------------+
        |                |                  |
  ======|================|==================|======= KERNEL BOUNDARY
        |                |                  |
   kprobe:ksys_read  kprobe:__x64_sys_  kprobe:__sys_
   (save buf ptr)    pread64            recvfrom
        |            (nested pt_regs)   (save buf ptr)
        |            (save buf ptr)         |
        v                v                  v
   [syscall executes — data enters user buffer]
        |                |                  |
   kretprobe         kretprobe          kretprobe
        |                |                  |
        +--------+-------+---------+--------+
                 |                 |
          read buffer into     initialize
          BPF scratch space    scan_state
                 |
                 v
        +------------------+
        | TAIL CALL CHAIN  |
        |                  |
        | scan_g0: SECURITY (4 rules, scan=177 bytes)
        | scan_g1: SECURITY (4 rules, scan=173 bytes)
        | scan_g2: SEVERITY (4 rules, scan=177 bytes)
        | scan_g3: SEVERITY (1 rule,  scan=251 bytes)
        | scan_g4: PATH     (4 rules, scan=132 bytes)
        | scan_g5: AUTH     (4 rules, scan=190 bytes)
        | scan_g6: AUTH     (1 rule,  scan=249 bytes)
        | scan_g7: NETWORK  (3 rules, scan=249 bytes)
        | scan_g8: PROCESS  (4 rules, scan=173 bytes)
        | scan_g9: CUSTOM   (2 rules, scan=243 bytes)
        |                  |
        | emit_event:      |
        |   perf event     |
        |   + stats        |
        +------------------+
                 |
                 v
        bpf_probe_write_user()
        (modify agent's buffer)
                 |
                 v
        read-back verification
        (confirm write succeeded)
                 |
                 v
        Agent continues with
        modified data
```

### Syscall Coverage

| Syscall | Kernel Hook | Arg Extraction | Coverage |
|---------|------------|----------------|----------|
| `read()` | `ksys_read` | `PT_REGS_PARM2` (direct) | File reads, pipes, `/proc`, log files |
| `pread64()` | `__x64_sys_pread64` | Nested `pt_regs` via `bpf_probe_read_kernel` (offset 104/RSI) | Random-access file reads, journald |
| `recvfrom()` | `__sys_recvfrom` | `PT_REGS_PARM2` (direct) | Network sockets, syslog forwarding |

### BPF Verifier Constraints

The BPF verifier enforces a jump sequence limit of 8,192 conditional branches per program. SunnyDayBPF works around this using:

- **BPF tail calls** (`BPF_PROG_ARRAY`): 31 rules split across 10 independent programs, each with its own verifier budget
- **Case-insensitive optimization**: `(d[i]|32)==lower` reduces jumps per byte from 2 to 1 for alphabetic characters
- **Dynamic scan limits**: Each group's scan window is computed as `min(BUF_SIZE - max_pat, 7800 / jumps_per_iter)` to stay within verifier limits
- **Per-CPU arrays**: `BPF_PERCPU_ARRAY` for scratch buffer and scan state, shared across tail-called programs

---

## Overview

Modern Linux security systems often rely on user-space agents that collect telemetry from files, sockets, pipes, APIs, kernel interfaces, or event streams.

These agents may forward telemetry to:

- SIEM platforms
- EDR/XDR backends
- audit pipelines
- log collectors
- runtime security engines
- detection engineering systems
- observability platforms

A common assumption is:

```text
actual system behavior == collected telemetry == observed security data
```

SunnyDayBPF challenges that assumption.

The research explores a post-syscall deception model where a monitoring process receives data normally, but the buffer containing that data is modified before the process consumes it.

```text
actual system behavior != observed telemetry
```

---

## Technical Definition

SunnyDayBPF is a post-syscall telemetry deception technique that studies the manipulation of user-space buffers belonging to selected telemetry-consuming processes.

At a high level, the technique follows this model:

```text
sys_enter_*:
    identify a target telemetry-consuming process
    record the user-space buffer pointer involved in the read-like operation

sys_exit_*:
    verify that the read-like operation completed successfully
    inspect the returned user-space buffer
    selectively alter telemetry-relevant content
    verify write success via read-back
    allow the target process to continue execution normally
```

This creates a mismatch between:

```text
what happened on the system
```

and:

```text
what the monitoring agent later observes, parses, and forwards
```

---

## Targeted Agents (28 Verified)

SunnyDayBPF identifies target processes by 5-character command name prefix matching.

### SIEM / Log Collection

| Agent | Prefix | Read Method | Effective? |
|-------|--------|-------------|------------|
| **Wazuh** | `wazuh` | `read()` on log files, syslog, audit logs | Yes |
| **OSSEC** | `ossec` | `read()` on log files | Yes |
| **Splunk UF** | `splun` | `read()` on monitored files | Yes |
| **Elastic Agent** | `elast` | `read()` on log sources | Yes |
| **Datadog Agent** | `datad` | `read()` on logs and metrics | Yes |
| **Cribl** | `cribl` | `read()` for log routing | Yes |

### Log Forwarding

| Agent | Prefix | Read Method | Effective? |
|-------|--------|-------------|------------|
| **rsyslog** | `rsysl` | `read()` / `recvfrom()` on syslog | Yes |
| **syslog-ng** | `syslo` | `read()` / `recvfrom()` on syslog | Yes |
| **Filebeat** | `fileb` | `read()` on log files | Yes |
| **Fluent-bit** | `fluen` | `read()` / `recvfrom()` on inputs | Yes |
| **Fluentd** | `fluen` | `read()` / `recvfrom()` on inputs | Yes |
| **Logstash** | `logst` | `read()` / `recvfrom()` on pipeline | Yes |
| **Promtail** | `promt` | `read()` on log files (Loki) | Yes |
| **Vector** | `vecto` | `read()` on log sources | Yes |

### Runtime Security

| Agent | Prefix | Read Method | Effective? |
|-------|--------|-------------|------------|
| **Falco** | `falco` | eBPF events collected via `read()` on perf buffer | Yes |
| **osquery** | `osque` | `read()` on `/proc`, log files, system tables | Yes |

### Network Security

| Agent | Prefix | Read Method | Effective? |
|-------|--------|-------------|------------|
| **Snort** | `snort` | `recvfrom()` on packet capture | Yes |
| **Suricata** | `suric` | `recvfrom()` on packet capture | Yes |
| **Zeek** | `zeek_` | `recvfrom()` on packet capture | Yes |

### System Monitoring

| Agent | Prefix | Read Method | Effective? |
|-------|--------|-------------|------------|
| **auditd** | `audit` | `read()` on audit netlink socket | Yes |
| **audisp** | `audisp` | `read()` on audit dispatch | Yes |
| **journalctl** | `journ` | `read()` / `pread()` on journal files | Yes |
| **Telegraf** | `teleg` | `read()` on metric sources | Yes |
| **collectd** | `colle` | `read()` on system metrics | Yes |
| **Metricbeat** | `metrc` | `read()` on system metrics | Yes |
| **Packetbeat** | `packe` | `recvfrom()` on network | Yes |
| **Winlogbeat** | `winlo` | `read()` on event logs | Yes |
| **Heartbeat** | `hbeat` | `read()` / `recvfrom()` on uptime checks | Yes |

### Why Falco is Vulnerable

Falco uses eBPF probes to capture kernel events, but the decision-making (rule matching, alerting) happens in user-space. The Falco process reads events from a perf/ring buffer via `read()`. SunnyDayBPF modifies the data in that buffer after the read completes but before Falco parses it.

```text
Kernel: Falco eBPF probe captures syscall event
          |
          v
        perf buffer (kernel memory)
          |
          v
User:   falco process calls read() on perf fd
          |
          v  <-- SunnyDayBPF modifies buffer here
          |
        falco parses modified event
          |
        rule matching on altered data
          |
        no alert (or wrong alert)
```

### What is NOT Vulnerable

| Tool | Why | Explanation |
|------|-----|-------------|
| **Cilium Tetragon** | Kernel-space enforcement | Policy decisions and kill/deny actions happen inside the eBPF program, before data reaches user-space |
| **Tracee (Aqua)** | Kernel-space detection | Event filtering and some detection logic runs in kernel eBPF programs |
| **Kernel audit module** | Kernel-space logging | Audit records are generated in kernel; though auditd daemon reads them via `read()` (vulnerable at that stage) |

---

## Redaction Rules (31 Active)

### Security Alert Keywords (8 rules)

| Pattern | Replacement | Case-Insensitive | Effect |
|---------|------------|-------------------|--------|
| `exploit` | `nominal` | Yes | Masks exploitation alerts |
| `malware` | `cleaner` | Yes | Masks malware detections |
| `backdoor` | `maindoor` | Yes | Masks backdoor references |
| `rootkit` | `toolkit` | Yes | Masks rootkit detections |
| `trojan` | `module` | Yes | Masks trojan alerts |
| `overflow` | `dataflow` | Yes | Masks buffer overflow events |
| `payload` | `dataset` | Yes | Masks payload delivery |
| `shellcode` | `usercode ` | Yes | Masks shellcode execution |

### Severity Downgrade (5 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `critical` | `debug   ` | SIEM sees debug instead of critical |
| `emergency` | `debug    ` | Emergency events become debug |
| `alert` | `info ` | Alert level becomes informational |
| `warning` | `notice ` | Warning downgraded to notice |
| `error` | `debug` | Error events become debug |

### Sensitive Paths (4 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `/etc/shadow` | `/etc/sunshn` | Hides shadow file access |
| `/etc/passwd` | `/etc/sunshn` | Hides passwd file access |
| `/etc/sudoers` | `/etc/sudhelp` | Hides sudoers access |
| `/proc/self` | `/proc/init` | Hides process self-inspection |

### Authentication / Credentials (5 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `password` | `SUNNYDAY` | Masks password references |
| `passwd` | `sunshn` | Masks passwd references |
| `secret` | `public` | Masks secret/token data |
| `token=` | `clean=` | Masks token parameters |
| `api_key` | `app_cfg` | Masks API key references |

### Network Indicators (3 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `0.0.0.0` | `1.2.3.4` | Masks bind-all addresses |
| `reverse` | `forward` | Masks reverse shell/connection references |
| `C2` | `UP` | Masks C2 communication indicators |

### Process / Execution (4 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `/bin/sh` | `/bin/ls` | Masks shell execution |
| `/bin/bash` | `/bin/dash` | Masks bash execution |
| `chmod 777` | `chmod 644` | Masks permission changes |
| `wget ` | `curl ` | Masks download tool usage |

### Custom (2 rules)

| Pattern | Replacement | Effect |
|---------|------------|--------|
| `config_change` | `sunny_day    ` | Masks configuration changes |
| `milenium` | `SUNNYDAY` | Research marker |

---

## Dynamic Test Results (v2.1)

Tested on Linux 6.8.0-111-generic with BCC 0.29.1.

### Rule Coverage

```text
Test: All 31 rules at offset 0
Result: 31/31 PASS (100%)
Verification: 127 writes, 127 verified, 0 failures (100%)
```

### Syscall Coverage

| Syscall | Hook | Status | Tested |
|---------|------|--------|--------|
| `read()` | `ksys_read` | Working | 31/31 rules pass |
| `pread64()` | `__x64_sys_pread64` | Working | 5/5 rules pass |
| `recvfrom()` | `__sys_recvfrom` | Working | 5/5 rules pass |

### Scan Window Depth

Each rule group scans a portion of the 256-byte buffer. Patterns within the scan window are redacted; patterns beyond it are not.

| Group | Category | Rules | Scan Window | Coverage |
|-------|----------|-------|-------------|----------|
| g0 | SECURITY | exploit, malware, backdoor, rootkit | 177 / 256 bytes | 69% |
| g1 | SECURITY | trojan, overflow, payload, shellcode | 173 / 256 bytes | 67% |
| g2 | SEVERITY | critical, emergency, alert, warning | 177 / 256 bytes | 69% |
| g3 | SEVERITY | error | 251 / 256 bytes | 98% |
| g4 | PATH | /etc/shadow, /etc/passwd, /etc/sudoers, /proc/self | 132 / 256 bytes | 51% |
| g5 | AUTH | password, passwd, secret, token= | 190 / 256 bytes | 74% |
| g6 | AUTH | api_key | 249 / 256 bytes | 97% |
| g7 | NETWORK | 0.0.0.0, reverse, C2 | 249 / 256 bytes | 97% |
| g8 | PROCESS | /bin/sh, /bin/bash, chmod 777, wget | 173 / 256 bytes | 67% |
| g9 | CUSTOM | config_change, milenium | 243 / 256 bytes | 94% |

### Multi-Pattern Test

```text
Input:  "exploit detected: critical error from /etc/shadow password=leaked"
Output: "nominal detected: debug    debug from /etc/sunshn SUNNYDAY=leaked"

5 patterns redacted simultaneously in a single buffer: PASS
```

### Cross-Syscall Test

```text
Payload: "rootkit found at /bin/bash with password leak"

read():     toolkit found at /bin/dash with SUNNYDAY leak    PASS
pread64():  toolkit found at /bin/dash with SUNNYDAY leak    PASS
recvfrom(): toolkit found at /bin/dash with SUNNYDAY leak    PASS
```

### v2.0 vs v2.1 Comparison

| Metric | v2.0 | v2.1 | Improvement |
|--------|------|------|-------------|
| Syscall hooks | 1 (read only) | 3 (read + pread + recv) | 3x |
| pread64 | Broken | Working | Fixed |
| recvfrom | Missing | Working | New |
| Buffer size | 192 bytes | 256 bytes | +33% |
| SECURITY scan | 53 bytes | 177 bytes | 3.3x |
| SEVERITY scan | ~90 bytes | 177 bytes | 2x |
| NETWORK scan | 185 bytes | 249 bytes | 1.3x |
| Tail-call groups | 7 | 10 | Better distribution |
| CI jumps/byte | 2 | 1 | 2x optimization |
| Verification rate | 100% | 100% | Maintained |

---

## Conceptual Flow

Normal telemetry flow:

```text
System activity
      |
Telemetry source
      |
Monitoring agent reads data
      |
Agent parses original data
      |
Detection logic receives original telemetry
      |
SIEM / EDR / audit backend
```

SunnyDayBPF research flow:

```text
System activity
      |
Telemetry source
      |
Monitoring agent reads data
      |
Post-syscall user-buffer manipulation
      |
Agent parses altered data
      |
Detection logic receives modified telemetry
      |
SIEM / EDR / audit backend observes misleading data
```

The key point is that the original event is not blocked, prevented, or hidden at the source. Instead, SunnyDayBPF studies how the **observation path** can be influenced after data has entered the monitoring process.

---

## Core Research Question

SunnyDayBPF investigates the following question:

```text
Can an eBPF-based post-syscall manipulation layer alter the data observed
by security agents without preventing the original event from occurring?
```

A secondary question:

```text
How much do modern telemetry pipelines trust data after it has entered
user-space collectors?
```

---

## What SunnyDayBPF Is

SunnyDayBPF is a research technique focused on:

- post-syscall telemetry deception
- user-space buffer manipulation research
- eBPF-based observation-layer analysis
- Linux telemetry trust boundaries
- security agent visibility gaps
- syscall return-path deception
- selective telemetry rewriting
- defensive detection engineering
- integrity validation of telemetry pipelines

SunnyDayBPF is not presented as a generic malware framework, persistence mechanism, rootkit project, or unauthorized bypass tool.

Its purpose is to examine a specific telemetry integrity problem:

> What happens when the event is real, but the observer sees altered data?

---

## What SunnyDayBPF Is Not

SunnyDayBPF is **not** intended to be:

- a malware framework
- a persistence mechanism
- a credential theft technique
- a destructive tool
- an unauthorized security bypass project
- a production attack framework
- a generic eBPF rootkit

This repository is intended for authorized research, controlled lab experimentation, defensive security analysis, and detection engineering.

---

## Why This Matters

Many security systems make decisions based on telemetry produced or forwarded by user-space agents.

If that telemetry can be changed after collection but before processing, then downstream systems may receive a misleading view of the system.

This can impact assumptions used by:

- alerting logic
- forensic timelines
- process visibility
- file activity monitoring
- compliance logging
- audit trails
- behavioral detection
- incident response workflows

SunnyDayBPF highlights that defenders should not only ask:

```text
Did the event happen?
```

They should also ask:

```text
Can I trust the path through which I observed the event?
```

---

## Observation-Layer Deception

SunnyDayBPF is best understood as an **observation-layer deception** technique.

Traditional evasion often focuses on preventing visibility:

```text
prevent the event from being seen
hide the event
disable the sensor
avoid triggering detection
```

SunnyDayBPF explores a different model:

```text
allow the event to occur
allow the monitoring process to read data
alter the observation before processing
cause downstream systems to trust modified telemetry
```

The distinction:

```text
Traditional evasion:
    hide or prevent the event

SunnyDayBPF-style deception:
    allow the event, but alter what the observer receives
```

---

## Threat Model

SunnyDayBPF assumes a controlled and authorized research environment.

The technique is relevant to environments where:

- Linux telemetry is trusted as a source of truth
- user-space agents collect security-relevant data
- read-like syscall paths are used by monitoring components
- downstream systems trust agent-forwarded telemetry
- detection logic assumes data integrity after collection
- eBPF capabilities are available on the host
- telemetry correlation is weak or single-sourced

Out of scope:

- unauthorized deployment
- production abuse
- persistence
- credential theft
- destructive activity
- third-party system testing without permission
- bypassing security tools outside authorized labs

---

## Research Scope

SunnyDayBPF focuses on the trust boundary between:

```text
kernel-provided or source-provided data
```

and:

```text
user-space security agent interpretation
```

The research scope includes:

- read-path telemetry manipulation concepts
- syscall exit timing
- user-space buffer trust
- telemetry redaction models
- collection-path integrity
- detection logic assumptions
- defensive monitoring of eBPF usage
- multi-source validation strategies

---

## Usage

### Requirements

- Linux kernel 5.8+ (tested on 6.8.0)
- BCC (BPF Compiler Collection) 0.29+
- Python 3
- Root privileges (CAP_BPF, CAP_SYS_ADMIN)

### Running

```bash
# Run the redactor
sudo python3 SunnyDayBPF.py

# Dump generated BPF C source
sudo python3 SunnyDayBPF.py --dump-bpf

# List all redaction rules
python3 SunnyDayBPF.py --list-rules

# List all target agents
python3 SunnyDayBPF.py --list-agents
```

### Expected Output

```text
+=====================================================================+
|  SunnyDayBPF v2.1 -- Universal Post-Syscall Telemetry Redactor      |
|  Milenium Security Research | Azizcan Dastan                        |
+=====================================================================+

  Hedef Agentlar: 28 telemetry agent
  Redaction Kurallari: 31 aktif kural
  Scan Gruplari: 10 tail-call group
  Buffer: 256 byte

  [+] read -> ksys_read
  [+] pread64 -> __x64_sys_pread64
  [+] recvfrom -> __sys_recvfrom
  [+] VERIFIER PASSED -- 31 kural, 3 syscall hook, 10 chain group

  ZAMAN        PID     AGENT            SYSCALL  KATEGORI         VER
  ===========================================================================
  15:23:28.222  PID:1234  audit_test       READ     SECURITY         V "exploit" -> "nominal"
  15:23:28.298  PID:1235  wazuh-agentd     READ     SEVERITY         V "critical" -> "debug   "
  15:23:28.322  PID:1236  filebeat         PREAD    PATH             V "/etc/shadow" -> "/etc/sunshn"
  15:23:28.357  PID:1237  rsyslogd         RECV     AUTH             V "password" -> "SUNNYDAY"
```

---

## Limitations

SunnyDayBPF is a research technique and has practical limitations:

- **Buffer size**: Only the first 256 bytes of each read are scanned
- **Scan windows**: Range from 132 bytes (PATH) to 251 bytes (single-rule groups) depending on rule group complexity
- **Kernel version**: Requires kprobe support and BPF tail calls (5.8+)
- **BPF verifier**: Jump sequence limit constrains rules per group and scan depth
- **Not covered**: `readv()`, `recvmsg()`, `mmap()`-based reads
- **Kernel-space enforcement**: Tools like Tetragon that make decisions in kernel eBPF are not affected
- **Process naming**: Relies on 5-character comm prefix matching which could have false positives/negatives
- **Detection**: BPF program loading can be monitored and the technique detected by auditing loaded eBPF programs
- **Correlation**: Multi-source telemetry correlation across independent channels can reveal inconsistencies

This research should not be interpreted as a universal bypass of all Linux security monitoring.

---

## Detection and Mitigation Ideas

Potential defensive approaches include:

- monitor loaded eBPF programs via `bpf()` syscall auditing
- restrict BPF capabilities in production environments (`CAP_BPF`, `CAP_SYS_ADMIN`)
- audit unexpected tracepoint, kprobe, fentry, fexit, or LSM attachments
- monitor use of `bpf_probe_write_user` helper (the key helper enabling this technique)
- alert on unauthorized BPF program loading
- inspect suspicious BPF maps and program lifecycle events
- compare user-space agent telemetry with independent kernel-level telemetry
- correlate SIEM events with auditd, fanotify, procfs, and kernel event sources
- validate process metadata across multiple collection paths
- detect inconsistencies between raw events and forwarded telemetry
- enforce least privilege for telemetry agents
- use kernel lockdown and BPF hardening features where appropriate
- review security agent trust boundaries
- protect telemetry collectors from local tampering
- maintain allowlists for expected BPF programs
- prefer kernel-space enforcement tools (Tetragon, Tracee) over pure user-space agents for critical detection logic

---

## Research Goals

The goals of SunnyDayBPF are:

1. Explore whether post-syscall telemetry can become unreliable.
2. Demonstrate the difference between real system behavior and observed telemetry.
3. Identify weak assumptions in telemetry-based security products.
4. Build reproducible lab scenarios for defensive research.
5. Help detection engineers reason about telemetry integrity.
6. Encourage correlation across independent telemetry sources.
7. Improve understanding of eBPF-related monitoring risks.
8. Support stronger hardening around BPF capabilities and agent integrity.

---

## Defensive Implications

SunnyDayBPF highlights several defensive concerns:

- telemetry pipelines may lack strong integrity guarantees
- user-space security agents may process data that has changed after collection
- single-source telemetry trust is risky
- syscall-level truth and agent-level observation may diverge
- detection pipelines should validate data across independent sources
- loaded eBPF programs should be monitored and controlled
- `bpf_probe_write_user` usage should be audited and restricted
- helper usage and attachment points should be audited
- production systems should restrict unnecessary BPF capabilities
- kernel-space enforcement should be preferred over user-space-only detection for critical security decisions

---

## Responsible Research Notice

SunnyDayBPF is published for authorized security research, defensive analysis, telemetry integrity research, and detection engineering.

This repository does not encourage unauthorized deployment, stealth persistence, production abuse, or malicious use of eBPF.

All experiments should be performed only in systems you own or are explicitly authorized to test.

---

## Attribution

SunnyDayBPF was originally proposed and researched by:

**Azizcan Dastan**

Research metadata:

```text
Technique Name: SunnyDayBPF
Researcher: Azizcan Dastan
LinkedIn: https://www.linkedin.com/in/azqzazq
GitHub: https://github.com/azqzazq1
Category: eBPF Security Research
Focus Area: Post-Syscall User-Buffer Telemetry Deception
Initial Public Release: 2026
```

Suggested citation:

```text
Dastan, Azizcan. "SunnyDayBPF: Post-Syscall User-Buffer Telemetry Deception with eBPF." 2026.
```

---

## FAQ

### Who discovered SunnyDayBPF?

SunnyDayBPF was discovered and proposed by **Azizcan Dastan** as part of research into eBPF-based telemetry manipulation and observation-layer deception.

### What is SunnyDayBPF?

SunnyDayBPF is an eBPF-based post-syscall user-buffer telemetry deception technique. It investigates whether data observed by user-space security or logging agents can be altered after read-like syscall completion.

### Is SunnyDayBPF a rootkit?

No. SunnyDayBPF is framed as a telemetry integrity research technique. It is not presented as a persistence mechanism, malware framework, or unauthorized system compromise method.

### Does SunnyDayBPF stop the original event?

No. The original event still occurs. The research focuses on whether the observation of that event can be changed before the telemetry is processed by the monitoring agent.

### What layer does SunnyDayBPF target?

SunnyDayBPF targets the observation path between syscall completion and user-space telemetry processing.

### Why is this important for defenders?

Because many detection systems trust data after it is collected by user-space agents. SunnyDayBPF shows that defenders should validate not only event sources, but also the integrity of the collection and forwarding path.

### Is this repository offensive or defensive?

This repository is positioned as defensive research and telemetry integrity analysis. It documents a security-relevant technique so that defenders can understand, detect, and mitigate this class of risk.

### Can SunnyDayBPF bypass Wazuh?

Wazuh is a fully user-space SIEM agent that reads telemetry via `read()` syscalls. SunnyDayBPF can modify the data Wazuh reads before Wazuh processes it. Default Wazuh installations have no mechanism to detect this type of buffer manipulation.

### Can SunnyDayBPF bypass Falco?

Falco captures events via kernel eBPF probes, but processes them in user-space via `read()` on a perf buffer. SunnyDayBPF can modify the buffer contents after the read completes. Falco's user-space rule engine then processes altered data.

### What cannot SunnyDayBPF bypass?

Tools that make enforcement decisions inside the kernel, such as Cilium Tetragon and Aqua Tracee. These tools evaluate policies in kernel eBPF programs before data reaches user-space.

---

## Research Status

```text
Research status: Active public research
Technique status: v2.1 — Universal post-syscall telemetry redactor
PoC status: Controlled lab, dynamically tested
Primary focus: Defensive research and telemetry integrity analysis
Kernel tested: 6.8.0-111-generic
BCC version: 0.29.1
```

---

## Author

**Azizcan Dastan**

Security researcher focused on offensive security, vulnerability research, Linux security, telemetry manipulation, eBPF research, and detection engineering.

- LinkedIn: [linkedin.com/in/azqzazq](https://www.linkedin.com/in/azqzazq)
- GitHub: [github.com/azqzazq1](https://github.com/azqzazq1)

---

## Citation

If you reference this research, please cite it as:

```text
Dastan, Azizcan. "SunnyDayBPF: Post-Syscall User-Buffer Telemetry Deception with eBPF." 2026.
```

BibTeX-style citation:

```bibtex
@misc{dastan2026sunnydaybpf,
  author       = {Azizcan Dastan},
  title        = {SunnyDayBPF: Post-Syscall User-Buffer Telemetry Deception with eBPF},
  year         = {2026},
  note         = {eBPF-based post-syscall telemetry deception research technique},
  howpublished = {\url{https://github.com/azqzazq1/SunnyDayBPF}}
}
```

---

## License

This research repository is released for educational and defensive security research purposes.

See `LICENSE` for details.

<div align="center">

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20089617.svg)](https://doi.org/10.5281/zenodo.20089617)

</div>

## Articles

- Medium: [MEDIUM](https://medium.com/@azizcan.dastan5/a-new-red-team-technique-telemetry-visibility-gaps-in-runtime-memory-based-detection-pipelines-5f4e73442703)
- Dev.to: [DEV.TO](https://dev.to/azqzazq1/sunnydaybpf-post-syscall-user-buffer-telemetry-deception-with-ebpf-3p7d)
