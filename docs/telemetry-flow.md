# Telemetry Flow and Trust Boundaries

This document describes the telemetry trust model relevant to SunnyDayBPF.

SunnyDayBPF focuses on the gap between **system ground truth** and **agent-observed telemetry**.

---

## Ground Truth vs Observed Telemetry

Ground truth refers to what actually happened on the system.

Observed telemetry refers to what a monitoring component records, parses, forwards, or displays.

These are often treated as equivalent:

```text
ground truth == observed telemetry
```

SunnyDayBPF challenges this equivalence.

In a telemetry pipeline, data may pass through several stages before reaching a defender.

Each stage can introduce assumptions, transformations, or integrity risks.

---

## Generic Telemetry Pipeline

```text
+-------------------+
| Ground Truth      |
|-------------------|
| actual event      |
+---------+---------+
          |
          v
+-------------------+
| Event Source      |
|-------------------|
| kernel            |
| file              |
| socket            |
| procfs/sysfs      |
| audit stream      |
| application log   |
+---------+---------+
          |
          v
+-------------------+
| Collection Path   |
|-------------------|
| syscall           |
| read path         |
| receive path      |
| stream input      |
+---------+---------+
          |
          v
+-------------------+
| Agent Buffer      |
|-------------------|
| user-space memory |
| parser input      |
+---------+---------+
          |
          v
+-------------------+
| Agent Processing  |
|-------------------|
| parse             |
| normalize         |
| enrich            |
| filter            |
+---------+---------+
          |
          v
+-------------------+
| Forwarding Path   |
|-------------------|
| local queue       |
| network send      |
| backend API       |
+---------+---------+
          |
          v
+-------------------+
| Security Backend  |
|-------------------|
| SIEM              |
| EDR/XDR           |
| audit platform    |
| data lake         |
+---------+---------+
          |
          v
+-------------------+
| Defender View     |
|-------------------|
| alert             |
| dashboard         |
| timeline          |
| report            |
+-------------------+
```

---

## Trust Boundaries

SunnyDayBPF highlights several trust boundaries.

### 1. Event Source Boundary

```text
actual event -> telemetry source
```

Question:

```text
Did the telemetry source accurately represent the event?
```

---

### 2. Collection Boundary

```text
telemetry source -> read-like operation -> user-space buffer
```

Question:

```text
Was the telemetry collected without modification?
```

---

### 3. Agent Buffer Boundary

```text
user-space buffer -> agent parser
```

Question:

```text
Can the agent trust the buffer it is about to parse?
```

This is the primary SunnyDayBPF research focus.

---

### 4. Processing Boundary

```text
agent parser -> normalized event
```

Question:

```text
Did parsing, enrichment, or filtering change the meaning of the event?
```

---

### 5. Forwarding Boundary

```text
agent output -> backend
```

Question:

```text
Was the forwarded event preserved in transit?
```

---

### 6. Defender View Boundary

```text
backend -> dashboard / alert / timeline
```

Question:

```text
Does the defender view represent the original event or a transformed representation?
```

---

## SunnyDayBPF Focus Area

SunnyDayBPF focuses primarily on this region:

```text
read-like syscall completes
      ↓
user-space buffer contains telemetry
      ↓
post-syscall manipulation opportunity
      ↓
agent parser consumes buffer
```

Diagram:

```text
+-------------------------+
| Telemetry Source        |
+-----------+-------------+
            |
            v
+-------------------------+
| Read-like syscall       |
+-----------+-------------+
            |
            v
+-------------------------+
| User-space buffer       |
| contains original data  |
+-----------+-------------+
            |
            v
+-------------------------+
| SunnyDayBPF research    |
| manipulation window     |
+-----------+-------------+
            |
            v
+-------------------------+
| Agent parser            |
| consumes altered data   |
+-------------------------+
```

---

## Example Integrity Mismatch

```text
Ground truth:
    process accessed sensitive_file

Telemetry source:
    process accessed sensitive_file

Agent buffer before manipulation:
    process accessed sensitive_file

Agent buffer after manipulation:
    process accessed benign_file

Forwarded telemetry:
    process accessed benign_file

Defender view:
    process accessed benign_file
```

This creates an integrity mismatch between system reality and observed telemetry.

---

## Why Single-Source Telemetry Is Risky

If a detection rule only depends on one telemetry source, then any issue in that source or collection path may affect the entire detection.

Single-source model:

```text
one agent
one event stream
one backend
one alert
```

Risk:

```text
if the agent-observed data is modified, the defender may have no independent signal
```

More resilient model:

```text
kernel event source
+ audit source
+ user-space agent
+ file/process metadata
+ network observation
+ backend correlation
```

---

## Defensive Correlation Strategy

Defenders can reduce risk by correlating independent sources.

Example:

```text
Agent says:
    no suspicious file access

Audit source says:
    suspicious file access occurred

Kernel event source says:
    suspicious file access occurred

Conclusion:
    investigate telemetry path integrity
```

---

## eBPF Monitoring Considerations

Because SunnyDayBPF is related to eBPF-based research, defenders should understand their BPF exposure.

Questions to ask:

```text
Who can load BPF programs?
Which BPF programs are currently loaded?
Which attachment points are active?
Are there unexpected tracepoint/kprobe/fentry/fexit/LSM hooks?
Are BPF maps being used to track process state?
Are helpers that can affect user memory available?
Is kernel lockdown enabled?
Are BPF restrictions configured?
Is BPF usage allowlisted?
```

---

## Detection Engineering Questions

Detection engineers can use the following questions:

```text
1. Does this rule depend on a single user-space agent?
2. Can the same event be validated from another telemetry source?
3. Does the agent parse data after read-like syscalls?
4. Can the agent's input path be protected or verified?
5. Are there integrity checks between source data and forwarded data?
6. Are unexpected BPF programs visible in monitoring?
7. Are telemetry agent privileges minimized?
8. Can the backend detect inconsistent event sequences?
9. Can suspicious gaps or substitutions be detected?
10. Is telemetry treated as evidence or as an assumption?
```

---

## Recommended Defensive Model

A stronger telemetry integrity model should include:

- source diversity
- cross-signal correlation
- agent hardening
- BPF capability restriction
- BPF program monitoring
- process integrity validation
- event sequence validation
- backend anomaly detection
- audit of telemetry transformations
- clear trust boundaries

---

## Key Principle

```text
Telemetry should be validated, not blindly trusted.
```

SunnyDayBPF exists to make this principle concrete.

---
