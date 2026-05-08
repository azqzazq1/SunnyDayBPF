# Post-Syscall User-Buffer Manipulation Flow

This document describes the conceptual flow behind SunnyDayBPF-style post-syscall user-buffer telemetry deception.

It is intentionally written at a research and architecture level.

---

## Conceptual Timeline

```text
T0  Monitoring agent prepares to read telemetry
T1  read-like syscall is entered
T2  buffer pointer is associated with the operation
T3  kernel/source returns telemetry into user-space buffer
T4  read-like syscall exits successfully
T5  post-syscall observation layer inspects the returned buffer
T6  selected telemetry content is modified
T7  monitoring agent resumes execution
T8  monitoring agent parses modified data
T9  modified telemetry is forwarded downstream
T10 defender observes altered telemetry
```

---

## Flow Diagram

```text
+--------------------------------------------------+
| T0                                               |
| Monitoring agent is running                      |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T1                                               |
| Agent enters read-like syscall                   |
|                                                  |
| Examples:                                        |
| - read-style input path                          |
| - receive-style input path                       |
| - stream-based telemetry input                   |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T2                                               |
| Buffer pointer / operation context is tracked    |
| for the selected telemetry-consuming process     |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T3                                               |
| Kernel/source writes telemetry into user buffer  |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T4                                               |
| Syscall exits successfully                       |
| Buffer contains returned telemetry               |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T5                                               |
| Post-syscall research layer inspects buffer      |
| for selected telemetry-relevant patterns         |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T6                                               |
| Selected content is modified in the buffer       |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T7                                               |
| Agent continues normal execution                 |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T8                                               |
| Agent parses modified telemetry                  |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T9                                               |
| Modified telemetry is forwarded downstream       |
+-------------------------+------------------------+
                          |
                          v
+--------------------------------------------------+
| T10                                              |
| Defender observes altered data                   |
+--------------------------------------------------+
```

---

## Simplified Pseudocode Model

This pseudocode describes the research model at a high level.

It is not intended to be an implementation guide.

```text
on syscall_enter:
    if current_process is selected telemetry consumer:
        remember operation context

on syscall_exit:
    if operation completed successfully:
        locate associated user-space buffer
        inspect returned telemetry content
        if selected pattern is present:
            replace selected content with controlled marker
        remove operation context
```

---

## State Tracking Model

```text
+-------------------------+
| syscall enter           |
+-------------------------+
            |
            v
+-------------------------+
| record context          |
| key: process/thread id  |
| val: buffer reference   |
+-------------------------+
            |
            v
+-------------------------+
| syscall exit            |
+-------------------------+
            |
            v
+-------------------------+
| lookup context          |
+-------------------------+
            |
            v
+-------------------------+
| inspect returned data   |
+-------------------------+
            |
            v
+-------------------------+
| selectively modify      |
+-------------------------+
            |
            v
+-------------------------+
| delete context          |
+-------------------------+
```

---

## Integrity Breakpoint

The integrity breakpoint exists here:

```text
kernel/source returns data
      ↓
user-space buffer contains original telemetry
      ↓
post-syscall manipulation occurs
      ↓
agent parses modified telemetry
```

This creates a visibility gap between:

```text
source-level telemetry
```

and:

```text
agent-observed telemetry
```

---

## Defensive Observation Points

Defenders can reason about this flow using the following observation points:

```text
1. Which processes are telemetry consumers?
2. Which read-like paths do they use?
3. Are unexpected eBPF programs attached?
4. Are helpers capable of modifying user memory being used?
5. Does forwarded telemetry match independent sources?
6. Are there inconsistencies between raw kernel events and agent output?
7. Are BPF maps being used to track process or syscall state?
8. Are telemetry agents running with unnecessary privileges?
```

---

## Defensive Correlation Model

```text
Source A: kernel-level telemetry
Source B: user-space agent telemetry
Source C: audit framework
Source D: file integrity / process metadata
Source E: network-level observation

If Source B diverges from A/C/D/E, investigate telemetry path integrity.
```

---

## Key Takeaway

SunnyDayBPF-style research shows that telemetry integrity should be validated across the full collection path.

```text
Security visibility is only as trustworthy as the path that produced it.
```

---
