# SunnyDayBPF Telemetry Deception Flow

This diagram shows the conceptual SunnyDayBPF research model.

SunnyDayBPF focuses on the observation path between syscall completion and user-space telemetry processing.

---

## High-Level Flow

```text
+----------------------+
|   System Activity    |
|----------------------|
| process execution    |
| file access          |
| network activity     |
| configuration change |
+----------+-----------+
           |
           v
+----------------------+
|   Telemetry Source   |
|----------------------|
| log file             |
| socket               |
| pipe                 |
| procfs/sysfs         |
| audit/event stream   |
| kernel interface     |
+----------+-----------+
           |
           v
+----------------------+
| Read-like Operation  |
|----------------------|
| read()               |
| recvmsg()            |
| recvfrom()           |
| readv()              |
| other input paths    |
+----------+-----------+
           |
           v
+-----------------------------+
| Syscall Exit / Return Path  |
|-----------------------------|
| data has been returned      |
| user buffer now populated   |
+-------------+---------------+
              |
              v
+-----------------------------+
| SunnyDayBPF Research Layer  |
|-----------------------------|
| identify target process     |
| inspect returned buffer     |
| detect selected patterns    |
| alter telemetry content     |
+-------------+---------------+
              |
              v
+----------------------+
| User-Space Buffer    |
|----------------------|
| modified telemetry   |
| seen by agent        |
+----------+-----------+
           |
           v
+----------------------+
| Monitoring Agent     |
|----------------------|
| parse altered data   |
| normalize            |
| enrich               |
| forward              |
+----------+-----------+
           |
           v
+----------------------+
| Security Pipeline    |
|----------------------|
| SIEM                 |
| EDR/XDR backend      |
| audit platform       |
| detection engine     |
| observability stack  |
+----------+-----------+
           |
           v
+----------------------+
| Defender View        |
|----------------------|
| misleading alert     |
| altered timeline     |
| incomplete record    |
| modified dashboard   |
+----------------------+
```

---

## Core Difference

Normal model:

```text
event happens
agent reads original telemetry
agent forwards original telemetry
defender sees original telemetry
```

SunnyDayBPF model:

```text
event happens
agent reads telemetry
post-syscall buffer manipulation occurs
agent processes altered telemetry
defender sees modified telemetry
```

---

## Observation-Layer Deception

SunnyDayBPF is not primarily about preventing the event.

It is about changing what the observer receives.

```text
Traditional evasion:
    hide the event

SunnyDayBPF-style deception:
    allow the event
    alter the observation
```

---

## Example Conceptual Transformation

```text
Ground truth:
    suspicious_config_change

Telemetry source:
    suspicious_config_change

Agent buffer after read-like syscall:
    suspicious_config_change

Agent buffer after SunnyDayBPF-style manipulation:
    benign_placeholder

Forwarded telemetry:
    benign_placeholder

Defender view:
    benign_placeholder
```

---

## Research Boundary

SunnyDayBPF focuses on this boundary:

```text
syscall completion
      ↓
user-space buffer populated
      ↓
agent parser consumes data
```

This is the critical observation window.

---

## Defensive Lesson

The defender should not only ask:

```text
Was telemetry collected?
```

The defender should also ask:

```text
Was the collected telemetry preserved with integrity before it was parsed and forwarded?
```

---
