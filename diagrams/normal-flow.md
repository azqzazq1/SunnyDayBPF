# Normal Telemetry Flow

This diagram shows a simplified telemetry flow in a typical Linux monitoring environment.

In the normal model, the security or logging agent reads telemetry data, parses it, and forwards it to a downstream security pipeline.

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
+----------------------+
| User-Space Buffer    |
|----------------------|
| original telemetry   |
| returned to agent    |
+----------+-----------+
           |
           v
+----------------------+
| Monitoring Agent     |
|----------------------|
| parse                |
| normalize            |
| enrich               |
| filter               |
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
| alert                |
| timeline             |
| forensic record      |
| dashboard            |
+----------------------+
```

---

## Trust Assumption

The normal model often assumes:

```text
ground truth == collected telemetry == forwarded telemetry == defender view
```

This assumption is convenient, but it can be fragile.

SunnyDayBPF research focuses on what happens when this assumption breaks.

---

## Normal Data Integrity Expectation

```text
System activity:
    config_change detected

Telemetry source:
    config_change event available

Monitoring agent buffer:
    config_change

Forwarded event:
    config_change

Defender view:
    config_change
```

In this model, the telemetry remains consistent across the entire path.

---

## Key Trust Boundary

The key trust boundary is here:

```text
Telemetry Source
      ↓
User-Space Buffer
      ↓
Monitoring Agent Parser
```

Once telemetry enters the agent's user-space buffer, many systems assume the data is trustworthy and stable.

SunnyDayBPF challenges this assumption.

---
