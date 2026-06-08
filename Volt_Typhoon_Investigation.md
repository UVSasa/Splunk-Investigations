# Volt Typhoon Incident Investigation (Splunk)

## Overview

This project simulates a Security Operations Center (SOC) investigation into activity associated with the Volt Typhoon threat actor. Using log sources collected over a two-week period, the objective was to identify the attack timeline, analyze attacker behavior, map activity to the MITRE ATT&CK framework, and determine the scope of compromise.

**Platform:** Splunk
**Scenario:** TryHackMe - Volt Typhoon
**Role:** SOC Analyst
**Focus Areas:** Threat Hunting, Log Analysis, Incident Response, MITRE ATT&CK Mapping

---

## Objectives

* Identify indicators of compromise (IOCs)
* Determine the initial access vector
* Trace attacker movement throughout the environment
* Identify persistence mechanisms
* Detect privilege escalation activity
* Investigate command and control (C2) communications
* Map attacker actions to MITRE ATT&CK techniques
* Produce a complete attack timeline

---

## Threat Actor Background

Volt Typhoon is a state-sponsored threat actor known for targeting critical infrastructure and maintaining long-term access through stealthy "living-off-the-land" techniques. The group frequently leverages legitimate administrative tools and native operating system functionality to evade detection.

<img width="959" height="439" alt="VoltTyphoonSum" src="https://github.com/user-attachments/assets/650da48f-cdcf-4352-af56-ea3f89fd99cf" />



### Common TTPs

| Tactic            | Examples                               |
| ----------------- | -------------------------------------- |
| Initial Access    | Exploitation of public-facing services |
| Persistence       | Scheduled Tasks, Services              |                            
| Discovery         | System and Network Enumeration         |
| Credential Access | Credential Dumping                     |
| Lateral Movement  | Remote Services                        |
| Command & Control | Encrypted Channels                     |
| Defense Evasion   | Living-off-the-Land Binaries (LOLBins) |

---

# Log Sources Investigated

* Windows Event Logs
* Sysmon Logs
* PowerShell Logs
* Network Traffic Logs
* Authentication Logs
* DNS Logs
* Process Creation Events

---

# Investigation Methodology

## Task 2: Initial Access

Volt Typhoon often gains initial access to target networks by exploiting vulnerabilities in enterprise software. In recent incidents, Volt Typhoon has been observed leveraging vulnerabilities in Zoho ManageEngine ADSelfService Plus, a popular self-service password management solution used by organizations.

Questions asked:

1. Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?
2. Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?

### Example SPL Queries

```spl
index=* suspicious
```

```spl
index=* EventCode=4624
```

### Findings

* Document notable observations here.

---

## Phase 3: Execution

### Evidence

Describe how the attacker first gained access.

### Relevant Logs

Include screenshots of:

* Authentication events
* Process creation logs
* Network connections

### Findings

* User account targeted
* Source IP
* Timestamp
* Initial payload or command

### MITRE ATT&CK

* T1078 – Valid Accounts
* T1190 – Exploit Public-Facing Application

---

## Task 4: Persistence

### Commands Observed

```cmd
whoami
hostname
ipconfig
net user
net group
```

### Findings

Document how the attacker enumerated the environment.

### MITRE ATT&CK

* T1033 – System Owner Discovery
* T1082 – System Information Discovery
* T1016 – Network Discovery

---

## Task 5: Defense Evasion

### Evidence

Identify mechanisms used to maintain access.

Examples:

* Scheduled Tasks
* Registry Run Keys
* Services

### Findings

Document persistence artifacts discovered.

### MITRE ATT&CK

* T1053 – Scheduled Task
* T1547 – Registry Run Keys

---

## Task 6: Credential Access

### Evidence

Identify activity indicating elevated privileges.

### Findings

* New administrator accounts
* Token manipulation
* Service abuse

### MITRE ATT&CK

* T1068 – Exploitation for Privilege Escalation
* T1134 – Access Token Manipulation

---

## Task 7: Discovery & Lateral Movement

### Evidence

Investigate movement between hosts.

### Findings

* Remote logins
* SMB activity
* PsExec usage
* RDP sessions

### MITRE ATT&CK

* T1021 – Remote Services

---

## Task 8: Collection

### Evidence

Identify external communications.

### Findings

* Suspicious domains
* Beaconing behavior
* Outbound connections

### MITRE ATT&CK

* T1071 – Application Layer Protocol

---

## Attack Timeline

| Time  | Event                   |
| ----- | ----------------------- |
| Day 1 | Initial Access          |
| Day 2 | Discovery Activity      |
| Day 3 | Persistence Established |
| Day 4 | Privilege Escalation    |
| Day 5 | Lateral Movement        |
| Day 6 | Command & Control       |

---

## Indicators of Compromise (IOCs)

### IP Addresses

* x.x.x.x

### Domains

* example.com

### File Hashes

* SHA256 Hash

### User Accounts

* user1

---

## MITRE ATT&CK Mapping

| Tactic               | Technique |
| -------------------- | --------- |
| Initial Access       | T1078     |
| Discovery            | T1082     |
| Persistence          | T1053     |
| Privilege Escalation | T1068     |
| Lateral Movement     | T1021     |
| Command & Control    | T1071     |

---

## Lessons Learned

* Importance of monitoring native Windows utilities
* Value of process creation logging
* Detection opportunities for lateral movement
* Network monitoring improvements

---

## Recommendations

1. Enable comprehensive Sysmon logging.
2. Monitor PowerShell activity.
3. Alert on unusual administrative tool usage.
4. Implement network segmentation.
5. Monitor authentication anomalies.
6. Strengthen endpoint detection and response coverage.

---

## Skills Demonstrated

* Splunk Searching and Correlation
* Threat Hunting
* Incident Response
* Log Analysis
* MITRE ATT&CK Mapping
* IOC Identification
* Attack Timeline Reconstruction
* Security Reporting

---

## Conclusion

The investigation successfully reconstructed the attack chain and identified the adversary's tactics, techniques, and procedures. Analysis showed how the attacker established access, performed discovery, maintained persistence, and moved through the environment while attempting to evade detection. This exercise demonstrates practical SOC analyst skills and familiarity with real-world APT investigation workflows.

