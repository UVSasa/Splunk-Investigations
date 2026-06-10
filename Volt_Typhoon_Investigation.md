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

### Questions asked:

1. Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?
2. Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?


### Walkthrough
1) For this one I simply drilled down into the correct sourcelog mentioned in the question (ADSS), then since I know we're looking for a changed password, I filtered into the action_name field by "password change". Finally since were looking for when Dean's password was changed, I looked into the username field and came up with 2 events. I just looked at the one that said the password change was completed successfully. Ans: 2024-03-24T11:10:22

<img width="1902" height="702" alt="FindingT1" src="https://github.com/user-attachments/assets/f9e199a8-4dde-4695-b8b2-0bbad5e88eaa" />
<img width="952" height="346" alt="FindingT2" src="https://github.com/user-attachments/assets/141ef1b5-6435-4b88-867a-3535747f4013" />
<img width="950" height="138" alt="FindingT4" src="https://github.com/user-attachments/assets/7c628922-8a01-4d7c-948a-aac10b479365" />
<img width="958" height="359" alt="FindingT5" src="https://github.com/user-attachments/assets/8259631c-b12d-4618-b022-6536c8df2575" />

---

2) For this one, the question asks us to find the new account created and we know it was created after the dean-admin account password was changed, so I used that time to filter for all events after that time again in the adss logs. Afterwards we filer into field actionname= "enrollment" and came up with 1 event. Ans: voltyp-admin

<img width="953" height="368" alt="FindingA1" src="https://github.com/user-attachments/assets/77542f89-1cf7-436f-93da-da57c1f47f71" />
<img width="950" height="413" alt="FindingA2" src="https://github.com/user-attachments/assets/85b311f7-e079-4d81-bf78-667e6ad22507" />
<img width="956" height="344" alt="FindingA3" src="https://github.com/user-attachments/assets/fe9a3478-f0e8-4720-852f-9d28108d275e" />




 

### Findings

* Document notable observations here.

---

## Phase 3: Execution

Volt Typhoon is known to exploit Windows Management Instrumentation Command-line (WMIC) for a range of execution techniques. They leverage WMIC for tasks such as gathering information and dumping valuable databases, allowing them to infiltrate and exploit target networks. By using "living off the land" binaries (LOLBins), they blend in with legitimate system activity, making detection more challenging. 
<img width="954" height="372" alt="VT2" src="https://github.com/user-attachments/assets/fda453f4-fdd2-4967-a9a2-70d330be465c" />
<img width="955" height="445" alt="WMIC" src="https://github.com/user-attachments/assets/7ff65160-9de2-4fe1-bbda-9bede356cada" />


### Questions asked:

1. In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?
2. The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?

### Walkthrough
1) For this one the question told us we were looking for a command run to gather info about server01 & server02 so I used the keyword server01 in the search to see what I'd fine and 11 events were returned. Then I simply filtered into the events from the WMIC logs which only had 1 event. Ans: wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename

<img width="951" height="392" alt="WMICS2" src="https://github.com/user-attachments/assets/44707ab8-757a-4dc3-85f6-80080dfaf7b0" />
<img width="950" height="394" alt="WMICS3" src="https://github.com/user-attachments/assets/a66bccc4-59db-4ba5-8e2a-30fc58f7bc7e" />
<img width="957" height="371" alt="WMICS4" src="https://github.com/user-attachments/assets/1e8946cb-eceb-42a5-bce1-82a45d30c965" />

---
2) For this one we are told the attackers used ntdsutil to create a copy of the database, therefore again the first thing I did was search and see if I can find anything by searching the key word ntdsutil. I found 1 event which had a very long and complicated command. I had to do some research to fully understand what it meant and what had been done on the computer. I explain it more at the end of the write-up, but for now I was able to learn that a temp folder was created with a file called temp.dit on server01 so the next thing I searched was for that file. 3 events showed up and we found the one we looking for. Ans: d5ag0nm@5t3r

<img width="951" height="416" alt="NTD1" src="https://github.com/user-attachments/assets/6cb848a2-a5db-479b-9882-fddc1ab0581e" />
<img width="956" height="317" alt="WMICP" src="https://github.com/user-attachments/assets/f1f0c60e-3211-4ba9-92c9-e2f85a865791" />






### Findings

* User account targeted
* Source IP
* Timestamp
* Initial payload or command

---

## Task 4: Persistence

Our target APT frequently employs web shells as a persistence mechanism to maintain a foothold. They disguise these web shells as legitimate files, enabling remote control over the server and allowing them to execute commands undetected.

### Questions asked:

1. To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?

----------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough
1) For this one the question essentially told us that web shells were placed in the environment, but we don't know where so I decided to check the mitre attack page since the over arching theme of this ctf is the threat actor Volt Typhoon. I just went to their page on Mitre and search for webshell as a keyword to see if anything was documented about them using webshells. I was able to find that they specially have used two webshells in past campagins and did a search for them. We are able to see what folder they are in my looking at the 1 event found in the log. Ans: C:\Windows\Temp\

<img width="949" height="442" alt="TF1" src="https://github.com/user-attachments/assets/130403b5-9619-4597-8aee-0050cc0c04ae" />

<img width="955" height="392" alt="image" src="https://github.com/user-attachments/assets/bb680b10-0ce1-4ab8-ac94-da80a71a86f4" />


### Findings

Document how the attacker enumerated the environment.

---

## Task 5: Defense Evasion

Volt Typhoon utilizes advanced defense evasion techniques to significantly reduce the risk of detection. These methods encompass regular file purging, eliminating logs, and conducting thorough reconnaissance of their operational environment.

### Questions asked:

1. In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?
2.The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?
3. Under what regedit path does the attacker check for evidence of a virtualized environment? 

----------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough
1) First thing I did was filter into the powershell logs with the time filter still set to all the events after the dean-admin account was compromised. I also used the keywords "RDP", "Most", "delete",  and "remove" to see if that will narrow down the searches. "Delete", "RDP", and "Most" didn't return anything, but remove returned 6 events which had the answer. Ans: Remove-ItemProperty

<img width="952" height="196" alt="Remove1" src="https://github.com/user-attachments/assets/7295c4aa-9f7a-413e-955d-4b383e7c5819" />
<img width="952" height="413" alt="Remove2" src="https://github.com/user-attachments/assets/647c8ed4-2636-47d9-b5a3-710e2801bf30" />

---
2) This question was more of a grind, I didn't have any keyword or anything I could think of that would help so again I set the time filter to see all the events after the dean-admin account was compromised and looked through them one by one. Luckily I didn't have to go too far, I eventually came upon this command that looked suspicous simply because I had been starting to get familiar more and more WMIC and how to read those commands through the course of this challenge. After researching this one as well I found it had the answer. Ans: cl64.gif

<img width="950" height="233" alt="EXT2" src="https://github.com/user-attachments/assets/ac263560-7102-46ab-889f-652c3e044424" />


<img width="952" height="421" alt="EXT1" src="https://github.com/user-attachments/assets/9be2b5c7-a124-45f9-8bd5-ca0ff32188f9" />

---
3) I just used the keyword virtal to look for anything since dean's account was compromised and found 1 event. Ans: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control

<img width="949" height="411" alt="Virtual1" src="https://github.com/user-attachments/assets/8926a8e6-d066-411b-86cd-d41239fe8d4d" />


### Findings

Document persistence artifacts discovered.

---

## Task 6: Credential Access

Volt Typhoon often combs through target networks to uncover and extract credentials from a range of programs. Additionally, they are known to access hashed credentials directly from system memory.

### Questions asked:

1. Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate? Answer Format: Alphabetical order separated by a comma and space.
2. What is the full decoded command the attacker uses to download and run mimikatz?
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough

Identify activity indicating elevated privileges.

### Findings

* New administrator accounts
* Token manipulation
* Service abuse

---

## Task 7: Discovery & Lateral Movement

Volt Typhoon uses enumeration techniques to gather additional information about network architecture, logging mechanisms, successful logins, and software configurations, enhancing their understanding of the target environment for strategic purposes.

The APT has been observed moving previously created web shells to different servers as part of their lateral movement strategy. This technique facilitates their ability to traverse through networks and maintain access across multiple systems.

### Questions asked:

1. The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for? Answer Format: Increasing order separated by a space.
2. Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?

----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Walkthrough

Investigate movement between hosts.

### Findings

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

