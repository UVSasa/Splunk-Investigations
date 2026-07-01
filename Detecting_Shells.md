# Detecting Shells in Splunk

📌 [Skip to the Summary, Key Takeaways, and Lessons Learned](#Summary) 

## Overview

This lab focuses on simulating the stages of a cyber attack within a controlled environment using Kali Linux, Metasploit, and other security tools. The objective is to emulate common attacker techniques, including persistence mechanisms and reverse/bind shell activity, while developing the ability to detect and investigate these behaviors in Splunk.

Throughout the lab, I will generate realistic attack telemetry and analyze the resulting logs to improve my threat detection, investigation, and threat hunting skills. In addition to strengthening my understanding of offensive security concepts, this project serves as an opportunity to gain more hands-on experience with Splunk, create effective searches and detections, and better understand how attacker actions appear from a defender's perspective.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Cyber Kill Chain

As part of this lab, I am also studying the Cyber Kill Chain to better understand how adversaries plan and execute attacks. The framework breaks an attack into a series of stages, allowing defenders to identify where malicious activity is occurring and implement detections to disrupt the attack before it reaches its objective.

**The Cyber Kill Chain consists of seven phases:**

1. **Reconnaissance** – Gathering information about the target. In this phase of my lab as the "attacker" I will be using kali linux/metaspolit to enumerate the target machine for open ports, services, known devices, vulnerabilities, firewall enumeration, and other things to understand what that behavior looks like in splunk.
2. **Weaponization** – Preparing tools, malware, or exploits for the attack. Here I will be using metaspolit to craft a "malicious payload" in the form of a reverse shell/bind shell using msfvenom in metasploit.
3. **Delivery** – Transmitting the malicious payload to the target. Using the assumption that me as the "atttacker" has already made it onto the network I will deliver the payload via ....
4. **Exploitation** – Triggering a vulnerability or executing malicious code.
5. **Installation** – Establishing a foothold on the system. As the "attacker" here I will create a loacl user account.
6. **Command and Control (C2)** – Creating a communication channel to remotely control the compromised host.
7. **Actions on Objectives** – Achieving the attacker's goal, such as data theft, persistence, or lateral movement.



Understanding these stages helps provide context for the activities performed throughout this lab and supports the development of more effective detection and response strategies in Splunk. The overall goal is to detect these stages in my splunk instance.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Attack Timeline

## Stage 1: Reconnaissance

**Attacker Activity**

In any environment an attackers first step is to gather information about their target/targets. In this lab we are assuming an attacker has already made it into our network or just has access to a network that multiple devices are connected to, for example like free hotel, airport, or cafe wifi. Here as the "attacker" in my kali vm I ran many enumeration commands using nmap to see what hosts I could discover and what services they have running.

- **Commands executed**
    - sudo nmap -PR -sn 192.168.1.0/24 (arp scan for local subnets)
    - sudo nmap -sS 192.168.1.10 (TCP SYN Scan (stealth) for port scanning)
    - command sudo nmap -PP -sn 192.168.1.0/24 (timestamp)(for firewall enumeration)
    - command sudo nmap -PM -sn 192.168.1.0/24 (address mask)(for firewall enumeration)
  
- **Screenshots**


<img width="2564" height="1450" alt="image" src="https://github.com/user-attachments/assets/26d3ee11-9530-446b-8cf4-5d7aa4794a0f" />

<img width="2542" height="1656" alt="image" src="https://github.com/user-attachments/assets/2a6ed3b7-a18f-4623-8fb8-a24dbd95f729" />




------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Splunk Analysis**

When thinking about the best way to detect enumeration attempts like port scanning or host discovery you'll find that detecting these allign more on the network side of things. This is because by nature they are connection attempts to the system that including things like the source IP, destination port, and whether the attempt was allowed or blocked. The best way to capture this network activity is with network monitoring tools like firewalls. Therefore in order to get better at detecting this activity at it's basic level I just decided to ingest window's pfirewall logs into splunk to see if we can recognize any reconnaissance patterns and report on them.

This was a learning point for me because I had to learn the hard way that the basic PFireWall logs in windows were not specific enough to reliably detect Nmap scans on their own. Rather than forcing detections that produced inconsistent results, I shifted my focus to the firewall's strengths—monitoring allowed and blocked network connections, identifying unusual connection patterns, tracking dropped traffic, and identifying potentially suspicious network activity. To accurately detect scanning tools like snort or zeek would be leagues better.

- **Relevant logs**

- **Detection opportunities**

Here is the dashboard I built. While it didn't reliably give insight on potential scanning it can give insight to the network traffic in an individual's or organization's network. 


<img width="631" height="341" alt="DR1" src="https://github.com/user-attachments/assets/fdb83cad-0966-4b1a-b167-1db33972e2f6" />



---
- **SPL queries**

Here are a few or the SPL queries in the dashboard

- index=main sourcetype=pfirewall | bucket _time span=1h | stats count(eval(action="DROP")) as drop_count by src_ip _time | where drop_count > 20 | sort - drop_count

   (identifies source IP addresses that generated more than 20 dropped firewall events within a one-hour period, helping detect potentially suspicious or malicious network activity such as port scanning or repeated connection attempts)

- index=* sourcetype= "Pfirewall" action="DROP" | timechart span=1h count

     (displays the number of dropped firewall events over time, can be valuable in seeing spikes of dropped packet)

- index=main sourcetype=pfirewall | stats count by dst_ip | sort - count | head 10

  (displays the top 10 most frequently targeted destination IPs)

- index=* sourcetype= "Pfirewall" action="DROP" | stats count

     (overall number of blocked network connections)

---
**Framework Mapping**
- Cyber Kill Chain: Reconnaissance
- MITRE ATT&CK Mapping:
    - The scanning techniques used to generate telemetry align with the Reconnaissance (TA0043) tactic and the Active Scanning (T1595) technique. The Splunk search identifies noisy hosts, common connections, traffic spikes, ips with a high number of dropped packets, and hosts attempting a high number of connections within a short time window, which is behavior commonly associated with network reconnaissance and service discovery.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Stage 2: Weaponization

**Attacker Activity**




**Splunk Analysis**

During the Weaponization stage, no telemetry is generated because the attacker is preparing the malicious payload offline. In this lab, the payload is a reverse shell that will be delivered in the next stage. The focus moving forward is to detect the execution of the payload, the establishment of the reverse shell connection, and the attacker activity that follows using Splunk and Sysmon logs.

**Framework Mapping**
- Cyber Kill Chain: Reconnaissance
- MITRE ATT&CK Mapping:
    - None. The Weaponization stage occurs on the attacker's system while preparing the malicious payload and does not involve activity within the target environment that is represented in the ATT&CK framework.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Stage 3: Delivery

**Attacker Activity**
- Delivering payload to the target
- File transfer or exploit delivery

**Splunk Analysis**
- Process creation events
- File creation activity
- Network activity

**MITRE ATT&CK Mapping**
- 
**Other Key Takeaways**


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 4: Exploitation

**Attacker Activity**
- Exploiting the vulnerability
- Code execution
- Initial shell access

**Splunk Analysis**
- Event IDs observed
- Process tree analysis
- SPL searches

**MITRE ATT&CK Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 5: Installation

**Attacker Activity**
- Create attacker account
- Add account to Administrators
- Scheduled task creation
- Service creation
- Registry persistence

**Splunk Analysis**
- User account creation events
- Group membership changes
- Scheduled task logs
- Service installation logs

**MITRE ATT&CK Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Stage 6: Command and Control (C2)

**Attacker Activity**
- Reverse shell
- Bind shell
- Meterpreter session

**Splunk Analysis**
- Network connection events
- Parent-child process relationships
- Listening ports
- Outbound connections

**MITRE ATT&CK Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 7: Actions on Objectives

**Attacker Activity**
- Credential dumping
- Sensitive file access
- Privilege escalation
- Lateral movement
- Data collection

**Splunk Analysis**
- Relevant logs
- Investigation workflow
- SPL searches

**MITRE ATT&CK Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Summary




























