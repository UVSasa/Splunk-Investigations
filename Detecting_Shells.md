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
**SPL queries**

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

The attacker during this phase after enumerating their target/s, will craft their payload that will exploit the weakness or vulnerability in the system. Here as the "attacker" I used metaspolit or more specifically MSFvemon to craft my payload. 

1) First I selected a reverse shell payload appropriate to the target OS/architecture of the "victim" machine ( windows/x64/meterpreter/reverse_tcp).
2) In the payload I set the LHOST/LPORT to connect back to my kali machine. Then I output the payload as an executeable file format matching the target platform (in this case .exe), representing how an attacker packages code for a specific victim environment.
3) I then named the file in a way to create a believable reason for the "victim" to click it and gave it a double file extension(.pdf.exe). This is because in real life attacker often rely on social engineering—manipulating people into opening a file or clicking a link. Also attackers often use double file extensions to trick users into believing a file is safe when it is actually executable.
4) I also noted (without executing) the concept of encoding/obfuscaton options MSFvenom offers, and why real-world attackers use them to reduce static signature detection.


<img width="2542" height="664" alt="image" src="https://github.com/user-attachments/assets/eb2825d9-ff3a-4a0e-ba92-415242e834f9" />


------------------

**Splunk Analysis**

During the Weaponization stage, no telemetry is generated because the attacker is preparing the malicious payload offline. In this lab, the payload is a reverse shell that will be delivered in the next stage. The focus moving forward is to detect the execution of the payload, the establishment of the reverse shell connection, and the attacker activity that follows using Splunk and Sysmon logs.

**Framework Mapping**
- Cyber Kill Chain: Weaponization
- MITRE ATT&CK Mapping:
   - From the attacker's pov the phase demonstrates understanding of how adversaries tailor payloads to a target rather than using generic tooling. This is a core TTP mapped to MITRE ATT&CK T1587.001 (Develop Capabilities: Malware)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Stage 3: Delivery

**Attacker Activity**
1) Here as the attacker I stood up a simple HTTP server (python3 -m http.server) on the attacker VM in the directory containing the payload, representing an adversary-controlled staging/distribution point.
2) From the target machine, initiated an outbound HTTP request (via browser or command-line tool like curl/certutil, depending on OS) to pull the file down - simulating a user or script fetching a malicious file, similiar phishing-link or waterhole delivery in the wild.
3) Confirmed successful transfer by validating the file existed on the target with matching hash to the source payload
4) Kept this entirely within an isolated, host-only lab network with no internet-facing exposure, since delivery in a real intrusion would typically ride over email, a compromised website, or USB - I used HTTP as a safe, observable stand-in for those vectors.

The first image is the python server, the second is the commad to download the payload from the server(simulating clicking a phishing link), the third is showing the payload on the "victim" machine with view file extension off, and the fourth is the payload on the "victim with view file extension on.

<img width="1508" height="626" alt="image" src="https://github.com/user-attachments/assets/9f56f8a9-e22a-4f70-9a3b-c5ca9c885f3d" />

<img width="865" height="227" alt="Delivery2" src="https://github.com/user-attachments/assets/c0b3722b-ba32-41c0-b018-2f79a82c3287" />

<img width="832" height="446" alt="Delivery3" src="https://github.com/user-attachments/assets/497c5f9e-4afe-4dfe-a802-0df7486f5f54" />

<img width="956" height="444" alt="Delivery1" src="https://github.com/user-attachments/assets/37652892-6bd2-4541-81e9-4bd9086e1c86" />


----------------------


**Splunk Analysis**

The objective was to detect indicators of initial access, malicious execution, file delivery, and outbound network communication by correlating Sysmon process creation, network connection, and file creation events. I decided to create a dashboard to provide real-time visibility into attacker activity using Sysmon Event IDs 1 (Process Creation), 3 (Network Connection), and 11 (File Creation).


---------------------------

**Detection opportunities**

The focus was on identifying common attacker techniques associated with malware delivery and execution like:
- How many Living-off-the-Land Binaries (LOLBins) such as certutil.exe, bitsadmin.exe, curl.exe, mshta.exe, regsvr32.exe, and rundll32.exe were executed in a day.
- PowerShell execution, including encoded commands and suspicious command-line arguments.
- Monitoring total network connections to dectect downloads to and from HTTP/HTTPS services, including internal Python web servers used to simulate malware hosting. This was also used to detect malicious ip addresses.
- Monitoring what processes were most responsible for the creation of executable and script files (.exe, .dll, .ps1, .bat, .vbs, .js) that may indicate payload delivery. 


<img width="295" height="216" alt="Dashboard 4" src="https://github.com/user-attachments/assets/35aa0ba7-efef-47d3-9557-88dbc7694436" />

----

**SPL queries**

Here are a few or the SPL queries in the dashboard

- index=main EventCode=3 | stats count by Image DestinationIp | sort -count

   (This search provides a summary of all Sysmon network connection events (Event ID 3) and identifies which processes are making the most outbound network connections and to which destination IP addresses.)

- index=main EventCode=11 (Image="*.exe" OR Image="*.dll" OR Image="*.ps1" OR Image="*.bat" OR Image="*.vbs" OR Image="*.js" OR Image="*.hta") | stats count by Image | sort - count

   (Summarizes which processes are creating the most executable and script files. Helpful to identify potentially suspicious processes.)

- index=main EventCode=1 (Image="*certutil.exe" OR Image="*bitsadmin.exe" OR Image="*mshta.exe" OR Image="*regsvr32.exe" OR Image="*rundll32.exe" OR Image="*curl.exe") | stats count by Image CommandLine

  (Searches the main index for Sysmon Event ID 1 (Process Creation) events and filters the results to only show processes commonly abused by attackers for payload delivery, execution, or defense evasion)

----

**Framework Mapping**
- Cyber Kill Chain: Delivery
- MITRE ATT&CK Mapping:
    - This maps to MITRE ATT&CK T1105(Ingress Tool Transfer) and demonstrates understanding of how delivery infrastructure works even when the "lure" mechanism (phishing, watering hole) is simulated rather than literally repliicated.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 4: Exploitation

**Attacker Activity**
Here we will assume a bit from the mind of the end user/victim. 

After the victim downloaded the file HolidayBonus2026.pdf.exe, they executed it by double-clicking the attachment. Although the filename appeared to be a PDF document, it was actually an executable disguised through the use of a double file extension. This social engineering technique relies on Windows hiding known file extensions, causing the victim to believe they were opening a legitimate document. This is where me as the "attacker" can begin to transition from attempting to access the target to establishing control over the system.

After successfully exploiting the target, the attacker typically performs post-exploitation discovery to better understand the environment and determine their next steps. This may include gathering information about the compromised host, such as the operating system, user privileges, network configuration, running processes, and available resources. This information helps the attacker identify potential opportunities for persistence, lateral movement, or achieving their final objectives.

The images below are just a few of the commands I ran once gaining the shell on the target. Some other ones were ipconfig,netstat, driverquery, netuser, etc.

<img width="1038" height="354" alt="image" src="https://github.com/user-attachments/assets/0c941d04-9d4b-482a-a658-3a47af2ae3d7" />


<img width="1672" height="792" alt="image" src="https://github.com/user-attachments/assets/0d7c146a-7ff9-482a-af21-41652687ca69" />


<img width="1500" height="470" alt="image" src="https://github.com/user-attachments/assets/586e37ce-f235-4d80-94a9-313833f1879b" />



-----------------------
**Splunk Analysis**

When trying to detect exploitation, I decided to focus on detecting behaviors commonly performed immediately after gaining access, such as system and user enumeration. This is because after gaining a foothold on a target an attacker has to essentially restart the attack process by enumerating their surrounds to see what devices are connected, what services are running etc,. 

-------

**Detection opportunities**

I used SPL searches and edited sysmon configurations to detect behaviors commonly observed immediately after an attacker gains access to a system, including:
- Execution of Windows discovery commands such as whoami, hostname, systeminfo, ipconfig, tasklist, and netstat.
- Command Prompt and PowerShell activity used to execute reconnaissance and administrative commands.
- The creation of temporary directories and files being used to store data to be exfiltrated later.

<img width="952" height="452" alt="Exploit2" src="https://github.com/user-attachments/assets/820d2632-ca1f-43b1-bdd5-87cd6a7316a4" />

<img width="782" height="346" alt="Exploit3" src="https://github.com/user-attachments/assets/edbeffa2-302e-4567-a1ef-d2796d5aff34" />



**Framework Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 5: Installation

**Attacker Activity**
During this phase, the following persistence techniques were simulated:

   - Created a new local user account.
   - Added the account to the local Administrators group.
   - Configured registry Run keys to automatically execute a program during user logon.
   - Verified that the persistence mechanisms remained active after reboot.

<img width="1044" height="434" alt="image" src="https://github.com/user-attachments/assets/68252544-65a4-4c0b-b63b-bf504b2a97c3" />


<img width="2230" height="252" alt="image" src="https://github.com/user-attachments/assets/c38338e7-40e8-4a36-8054-fa1ed6def838" />





-----------------------------

**Splunk Analysis**
From a defender's perspective, the Installation stage focuses on identifying evidence that an attacker has established persistence to maintain access after the initial compromise. During this phase, we monitor for behaviors such as the creation of new user accounts, changes to registry autorun locations, scheduled tasks, or other persistence mechanisms. Detecting these activities early is critical because they indicate an attacker is preparing for long-term access, enabling defenders to contain the threat before additional objectives such as privilege escalation, lateral movement, or data exfiltration occur.

The SPL searches were developed to identify:
- Registry modifications to common persistence locations, including Run and RunOnce registry keys.
- Creation and modification of registry values that could automatically execute programs during user logon.
- Execution of administrative commands such as net user and net localgroup used to enumerate or modify local user accounts.

**Detection opportunities**

<img width="1917" height="880" alt="Screenshot 2026-07-23 084044" src="https://github.com/user-attachments/assets/dd392dfc-e9ce-49cb-8f89-048172a9c7ae" />


**SPL Queries**

**Framework Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Stage 6: Command and Control (C2)

**Attacker Activity**
The objective of the Command and Control phase is to establish and maintain communication with a compromised system after gaining initial access. This communication channel allows the attacker to remotely interact with the host, execute commands, gather additional information, and continue operations without requiring direct access to the machine.

In this lab, a remote shell session was used to simulate a command and control channel between the attacker and compromised Windows system. Once established, the session allowed the attacker to interact with the host and perform post-exploitation activities.

-------------------------

**Splunk Analysis**
From a defender's perspective, the Command and Control phase focuses on identifying systems that have established unauthorized communication with an external host. During this phase, defenders monitor for unusual outbound connections, repeated beaconing patterns, and processes initiating unexpected network traffic. Detecting C2 activity is critical because it can reveal an active compromise, allowing security teams to isolate the affected system and disrupt the attacker's ability to remotely control the host before they can achieve their objectives.

**Framework Mapping**

**Other Key Takeaways**


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## Stage 7: Actions on Objectives

**Attacker Activity**
The objective of the Actions on Objectives phase is to achieve the ultimate goal of the attack after successfully compromising and maintaining access to the target system. Depending on the attacker's intent, this may involve locating and collecting sensitive information, transferring data to an external destination, disrupting system operations, deploying ransomware, or removing evidence to hinder forensic investigation. At this stage, the attacker seeks to maximize the value of the compromise before access is lost or the attack is detected.

<img width="1118" height="886" alt="image" src="https://github.com/user-attachments/assets/816069e2-fd56-4fa0-8298-c4b698b2ec52" />

<img width="1368" height="306" alt="image" src="https://github.com/user-attachments/assets/a4d4d758-7e41-4d3e-a0ca-118c78dc7ca0" />

<img width="1502" height="196" alt="image" src="https://github.com/user-attachments/assets/66ae0892-3d9c-4b93-af6b-5cba93826473" />

<img width="880" height="114" alt="image" src="https://github.com/user-attachments/assets/0cfa953e-cc14-410c-a7f5-da04b801cb2e" />

<img width="1008" height="114" alt="image" src="https://github.com/user-attachments/assets/9b85628f-4f9c-4f8c-89f4-d92355e3bdca" />







--------------------------

**Splunk Analysis**
Splunk was used to analyze Sysmon telemetry to identify attacker activity related to data extraction and cleanup operations. The goal of this phase was to detect behaviors that commonly occur after an attacker has gained access and is attempting to collect information while minimizing evidence left behind.

Sysmon provided endpoint visibility through process creation, file activity, and network telemetry, which was ingested into Splunk for investigation.


The analysis focused on identifying:

- File deletion activity used to remove attacker-created artifacts
- Execution of cleanup commands through command-line utilities
- Potential data staging locations commonly used before exfiltration
- Network connections that could indicate potential data transfer


**Detection opportunities**

<img width="568" height="301" alt="Sysmon1" src="https://github.com/user-attachments/assets/ac5a8fae-ced7-4dab-92d0-825510490c04" />


**SPL Queries**

**Framework Mapping**

**Other Key Takeaways**
- Here I edited the sysmon config to detect files being delelted in common staging locations like the temp folder

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Summary




























