## Overview

This lab focuses on simulating the stages of a cyber attack within a controlled environment using Kali Linux, Metasploit, and other security tools. The objective is to emulate common attacker techniques, including persistence mechanisms and reverse/bind shell activity, while developing the ability to detect and investigate these behaviors in Splunk.

Throughout the lab, I will generate realistic attack telemetry and analyze the resulting logs to improve my threat detection, investigation, and threat hunting skills. In addition to strengthening my understanding of offensive security concepts, this project serves as an opportunity to gain more hands-on experience with Splunk, create effective searches and detections, and better understand how attacker actions appear from a defender's perspective.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Cyber Kill Chain

As part of this lab, I am also studying the Cyber Kill Chain to better understand how adversaries plan and execute attacks. The framework breaks an attack into a series of stages, allowing defenders to identify where malicious activity is occurring and implement detections to disrupt the attack before it reaches its objective.

**The Cyber Kill Chain consists of seven phases:**

1. **Reconnaissance** – Gathering information about the target. In this phase of my lab as the "attacker" I will be using kali/metaspolit to enumerate the target machine for open ports, services, known devices, vulnerabilities, firewall enumeration, and other things to understand what that behavior looks like in splunk.
2. **Weaponization** – Preparing tools, malware, or exploits for the attack. Here I will be using metaspolit to craft a "malicious payload" in the form of a reverse shell/bind shell using msfvenom in metasploit.
3. **Delivery** – Transmitting the malicious payload to the target. Using the assumption that me as the "atttacker" has already made it onto the network I will deliver the payload via ....
4. **Exploitation** – Triggering a vulnerability or executing malicious code.
5. **Installation** – Establishing a foothold on the system. As the "attacker" here I will create a loacl user account.
6. **Command and Control (C2)** – Creating a communication channel to remotely control the compromised host.
7. **Actions on Objectives** – Achieving the attacker's goal, such as data theft, persistence, or lateral movement.



Understanding these stages helps provide context for the activities performed throughout this lab and supports the development of more effective detection and response strategies in Splunk. The overall goal is to detect these stages in my splunk instance.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------


