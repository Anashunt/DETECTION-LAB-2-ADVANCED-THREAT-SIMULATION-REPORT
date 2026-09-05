# DetectionLab 2 — Advanced Threat Simulation & Detection

This repository documents an advanced **Active Directory attack simulation and Blue Team detection lab** built using the DetectionLab environment.

The objective of this lab was to simulate a realistic multi-stage attack against an Active Directory domain and investigate the resulting activity from a **SOC and Detection Engineering perspective**.

The lab focused on understanding how advanced attacks such as **Golden Ticket forgery, DCSync, Pass-the-Hash, Mimikatz credential harvesting, lateral movement, persistence, and DNS exfiltration** appear across Windows Event Logs, Splunk, and network traffic.

---

## Lab Environment

The lab was built around a Windows Active Directory environment containing multiple systems generating security telemetry.

### Infrastructure

| Host                  | IP Address       | Role                     |
| --------------------- | ---------------- | ------------------------ |
| `dc.windomain.local`  | `192.168.56.101` | Domain Controller        |
| `wef.windomain.local` | `192.168.56.103` | WEF Collector            |
| `Kali Linux`          | `192.168.56.104` | Attacker Machine         |
| `logger`              | `192.168.56.105` | Splunk / Zeek Log Server |

### Technologies

* Active Directory
* Kerberos
* Windows Event Forwarding (WEF)
* Splunk Enterprise
* Zeek
* Sysmon
* Wireshark
* Kali Linux
* Impacket
* Mimikatz
* Nmap
* Kerbrute
* Vagrant
* VirtualBox

---

## Attack Simulation

The lab simulated a complete multi-stage attack chain against the Active Directory environment.

### Attack Chain

```text
Network Reconnaissance
        ↓
Username Enumeration
        ↓
AS-REP Roasting Attempt
        ↓
Golden Ticket Forgery
        ↓
Domain Controller Compromise
        ↓
DCSync / NTDS Credential Extraction
        ↓
Pass-the-Hash
        ↓
Lateral Movement to WEF
        ↓
Mimikatz / LSASS Credential Harvesting
        ↓
Scheduled Task Persistence
        ↓
DNS Exfiltration
        ↓
Detection & Investigation
```

---

## Attack Techniques

### Network Reconnaissance

Nmap was used to identify active hosts and enumerate exposed services across the lab network.

The Domain Controller and WEF server were investigated for services including:

* Kerberos
* LDAP
* SMB
* WinRM
* RPC
* Splunk

SMB configuration was also reviewed, including the discovery that **SMB Signing was disabled on the WEF server**.

---

### Kerberos Enumeration

Kerbrute was used to identify valid domain accounts.

Confirmed accounts included:

* `administrator@windomain.local`
* `vagrant@windomain.local`

An AS-REP Roasting attempt was also performed.

The attack failed because the tested account had Kerberos pre-authentication enabled, demonstrating an effective security control.

---

### Golden Ticket

A compromised **krbtgt NT hash** was used to forge a Kerberos Ticket Granting Ticket.

The forged ticket allowed authentication as the `Administrator` account without requiring the user's password.

The ticket was created locally on Kali Linux and subsequently used for authentication against the Domain Controller.

This demonstrated the impact of a compromised `krbtgt` credential and the ability to establish long-term domain persistence.

---

### PSExec

The forged Kerberos ticket was used to access the Domain Controller through PSExec.

The attack resulted in:

* SMB access
* Service creation
* Execution as `LocalSystem`
* Interactive SYSTEM shell

The generated service and executable provided valuable detection artifacts through **Windows Event ID 7045**.

---

### DCSync

The forged Administrator identity was used to perform a DCSync attack against the Domain Controller.

The attack leveraged the **DRSUAPI replication protocol** to extract domain credential hashes from Active Directory.

This demonstrated that a compromised `krbtgt` credential can ultimately lead to complete domain credential compromise.

---

### Pass-the-Hash

Credentials obtained during the attack were used to perform lateral movement to the WEF server.

WMIExec was used with the recovered Administrator NT hash, allowing authentication without the plaintext password.

---

### Mimikatz

Mimikatz was executed on the compromised WEF server to access LSASS memory.

The investigation demonstrated credential exposure including:

* NTLM credentials
* Plaintext credentials
* Machine account credentials

The lab also demonstrated the security impact of **WDigest authentication being enabled**, which allowed plaintext credential recovery.

---

### Scheduled Task Persistence

A scheduled task named:

```text
SystemUpdateCheck
```

was created to execute at system startup as:

```text
NT AUTHORITY\SYSTEM
```

This demonstrated a persistence mechanism capable of surviving system restarts.

The task was intentionally given a legitimate-looking name to demonstrate how attackers can blend malicious persistence into normal Windows activity.

---

### DNS Exfiltration

The lab also simulated covert data exfiltration through DNS.

Data was placed inside a DNS query:

```text
ConfidentialDataHere.attacker.com
```

The query was sent to an attacker-controlled DNS server and analyzed as a potential covert communication channel.

This demonstrated how DNS can be abused to move information through a protocol that is commonly permitted across enterprise networks.

---

# Detection & Monitoring

A major objective of this lab was to identify the telemetry generated by each attack technique and correlate multiple sources during investigation.

### Primary Detection Sources

* Splunk
* Windows Security Event Logs
* Sysmon
* Zeek
* Wireshark

### Important Windows Events

| Event ID | Detection Focus                          |
| -------- | ---------------------------------------- |
| **4624** | Successful network logon                 |
| **4662** | Directory Service object access / DCSync |
| **4672** | Special privileges assigned              |
| **4698** | Scheduled task creation                  |
| **4768** | Kerberos TGT request                     |
| **4769** | Kerberos service ticket request          |
| **7045** | New service installation                 |

---

# Splunk Detection

Splunk was used to investigate the attack chain and identify suspicious authentication and privilege activity.

### Golden Ticket Detection

Investigated:

```text
EventCode=4769
Ticket_Encryption_Type=0x17
```

RC4 Kerberos encryption was observed in suspicious TGS activity involving the Administrator account.

---

### Suspicious Kerberos Logon

Event ID `4624` was investigated for:

```text
Logon_Type=3
Logon_Process=Kerberos
Source_Network_Address=192.168.56.104
```

The investigation identified Kerberos authentication originating from the Kali Linux host.

---

### DCSync Detection

Event ID `4662` was used to investigate suspicious directory replication activity.

The Administrator account generated multiple directory service access events consistent with DCSync behavior.

---

### PSExec Detection

Event ID `7045` exposed the service created by PSExec.

Observed artifacts included:

```text
Service Name: ltyV
Executable: %systemroot%\qVVgbUDh.exe
Account: LocalSystem
```

Randomly generated service names and executables combined with SYSTEM execution provided a strong detection signal.

---

### Privilege Escalation

Event ID `4672` was investigated for unexpected privileged activity.

Special privileges assigned to Administrator and other accounts were correlated with the corresponding attack phases.

---

# Network Detection with Wireshark

Wireshark was used to analyze the network traffic generated during the attack.

The packet capture contained:

* Kerberos traffic
* SMB traffic
* RPC traffic
* DRSUAPI communication
* Network reconnaissance
* WMIExec activity
* DNS traffic

### Key Network Indicators

```text
Kali → DC : Kerberos / 88
Kali → DC : SMB / 445
Kali → DC : RPC / 135
Kali → DC : DRSUAPI high-port traffic
Kali → WEF : RPC / WMI
Victim → DNS : Exfiltration queries
```

The I/O Graph also revealed multiple attack waves separated by a period of minimal network activity.

---

# Detection Evidence

The investigation correlated endpoint and network telemetry across the attack chain.

| Attack           | Splunk                   | Network Evidence          | MITRE ATT&CK |
| ---------------- | ------------------------ | ------------------------- | ------------ |
| Nmap             | Authentication artifacts | Port scanning / I/O spike | T1046        |
| Kerbrute         | 4768                     | AS-REQ traffic            | T1589.002    |
| Golden Ticket    | 4769 / 4624              | TGS-REQ from Kali         | T1558.001    |
| PSExec           | 7045                     | SMB traffic               | T1021.002    |
| DCSync           | 4662                     | DRSUAPI traffic           | T1003.003    |
| Pass-the-Hash    | 4624                     | SMB / RPC                 | T1550.002    |
| Mimikatz         | 4672                     | Endpoint activity         | T1003.001    |
| Scheduled Task   | 4698                     | Host-based persistence    | T1053.005    |
| DNS Exfiltration | Zeek DNS logs            | DNS queries               | T1071.004    |

---

# MITRE ATT&CK Coverage

The lab covered multiple tactics and techniques from the MITRE ATT&CK framework.

### Reconnaissance

* **T1046** — Network Service Scanning
* **T1589.002** — Gather Victim Identity Information: Username

### Credential Access

* **T1110.002** — Password Cracking: Password Cracking / AS-REP
* **T1558.001** — Steal or Forge Kerberos Tickets: Golden Ticket
* **T1003.001** — OS Credential Dumping: LSASS Memory
* **T1003.003** — OS Credential Dumping: NTDS

### Execution & Lateral Movement

* **T1021.002** — SMB/Windows Admin Shares
* **T1550.002** — Pass the Hash

### Persistence

* **T1053.005** — Scheduled Task/Job: Scheduled Task

### Exfiltration

* **T1071.004** — Application Layer Protocol: DNS

---

# Blue Team Recommendations

The lab highlighted several defensive controls that can reduce the impact of these attacks:

* Rotate the `krbtgt` password twice following suspected compromise.
* Reduce or eliminate RC4 Kerberos usage where possible.
* Monitor Kerberos authentication originating from unexpected systems.
* Deploy Credential Guard to reduce LSASS credential exposure.
* Disable WDigest authentication where not required.
* Monitor unusual DNS query length and frequency.
* Alert on suspicious scheduled task creation.
* Enable SMB Signing across domain systems.
* Correlate Windows Event Logs with network telemetry.
* Build behavioral detections rather than relying exclusively on individual Event IDs.

---

# Skills Demonstrated

* Active Directory Security Monitoring
* Advanced Kerberos Investigation
* Golden Ticket Detection
* DCSync Detection
* Pass-the-Hash Investigation
* LSASS / Mimikatz Detection
* Windows Event Log Analysis
* Splunk SPL
* Wireshark Network Analysis
* Zeek DNS Analysis
* SMB Investigation
* RPC / DRSUAPI Analysis
* Network Reconnaissance Detection
* Persistence Detection
* DNS Exfiltration Detection
* Event Correlation
* Threat Hunting
* Detection Engineering
* MITRE ATT&CK Mapping
* Incident Investigation

---

# Repository Structure

```text
DetectionLab/
│
├── README.md
├── DetectionLab-2-Report.pdf
│
└── Screenshots/
    ├── Splunk-Golden-Ticket-4769.png
    ├── Splunk-Golden-Ticket-4624.png
    ├── Splunk-DCSync-4662.png
    ├── Splunk-PSExec-7045.png
    ├── Splunk-Privilege-4672.png
    ├── Splunk-WMIExec-4624.png
    ├── Wireshark-Kerberos.png
    ├── Wireshark-SMB.png
    ├── Wireshark-DRSUAPI.png
    ├── Wireshark-IO-Graph.png
    └── DNS-Exfiltration.png
```

---

# Objective

The objective of DetectionLab 2 was to progress from basic Windows and Active Directory monitoring toward **advanced attack-chain detection and investigation**.

The lab demonstrated how a Blue Team can correlate multiple telemetry sources:

```text
Attack
  ↓
Endpoint Activity
  ↓
Windows Security Events
  ↓
Sysmon / Zeek
  ↓
Network Traffic
  ↓
Splunk
  ↓
Event Correlation
  ↓
Threat Detection
  ↓
Investigation
```

This project focuses on the defender's perspective: understanding attacker behavior, identifying the telemetry generated by each technique, correlating evidence across multiple sources, and developing detections capable of identifying advanced Active Directory attacks.
