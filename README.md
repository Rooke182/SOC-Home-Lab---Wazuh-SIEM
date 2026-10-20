# SOC Home Lab — Windows Failed Logon Detection with Wazuh

A hands-on cybersecurity home lab demonstrating how **Windows failed-logon events (Event ID 4625)** can be captured on an endpoint, forwarded to **Wazuh SIEM**, and investigated through security logs and alerts.

This is a controlled learning project, not an investigation of a real attack.

## At a glance

- **Goal:** Verify end-to-end visibility of unsuccessful Windows sign-ins in a SIEM.
- **Environment:** Oracle VirtualBox, Ubuntu Server hosting Wazuh Manager, and a Windows 11 endpoint running the Wazuh agent.
- **Tools:** Wazuh SIEM, Windows Event Viewer, PowerShell, `auditpol`, and `Get-WinEvent`.
- **Result:** Confirmed **two Windows Event ID 4625 records** on the endpoint and **two corresponding Wazuh alerts**.

## Lab architecture

```text
Windows 11 virtual machine
  └─ Windows Security log (Event ID 4625)
       └─ Wazuh agent
            └─ Wazuh Manager (Ubuntu Server VM)
                 └─ Wazuh dashboard / Threat Hunting
```

The virtual machines ran in an isolated lab setup for learning and testing.

## Investigation workflow

1. **Verify endpoint monitoring:** Checked that the Windows Wazuh agent service was running and that the endpoint appeared as active in the Wazuh Manager.
2. **Check audit configuration:** Used `auditpol` to confirm Windows Logon auditing included both success and failure events.
3. **Test and troubleshoot:** An initial `runas` test did not produce a confirmed Event ID 4625. Rather than assuming a SIEM problem, checked the local Windows Security log.
4. **Generate controlled failed sign-ins:** Locked the Windows workstation and deliberately entered incorrect credentials.
5. **Confirm source events:** Queried Windows Security events using PowerShell; two Event ID 4625 records appeared.
6. **Verify SIEM ingestion:** Filtered Wazuh Threat Hunting for Event ID 4625 and found two corresponding alerts from the monitored endpoint.
7. **Review event details:** Examined logon type and status/substatus fields to understand the cause of the failed authentication.

### Example investigation commands

```powershell
# Confirm whether Windows audits unsuccessful logons
auditpol /get /subcategory:"Logon"

# Inspect recent failed-logon events on the Windows endpoint
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
```

Wazuh Threat Hunting filter:

```text
data.win.system.eventID: 4625
```

## Findings

| Observation | Interpretation |
| --- | --- |
| **Windows Event ID 4625** | An account failed to log on. |
| **Logon type 2** | An interactive sign-in attempt, consistent with the local test. |
| **Status 0xC000006D** | Authentication failed. |
| **Substatus 0xC000006A** | Incorrect password. |
| **Wazuh rule 60122, level 5** | The collected event matched a Wazuh failed-logon rule and appeared for review. |
| **Two Windows records and two Wazuh alerts** | Supported successful collection and central visibility of the controlled test events. |

**Conclusion:** The investigation validated the path from Windows Security auditing to Wazuh alert visibility and demonstrated basic endpoint monitoring, log analysis, and security event triage.

## Troubleshooting and lessons learned

- A command returning an error does **not** automatically prove a particular security event was logged.
- Check the **source endpoint's events** before assuming the SIEM is failing to ingest them.
- Verify **agent health, connectivity, and audit policy** as part of troubleshooting.
- Use Windows **status, substatus, and logon-type fields** to interpret alerts rather than relying on alert titles alone.
- Document failed tests as well as successful ones so findings can be reproduced.

## Scope and limitations

- All sign-in attempts were **deliberately generated in a lab**.
- The observed events do **not** demonstrate brute-force activity, an external intruder, or a compromised account.
- No custom Wazuh detection rule, automated response, or production remediation was implemented during this exercise.
- Screenshots were captured at different times, so they should not be treated as evidence of one uninterrupted session.

## Evidence and report

A detailed technical investigation report and supporting screenshots were produced during the lab. **They are not included in this public repository yet** while the material is reviewed for personal or sensitive information.

## Potential next steps

- [ ] Add reviewed and redacted screenshots and the investigation report.
- [ ] Repeat tests with multiple controlled failed sign-ins and examine thresholds and patterns.
- [ ] Explore custom Wazuh alert rules and document their behaviour.
- [ ] Create a small script for parsing or summarising Windows authentication events.

---

*Personal cybersecurity learning project. Documented findings are based on controlled lab activity.*
