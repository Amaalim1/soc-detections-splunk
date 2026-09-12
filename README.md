# Home SOC Lab — Detection Engineering Portfolio

A self-built Security Operations lab used to practice attacking and detecting
real techniques against a small simulated Active Directory environment.

## Lab Architecture

| Component | Role | Details |
|---|---|---|
| Windows 10 | Client / workstation | Sysmon (SwiftOnSecurity config) + Security log + PowerShell Script Block Logging, forwarded via Splunk UF |
| Windows Server 2019 | Domain Controller | AD DS, DNS, forest `corp.local` (NetBIOS `CORP`); Advanced Audit Policy enabled for Kerberos, Account Management, DS Access |
| Ubuntu | Splunk Enterprise (indexer/search head) | Receives forwarded logs on port 9997, indexes into `endpoint` |
| Kali Linux | Attacker | Runs all offensive tooling (netexec, kerbrute, Impacket, etc.) |

All four hosts run on the same isolated virtual network.

## Simulated Organization

A small fictitious company was built inside `corp.local` to give detections
something realistic to work against:

- **5 departments (OUs):** IT, Finance, HR, Sales, Executives
- **15 standard user accounts** (3 per department)
- **`svc.itadmin`** — dedicated Domain Admin service account (kept separate
  from the built-in Administrator, matching real-world practice)
- **`svc.backup`** — deliberately configured with Kerberos pre-authentication
  disabled (AS-REP roastable)
- **`svc.sql`** — deliberately assigned an SPN (Kerberoastable)

See [`org-builder/build-fake-org.ps1`](org-builder/build-fake-org.ps1) for the
script used to provision all of this in one pass.

## Logging Pipeline

Both the client and the DC forward to a shared Splunk indexer:

- **Client:** Sysmon Operational, Security, PowerShell Operational logs
- **DC:** Security log with Advanced Audit Policy enabled for:
  - Kerberos Authentication Service / Service Ticket Operations
  - User / Security Group / Computer Account Management
  - Directory Service Access / Changes
  - Logon / Logoff

Notable lessons learned while building this pipeline (documented in
[`docs/pipeline-troubleshooting.md`](docs/pipeline-troubleshooting.md)):
- Sysmon's ETW **provider** ACL is separate from the channel ACL — a service
  account with correct channel read access can still fail to subscribe
  (`errorCode=5`) unless it also has provider-level access. Simplest fix:
  run the forwarder as `LocalSystem` rather than the default virtual service
  account.
- Windows hides file extensions by default, which silently produced an
  `inputs.conf.py` file that Splunk never read — always verify extensions
  are visible before editing forwarder configs.
- NTLM authentication (Event 4776) does not include a source IP field the
  way Kerberos events do — an important limitation when building
  network-based detections.

## Detections

| Technique | ATT&CK ID | Write-up |
|---|---|---|
| Password Spraying | T1110.003 | [`detections/password-spray/`](detections/password-spray/) |

More to come — this repo will grow as additional techniques (Kerberoasting,
AS-REP Roasting, DCSync, lateral movement) are run against the lab.

## Why this exists

Built as hands-on practice for detection engineering / blue team work,
documenting both the infrastructure build-out and the attack-to-detection
process the way a SOC analyst would triage and report a real finding.
