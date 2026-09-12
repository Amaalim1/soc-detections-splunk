# Lessons Learned: Building the Logging Pipeline

Setting up telemetry from scratch surfaced several non-obvious issues worth
documenting — these cost real debugging time and are easy to hit again.

## 1. Sysmon events silently failing with `errorCode=5`

**Symptom:** Splunk Universal Forwarder connected fine to the indexer,
`inputs.conf` was correctly configured, but no Sysmon events ever arrived —
only Security log events did.

**Root cause:** `splunkd.log` showed repeated:
```
WinEventLogChannel::init: Init failed, unable to subscribe to Windows Event
Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5
```
Error 5 is Windows for **Access Denied**. The forwarder's default service
account (`NT SERVICE\SplunkForwarder`) was a member of the built-in
**Event Log Readers** group, which *does* have read access to the Sysmon
**channel** ACL — but Sysmon's ETW **provider** has its own, separate access
control that isn't covered by channel permissions alone. Channel access and
provider access are two different permission layers; having one doesn't
guarantee the other.

**Fix:** Run the forwarder service as `LocalSystem`, which has unrestricted
access to all event log channels and providers:
```powershell
sc.exe config SplunkForwarder obj= LocalSystem
Restart-Service SplunkForwarder
```

## 2. Windows hiding file extensions caused a silently broken config

**Symptom:** `inputs.conf` appeared to exist in the right folder, Splunk
gave no error on restart, but no new data arrived.

**Root cause:** File name extensions were hidden in Explorer. A file saved
as `inputs.conf` actually saved as `inputs.conf.py` (some other tool had
`.conf` associated with an editor that appended its own extension). Since
Splunk only reads files matching exact expected names, `inputs.conf.py` was
never loaded — with no error, since as far as Splunk was concerned the file
simply didn't exist.

**Fix:** Enable **View → File name extensions** before creating/editing any
Splunk config file, or create/verify files via PowerShell (`Get-Content`,
heredoc `@"..."@ | Out-File`) instead of relying on Explorer's file listing.

## 3. NTLM events (4776) lack a clean source-IP field

**Symptom:** A detection query built assuming Kerberos-style fields
(`Client_Address`) returned nothing against NTLM authentication events.

**Root cause:** Event 4776 (NTLM credential validation) only exposes a
`Logon_Account` field for the target account and a free-text
`Source Workstation` name embedded in the `Message` field — no indexed,
queryable source IP the way Kerberos events (4768/4769/4771) provide via
`Client_Address`.

**Fix:** Either extract the workstation name via `rex` against the
`Message` field for partial attribution, or shift detection logic to use
Kerberos events where possible for cleaner source-based correlation.

## 4. `stats ... by field span=1m` syntax rejected

**Symptom:** `Error in 'stats' command: The argument 'span=1m' is invalid.`

**Root cause:** Some Splunk versions don't support inline `span=` inside a
`stats ... by` clause.

**Fix:** Bucket the time field explicitly first, then aggregate:
```spl
| bin _time span=1m
| stats dc(field) by _time
```
