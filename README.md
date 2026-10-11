# Test Your SOC

Free, harmless tests that check whether your SOC sees common attacker steps.

Each folder is one test. It holds a short README with the command to run, the event it should produce and how to put your machine back, and, where one exists, the detection logic as a Sigma rule.

Home page with the full write-ups: https://cyray.io/test-your-soc

## How to use it

1. Pick a folder and open its README.
2. Run the command on a test machine you own.
3. Open your SIEM or EDR and look for the event the README names.
4. If nothing shows up in folders 14 to 18, the README says which source to check and which setting to switch on. Switch it on, run the test again.
5. Revert the setting with the commands at the end of the README.

The first 13 folders are tests of attacker commands, each with a Sigma rule. Folders 14 to 18 are tests where Windows does not write the event until one setting is on; they describe the rule condition in words.

## Safety

- Run every test on a test machine you own. Never on a machine you do not own or a production machine.
- Run as an administrator where the README says so.
- Revert after the test: put the audit policy back and delete anything the test created. Each README ends with the revert commands.
- The commands are harmless: they read system information or create a task or file that does nothing, and the README says how to remove it.

## Tests

| Folder | Technique | Detection |
| --- | --- | --- |
| [01-erase-the-trail](01-erase-the-trail) | T1070.003 Indicator Removal: Clear Command History | Sigma rule |
| [02-enumerate-local-accounts](02-enumerate-local-accounts) | T1087 Account Discovery | Sigma rule |
| [03-enumerate-shares-and-sessions](03-enumerate-shares-and-sessions) | T1018 Remote System Discovery | Sigma rule |
| [04-scheduled-task-creation](04-scheduled-task-creation) | T1053.005 Scheduled Task/Job: Scheduled Task | Sigma rule |
| [05-inventory-the-machine](05-inventory-the-machine) | T1082 System Information Discovery | Sigma rule |
| [06-list-the-running-processes](06-list-the-running-processes) | T1057 Process Discovery | Sigma rule |
| [07-count-the-live-connections](07-count-the-live-connections) | T1049 System Network Connections Discovery | Sigma rule |
| [08-read-the-network-layout](08-read-the-network-layout) | T1016 System Network Configuration Discovery | Sigma rule |
| [09-look-for-the-security-agent](09-look-for-the-security-agent) | T1518.001 Software Discovery: Security Software Discovery | Sigma rule |
| [10-change-a-registry-value](10-change-a-registry-value) | T1112 Modify Registry | Sigma rule |
| [11-encode-the-payload](11-encode-the-payload) | T1027 Obfuscated Files or Information | Sigma rule |
| [12-decode-a-powershell-command](12-decode-a-powershell-command) | T1059.001 Command and Scripting Interpreter: PowerShell | Sigma rule |
| [13-read-the-typed-password](13-read-the-typed-password) | T1552.001 Unsecured Credentials: Credentials In Files | Sigma rule |
| [14-blind-scheduled-task-creation](14-blind-scheduled-task-creation) | Scheduled task creation (event 4698) | Condition in words |
| [15-blind-audit-policy-enumeration](15-blind-audit-policy-enumeration) | Audit policy enumeration (auditpol /get) | Condition in words |
| [16-blind-vm-check-registry](16-blind-vm-check-registry) | Virtual machine check via the registry (reg query VBOX) | Condition in words |
| [17-blind-hard-link-creation](17-blind-hard-link-creation) | Hard link creation (fsutil hardlink) | Condition in words |
| [18-blind-powershell-script-block](18-blind-powershell-script-block) | PowerShell commands (Script Block Logging, event 4104) | Condition in words |

## Licences

- Scripts and command snippets: MIT (see LICENSE). MIT is short, permissive and well known, so anyone can copy a command into their own test plan.
- Detections (the Sigma YAML files): Detection Rule License 1.1 (see LICENSE-DETECTIONS.md). Twelve of the thirteen rules come from the SigmaHQ project and were released by their authors under DRL 1.1, which requires that licence to stay with them; the remaining rule was written by CyRay and uses the same licence so the repository has one detection licence. Each README names the rule's author and source.
- Page text and READMEs: MIT, together with the scripts.

## About

Test Your SOC is published by CyRay. Questions and fixes are welcome as issues.
