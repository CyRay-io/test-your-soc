# An intruder finishes the job by erasing their tracks.

One real command wipes the record of everything they typed. You can run that exact command on your own machine right now — then look at your alerts and learn something true about your coverage.

- Test page: https://cyray.io/test-your-soc/erase-the-trail
- MITRE ATT&CK: [T1070.003 Indicator Removal: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- Seen in: Medusa ransomware
- Where to run it: any Windows box
- Time: About 60 seconds

## What it simulates

When someone works through your network by hand, PowerShell keeps a running record of every command on disk. It is the single most useful file a responder opens the morning after. Which is exactly why a careful intruder deletes it before they leave — and if your tooling doesn’t notice the deletion, the whole account of what they did goes with it.

The detection watches one thing: something **deleting or truncating your PowerShell history file**. Catch that, and even an attacker who cleaned up leaves you the fact that they cleaned up.

## The harmless command

This does exactly what Medusa does — it deletes your PowerShell history file — so it produces the exact event a real detection is meant to catch. Windows simply creates the file again next time; nothing is harmed. Run it, wait a moment, then open your alerts.

```powershell
# TEST YOUR SOC — run on a machine you own. Safe: Windows recreates the file.
# STEP 1 — leave something in the history worth erasing.
whoami; Get-Process | Select-Object -First 1 | Out-Null

# STEP 2 — Medusa's move, with the path written out: delete the PowerShell history file on disk.
Remove-Item -Force $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# STEP 3 — open your SOC / EDR. Did anything alert on the deletion?
# Nothing to clean up. A new history file is created automatically.
```

The same commands are in `test-your-soc.ps1` in this folder.

Steps:

1. **Leave a mark.** Run two obvious commands so there is something in the history worth hiding — the way a real session would have.
2. **Erase it.** Run the same move Medusa makes, with the history file’s path written out instead of looked up. It deletes the same file on disk. This is the moment your SOC should speak up.
3. **Check your alerts.** Open your SOC or EDR. Did anything alert on the deletion — or did the trail just quietly disappear?

## The event it should produce

The detection below reads this log source: category: file_delete, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

It only deletes your own PowerShell history file — the same file Windows rewrites every session. No admin rights, no payload, nothing to undo.

## The detection

The detection is simple and every major SIEM already supports it: **alert whenever the PowerShell history file is deleted or emptied.** Here is the logic, in Sigma — the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `powershell_history_deleted.yml` in this folder (Sigma format).

Rule: written by CyRay for this test. Licence: Detection Rule License 1.1, same as the other rules in this repository.
