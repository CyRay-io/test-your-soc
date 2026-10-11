# Can your SOC see someone reading what you typed last week?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/read-the-typed-password
- MITRE ATT&CK: [T1552.001 Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- Seen in: Fox Kitten
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

PowerShell writes every command you type to a plain text file, forever, with no permissions on it beyond your own account. Most people have never opened it. An intruder opens it first, because people put passwords, connection strings and keys on command lines and the file keeps all of them exactly as typed.

This is not a credential attack in the usual sense — nothing is cracked, dumped or elevated. It is one file read. The detection watches for the file being located or opened from a command line, because that is a very specific thing to go looking for.

The detection watches one thing: **the PowerShell console history file being opened or located from a command line**.

## The harmless command

Read your own history file the way an intruder reads it, then open your alerts.

```powershell
# test-your-soc-credentials-in-files.ps1 — run on a machine you own.
# Safe: reads your own PowerShell history file. Read-only, nothing changed, nothing to undo.
# STEP 1 - ask PowerShell where its own console history is kept.
powershell -NoProfile -Command "(Get-PSReadLineOption).HistorySavePath"
# STEP 2 - the actual technique: read that file, the way an intruder harvests typed secrets.
powershell -NoProfile -Command "Get-Content (Get-PSReadLineOption).HistorySavePath -Tail 20"
# STEP 3 - open your SOC / EDR. Did console history access alert?
```

The same commands are in `test-your-soc-credentials-in-files.ps1` in this folder.

Steps:

1. **Find where your history is kept.** The first line asks PowerShell for the path of its own history file. This is already the lookup an intruder makes.
2. **Read the last lines of it.** The second line prints the end of that file — your own typed commands. Look at them honestly: is there anything in there you would not want an intruder to read?
3. **Check your alerts.** Open your SOC or EDR. Did console history access alert — or can that file be read without anyone knowing?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

Both lines are read-only and they read only your own account's history file. Nothing is deleted, modified, copied off the machine or sent anywhere, so there is nothing to undo and no admin rights are needed. If you would rather not see the contents at all, run only the first line — locating the file is enough to test the detection.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_powershell_console_history_file_access.yml` in this folder (Sigma format).

Rule: "Potential PowerShell Console History Access Attempt via History File" (Sigma rule id f4ff7323-b5fc-4323-8b52-6b9408e15788). Author: Luc Génaux. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_console_history_file_access.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
