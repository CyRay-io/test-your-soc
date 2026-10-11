# Can your SOC see a task quietly schedule itself?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/scheduled-task-creation
- MITRE ATT&CK: [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- Seen in: APT29
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

A scheduled task is how an intruder makes their access survive a reboot. `schtasks /create` registers a task that Windows will run for them later — on a timer, at logon, on their schedule instead of yours. It is one of the oldest and most reliable persistence moves, and it is a single built-in command.

The detection watches for that command running: `schtasks.exe` creating a task from a user account. Your admins create tasks too, so the rule leaves the automated system tasks alone and flags the ones a person just typed.

The detection watches one thing: **the built-in schtasks tool creating a new scheduled task**.

## The harmless command

Create a harmless task, watch for the alert, then delete it — the script cleans up after itself.

```powershell
# test-your-soc-scheduled-task.ps1 — run on a machine you own.
# Safe: creates one harmless task that only exits, then deletes it. Runs as you, no admin.
# STEP 1 - the real persistence move: register a scheduled task via schtasks.
schtasks /create /tn "CyRaySOCTest" /tr "cmd /c exit" /sc once /st 23:59 /f
# STEP 2 - open your SOC / EDR. Did scheduled-task creation alert?
# STEP 3 - clean up: delete exactly the task this script created.
schtasks /delete /tn "CyRaySOCTest" /f
```

The same commands are in `test-your-soc-scheduled-task.ps1` in this folder.

Steps:

1. **Schedule a harmless task.** Run `schtasks /create` for a task named CyRaySOCTest that does nothing but exit. This is the moment your SOC should notice a new task.
2. **Check your alerts.** Open your SOC or EDR. Did scheduled-task creation alert?
3. **Remove it.** The last line deletes the task it created, so nothing is left behind.

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

The task does nothing but exit, runs as your own account (no admin), and the final line deletes exactly the task the script created. Nothing else on the machine is touched.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_schtasks_creation.yml` in this folder (Sigma format).

Rule: "Scheduled Task Creation Via Schtasks.EXE" (Sigma rule id 92626ddd-662c-49e3-ac59-f6535f12d189). Author: Florian Roth (Nextron Systems). Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
