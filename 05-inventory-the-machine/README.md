# Can your SOC see the machine being sized up?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/inventory-the-machine
- MITRE ATT&CK: [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- Seen in: Black Basta
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

Before an intruder decides what to do with a machine, they ask it what it is. `systeminfo` answers in one screen: the Windows build, the domain, the patch level, the memory, the boot time. It is the same command a help-desk engineer runs, and it is the first thing a hands-on attacker runs after landing.

The detection does not try to ban the tool — plenty of legitimate work needs it. It watches for the *execution*, so that when a box is inventoried by something that has no reason to inventory it, a human gets to look at the timing and the parent process.

The detection watches one thing: **the built-in systeminfo tool being run to read the machine's full specification**.

## The harmless command

Run the same inventory an intruder runs, then open your own alerts.

```powershell
# test-your-soc-system-info.ps1 — run on a machine you own.
# Safe: one read-only lookup. Nothing is created, changed or deleted.
# STEP 1 - the inventory an intruder takes the minute they land.
systeminfo
# STEP 2 - open your SOC / EDR. Did system information discovery alert?
```

The same commands are in `test-your-soc-system-info.ps1` in this folder.

Steps:

1. **Take the inventory.** Run `systeminfo` — the built-in that prints the machine's full specification in one go. This is the moment your SOC should notice.
2. **Read what it told you.** Look at the output the way an attacker would: build number, domain membership, installed hotfixes. That is the map they just got for free.
3. **Check your alerts.** Open your SOC or EDR. Did system information discovery alert — or was the machine sized up in silence?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

One read-only command that prints the machine's own specification. Nothing is created, changed or deleted, so there is nothing to undo and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_systeminfo_execution.yml` in this folder (Sigma format).

Rule: "Suspicious Execution of Systeminfo" (Sigma rule id 0ef56343-059e-4cb6-adc1-4c3c967c5e46). Author: frack113. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_systeminfo_execution.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
