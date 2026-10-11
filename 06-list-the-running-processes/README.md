# Can your SOC see someone checking what is running?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/list-the-running-processes
- MITRE ATT&CK: [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057/)
- Seen in: Akira
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

An intruder who has just landed wants to know what else is on the box: which agent is running, which backup service, which database. `tasklist` prints the list, and piping it into `findstr` narrows it to the one name they care about. That pipe is the tell — a person reading a list does not need to filter it, a script hunting for one process does.

The detection watches for exactly that shape: a reconnaissance command whose output goes straight into a filter on the same command line.

The detection watches one thing: **a process listing being piped straight into a filter, so the attacker reads only the name they came for**.

## The harmless command

Run the same filtered process listing an intruder runs, then open your alerts.

```powershell
# test-your-soc-process-discovery.ps1 — run on a machine you own.
# Safe: read-only. Lists processes and filters the list. Nothing is changed, nothing to undo.
# STEP 1 - list what is running and filter it the way an intruder does.
cmd /c "tasklist | findstr /i explorer"
# STEP 2 - open your SOC / EDR. Did process discovery alert?
```

The same commands are in `test-your-soc-process-discovery.ps1` in this folder.

Steps:

1. **List and filter in one line.** Run `tasklist` piped into `findstr` looking for a process you know is there. This is the moment your SOC should notice a recon command being filtered.
2. **Look at what came back.** One line of output. That is the whole point — the attacker asked a narrow question and got a narrow answer, with nothing written to disk.
3. **Check your alerts.** Open your SOC or EDR. Did process discovery alert — or did the box get read in silence?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

Both halves of the line are read-only: one lists the running processes, the other filters that text. Nothing is created, changed or deleted, so there is nothing to undo and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_findstr_recon_pipe_output.yml` in this folder (Sigma format).

Rule: "Recon Command Output Piped To Findstr.EXE" (Sigma rule id ccb5742c-c248-4982-8c5c-5571b9275ad3). Author: Nasreddine Bencherchali (Nextron Systems), frack113. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_findstr_recon_pipe_output.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
