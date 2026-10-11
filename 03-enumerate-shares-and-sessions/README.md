# Can your SOC see someone counting the doors?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/enumerate-shares-and-sessions
- MITRE ATT&CK: [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- Seen in: Conti
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

Once an intruder has a foothold, the next question is: what else can I reach? `net view` answers it — a built-in command that lists the file shares, printer shares and active sessions visible from this machine. It is how a hands-on attacker builds the map they use to spread.

The detection watches for `net view` doing broad enumeration — not the single, targeted lookup an admin runs, but the sweep an intruder runs to find where to go next.

The detection watches one thing: **the built-in net command being used to enumerate shares and sessions across the network**.

## The harmless command

Run the same share-and-session sweep an intruder runs, then open your alerts.

```powershell
# test-your-soc-remote-discovery.ps1 — run on a machine you own.
# Safe: read-only enumeration. Nothing is changed, nothing to undo.
# STEP 1 - list the shares and sessions visible from this machine.
net view
# STEP 2 - the broader sweep an intruder runs to see everything reachable.
net view /all
# STEP 3 - open your SOC / EDR. Did share/session enumeration alert?
```

The same commands are in `test-your-soc-remote-discovery.ps1` in this folder.

Steps:

1. **Enumerate the neighbourhood.** Run `net view` — the built-in that lists shares and sessions visible from this box.
2. **Widen the sweep.** Run `net view /all` — the broader enumeration an attacker uses to see everything reachable. This is the moment your SOC should speak up.
3. **Check your alerts.** Open your SOC or EDR. Did share-and-session enumeration alert — or did the network get mapped in silence?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

Both lines only list what is already visible on the network — nothing is created, mounted, changed or deleted. There is nothing to undo and no admin rights are needed. If the command returns an error (a modern box often answers `net view` with error 6118), the test is still valid — the detection watches the command running, not what it prints.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_net_view_share_and_sessions_enum.yml` in this folder (Sigma format).

Rule: "Share And Session Enumeration Using Net.EXE" (Sigma rule id 62510e69-616b-4078-b371-847da438cc03). Author: Endgame, JHasenbusch (ported for oscd.community). Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_net_view_share_and_sessions_enum.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
