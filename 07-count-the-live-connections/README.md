# Can your SOC see someone asking where this box is already connected?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/count-the-live-connections
- MITRE ATT&CK: [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)
- Seen in: Volt Typhoon
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

A machine's live connections are a shortcut. Every one of them is a place this account has already been trusted, which means the intruder does not have to guess where to go next — the box will tell them. `net use` prints them.

The detection watches for that specific use of `net`: not the form that mounts something new, the form that reads back what is already there. Your admins run it too, which is why the rule is about the behaviour and the context around it rather than the tool.

The detection watches one thing: **the built-in net command being used to list the connections this machine already holds**.

## The harmless command

Run the same connection listing an intruder runs, then open your alerts.

```powershell
# test-your-soc-network-connections.ps1 — run on a machine you own.
# Safe: read-only. Lists connections that already exist; creates none. Nothing to undo.
# STEP 1 - list the connections this machine already holds.
net use
# STEP 2 - open your SOC / EDR. Did network connection discovery alert?
```

The same commands are in `test-your-soc-network-connections.ps1` in this folder.

Steps:

1. **List what this machine already reaches.** Run `net use` with no arguments — the built-in that prints the connections this account currently holds. This is the moment your SOC should notice.
2. **Read it as an attacker would.** Every entry is somewhere this account is already accepted. That list is the shortlist for the next hop.
3. **Check your alerts.** Open your SOC or EDR. Did network connection discovery alert — or did the shortlist get read in silence?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

`net use` with no arguments only prints the connections that already exist — it creates, mounts and removes nothing. There is nothing to undo and no admin rights are needed. If the list comes back empty, the test is still valid: the detection watches the command running, not what it prints.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_net_use_network_connections_discovery.yml` in this folder (Sigma format).

Rule: "System Network Connections Discovery Via Net.EXE" (Sigma rule id 1c67a717-32ba-409b-a45d-0fb704a73a81). Author: frack113. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_net_use_network_connections_discovery.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
