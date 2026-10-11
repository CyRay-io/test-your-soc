# Can your SOC see someone drawing the map?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/read-the-network-layout
- MITRE ATT&CK: [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- Seen in: Lazarus Group
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

Three commands tell an intruder where they are standing. `ipconfig /all` gives the addressing and the DNS servers, `arp -a` gives the neighbours this machine has recently spoken to, and `route print` gives what is reachable from here. Together they are the map, and they take about four seconds to draw.

The detection watches for those specific lookups running. None of them is rare on its own, which is why the useful signal is the cluster: several of them, from one process, inside a minute.

The detection watches one thing: **the classic network-configuration lookups running — the addressing, the neighbours and the routes**.

## The harmless command

Run the same three lookups an intruder runs, then open your alerts.

```powershell
# test-your-soc-network-config.ps1 — run on a machine you own.
# Safe: three read-only lookups of this machine's own network settings. Nothing to undo.
# STEP 1 - the full network configuration, the way an intruder reads it.
ipconfig /all
# STEP 2 - the neighbours this machine has recently spoken to.
arp -a
# STEP 3 - the routing table, which shows what else is reachable from here.
route print
# STEP 4 - open your SOC / EDR. Did network configuration discovery alert?
```

The same commands are in `test-your-soc-network-config.ps1` in this folder.

Steps:

1. **Read the addressing.** Run `ipconfig /all` — the full network configuration, including the DNS servers this machine trusts.
2. **Read the neighbours and the routes.** Run `arp -a` and then `route print`. This is the moment your SOC should see a cluster of discovery, not a single lookup.
3. **Check your alerts.** Open your SOC or EDR. Did network configuration discovery alert — or did the map get drawn in silence?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

All three lines only print settings this machine already holds. Nothing is created, changed or deleted, so there is nothing to undo and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_susp_network_command.yml` in this folder (Sigma format).

Rule: "Suspicious Network Command" (Sigma rule id a29c1813-ab1f-4dde-b489-330b952e91ae). Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_network_command.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
