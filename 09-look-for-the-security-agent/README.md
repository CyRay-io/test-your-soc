# Can your SOC see someone checking what is watching them?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/look-for-the-security-agent
- MITRE ATT&CK: [T1518.001 Software Discovery: Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/)
- Seen in: MuddyWater
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

Before an intruder does anything noisy, they check who is watching. The cheapest way is to list the running processes and filter that list for the names of security products. If the filter comes back empty, the next steps get bolder; if it finds an agent, the plan changes.

The detection is the neat part: it does not care about the process list, it cares about the *keyword*. Filtering anything for the name of a security vendor is a question almost nobody legitimate asks at a command line, which makes it a rare and high-quality signal.

The detection watches one thing: **a process list being filtered for the name of a security product**.

## The harmless command

Ask the same question an intruder asks about your agent, then open your alerts.

```powershell
# test-your-soc-security-software-discovery.ps1 — run on a machine you own.
# Safe: read-only. Lists processes and filters the text. Nothing is changed, nothing to undo.
# STEP 1 - look for the security agent by name, the way an intruder checks what is watching.
cmd /c "tasklist | findstr /i defender"
# STEP 2 - open your SOC / EDR. Did security software discovery alert?
```

The same commands are in `test-your-soc-security-software-discovery.ps1` in this folder.

Steps:

1. **Filter the process list for a security product.** Run `tasklist` piped into `findstr` looking for a security-product keyword. This is the moment your SOC should notice someone asking who is watching.
2. **Note what the answer would tell them.** A hit tells an attacker which agent to work around. Silence tells them the box is unguarded. Either way they now know more than you do about your own coverage.
3. **Check your alerts.** Open your SOC or EDR. Did security software discovery alert — or did someone case your defences unnoticed?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

The line lists the running processes and filters that text for a keyword. It touches no security product, changes no setting and disables nothing — it only looks. Nothing is created, changed or deleted, and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_findstr_security_keyword_lookup.yml` in this folder (Sigma format).

Rule: "Security Tools Keyword Lookup Via Findstr.EXE" (Sigma rule id 4fe074b4-b833-4081-8f24-7dcfeca72b42). Author: Nasreddine Bencherchali (Nextron Systems), frack113. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_findstr_security_keyword_lookup.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
