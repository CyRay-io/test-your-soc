# Can your SOC see who is asking who lives here?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/enumerate-local-accounts
- MITRE ATT&CK: [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087/)
- Seen in: Scattered Spider
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

The first thing a hands-on intruder does after landing is ask the machine who lives here. Not with malware — with the same commands your own admins use. `net user` lists the local accounts, `whoami /all` reads back exactly what the current token can do. It is quiet, it is built in, and it is how an attacker decides which account to steal next.

The detection does not try to ban these tools — your admins need them. It watches for the *pattern*: the account-enumeration utilities running, so that when they run at 3am from a process that has no business enumerating anything, someone gets to look.

The detection watches one thing: **a built-in tool listing the local accounts and the current user's privileges**.

## The harmless command

Run the same enumeration an intruder runs, then open your own alerts.

```powershell
# test-your-soc-account-discovery.ps1 — run on a machine you own.
# Safe: these are read-only lookups. Nothing is changed, nothing to undo.
# STEP 1 - list the local accounts, the way an intruder maps who lives here.
net user
# STEP 2 - read back exactly what the current account is allowed to do.
whoami /all
# STEP 3 - open your SOC / EDR. Did account enumeration alert?
```

The same commands are in `test-your-soc-account-discovery.ps1` in this folder.

Steps:

1. **List the local accounts.** Run `net user` — the built-in that dumps every local account on the box.
2. **Read your own privileges.** Run `whoami /all` — exactly what an attacker reads to learn what this token can do. This is the moment your SOC should notice.
3. **Check your alerts.** Open your SOC or EDR. Did account enumeration alert — or did the reconnaissance pass unseen?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

Every line is a read-only lookup — it lists accounts and prints your own privileges. Nothing is created, changed or deleted, so there is nothing to undo and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_susp_local_system_owner_account_discovery.yml` in this folder (Sigma format).

Rule: "Local Accounts Discovery" (Sigma rule id 502b42de-4306-40b4-9596-6f590c81f073). Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
