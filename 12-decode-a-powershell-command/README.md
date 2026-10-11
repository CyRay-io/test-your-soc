# Can your SOC see a command that arrives unreadable?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/decode-a-powershell-command
- MITRE ATT&CK: [T1059.001 Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- Seen in: Turla
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

PowerShell will happily take its instructions as base64 and decode them itself. That is a legitimate feature — it survives quoting and line breaks — and it is also the single most common way an attacker's command reaches a machine in a form that nothing in between can read. The command line is logged, but what it says is unreadable at the moment it matters.

The detection takes the honest route: it does not try to decode anything, it watches for the decode itself. A command line that contains the decoding call is a command line that is hiding its own contents, whatever those contents turn out to be.

The detection watches one thing: **a PowerShell command line that decodes a base64 string before running it**.

## The harmless command

Run the same construction an intruder runs, with a harmless string inside it, then open your alerts.

```powershell
# test-your-soc-powershell-encoded.ps1 — run on a machine you own.
# Safe: decodes one short, harmless string and prints it. Nothing is written, downloaded or changed.
# STEP 1 - the actual technique: a PowerShell command line that decodes its own contents.
powershell -NoProfile -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U09D'))"
# STEP 2 - open your SOC / EDR. Did an encoded PowerShell command alert?
```

The same commands are in `test-your-soc-powershell-encoded.ps1` in this folder.

Steps:

1. **Run a command that decodes itself.** The script launches PowerShell with a command line that decodes a short base64 string and prints it. This is the moment your SOC should notice a self-decoding command.
2. **Look at what was logged.** The output is one harmless word. What matters is the command line your logging captured — unreadable until something decodes it, which is exactly the attacker's advantage.
3. **Check your alerts.** Open your SOC or EDR. Did the encoded PowerShell command alert — or did an unreadable instruction run without comment?

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

The encoded string decodes to three plain letters, which are printed and nothing more. Nothing is downloaded, written to disk, installed or changed, so there is nothing to undo and no admin rights are needed. `-NoProfile` means your own PowerShell profile is not loaded either.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_powershell_frombase64string.yml` in this folder (Sigma format).

Rule: "Base64 Encoded PowerShell Command Detected" (Sigma rule id e32d4572-9826-4738-b651-95fa63747e8a). Author: Florian Roth (Nextron Systems). Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
