# Can your SOC see one value quietly written?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/change-a-registry-value
- MITRE ATT&CK: [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112/)
- Seen in: APT41
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

The registry is where Windows keeps the settings that decide what starts, what is trusted and what gets logged. An intruder who can write one value can change any of those, and the quietest way to do it is not to type the key at all — it is to drop a small `.reg` file somewhere writable and import it in one line.

The detection watches for exactly that shape: `reg.exe import` reading from a temp or user folder. An administrator importing a settings file usually does it from a managed location; a `.reg` file that arrived in a temp directory minutes ago is a different story.

The detection watches one thing: **reg.exe importing a registry file from a temporary or user-writable folder**.

## The harmless command

Write one harmless value the way an intruder writes it, then delete it — the script cleans up after itself.

```powershell
# test-your-soc-modify-registry.ps1 — run on a machine you own.
# Safe: writes ONE marker value under your own user hive, then deletes exactly that key. No admin.
# STEP 1 - build a one-value registry file in your own temp folder, written out in full so the command line shows the path.
Set-Content -Path "$env:USERPROFILE\AppData\Local\Temp\CyRaySOCTest.reg" -Value @('Windows Registry Editor Version 5.00','','[HKEY_CURRENT_USER\Software\CyRaySOCTest]','"Marker"="test-your-soc"')
# STEP 2 - the actual technique: import it, which writes the value.
reg import "$env:USERPROFILE\AppData\Local\Temp\CyRaySOCTest.reg"
# STEP 3 - open your SOC / EDR. Did a registry modification alert?
# STEP 4 - clean up: remove exactly the key and the file this script created.
reg delete "HKCU\Software\CyRaySOCTest" /f
Remove-Item "$env:USERPROFILE\AppData\Local\Temp\CyRaySOCTest.reg" -Force
```

The same commands are in `test-your-soc-modify-registry.ps1` in this folder.

Steps:

1. **Build a one-value registry file.** The script writes a small `.reg` file into your own temp folder. It sets a single marker value under your own user hive and touches nothing else.
2. **Import it with the built-in tool.** Run `reg import` on that file — the actual technique, a registry value written from a file in a temp folder. This is the moment your SOC should notice.
3. **Check your alerts, then let it clean up.** Open your SOC or EDR and see whether a registry modification was flagged. The last two lines delete exactly the key and the file the script created.

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

The script creates one key with one value under your own user hive — a key that did not exist before — and one small file in your own temp folder. The last two lines delete exactly those two things. No machine-wide setting is touched, nothing existing is overwritten, and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_reg_import_from_suspicious_paths.yml` in this folder (Sigma format).

Rule: "Potential Suspicious Registry File Imported Via Reg.EXE" (Sigma rule id 62e0298b-e994-4189-bc87-bc699aa62d97). Author: frack113, Nasreddine Bencherchali. Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_import_from_suspicious_paths.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
