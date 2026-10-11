# Can your SOC see a payload wrapped up to look like nothing?

One real attacker move, a safe way to run it on a machine you own, and the detection that closes the gap — in that order, so you leave with better coverage than you arrived with.

- Test page: https://cyray.io/test-your-soc/encode-the-payload
- MITRE ATT&CK: [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- Seen in: Kimsuky
- Where to run it: any Windows box
- Time: About a minute

## What it simulates

A content scanner reads bytes. Encode those bytes to base64 and the scanner reads nothing — not a signature, not a keyword, not a file type. That is the whole trick, and Windows performs it for free: `certutil -encode` was built to handle certificates, and it will happily encode anything you hand it.

The detection does not try to decide whether the encoded thing is malicious — it cannot, and neither can your scanner, which is the point. It watches for the *tool being used this way*, because a certificate utility encoding a file is a question worth asking.

The detection watches one thing: **certutil being used to encode a file to base64**.

## The harmless command

Encode a harmless file the way an intruder encodes a payload, then delete both — the script cleans up after itself.

```powershell
# test-your-soc-obfuscation.ps1 — run on a machine you own.
# Safe: makes one small text file in your own temp folder, encodes it, then deletes both. No admin.
# STEP 1 - write a harmless marker file.
Set-Content -Path "$env:TEMP\CyRaySOCTest.txt" -Value 'harmless marker for a SOC test'
# STEP 2 - the actual technique: encode it so a content scanner reads nothing.
certutil -encode "$env:TEMP\CyRaySOCTest.txt" "$env:TEMP\CyRaySOCTest.b64"
# STEP 3 - open your SOC / EDR. Did encoding by certutil alert?
# STEP 4 - clean up: delete exactly the two files this script created.
Remove-Item "$env:TEMP\CyRaySOCTest.txt","$env:TEMP\CyRaySOCTest.b64" -Force
```

The same commands are in `test-your-soc-obfuscation.ps1` in this folder.

Steps:

1. **Write a harmless marker file.** The script creates one small text file in your own temp folder. Its contents are a plain sentence and nothing else.
2. **Encode it with the built-in utility.** Run `certutil -encode` on that file — the actual technique, a file turned into base64 so a content scanner reads nothing. This is the moment your SOC should notice.
3. **Check your alerts, then let it clean up.** Open your SOC or EDR and see whether encoding by certutil was flagged. The last line deletes exactly the two files the script created.

## The event it should produce

The detection below reads this log source: category: process_creation, product: windows. Your SIEM needs to receive that log source for the test to be visible.

## Safety and revert

The script creates two files in your own temp folder — a plain sentence and its base64 form — and the last line deletes exactly those two. Nothing is downloaded, nothing is executed, nothing existing is touched, and no admin rights are needed.

## The detection

The logic is public and every major SIEM already supports it. Here it is in Sigma, the open, vendor-neutral format your team can translate into whatever you run.

The rule is in `proc_creation_win_certutil_encode.yml` in this folder (Sigma format).

Rule: "File Encoded To Base64 Via Certutil.EXE" (Sigma rule id e62a9f0c-ca1e-46b2-85d5-a6da77f86d1a). Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems). Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_encode.yml. Licence: Detection Rule License 1.1 (DRL 1.1), https://github.com/SigmaHQ/Detection-Rule-License.
