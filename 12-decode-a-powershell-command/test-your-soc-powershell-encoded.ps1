# test-your-soc-powershell-encoded.ps1 — run on a machine you own.
# Safe: decodes one short, harmless string and prints it. Nothing is written, downloaded or changed.
# STEP 1 - the actual technique: a PowerShell command line that decodes its own contents.
powershell -NoProfile -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U09D'))"
# STEP 2 - open your SOC / EDR. Did an encoded PowerShell command alert?
