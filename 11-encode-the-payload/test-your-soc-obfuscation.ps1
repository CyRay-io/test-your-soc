# test-your-soc-obfuscation.ps1 — run on a machine you own.
# Safe: makes one small text file in your own temp folder, encodes it, then deletes both. No admin.
# STEP 1 - write a harmless marker file.
Set-Content -Path "$env:TEMP\CyRaySOCTest.txt" -Value 'harmless marker for a SOC test'
# STEP 2 - the actual technique: encode it so a content scanner reads nothing.
certutil -encode "$env:TEMP\CyRaySOCTest.txt" "$env:TEMP\CyRaySOCTest.b64"
# STEP 3 - open your SOC / EDR. Did encoding by certutil alert?
# STEP 4 - clean up: delete exactly the two files this script created.
Remove-Item "$env:TEMP\CyRaySOCTest.txt","$env:TEMP\CyRaySOCTest.b64" -Force
