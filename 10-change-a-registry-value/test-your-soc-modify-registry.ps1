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
