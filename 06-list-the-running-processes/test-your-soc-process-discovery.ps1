# test-your-soc-process-discovery.ps1 — run on a machine you own.
# Safe: read-only. Lists processes and filters the list. Nothing is changed, nothing to undo.
# STEP 1 - list what is running and filter it the way an intruder does.
cmd /c "tasklist | findstr /i explorer"
# STEP 2 - open your SOC / EDR. Did process discovery alert?
