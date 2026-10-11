# test-your-soc-security-software-discovery.ps1 — run on a machine you own.
# Safe: read-only. Lists processes and filters the text. Nothing is changed, nothing to undo.
# STEP 1 - look for the security agent by name, the way an intruder checks what is watching.
cmd /c "tasklist | findstr /i defender"
# STEP 2 - open your SOC / EDR. Did security software discovery alert?
