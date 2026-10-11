# test-your-soc-account-discovery.ps1 — run on a machine you own.
# Safe: these are read-only lookups. Nothing is changed, nothing to undo.
# STEP 1 - list the local accounts, the way an intruder maps who lives here.
net user
# STEP 2 - read back exactly what the current account is allowed to do.
whoami /all
# STEP 3 - open your SOC / EDR. Did account enumeration alert?
