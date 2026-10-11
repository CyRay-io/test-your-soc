# test-your-soc-network-config.ps1 — run on a machine you own.
# Safe: three read-only lookups of this machine's own network settings. Nothing to undo.
# STEP 1 - the full network configuration, the way an intruder reads it.
ipconfig /all
# STEP 2 - the neighbours this machine has recently spoken to.
arp -a
# STEP 3 - the routing table, which shows what else is reachable from here.
route print
# STEP 4 - open your SOC / EDR. Did network configuration discovery alert?
