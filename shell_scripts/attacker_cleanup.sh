#!/bin/bash
# attacker_cleanup.sh: Clean up worm files on the attacker machine.
cd ~ || exit 1
rm -f infected.log netvermin_*.py
echo "Attacker cleanup complete."
