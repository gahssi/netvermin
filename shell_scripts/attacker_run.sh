#!/bin/bash
# attacker_run.sh: Run the worm on the attacker machine.
cd ~/worm || { echo "worm directory not found"; exit 1; }
cp ../netvermin.py .
chmod +x netvermin.py
python3 netvermin.py
