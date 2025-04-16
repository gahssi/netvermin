#!/bin/bash
# target_cleanup.sh: Clean up worm traces on target machines and restore original files.
rm -f ~/Documents.tar.enc ~/openme.txt ~/dmsg.log
rm -rf ~/Temp
mkdir -p ~/Documents
echo "Target cleanup complete."
