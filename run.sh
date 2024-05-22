#!/bin/bash
SCRIPTDIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
cd $SCRIPTDIR
source venv/bin/activate
python3 nmap_monitor.py 2>&1 | tee -a scanner.log
