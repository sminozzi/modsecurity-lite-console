#!/bin/bash
#
# Project : ModSecurity Lite Console - StopBadBots
# Script  : uninstall.sh
# Purpose : Remove installed ModSecurity Lite Console scripts from /usr/local/bin.
# Author  : Bill Minozzi
# Version : 0.1 beta
# Created : 2026-05-09
# Updated : 2026-05-09

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run this uninstaller as root."
    exit 1
fi

rm -f /usr/local/bin/mslc
rm -f /usr/local/bin/mslc-console.sh
rm -f /usr/local/bin/mslc-live-monitor.py
rm -f /usr/local/bin/mslc-rules-today.py
rm -f /usr/local/bin/mslc-rules-yesterday.py
rm -f /usr/local/bin/mslc-rule-totals.py
rm -f /usr/local/bin/mslc-top-urls-today.py

echo "ModSecurity Lite Console - StopBadBots was removed."
echo "Configuration file /etc/mslc.conf was not removed."
