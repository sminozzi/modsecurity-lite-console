#!/bin/bash
#
# Project : ModSecurity Lite Console - StopBadBots
# Script  : install.sh
# Purpose : Install ModSecurity Lite Console scripts into /usr/local/bin.
# Author  : Bill Minozzi
# Version : 0.1 beta
# Created : 2026-05-09
# Updated : 2026-05-09

set -e

PROJECT_NAME="ModSecurity Lite Console - StopBadBots"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc"
CONF_FILE="$CONF_DIR/mslc.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Please run this installer as root."
    exit 1
fi

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $1"
        exit 1
    fi
}

check_command bash
check_command python3
check_command awk
check_command grep
check_command tail
check_command sort
check_command uniq
check_command head
check_command watch

mkdir -p "$BIN_DIR"
install -m 0755 "$SRC_DIR/bin/mslc-console.sh" "$BIN_DIR/mslc-console.sh"
install -m 0755 "$SRC_DIR/bin/mslc-live-monitor.py" "$BIN_DIR/mslc-live-monitor.py"
install -m 0755 "$SRC_DIR/bin/mslc-rules-today.py" "$BIN_DIR/mslc-rules-today.py"
install -m 0755 "$SRC_DIR/bin/mslc-rules-yesterday.py" "$BIN_DIR/mslc-rules-yesterday.py"
install -m 0755 "$SRC_DIR/bin/mslc-rule-totals.py" "$BIN_DIR/mslc-rule-totals.py"
install -m 0755 "$SRC_DIR/bin/mslc-top-urls-today.py" "$BIN_DIR/mslc-top-urls-today.py"

ln -sf "$BIN_DIR/mslc-console.sh" "$BIN_DIR/mslc"

if [ ! -f "$CONF_FILE" ]; then
    install -m 0644 "$SRC_DIR/conf/mslc.conf" "$CONF_FILE"
fi

echo
echo "$PROJECT_NAME installed successfully."
echo
echo "Run:"
echo "  mslc"
echo
