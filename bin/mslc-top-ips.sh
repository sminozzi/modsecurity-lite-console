#!/bin/bash

CONF_FILE="/etc/mslc.conf"

if [ -f "$CONF_FILE" ]; then
    source "$CONF_FILE"
else
    echo "ERROR: Config file not found: $CONF_FILE"
    exit 1
fi

TOP_LIMIT="${TOP_LIMIT:-10}"
ACCESS_LOG="${ACCESS_LOG:-/usr/local/apache/logs/access_log}"

if [ ! -f "$ACCESS_LOG" ]; then
    echo "ERROR: Access log not found: $ACCESS_LOG"
    exit 1
fi

echo "ModSecurity Lite Console - Top ${TOP_LIMIT} Blocked IPs"
echo "Updated: $(date)"
echo
echo "Press Ctrl+C to stop."
echo
printf "%-10s | %s\n" "Number" "IP"
echo "----------------------------------------"

if [ -n "${SERVER_IP:-}" ]; then
    tail -n 300 "$ACCESS_LOG" \
    | grep -v 'httpapi' \
    | grep -vF "$SERVER_IP" \
    | awk '{print $1}' \
    | sort \
    | uniq -c \
    | awk '$1 > 2' \
    | sort -nr \
    | head -"${TOP_LIMIT}"
else
    tail -n 300 "$ACCESS_LOG" \
    | grep -v 'httpapi' \
    | awk '{print $1}' \
    | sort \
    | uniq -c \
    | awk '$1 > 2' \
    | sort -nr \
    | head -"${TOP_LIMIT}"
fi
