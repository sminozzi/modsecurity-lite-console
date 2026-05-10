#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-live-monitor.py
Purpose : Real-time ModSecurity audit log monitor with clean formatted output.
Author  : Bill Minozzi
Version : 0.1 beta
Created : 2026-05-09
Updated : 2026-05-09
"""

import os
import re
import time

LOG_FILE = "/usr/local/apache/logs/modsec_audit.log"

BOUNDARY_END_PATTERN = re.compile(r"^--[a-fA-F0-9]+-Z--")
ID_PATTERN = re.compile(r'\[id "([^"]+)"\]')
MSG_PATTERN = re.compile(r'\[msg "([^"]+)"\]')
DATA_PATTERN = re.compile(r'\[data "([^"]+)"\]')
SEVERITY_PATTERN = re.compile(r'\[severity "([^"]+)"\]')


def extract_value(pattern, text):
    match = pattern.search(text)
    return match.group(1) if match else ""


def process_transaction(lines):
    request_line = ""
    host = ""
    status_line = ""
    message = ""
    action = ""
    attacker_ip = ""
    timestamp = ""

    for line in lines:
        line = line.strip()

        time_match = re.match(r'^\[([^\]]+)\]', line)

        if time_match and not timestamp:
            timestamp = time_match.group(1)

        a_section_match = re.match(
            r'^\[[^\]]+\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+',
            line
        )

        if a_section_match and not attacker_ip:
            attacker_ip = a_section_match.group(1)

        if re.match(r"^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+", line):
            request_line = line

        elif line.startswith("Host:"):
            host = line.replace("Host:", "", 1).strip()

        elif line.startswith("HTTP/"):
            status_line = line

        elif line.startswith("Message:"):
            message = line

        elif line.startswith("Action:"):
            action = line.replace("Action:", "", 1).strip()

    if not message:
        return

    rule_id = extract_value(ID_PATTERN, message)
    msg = extract_value(MSG_PATTERN, message)
    data = extract_value(DATA_PATTERN, message)
    severity = extract_value(SEVERITY_PATTERN, message)

    if timestamp:
        timestamp = timestamp.replace(":", " ", 1)
        print(f"Time    : {timestamp}")

    if attacker_ip:
        print(f"IP      : {attacker_ip}")

    if request_line:
        print(f"Request : {request_line}")

    if host:
        print(f"Host    : {host}")

    if status_line:
        print(f"Status  : {status_line}")

    if rule_id:
        print(f"Rule ID : {rule_id}")

    if severity:
        print(f"Severity: {severity}")

    if msg:
        print(f"Message : {msg}")
    else:
        clean_message = message.replace("Message:", "", 1).strip()
        print(f"Message : {clean_message}")

    if data:
        print(f"Data    : {data}")

    if action:
        print(f"Action  : {action}")

    print("-" * 72, flush=True)


def follow_file(path):
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        transaction = []

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.2)
                continue

            transaction.append(line)

            if BOUNDARY_END_PATTERN.match(line):
                process_transaction(transaction)
                transaction = []


if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
    else:
        print("Watching ModSecurity audit log...")
        print("Press Ctrl+C to stop.")
        print()
        follow_file(LOG_FILE)