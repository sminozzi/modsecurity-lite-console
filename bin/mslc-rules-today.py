#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-rules-today.py
Purpose : Analyze today's ModSecurity audit log and report triggered rule IDs.
Author  : Bill Minozzi
Version : 0.1 beta
Created : 2026-05-09
Updated : 2026-05-09
"""

import re
from collections import Counter
from datetime import datetime
import locale

RULE_DESCRIPTIONS = {
  "248270": "Shellshock Attack",
  "244600": "Code Injection Attempt",
  "244050": "PHP Code Injection",
  "243930": "File Inclusion Attack",
  "243420": "Malicious File Upload Attempt",
  "243320": "Malicious File Extension Bypass",
  "240650": "Code Injection in Uploads",
  "240335": "Remote File Inclusion Attempt",
  "240022": "Local File Inclusion",
  "240020": "Remote File Inclusion",
  "240000": "Remote Code Execution Attempt",
  "225170": "Get Usernames",
  "211650": "Mysql attack",
  "211080": "Header line break attempt / header splitting",
  "210831": "Block bad UA by user agent table...",
  "210730": "Looking for .exe, .sql, .ini, .sh and related probes",
  "210492": "/env probe",
  "2000004": "Block Login (wrong ip)",
  "2000003": "Block Shortcodes Ultimate Vendor Folder",
  "2000002": "Allow Specific Font for Shortcodes Ultimate",
  "2000001": "Block wp-admin/install.php Access",
  "1000028": "Excessive 404s Counter",
  "1000027": "Web Shells - File",
  "1000026": "Restricted Files - File",
  "1000025": "Prototype Pollution Attack",
  "1000024": "XXE Attack",
  "1000023": "PHAR Deserialization Attack",
  "1000022": "PHP Object Injection - Cookies",
  "1000021": "PHP Object Injection - Body/Args",
  "1000020": "Shell Commands in Arguments",
  "1000019": "Directory Traversal - Arguments",
  "1000018": "Directory Traversal - Headers",
  "1000017": "Sensitive File Access",
  "1000016": "wp-config Access",
  "1000015": "Missing Accept Header",
  "1000014": "Host Header is IP Address",
  "1000013": "XSS in Forwarding Headers",
  "1000012": "Bad Bot User-Agent - File",
  "1000011": "Vulnerability Scanner User-Agent",
  "1000010": "Command-Line User-Agent",
  "1000009": "Malicious User-Agent Substring",
  "1000008": "Exact Malicious User-Agent",
  "1000007": "Excessive HEADs Blocker",
  "1000006": "Excessive HEADs Counter Increment",
  "1000005": "Excessive HEADs Counter Init",
  "1000004": "Excessive 404s Blocker",
  "1000003": "Enforce Allowed HTTP Methods",
  "1000002": "HTTP Method Exception - WP API",
  "1000001": "Block xmlrpc.php Access",
  "100002": "Generic Security Violation",
  "100001": "Generic Attack Pattern",
  "1001": "Generic Security Block",
  "900004": "Whitelist for sensitive file check rule 210580",
  "9990": "SQL Injection Attempt"
}

ID_PATTERN = re.compile(r'\[id "(\d+)"\]')
DATE_PATTERN = re.compile(
    r'^\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]'
)


def analyze_audit_log():
    try:
        locale.setlocale(locale.LC_TIME, 'C')
    except locale.Error:
        print("Warning: could not set locale to 'C'.")

    LOG_FILE_PATH = "/usr/local/apache/logs/modsec_audit.log"

    today_str = datetime.now().strftime('%d/%b/%Y')

    date_compare_pattern = re.compile(
        r'\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})'
    )

    print(f"--- Starting analysis of '{LOG_FILE_PATH}' for today's date: '{today_str}' ---")

    id_counts = Counter()
    current_transaction = []

    try:
        with open(LOG_FILE_PATH, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                if DATE_PATTERN.match(line):
                    if current_transaction:
                        transaction_text = "".join(current_transaction)
                        date_match = date_compare_pattern.search(transaction_text)

                        if date_match and date_match.group(1) == today_str:
                            matches = ID_PATTERN.finditer(transaction_text)
                            for match in matches:
                                rule_id = match.group(1)
                                id_counts[rule_id] += 1

                    current_transaction = [line]
                else:
                    if current_transaction:
                        current_transaction.append(line)

            if current_transaction:
                transaction_text = "".join(current_transaction)
                date_match = date_compare_pattern.search(transaction_text)

                if date_match and date_match.group(1) == today_str:
                    matches = ID_PATTERN.finditer(transaction_text)
                    for match in matches:
                        rule_id = match.group(1)
                        id_counts[rule_id] += 1

    except FileNotFoundError:
        print(f"WARNING: The log file '{LOG_FILE_PATH}' was not found.")
        return
    except Exception as e:
        print(f"ERROR: An error occurred while reading {LOG_FILE_PATH}. Detail: {e}")
        return

    if not id_counts:
        print("\n--- Analysis complete: No ModSecurity entries were found for today. ---")
        return

    print("\n--- ModSecurity Rules Triggered Today ---")
    print()
    print(f"{'Count':<10} | {'Rule ID':<10} | {'Rule Name'}")
    print("-" * 72)

    sorted_ids = sorted(id_counts.items(), key=lambda item: item[1], reverse=True)

    for rule_id, count in sorted_ids:
        rule_name = RULE_DESCRIPTIONS.get(rule_id, "Unknown rule name")
        print(f"{count:<10} | {rule_id:<10} | {rule_name}")

    grand_total = sum(id_counts.values())

    print("-" * 72)
    print(f"{grand_total:<10} | {'TOTAL':<10} |")


if __name__ == "__main__":
    analyze_audit_log()
