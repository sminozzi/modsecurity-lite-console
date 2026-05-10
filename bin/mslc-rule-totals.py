#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-rule-totals.py
Purpose : Summarize ModSecurity triggered rules by date from audit logs.
Author  : Bill Minozzi
Version : 0.1 beta
Created : 2026-05-09
Updated : 2026-05-09
"""

import re
import glob
import os
from collections import Counter

# --- Global regex patterns ---
ID_PATTERN = re.compile(r'\[id "(\d+)"\]')
DATE_PATTERN = re.compile(r'^\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]')
DATE_COMPARE_PATTERN = re.compile(r'(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})')

# Month mapping to avoid locale issues
MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def parse_date(date_str):
    # date_str example: "25/Aug/2025"
    day, mon, year = date_str.split('/')
    return int(year), MONTHS[mon], int(day)


def analyze_audit_logs():
    """
    Reads current and rotated ModSecurity logs and generates a blocks-by-date table.
    """
    LOG_DIR = "/usr/local/apache/logs"
    LOG_PATTERN = os.path.join(LOG_DIR, "modsec_audit.log*")

    files = sorted(glob.glob(LOG_PATTERN))

    if not files:
        print(f"WARNING: No file found in {LOG_PATTERN}")
        return

    print(f"--- Starting analysis of {len(files)} file(s) ({LOG_PATTERN}) ---")

    blocks_by_day = Counter()

    for logfile in files:
        try:
            with open(logfile, 'r', encoding='latin-1', errors='ignore') as f:
                current_transaction = []

                for line in f:
                    if DATE_PATTERN.match(line):
                        if current_transaction:
                            transaction_text = "".join(current_transaction)
                            date_match = DATE_COMPARE_PATTERN.search(transaction_text)

                            if date_match:
                                date_value = date_match.group(1)
                                matches = ID_PATTERN.findall(transaction_text)

                                if matches:
                                    blocks_by_day[date_value] += len(matches)

                        current_transaction = [line]

                    else:
                        if current_transaction:
                            current_transaction.append(line)

                # Process the last transaction.
                if current_transaction:
                    transaction_text = "".join(current_transaction)
                    date_match = DATE_COMPARE_PATTERN.search(transaction_text)

                    if date_match:
                        date_value = date_match.group(1)
                        matches = ID_PATTERN.findall(transaction_text)

                        if matches:
                            blocks_by_day[date_value] += len(matches)

        except Exception as e:
            print(f"ERROR while processing {logfile}: {e}")

    if not blocks_by_day:
        print("\n--- Analysis complete: No ModSecurity entries were found. ---")
        return

    print("\n--- Blocks by Date ---")
    print(f"{'Date':<15} | {'Total Blocks':<20}")
    print("-" * 40)

    grand_total = 0

    for date_value, total in sorted(blocks_by_day.items(), key=lambda x: parse_date(x[0])):
        print(f"{date_value:<15} | {total:<20}")
        grand_total += total

    print("-" * 40)
    print(f"{'TOTAL':<15} | {grand_total:<20}")


if __name__ == "__main__":
    analyze_audit_logs()