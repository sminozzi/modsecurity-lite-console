#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-rule-totals.py
Purpose : Summarize ModSecurity triggered rules by date from audit logs.
Author  : Bill Minozzi
Version : 0.2 beta
Updated : 2026-06-23
"""

import re
import glob
import os
from collections import Counter

# --- Global regex patterns ---
ID_PATTERN = re.compile(r'\[id "(\d+)"\]')

# UNIVERSAL DATE PATTERN:
# - Optionally matches the new prefix: --[hash]-A--
# - Optionally matches milliseconds (\.\d+)
# - Works with both old-style (starting with '[') and new-style logs
DATE_PATTERN = re.compile(
    r'^(?:--[a-f0-9]+-A--\s*)?\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? \+\d{4})\]'
)

DATE_COMPARE_PATTERN = re.compile(
    r'(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})'
)

# Month mapping to avoid locale issues
MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def parse_date(date_str):
    """
    Parses a date string like '25/Aug/2025' into a tuple (year, month, day)
    for reliable chronological sorting.
    """
    day, mon, year = date_str.split('/')
    return int(year), MONTHS[mon], int(day)


def analyze_audit_logs():
    """
    Reads current and rotated ModSecurity logs and generates a blocks-by-date table.
    """
    LOG_DIR = "/usr/local/apache/logs"
    LOG_PATTERN = os.path.join(LOG_DIR, "modsec_audit.log*")

    # Get all log files and explicitly exclude compressed .gz files
    all_files = glob.glob(LOG_PATTERN)
    files = sorted([f for f in all_files if not f.endswith('.gz')])

    if not files:
        print(f"WARNING: No log files found matching {LOG_PATTERN} (excluding .gz)")
        return

    print(f"--- Starting analysis of {len(files)} file(s) ({LOG_PATTERN}) ---")

    blocks_by_day = Counter()

    for logfile in files:
        try:
            with open(logfile, 'r', encoding='latin-1', errors='ignore') as f:
                current_transaction = []

                for line in f:
                    # Check if this line is the start of a new transaction
                    if DATE_PATTERN.match(line):
                        # Process the previous transaction if it exists
                        if current_transaction:
                            transaction_text = "".join(current_transaction)
                            date_match = DATE_COMPARE_PATTERN.search(transaction_text)

                            if date_match:
                                date_value = date_match.group(1)
                                matches = ID_PATTERN.findall(transaction_text)

                                if matches:
                                    # Count total rule triggers (multiple IDs per transaction count as multiple blocks)
                                    blocks_by_day[date_value] += len(matches)

                        # Start a new transaction with this line
                        current_transaction = [line]

                    else:
                        # Accumulate lines for the current transaction
                        if current_transaction:
                            current_transaction.append(line)

                # Process the last transaction in the file
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

    # --- Output Results ---
    if not blocks_by_day:
        print("\n--- Analysis complete: No ModSecurity entries (rule IDs) were found in any log file. ---")
        return

    print("\n--- Blocks by Date ---")
    print(f"{'Date':<15} | {'Total Blocks':<20}")
    print("-" * 40)

    grand_total = 0

    # Sort chronologically using the custom parse_date function
    for date_value, total in sorted(blocks_by_day.items(), key=lambda x: parse_date(x[0])):
        print(f"{date_value:<15} | {total:<20}")
        grand_total += total

    print("-" * 40)
    print(f"{'TOTAL':<15} | {grand_total:<20}")


if __name__ == "__main__":
    analyze_audit_logs()