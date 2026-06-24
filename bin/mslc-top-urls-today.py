#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-top-urls-today.py
Purpose : Show the top URLs blocked by ModSecurity today.
Author  : Bill Minozzi
Version : 0.1 beta
Created : 2026-05-09
Updated : 2026-05-09
"""

import re
import glob
import os
import shutil
from collections import Counter
from datetime import datetime
import locale



DATE_PATTERN = re.compile(
    r'^(?:--[a-f0-9]+-A--\s*|\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? \+\d{4})\])'
)



DATE_COMPARE_PATTERN = re.compile(
    r'\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})'
)




REQUEST_PATTERN = re.compile(
    r'^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?',
    re.MULTILINE
)


def analyze_today_urls():
    try:
        locale.setlocale(locale.LC_TIME, 'C')
    except locale.Error:
        pass

    LOG_DIR = "/usr/local/apache/logs"
    LOG_PATTERN = os.path.join(LOG_DIR, "modsec_audit.log*")

    today = datetime.now()
    target_date_str = today.strftime('%d/%b/%Y')

    todos_files = glob.glob(LOG_PATTERN)
    files = [f for f in todos_files if not f.endswith('.gz')]

    if not files:
        print(f"No file found in {LOG_PATTERN}")
        return

    files = sorted(files, key=os.path.getmtime, reverse=True)

    url_counts = Counter()

    for logfile in files:
        try:
            current_transaction = []

            with open(logfile, 'r', encoding='latin-1', errors='ignore') as f:
                for line in f:
                    if DATE_PATTERN.match(line):
                        if current_transaction:
                            process_transaction(current_transaction, target_date_str, url_counts)

                        current_transaction = [line]
                    else:
                        if current_transaction:
                            current_transaction.append(line)

                if current_transaction:
                    process_transaction(current_transaction, target_date_str, url_counts)

        except Exception:
            continue

    if not url_counts:
        print(f"\nNo ModSecurity URL found for {target_date_str}.")
        return

    terminal_width = shutil.get_terminal_size((80, 20)).columns
    line_width = min(terminal_width - 1, 120)

    print(f"\n--- URLs blocked by ModSecurity on {target_date_str} ---")
    print()
    print(f"{'Count':<10} | URL")
    print("-" * line_width)

    for url, count in url_counts.most_common(20):
        print(f"{count:<10} | {url}")

    print("-" * line_width)
    print(f"{sum(url_counts.values()):<10} | TOTAL")


def process_transaction(transaction, target_date_str, url_counts):
    text = "".join(transaction)

    date_match = DATE_COMPARE_PATTERN.search(text)
    if not date_match:
        return

    if date_match.group(1) != target_date_str:
        return

    request_match = REQUEST_PATTERN.search(text)
    if not request_match:
        return

    url = request_match.group(2)
    url_counts[url] += 1


if __name__ == "__main__":
    analyze_today_urls()
