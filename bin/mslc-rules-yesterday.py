#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project : ModSecurity Lite Console - StopBadBots
Script  : mslc-rules-yesterday.py
Purpose : Analyze yesterday's ModSecurity audit logs and report triggered rule IDs.
Author  : Bill Minozzi
Version : 0.1 beta
Created : 2026-05-09
Updated : 2026-05-09
"""

import re
import glob
import os
from collections import Counter
from datetime import datetime, timedelta
import locale

# --- Rule ID to rule name mapping ---
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
  "234930": "XML External Entity Injection",
  "232981": "HTTP Response Injection",
  "232980": "HTTP Header Injection",
  "232920": "HTTP Response Splitting",
  "232850": "HTTP Request Smuggling",
  "232380": "HTTP Cache Poisoning",
  "231990": "HTTP Method Tampering",
  "231011": "HTTP Parameter Pollution",
  "228070": "XSS using HTML5 Features",
  "227280": "XSS in PostMessage",
  "226980": "XSS in DOM Events",
  "226960": "XSS in Eval Function",
  "226910": "XSS in Document Domain",
  "226830": "XSS in Window Name",
  "226070": "XSS in AJAX Response",
  "225220": "XSS in HTTP Headers",
  "225170": "Get Usernames",
  "225080": "XSS in XML Date",
  "222550": "XSS using CSS Import",
  "222390": "XSS using Date Protocol",
  "222350": "XSS using CSS Animation",
  "222212": "XSS in CSS Expression",
  "222160": "XSS using Behavior Property",
  "222060": "XSS using Style Injection",
  "222050": "XSS using Expression Property",
  "221540": "XSS in SetTimeout",
  "221260": "XSS in JSON Response",
  "218580": "Directory Traversal with Null Byte",
  "218530": "Path Traversal with Encoding",
  "218500": "Path Traversal Attack",
  "218420": "Directory Traversal Attack",
  "217291": "SSI (Server Side Includes) Injection",
  "217280": "XSS using Embed Tags",
  "217260": "XSS using Blink Tags",
  "217240": "XSS using VBScript",
  "217210": "XSS using Marquee Tags",
  "213060": "XSS in SVG Content",
  "213020": "XSS Filtro de Detecção de Ofuscação",
  "213010": "XSS in XML Content",
  "212970": "XSS in Input Image",
  "212960": "XSS in Object Date",
  "212920": "XSS in Textarea",
  "212890": "XSS with Malicious Attributes",
  "212880": "XSS in Anchor Tags",
  "212860": "XSS in Form Action",
  "212850": "XSS using Div Tags",
  "212830": "XSS using Button Tags",
  "212820": "XSS using Select Tags",
  "212800": "XSS in Link Attributes",
  "212790": "XSS using Meta Tags",
  "212750": "XSS in Style Attribute",
  "212620": "XSS in Script Context",
  "212380": "XSS with UTF-7 Encoding",
  "212340": "XSS with Double Encoding",
  "212320": "XSS with Unicode Encoding",
  "212290": "XSS with JavaScript Protocol",
  "212280": "XSS using Base64 Encoding",
  "212270": "XSS with Encoded Characters",
  "212200": "XSS using Document Write",
  "211820": "LDAP Injection Attempt",
  "211790": "XSS using Object Tags",
  "211760": "XSS using Frame Tags",
  "211750": "XSS using IFrame",
  "211710": "XSS using Script Tags",
  "211700": "XSS using Style Sheets",
  "211680": "XSS using Link Tags",
  "211650": "Mysql attack",
  "211540": "XSS using JavaScript Events",
  "211230": "XSS (Cross-Site Scripting) Attempt",
  "211210": "XSS using Applet Tags",
  "211200": "XSS using Layer Tags",
  "211190": "XSS Attack via HTML Tags",
  "211180": "XSS Filter Attack",
  "211120": "XSS Filter Evasion",
  "211080": "Header line break attempt / header splitting",
  "211040": "XSS using Body Tags",
  "211030": "XSS using Input Tags",
  "211020": "XSS using Image Tags",
  "211010": "XSS using Form Tags",
  "210831": "Bad user agent table...",
  "210801": "SQL Injection Time Delay",
  "210740": "SQL Injection Comment Detection",
  "210730": "Looking for .exe, .sql, .ini, .sh and related probes",
  "210710": "SQL Injection UNION Attack",
  "210580": "SQL Injection Tautology",
  "210492": "/env probe",
  "210410": "SQL Injection Hex Encoding",
  "210381": "SQL Injection Char Encoding",
  "210380": "SQL Injection Boolean",
  "210350": "SQL Injection Fingerprinting",
  "210280": "SQL Injection Function Detection",
  "210270": "SQL Injection Information Gathering",
  "210240": "SQL Injection Benchmark",
  "210231": "SQL Injection Stacked Queries",
  "210230": "SQL Injection Detection",
  "210220": "SQL Injection Error Based",
  "220150": "Command Injection Attempt",
  "220020": "OS Command Injection",
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

# --- Global regex patterns ---
ID_PATTERN = re.compile(r'\[id "(\d+)"\]')
DATE_PATTERN = re.compile(r'^\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]')
DATE_COMPARE_PATTERN = re.compile(r'\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})')


def analyze_audit_logs_yesterday():
    """
    Main function that analyzes multiple log files for yesterday.
    """
    try:
        locale.setlocale(locale.LC_TIME, 'C')
    except locale.Error:
        pass
    
    LOG_DIR = "/usr/local/apache/logs"
    LOG_PATTERN = os.path.join(LOG_DIR, "modsec_audit.log*")
    
    # Yesterday date
    yesterday = datetime.now() - timedelta(days=1)
    target_date_str = yesterday.strftime('%d/%b/%Y')

    # Pegar TODOS os files de log únicos, mas ignorar .gz
    todos_files = glob.glob(LOG_PATTERN)
    files = [f for f in todos_files if not f.endswith('.gz')]
    
    if not files:
        print(f"WARNING: No file found in {LOG_PATTERN} (excluding .gz)")
        return

    # Ordenar por data de modificação (mais recente primeiro)
    files = sorted(files, key=os.path.getmtime, reverse=True)

    id_counts = Counter()

    for logfile in files:
        try:
            current_transaction = []
            
            with open(logfile, 'r', encoding='latin-1', errors='ignore') as f:
                for line in f:
                    # O padrão de data/hora no início da line marca o começo de uma nova transação
                    if DATE_PATTERN.match(line):
                        # Se já temos uma transação guardada, processa-a
                        if current_transaction:
                            transaction_text = "".join(current_transaction)
                            date_match = DATE_COMPARE_PATTERN.search(transaction_text)
                            if date_match and date_match.group(1) == target_date_str:
                                # Encontra todos os IDs de regras dentro desta transação
                                matches = ID_PATTERN.finditer(transaction_text)
                                for match in matches:
                                    rule_id = match.group(1)
                                    id_counts[rule_id] += 1
                        
                        # Inicia uma nova transação
                        current_transaction = [line]
                    else:
                        # Continua a adicionar lines à transação atual
                        if current_transaction:
                            current_transaction.append(line)
                
                # Process the last transaction in the file
                if current_transaction:
                    transaction_text = "".join(current_transaction)
                    date_match = DATE_COMPARE_PATTERN.search(transaction_text)
                    if date_match and date_match.group(1) == target_date_str:
                        matches = ID_PATTERN.finditer(transaction_text)
                        for match in matches:
                            rule_id = match.group(1)
                            id_counts[rule_id] += 1
                        
        except Exception as e:
            continue

    # --- Result ---
    if not id_counts:
        print(f"\n--- Analysis complete: No ModSecurity entries were found for {target_date_str}. ---")
    else:
        print(f"\n--- ModSecurity Rules Triggered on {target_date_str} ---")
        print(f"{'Count':<10} | {'Rule ID':<10} | {'Rule Name'}")
        print("-" * 72)

        sorted_ids = sorted(id_counts.items(), key=lambda item: item[1], reverse=True)

        for rule_id, count in sorted_ids:
            rule_name = RULE_DESCRIPTIONS.get(rule_id, "Unknown rule name")
            print(f"{count:<10} | {rule_id:<10} | {rule_name}")

        # Grand total
        grand_total = sum(id_counts.values())
        print("-" * 72)
        print(f"{grand_total:<10} | {'TOTAL':<10} |")


if __name__ == "__main__":
    analyze_audit_logs_yesterday()
