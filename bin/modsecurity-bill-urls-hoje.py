# -*- coding: utf-8 -*-

import re
import glob
import os
import shutil
from collections import Counter
from datetime import datetime
import locale

#DATE_PATTERN = re.compile(
#    r'^\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]'
#)

DATE_PATTERN = re.compile(
    r'^\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? \+\d{4})\]'
)


DATE_COMPARE_PATTERN = re.compile(
    r'\[(\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4})'
)

REQUEST_PATTERN = re.compile(
    r'^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?',
    re.MULTILINE
)


def analisar_urls_hoje():
    try:
        locale.setlocale(locale.LC_TIME, 'C')
    except locale.Error:
        pass

    LOG_DIR = "/usr/local/apache/logs"
    LOG_PATTERN = os.path.join(LOG_DIR, "modsec_audit.log*")

    hoje = datetime.now()
    data_alvo_str = hoje.strftime('%d/%b/%Y')

    todos_arquivos = glob.glob(LOG_PATTERN)
    arquivos = [f for f in todos_arquivos if not f.endswith('.gz')]

    if not arquivos:
        print(f"Nenhum arquivo encontrado em {LOG_PATTERN}")
        return

    arquivos = sorted(arquivos, key=os.path.getmtime, reverse=True)

    url_counts = Counter()

    for logfile in arquivos:
        try:
            transacao_atual = []

            with open(logfile, 'r', encoding='latin-1', errors='ignore') as f:
                for linha in f:
                    if DATE_PATTERN.match(linha):
                        if transacao_atual:
                            processar_transacao(transacao_atual, data_alvo_str, url_counts)

                        transacao_atual = [linha]
                    else:
                        if transacao_atual:
                            transacao_atual.append(linha)

                if transacao_atual:
                    processar_transacao(transacao_atual, data_alvo_str, url_counts)

        except Exception:
            continue

    if not url_counts:
        print(f"\nNenhuma URL encontrada no ModSecurity para {data_alvo_str}.")
        return

    terminal_width = shutil.get_terminal_size((80, 20)).columns
    line_width = min(terminal_width - 1, 120)

    print(f"\n--- URLs atingidas pelo ModSecurity em {data_alvo_str} ---")
    print()
    print(f"{'Contagem':<10} | URL")
    print("-" * line_width)

    for url, count in url_counts.most_common(20):
        print(f"{count:<10} | {url}")

    print("-" * line_width)
    print(f"{sum(url_counts.values()):<10} | TOTAL")


def processar_transacao(transacao, data_alvo_str, url_counts):
    texto = "".join(transacao)

    date_match = DATE_COMPARE_PATTERN.search(texto)
    if not date_match:
        return

    if date_match.group(1) != data_alvo_str:
        return

    request_match = REQUEST_PATTERN.search(texto)
    if not request_match:
        return

    url = request_match.group(2)
    url_counts[url] += 1


if __name__ == "__main__":
    analisar_urls_hoje()