#!/usr/bin/env python
import argparse
import os
import sys
import json
import gzip
import glob
import ipaddress
from collections import defaultdict, Counter
from tabulate import tabulate
from rich.console import Console
from datetime import datetime

console = Console()

# Argument parsing
parser = argparse.ArgumentParser(description='Summarize Zeek log files.')
parser.add_argument('-d', '--directory', type=str, required=True, help='Zeek log directory')
args = parser.parse_args()

# Detect files
log_types = ['conn', 'dns', 'http', 'ssl']
log_files = defaultdict(list)
for log_type in log_types:
    patterns = [f"{log_type}.log", f"{log_type}.*.log", f"{log_type}.*.log.gz"]
    for pattern in patterns:
        log_files[log_type] += glob.glob(os.path.join(args.directory, pattern))

# Read files with TSV header support
def read_lines(filepath):
    open_func = gzip.open if filepath.endswith('.gz') else open
    mode = 'rt' if filepath.endswith('.gz') else 'r'
    fields = []
    try:
        with open_func(filepath, mode, errors='replace') as f:
            for line in f:
                if line.startswith('#fields'):
                    fields = line.strip().split('\t')[1:]
                elif not line.startswith('#') and fields:
                    parts = line.strip().split('\t')
                    if len(parts) != len(fields):
                        continue
                    yield dict(zip(fields, parts))
    except EOFError:
        console.print(f"[bold yellow]⚠ Warning: Truncated gzip file detected:[/bold yellow] {filepath}")

# ============================
# GLOBAL SUMMARY FIRST
# ============================
all_src_ips = set()
all_dst_ips = set()
proto_counter = Counter()
dns_query_counter = Counter()
http_host_counter = Counter()
http_uri_counter = Counter()
ssl_issuer_counter = Counter()
ssl_subject_counter = Counter()

# CONN
for file in sorted(log_files['conn']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        dst = entry.get('id.resp_h')
        proto = entry.get('proto', '-')
        if src:
            all_src_ips.add(src)
            proto_counter[proto] += 1
        if dst:
            all_dst_ips.add(dst)

# DNS
for file in sorted(log_files['dns']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        qname = entry.get('query')
        if src:
            all_src_ips.add(src)
        if qname:
            dns_query_counter[qname] += 1

# HTTP
for file in sorted(log_files['http']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        uri = entry.get('uri')
        host = entry.get('host')
        if src:
            all_src_ips.add(src)
        if uri:
            http_uri_counter[uri] += 1
        if host:
            http_host_counter[host] += 1

# SSL
for file in sorted(log_files['ssl']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        issuer = entry.get('issuer')
        subject = entry.get('subject')
        if src:
            all_src_ips.add(src)
        if issuer:
            ssl_issuer_counter[issuer] += 1
        if subject:
            ssl_subject_counter[subject] += 1

# Print GLOBAL SUMMARY
console.print("\n[bold cyan]🌍 Global Summary[/bold cyan]")
console.print(tabulate([
    ["Unique Src IPs", len(all_src_ips)],
    ["Unique Dst IPs", len(all_dst_ips)],
    ["Total Protocols Seen", len(proto_counter)],
    ["Top Protocols", ', '.join(f"{k}:{v}" for k,v in proto_counter.most_common(3))],
    ["Top DNS Queries", ', '.join(f"{k} ({v})" for k,v in dns_query_counter.most_common(3))],
    ["Top HTTP Hosts", ', '.join(f"{k} ({v})" for k,v in http_host_counter.most_common(3))],
    ["Top SSL Issuers", ', '.join(f"{k} ({v})" for k,v in ssl_issuer_counter.most_common(2))],
], headers=["Category", "Summary"], tablefmt="fancy_grid"))

# ============================
# IP-CENTRIC AGGREGATION
# ============================
ip_profiles = defaultdict(lambda: defaultdict(Counter))

# CONN log
for file in sorted(log_files['conn']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        dst = entry.get('id.resp_h')
        proto = entry.get('proto', '-')
        if src:
            ip_profiles[src]['protocols'][proto] += 1
            ip_profiles[src]['roles']['source'] += 1
        if dst:
            ip_profiles[dst]['protocols'][proto] += 1
            ip_profiles[dst]['roles']['destination'] += 1

# DNS log
for file in sorted(log_files['dns']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        qname = entry.get('query')
        if src and qname:
            ip_profiles[src]['dns_queries'][qname] += 1
            ip_profiles[src]['roles']['dns_client'] += 1

# HTTP log
for file in sorted(log_files['http']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        uri = entry.get('uri')
        host = entry.get('host')
        if src:
            if uri:
                ip_profiles[src]['http_uris'][uri] += 1
            if host:
                ip_profiles[src]['http_hosts'][host] += 1
            ip_profiles[src]['roles']['http_client'] += 1

# SSL log
for file in sorted(log_files['ssl']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        issuer = entry.get('issuer')
        subject = entry.get('subject')
        if src:
            if issuer:
                ip_profiles[src]['ssl_issuers'][issuer] += 1
            if subject:
                ip_profiles[src]['ssl_subjects'][subject] += 1
            ip_profiles[src]['roles']['ssl_client'] += 1

# ============================
# PER-IP DETAILED SUMMARY
# ============================
console.print("\n[bold cyan]📌 Per-IP Summary[/bold cyan]")
for ip, sections in sorted(ip_profiles.items()):
    total_flows = sum(sections['roles'].values())
    console.print(f"\n[bold blue]🔹 {ip}[/bold blue] — Total roles: {total_flows}")
    if 'protocols' in sections:
        proto_line = ', '.join(f"{k}:{v}" for k, v in sections['protocols'].items())
        console.print(f"  ⚙ Protocols: {proto_line}")
    if 'roles' in sections:
        roles_line = ', '.join(f"{k}:{v}" for k, v in sections['roles'].items())
        console.print(f"  🧭 Roles: {roles_line}")
    if 'dns_queries' in sections:
        top_dns = sections['dns_queries'].most_common(3)
        console.print("  📡 DNS Queries: " + ', '.join(f"{k} ({v})" for k, v in top_dns))
    if 'http_hosts' in sections:
        top_hosts = sections['http_hosts'].most_common(2)
        console.print("  🌐 HTTP Hosts: " + ', '.join(f"{k} ({v})" for k, v in top_hosts))
    if 'http_uris' in sections:
        top_uris = sections['http_uris'].most_common(2)
        console.print("  📄 HTTP URIs: " + ', '.join(f"{k} ({v})" for k, v in top_uris))
    if 'ssl_issuers' in sections:
        top_issuers = sections['ssl_issuers'].most_common(1)
        console.print("  🏛 SSL Issuer: " + ', '.join(f"{k} ({v})" for k, v in top_issuers))
    if 'ssl_subjects' in sections:
        top_subjects = sections['ssl_subjects'].most_common(1)
        console.print("  🔐 SSL Subject: " + ', '.join(f"{k} ({v})" for k, v in top_subjects))

