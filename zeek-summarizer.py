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
# CONN LOG SUMMARY
# ============================
unique_ips = {
    'src_ipv4': set(),
    'dst_ipv4': set(),
    'src_ipv6': set(),
    'dst_ipv6': set(),
}
flow_counts = defaultdict(lambda: defaultdict(int))  # ip -> protocol -> count
ip_activity = defaultdict(lambda: defaultdict(int))  # ip -> activity field -> count

for file in sorted(log_files['conn']):
    for entry in read_lines(file):
        orig_ip = entry.get('id.orig_h')
        resp_ip = entry.get('id.resp_h')
        proto = entry.get('proto', 'unknown')

        for ip, kind in [(orig_ip, 'src'), (resp_ip, 'dst')]:
            if not ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_key = f"{kind}_ipv4" if ip_obj.version == 4 else f"{kind}_ipv6"
                unique_ips[ip_key].add(ip)
                flow_counts[ip][proto] += 1
                ip_activity[ip][f"{kind}_{proto}"] += 1
            except ValueError:
                continue

# Show IP summary table
summary_table = [
    ["🌍 Src IPv4", len(unique_ips['src_ipv4'])],
    ["🌍 Dst IPv4", len(unique_ips['dst_ipv4'])],
    ["🌐 Src IPv6", len(unique_ips['src_ipv6'])],
    ["🌐 Dst IPv6", len(unique_ips['dst_ipv6'])],
]
console.print("\n[bold cyan]📊 Unique IP Address Summary[/bold cyan]")
console.print(tabulate(summary_table, headers=["Type", "Count"], tablefmt="fancy_grid"))

# Show top IPs by flows
flow_table = []
for ip, proto_counts in sorted(flow_counts.items(), key=lambda x: -sum(x[1].values()))[:15]:
    total = sum(proto_counts.values())
    proto_str = ', '.join(f"{p}:{c}" for p, c in proto_counts.items())
    flow_table.append([ip, total, proto_str])
console.print("\n[bold green]🔥 Top IPs by Flow Count[/bold green]")
console.print(tabulate(flow_table, headers=["IP", "Total Flows", "Protocols"], tablefmt="fancy_grid"))

# Show activity summary per IP
ip_summary_table = []
for ip, actions in sorted(ip_activity.items(), key=lambda x: -sum(x[1].values()))[:10]:
    summary = ', '.join(f"{k}:{v}" for k, v in actions.items())
    ip_summary_table.append([ip, summary])
console.print("\n[bold green]🧾 IP Behavior Summary[/bold green]")
console.print(tabulate(ip_summary_table, headers=["IP", "Behavior"], tablefmt="fancy_grid"))

# ============================
# DNS SUMMARY
# ============================
dns_queries = Counter()
for file in sorted(log_files['dns']):
    for entry in read_lines(file):
        query = entry.get('query')
        if query:
            dns_queries[query] += 1
if dns_queries:
    dns_table = dns_queries.most_common(15)
    console.print("\n[bold magenta]🧠 Top DNS Queries[/bold magenta]")
    console.print(tabulate(dns_table, headers=["Domain", "Count"], tablefmt="fancy_grid"))

# ============================
# HTTP SUMMARY
# ============================
http_hosts = Counter()
http_uris = Counter()
for file in sorted(log_files['http']):
    for entry in read_lines(file):
        host = entry.get('host')
        uri = entry.get('uri')
        if host:
            http_hosts[host] += 1
        if uri:
            http_uris[uri] += 1
if http_hosts:
    console.print("\n[bold blue]🌐 Top HTTP Hosts[/bold blue]")
    console.print(tabulate(http_hosts.most_common(10), headers=["Host", "Requests"], tablefmt="fancy_grid"))
if http_uris:
    console.print("\n[bold blue]📄 Top HTTP URIs[/bold blue]")
    console.print(tabulate(http_uris.most_common(10), headers=["URI", "Count"], tablefmt="fancy_grid"))

# ============================
# SSL SUMMARY
# ============================
ssl_subjects = Counter()
ssl_issuers = Counter()
for file in sorted(log_files['ssl']):
    for entry in read_lines(file):
        subject = entry.get('subject')
        issuer = entry.get('issuer')
        if subject:
            ssl_subjects[subject] += 1
        if issuer:
            ssl_issuers[issuer] += 1
if ssl_subjects:
    console.print("\n[bold yellow]🔐 Top SSL Subjects[/bold yellow]")
    console.print(tabulate(ssl_subjects.most_common(10), headers=["Subject", "Count"], tablefmt="fancy_grid"))
if ssl_issuers:
    console.print("\n[bold yellow]🏛 Top SSL Issuers[/bold yellow]")
    console.print(tabulate(ssl_issuers.most_common(10), headers=["Issuer", "Count"], tablefmt="fancy_grid"))

