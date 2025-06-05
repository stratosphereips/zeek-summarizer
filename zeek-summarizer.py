#!/usr/bin/env python
import argparse
import os
import sys
import json
import gzip
import glob
import ipaddress
from collections import defaultdict
from tabulate import tabulate
from rich.console import Console
from datetime import datetime

console = Console()

# Argument parsing
parser = argparse.ArgumentParser(description='Summarize Zeek log files.')
parser.add_argument('-d', '--directory', type=str, required=True, help='Zeek log directory')
args = parser.parse_args()

# Detect files
file_patterns = ['conn.log', 'conn.*.log', 'conn.*.log.gz']
files = []
for pattern in file_patterns:
    files += glob.glob(os.path.join(args.directory, pattern))

if not files:
    console.print("[bold red]No conn.log files found![/bold red]")
    exit(1)

# Initialize stats
unique_ips = {
    'src_ipv4': set(),
    'dst_ipv4': set(),
    'src_ipv6': set(),
    'dst_ipv6': set(),
}

flow_counts = defaultdict(lambda: defaultdict(int))  # ip -> protocol -> count

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

for file in sorted(files):
    for entry in read_lines(file):
        orig_ip = entry.get('id.orig_h')
        resp_ip = entry.get('id.resp_h')
        proto = entry.get('proto', 'unknown')

        # Classify IPs
        for ip, kind in [(orig_ip, 'src'), (resp_ip, 'dst')]:
            if not ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_key = f"{kind}_ipv4" if ip_obj.version == 4 else f"{kind}_ipv6"
                unique_ips[ip_key].add(ip)
                flow_counts[ip][proto] += 1
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

