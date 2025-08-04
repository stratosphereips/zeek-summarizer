#!/usr/bin/env python3
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
parser.add_argument('-r', '--require-activity', action='store_true', help='Only show IPs that appear in non-conn logs')
parser.add_argument('-o', '--only-conn', action='store_true', help='Only show IPs that appear only in conn logs')
parser.add_argument('-p', '--per-port', action='store_true', help='Show summary per port instead of per IP')
parser.add_argument('--local-only', '-l', action='store_true', help='Only show info about local networks (IPv4/IPv6)')
args = parser.parse_args()

# Detect files
log_types = ['conn', 'dns', 'http', 'ssl', 'smb_mapping']  # Added smb_mapping
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

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # IPv4 private, loopback, link-local, multicast, reserved
        if ip_obj.version == 4:
            return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)
        # IPv6: private (unique local), loopback, link-local, multicast, reserved
        elif ip_obj.version == 6:
            return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)
    except Exception:
        return False
    return False

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
# SMB global counters
smb_src_ips = set()
smb_dst_ips = set()
smb_share_counter = Counter()
smb_native_fs_counter = Counter()
smb_share_type_counter = Counter()

# Track non-conn log activity
non_conn_ips = set()

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
            non_conn_ips.add(src)
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
            non_conn_ips.add(src)
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
        sni = entry.get('server_name')
        if src:
            all_src_ips.add(src)
            non_conn_ips.add(src)
        if issuer:
            ssl_issuer_counter[issuer] += 1
        if subject:
            ssl_subject_counter[subject] += 1

# SMB_MAPPING
for file in sorted(log_files['smb_mapping']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        dst = entry.get('id.resp_h')
        share = entry.get('path')
        native_fs = entry.get('native_file_system')
        share_type = entry.get('share_type')
        if src:
            smb_src_ips.add(src)
            all_src_ips.add(src)
            non_conn_ips.add(src)
        if dst:
            smb_dst_ips.add(dst)
            all_dst_ips.add(dst)
            non_conn_ips.add(dst)
        if share:
            smb_share_counter[share] += 1
        if native_fs:
            smb_native_fs_counter[native_fs] += 1
        if share_type:
            smb_share_type_counter[share_type] += 1

# Print GLOBAL SUMMARY
console.print("\n[bold cyan]🌍 Global Summary[/bold cyan]")
def filter_local(counter):
    if not args.local_only:
        return counter
    filtered = Counter()
    for k, v in counter.items():
        if is_local_ip(k):
            filtered[k] = v
    return filtered

def filter_local_set(ipset):
    if not args.local_only:
        return ipset
    return {ip for ip in ipset if is_local_ip(ip)}

console.print(tabulate([
    ["Unique Src IPs", len(filter_local_set(all_src_ips))],
    ["Unique Dst IPs", len(filter_local_set(all_dst_ips))],
    ["Total Protocols Seen", len(proto_counter)],
    ["Top Protocols", ', '.join(f"{k}:{v}" for k,v in proto_counter.most_common(3))],
    ["Top DNS Queries", ', '.join(f"{k} ({v})" for k,v in filter_local(dns_query_counter).most_common(3))],
    ["Top HTTP Hosts", ', '.join(f"{k} ({v})" for k,v in filter_local(http_host_counter).most_common(3))],
    ["Top SSL Issuers", ', '.join(f"{k} ({v})" for k,v in filter_local(ssl_issuer_counter).most_common(2))],
    # SMB summary lines
    ["Unique SMB Src IPs", len(filter_local_set(smb_src_ips))],
    ["Unique SMB Dst IPs", len(filter_local_set(smb_dst_ips))],
    ["Top SMB Shares", ', '.join(f"{k} ({v})" for k,v in filter_local(smb_share_counter).most_common(3))],
    ["Top SMB Native FS", ', '.join(f"{k} ({v})" for k,v in filter_local(smb_native_fs_counter).most_common(2))],
    ["Top SMB Share Types", ', '.join(f"{k} ({v})" for k,v in filter_local(smb_share_type_counter).most_common(2))],
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
            ip_profiles[src]['flows']['as source'] += 1
        if dst:
            ip_profiles[dst]['protocols'][proto] += 1
            ip_profiles[dst]['flows']['destination'] += 1
        if args.only_conn or True:  # Always collect ports for per-IP stats
            dport = entry.get('id.resp_p')
            if dport:
                if src:
                    ip_profiles[src]['dst_ports_as_src'][dport] += 1
                if dst:
                    ip_profiles[dst]['dst_ports_as_dst'][dport] += 1

# DNS log
for file in sorted(log_files['dns']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        qname = entry.get('query')
        if src and qname:
            ip_profiles[src]['dns_queries'][qname] += 1
            ip_profiles[src]['flows']['dns_client'] += 1

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
            ip_profiles[src]['flows']['http_client'] += 1

# SSL log
for file in sorted(log_files['ssl']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        issuer = entry.get('issuer')
        subject = entry.get('subject')
        sni = entry.get('server_name')
        if src:
            if issuer:
                ip_profiles[src]['ssl_issuers'][issuer] += 1
            if subject:
                ip_profiles[src]['ssl_subjects'][subject] += 1
            if sni:
                ip_profiles[src]['snis'][sni] += 1
            ip_profiles[src]['flows']['ssl_client'] += 1

# SMB_MAPPING log
for file in sorted(log_files['smb_mapping']):
    for entry in read_lines(file):
        src = entry.get('id.orig_h')
        dst = entry.get('id.resp_h')
        share = entry.get('path')
        native_fs = entry.get('native_file_system')
        share_type = entry.get('share_type')
        if src:
            if share:
                ip_profiles[src]['smb_shares'][share] += 1
            if native_fs:
                ip_profiles[src]['smb_native_fs'][native_fs] += 1
            if share_type:
                ip_profiles[src]['smb_share_types'][share_type] += 1
            ip_profiles[src]['flows']['smb_client'] += 1
        if dst:
            if share:
                ip_profiles[dst]['smb_shares'][share] += 1
            if native_fs:
                ip_profiles[dst]['smb_native_fs'][native_fs] += 1
            if share_type:
                ip_profiles[dst]['smb_share_types'][share_type] += 1
            ip_profiles[dst]['flows']['smb_server'] += 1

# ============================
# PER-PORT SUMMARY IF REQUESTED
# ============================
if args.per_port:
    port_summary = defaultdict(lambda: defaultdict(int))
    for ip, sections in ip_profiles.items():
        if args.require_activity and ip not in non_conn_ips:
            continue
        if args.only_conn and ip in non_conn_ips:
            continue
        for dport, count in sections.get('dst_ports_as_src', {}).items():
            port_summary[dport]['as_dst'] += count
        for dport, count in sections.get('dst_ports_as_dst', {}).items():
            port_summary[dport]['as_target'] += count

    console.print("[bold magenta]📊 Per-Port Summary[/bold magenta]")

    # Build histogram bins with correct scaling
    bin_size = 100
    port_bins = defaultdict(int)
    for port_str, counts in port_summary.items():
        try:
            port = int(port_str)
            bin_label = f"{(port // bin_size) * bin_size}-{((port // bin_size) + 1) * bin_size - 1}"
            port_bins[bin_label] += counts.get('as_dst', 0) + counts.get('as_target', 0)
        except ValueError:
            continue

    max_count = max(port_bins.values(), default=1)
    console.print("[bold green]📉 Port Usage Histogram (bin size: 100)[/bold green]")
    for label in sorted(port_bins, key=lambda x: int(x.split('-')[0])):
        count = port_bins[label]
        bar = '█' * int((count / max_count) * 40)  # Scaled relative to max
        console.print(f"  {label.ljust(12)} | {bar} ({count})")

    table_data = []
    for port, data in sorted(port_summary.items(), key=lambda x: int(x[0])):
        table_data.append([port, data.get('as_dst', 0), data.get('as_target', 0)])
    console.print(tabulate(table_data, headers=["Port", "Used as Destination", "Targeted by Others"], tablefmt="fancy_grid"))
    sys.exit(0)

# ============================
# PER-IP DETAILED SUMMARY
# ============================
console.print("\n[bold cyan]📌 Per-IP Summary[/bold cyan]")
for ip, sections in sorted(ip_profiles.items()):
    if args.require_activity and ip not in non_conn_ips:
        continue
    if args.only_conn and ip in non_conn_ips:
        continue
    if args.local_only and not is_local_ip(ip):
        continue
    total_flows = sum(sections['flows'].values())
    console.print(f"\n[bold blue]🔹 {ip}[/bold blue] — Total flows: {total_flows}")
    if 'protocols' in sections:
        proto_line = ', '.join(f"{k}:{v}" for k, v in sections['protocols'].items())
        console.print(f"  ⚙ Protocols: {proto_line}")
    if 'flows' in sections:
        flows_line = ', '.join(f"{k}:{v}" for k, v in sections['flows'].items())
        console.print(f"  🧭 Flows: {flows_line}")
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
        console.print("  🏛  SSL Issuer: " + ', '.join(f"{k} ({v})" for k, v in top_issuers))
    if 'ssl_subjects' in sections:
        top_subjects = sections['ssl_subjects'].most_common(1)
        console.print("  🔐 SSL Subject: " + ', '.join(f"{k} ({v})" for k, v in top_subjects))
    if 'snis' in sections:
        top_snis = sections['snis'].most_common(2)
        console.print("  📛 SSL SNI: " + ', '.join(f"{k} ({v})" for k, v in top_snis))
    # SMB per-IP summary
    if 'smb_shares' in sections:
        top_smb_shares = sections['smb_shares'].most_common(3)
        if top_smb_shares:
            console.print("  🗄️  SMB Shares: " + ', '.join(f"{k} ({v})" for k, v in top_smb_shares))
    if 'smb_native_fs' in sections:
        top_smb_fs = sections['smb_native_fs'].most_common(2)
        if top_smb_fs:
            console.print("  🧮 SMB Native FS: " + ', '.join(f"{k} ({v})" for k, v in top_smb_fs))
    if 'smb_share_types' in sections:
        top_smb_types = sections['smb_share_types'].most_common(2)
        if top_smb_types:
            console.print("  🏷️  SMB Share Types: " + ', '.join(f"{k} ({v})" for k, v in top_smb_types))
    # Show top destination ports as source (outgoing)
    if 'dst_ports_as_src' in sections:
        top_ports_src = sections['dst_ports_as_src'].most_common(10)
        if top_ports_src:
            console.print("  🎯 Top Dst Ports used (as source): " +
                          ', '.join(f"{k} ({v})" for k, v in top_ports_src))
    # Show top destination ports as destination (incoming)
    if 'dst_ports_as_dst' in sections:
        top_ports_dst = sections['dst_ports_as_dst'].most_common(10)
        if top_ports_dst:
            console.print("  🛡️  Top Dst Ports targeted (as destination): " +
                          ', '.join(f"{k} ({v})" for k, v in top_ports_dst))
    if args.only_conn:
        if 'dst_ports_as_src' in sections:
            legacy_ports_src = sections['dst_ports_as_src'].most_common(5)
            if legacy_ports_src:
                console.print("  🎯 Dst Ports (as source, top 5): " + ', '.join(f"{k} ({v})" for k, v in legacy_ports_src))
        if 'dst_ports_as_dst' in sections:
            legacy_ports_dst = sections['dst_ports_as_dst'].most_common(5)
            if legacy_ports_dst:
                console.print("  🛡️ Dst Ports (as destination, top 5): " + ', '.join(f"{k} ({v})" for k, v in legacy_ports_dst))

