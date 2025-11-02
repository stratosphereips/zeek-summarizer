#!/usr/bin/env python3
import argparse
import gzip
import json
import glob
import ipaddress
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from rich.console import Console
from tabulate import tabulate

console = Console()

LOG_TYPES = ['conn', 'dns', 'http', 'ssl', 'smb_mapping']


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Summarize Zeek log files.')
    parser.add_argument('-d', '--directory', type=str, required=True, help='Zeek log directory')
    parser.add_argument('-r', '--require-activity', action='store_true',
                        help='Only show IPs that appear in non-conn logs')
    parser.add_argument('-o', '--only-conn', action='store_true',
                        help='Only show IPs that appear only in conn logs')
    parser.add_argument('-p', '--per-port', action='store_true', help='Show summary per port instead of per IP')
    parser.add_argument('--local-only', '-l', action='store_true',
                        help='Only show info about local networks (IPv4/IPv6)')
    parser.add_argument('--output-format', choices=['text', 'json', 'html'], default='text',
                        help='Choose output mode')
    parser.add_argument('--output-file', type=str, help='Path to write JSON or HTML output')
    return parser


def detect_log_files(directory: str) -> Dict[str, List[str]]:
    log_files: Dict[str, List[str]] = defaultdict(list)
    for log_type in LOG_TYPES:
        patterns = [
            f"{log_type}.log",
            f"{log_type}.log.gz",
            f"{log_type}.*.log",
            f"{log_type}.*.log.gz",
        ]
        found = set()
        for pattern in patterns:
            found.update(glob.glob(os.path.join(directory, pattern)))
        log_files[log_type] = sorted(found)
    return log_files


def read_lines(filepath: str) -> Iterable[Dict[str, object]]:
    open_func = gzip.open if filepath.endswith('.gz') else open
    mode = 'rt' if filepath.endswith('.gz') else 'r'
    fields: List[str] = []
    is_json = None
    try:
        with open_func(filepath, mode, errors='replace') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    if line.startswith('#fields'):
                        fields = line.split('\t')[1:]
                    continue
                if is_json is None:
                    is_json = line.startswith('{')
                if is_json:
                    try:
                        yield json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue
                else:
                    if not fields:
                        continue
                    parts = raw_line.rstrip('\n').split('\t')
                    if len(parts) != len(fields):
                        continue
                    yield dict(zip(fields, parts))
    except EOFError:
        console.print(f"[bold yellow]⚠ Warning: Truncated gzip file detected:[/bold yellow] {filepath}")


def is_local_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
            )
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except Exception:
        return False


def classify_ip(ip: str) -> Dict[str, str]:
    info = {
        "category": "Unknown",
        "network": "Unknown",
        "version": "unknown",
    }
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return info

    info["version"] = f"ipv{ip_obj.version}"

    if ip_obj.is_unspecified:
        info["category"] = "Unspecified"
    elif ip_obj.is_loopback:
        info["category"] = "Loopback"
    elif ip_obj.is_multicast:
        info["category"] = "Multicast"
    elif ip_obj.is_link_local:
        info["category"] = "Link-Local"
    elif ip_obj.is_private:
        info["category"] = f"Local IPv{ip_obj.version}"
    else:
        info["category"] = f"External IPv{ip_obj.version}"

    prefix = 24 if ip_obj.version == 4 else 64
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        info["network"] = f"{network.with_prefixlen}"
    except ValueError:
        info["network"] = ip

    return info


def aggregate_logs(directory: str) -> Dict[str, object]:
    log_files = detect_log_files(directory)
    all_src_ips = set()
    all_dst_ips = set()
    proto_counter = Counter()
    dns_query_counter = Counter()
    http_host_counter = Counter()
    http_uri_counter = Counter()
    ssl_issuer_counter = Counter()
    ssl_subject_counter = Counter()
    smb_src_ips = set()
    smb_dst_ips = set()
    smb_share_counter = Counter()
    smb_native_fs_counter = Counter()
    smb_share_type_counter = Counter()
    non_conn_ips = set()
    ip_profiles: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))

    # CONN logs
    for filepath in log_files['conn']:
        for entry in read_lines(filepath):
            src = entry.get('id.orig_h')
            dst = entry.get('id.resp_h')
            proto = entry.get('proto') or '-'
            src_str = str(src) if src else None
            dst_str = str(dst) if dst else None
            proto_str = str(proto)
            if src_str:
                all_src_ips.add(src_str)
                proto_counter[proto_str] += 1
                ip_profiles[src_str]['protocols'][proto_str] += 1
                ip_profiles[src_str]['flows']['as source'] += 1
            if dst_str:
                all_dst_ips.add(dst_str)
                ip_profiles[dst_str]['protocols'][proto_str] += 1
                ip_profiles[dst_str]['flows']['destination'] += 1
            dport = entry.get('id.resp_p')
            if dport not in (None, ''):
                dport_str = str(dport)
                if src_str:
                    ip_profiles[src_str]['dst_ports_as_src'][dport_str] += 1
                if dst_str:
                    ip_profiles[dst_str]['dst_ports_as_dst'][dport_str] += 1

    # DNS logs
    for filepath in log_files['dns']:
        for entry in read_lines(filepath):
            src = entry.get('id.orig_h')
            dst = entry.get('id.resp_h')
            qname = entry.get('query')
            src_str = str(src) if src else None
            dst_str = str(dst) if dst else None
            qname_str = str(qname) if qname else None
            if src_str:
                all_src_ips.add(src_str)
                non_conn_ips.add(src_str)
            if dst_str:
                all_dst_ips.add(dst_str)
                non_conn_ips.add(dst_str)
            if qname_str:
                dns_query_counter[qname_str] += 1
                if src_str:
                    ip_profiles[src_str]['dns_queries'][qname_str] += 1
                    ip_profiles[src_str]['flows']['dns_client'] += 1
                if dst_str:
                    ip_profiles[dst_str]['dns_queries'][qname_str] += 1
                    ip_profiles[dst_str]['flows']['dns_server'] += 1

    # HTTP logs
    for filepath in log_files['http']:
        for entry in read_lines(filepath):
            src = entry.get('id.orig_h')
            dst = entry.get('id.resp_h')
            uri = entry.get('uri')
            host = entry.get('host')
            src_str = str(src) if src else None
            dst_str = str(dst) if dst else None
            uri_str = str(uri) if uri else None
            host_str = str(host) if host else None
            if src_str:
                all_src_ips.add(src_str)
                non_conn_ips.add(src_str)
                if uri_str:
                    ip_profiles[src_str]['http_uris'][uri_str] += 1
                if host_str:
                    ip_profiles[src_str]['http_hosts'][host_str] += 1
                ip_profiles[src_str]['flows']['http_client'] += 1
            if dst_str:
                all_dst_ips.add(dst_str)
                non_conn_ips.add(dst_str)
                ip_profiles[dst_str]['flows']['http_server'] += 1
            if uri_str:
                http_uri_counter[uri_str] += 1
            if host_str:
                http_host_counter[host_str] += 1

    # SSL logs
    for filepath in log_files['ssl']:
        for entry in read_lines(filepath):
            src = entry.get('id.orig_h')
            dst = entry.get('id.resp_h')
            issuer = entry.get('issuer')
            subject = entry.get('subject')
            sni = entry.get('server_name')
            src_str = str(src) if src else None
            dst_str = str(dst) if dst else None
            issuer_str = str(issuer) if issuer else None
            subject_str = str(subject) if subject else None
            sni_str = str(sni) if sni else None
            if src_str:
                all_src_ips.add(src_str)
                non_conn_ips.add(src_str)
                if issuer_str:
                    ip_profiles[src_str]['ssl_issuers'][issuer_str] += 1
                if subject_str:
                    ip_profiles[src_str]['ssl_subjects'][subject_str] += 1
                if sni_str:
                    ip_profiles[src_str]['snis'][sni_str] += 1
                ip_profiles[src_str]['flows']['ssl_client'] += 1
            if dst_str:
                all_dst_ips.add(dst_str)
                non_conn_ips.add(dst_str)
                ip_profiles[dst_str]['flows']['ssl_server'] += 1
            if issuer_str:
                ssl_issuer_counter[issuer_str] += 1
            if subject_str:
                ssl_subject_counter[subject_str] += 1

    # SMB mapping logs
    for filepath in log_files['smb_mapping']:
        for entry in read_lines(filepath):
            src = entry.get('id.orig_h')
            dst = entry.get('id.resp_h')
            share = entry.get('path')
            native_fs = entry.get('native_file_system')
            share_type = entry.get('share_type')
            src_str = str(src) if src else None
            dst_str = str(dst) if dst else None
            share_str = str(share) if share else None
            native_fs_str = str(native_fs) if native_fs else None
            share_type_str = str(share_type) if share_type else None
            if src_str:
                smb_src_ips.add(src_str)
                all_src_ips.add(src_str)
                non_conn_ips.add(src_str)
                if share_str:
                    ip_profiles[src_str]['smb_shares'][share_str] += 1
                if native_fs_str:
                    ip_profiles[src_str]['smb_native_fs'][native_fs_str] += 1
                if share_type_str:
                    ip_profiles[src_str]['smb_share_types'][share_type_str] += 1
                ip_profiles[src_str]['flows']['smb_client'] += 1
            if dst_str:
                smb_dst_ips.add(dst_str)
                all_dst_ips.add(dst_str)
                non_conn_ips.add(dst_str)
                if share_str:
                    ip_profiles[dst_str]['smb_shares'][share_str] += 1
                if native_fs_str:
                    ip_profiles[dst_str]['smb_native_fs'][native_fs_str] += 1
                if share_type_str:
                    ip_profiles[dst_str]['smb_share_types'][share_type_str] += 1
                ip_profiles[dst_str]['flows']['smb_server'] += 1
            if share_str:
                smb_share_counter[share_str] += 1
            if native_fs_str:
                smb_native_fs_counter[native_fs_str] += 1
            if share_type_str:
                smb_share_type_counter[share_type_str] += 1

    port_summary = defaultdict(lambda: {'as_dst': 0, 'as_target': 0})
    for sections in ip_profiles.values():
        for port, count in sections.get('dst_ports_as_src', Counter()).items():
            port_summary[port]['as_dst'] += int(count)
        for port, count in sections.get('dst_ports_as_dst', Counter()).items():
            port_summary[port]['as_target'] += int(count)

    return {
        'log_files': log_files,
        'all_src_ips': all_src_ips,
        'all_dst_ips': all_dst_ips,
        'proto_counter': proto_counter,
        'dns_query_counter': dns_query_counter,
        'http_host_counter': http_host_counter,
        'http_uri_counter': http_uri_counter,
        'ssl_issuer_counter': ssl_issuer_counter,
        'ssl_subject_counter': ssl_subject_counter,
        'smb_src_ips': smb_src_ips,
        'smb_dst_ips': smb_dst_ips,
        'smb_share_counter': smb_share_counter,
        'smb_native_fs_counter': smb_native_fs_counter,
        'smb_share_type_counter': smb_share_type_counter,
        'non_conn_ips': non_conn_ips,
        'ip_profiles': ip_profiles,
        'port_summary': {k: dict(v) for k, v in port_summary.items()},
    }


def filter_local_counter(counter: Counter, local_only: bool) -> Counter:
    if not local_only:
        return counter
    filtered = Counter()
    for key, value in counter.items():
        if is_local_ip(key):
            filtered[key] = value
    return filtered


def filter_local_set(values: Iterable[str], local_only: bool) -> set:
    values = set(values)
    if not local_only:
        return values
    return {ip for ip in values if is_local_ip(ip)}


def should_include_ip(ip: str, args: argparse.Namespace, non_conn_ips: set) -> bool:
    if args.require_activity and ip not in non_conn_ips:
        return False
    if args.only_conn and ip in non_conn_ips:
        return False
    if args.local_only and not is_local_ip(ip):
        return False
    return True


def render_port_summary(result: Dict[str, object]) -> None:
    port_summary: Dict[str, Dict[str, int]] = result['port_summary']
    if not port_summary:
        console.print("[bold yellow]No port data available.[/bold yellow]")
        return

    console.print("[bold magenta]📊 Per-Port Summary[/bold magenta]")
    bin_size = 100
    port_bins = defaultdict(int)
    for port_str, counts in port_summary.items():
        try:
            port = int(port_str)
        except (TypeError, ValueError):
            continue
        bin_label = f"{(port // bin_size) * bin_size}-{((port // bin_size) + 1) * bin_size - 1}"
        port_bins[bin_label] += counts.get('as_dst', 0) + counts.get('as_target', 0)

    max_count = max(port_bins.values(), default=1)
    console.print("[bold green]📉 Port Usage Histogram (bin size: 100)[/bold green]")
    for label in sorted(port_bins, key=lambda x: int(x.split('-')[0])):
        count = port_bins[label]
        bar = '█' * int((count / max_count) * 40) if max_count else ''
        console.print(f"  {label.ljust(12)} | {bar} ({count})")

    def port_sort_key(item):
        port = item[0]
        try:
            return int(port)
        except (TypeError, ValueError):
            return 10**9

    table_data = []
    for port, counts in sorted(port_summary.items(), key=port_sort_key):
        table_data.append([
            port,
            counts.get('as_dst', 0),
            counts.get('as_target', 0),
        ])
    console.print(tabulate(table_data, headers=["Port", "Used as Destination", "Targeted by Others"], tablefmt="fancy_grid"))


def render_text_report(result: Dict[str, object], args: argparse.Namespace) -> None:
    console.print("\n[bold cyan]🌍 Global Summary[/bold cyan]")
    local_src_ips = filter_local_set(result['all_src_ips'], args.local_only)
    local_dst_ips = filter_local_set(result['all_dst_ips'], args.local_only)
    top_protocols = result['proto_counter'].most_common(3)
    top_dns = filter_local_counter(result['dns_query_counter'], args.local_only).most_common(3)
    top_http_hosts = filter_local_counter(result['http_host_counter'], args.local_only).most_common(3)
    top_ssl_issuers = filter_local_counter(result['ssl_issuer_counter'], args.local_only).most_common(2)
    top_smb_shares = filter_local_counter(result['smb_share_counter'], args.local_only).most_common(3)
    top_smb_fs = filter_local_counter(result['smb_native_fs_counter'], args.local_only).most_common(2)
    top_smb_types = filter_local_counter(result['smb_share_type_counter'], args.local_only).most_common(2)

    global_table = [
        ["Unique Src IPs", len(local_src_ips)],
        ["Unique Dst IPs", len(local_dst_ips)],
        ["Total Protocols Seen", len(result['proto_counter'])],
        ["Top Protocols", ', '.join(f"{k}:{v}" for k, v in top_protocols)],
        ["Top DNS Queries", ', '.join(f"{k} ({v})" for k, v in top_dns)],
        ["Top HTTP Hosts", ', '.join(f"{k} ({v})" for k, v in top_http_hosts)],
        ["Top SSL Issuers", ', '.join(f"{k} ({v})" for k, v in top_ssl_issuers)],
        ["Unique SMB Src IPs", len(filter_local_set(result['smb_src_ips'], args.local_only))],
        ["Unique SMB Dst IPs", len(filter_local_set(result['smb_dst_ips'], args.local_only))],
        ["Top SMB Shares", ', '.join(f"{k} ({v})" for k, v in top_smb_shares)],
        ["Top SMB Native FS", ', '.join(f"{k} ({v})" for k, v in top_smb_fs)],
        ["Top SMB Share Types", ', '.join(f"{k} ({v})" for k, v in top_smb_types)],
    ]
    console.print(tabulate(global_table, headers=["Category", "Summary"], tablefmt="fancy_grid"))

    if args.per_port:
        render_port_summary(result)
        return

    console.print("\n[bold cyan]📌 Per-IP Summary[/bold cyan]")
    shown_any = False
    for ip in sorted(result['ip_profiles'].keys()):
        if not should_include_ip(ip, args, result['non_conn_ips']):
            continue
        sections = result['ip_profiles'][ip]
        flows_counter = sections.get('flows', Counter())
        total_flows = sum(flows_counter.values())
        console.print(f"\n[bold blue]🔹 {ip}[/bold blue] — Total flows: {total_flows}")
        protocols = sections.get('protocols', Counter())
        if protocols:
            proto_line = ', '.join(f"{k}:{v}" for k, v in protocols.items())
            console.print(f"  ⚙ Protocols: {proto_line}")
        if flows_counter:
            flows_line = ', '.join(f"{k}:{v}" for k, v in flows_counter.items())
            console.print(f"  🧭 Flows: {flows_line}")
        dns_queries = sections.get('dns_queries', Counter())
        if dns_queries:
            top_dns = dns_queries.most_common(3)
            console.print("  📡 DNS Queries: " + ', '.join(f"{k} ({v})" for k, v in top_dns))
        http_hosts = sections.get('http_hosts', Counter())
        if http_hosts:
            top_hosts = http_hosts.most_common(2)
            console.print("  🌐 HTTP Hosts: " + ', '.join(f"{k} ({v})" for k, v in top_hosts))
        http_uris = sections.get('http_uris', Counter())
        if http_uris:
            top_uris = http_uris.most_common(2)
            console.print("  📄 HTTP URIs: " + ', '.join(f"{k} ({v})" for k, v in top_uris))
        ssl_issuers = sections.get('ssl_issuers', Counter())
        if ssl_issuers:
            top_issuers = ssl_issuers.most_common(1)
            console.print("  🏛  SSL Issuer: " + ', '.join(f"{k} ({v})" for k, v in top_issuers))
        ssl_subjects = sections.get('ssl_subjects', Counter())
        if ssl_subjects:
            top_subjects = ssl_subjects.most_common(1)
            console.print("  🔐 SSL Subject: " + ', '.join(f"{k} ({v})" for k, v in top_subjects))
        snis = sections.get('snis', Counter())
        if snis:
            top_snis = snis.most_common(2)
            console.print("  📛 SSL SNI: " + ', '.join(f"{k} ({v})" for k, v in top_snis))
        smb_shares = sections.get('smb_shares', Counter())
        if smb_shares:
            top_smb_shares = smb_shares.most_common(3)
            console.print("  🗄️  SMB Shares: " + ', '.join(f"{k} ({v})" for k, v in top_smb_shares))
        smb_native_fs = sections.get('smb_native_fs', Counter())
        if smb_native_fs:
            top_smb_fs = smb_native_fs.most_common(2)
            console.print("  🧮 SMB Native FS: " + ', '.join(f"{k} ({v})" for k, v in top_smb_fs))
        smb_share_types = sections.get('smb_share_types', Counter())
        if smb_share_types:
            top_smb_types = smb_share_types.most_common(2)
            console.print("  🏷️  SMB Share Types: " + ', '.join(f"{k} ({v})" for k, v in top_smb_types))
        dst_ports_src = sections.get('dst_ports_as_src', Counter())
        if dst_ports_src:
            top_ports_src = dst_ports_src.most_common(10)
            console.print("  🎯 Top Dst Ports used (as source): " +
                          ', '.join(f"{k} ({v})" for k, v in top_ports_src))
        dst_ports_dst = sections.get('dst_ports_as_dst', Counter())
        if dst_ports_dst:
            top_ports_dst = dst_ports_dst.most_common(10)
            console.print("  🛡️  Top Dst Ports targeted (as destination): " +
                          ', '.join(f"{k} ({v})" for k, v in top_ports_dst))
        if args.only_conn:
            if dst_ports_src:
                legacy_ports_src = dst_ports_src.most_common(5)
                console.print("  🎯 Dst Ports (as source, top 5): " +
                              ', '.join(f"{k} ({v})" for k, v in legacy_ports_src))
            if dst_ports_dst:
                legacy_ports_dst = dst_ports_dst.most_common(5)
                console.print("  🛡️ Dst Ports (as destination, top 5): " +
                              ', '.join(f"{k} ({v})" for k, v in legacy_ports_dst))
        shown_any = True

    if not shown_any:
        console.print("[bold yellow]No IPs matched the chosen filters.[/bold yellow]")


def counter_to_list(counter, limit: int | None = None) -> List[Dict[str, int]]:
    if isinstance(counter, Counter):
        items = counter.most_common()
    else:
        items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
    if limit is not None:
        items = items[:limit]
    return [{"label": str(k), "count": int(v)} for k, v in items if v]


def compute_port_bins(port_summary: Dict[str, Dict[str, int]], bin_size: int = 100) -> List[Dict[str, int]]:
    bins = defaultdict(int)
    for port_str, counts in port_summary.items():
        try:
            port = int(port_str)
        except (TypeError, ValueError):
            continue
        label = f"{(port // bin_size) * bin_size}-{((port // bin_size) + 1) * bin_size - 1}"
        bins[label] += counts.get('as_dst', 0) + counts.get('as_target', 0)
    return [{"label": label, "count": bins[label]} for label in sorted(bins, key=lambda lbl: int(lbl.split('-')[0]))]


def build_export_data(result: Dict[str, object], args: argparse.Namespace, top_limit: int = 15) -> Dict[str, object]:
    local_src_ips = filter_local_set(result['all_src_ips'], args.local_only)
    local_dst_ips = filter_local_set(result['all_dst_ips'], args.local_only)
    global_section = {
        "unique_src_ips": len(local_src_ips),
        "unique_dst_ips": len(local_dst_ips),
        "total_protocols": len(result['proto_counter']),
        "top_protocols": counter_to_list(result['proto_counter'], min(top_limit, len(result['proto_counter']))),
        "top_dns_queries": counter_to_list(filter_local_counter(result['dns_query_counter'], args.local_only), top_limit),
        "top_http_hosts": counter_to_list(filter_local_counter(result['http_host_counter'], args.local_only), top_limit),
        "top_http_uris": counter_to_list(filter_local_counter(result['http_uri_counter'], args.local_only), top_limit),
        "top_ssl_issuers": counter_to_list(filter_local_counter(result['ssl_issuer_counter'], args.local_only), top_limit),
        "top_ssl_subjects": counter_to_list(filter_local_counter(result['ssl_subject_counter'], args.local_only), top_limit),
        "top_smb_shares": counter_to_list(filter_local_counter(result['smb_share_counter'], args.local_only), top_limit),
        "top_smb_native_fs": counter_to_list(filter_local_counter(result['smb_native_fs_counter'], args.local_only), top_limit),
        "top_smb_share_types": counter_to_list(filter_local_counter(result['smb_share_type_counter'], args.local_only), top_limit),
    }
    global_section["unique_smb_src_ips"] = len(filter_local_set(result['smb_src_ips'], args.local_only))
    global_section["unique_smb_dst_ips"] = len(filter_local_set(result['smb_dst_ips'], args.local_only))

    top_ports = []
    for port, counts in result['port_summary'].items():
        total = counts.get('as_dst', 0) + counts.get('as_target', 0)
        if not total:
            continue
        top_ports.append({
            "label": str(port),
            "as_dst": counts.get('as_dst', 0),
            "as_target": counts.get('as_target', 0),
            "total": total,
        })
    top_ports.sort(key=lambda item: item["total"], reverse=True)
    top_ports = top_ports[:top_limit]

    hosts: List[Dict[str, object]] = []
    category_counts = Counter()
    network_counts = Counter()

    for ip, sections in result['ip_profiles'].items():
        if not should_include_ip(ip, args, result['non_conn_ips']):
            continue
        flows_counter = sections.get('flows', Counter())
        total_flows = int(sum(flows_counter.values()))
        ip_meta = classify_ip(ip)
        category = ip_meta["category"]
        network = ip_meta["network"]
        category_counts[category] += 1
        if network:
            network_counts[network] += 1
        host_entry = {
            "ip": ip,
            "is_local": is_local_ip(ip),
            "seen_in_non_conn": ip in result['non_conn_ips'],
            "total_flows": total_flows,
            "category": category,
            "network": network,
            "ip_version": ip_meta["version"],
            "protocols": counter_to_list(sections.get('protocols', Counter()), top_limit),
            "flows": counter_to_list(flows_counter, top_limit),
            "dns_queries": counter_to_list(sections.get('dns_queries', Counter()), top_limit),
            "http_hosts": counter_to_list(sections.get('http_hosts', Counter()), top_limit),
            "http_uris": counter_to_list(sections.get('http_uris', Counter()), top_limit),
            "ssl_issuers": counter_to_list(sections.get('ssl_issuers', Counter()), top_limit),
            "ssl_subjects": counter_to_list(sections.get('ssl_subjects', Counter()), top_limit),
            "snis": counter_to_list(sections.get('snis', Counter()), top_limit),
            "smb_shares": counter_to_list(sections.get('smb_shares', Counter()), top_limit),
            "smb_native_fs": counter_to_list(sections.get('smb_native_fs', Counter()), top_limit),
            "smb_share_types": counter_to_list(sections.get('smb_share_types', Counter()), top_limit),
            "dst_ports_as_src": counter_to_list(sections.get('dst_ports_as_src', Counter()), top_limit),
            "dst_ports_as_dst": counter_to_list(sections.get('dst_ports_as_dst', Counter()), top_limit),
        }
        hosts.append(host_entry)
    hosts.sort(key=lambda item: item['total_flows'], reverse=True)

    networks_sorted = sorted(network_counts.items(), key=lambda kv: kv[1], reverse=True)
    network_limit = 60
    network_options = [
        {"label": label, "count": count}
        for label, count in networks_sorted
        if label and label != "Unknown"
    ][:network_limit]

    generated_at = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
    export_data = {
        "generated_at": generated_at,
        "global": global_section,
        "hosts": hosts,
        "charts": {
            "protocols": counter_to_list(result['proto_counter'], min(8, len(result['proto_counter']))),
            "dns": counter_to_list(filter_local_counter(result['dns_query_counter'], args.local_only), 10),
            "http": counter_to_list(filter_local_counter(result['http_host_counter'], args.local_only), 10),
            "ports": top_ports,
            "port_bins": compute_port_bins(result['port_summary']),
        },
        "meta": {
            "directory": os.path.abspath(args.directory),
            "filters": {
                "require_activity": args.require_activity,
                "only_conn": args.only_conn,
                "local_only": args.local_only,
                "per_port": args.per_port,
            },
            "log_files": {log_type: len(paths) for log_type, paths in result['log_files'].items()},
        },
        "totals": {
            "hosts": len(hosts),
            "hosts_with_non_conn": sum(1 for host in hosts if host['seen_in_non_conn']),
            "unique_smb_sources": len(filter_local_set(result['smb_src_ips'], args.local_only)),
            "unique_smb_destinations": len(filter_local_set(result['smb_dst_ips'], args.local_only)),
        },
        "filter_options": {
            "categories": counter_to_list(category_counts),
            "networks": network_options,
        },
    }
    return export_data


def write_json_output(export_data: Dict[str, object], output_file: str | None = None) -> None:
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as handle:
            json.dump(export_data, handle, indent=2)
        console.print(f"[bold green]✅ JSON report written to[/bold green] {output_file}")
    else:
        json.dump(export_data, sys.stdout, indent=2)
        sys.stdout.write('\n')


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Zeek Security Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0f172a;
  --bg-card: #1e293b;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --accent: #38bdf8;
  --shadow: 0 18px 45px rgba(15, 23, 42, 0.35);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text-primary);
}
a { color: var(--accent); }
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 24px 32px 16px;
  flex-wrap: wrap;
  gap: 16px;
  background: linear-gradient(120deg, rgba(56,189,248,0.25), rgba(168,85,247,0.2));
  box-shadow: inset 0 -1px 0 rgba(148, 163, 184, 0.2);
}
.page-header h1 {
  margin: 0;
  font-size: 2rem;
  color: var(--text-primary);
}
.page-header .sub {
  margin: 4px 0 0;
  color: var(--text-secondary);
  font-size: 0.95rem;
}
.badge {
  background: rgba(59,130,246,0.2);
  color: #93c5fd;
  padding: 6px 12px;
  border-radius: 999px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-size: 0.75rem;
}
.main {
  padding: 24px 32px 48px;
  max-width: 1400px;
  margin: 0 auto;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}
.stat-card {
  background: var(--bg-card);
  border-radius: 16px;
  padding: 16px;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
}
.stat-card::after {
  content: "";
  position: absolute;
  top: -40px;
  right: -40px;
  width: 120px;
  height: 120px;
  background: radial-gradient(circle at center, rgba(59,130,246,0.45), transparent 70%);
  transform: rotate(25deg);
}
.stat-card .label {
  font-size: 0.9rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
}
.stat-card .value {
  font-size: 2rem;
  font-weight: 700;
  color: var(--text-primary);
}
.stat-card .detail {
  margin-top: 8px;
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.charts {
  margin-top: 32px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 20px;
}
.chart-card {
  position: relative;
  z-index: 1;
  background: var(--bg-card);
  border-radius: 16px;
  padding: 18px;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 240px;
  max-height: 320px;
}
.chart-card canvas {
  width: 100% !important;
  height: 210px !important;
  max-height: 210px;
  margin-top: 4px;
}
.chart-card h2 {
  margin: 0 0 12px;
  font-size: 1.1rem;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
}
.chart-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 12px;
  box-shadow: inset 0 0 0 1px rgba(148,163,184,0.25);
  color: var(--text-secondary);
  font-size: 0.9rem;
  border: 1px dashed rgba(148,163,184,0.4);
  border-radius: 12px;
  padding: 18px;
  min-height: 210px;
  pointer-events: none;
  position: absolute;
  inset: 0;
  z-index: 0;
}
.host-controls {
  margin-top: 40px;
  background: var(--bg-card);
  border-radius: 16px;
  box-shadow: var(--shadow);
  padding: 20px;
  display: grid;
  gap: 16px;
  position: relative;
  z-index: 3;
}
.host-controls .filters {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 20px;
  align-items: center;
}
.host-controls label {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.host-controls select {
  background: rgba(148,163,184,0.2);
  border: 1px solid rgba(148,163,184,0.3);
  color: var(--text-primary);
  border-radius: 10px;
  padding: 6px 10px;
  font-size: 0.85rem;
}
#hostSearch {
  width: 100%;
  padding: 12px 16px;
  background: rgba(148,163,184,0.2);
  border: 1px solid rgba(148,163,184,0.3);
  border-radius: 12px;
  color: var(--text-primary);
  font-size: 1rem;
}
#hostSearch::placeholder { color: rgba(148,163,184,0.6); }
.host-grid {
  margin-top: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 20px;
}
.host-card {
  background: var(--bg-card);
  border-radius: 18px;
  padding: 20px;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 12px;
  border: 1px solid transparent;
  transition: transform 0.2s ease, border-color 0.2s ease;
}
.host-card:hover {
  transform: translateY(-2px);
  border-color: rgba(96,165,250,0.5);
}
.host-card.local { border-color: rgba(74, 222, 128, 0.45); }
.host-card .host-title {
  font-size: 1.2rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
}
.host-card .metrics {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.section { margin-top: 6px; }
.section h4 {
  margin: 0 0 6px;
  font-size: 0.9rem;
  color: var(--accent);
  display: flex;
  gap: 8px;
  align-items: center;
}
.tag-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.tag {
  background: rgba(148,163,184,0.15);
  color: var(--text-primary);
  border-radius: 999px;
  padding: 6px 10px;
  font-size: 0.82rem;
  display: inline-flex;
  gap: 6px;
  align-items: center;
}
.tag strong { color: #fbbf24; }
.badge-pill {
  padding: 4px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  background: rgba(59,130,246,0.25);
  color: #93c5fd;
}
footer {
  margin-top: 40px;
  color: var(--text-secondary);
  font-size: 0.8rem;
  text-align: center;
}
.empty { color: rgba(148,163,184,0.6); font-style: italic; }
@media (max-width: 768px) {
  .page-header { padding: 20px; }
  .main { padding: 20px; }
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<header class="page-header">
  <div>
    <h1>🛡️ Zeek Security Dashboard</h1>
    <p class="sub">Directory: <span id="directoryPath"></span></p>
    <p class="sub">Generated: <span id="generatedAt"></span></p>
  </div>
  <div class="badge">Security Overview</div>
</header>
<main class="main">
  <section class="stats-grid">
    <div class="stat-card" data-stat="uniqueSrcIps">
      <div class="label">Unique Src IPs</div>
      <div class="value">0</div>
      <div class="detail"></div>
    </div>
    <div class="stat-card" data-stat="uniqueDstIps">
      <div class="label">Unique Dst IPs</div>
      <div class="value">0</div>
      <div class="detail"></div>
    </div>
    <div class="stat-card" data-stat="totalProtocols">
      <div class="label">Protocols Observed</div>
      <div class="value">0</div>
      <div class="detail"></div>
    </div>
    <div class="stat-card" data-stat="topProtocol">
      <div class="label">Top Protocol</div>
      <div class="value">-</div>
      <div class="detail"></div>
    </div>
    <div class="stat-card" data-stat="topDns">
      <div class="label">Top DNS Query</div>
      <div class="value">-</div>
      <div class="detail"></div>
    </div>
    <div class="stat-card" data-stat="topHttp">
      <div class="label">Top HTTP Host</div>
      <div class="value">-</div>
      <div class="detail"></div>
    </div>
  </section>

  <section class="charts">
    <div class="chart-card">
      <h2>🛰️ Protocol Distribution</h2>
      <canvas id="protocolChart"></canvas>
      <div class="chart-placeholder" data-placeholder="protocolChart" hidden>No protocol data available.</div>
    </div>
    <div class="chart-card">
      <h2>🧠 Top DNS Queries</h2>
      <canvas id="dnsChart"></canvas>
      <div class="chart-placeholder" data-placeholder="dnsChart" hidden>No DNS data available.</div>
    </div>
    <div class="chart-card">
      <h2>🎯 Targeted Ports</h2>
      <canvas id="portChart"></canvas>
      <div class="chart-placeholder" data-placeholder="portChart" hidden>No port activity recorded.</div>
    </div>
  </section>

  <section class="host-controls">
    <div>
      <label for="hostSearch">🔍 Search hosts, domains, ports, or certificates</label>
      <input id="hostSearch" type="search" placeholder="Type to filter hosts, ports, domains…">
    </div>
    <div class="filters">
      <label><input type="checkbox" id="filterLocal"> Local only</label>
      <label><input type="checkbox" id="filterNonConn"> Require non-conn activity</label>
      <label>Min flows <input type="number" id="filterFlows" min="0" value="0" style="width:80px;"></label>
      <label>Category
        <select id="filterCategory">
          <option value="all">All categories</option>
        </select>
      </label>
      <label>Network
        <select id="filterNetwork">
          <option value="all">All networks</option>
        </select>
      </label>
      <span class="badge-pill">Showing <span id="hostCount">0</span> hosts</span>
    </div>
  </section>

  <section id="hostContainer" class="host-grid"></section>
</main>
<footer>
  Built with ❤️ for security analysts. Use the filters above to spotlight suspicious activity quickly.
</footer>
<script>
const DASHBOARD_DATA = __DATA_PLACEHOLDER__;

const palette = ["#3B82F6","#10B981","#F97316","#F43F5E","#8B5CF6","#0EA5E9","#F59E0B","#22D3EE","#6366F1","#14B8A6","#EC4899","#94A3B8"];

const stats = {
  uniqueSrcIps: DASHBOARD_DATA.global.unique_src_ips || 0,
  uniqueDstIps: DASHBOARD_DATA.global.unique_dst_ips || 0,
  totalProtocols: DASHBOARD_DATA.global.total_protocols || 0,
  topProtocol: (DASHBOARD_DATA.global.top_protocols || [])[0] || null,
  topDns: (DASHBOARD_DATA.global.top_dns_queries || [])[0] || null,
  topHttp: (DASHBOARD_DATA.global.top_http_hosts || [])[0] || null
};

function setStatCard(key, value, detail) {
  const card = document.querySelector(`.stat-card[data-stat="${key}"]`);
  if (!card) return;
  const valueEl = card.querySelector('.value');
  const detailEl = card.querySelector('.detail');
  if (valueEl) {
    valueEl.textContent = typeof value === 'number' ? value.toLocaleString() : (value || '-');
  }
  if (detailEl) {
    detailEl.textContent = detail || '';
  }
}

setStatCard('uniqueSrcIps', stats.uniqueSrcIps, `${DASHBOARD_DATA.totals.hosts_with_non_conn || 0} hosts with non-conn logs`);
setStatCard('uniqueDstIps', stats.uniqueDstIps, `${DASHBOARD_DATA.global.unique_smb_dst_ips || 0} SMB destinations`);
setStatCard('totalProtocols', stats.totalProtocols, `Top: ${stats.topProtocol ? stats.topProtocol.label : 'n/a'}`);
setStatCard('topProtocol', stats.topProtocol ? stats.topProtocol.label : '-', stats.topProtocol ? `${stats.topProtocol.count} flows` : '');
setStatCard('topDns', stats.topDns ? stats.topDns.label : '-', stats.topDns ? `${stats.topDns.count} requests` : '');
setStatCard('topHttp', stats.topHttp ? stats.topHttp.label : '-', stats.topHttp ? `${stats.topHttp.count} hits` : '');

document.getElementById('directoryPath').textContent = DASHBOARD_DATA.meta.directory;
document.getElementById('generatedAt').textContent = DASHBOARD_DATA.generated_at;

function useChart(canvasId, type, items, options = {}) {
  const canvas = document.getElementById(canvasId);
  const placeholder = document.querySelector(`.chart-placeholder[data-placeholder="${canvasId}"]`);
  if (!canvas || !items || !items.length) {
    if (canvas) {
      canvas.hidden = true;
    }
    if (placeholder) {
      placeholder.hidden = false;
    }
    return null;
  }
  if (placeholder) {
    placeholder.hidden = true;
  }
  canvas.hidden = false;
  canvas.height = 210;
  const ctx = canvas.getContext('2d');
  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "#e2e8f0" } },
      tooltip: {
        callbacks: {
          label(context) {
            const item = items[context.dataIndex];
            if (item && item.total && (item.as_dst !== undefined || item.as_target !== undefined)) {
              return [
                `Total: ${item.total.toLocaleString()}`,
                `From hosts: ${(item.as_dst || 0).toLocaleString()}`,
                `Targeted: ${(item.as_target || 0).toLocaleString()}`
              ];
            }
            const value = context.parsed;
            return `${context.label}: ${value.toLocaleString()}`;
          }
        }
      }
    }
  };
  if (type === 'bar') {
    baseOptions.scales = {
      x: {
        ticks: {
          color: "#cbd5f5",
          callback: function(value, index) {
            const labels = this.chart?.data?.labels || [];
            const label = labels[index] || value;
            return label.length > 18 ? label.slice(0, 16) + "…" : label;
          }
        },
        grid: { color: "rgba(148,163,184,0.15)" }
      },
      y: {
        ticks: { color: "#cbd5f5" },
        grid: { color: "rgba(148,163,184,0.1)" }
      }
    };
  }
  const finalOptions = Object.assign({}, baseOptions, options);
  return new Chart(ctx, {
    type,
    data: {
      labels: items.map(item => item.label),
      datasets: [{
        data: items.map(item => (item.count ?? item.total ?? 0)),
        backgroundColor: items.map((_, idx) => palette[idx % palette.length]),
        borderWidth: 1,
        borderColor: "rgba(15,23,42,0.4)",
        hoverOffset: 6
      }]
    },
    options: finalOptions
  });
}

useChart('protocolChart', 'doughnut', (DASHBOARD_DATA.charts.protocols || []).slice(0, 8));
useChart('dnsChart', 'bar', (DASHBOARD_DATA.charts.dns || []).slice(0, 8), { indexAxis: 'y' });
useChart('portChart', 'bar', (DASHBOARD_DATA.charts.ports || []).slice(0, 10), { indexAxis: 'y' });

const hostContainer = document.getElementById('hostContainer');
const hostSearch = document.getElementById('hostSearch');
const filterLocal = document.getElementById('filterLocal');
const filterNonConn = document.getElementById('filterNonConn');
const filterFlows = document.getElementById('filterFlows');
const filterCategory = document.getElementById('filterCategory');
const filterNetwork = document.getElementById('filterNetwork');
const hostCount = document.getElementById('hostCount');
const hostCards = [];

const filterOptions = DASHBOARD_DATA.filter_options || {};
if (filterCategory) {
  const categories = filterOptions.categories || [];
  categories.forEach(item => {
    const option = document.createElement('option');
    option.value = item.label;
    option.textContent = `${item.label} (${item.count})`;
    filterCategory.appendChild(option);
  });
}
if (filterNetwork) {
  const networks = filterOptions.networks || [];
  networks.forEach(item => {
    const option = document.createElement('option');
    option.value = item.label;
    option.textContent = `${item.label} (${item.count})`;
    filterNetwork.appendChild(option);
  });
}

const placeholderCandidates = [];
const hostList = DASHBOARD_DATA.hosts || [];
if (hostList.length) {
  placeholderCandidates.push(hostList[0].ip);
  const firstHostHttp = (hostList[0].http_hosts || [])[0];
  if (firstHostHttp) placeholderCandidates.push(firstHostHttp.label);
  const firstHostDns = (hostList[0].dns_queries || [])[0];
  if (firstHostDns) placeholderCandidates.push(firstHostDns.label);
  const firstHostPort = (hostList[0].dst_ports_as_src || [])[0];
  if (firstHostPort) placeholderCandidates.push(firstHostPort.label);
}
const topDnsGlobal = (DASHBOARD_DATA.global.top_dns_queries || [])[0];
if (topDnsGlobal) placeholderCandidates.push(topDnsGlobal.label);
const topHttpGlobal = (DASHBOARD_DATA.global.top_http_hosts || [])[0];
if (topHttpGlobal) placeholderCandidates.push(topHttpGlobal.label);
const topPortChart = (DASHBOARD_DATA.charts.ports || [])[0];
if (topPortChart) placeholderCandidates.push(topPortChart.label);
const placeholderUnique = Array.from(new Set(placeholderCandidates.filter(Boolean)));
if (hostSearch && placeholderUnique.length) {
  const snippet = placeholderUnique.slice(0, 3).join(', ');
  hostSearch.placeholder = `Type to filter (e.g. ${snippet})`;
}

function escapeHtml(value) {
  return (value ?? '').toString().replace(/[&<>"']/g, match => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[match]);
}

function renderTags(items) {
  if (!items || !items.length) {
    return '<span class="empty">No data</span>';
  }
  return items.map(item => `<span class="tag">${escapeHtml(item.label)} <strong>${(item.count ?? item.total ?? 0).toLocaleString()}</strong></span>`).join('');
}

function createHostCard(host) {
  const card = document.createElement('article');
  card.className = 'host-card' + (host.is_local ? ' local' : '');
  card.dataset.ip = host.ip;
  card.dataset.isLocal = host.is_local ? 'true' : 'false';
  card.dataset.nonConn = host.seen_in_non_conn ? 'true' : 'false';
  card.dataset.totalFlows = host.total_flows || 0;
  card.dataset.category = host.category || 'Unknown';
  card.dataset.network = host.network || 'Unknown';
  const searchBits = new Set();
  searchBits.add(host.ip);
  if (host.category) searchBits.add(host.category);
  if (host.network) searchBits.add(host.network);
  (host.dns_queries || []).forEach(item => searchBits.add(item.label));
  (host.http_hosts || []).forEach(item => searchBits.add(item.label));
  (host.http_uris || []).forEach(item => searchBits.add(item.label));
  (host.dst_ports_as_src || []).forEach(item => searchBits.add(item.label));
  (host.dst_ports_as_dst || []).forEach(item => searchBits.add(item.label));
  card.dataset.search = Array.from(searchBits).join(' ').toLowerCase();

  const badges = [];
  badges.push(host.is_local
    ? '<span class="badge-pill">Local</span>'
    : '<span class="badge-pill" style="background:rgba(248,113,113,0.2);color:#fca5a5;">External</span>');
  if (host.seen_in_non_conn) {
    badges.push('<span class="badge-pill" style="background:rgba(34,197,94,0.2);color:#bbf7d0;">Non-conn activity</span>');
  }

  card.innerHTML = `
    <div class="host-title">🔹 ${escapeHtml(host.ip)}</div>
    <div class="metrics">
      <span>Flows: <strong>${(host.total_flows || 0).toLocaleString()}</strong></span>
      <span>Protocols: ${escapeHtml((host.protocols || []).map(item => item.label).join(', ') || 'n/a')}</span>
      <span>Category: <strong>${escapeHtml(host.category || 'Unknown')}</strong></span>
      <span>Network: <strong>${escapeHtml(host.network || 'Unknown')}</strong></span>
      ${badges.join(' ')}
    </div>
    <div class="section">
      <h4>🧭 Flows</h4>
      <div class="tag-list">${renderTags(host.flows)}</div>
    </div>
    <div class="section">
      <h4>📡 DNS</h4>
      <div class="tag-list">${renderTags(host.dns_queries)}</div>
    </div>
    <div class="section">
      <h4>🌐 HTTP Hosts</h4>
      <div class="tag-list">${renderTags(host.http_hosts)}</div>
    </div>
    <div class="section">
      <h4>📄 HTTP URIs</h4>
      <div class="tag-list">${renderTags(host.http_uris)}</div>
    </div>
    <div class="section">
      <h4>🔐 SSL</h4>
      <div class="tag-list">${renderTags(host.ssl_issuers)}</div>
    </div>
    <div class="section">
      <h4>📛 SSL SNI</h4>
      <div class="tag-list">${renderTags(host.snis)}</div>
    </div>
    <div class="section">
      <h4>🗄️ SMB Shares</h4>
      <div class="tag-list">${renderTags(host.smb_shares)}</div>
    </div>
    <div class="section">
      <h4>🎯 Ports Used (as source)</h4>
      <div class="tag-list">${renderTags(host.dst_ports_as_src)}</div>
    </div>
    <div class="section">
      <h4>🛡️ Ports Targeted (as destination)</h4>
      <div class="tag-list">${renderTags(host.dst_ports_as_dst)}</div>
    </div>
  `;
  return card;
}

(DASHBOARD_DATA.hosts || []).forEach(host => {
  const card = createHostCard(host);
  hostCards.push(card);
  hostContainer.appendChild(card);
});
hostCount.textContent = hostCards.length.toString();

if (DASHBOARD_DATA.meta.filters.local_only) {
  filterLocal.checked = true;
}
if (DASHBOARD_DATA.meta.filters.require_activity) {
  filterNonConn.checked = true;
}

function applyFilters() {
  const term = hostSearch ? hostSearch.value.trim().toLowerCase() : '';
  const requireLocal = filterLocal && filterLocal.checked;
  const requireNonConn = filterNonConn && filterNonConn.checked;
  const minFlows = filterFlows ? (parseInt(filterFlows.value, 10) || 0) : 0;
  const categoryValue = filterCategory ? filterCategory.value : 'all';
  const networkValue = filterNetwork ? filterNetwork.value : 'all';
  let visible = 0;
  hostCards.forEach(card => {
    const matchesSearch = !term || card.dataset.search.includes(term);
    const matchesLocal = !requireLocal || card.dataset.isLocal === 'true';
    const matchesNonConn = !requireNonConn || card.dataset.nonConn === 'true';
    const matchesFlows = Number(card.dataset.totalFlows) >= minFlows;
    const matchesCategory = categoryValue === 'all' || card.dataset.category === categoryValue;
    const matchesNetwork = networkValue === 'all' || card.dataset.network === networkValue;
    const show = matchesSearch && matchesLocal && matchesNonConn && matchesFlows && matchesCategory && matchesNetwork;
    card.style.display = show ? '' : 'none';
    if (show) visible += 1;
  });
  hostCount.textContent = visible.toString();
}

if (hostSearch) hostSearch.addEventListener('input', applyFilters);
if (filterLocal) filterLocal.addEventListener('change', applyFilters);
if (filterNonConn) filterNonConn.addEventListener('change', applyFilters);
if (filterFlows) filterFlows.addEventListener('input', applyFilters);
if (filterCategory) filterCategory.addEventListener('change', applyFilters);
if (filterNetwork) filterNetwork.addEventListener('change', applyFilters);

applyFilters();
</script>
</body>
</html>
"""


def write_html_output(export_data: Dict[str, object], output_file: str | None = None) -> None:
    target = output_file or "zeek-dashboard.html"
    data_json = json.dumps(export_data).replace('</', '<\\/')
    html_content = HTML_TEMPLATE.replace('__DATA_PLACEHOLDER__', data_json)
    with open(target, 'w', encoding='utf-8') as handle:
        handle.write(html_content)
    console.print(f"[bold green]✅ HTML dashboard written to[/bold green] {target}")


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not os.path.isdir(args.directory):
        parser.error(f"Directory not found: {args.directory}")

    result = aggregate_logs(args.directory)

    if args.output_format == 'text':
        if args.output_file:
            console.print("[bold yellow]⚠ --output-file is ignored for text output.[/bold yellow]")
        render_text_report(result, args)
        return

    export_data = build_export_data(result, args)
    if args.output_format == 'json':
        write_json_output(export_data, args.output_file)
    elif args.output_format == 'html':
        write_html_output(export_data, args.output_file)


if __name__ == '__main__':
    main()
