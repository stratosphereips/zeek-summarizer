import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace


rich_module = types.ModuleType("rich")
rich_console_module = types.ModuleType("rich.console")


class Console:
    def print(self, *args, **kwargs):
        pass


rich_console_module.Console = Console
sys.modules.setdefault("rich", rich_module)
sys.modules.setdefault("rich.console", rich_console_module)

tabulate_module = types.ModuleType("tabulate")
tabulate_module.tabulate = lambda *args, **kwargs: ""
sys.modules.setdefault("tabulate", tabulate_module)

MODULE_PATH = Path(__file__).resolve().parents[1] / "zeek-summarizer.py"
SPEC = importlib.util.spec_from_file_location("zeek_summarizer", MODULE_PATH)
zeek_summarizer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(zeek_summarizer)


class AggregateLogsTest(unittest.TestCase):
    def test_dns_entries_are_not_counted_as_smtp(self):
        with tempfile.TemporaryDirectory() as directory:
            dns_log = Path(directory) / "dns.log"
            dns_log.write_text(
                "#fields\tid.orig_h\tid.resp_h\tquery\n"
                "10.0.0.1\t8.8.8.8\texample.com\n",
                encoding="utf-8",
            )

            result = zeek_summarizer.aggregate_logs(directory)
            client_flows = result["ip_profiles"]["10.0.0.1"]["flows"]
            server_flows = result["ip_profiles"]["8.8.8.8"]["flows"]

            self.assertEqual(client_flows["dns_client"], 1)
            self.assertEqual(server_flows["dns_server"], 1)
            self.assertEqual(client_flows["smtp_client"], 0)
            self.assertEqual(server_flows["smtp_server"], 0)

            rows = zeek_summarizer.build_global_summary_rows(
                result,
                SimpleNamespace(local_only=False),
            )
            labels = {row[0] for row in rows}

            self.assertIn("Top DNS Queries", labels)
            self.assertNotIn("Top SSL Issuers", labels)
            self.assertNotIn("Unique SMB Src IPs", labels)
            self.assertNotIn("Unique SMB Dst IPs", labels)
            self.assertNotIn("Top SMTP Senders", labels)
            self.assertNotIn("SMTP TLS Usage", labels)

    def test_conn_metrics_track_host_direction_peers_and_time(self):
        with tempfile.TemporaryDirectory() as directory:
            conn_log = Path(directory) / "conn.log"
            conn_log.write_text(
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\t"
                "duration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\t"
                "history\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
                "10\tC1\t10.0.0.1\t50000\t8.8.8.8\t80\ttcp\thttp\t2.5\t1000\t200\tSF\t-\t-\t0\tShADadfF\t10\t1500\t5\t500\t-\n"
                "20\tC2\t1.1.1.1\t50001\t10.0.0.1\t4444\ttcp\t-\t5\t300\t400\tRSTR\t-\t-\t0\tShR\t3\t500\t4\t600\t-\n"
                "30\tC3\t10.0.0.1\t0\t8.8.8.8\t0\ticmp\t-\t-\t0\t0\tOTH\t-\t-\t0\t-\t1\t60\t0\t0\t-\n",
                encoding="utf-8",
            )

            result = zeek_summarizer.aggregate_logs(directory)
            profile = result["ip_profiles"]["10.0.0.1"]

            self.assertEqual(zeek_summarizer.connection_count(profile), 3)
            self.assertEqual(profile["flows"]["as source"], 2)
            self.assertEqual(profile["flows"]["destination"], 1)
            self.assertEqual(profile["traffic"]["sent_bytes"], 1400)
            self.assertEqual(profile["traffic"]["received_bytes"], 500)
            self.assertEqual(profile["traffic"]["sent_packets"], 15)
            self.assertEqual(profile["traffic"]["received_packets"], 8)
            self.assertEqual(zeek_summarizer.activity_span_seconds(profile), 20.0)
            self.assertNotIn("0", profile["dst_ports_as_src"])

            peers = zeek_summarizer.peer_summaries(profile)
            self.assertEqual(peers[0], {
                "ip": "8.8.8.8",
                "connections": 2,
                "sent_bytes": 1000,
                "received_bytes": 200,
                "total_bytes": 1200,
            })
            self.assertEqual(peers[1]["ip"], "1.1.1.1")

            outcomes = zeek_summarizer.connection_outcomes(profile["connection_states"])
            self.assertEqual(outcomes["normal"], 1)
            self.assertEqual(outcomes["reset"], 1)
            self.assertEqual(outcomes["other"], 1)

            args = SimpleNamespace(
                directory=directory,
                local_only=False,
                require_activity=False,
                only_conn=False,
                per_port=False,
            )
            export = zeek_summarizer.build_export_data(result, args)
            host = next(item for item in export["hosts"] if item["ip"] == "10.0.0.1")
            self.assertEqual(host["connection_count"], 3)
            self.assertEqual(host["peer_count"], 2)
            self.assertEqual(host["traffic"]["sent_bytes"], 1400)
            self.assertEqual(host["top_peers"][0]["ip"], "8.8.8.8")

            rendered = []
            original_console = zeek_summarizer.console
            zeek_summarizer.console = SimpleNamespace(
                print=lambda *values, **kwargs: rendered.append(' '.join(map(str, values)))
            )
            try:
                zeek_summarizer.render_text_report(result, args)
            finally:
                zeek_summarizer.console = original_console

            report = '\n'.join(rendered)
            self.assertIn("Connections: 3 · Peers: 2 · Span: 20s", report)
            self.assertIn("Traffic: sent 1.4 KiB (15 pkts) · received 500 B (8 pkts)", report)
            self.assertIn("Peers (sent/received): 8.8.8.8", report)
            self.assertNotIn("Total flows", report)


if __name__ == "__main__":
    unittest.main()
