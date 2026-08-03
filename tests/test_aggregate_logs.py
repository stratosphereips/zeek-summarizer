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


if __name__ == "__main__":
    unittest.main()
