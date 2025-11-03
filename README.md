# Zeek Summarizer

`zeek-summarizer` digests a full Zeek log directory (plain TSV or JSON, compressed or not) and produces:

- Global statistics for connections, DNS, HTTP, TLS/SSL, SMB, and SMTP activity.
- Rich per-host drill downs (protocol mix, ports, DNS/HTTP targets, TLS issuers, SMB shares, SMTP senders/recipients, etc.).
- Optional per-port view to see which services are most active or targeted.
- Export to JSON or a self-contained HTML dashboard with interactive charts, search, and filters.

## Web Dashboard
<img width="1366" height="697" alt="image" src="https://github.com/user-attachments/assets/df3537b6-e180-49cf-9716-eb149da4c816" />

## Text output
<img width="1105" height="475" alt="image" src="https://github.com/user-attachments/assets/ac36cd3b-b174-44d2-ba6b-422d9bf2d65c" />


---

## 1. Requirements

- Python 3.10+ (tested with 3.11/3.12/3.13)
- Zeek logs on disk (e.g. `conn.log`, `dns.log`, `http.log`, `ssl.log`, `smtp.log`)
- Packages listed in `requirements.txt`

---

## 2. Installation

```bash
# Clone the repository
git clone https://github.com/stratosphereips/zeek-summarizer.git
cd zeek-summarizer

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

To leave the environment later, run `deactivate`.

---

## 3. Quick Start (text summary)

```bash
./zeek-summarizer.sh -d /path/to/zeek/logs
# or python venv/bin/python zeek-summarizer.py -d /path/to/zeek/logs
```

Useful CLI flags:

| Flag | Description |
| --- | --- |
| `-d DIR` | Directory containing Zeek logs (supports rotated `*.log*` and `*.log.gz`). |
| `-r`, `--require-activity` | Only list hosts that appear in non-`conn` logs. |
| `-o`, `--only-conn` | Only list hosts that have `conn` activity and nothing else. |
| `-p`, `--per-port` | Switch to per-port aggregated view. |
| `--local-only` | Keep statistics for private/local IPs only (v4/v6). |
| `--output-format {text,json,html}` | Choose output renderer (default `text`). |
| `--output-file PATH` | Write JSON/HTML to file instead of STDOUT (ignored for `text`). |

The helper script `zeek-summarizer.sh` simply activates the bundled `venv/` and forwards every argument to the Python entry point (`"$@"`).

---

## 4. Generate the interactive dashboard

```bash
./zeek-summarizer.sh -d /path/to/zeek/logs \
  --output-format html \
  --output-file zeek-dashboard.html

# Open the report locally (macOS example)
open zeek-dashboard.html
```

The HTML uses embedded data: no web server or backend required. Charts cover protocol mix, top DNS/HTTP targets, port targeting, SMTP TLS usage, and SMTP error codes. The search bar and filters let you jump straight to local hosts, specific /24 or /64 networks, or hosts that triggered non-connection logs.

---

## 5. Export machine-readable JSON

```bash
./zeek-summarizer.sh -d /path/to/zeek/logs \
  --output-format json \
  --output-file zeek-summary.json
```

Each host entry includes counters for protocols, flows, DNS queries, HTTP hosts, TLS issuers/subjects, SMB shares, SMTP metadata, and port usage. The `global` section mirrors the top cards in the dashboard.

---

## 6. Example workflows

```bash
# Baseline summary (text)
./zeek-summarizer.sh -d ./sample-logs

# Focus on local assets that touched non-connection logs
./zeek-summarizer.sh -d ./sample-logs -r --local-only

# Investigate service exposure (per-port view)
./zeek-summarizer.sh -d ./sample-logs -p

# Produce HTML and JSON in one go
./zeek-summarizer.sh -d ./sample-logs --output-format html --output-file report.html
./zeek-summarizer.sh -d ./sample-logs --output-format json --output-file report.json
```

---

## 7. Supported log families

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`
- `smb_mapping.log`
- `smtp.log`

The parser accepts TSV (default Zeek format) and JSON, with optional `.gz` compression and rotated filenames such as `dns.2024-10-05-00-00-00.log.gz`.

---

Made with ❤️ for network defenders who want fast situational awareness from Zeek captures.
