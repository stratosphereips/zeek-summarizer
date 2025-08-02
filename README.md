# Zeek Summarizer

**Zeek Summarizer** is a command-line tool to analyze and summarize Zeek log files. It supports connection logs, DNS, HTTP, and SSL/TLS logs and provides global statistics as well as detailed per-IP or per-port summaries.

## 🔧 Installation

```bash
git clone https://github.com/stratosphereips/zeek-summarizing.git
cd zeek-summarizer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📦 Requirements

See `requirements.txt`.

## 🚀 Usage

```bash
python zeek-summarizer.py -d <zeek_log_directory> [options]
```

### Options:

- `-d, --directory` (**required**): Path to the directory containing Zeek logs.
- `-r, --require-activity`: Show only IPs that appear in non-conn logs.
- `-o, --only-conn`: Show only IPs that appear only in conn logs.
- `-p, --per-port`: Show summary per port instead of per IP.
- `--debug`: Show debug information for internal operations.

## Screenshots

![image](https://github.com/user-attachments/assets/b2564745-bb3e-4780-9064-f9606f8c532a)

![image](https://github.com/user-attachments/assets/400b673f-6e95-4c61-994b-6a56f1d30619)


## 📊 Examples

### Basic usage

```bash
python zeek-summarizer.py -d ./logs
```

### Only show IPs that have non-connection activity:

```bash
python zeek-summarizer.py -d ./logs -r
```

### Show per-port summary:

```bash
python zeek-summarizer.py -d ./logs -p
```

### Show only connection logs and debug info:

```bash
python zeek-summarizer.py -d ./logs -o --debug
```

## 📁 Supported Logs

- `conn.log`
- `dns.log`
- `http.log`
- `ssl.log`

Logs may be compressed with `.gz` and can use rotated filenames like `conn.01:00:00-02:00:00.log.gz`.

---

Created with ❤️ for Zeek network traffic analysis.
