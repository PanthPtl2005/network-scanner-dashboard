# NetScan Dashboard

A full-stack **network scanner dashboard** built with Python/Flask, nmap, masscan, SQLite, and vanilla JavaScript.

## Features
- **Two-stage scanning**: masscan (fast SYN discovery) → nmap (service/OS detection)
- **Real-time progress**: live polling with animated step indicators
- **Risk scoring**: High/Medium/Low per host & port (RDP, SMB, Telnet = High)
- **CVE lookup**: queries NVD API for matching CVEs per service
- **Charts**: port frequency bar chart + service distribution doughnut (Chart.js)
- **Export**: JSON & CSV download per scan
- **Scan history**: full CRUD with load/delete
- **Dark/light mode**: persists via localStorage
- **Demo mode**: inject sample data without nmap installed

## Quickstart

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install system tools (macOS)
brew install nmap masscan

# 3. Run the server
python run.py
# → http://localhost:5000
```

## Usage

1. Enter a subnet (`192.168.1.0/24`) and choose scan depth
2. Click **Start Scan** — masscan discovers live IPs, nmap does deep scan
3. Watch real-time progress bar; results render automatically
4. Click **Ports** on any row to see the port detail panel
5. Click **Lookup CVEs** to query NVD for the host's services
6. Download results as JSON or CSV

## Notes

- masscan requires `sudo` on most systems — run Flask with `sudo python run.py` or grant raw socket access
- nmap OS detection (`-O`) requires root; set `os_detect=False` in `scanner.py` if running unprivileged
- SQLite DB is stored at `scans/netscan.db`
- All nmap XML outputs are stored in `scans/`
