#!/usr/bin/env python3
"""
VPN Detection Database Builder
Downloads free IP blocklists and builds a single SQLite database
for offline VPN / proxy detection in WordPress plugins.

Sources used (all free, no API key required):
  - X4BNet          : Commercial VPN provider IP ranges
  - Tor Project     : Official Tor exit node list
  - client9/ipcat   : Datacenter / hosting IP ranges (CSV)
  - Stamparm        : Known open proxies (level 3 = high confidence)
  - StopForumSpam   : Known forum/blog spammer IPs (30-day list, zipped)
  - AbuseIPDB       : 100% confidence abuse score IPs, 30-day (borestad mirror, no key)
  - brianhama       : Bad ASN list (ASN-level blocklist)
  - FFraud-com      : High-abuse networks ASN list
"""

import ipaddress
import sqlite3
import urllib.request
import csv
import io
import zipfile
import os
import sys
import logging
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DB_PATH = "vpn_detection.db"

# Read the built-in GitHub Actions token from environment.
# Automatically available in every workflow via ${{ secrets.GITHUB_TOKEN }}.
# Raises rate limits for raw.githubusercontent.com significantly.
# Falls back to empty string when running locally — unauthenticated still works,
# just at the lower public rate limit.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Multiple ASN blocklist sources
ASN_SOURCES = [
    {
        "name": "bad_asn_list",
        "url": "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv",
    },
    {
        "name": "ffraud_high_abuse_asn",
        "url": "https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/refs/heads/main/asn-reputation/high-abuse-networks.csv",
    },
]

SOURCES = [
    {
        "name":   "x4bnet_vpn",
        "url":    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
        "type":   "vpn",
        "format": "cidr",
    },
    {
        "name":   "tor_exits",
        "url":    "https://check.torproject.org/torbulkexitlist",
        "type":   "tor",
        "format": "ip",
    },
    {
        "name":   "ipcat_datacenter",
        "url":    "https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv",
        "type":   "datacenter",
        "format": "ipcat_csv",   # ip_start,ip_end,name,url  (dot notation, not CIDR)
    },
    {
        "name":   "ipsum_proxy",
        "url":    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type":   "proxy",
        "format": "ip",
    },
    {
        "name":   "stopforumspam",
        "url":    "https://www.stopforumspam.com/downloads/listed_ip_30.zip",
        "type":   "spam",
        "format": "sfs_zip",   # ZIP containing a plain-text file of IPs, one per line
    },
    {
        "name":   "abuseipdb",
        "url":    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4",
        "type":   "abuse",
        "format": "ip",        # plain text, one IP per line — no API key required
    },
]


# ── Parsing helpers ────────────────────────────────────────────────────────────

def cidr_to_range(cidr: str):
    """Convert a CIDR string to an (ip_start_int, ip_end_int) tuple, or None."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
        if net.version != 4:
            return None
        return int(net.network_address), int(net.broadcast_address)
    except ValueError:
        return None


def ip_to_range(ip: str):
    """Convert a single IPv4 string to an (ip_start_int, ip_end_int) tuple, or None."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        if addr.version != 4:
            return None
        n = int(addr)
        return n, n
    except ValueError:
        return None


def parse_lines(content: str, fmt: str):
    """Yield (ip_start, ip_end) integer pairs from raw text content."""

    # sfs_zip: already extracted to plain text by download_zip() — treat as plain IPs
    if fmt == "sfs_zip":
        fmt = "ip"

    # client9/ipcat format: ip_start,ip_end,name,url  (dot notation, no CIDR)
    if fmt == "ipcat_csv":
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            try:
                start = int(ipaddress.ip_address(parts[0].strip()))
                end   = int(ipaddress.ip_address(parts[1].strip()))
                if start <= end:
                    yield start, end
            except ValueError:
                continue
        return
    for raw_line in content.splitlines():
        line = raw_line.strip()

        # Skip blanks and comments
        if not line or line.startswith("#") or line.startswith(";") or line.startswith("//"):
            continue

        # Strip inline comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        if "/" in line:
            result = cidr_to_range(line)
        elif fmt == "cidr":
            result = ip_to_range(line)   # CIDR list with a bare IP (treat as /32)
        else:
            result = ip_to_range(line)

        if result:
            yield result


# ── Download ───────────────────────────────────────────────────────────────────

def _make_headers(url: str) -> dict:
    """Build request headers, adding GitHub auth for raw.githubusercontent.com URLs."""
    headers = {"User-Agent": "vpn-detection-db-builder/1.0 (github.com)"}
    if "githubusercontent.com" in url and GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def download(url: str) -> str:
    req = urllib.request.Request(url, headers=_make_headers(url))
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def download_zip(url: str) -> str:
    """Download a .zip file and return the text content of the first file inside it."""
    req = urllib.request.Request(url, headers=_make_headers(url))
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw_bytes = resp.read()

    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
        # StopForumSpam zip contains exactly one text file — grab the first entry
        first_name = zf.namelist()[0]
        with zf.open(first_name) as f:
            return f.read().decode("utf-8", errors="ignore")


# ── Main build ─────────────────────────────────────────────────────────────────

def build_database():
    log.info("Starting database build …")

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    cur.executescript("""
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA page_size    = 4096;

        CREATE TABLE ip_ranges (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_start   INTEGER NOT NULL,
            ip_end     INTEGER NOT NULL,
            type       TEXT    NOT NULL,   -- 'vpn' | 'tor' | 'datacenter' | 'proxy' | 'spam' | 'abuse'
            source     TEXT    NOT NULL    -- source identifier
        );

        -- ASN-level blocklists
        CREATE TABLE asn_blocklist (
            asn       TEXT PRIMARY KEY,   -- e.g. 'AS9009'
            org       TEXT,               -- e.g. 'M247 Ltd'
            type      TEXT,               -- 'vpn' | 'datacenter' | 'proxy' | 'bad'
            country   TEXT
        );

        CREATE TABLE meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    grand_total = 0
    failed      = []

    for source in SOURCES:
        log.info(f"  Processing source: {source['name']} …")
        try:
            # StopForumSpam delivers a .zip — use the zip-aware downloader
            if source["format"] == "sfs_zip":
                content = download_zip(source["url"])
            else:
                content = download(source["url"])
            rows    = [
                (ip_start, ip_end, source["type"], source["name"])
                for ip_start, ip_end in parse_lines(content, source["format"])
            ]
            cur.executemany(
                "INSERT INTO ip_ranges (ip_start, ip_end, type, source) VALUES (?, ?, ?, ?)",
                rows,
            )
            conn.commit()
            log.info(f"    → {len(rows):>7,} ranges inserted")
            grand_total += len(rows)
        except Exception as exc:
            log.error(f"    ✗ Failed: {exc}")
            failed.append(source["name"])

    # Build indexes AFTER bulk insert — dramatically faster
    log.info("Building indexes …")
    cur.executescript("""
        CREATE INDEX idx_start ON ip_ranges (ip_start);
        CREATE INDEX idx_end   ON ip_ranges (ip_end);
    """)

# ── ASN blocklists ──────────────────────────────────────────────────────────
    asn_count = 0
    all_asn_rows = []

    for asn_source in ASN_SOURCES:
        log.info(f"Processing source: {asn_source['name']} …")
        try:
            content = download(asn_source["url"])
            f_io = io.StringIO(content.strip())
            
            # Peek at the first line to see if it looks like a header
            first_line = f_io.readline()
            f_io.seek(0)
            
            # Check if common header keywords exist
            has_header = any(k in first_line.lower() for k in ["asn", "organization", "country", "org", "name"])
            source_count = 0

            if has_header:
                reader = csv.DictReader(f_io)
                for row in reader:
                    asn = (row.get("ASN") or row.get("asn") or row.get("autonomous_system") or row.get("AS") or "").strip()
                    if not asn:
                        vals = list(row.values())
                        asn = vals[0] if vals else ""
                    
                    if not asn or not asn.replace("AS", "").isdigit():
                        continue

                    if not asn.upper().startswith("AS"):
                        asn = "AS" + asn

                    org = (row.get("AS Name") or row.get("Organization") or row.get("org") or row.get("name") or "").strip()
                    country = (row.get("Country Code") or row.get("Country") or row.get("country") or "").strip()
                    
                    all_asn_rows.append((asn.upper(), org, "bad", country))
                    source_count += 1
            else:
                reader = csv.reader(f_io)
                for row in reader:
                    if not row:
                        continue
                    asn = row[0].strip()
                    if not asn:
                        continue
                    if not asn.upper().startswith("AS"):
                        asn = "AS" + asn
                    
                    org = row[1].strip() if len(row) > 1 else ""
                    country = row[2].strip() if len(row) > 2 else ""
                    
                    all_asn_rows.append((asn.upper(), org, "bad", country))
                    source_count += 1

            log.info(f"    → {source_count:>7,} ASNs parsed from {asn_source['name']}")
        except Exception as exc:
            log.error(f"    ✗ {asn_source['name']} failed: {exc}")
            failed.append(asn_source["name"])

    if all_asn_rows:
        # INSERT OR REPLACE handles any overlapping ASNs between blocklists cleanly
        cur.executemany(
            "INSERT OR REPLACE INTO asn_blocklist (asn, org, type, country) VALUES (?, ?, ?, ?)",
            all_asn_rows,
        )
        conn.commit()
        
        # Get count of unique stored ASNs
        cur.execute("SELECT COUNT(*) FROM asn_blocklist")
        asn_count = cur.fetchone()[0]
        log.info(f"    → {asn_count:>7,} total unique ASNs inserted")

    # Metadata row
    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", [
        ("built_at",        built_at),
        ("total_ranges",    str(grand_total)),
        ("total_asns",      str(asn_count)),
        ("failed_sources", ",".join(failed) if failed else ""),
    ])
    conn.commit()

    # Compact the file
    cur.execute("VACUUM")
    conn.close()

    size_kb = os.path.getsize(DB_PATH) / 1024
    log.info("─" * 50)
    log.info(f"  Total IP ranges : {grand_total:,}")
    log.info(f"  Total ASNs      : {asn_count:,}")
    log.info(f"  File size       : {size_kb:,.1f} KB")
    log.info(f"  Built at        : {built_at}")
    if failed:
        log.warning(f"  Failed sources: {', '.join(failed)}")
    log.info(f"  Output       : {DB_PATH}")

    # Exit with error if ALL sources failed
    if len(failed) == len(SOURCES) + len(ASN_SOURCES):
        log.error("All sources failed — aborting.")
        sys.exit(1)

    if grand_total < 1000:
        log.error(f"Too few ranges ({grand_total}) — something is wrong.")
        sys.exit(1)


if __name__ == "__main__":
    build_database()
