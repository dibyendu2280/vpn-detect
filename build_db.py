#!/usr/bin/env python3
"""
VPN Detection Database Builder
Downloads free IP blocklists and builds a single SQLite database
for offline VPN / proxy detection in WordPress plugins.

Sources used (all free, no API key required):
  - X4BNet       : Commercial VPN provider IP ranges
  - Tor Project  : Official Tor exit node list
  - Firehol      : Datacenter / hosting IP ranges
  - Stamparm     : Known open proxies (level 3 = high confidence)
"""

import ipaddress
import sqlite3
import urllib.request
import csv
import io
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

BAD_ASN_URL = (
    "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
)

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
        "name":   "firehol_datacenter",
        "url":    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/datacenters.netset",
        "type":   "datacenter",
        "format": "cidr",
    },
    {
        "name":   "ipsum_proxy",
        "url":    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "type":   "proxy",
        "format": "ip",
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
            result = ip_to_range(line)     # CIDR list with a bare IP (treat as /32)
        else:
            result = ip_to_range(line)

        if result:
            yield result


# ── Download ───────────────────────────────────────────────────────────────────

def download(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "vpn-detection-db-builder/1.0 (github.com)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="ignore")


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
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_start INTEGER NOT NULL,
            ip_end   INTEGER NOT NULL,
            type     TEXT    NOT NULL,   -- 'vpn' | 'tor' | 'datacenter' | 'proxy'
            source   TEXT    NOT NULL    -- source identifier
        );

        -- ASN-level blocklist from brianhama/bad-asn-list
        -- Used as Layer 2 fallback when an IP is not in ip_ranges
        CREATE TABLE asn_blocklist (
            asn         TEXT PRIMARY KEY,  -- e.g. 'AS9009'
            org         TEXT,              -- e.g. 'M247 Ltd'
            type        TEXT,              -- 'vpn' | 'datacenter' | 'proxy' | 'bad'
            country     TEXT
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

    # ── ASN blocklist ──────────────────────────────────────────────────────────
    asn_count = 0
    log.info("Processing source: bad_asn_list …")
    try:
        content  = download(BAD_ASN_URL)
        reader   = csv.DictReader(io.StringIO(content))
        asn_rows = []

        for row in reader:
            asn = row.get("ASN", "").strip()
            if not asn:
                continue

            # Normalise: ensure it starts with 'AS'
            if not asn.upper().startswith("AS"):
                asn = "AS" + asn

            org     = row.get("AS Name", row.get("Organization", "")).strip()
            country = row.get("Country Code", row.get("Country", "")).strip()

            # Infer type from org name keywords
            org_lower = org.lower()
            if any(k in org_lower for k in ["vpn", "nordvpn", "expressvpn", "surfshark",
                                             "pia", "private internet", "mullvad", "protonvpn",
                                             "airvpn", "hidemyass", "purevpn", "ipvanish"]):
                asn_type = "vpn"
            elif any(k in org_lower for k in ["cloud", "hosting", "server", "datacenter",
                                               "data center", "vultr", "digitalocean", "linode",
                                               "hetzner", "ovh", "aws", "amazon", "azure",
                                               "google", "cloudflare"]):
                asn_type = "datacenter"
            elif any(k in org_lower for k in ["proxy", "anonymize", "anonymous"]):
                asn_type = "proxy"
            else:
                asn_type = "bad"

            asn_rows.append((asn.upper(), org, asn_type, country))

        cur.executemany(
            "INSERT OR IGNORE INTO asn_blocklist (asn, org, type, country) VALUES (?, ?, ?, ?)",
            asn_rows,
        )
        conn.commit()
        asn_count = len(asn_rows)
        log.info(f"    → {asn_count:>7,} ASNs inserted")
    except Exception as exc:
        log.error(f"    ✗ bad_asn_list failed: {exc}")
        failed.append("bad_asn_list")

    # Metadata row
    built_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", [
        ("built_at",      built_at),
        ("total_ranges",  str(grand_total)),
        ("total_asns",    str(asn_count)),
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
    if len(failed) == len(SOURCES):
        log.error("All sources failed — aborting.")
        sys.exit(1)

    if grand_total < 1000:
        log.error(f"Too few ranges ({grand_total}) — something is wrong.")
        sys.exit(1)


if __name__ == "__main__":
    build_database()
