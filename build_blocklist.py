#!/usr/bin/env python3
"""Build the Dead Air scam-number list from FTC Do Not Call complaint data.

The FTC publishes one CSV per business day of numbers consumers reported:
https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data

This script pulls the last WINDOW_DAYS of those files, counts reports per
number, and writes two tiers into a compact binary file the app downloads:

  block  — reported >= BLOCK_MIN times: the phone blocks the call outright
  label  — reported >= LABEL_MIN times: the phone shows "Reported scam"

Reports are unverified and scammers spoof innocent numbers, so the bar for
blocking is deliberately high; most numbers are only labeled.

Output (in OUT_DIR):
  blocklist.bin   — see FORMAT below
  manifest.json   — tiny; the app checks it before downloading the list

FORMAT (all little-endian):
  4 bytes   magic "DABL"
  1 byte    format version (1)
  4 bytes   generated day (days since 1970-01-01, UTC)
  4 bytes   block count
  4 bytes   label count
  then the block numbers, then the label numbers. Each list is sorted
  ascending; each number (11 digits, leading 1, e.g. 17705551234) is
  stored as the unsigned LEB128 varint of its difference from the previous
  number in the same list (the first is the difference from 0).
  A number appears in at most one list.

Stdlib only. Usage:
  python3 build_blocklist.py                      # fetch from the FTC
  python3 build_blocklist.py --csv a.csv b.csv    # build from local files
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from typing import Iterable

FTC_URL = "https://www.ftc.gov/sites/default/files/DNC_Complaint_Numbers_{date}.csv"
MAGIC = b"DABL"
FORMAT_VERSION = 1

WINDOW_DAYS = int(os.environ.get("WINDOW_DAYS", 30))
LABEL_MIN = int(os.environ.get("LABEL_MIN", 3))
BLOCK_MIN = int(os.environ.get("BLOCK_MIN", 10))
# Hard ceiling so the download always stays small (the busiest numbers win).
MAX_NUMBERS = int(os.environ.get("MAX_NUMBERS", 250_000))


# --- numbers -----------------------------------------------------------------

def normalize(raw: str) -> int | None:
    """FTC numbers are bare digits of varying length. Keep valid US (NANP)
    numbers only, as 1NPANXXXXXX. Area code and exchange can't start with
    0 or 1; N11 codes (211, 411, 911...) aren't real area codes."""
    digits = "".join(c for c in raw if c.isdigit())
    if len(digits) == 11 and digits[0] == "1":
        digits = digits[1:]
    if len(digits) != 10:
        return None
    npa, nxx = digits[:3], digits[3:6]
    if npa[0] in "01" or nxx[0] in "01" or npa[1:] == "11":
        return None
    return int("1" + digits)


def count_reports(rows: Iterable[dict]) -> Counter:
    counts: Counter = Counter()
    for row in rows:
        number = normalize(row.get("Company_Phone_Number") or "")
        if number is not None:
            counts[number] += 1
    return counts


def tiers(counts: Counter) -> tuple[list[int], list[int]]:
    eligible = [(n, c) for n, c in counts.items() if c >= LABEL_MIN]
    eligible.sort(key=lambda nc: (-nc[1], nc[0]))
    eligible = eligible[:MAX_NUMBERS]
    block = sorted(n for n, c in eligible if c >= BLOCK_MIN)
    label = sorted(n for n, c in eligible if c < BLOCK_MIN)
    return block, label


# --- encoding ----------------------------------------------------------------

def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode(block: list[int], label: list[int], generated: dt.date) -> bytes:
    day = (generated - dt.date(1970, 1, 1)).days
    out = bytearray(MAGIC)
    out += struct.pack("<BIII", FORMAT_VERSION, day, len(block), len(label))
    for numbers in (block, label):
        previous = 0
        for n in numbers:
            out += varint(n - previous)
            previous = n
    return bytes(out)


def decode(data: bytes) -> tuple[list[int], list[int], dt.date]:
    """Reference decoder — mirrors Shared/ScamList.swift in the app."""
    if data[:4] != MAGIC:
        raise ValueError("bad magic")
    version, day, n_block, n_label = struct.unpack_from("<BIII", data, 4)
    if version != FORMAT_VERSION:
        raise ValueError(f"unsupported version {version}")
    pos = 4 + struct.calcsize("<BIII")

    def read(count: int) -> list[int]:
        nonlocal pos
        values, previous = [], 0
        for _ in range(count):
            shift = value = 0
            while True:
                byte = data[pos]
                pos += 1
                value |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            previous += value
            values.append(previous)
        return values

    block, label = read(n_block), read(n_label)
    if pos != len(data):
        raise ValueError("trailing bytes")
    return block, label, dt.date(1970, 1, 1) + dt.timedelta(days=day)


# --- fetching ----------------------------------------------------------------

USER_AGENT = "dead-air-blocklist (github.com/ninefingerwoodshop-ops/dead-air-blocklist)"


def annotate(level: str, message: str) -> None:
    """Print a GitHub Actions annotation (readable through the API) and a plain line."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level}::{message}")
    print(message, file=sys.stderr)


def fetch_day(date: dt.date) -> str | None:
    """Returns the CSV text, or None if that day has no file (weekend, holiday,
    not posted yet). Raises after retries on anything else."""
    url = FTC_URL.format(date=date.isoformat())
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                text = response.read().decode("utf-8-sig", errors="replace")
                if not text.startswith("Company_Phone_Number"):
                    raise ValueError(f"unexpected content: {text[:80]!r}")
                return text
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last_error = e
        except (urllib.error.URLError, ValueError, TimeoutError) as e:
            last_error = e
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"{date}: {last_error}")


def fetch_window(today: dt.date) -> tuple[list[dict], int]:
    """Skips days that fail (and says why); only a window with no data at all is fatal."""
    rows: list[dict] = []
    files = 0
    for offset in range(WINDOW_DAYS):
        day = today - dt.timedelta(days=offset)
        try:
            text = fetch_day(day)
        except RuntimeError as e:
            annotate("warning", f"FTC download failed for {e}")
            continue
        if text is None:
            continue
        files += 1
        rows.extend(csv.DictReader(io.StringIO(text)))
    return rows, files


# --- main --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--csv", nargs="*", help="build from local CSV files instead of fetching")
    parser.add_argument("--out", default=".", help="output directory")
    parser.add_argument("--date", help="treat this as today (YYYY-MM-DD)")
    args = parser.parse_args()

    today = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.timezone.utc).date()

    if args.csv:
        rows = []
        for path in args.csv:
            with open(path, newline="", encoding="utf-8-sig") as f:
                rows.extend(csv.DictReader(f))
        files = len(args.csv)
    else:
        rows, files = fetch_window(today)

    if files == 0 or not rows:
        annotate("error", "No FTC data downloaded; leaving the existing list untouched.")
        return 1

    counts = count_reports(rows)
    block, label = tiers(counts)
    data = encode(block, label, today)

    # Round-trip check before publishing anything.
    if decode(data)[:2] != (block, label):
        print("Encoding round-trip failed", file=sys.stderr)
        return 1

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "blocklist.bin"), "wb") as f:
        f.write(data)
    manifest = {
        "format": FORMAT_VERSION,
        "generated": today.isoformat(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "block": len(block),
        "label": len(label),
        "window_days": WINDOW_DAYS,
        "label_min_reports": LABEL_MIN,
        "block_min_reports": BLOCK_MIN,
        "source": "FTC Do Not Call reported calls data",
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"{files} FTC files, {len(rows):,} reports, {len(counts):,} distinct valid numbers")
    print(f"block {len(block):,} (>= {BLOCK_MIN} reports), label {len(label):,} (>= {LABEL_MIN})")
    print(f"blocklist.bin {len(data):,} bytes ({len(data) / max(1, len(block) + len(label)):.2f} bytes/number)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
