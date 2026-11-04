#!/usr/bin/env python3
"""Build the Dead Air scam-number list from FTC Do Not Call complaint data.

Source: the FTC's official Do Not Call reported calls API
https://www.ftc.gov/developer/api/v0/endpoints/do-not-call-dnc-reported-calls-data-api
(free key from https://api.data.gov/signup, passed as FTC_API_KEY).

The API returns at most 50 complaints per request and a free key allows
roughly 1,000 requests an hour, while a month of complaints is ~6,000
requests. So collection is incremental:

  1. collect — for each finished day in the window that we don't have yet,
     page through that day's complaints (one hour at a time, so paging never
     goes deep) and save a per-day tally to daily/YYYY-MM-DD.tsv
     ("number<TAB>reports"). A day is only written once it's complete.
     Stops early when the request budget runs low; the next run resumes.
  2. build — add up the daily tallies for the last WINDOW_DAYS and write
     two tiers into a compact binary file the app downloads:

       block  — reported >= BLOCK_MIN times: the phone blocks the call
       label  — reported >= LABEL_MIN times: caller ID says "Reported scam"

Reports are unverified and scammers spoof innocent numbers, so the bar for
blocking is deliberately high; most numbers are only labeled.

Output (in --out):
  blocklist.bin   — see FORMAT below
  manifest.json   — tiny; the app checks it before downloading the list.
                    "signature" is the base64 Ed25519 signature of
                    blocklist.bin; the app only installs a list that
                    verifies against the public key pinned in it.

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

SIGNING: set BLOCKLIST_SIGNING_KEY to the Ed25519 private key (PKCS#8 PEM,
or just its one-line base64 body). Create it with tools/new-signing-key.sh.
Inside GitHub Actions an unsigned list is never published. Signatures are
deterministic (RFC 8032), so rebuilding the same bytes gives the same manifest.

Stdlib only; signing shells out to the openssl CLI (OpenSSL 3). Usage:
  FTC_API_KEY=... python3 build_blocklist.py --out .   # collect + build
  python3 build_blocklist.py --csv a.csv --out .       # build from FTC CSV exports
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Iterable

API_URL = "https://api.ftc.gov/v0/dnc-complaints"
PAGE_SIZE = 50  # the API's maximum
MAGIC = b"DABL"
FORMAT_VERSION = 1

WINDOW_DAYS = int(os.environ.get("WINDOW_DAYS", 30))
LABEL_MIN = int(os.environ.get("LABEL_MIN", 3))
BLOCK_MIN = int(os.environ.get("BLOCK_MIN", 10))
# Hard ceiling so the download always stays small (the busiest numbers win).
MAX_NUMBERS = int(os.environ.get("MAX_NUMBERS", 250_000))
# Requests per run; stays under api.data.gov's default hourly limit.
REQUEST_BUDGET = int(os.environ.get("REQUEST_BUDGET", 900))
USER_AGENT = "dead-air-blocklist (github.com/ninefingerwoodshop-ops/dead-air-blocklist)"


def annotate(level: str, message: str) -> None:
    """A GitHub Actions annotation (readable through the API) plus a plain line."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level}::{message}")
    print(message, file=sys.stderr)


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


def count_numbers(raw_numbers: Iterable[str]) -> Counter:
    counts: Counter = Counter()
    for raw in raw_numbers:
        number = normalize(raw or "")
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


# --- daily tallies -----------------------------------------------------------

def tally_path(daily_dir: str, day: dt.date) -> str:
    return os.path.join(daily_dir, f"{day.isoformat()}.tsv")


def write_tally(path: str, counts: Counter) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for number in sorted(counts):
            f.write(f"{number}\t{counts[number]}\n")
    os.replace(tmp, path)  # a day appears only once it's complete


def read_tally(path: str) -> Counter:
    counts: Counter = Counter()
    with open(path) as f:
        for line in f:
            number, reports = line.split("\t")
            counts[int(number)] += int(reports)
    return counts


def window_days(today: dt.date) -> list[dt.date]:
    """Finished days only (today's complaints are still coming in), newest first."""
    return [today - dt.timedelta(days=offset) for offset in range(1, WINDOW_DAYS + 1)]


def prune(daily_dir: str, today: dt.date) -> None:
    keep = {tally_path(daily_dir, d) for d in window_days(today)}
    for name in os.listdir(daily_dir):
        path = os.path.join(daily_dir, name)
        if name.endswith(".tsv") and path not in keep:
            os.remove(path)


# --- FTC API -----------------------------------------------------------------

class BudgetExhausted(Exception):
    pass


class FTCClient:
    def __init__(self, api_key: str, budget: int):
        self.api_key = api_key
        self.budget = budget
        self.requests = 0

    def get(self, params: dict) -> dict:
        if self.requests >= self.budget:
            raise BudgetExhausted
        url = API_URL + "?" + urllib.parse.urlencode(params)
        # Key in a header so it never appears in URLs or logs.
        request = urllib.request.Request(url, headers={"X-Api-Key": self.api_key, "User-Agent": USER_AGENT})
        for attempt in range(4):
            self.requests += 1
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    body = json.load(response)
                if remaining is not None and int(remaining) < 10:
                    self.budget = self.requests  # stop after this one
                return body
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    raise BudgetExhausted from e
                if e.code in (401, 403):
                    raise RuntimeError(f"FTC API rejected the key (HTTP {e.code}). Check the FTC_API_KEY secret.") from e
                if e.code < 500 or attempt == 3:
                    raise RuntimeError(f"FTC API HTTP {e.code} for {params}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt == 3:
                    raise RuntimeError(f"FTC API unreachable: {e}") from e
            time.sleep(5 * (attempt + 1))
        raise RuntimeError("unreachable")

    def numbers_for_day(self, day: dt.date) -> list[str]:
        """Every complaint's number for one day, an hour at a time so the
        offset never grows past a few hundred."""
        numbers: list[str] = []
        for hour in range(24):
            start = f'"{day.isoformat()} {hour:02d}:00:00"'
            end = f'"{day.isoformat()} {hour:02d}:59:59"'
            offset = 0
            while True:
                body = self.get({
                    "created_date_from": start,
                    "created_date_to": end,
                    "items_per_page": PAGE_SIZE,
                    "offset": offset,
                })
                page = body.get("data") or []
                numbers.extend((item.get("attributes") or {}).get("company-phone-number") or "" for item in page)
                if len(page) < PAGE_SIZE:
                    break
                offset += PAGE_SIZE
        return numbers


def collect(client: FTCClient, daily_dir: str, today: dt.date) -> tuple[int, int]:
    """Fetch missing days, newest first. Returns (days fetched, days still missing)."""
    os.makedirs(daily_dir, exist_ok=True)
    missing = [d for d in window_days(today) if not os.path.exists(tally_path(daily_dir, d))]
    fetched = 0
    for day in missing:
        try:
            numbers = client.numbers_for_day(day)
        except BudgetExhausted:
            break
        write_tally(tally_path(daily_dir, day), count_numbers(numbers))
        fetched += 1
        print(f"{day}: {len(numbers):,} complaints")
    return fetched, len(missing) - fetched


# --- signing -----------------------------------------------------------------

SIGNING_KEY_ENV = "BLOCKLIST_SIGNING_KEY"


def sign(data: bytes, key: str) -> str:
    """Base64 Ed25519 signature of data. The key never touches the output."""
    key = key.strip()
    if "BEGIN" not in key:
        key = f"-----BEGIN PRIVATE KEY-----\n{key}\n-----END PRIVATE KEY-----"
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        data_path = os.path.join(tmp, "data.bin")
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(key + "\n")
        with open(data_path, "wb") as f:
            f.write(data)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", data_path],
            capture_output=True)
    if result.returncode != 0 or len(result.stdout) != 64:
        raise RuntimeError("openssl couldn't make an Ed25519 signature; "
                           f"check {SIGNING_KEY_ENV} and that openssl is version 3")
    return base64.b64encode(result.stdout).decode()


def signature_for(data: bytes) -> str | None:
    key = os.environ.get(SIGNING_KEY_ENV, "")
    if key.strip():
        return sign(data, key)
    if os.environ.get("GITHUB_ACTIONS"):
        raise RuntimeError(f"{SIGNING_KEY_ENV} is not set; refusing to publish an unsigned list. "
                           "Create it with tools/new-signing-key.sh.")
    annotate("warning", f"{SIGNING_KEY_ENV} is not set; the app won't install this unsigned list.")
    return None


# --- build -------------------------------------------------------------------

def publish(counts: Counter, out_dir: str, today: dt.date, days_used: int) -> None:
    block, label = tiers(counts)
    data = encode(block, label, today)
    if decode(data)[:2] != (block, label):
        raise RuntimeError("encoding round-trip failed")
    signature = signature_for(data)  # before writing anything, so a failure leaves no half-built output

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "blocklist.bin"), "wb") as f:
        f.write(data)
    manifest = {
        "format": FORMAT_VERSION,
        "generated": today.isoformat(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "block": len(block),
        "label": len(label),
        "days": days_used,
        "window_days": WINDOW_DAYS,
        "label_min_reports": LABEL_MIN,
        "block_min_reports": BLOCK_MIN,
        "source": "FTC Do Not Call reported calls data",
    }
    if signature:
        manifest["signature"] = signature
    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"block {len(block):,} (>= {BLOCK_MIN} reports), label {len(label):,} (>= {LABEL_MIN}) "
          f"from {days_used} days; blocklist.bin {len(data):,} bytes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--csv", nargs="*", help="build from FTC CSV exports instead of the API")
    parser.add_argument("--out", default=".", help="output directory")
    parser.add_argument("--daily", default="daily", help="directory of per-day tallies")
    parser.add_argument("--date", help="treat this as today (YYYY-MM-DD)")
    args = parser.parse_args()

    today = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.timezone.utc).date()

    if args.csv:
        raw = []
        for path in args.csv:
            with open(path, newline="", encoding="utf-8-sig") as f:
                raw.extend(row.get("Company_Phone_Number") or "" for row in csv.DictReader(f))
        publish(count_numbers(raw), args.out, today, days_used=len(args.csv))
        return 0

    api_key = os.environ.get("FTC_API_KEY")
    if not api_key:
        annotate("error", "FTC_API_KEY is not set. Add it as a repository secret (free key: https://api.data.gov/signup).")
        return 1

    client = FTCClient(api_key, REQUEST_BUDGET)
    try:
        fetched, remaining = collect(client, args.daily, today)
    except RuntimeError as e:
        annotate("error", str(e))
        return 1
    prune(args.daily, today)
    annotate("notice", f"Fetched {fetched} day(s) in {client.requests} requests; {remaining} day(s) still to backfill.")

    days = [d for d in window_days(today) if os.path.exists(tally_path(args.daily, d))]
    if not days:
        annotate("error", "No complete days collected yet; nothing to publish.")
        return 1
    counts: Counter = Counter()
    for d in days:
        counts.update(read_tally(tally_path(args.daily, d)))
    publish(counts, args.out, today, days_used=len(days))
    return 0


def run() -> int:
    try:
        return main()
    except RuntimeError as e:
        annotate("error", str(e))
        return 1


if __name__ == "__main__":
    sys.exit(run())
