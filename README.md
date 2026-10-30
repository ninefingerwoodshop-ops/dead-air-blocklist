# Dead Air scam list

The public list of reported scam phone numbers used by [Dead Air](https://github.com/ninefingerwoodshop-ops/dead-air), a free iPhone scam call and text blocker.

A GitHub Action collects complaints from the FTC's official [Do Not Call reported calls API](https://www.ftc.gov/developer/api/v0/endpoints/do-not-call-dnc-reported-calls-data-api) one finished day at a time, keeps a per-day tally in `daily/`, and rebuilds the list from the last 30 days. It runs every 3 hours; most runs have nothing new to fetch. The API allows 50 complaints per request, so the first 30-day backfill spreads across several runs.

| File | What |
| --- | --- |
| `manifest.json` | A few hundred bytes. The app checks this first and only downloads the list when it changed. |
| `blocklist.bin` | The list. Sorted, delta-encoded, about 3 bytes per number. Format documented in `build_blocklist.py`. |
| `daily/YYYY-MM-DD.tsv` | Per-day report counts (`number<TAB>reports`), only written once a day is complete. |

## Tiers

| Tier | Rule (last 30 days) | On the phone |
| --- | --- | --- |
| Block | reported 10+ times | the call never rings |
| Label | reported 3–9 times | caller ID shows "Reported scam" |

FTC reports are unverified, and scammers fake real people's numbers, so most numbers are only labeled. Thresholds are env vars in `build_blocklist.py` (`LABEL_MIN`, `BLOCK_MIN`, `WINDOW_DAYS`, `MAX_NUMBERS`).

## Privacy

The app only downloads these two files. It never uploads anything about the user.

## Setup

The Action needs a free api.data.gov key in the repository secret `FTC_API_KEY` (get one at https://api.data.gov/signup).

## Run it

```sh
python3 -m unittest test_build_blocklist
FTC_API_KEY=... python3 build_blocklist.py --out .   # collect + build
python3 build_blocklist.py --csv day.csv --out .     # or from FTC CSV exports
```

Stdlib-only Python 3.10+. Run the Action by hand from the Actions tab ("Build scam list" → Run workflow).
