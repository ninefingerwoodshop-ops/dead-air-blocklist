# Dead Air scam list

The public list of reported scam phone numbers used by [Dead Air](https://github.com/ninefingerwoodshop-ops/dead-air), a free iPhone scam call and text blocker.

Every Monday a GitHub Action pulls the last 30 days of the FTC's [Do Not Call reported calls data](https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data), counts reports per number, and publishes:

| File | What |
| --- | --- |
| `manifest.json` | A few hundred bytes. The app checks this first and only downloads the list when it changed. |
| `blocklist.bin` | The list. Sorted, delta-encoded, about 3 bytes per number. Format documented in `build_blocklist.py`. |

## Tiers

| Tier | Rule (last 30 days) | On the phone |
| --- | --- | --- |
| Block | reported 10+ times | the call never rings |
| Label | reported 3–9 times | caller ID shows "Reported scam" |

FTC reports are unverified, and scammers fake real people's numbers, so most numbers are only labeled. Thresholds are env vars in `build_blocklist.py` (`LABEL_MIN`, `BLOCK_MIN`, `WINDOW_DAYS`, `MAX_NUMBERS`).

## Privacy

The app only downloads these two files. It never uploads anything about the user.

## Run it

```sh
python3 -m unittest test_build_blocklist
python3 build_blocklist.py --out .                 # fetch from the FTC
python3 build_blocklist.py --csv day.csv --out .   # or from local CSVs
```

Stdlib-only Python 3.10+. Run the Action by hand from the Actions tab ("Build scam list" → Run workflow).
