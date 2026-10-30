import datetime as dt
import random
import unittest

import build_blocklist as b


class NormalizeTests(unittest.TestCase):
    def test_keeps_valid_us_numbers(self):
        self.assertEqual(b.normalize("7252099152"), 17252099152)
        self.assertEqual(b.normalize("17252099152"), 17252099152)

    def test_drops_junk_seen_in_ftc_files(self):
        for raw in ["", "213", "941430760", "03170445558", "8656696225537",
                    "1234567890",   # area code starts with 1
                    "7251234567",   # exchange starts with 1
                    "9115551234"]:  # N11 area code
            self.assertIsNone(b.normalize(raw), raw)


class TierTests(unittest.TestCase):
    def test_thresholds(self):
        raw = (["7252099152"] * b.BLOCK_MIN
               + ["7327819682"] * b.LABEL_MIN
               + ["8063389043"] * (b.LABEL_MIN - 1))
        block, label = b.tiers(b.count_numbers(raw))
        self.assertEqual(block, [17252099152])
        self.assertEqual(label, [17327819682])


class EncodingTests(unittest.TestCase):
    def test_round_trip(self):
        rng = random.Random(42)
        numbers = sorted(rng.sample(range(12002000000, 19899999999), 5000))
        block, label = numbers[:700], numbers[700:]
        block.sort(); label.sort()
        day = dt.date(2026, 10, 30)
        data = b.encode(block, label, day)
        self.assertEqual(b.decode(data), (block, label, day))
        # Sorted deltas keep it small: well under 4 bytes per number.
        self.assertLess(len(data) / len(numbers), 4)

    def test_empty(self):
        day = dt.date(2026, 10, 30)
        self.assertEqual(b.decode(b.encode([], [], day)), ([], [], day))

    def test_known_bytes(self):
        """Fixture shared with the app's Swift decoder test."""
        data = b.encode([17705551234], [14045550199, 17705559999], dt.date(2026, 10, 30))
        self.assertEqual(data.hex(), FIXTURE_HEX)


class TallyTests(unittest.TestCase):
    def test_round_trip_and_window(self):
        import collections, os, tempfile
        today = dt.date(2026, 10, 30)
        with tempfile.TemporaryDirectory() as d:
            counts = collections.Counter({17705551234: 4, 14045550199: 1})
            inside = b.tally_path(d, today - dt.timedelta(days=1))
            b.write_tally(inside, counts)
            self.assertEqual(b.read_tally(inside), counts)
            # Today (incomplete) and days past the window are pruned.
            for day in (today, today - dt.timedelta(days=b.WINDOW_DAYS + 1)):
                b.write_tally(b.tally_path(d, day), counts)
            b.prune(d, today)
            self.assertEqual(os.listdir(d), [os.path.basename(inside)])


class CollectTests(unittest.TestCase):
    """Paging and budget handling against a fake API."""

    class FakeClient(b.FTCClient):
        def __init__(self, per_hour, budget):
            super().__init__("key", budget)
            self.per_hour = per_hour

        def get(self, params):
            if self.requests >= self.budget:
                raise b.BudgetExhausted
            self.requests += 1
            remaining = max(0, self.per_hour - params["offset"])
            page = [{"attributes": {"company-phone-number": "7705551234"}}] * min(b.PAGE_SIZE, remaining)
            return {"data": page}

    def test_pages_every_hour_and_resumes_after_budget(self):
        import tempfile
        today = dt.date(2026, 10, 30)
        with tempfile.TemporaryDirectory() as d:
            # 120 complaints/hour = 3 pages/hour = 72 requests/day; budget fits 2 days.
            client = self.FakeClient(per_hour=120, budget=150)
            fetched, remaining = b.collect(client, d, today)
            self.assertEqual((fetched, remaining), (2, b.WINDOW_DAYS - 2))
            day1 = b.read_tally(b.tally_path(d, today - dt.timedelta(days=1)))
            self.assertEqual(day1[17705551234], 120 * 24)
            # Next run picks up where it stopped; half-fetched days were never written.
            fetched, remaining = b.collect(self.FakeClient(per_hour=120, budget=150), d, today)
            self.assertEqual((fetched, remaining), (2, b.WINDOW_DAYS - 4))


# Pinned bytes — if this changes, the app's decoder test must change too.
FIXTURE_HEX = "4441424c01145100000100000002000000828bd5fa41f7acb8a934c8a29dd10d"

if __name__ == "__main__":
    unittest.main()
