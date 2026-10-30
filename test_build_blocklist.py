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
        rows = ([{"Company_Phone_Number": "7252099152"}] * b.BLOCK_MIN
                + [{"Company_Phone_Number": "7327819682"}] * b.LABEL_MIN
                + [{"Company_Phone_Number": "8063389043"}] * (b.LABEL_MIN - 1))
        block, label = b.tiers(b.count_reports(rows))
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


# Pinned bytes — if this changes, the app's decoder test must change too.
FIXTURE_HEX = "4441424c01145100000100000002000000828bd5fa41f7acb8a934c8a29dd10d"

if __name__ == "__main__":
    unittest.main()
