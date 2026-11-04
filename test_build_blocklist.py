import base64
import datetime as dt
import json
import os
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

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


def openssl_has_ed25519() -> bool:
    if not shutil.which("openssl"):
        return False
    out = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    return out.startswith("OpenSSL 3")


@unittest.skipUnless(openssl_has_ed25519(), "needs OpenSSL 3")
class SigningTests(unittest.TestCase):
    def test_pinned_signature(self):
        """Shared with the app's Swift signature test: same key, bytes, signature."""
        data = bytes.fromhex(FIXTURE_HEX)
        self.assertEqual(b.sign(data, TEST_SIGNING_KEY), FIXTURE_SIGNATURE)
        pem = f"-----BEGIN PRIVATE KEY-----\n{TEST_SIGNING_KEY}\n-----END PRIVATE KEY-----\n"
        self.assertEqual(b.sign(data, pem), FIXTURE_SIGNATURE)

    def test_publish_signs_manifest(self):
        counts = b.count_numbers(["7252099152"] * b.BLOCK_MIN)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {b.SIGNING_KEY_ENV: TEST_SIGNING_KEY}):
            b.publish(counts, d, dt.date(2026, 10, 30), days_used=1)
            with open(os.path.join(d, "manifest.json")) as f:
                manifest = json.load(f)
            with open(os.path.join(d, "blocklist.bin"), "rb") as f:
                data = f.read()
        self.assertEqual(manifest["signature"], b.sign(data, TEST_SIGNING_KEY))
        self.assertEqual(len(base64.b64decode(manifest["signature"])), 64)

    def test_bad_key_fails_without_writing(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {b.SIGNING_KEY_ENV: "not a key"}):
            with self.assertRaises(RuntimeError):
                b.publish(b.count_numbers([]), d, dt.date(2026, 10, 30), days_used=1)
            self.assertEqual(os.listdir(d), [])


class UnsignedTests(unittest.TestCase):
    def test_actions_refuses_to_publish_unsigned(self):
        env = {k: v for k, v in os.environ.items() if k != b.SIGNING_KEY_ENV}
        env["GITHUB_ACTIONS"] = "true"
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                b.publish(b.count_numbers([]), d, dt.date(2026, 10, 30), days_used=1)
            self.assertEqual(os.listdir(d), [])

    def test_local_build_without_key_is_unsigned(self):
        env = {k: v for k, v in os.environ.items() if k not in (b.SIGNING_KEY_ENV, "GITHUB_ACTIONS")}
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=True):
            b.publish(b.count_numbers([]), d, dt.date(2026, 10, 30), days_used=1)
            with open(os.path.join(d, "manifest.json")) as f:
                self.assertNotIn("signature", json.load(f))


# Pinned bytes — if this changes, the app's decoder test must change too.
FIXTURE_HEX = "4441424c01145100000100000002000000828bd5fa41f7acb8a934c8a29dd10d"

# TEST-ONLY Ed25519 key (PKCS#8 base64). Published on purpose so the app's
# Swift test can check the same signature; it signs nothing real. The real
# key lives only in the BLOCKLIST_SIGNING_KEY secret and the owner's Keychain.
TEST_SIGNING_KEY = "MC4CAQAwBQYDK2VwBCIEIDSzIzzj/06YvTDooKtwgMAamhtUGl/0cLtoNzwtppV3"
TEST_PUBLIC_KEY = "qNVBY08Ins4R3dOXEVzFTXt8c90rhL9O3xcOI9anFKo="  # raw 32 bytes, pinned in the Swift test
FIXTURE_SIGNATURE = "h75tCAHFkqugGCCie9ZsneshZdTDQddMVYIJhTGxtEZkMBla/R/cwjxXbGilZgDLDFrIo7m1xEiLG7I/iMedCg=="

if __name__ == "__main__":
    unittest.main()
