"""核对外部资料的格式及可读取性。"""
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from transcript import load, serve


class SourceContract(unittest.TestCase):
    def test_observations(self):
        sources, records = load()
        self.assertTrue(records)
        identifiers = {row["record_id"] for row in records}
        self.assertEqual(len(identifiers), len(records))
        self.assertEqual(set(sources), {row["source"] for row in records})
        previous = -1
        observed_at = {row["record_id"]: row["observed"] for row in records}
        for row in records:
            self.assertGreaterEqual(row["observed"], previous)
            self.assertIsInstance(row["payload"], dict)
            self.assertTrue(set(row["relates_to"]) <= identifiers)
            for reference in row["relates_to"]:
                self.assertLessEqual(observed_at[reference], row["observed"])
            previous = row["observed"]

    def test_feed(self):
        sources, records = load()
        source = next(iter(sources))
        with serve("127.0.0.1", 0) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                root = f"http://127.0.0.1:{server.server_address[1]}"
                with urlopen(f"{root}/sources", timeout=2) as response:
                    self.assertEqual(json.load(response), sources)
                boundary = records[len(records) // 2]["observed"]
                with urlopen(f"{root}/observations?source={source}&through={boundary}", timeout=2) as response:
                    known = [row for row in records if row["source"] == source and row["observed"] <= boundary]
                    self.assertEqual(json.load(response), known)
                with self.assertRaises(HTTPError) as failure:
                    urlopen(f"{root}/observations?through=invalid", timeout=2)
                self.assertEqual(failure.exception.code, 400)
                failure.exception.close()
            finally:
                server.shutdown()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
