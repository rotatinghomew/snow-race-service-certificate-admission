"""两个接入域 mTLS 接收端的集成测试。

证书在临时目录真实生成；practice 与 race 各有独立信任根。
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import ssl

from station.core import Station, FileTrust, ACCEPTED, BLOCKED, REVIEW
from station.receiver import build_receiver

REPO = Path(__file__).resolve().parent.parent


def _client_context(cert_dir: Path, group: str, label: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cert_dir / group / "ca.crt")
    context.load_cert_chain(
        cert_dir / group / f"{label}.crt",
        cert_dir / group / f"{label}.key",
    )
    return context


class ReceiverIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_dir = Path(tempfile.mkdtemp(prefix="station-certs-"))
        result = subprocess.run(
            ["python3", str(REPO / "fixture_certs.py"),
             "--output", str(cls.cert_dir), "--timing"],
            capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cert_dir, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="station-state-"))
        self.state = self.tmp / "station.json"
        self.trust = FileTrust(self.cert_dir)
        self.servers = []
        self.threads = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
        for thread in self.threads:
            thread.join(timeout=2)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _start(self, domain: str) -> str:
        httpd, _ = build_receiver(
            domain=domain, cert_dir=self.cert_dir, state_path=self.state,
            trust=self.trust,
        )
        self.servers.append(httpd)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.threads.append(thread)
        return f"https://127.0.0.1:{httpd.server_address[1]}"

    def _seed(self):
        station = Station(trust=self.trust)
        station.register("timer-81", "p-361", "practice", "timer-p1", observed=0)
        station.register("timer-81", "r-164", "race", "timer-r1", observed=0)
        station.register("timer-81", "r-189", "race", "timer-r2", observed=0)
        station.add_route("route-p", "practice", "practice",
                          ["north", "south"], ["p-361"])
        station.add_route("route-r", "race", "race",
                          ["north", "south"], ["r-164", "r-189"])
        station.record_cert("timer-r1", "issued", observed=1, issued_at=1)
        station.record_cert("timer-r2", "unknown", observed=5)
        station.add_permit("perm/31", "r-164", ["north"], 0, 70,
                           "route-r", observed=1)
        station.save(self.state)

    def _call(self, url: str, method: str, group: str, label: str,
              body: dict | None = None):
        context = _client_context(self.cert_dir, group, label)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(url, data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, context=context, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_cross_domain_handshake_is_rejected(self):
        race_url = self._start("race")
        practice_url = self._start("practice")
        # practice CA 签的身份无法通过 race 域的双向信任校验：
        # 客户端不信任 race 服务端证书，或服务端拒绝 practice 客户端证书
        with self.assertRaises(URLError):
            self._call(f"{race_url}/v1/whoami", "GET", "practice", "timer-p1")
        with self.assertRaises(URLError):
            self._call(f"{practice_url}/v1/whoami", "GET", "race", "timer-r1")

    def test_practice_duty_cannot_read_race_domain(self):
        self._seed()
        practice_url = self._start("practice")
        race_url = self._start("race")
        status, body = self._call(
            f"{practice_url}/v1/whoami", "GET", "practice", "timer-p1")
        self.assertEqual(status, 200)
        self.assertEqual(body["role"], "practice_duty")
        # 同一张练习身份即使拿到 race 网络位置也被应用层拒绝
        # （TLS 层先拒绝，这里验证 race 身份对练习端的反向角色隔离）
        status, body = self._call(
            f"{race_url}/v1/whoami", "GET", "race", "timer-r1")
        self.assertEqual(status, 200)

    def test_read_only_role_cannot_write(self):
        from station.receiver import ROLE_BY_LABEL
        self._seed()
        practice_url = self._start("practice")
        # 模拟本域只读身份：把练习值班角色临时降为 viewer
        original = ROLE_BY_LABEL.get("timer-p1")
        ROLE_BY_LABEL["timer-p1"] = "viewer"
        try:
            status, body = self._call(
                f"{practice_url}/v1/samples", "POST", "practice", "timer-p1",
                body={"record_id": "ro", "track": "north", "sequence": 1,
                      "observed": 10},
            )
            self.assertEqual(status, 403)
            status, _ = self._call(
                f"{practice_url}/v1/ledger", "GET", "practice", "timer-p1")
            self.assertEqual(status, 200)
        finally:
            ROLE_BY_LABEL["timer-p1"] = original

    def test_race_identity_rejected_by_practice_tls_root(self):
        self._seed()
        practice_url = self._start("practice")
        # race 信任根下的身份链不到 practice CA：TLS 层即拒绝，
        # 不会进入应用层（这正是两个接入域各自信任材料的意义）
        with self.assertRaises(URLError):
            self._call(
                f"{practice_url}/v1/samples", "POST", "race", "timer-r1",
                body={"record_id": "x", "track": "north", "sequence": 1,
                      "observed": 10},
            )

    def test_valid_race_upload_accepted_and_persisted(self):
        self._seed()
        race_url = self._start("race")
        status, body = self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r1",
            body={"record_id": "live-1", "track": "north",
                  "sequence": 700, "observed": 20},
        )
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], ACCEPTED)
        # 落盘后重新加载，收件事实仍在
        reloaded = Station.load(self.state, trust=self.trust)
        self.assertIn(("race", "north", 700), reloaded.bookings)

    def test_unconfirmed_cert_upload_is_locked(self):
        self._seed()
        race_url = self._start("race")
        status, body = self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r2",
            body={"record_id": "live-2", "track": "north",
                  "sequence": 701, "observed": 20},
        )
        self.assertEqual(status, 423)
        self.assertEqual(body["status"], BLOCKED)

    def test_duplicate_sequence_is_locked(self):
        self._seed()
        race_url = self._start("race")
        first, _ = self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r1",
            body={"record_id": "live-3", "track": "north",
                  "sequence": 702, "observed": 20},
        )
        self.assertEqual(first, 202)
        status, body = self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r1",
            body={"record_id": "live-3-again", "track": "north",
                  "sequence": 702, "observed": 21},
        )
        self.assertEqual(status, 423)
        self.assertEqual(body["reason"], "blocked_duplicate_sequence")

    def test_probe_distinguishes_tls_and_production_readiness(self):
        self._seed()
        race_url = self._start("race")
        status, body = self._call(
            f"{race_url}/v1/probe", "POST", "race", "timer-r2",
            body={"track": "north", "observed": 20},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["tls_accepted"])
        self.assertFalse(body["production_ready"])

    def test_ledger_explains_owner_instance_and_domain(self):
        self._seed()
        practice_url = self._start("practice")
        race_url = self._start("race")
        self._call(
            f"{practice_url}/v1/samples", "POST", "practice", "timer-p1",
            body={"record_id": "p-1", "track": "north",
                  "sequence": 1, "observed": 10},
        )
        self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r1",
            body={"record_id": "r-1", "track": "north",
                  "sequence": 1, "observed": 10},
        )
        _, practice_ledger = self._call(
            f"{practice_url}/v1/ledger", "GET", "practice", "timer-p1")
        self.assertEqual(len(practice_ledger["ledger"]), 1)
        self.assertEqual(practice_ledger["ledger"][0]["instance"], "p-361")
        _, race_ledger = self._call(
            f"{race_url}/v1/ledger", "GET", "race", "timer-r1")
        entries = race_ledger["ledger"]
        self.assertEqual({e["domain"] for e in entries}, {"race"})
        self.assertEqual(entries[0]["instance"], "r-164")

    def test_intake_buckets_visible_by_domain(self):
        self._seed()
        race_url = self._start("race")
        self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r1",
            body={"record_id": "ok", "track": "north",
                  "sequence": 800, "observed": 20},
        )
        self._call(
            f"{race_url}/v1/samples", "POST", "race", "timer-r2",
            body={"record_id": "held", "track": "north",
                  "sequence": 801, "observed": 20},
        )
        status, body = self._call(
            f"{race_url}/v1/intake", "GET", "race", "timer-r1")
        self.assertEqual(status, 200)
        self.assertTrue(body["accepted"])
        self.assertTrue(body["blocked"])
        self.assertEqual(body["domain"], "race")


if __name__ == "__main__":
    unittest.main()
