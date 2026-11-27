"""值班 CLI 端到端测试：登记、试用、转正、隔离与重放。"""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from station.ops import build_parser, main


class CliWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="station-cli-"))
        self.state = self.tmp / "station.json"
        self.parser = build_parser()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *argv) -> dict:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main(["--state-file", str(self.state), *argv])
        return json.loads(buffer.getvalue())

    def test_register_trial_promote_quarantine_workflow(self):
        # 1) 登记：同设备两个实例，练习与正式用途分开
        out = self._run(
            "register", "--device", "timer-9", "--instance", "p-9",
            "--purpose", "practice", "--cert-label", "timer-p1",
        )
        self.assertEqual(out["registered"]["purpose"], "practice")
        self._run(
            "register", "--device", "timer-9", "--instance", "r-9",
            "--purpose", "race", "--cert-label", "timer-r2",
        )
        self._run(
            "route", "--route-id", "route-r", "--domain", "race",
            "--cert-group", "race", "--tracks", "north",
            "--instances", "r-9",
        )
        self._run(
            "route", "--route-id", "route-p", "--domain", "practice",
            "--cert-group", "practice", "--tracks", "north",
            "--instances", "p-9",
        )

        # 2) 试用：证书签发状态未确认，探测可 TLS 但不能生产
        self._run(
            "cert", "--label", "timer-r2", "--state", "unknown",
            "--observed", "5",
        )
        probe = self._run(
            "probe", "--domain", "race", "--cert-label", "timer-r2",
            "--track", "north", "--observed", "8",
        )["probe"]
        self.assertTrue(probe["tls_accepted"])
        self.assertFalse(probe["production_ready"])

        # 3) 转正：签发确认 + 赛事负责人独立许可，探测生产就绪
        self._run(
            "cert", "--label", "timer-r2", "--state", "issued",
            "--observed", "20", "--issued-at", "20",
        )
        self._run(
            "permit", "--permit-ref", "perm/9", "--instance", "r-9",
            "--tracks", "north", "--start", "20", "--until", "90",
            "--route", "route-r", "--observed", "20",
        )
        probe2 = self._run(
            "probe", "--record-id", "probe-2", "--domain", "race",
            "--cert-label", "timer-r2", "--track", "north",
            "--observed", "25",
        )["probe"]
        self.assertTrue(probe2["production_ready"])

        # 正式资料可进正式入口
        uploaded = self._run(
            "upload", "--record-id", "up-1", "--domain", "race",
            "--track", "north", "--sequence", "1", "--observed", "30",
            "--instance", "r-9",
        )["intake"]
        self.assertEqual(uploaded["status"], "accepted")

        # 4) 隔离：只停 r-9，练习实例 p-9 照常收件
        self._run("quarantine", "--instance", "r-9", "--observed", "40")
        blocked = self._run(
            "upload", "--record-id", "up-2", "--domain", "race",
            "--track", "north", "--sequence", "2", "--observed", "41",
            "--instance", "r-9",
        )["intake"]
        self.assertEqual(blocked["reason"], "blocked_instance_quarantined")
        practice = self._run(
            "upload", "--record-id", "up-p", "--domain", "practice",
            "--track", "north", "--sequence", "1", "--observed", "42",
            "--instance", "p-9",
        )["intake"]
        self.assertEqual(practice["status"], "accepted")

        # 账本可解释每笔由哪个实例、哪个域入账
        ledger = self._run("ledger")["ledger"]
        owners = {(e["domain"], e["sequence"]): e["instance"] for e in ledger}
        self.assertEqual(owners[("race", 1)], "r-9")
        self.assertEqual(owners[("practice", 1)], "p-9")

    def test_replay_command_reconstructs_fixture(self):
        out = self._run("replay", "--data", "data")
        self.assertEqual(out["bookings"], 5)
        self.assertEqual(out["blocked"], 2)
        self.assertEqual(out["pending_review"], 1)
        self.assertEqual(out["accepted"], 5)
        # 重放后状态查询可用，且按域过滤
        race_status = self._run("status", "--domain", "race")["intake"]
        self.assertTrue(race_status["blocked"])
        practice_status = self._run("status", "--domain", "practice")["intake"]
        self.assertEqual(len(practice_status["blocked"]), 0)

    def test_handover_command_reports_two_facts(self):
        self._run("replay", "--data", "data")
        report = self._run("handover", "--device", "timer-81")
        self.assertTrue(report["certificate_switched"])
        self.assertFalse(report["handover_complete"])
        self.assertEqual(report["new_instance"], "r-189")

    def test_revoke_command_stops_scope(self):
        self._run("replay", "--data", "data")
        self._run(
            "revoke", "--permit-ref", "perm/39", "--track", "south",
            "--observed", "100", "--review-from", "90",
        )
        # 撤销同时隔离持错误资格的实例：新上传先被隔离拦截
        out = self._run(
            "upload", "--record-id", "post-revoke", "--domain", "race",
            "--track", "south", "--sequence", "999", "--observed", "101",
            "--instance", "r-301",
        )["intake"]
        self.assertEqual(out["reason"], "blocked_instance_quarantined")
        # 站点范围层面的撤销事实独立存在：解除隔离后仍被范围撤销拦截
        from station.core import Station
        station = Station.load(self.state)
        station.installations["r-301"].quarantined = False
        station.save(self.state)
        scoped = self._run(
            "upload", "--record-id", "post-revoke-2", "--domain", "race",
            "--track", "south", "--sequence", "998", "--observed", "102",
            "--instance", "r-301",
        )["intake"]
        self.assertEqual(scoped["reason"], "blocked_scope_revoked")


if __name__ == "__main__":
    unittest.main()
