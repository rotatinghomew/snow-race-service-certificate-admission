"""领域引擎规则测试：用途隔离、签发状态、收件分类与交接。"""
import unittest

from station.core import (
    Station, StaticTrust,
    ACCEPTED, REVIEW, BLOCKED,
    BLOCKED_WRONG_DOMAIN, BLOCKED_TRUST, BLOCKED_NO_CERT,
    BLOCKED_CERT_UNKNOWN, BLOCKED_CERT_REVOKED, BLOCKED_NO_PERMIT,
    BLOCKED_OUTSIDE_WINDOW, BLOCKED_DUPLICATE, BLOCKED_REVOKED_SCOPE,
    BLOCKED_QUARANTINED, CERT_ISSUED, CERT_UNKNOWN, CERT_REVOKED,
)
from station.replay import replay_file, DEFAULT_GROUPS


class FixtureReplay(unittest.TestCase):
    def setUp(self):
        self.station = replay_file("data")

    def test_eight_intake_facts_match_story(self):
        by_id = {item.record_id: item for item in self.station.intake}
        self.assertEqual(by_id["try-441"].status, ACCEPTED)
        self.assertEqual(by_id["official-441"].status, ACCEPTED)
        self.assertEqual(by_id["official-442-unknown"].status, REVIEW)
        self.assertEqual(by_id["r2-premature"].status, BLOCKED)
        self.assertEqual(by_id["r2-premature"].reason, BLOCKED_OUTSIDE_WINDOW)
        self.assertEqual(by_id["official-442-late"].status, ACCEPTED)
        self.assertEqual(by_id["official-442-late"].detail["backfill"], True)
        self.assertEqual(by_id["r2-retry"].status, BLOCKED)
        self.assertEqual(by_id["r2-retry"].reason, BLOCKED_DUPLICATE)
        self.assertEqual(by_id["other-track"].status, ACCEPTED)
        self.assertEqual(by_id["try-445"].status, ACCEPTED)

    def test_three_buckets(self):
        blocked = {item.record_id for item in self.station.intake if item.status == BLOCKED}
        review = {item.record_id for item in self.station.intake if item.status == REVIEW}
        accepted = {item.record_id for item in self.station.intake if item.status == ACCEPTED}
        self.assertEqual(blocked, {"r2-premature", "r2-retry"})
        self.assertEqual(review, {"official-442-unknown"})
        self.assertEqual(accepted, {
            "try-441", "official-441", "official-442-late", "other-track", "try-445",
        })

    def test_sequence_booked_once_with_owner_identity(self):
        north = [
            b for b in self.station.bookings.values()
            if b.domain == "race" and b.track == "north"
        ]
        seq442 = [b for b in north if b.sequence == 442]
        self.assertEqual(len(seq442), 1)
        booking = seq442[0]
        self.assertEqual(booking.owner_instance, "r-164")
        self.assertEqual(booking.receipt_ref, "N-442")
        self.assertEqual(booking.record_id, "official-442-unknown")

    def test_same_sequence_other_track_is_independent_record(self):
        south = self.station.bookings[("race", "south", 442)]
        self.assertEqual(south.owner_instance, "r-301")
        self.assertTrue(south.solid)

    def test_revocation_moves_older_receipt_into_review_and_blocks_new(self):
        # N-442 实际收到于 33，复核起点 31：转入待复核
        booking = self.station.bookings[("race", "north", 442)]
        self.assertTrue(booking.reviewed)
        self.assertFalse(booking.solid)
        # 撤销后该用途范围新上传停止（实例已隔离，先报隔离原因）
        item = self.station.consider_sample(
            "after-revoke", "race", "north", 500, observed=80, moment=80,
            instance="r-164",
        )
        self.assertEqual(item.status, BLOCKED)
        self.assertIn(item.reason, (BLOCKED_QUARANTINED, BLOCKED_REVOKED_SCOPE))
        # 直接核验：许可范围已撤销，隔离解除后仍被范围撤销拦截
        self.station.installations["r-164"].quarantined = False
        scoped = self.station.consider_sample(
            "after-revoke-2", "race", "north", 501, observed=81, moment=81,
            instance="r-164",
        )
        self.assertEqual(scoped.reason, BLOCKED_REVOKED_SCOPE)
        # 同设备练习资料仍有独立依据
        practice = self.station.consider_sample(
            "practice-continues", "practice", "north", 501,
            observed=80, moment=80, instance="p-361",
        )
        self.assertEqual(practice.status, ACCEPTED)

    def test_handover_separates_switch_and_completion(self):
        report = self.station.handover_report("timer-81")
        self.assertTrue(report["certificate_switched"])
        self.assertFalse(report["handover_complete"])
        self.assertEqual(report["old_instance"], "r-164")
        self.assertEqual(report["new_instance"], "r-189")
        # N-442 补齐回执后因撤销复核仍挂起，交接未完成
        self.assertEqual(len(report["old_pending_records"]), 1)

    def test_probe_tls_ok_but_not_production_ready_before_permit(self):
        probe = self.station.probes[0]
        self.assertTrue(probe.tls_accepted)
        self.assertFalse(probe.production_ready)
        self.assertEqual(probe.reason, BLOCKED_NO_PERMIT)


class PurposeIsolation(unittest.TestCase):
    def _station(self):
        station = Station(StaticTrust(DEFAULT_GROUPS))
        station.register("dev-1", "prac-1", "practice", "timer-p1", observed=0)
        station.register("dev-1", "race-1", "race", "timer-r1", observed=0)
        station.add_route("route-p", "practice", "practice", ["north"], ["prac-1"])
        station.add_route("route-r", "race", "race", ["north"], ["race-1"])
        station.record_cert("timer-p1", CERT_ISSUED, observed=1, issued_at=1)
        station.record_cert("timer-r1", CERT_ISSUED, observed=1, issued_at=1)
        station.add_permit("perm/1", "race-1", ["north"], 0, 100, "route-r", observed=1)
        return station

    def test_relabel_does_not_promote_practice_instance(self):
        station = self._station()
        # 给练习实例换发一张正式域标签的证书：用途不变
        station.register("dev-1", "prac-1", "practice", "timer-r2", observed=2)
        item = station.consider_sample(
            "sneak", "race", "north", 1, observed=3, moment=3, instance="prac-1",
        )
        self.assertEqual(item.status, BLOCKED)
        self.assertEqual(item.reason, BLOCKED_WRONG_DOMAIN)
        # 练习通道只接受练习信任根下的身份；正式标签在练习域同样不可信
        cross = station.consider_sample(
            "cross-practice", "practice", "north", 1,
            observed=3, moment=3, instance="prac-1",
        )
        self.assertEqual(cross.reason, BLOCKED_TRUST)
        # 把标签换回练习域，练习进程照常运行
        station.register("dev-1", "prac-1", "practice", "timer-p1", observed=4)
        ok = station.consider_sample(
            "fine", "practice", "north", 1, observed=5, moment=5, instance="prac-1",
        )
        self.assertEqual(ok.status, ACCEPTED)

    def test_practice_cert_cannot_enter_race_domain(self):
        station = self._station()
        item = station.consider_sample(
            "cross", "race", "north", 2, observed=3, moment=3,
            cert_label="timer-p1",
        )
        # timer-p1 链不到 race 信任根
        self.assertEqual(item.reason, BLOCKED_TRUST)

    def test_other_device_instance_isolation(self):
        station = self._station()
        station.quarantine("race-1", observed=5)
        item = station.consider_sample(
            "q", "race", "north", 3, observed=6, moment=6, instance="race-1",
        )
        self.assertEqual(item.reason, BLOCKED_QUARANTINED)
        # 练习实例不受影响
        ok = station.consider_sample(
            "p", "practice", "north", 3, observed=6, moment=6, instance="prac-1",
        )
        self.assertEqual(ok.status, ACCEPTED)


class CertificateTiming(unittest.TestCase):
    def _station(self):
        station = Station(StaticTrust(DEFAULT_GROUPS))
        station.register("dev-2", "race-2", "race", "timer-r2", observed=0)
        station.add_route("route-r", "race", "race", ["north"], ["race-2"])
        station.add_permit("perm/2", "race-2", ["north"], 0, 100, "route-r", observed=1)
        return station

    def test_unknown_issuance_blocks_production(self):
        station = self._station()
        station.record_cert("timer-r2", CERT_UNKNOWN, observed=10)
        item = station.consider_sample(
            "early", "race", "north", 1, observed=12, moment=12, instance="race-2",
        )
        self.assertEqual(item.reason, BLOCKED_CERT_UNKNOWN)

    def test_late_issuance_is_not_backdated(self):
        station = self._station()
        station.record_cert("timer-r2", CERT_UNKNOWN, observed=10)
        station.record_cert("timer-r2", CERT_ISSUED, observed=41, issued_at=40)
        # 时刻 35 的来件：证书当时尚未查清签出，不能准许
        early = station.consider_sample(
            "early", "race", "north", 1, observed=35, moment=35, instance="race-2",
        )
        self.assertEqual(early.status, BLOCKED)
        # 时刻 45 再来：签发已确认且生效段覆盖，可受理
        late = station.consider_sample(
            "late", "race", "north", 2, observed=45, moment=45, instance="race-2",
        )
        self.assertEqual(late.status, ACCEPTED)

    def test_revoked_certificate_blocks(self):
        station = self._station()
        station.record_cert("timer-r2", CERT_ISSUED, observed=5, issued_at=5)
        station.record_cert("timer-r2", CERT_REVOKED, observed=30)
        item = station.consider_sample(
            "dead", "race", "north", 1, observed=31, moment=31, instance="race-2",
        )
        self.assertEqual(item.reason, BLOCKED_CERT_REVOKED)


class DuplicateAndReceipts(unittest.TestCase):
    def _station(self):
        station = Station(StaticTrust(DEFAULT_GROUPS))
        station.register("dev-3", "race-a", "race", "timer-r1", observed=0)
        station.register("dev-3", "race-b", "race", "timer-r2", observed=0)
        station.add_route("route-r", "race", "race", ["north"], ["race-a", "race-b"])
        station.record_cert("timer-r1", CERT_ISSUED, observed=1, issued_at=1)
        station.record_cert("timer-r2", CERT_ISSUED, observed=1, issued_at=1)
        station.add_permit("perm/a", "race-a", ["north"], 0, 100, "route-r", observed=1)
        station.add_permit("perm/b", "race-b", ["north"], 0, 100, "route-r", observed=1)
        return station

    def test_second_instance_cannot_rebook_same_sequence(self):
        station = self._station()
        first = station.consider_sample(
            "first", "race", "north", 90, observed=10, moment=10, instance="race-a",
        )
        self.assertEqual(first.status, ACCEPTED)
        second = station.consider_sample(
            "second", "race", "north", 90, observed=11, moment=11, instance="race-b",
        )
        self.assertEqual(second.reason, BLOCKED_DUPLICATE)
        self.assertEqual(second.detail["owner_instance"], "race-a")
        self.assertEqual(len(station.bookings), 1)

    def test_unknown_then_receipt_is_one_booking(self):
        station = self._station()
        pending = station.consider_receipt(
            "n-1", "race", "north", 91, observed=20, receipt_ref="N-91",
            state="unknown", received_at=None, instance="race-a",
        )
        self.assertEqual(pending.status, REVIEW)
        backfill = station.consider_receipt(
            "n-1b", "race", "north", 91, observed=40, receipt_ref="N-91",
            state="received", received_at=22, instance="race-a",
        )
        self.assertEqual(backfill.status, ACCEPTED)
        self.assertTrue(backfill.detail["backfill"])
        booking = station.bookings[("race", "north", 91)]
        self.assertEqual(booking.received_at, 22)
        self.assertTrue(booking.solid)
        self.assertEqual(len(station.bookings), 1)

    def test_other_instance_receipt_rejected(self):
        station = self._station()
        station.consider_receipt(
            "n-2", "race", "north", 92, observed=20, receipt_ref="N-92",
            state="unknown", received_at=None, instance="race-a",
        )
        stolen = station.consider_receipt(
            "n-2x", "race", "north", 92, observed=21, receipt_ref="N-92",
            state="received", received_at=21, instance="race-b",
        )
        self.assertEqual(stolen.reason, BLOCKED_DUPLICATE)


class WindowAndPermits(unittest.TestCase):
    def test_half_open_window(self):
        station = Station(StaticTrust(DEFAULT_GROUPS))
        station.register("dev-4", "race-4", "race", "timer-r3", observed=0)
        station.add_route("route-r", "race", "race", ["north"], ["race-4"])
        station.record_cert("timer-r3", CERT_ISSUED, observed=1, issued_at=1)
        station.add_permit("perm/4", "race-4", ["north"], 10, 20, "route-r", observed=1)
        inside = station.consider_sample(
            "in", "race", "north", 1, observed=10, moment=10, instance="race-4",
        )
        self.assertEqual(inside.status, ACCEPTED)  # 含起点
        outside = station.consider_sample(
            "out", "race", "north", 2, observed=20, moment=20, instance="race-4",
        )
        self.assertEqual(outside.reason, BLOCKED_OUTSIDE_WINDOW)  # 不含终点

    def test_no_permit_vs_wrong_track(self):
        station = Station(StaticTrust(DEFAULT_GROUPS))
        station.register("dev-5", "race-5", "race", "timer-r3", observed=0)
        station.add_route("route-r", "race", "race", ["north", "south"], ["race-5"])
        station.record_cert("timer-r3", CERT_ISSUED, observed=1, issued_at=1)
        station.add_permit("perm/5", "race-5", ["north"], 0, 100, "route-r", observed=1)
        south = station.consider_sample(
            "s", "race", "south", 1, observed=10, moment=10, instance="race-5",
        )
        self.assertEqual(south.reason, BLOCKED_NO_PERMIT)


if __name__ == "__main__":
    unittest.main()
