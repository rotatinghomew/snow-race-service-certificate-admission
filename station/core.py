"""领域引擎：按已验证身份、用途、赛道与生效段裁决资料去向。

设计要点（对应赛务约定）：

* 一台物理设备可以有多个已登记采集实例，证书按实例标签登记，换证不改变
  实例的用途，练习实例不会因为换了正式标签的证书而变成正式实例。
* 生产授权（permit）绑定实例、赛道与含起点不含终点的生效段，不随设备名迁移。
* 证书有独立的签发事实与可查询状态；尚未确认何时签出的证书，不能把后来的
  签发结果倒推为之前已准许生产。
* 两个接入域（practice / race）有各自的信任材料与许可范围。
* 接收方把来件分成：已阻止、已受理但来源授权待复核、已稳固受理三类；
  同一业务序号只能入账一次，回执补查不是第二笔记录。
* 撤销错误生产资格后，该用途范围的新上传立即停止，同设备的练习资料不受影响。
* 证书切换成功与资料交接完毕是两个独立事实，分别报告。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
import json
from typing import Optional

# ---- 裁决原因（稳定字符串，测试与 CLI 都依赖） ----
ACCEPTED = "accepted"
REVIEW = "accepted_pending_review"
BLOCKED_WRONG_DOMAIN = "blocked_wrong_domain"
BLOCKED_UNREGISTERED = "blocked_unregistered_identity"
BLOCKED_TRUST = "blocked_untrusted_credential"
BLOCKED_NO_CERT = "blocked_certificate_not_issued"
BLOCKED_CERT_UNKNOWN = "blocked_certificate_issuance_unconfirmed"
BLOCKED_CERT_REVOKED = "blocked_certificate_revoked"
BLOCKED_NO_PERMIT = "blocked_no_permit"
BLOCKED_OUTSIDE_WINDOW = "blocked_outside_permit_window"
BLOCKED_QUARANTINED = "blocked_instance_quarantined"
BLOCKED_DUPLICATE = "blocked_duplicate_sequence"
BLOCKED_REVOKED_SCOPE = "blocked_scope_revoked"

BLOCKED = "blocked"

# 证书可查询状态
CERT_ISSUED = "issued"
CERT_UNKNOWN = "unknown"
CERT_REVOKED = "revoked"
CERT_NONE = "not_issued"


@dataclass
class Installation:
    device: str
    instance: str
    purpose: str          # practice / race
    cert_label: str
    observed: int
    quarantined: bool = False
    quarantine_at: Optional[int] = None

    def key(self) -> str:
        return self.instance


@dataclass
class Route:
    record_id: str
    domain: str
    cert_group: str
    tracks: list[str]
    instances: list[str] = field(default_factory=list)


@dataclass
class Permit:
    permit_ref: str
    instance: str
    tracks: list[str]
    valid_from: int
    valid_until: int
    route_id: str
    observed: int
    revoked_at: Optional[int] = None
    review_from: Optional[int] = None
    revoke_track: Optional[str] = None

    @property
    def live(self) -> bool:
        return self.revoked_at is None

    def covers(self, track: str, moment: int) -> bool:
        """含起点、不含终点的生效段。"""
        return (
            track in self.tracks
            and self.valid_from <= moment < self.valid_until
            and (self.revoke_track is None or self.revoke_track != track)
        )


@dataclass
class Booking:
    domain: str
    track: str
    sequence: int
    owner_instance: str
    owner_device: str
    owner_label: str
    record_id: str
    received_at: Optional[int]
    observed: int
    solid: bool
    reviewed: bool = False
    receipt_ref: Optional[str] = None
    permit_ref: Optional[str] = None

    def identity(self) -> dict:
        """已完成记录由哪个实例、哪个接收域入账的可解释信息。"""
        return {
            "domain": self.domain,
            "track": self.track,
            "sequence": self.sequence,
            "instance": self.owner_instance,
            "device": self.owner_device,
            "cert_label": self.owner_label,
            "record_id": self.record_id,
            "receipt": self.receipt_ref,
            "permit_ref": self.permit_ref,
            "solid": self.solid,
            "reviewed": self.reviewed,
        }


@dataclass
class IntakeItem:
    record_id: str
    kind: str
    domain: str
    track: Optional[str]
    sequence: Optional[int]
    instance: Optional[str]
    device: Optional[str]
    cert_label: Optional[str]
    observed: int
    status: str
    reason: str
    detail: dict = field(default_factory=dict)


@dataclass
class Probe:
    record_id: str
    domain: str
    cert_label: str
    instance: Optional[str]
    track: str
    observed: int
    tls_accepted: bool
    production_ready: bool
    reason: Optional[str]


class Trust:
    """信任材料接口：回答某个标签的真实 TLS 身份能否被某接入域接受。"""

    def verify(self, domain: str, group: str, cert_label: str) -> bool:
        raise NotImplementedError


class StaticTrust(Trust):
    """离线重放用：按证书组登记可信标签（来自本地信任清单）。"""

    def __init__(self, groups: Optional[dict[str, list[str]]] = None):
        self.groups = groups or {}

    def verify(self, domain: str, group: str, cert_label: str) -> bool:
        return cert_label in self.groups.get(group, [])


class FileTrust(Trust):
    """真实 mTLS 用：以接入域目录下的 CA 与证书文件为信任材料。"""

    def __init__(self, cert_dir: Path | str):
        self.cert_dir = Path(cert_dir)

    def verify(self, domain: str, group: str, cert_label: str) -> bool:
        folder = self.cert_dir / group
        return (folder / "ca.crt").is_file() and (folder / f"{cert_label}.crt").is_file()


class Station:
    """有状态的赛务裁决引擎。事件按观测时刻顺序送入。"""

    def __init__(self, trust: Optional[Trust] = None, now: Optional[int] = None):
        self.trust = trust or StaticTrust()
        self.now = now
        self.installations: dict[str, Installation] = {}
        self.routes: dict[str, Route] = {}
        self.routes_by_domain: dict[str, Route] = {}
        self.permits: list[Permit] = []
        # 证书状态：label -> 状态字典
        self.certificates: dict[str, dict] = {}
        self.bookings: dict[tuple[str, str, int], Booking] = {}
        self.intake: list[IntakeItem] = []
        self.probes: list[Probe] = []

    # ------------------------------------------------------------------ #
    # 状态持久化
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        return {
            "now": self.now,
            "installations": {k: asdict(v) for k, v in self.installations.items()},
            "routes": {k: asdict(v) for k, v in self.routes.items()},
            "permits": [asdict(p) for p in self.permits],
            "certificates": self.certificates,
            "bookings": {
                "|".join(str(part) for part in key): asdict(value)
                for key, value in self.bookings.items()
            },
            "intake": [asdict(item) for item in self.intake],
            "probes": [asdict(p) for p in self.probes],
        }

    @classmethod
    def from_dict(cls, data: dict, trust: Optional[Trust] = None) -> "Station":
        station = cls(trust=trust, now=data.get("now"))
        for raw in data["installations"].values():
            inst = Installation(**raw)
            station.installations[inst.instance] = inst
        for raw in data["routes"].values():
            route = Route(**raw)
            station.routes[route.record_id] = route
            station.routes_by_domain[route.domain] = route
        station.permits = [Permit(**raw) for raw in data["permits"]]
        station.certificates = dict(data["certificates"])
        for composite, raw in data["bookings"].items():
            domain, track, sequence = composite.split("|")
            station.bookings[(domain, track, int(sequence))] = Booking(**raw)
        station.intake = [IntakeItem(**raw) for raw in data["intake"]]
        station.probes = [Probe(**raw) for raw in data["probes"]]
        return station

    def save(self, path: Path | str) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: Path | str, trust: Optional[Trust] = None) -> "Station":
        return cls.from_dict(
            json.loads(Path(path).read_text(encoding="utf-8")), trust=trust
        )

    # ------------------------------------------------------------------ #
    # 登记与核准
    # ------------------------------------------------------------------ #
    def register(self, device: str, instance: str, purpose: str,
                 cert_label: str, observed: int) -> Installation:
        """登记员核实设备归属、实例用途与实际持有的密钥后登记实例。

        同一物理设备可以有多个实例；换证只改标签，不改变用途。
        """
        if instance in self.installations:
            current = self.installations[instance]
            current.cert_label = cert_label
            current.observed = observed
            return current
        installed = Installation(
            device=device, instance=instance, purpose=purpose,
            cert_label=cert_label, observed=observed,
        )
        self.installations[instance] = installed
        return installed

    def add_route(self, record_id: str, domain: str, cert_group: str,
                  tracks: list[str], instances: list[str]) -> Route:
        route = Route(
            record_id=record_id, domain=domain, cert_group=cert_group,
            tracks=list(tracks), instances=list(instances),
        )
        self.routes[record_id] = route
        self.routes_by_domain[domain] = route
        return route

    def add_permit(self, permit_ref: str, instance: str, tracks: list[str],
                   valid_from: int, valid_until: int, route_id: str,
                   observed: int) -> Permit:
        """赛事负责人对比赛日/赛道的独立生产确认。"""
        permit = Permit(
            permit_ref=permit_ref, instance=instance, tracks=list(tracks),
            valid_from=valid_from, valid_until=valid_until, route_id=route_id,
            observed=observed,
        )
        self.permits.append(permit)
        return permit

    def record_cert(self, label: str, state: str, observed: int,
                    issued_at: Optional[int] = None) -> dict:
        """登记证书签发端给出的实际证书状态。

        只有 observed 时刻已经确认的签发事实，在该时刻之后才可用；
        unknown 表示来源尚不能确认发生与否，不得据其准许生产。
        """
        current = self.certificates.get(label)
        if state == CERT_ISSUED:
            effective = issued_at if issued_at is not None else observed
            if current is None or current["state"] != CERT_ISSUED:
                self.certificates[label] = {
                    "state": CERT_ISSUED,
                    "issued_at": effective,
                    "observed_at": observed,
                }
            else:
                current["observed_at"] = observed
        elif state == CERT_REVOKED:
            self.certificates[label] = {
                "state": CERT_REVOKED,
                "issued_at": (current or {}).get("issued_at"),
                "observed_at": observed,
            }
        else:  # unknown：只登记查询结果，不产生签发事实
            self.certificates[label] = {
                "state": CERT_UNKNOWN,
                "issued_at": None,
                "observed_at": observed,
            }
        return self.certificates[label]

    def revoke(self, permit_ref: str, revoked_at: int,
               review_from: int, track: str) -> Optional[Permit]:
        """站点撤销错误的生产资格：该用途范围新上传立即停止。"""
        target = next((p for p in self.permits if p.permit_ref == permit_ref), None)
        if target is None:
            return None
        target.revoked_at = revoked_at
        target.review_from = review_from
        target.revoke_track = track
        # 撤销后隔离持错误资格的实例
        installation = self.installations.get(target.instance)
        if installation is not None and not installation.quarantined:
            installation.quarantined = True
            installation.quarantine_at = revoked_at
        # 已受理但落在复核起点之后的记录转入待复核
        for booking in self.bookings.values():
            if (
                booking.owner_instance == target.instance
                and booking.track == track
                and booking.received_at is not None
                and booking.received_at >= review_from
                and not booking.reviewed
            ):
                booking.solid = False
                booking.reviewed = True
        return target

    def quarantine(self, instance: str, observed: int) -> Optional[Installation]:
        """隔离单个实例，不影响同设备上其他实例与整个站点。"""
        installation = self.installations.get(instance)
        if installation is None:
            return None
        installation.quarantined = True
        installation.quarantine_at = observed
        return installation

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def cert_status(self, label: str) -> dict:
        return self.certificates.get(
            label, {"state": CERT_NONE, "issued_at": None, "observed_at": None}
        )

    def _route_for(self, domain: str) -> Optional[Route]:
        return self.routes_by_domain.get(domain)

    def _active_permit(self, instance: str, track: str,
                       moment: int) -> Optional[Permit]:
        candidates = [
            p for p in self.permits
            if p.instance == instance and p.live and p.covers(track, moment)
        ]
        return candidates[0] if candidates else None

    def probe_connectivity(self, record_id: str, domain: str, cert_label: str,
                           track: str, observed: int,
                           tls_accepted: Optional[bool] = None) -> Probe:
        """新实例对目标入口的可用性验证。TLS 通过不等于生产可用。"""
        route = self._route_for(domain)
        instance = next(
            (i for i in self.installations.values() if i.cert_label == cert_label),
            None,
        )
        if route is None:
            trusted = False
        else:
            trusted = self.trust.verify(domain, route.cert_group, cert_label)
        if tls_accepted is None:
            tls_accepted = trusted
        ready = False
        reason: Optional[str] = None
        if not tls_accepted:
            reason = BLOCKED_TRUST
        elif instance is None:
            reason = BLOCKED_UNREGISTERED
        elif instance.purpose != domain:
            reason = BLOCKED_WRONG_DOMAIN
        else:
            cert = self.cert_status(cert_label)
            if cert["state"] == CERT_UNKNOWN:
                reason = BLOCKED_CERT_UNKNOWN
            elif cert["state"] == CERT_REVOKED:
                reason = BLOCKED_CERT_REVOKED
            elif cert["state"] == CERT_NONE and instance.observed > observed:
                reason = BLOCKED_NO_CERT
            elif (
                cert["state"] == CERT_ISSUED
                and cert.get("issued_at") is not None
                and cert["issued_at"] > observed
            ):
                reason = BLOCKED_NO_CERT
            elif domain == "race":
                permit = self._active_permit(instance.instance, track, observed)
                if permit is None:
                    reason = BLOCKED_NO_PERMIT
                elif instance.quarantined:
                    reason = BLOCKED_QUARANTINED
                else:
                    ready = True
            else:
                ready = not instance.quarantined
                if instance.quarantined:
                    reason = BLOCKED_QUARANTINED
        probe = Probe(
            record_id=record_id, domain=domain, cert_label=cert_label,
            instance=instance.instance if instance else None, track=track,
            observed=observed, tls_accepted=bool(tls_accepted),
            production_ready=ready, reason=reason,
        )
        self.probes.append(probe)
        return probe

    # ------------------------------------------------------------------ #
    # 收件裁决
    # ------------------------------------------------------------------ #
    def _admit(self, domain: str, track: str, sequence: int, instance_hint: Optional[str],
               cert_label: Optional[str], observed: int, moment: int,
               record_id: str, receipt_ref: Optional[str]) -> tuple[str, str, dict]:
        """核心裁决，返回 (status, reason, detail)。"""
        route = self._route_for(domain)
        if route is None:
            return BLOCKED, BLOCKED_NO_PERMIT, {"note": "接入域未配置"}
        instance = (
            self.installations.get(instance_hint)
            if instance_hint
            else next(
                (i for i in self.installations.values() if i.cert_label == cert_label),
                None,
            )
        )
        if instance is None:
            return BLOCKED, BLOCKED_UNREGISTERED, {"cert_label": cert_label}
        # 先看真实 TLS 身份能否链到本接入域信任根
        if not self.trust.verify(domain, route.cert_group, instance.cert_label):
            return BLOCKED, BLOCKED_TRUST, {
                "cert_group": route.cert_group,
                "cert_label": instance.cert_label,
            }
        # 再看实例登记用途是否与接入域一致：换证不改变用途
        if instance.purpose != domain:
            return BLOCKED, BLOCKED_WRONG_DOMAIN, {
                "instance_purpose": instance.purpose, "domain": domain,
            }
        if instance.quarantined:
            return BLOCKED, BLOCKED_QUARANTINED, {"instance": instance.instance}

        cert = self.cert_status(instance.cert_label)
        if cert["state"] == CERT_REVOKED:
            return BLOCKED, BLOCKED_CERT_REVOKED, {}
        if cert["state"] == CERT_UNKNOWN:
            # 来源尚未确认何时签出，不得准许生产
            return BLOCKED, BLOCKED_CERT_UNKNOWN, {}
        if cert["state"] == CERT_NONE:
            # 签发端没有回执：若真实 TLS 身份能链到本域信任根且登记在先，
            # 以登记观测时刻作为本地持有的证书事实；否则视为无证书。
            if instance.observed > moment:
                return BLOCKED, BLOCKED_NO_CERT, {}
            effective_issued_at = instance.observed
        else:
            # 不能把后来的签发结果倒推为之前已准许
            if cert["issued_at"] is not None and cert["issued_at"] > moment:
                return BLOCKED, BLOCKED_NO_CERT, {
                    "issued_at": cert["issued_at"], "moment": moment,
                }
            effective_issued_at = cert["issued_at"]

        permit = None
        if domain == "race":
            permit = self._active_permit(instance.instance, track, moment)
            if permit is None:
                # 区分：生效段不符、范围已撤销、根本没有许可
                track_permits = [
                    p for p in self.permits
                    if p.instance == instance.instance and track in p.tracks
                ]
                if any(not p.live and p.revoke_track == track for p in track_permits):
                    return BLOCKED, BLOCKED_REVOKED_SCOPE, {}
                if track_permits:
                    return BLOCKED, BLOCKED_OUTSIDE_WINDOW, {
                        "moment": moment,
                        "windows": [
                            {"from": p.valid_from, "until": p.valid_until}
                            for p in track_permits
                        ],
                    }
                return BLOCKED, BLOCKED_NO_PERMIT, {}

        # 同一接收域+赛道+序号只能入账一次
        key = (domain, track, sequence)
        existing = self.bookings.get(key)
        if existing is not None:
            return BLOCKED, BLOCKED_DUPLICATE, {
                "owner_instance": existing.owner_instance,
                "owner_record": existing.record_id,
            }

        detail = {
            "instance": instance.instance,
            "device": instance.device,
            "cert_label": instance.cert_label,
            "cert_issued_at": effective_issued_at,
        }
        if permit is not None:
            detail["permit_ref"] = permit.permit_ref
            # 撤销复核：许可后来被撤销，且来件落在复核起点之后
            if (
                not permit.live
                and permit.review_from is not None
                and moment >= permit.review_from
            ):
                detail["review_from"] = permit.review_from
                return REVIEW, REVIEW, detail
        return ACCEPTED, ACCEPTED, detail

    def consider_sample(self, record_id: str, domain: str, track: str, sequence: int,
                        observed: int, moment: int,
                        instance: Optional[str] = None,
                        cert_label: Optional[str] = None,
                        receipt_ref: Optional[str] = None) -> IntakeItem:
        """接收方对一份来件做裁决并登记收件事实。"""
        status, reason, detail = self._admit(
            domain, track, sequence, instance, cert_label,
            observed, moment, record_id, receipt_ref,
        )
        owner = self.installations.get(detail.get("instance", "")) if status != BLOCKED else None
        if status != BLOCKED:
            booking = Booking(
                domain=domain, track=track, sequence=sequence,
                owner_instance=owner.instance, owner_device=owner.device,
                owner_label=owner.cert_label, record_id=record_id,
                received_at=moment, observed=observed,
                solid=(status == ACCEPTED),
                receipt_ref=receipt_ref,
                permit_ref=detail.get("permit_ref"),
            )
            self.bookings[(domain, track, sequence)] = booking
        item = IntakeItem(
            record_id=record_id, kind="sample", domain=domain, track=track,
            sequence=sequence,
            instance=owner.instance if owner else instance,
            device=owner.device if owner else None,
            cert_label=owner.cert_label if owner else cert_label,
            observed=observed, status=status, reason=reason, detail=detail,
        )
        self.intake.append(item)
        return item

    def consider_receipt(self, record_id: str, domain: str, track: str, sequence: int,
                         observed: int, receipt_ref: str,
                         state: str, received_at: Optional[int],
                         instance: Optional[str] = None,
                         cert_label: Optional[str] = None) -> IntakeItem:
        """回执/补查处理。

        已合法受理的序号可带回执补查，不产生第二笔；第二个实例重收会被拒。
        unknown 表示来源尚不能确认，先挂待确认占位，由后来的回执补齐。
        """
        key = (domain, track, sequence)
        existing = self.bookings.get(key)
        if state == "unknown":
            if existing is not None:
                item = IntakeItem(
                    record_id=record_id, kind="receipt", domain=domain, track=track,
                    sequence=sequence, instance=existing.owner_instance,
                    device=existing.owner_device, cert_label=existing.owner_label,
                    observed=observed, status=BLOCKED, reason=BLOCKED_DUPLICATE,
                    detail={"owner_record": existing.record_id},
                )
                self.intake.append(item)
                return item
            # 占位：来源尚未确认发生与否，先挂待确认
            inst = self.installations.get(instance) if instance else None
            booking = Booking(
                domain=domain, track=track, sequence=sequence,
                owner_instance=instance or "",
                owner_device=inst.device if inst else "",
                owner_label=(inst.cert_label if inst else (cert_label or "")),
                record_id=record_id, received_at=None, observed=observed,
                solid=False, receipt_ref=receipt_ref,
            )
            self.bookings[key] = booking
            item = IntakeItem(
                record_id=record_id, kind="receipt", domain=domain, track=track,
                sequence=sequence, instance=instance,
                device=inst.device if inst else None,
                cert_label=booking.owner_label, observed=observed,
                status=REVIEW, reason=REVIEW, detail={"awaiting": "receipt_confirmation"},
            )
            self.intake.append(item)
            return item

        # 明确回执
        if existing is None:
            # 之前没有任何记录：按完整来件裁决
            return self.consider_sample(
                record_id, domain, track, sequence, observed,
                received_at if received_at is not None else observed,
                instance=instance, cert_label=cert_label, receipt_ref=receipt_ref,
            )
        # 同一实例的回执补查：补齐实际收到时间，不是新记录。
        # 占位记录（来源曾为 unknown）尚无确定 owner 时，首个回执即补齐它。
        if (
            instance is not None
            and existing.owner_instance
            and existing.owner_instance != instance
        ):
            # 第二个实例不能把同一序号重新收成自己的一笔
            item = IntakeItem(
                record_id=record_id, kind="receipt", domain=domain, track=track,
                sequence=sequence, instance=instance, device=None,
                cert_label=cert_label, observed=observed,
                status=BLOCKED, reason=BLOCKED_DUPLICATE,
                detail={
                    "owner_instance": existing.owner_instance,
                    "owner_record": existing.record_id,
                },
            )
            self.intake.append(item)
            return item
        existing.received_at = received_at
        if not existing.owner_instance and instance is not None:
            inst = self.installations.get(instance)
            existing.owner_instance = instance
            if inst is not None:
                existing.owner_device = inst.device
                existing.owner_label = inst.cert_label
        existing.solid = True
        # 复核状态保留：已转入复核的记录不因回执到达自动变稳固
        if existing.reviewed:
            existing.solid = False
        item = IntakeItem(
            record_id=record_id, kind="receipt", domain=domain, track=track,
            sequence=sequence, instance=existing.owner_instance,
            device=existing.owner_device, cert_label=existing.owner_label,
            observed=observed,
            status=REVIEW if existing.reviewed else ACCEPTED,
            reason=REVIEW if existing.reviewed else ACCEPTED,
            detail={"backfill": True, "owner_record": existing.record_id},
        )
        self.intake.append(item)
        return item

    # ------------------------------------------------------------------ #
    # 分类视图与交接
    # ------------------------------------------------------------------ #
    def blocked_items(self, domain: Optional[str] = None) -> list[dict]:
        return [
            asdict(item) for item in self.intake
            if item.status == BLOCKED and (domain is None or item.domain == domain)
        ]

    def review_items(self, domain: Optional[str] = None) -> list[dict]:
        return [
            asdict(item) for item in self.intake
            if item.status == REVIEW and (domain is None or item.domain == domain)
        ]

    def accepted_items(self, domain: Optional[str] = None) -> list[dict]:
        return [
            asdict(item) for item in self.intake
            if item.status == ACCEPTED and (domain is None or item.domain == domain)
        ]

    def ledger(self, domain: Optional[str] = None) -> list[dict]:
        """入账账本：每个序号由哪个实例、哪个接收域入账。"""
        bookings = sorted(
            self.bookings.values(),
            key=lambda b: (b.domain, b.track, b.sequence),
        )
        return [
            b.identity() for b in bookings
            if domain is None or b.domain == domain
        ]

    def handover_report(self, device: str) -> dict:
        """证书切换与资料交接两个事实分别报告。"""
        instances = [
            i for i in self.installations.values() if i.device == device
        ]
        race_instances = [i for i in instances if i.purpose == "race"]
        # 旧实例：被撤销/隔离的那台；新实例：同设备仍活跃的 race 实例
        revoked = [i for i in race_instances if i.quarantined]
        active = [i for i in race_instances if not i.quarantined]
        old_instance = revoked[0] if revoked else (
            min(race_instances, key=lambda i: i.observed) if len(race_instances) > 1 else None
        )
        new_instance = active[0] if active else (
            max(race_instances, key=lambda i: i.observed) if len(race_instances) > 1 else None
        )

        def cert_switched(inst: Optional[Installation]) -> bool:
            if inst is None:
                return False
            status = self.cert_status(inst.cert_label)
            return status["state"] == CERT_ISSUED

        new_ready = False
        probe_at = None
        if new_instance is not None:
            passed = [
                p for p in self.probes
                if p.cert_label == new_instance.cert_label and p.tls_accepted
            ]
            if passed:
                probe_at = min(p.observed for p in passed)
                new_ready = any(p.production_ready for p in passed)

        pending_old: list[dict] = []
        if old_instance is not None:
            pending_old = [
                b.identity() for b in self.bookings.values()
                if b.owner_instance == old_instance.instance and not b.solid
            ]
        handover_done = (
            old_instance is not None
            and new_instance is not None
            and new_ready
            and not pending_old
        )
        return {
            "device": device,
            "old_instance": old_instance.instance if old_instance else None,
            "new_instance": new_instance.instance if new_instance else None,
            "certificate_switched": cert_switched(new_instance),
            "new_instance_probe_at": probe_at,
            "new_instance_production_ready": new_ready,
            "old_pending_records": pending_old,
            "handover_complete": handover_done,
        }
