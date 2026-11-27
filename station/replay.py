"""把合作方资料端的来件按观测时刻重放进裁决引擎。"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .core import (
    Station, StaticTrust, FileTrust, Trust,
)

# 本地演练信任清单：两个接入域各自的信任根与标签
DEFAULT_GROUPS = {
    "practice": ["timer-p1"],
    "race": ["timer-r1", "timer-r2", "timer-r3"],
}


def trust_from_dir(cert_dir: Path | str) -> FileTrust:
    return FileTrust(cert_dir)


def replay(records: list[dict], trust: Optional[Trust] = None,
           station: Optional[Station] = None) -> Station:
    """按观测顺序处理全部来件，返回处理完的站点引擎。"""
    engine = station or Station(trust=trust or StaticTrust(DEFAULT_GROUPS))
    # record_id -> record，便于解析 relates_to
    by_id = {row["record_id"]: row for row in records}

    def related(row, source: str, kind: str) -> list[dict]:
        return [
            by_id[ref] for ref in row["relates_to"]
            if ref in by_id and by_id[ref]["source"] == source
            and by_id[ref]["kind"] == kind
        ]

    def instance_of(row) -> Optional[str]:
        """找到来件关联的登记实例，直接关联优先，再沿链传递回退。

        沿链搜索时每一层都先看登记记录，避免被证书/许可的旁路关联带偏。
        """
        direct = related(row, "registry", "installation")
        if direct:
            return direct[0]["payload"]["instance"]
        seen: set[str] = set()
        queue = list(row["relates_to"])
        while queue:
            ref = queue.pop(0)
            if ref in seen or ref not in by_id:
                continue
            seen.add(ref)
            candidate = by_id[ref]
            if candidate["kind"] == "installation":
                return candidate["payload"]["instance"]
            # 登记记录优先，其余关联按原顺序继续
            queue.extend(candidate["relates_to"])
        return None

    for row in records:
        observed = row["observed"]
        engine.now = observed
        payload = row["payload"]
        kind = row["kind"]
        source = row["source"]

        if kind == "installation":
            engine.register(
                device=payload["device"], instance=payload["instance"],
                purpose=payload["purpose"], cert_label=payload["cert_label"],
                observed=observed,
            )
            continue

        if kind == "receiver":
            instances = []
            for ref in row["relates_to"]:
                earlier = by_id.get(ref)
                if earlier and earlier["kind"] == "installation":
                    instances.append(earlier["payload"]["instance"])
            engine.add_route(
                record_id=row["record_id"], domain=payload["domain"],
                cert_group=payload["cert_group"], tracks=payload["tracks"],
                instances=instances,
            )
            continue

        if kind == "permit":
            install = related(row, "registry", "installation")
            target = install[0]["payload"]["instance"] if install else None
            route = related(row, "authority", "receiver")
            route_id = route[0]["record_id"] if route else ""
            engine.add_permit(
                permit_ref=payload["permit_ref"], instance=target,
                tracks=payload["tracks"], valid_from=payload["from"],
                valid_until=payload["until"], route_id=route_id,
                observed=observed,
            )
            continue

        if kind == "certificate":
            engine.record_cert(
                label=payload["label"], state=payload["state"],
                observed=observed, issued_at=payload.get("issued_at"),
            )
            continue

        if kind == "revoke":
            permit_rows = related(row, "authority", "permit")
            if permit_rows:
                engine.revoke(
                    permit_ref=permit_rows[0]["payload"]["permit_ref"],
                    revoked_at=payload["revoked_at"],
                    review_from=payload["review_from"],
                    track=payload["track"],
                )
            continue

        if kind == "probe":
            engine.probe_connectivity(
                record_id=row["record_id"], domain="race",
                cert_label=payload["credential"], track=payload["track"],
                observed=observed, tls_accepted=payload["tls_accepted"],
            )
            continue

        if kind in ("sample", "receipt"):
            # 沿关联链确定持票实例（样本可能只关联证书/许可，需传递到登记记录）
            instance = instance_of(row)
            # 演练/正式来件按来源接收方区分接入域，payload 内显式 domain 优先
            domain = payload.get("domain", source)
            if kind == "sample":
                # 裁决时刻取接收方观测时刻；time_us 是业务计时值，
                # 与许可生效段（观测时刻单位）不可比
                engine.consider_sample(
                    record_id=row["record_id"], domain=domain,
                    track=payload["track"], sequence=payload["sequence"],
                    observed=observed, moment=observed,
                    instance=instance,
                )
            else:
                # 回执补查可能只关联到先前回执，实例沿用既有占位记录的归属
                if instance is None:
                    prior = engine.bookings.get(
                        (domain, payload["track"], payload["sequence"])
                    )
                    if prior is not None and prior.owner_instance:
                        instance = prior.owner_instance
                engine.consider_receipt(
                    record_id=row["record_id"], domain=domain,
                    track=payload["track"], sequence=payload["sequence"],
                    observed=observed, receipt_ref=payload["receipt"],
                    state=payload["state"],
                    received_at=payload.get("received_at"),
                    instance=instance,
                )

    return engine


def replay_file(data_root: Path | str, trust: Optional[Trust] = None) -> Station:
    import json
    root = Path(data_root)
    with (root / "observations.jsonl").open(encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream if line.strip()]
    return replay(records, trust=trust)
